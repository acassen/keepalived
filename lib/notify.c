/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Forked system call to launch an extra script.
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include "config.h"

#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <grp.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <pwd.h>

#include "notify.h"
#include "signals.h"
#include "logger.h"
#include "utils.h"
#include "vector.h"
#include "parser.h"

/* perform a system call */
static int
system_call(const char *cmdline, uid_t uid, gid_t gid)
{
	int retval;

	/* Drop our privileges if configured */
	if (gid) {
		setgid(gid);

		/* Clear any extra supplementary groups */
		setgroups(1, &gid);
	}
	if (uid)
		setuid(uid);

	/* system() fails if SIGCHLD is set to SIG_IGN */
	signal_set(SIGCHLD, (void*)SIG_DFL, NULL);

	retval = system(cmdline);

	if (retval == 127) {
		/* couldn't exec command */
		log_message(LOG_ALERT, "Couldn't find command: %s", cmdline);
	} else if (retval == 126) {
		/* don't have sufficient privilege to exec command */
		log_message(LOG_ALERT, "Insufficient privilege to exec command: %s", cmdline);
	} else if (retval == -1) {
		/* other error */
		log_message(LOG_ALERT, "Error exec-ing command: %s", cmdline);
	}

	return retval;
}

static void
script_setup(void)
{
	signal_handler_script();

	set_std_fd(false);
}

/* Execute external script/program */
int
notify_exec(const notify_script_t *script)
{
	pid_t pid;

	pid = fork();

	/* In case of fork is error. */
	if (pid < 0) {
		log_message(LOG_INFO, "Failed fork process");
		return -1;
	}

	/* In case of this is parent process */
	if (pid)
		return 0;

#ifdef _MEM_CHECK_
	skip_mem_dump();
#endif

	script_setup();

	system_call(script->name, script->uid, script->gid);

	exit(0);
}

int
system_call_script(thread_master_t *m, int (*func) (thread_t *), void * arg, unsigned long timer, const char* script, uid_t uid, gid_t gid)
{
	int status;
	pid_t pid;

	/* Daemonization to not degrade our scheduling timer */
	pid = fork();

	/* In case of fork is error. */
	if (pid < 0) {
		log_message(LOG_INFO, "Failed fork process");
		return -1;
	}

	/* In case of this is parent process */
	if (pid) {
		thread_add_child(m, func, arg, pid, timer);
		return 0;
	}

	/* Child part */
#ifdef _MEM_CHECK_
	skip_mem_dump();
#endif

	setpgid(0, 0);

	script_setup();

	status = system_call(script, uid, gid);

	if (status < 0 || !WIFEXITED(status))
		exit(0); /* Script errors aren't server errors */

	exit(WEXITSTATUS(status));
}

void
script_killall(thread_master_t *m, int signo)
{
	sigset_t old_set, child_wait;
	thread_t *thread;
	pid_t p_pgid, c_pgid;

	sigprocmask(0, NULL, &old_set);
	if (!sigismember(&old_set, SIGCHLD)) {
		sigemptyset(&child_wait);
		sigaddset(&child_wait, SIGCHLD);
		sigprocmask(SIG_BLOCK, &child_wait, NULL);
	}

	thread = m->child.head;

	p_pgid = getpgid(0);

	while (thread) {
		c_pgid = getpgid(thread->u.c.pid);
		if (c_pgid != p_pgid) {
			kill(-c_pgid, signo);
		}
		thread = thread->next;
	}

	if (!sigismember(&old_set, SIGCHLD))
		sigprocmask(SIG_UNBLOCK, &child_wait, NULL);
}

int
check_script_secure(notify_script_t *script, bool script_security)
{
	int flags;
	char *slash;
	char *next = script->name;
	char sav;
	int ret;
	struct stat buf;

	if (!script)
		return 0;

	flags = SC_ISSCRIPT;

	while (next) {
		slash = strchr(next, '/');

		/* If there are multiple consecutive '/'s, don't check subsequent ones */
		if (slash && slash > script->name && slash[-1] == '/')
			continue;

		if (slash) {
			next = slash + 1;
			if (slash == script->name)
				slash++;
			sav = *slash;
			*slash = 0;
		}
		else
			next = NULL;

		ret = stat(script->name, &buf);

		/* Restore the full path name */
		if (slash)
			*slash = sav;

		if (ret) {
			if (errno == EACCES || errno == ELOOP || errno == ENOENT || errno == ENOTDIR)
				log_message(LOG_INFO, "check_script_secure could not find script '%s'", script->name);
			else
				log_message(LOG_INFO, "check_script_secure('%s') returned errno %d - %s", script->name, errno, strerror(errno));
			return flags | SC_NOTFOUND;
		}

		if (!(flags & SC_INSECURE) &&			/* Don't check again */
		    (script->uid == 0 || script->gid == 0) &&	/* Script executes with root user or group privilege */
		    (buf.st_uid ||				/* Owner is not root */
		     ((!(buf.st_mode & S_ISVTX) ||		/* Sticky bit not set */
		       buf.st_mode & S_IFREG) &&		/* This is a file */
		      ((buf.st_gid && buf.st_mode & S_IWGRP) ||	/* Group is not root and group write permission */
		       buf.st_mode & S_IWOTH)))) {		/* World has write permission */
			log_message(LOG_INFO, "Unsafe permissions found for script '%s' executed by root.", script->name);
			flags |= SC_INSECURE;
			if (script_security && flags & SC_INSECURE)
				flags |= SC_INHIBIT;
		}

		if (!slash) {
			/* We have the final file. Check if it is executable. */
			if (((script->uid == 0 || script->uid == buf.st_uid) && buf.st_mode & S_IXUSR) ||
			    ((script->uid == 0 || script->uid != buf.st_uid) && (script->gid == 0 || script->gid == buf.st_gid) && buf.st_mode & S_IXGRP) ||
			    ((script->uid == 0 || script->uid != buf.st_uid) && (script->gid == 0 || script->gid != buf.st_gid) && buf.st_mode & S_IXOTH)) {
				/* The script is executable for us */
				flags |= SC_EXECUTABLE;
			} else {
				log_message(LOG_INFO, "WARNING - script '%s' is not executable for uid:gid %d:%d. Please fix.", script->name, script->uid, script->gid);
			}
		}
	}
	return flags;
}

/* The default script user/group is keepalived_script if it exists, or root otherwise */
void
set_default_script_user(uid_t *uid, gid_t *gid)
{
	char buf[sysconf(_SC_GETPW_R_SIZE_MAX)];
	char *default_user_name = "keepalived_script";
        struct passwd pwd;
        struct passwd *pwd_p;

	if (getpwnam_r(default_user_name, &pwd, buf, sizeof(buf), &pwd_p)) {
		log_message(LOG_INFO, "Unable to resolve default script username '%s' - ignoring", default_user_name);
		return;
	}
	if (!pwd_p) {
		/* The username does not exist */
		log_message(LOG_INFO, "WARNING - default user '%s' for script execution does not exist - please create.", default_user_name);
		return;
	}

	*uid = pwd.pw_uid;
	*gid = pwd.pw_gid;

	log_message(LOG_INFO, "Setting default script user to '%s', uid:gid %d:%d", default_user_name, pwd.pw_uid, pwd.pw_gid);
}

notify_script_t*
notify_script_init(vector_t *strvec, uid_t uid, gid_t gid)
{
	notify_script_t *script = MALLOC(sizeof(notify_script_t));

	script->name = set_value(strvec);
	script->uid = uid;
	script->gid = gid;

	return script;
}

