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

/* Default user/group for script execution */
uid_t default_script_uid;
gid_t default_script_gid;

/* Script security enabled */
bool script_security = false;

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

	/* Prepare for invoking process/script */
	signal_handler_script();
	set_std_fd(false);

	retval = system(cmdline);


	if (retval == -1) {
		/* other error */
		log_message(LOG_ALERT, "Error exec-ing command error %d: %s", errno, cmdline);
	}
	else if (WIFEXITED(retval)) {
		if (retval == 127) {
			/* couldn't exec /bin/sh or couldn't find command */
			log_message(LOG_ALERT, "Couldn't find command: %s", cmdline);
		} else if (retval == 126) {
			/* don't have sufficient privilege to exec command */
			log_message(LOG_ALERT, "Insufficient privilege to exec command: %s", cmdline);
		}
	}

	return retval;
}

/* Execute external script/program */
int
notify_exec(const notify_script_t *script)
{
	pid_t pid;

	pid = fork();

	if (pid < 0) {
		/* fork error */
		log_message(LOG_INFO, "Failed fork process");
		return -1;
	}

	if (pid) {
		/* parent process */
		return 0;
	}

#ifdef _MEM_CHECK_
	skip_mem_dump();
#endif

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

	if (pid < 0) {
		/* fork error */
		log_message(LOG_INFO, "Failed fork process");
		return -1;
	}

	if (pid) {
		/* parent process */
		thread_add_child(m, func, arg, pid, timer);
		return 0;
	}

	/* Child process */
#ifdef _MEM_CHECK_
	skip_mem_dump();
#endif

	/* Move us into our own process group, so if the script needs to be killed
	 * all its child processes will also be killed. */
	setpgid(0, 0);

	status = system_call(script, uid, gid);

	/* Note, if script_use_exec is set, system_call will not return */
// TODO - Maybe we should exit with status 127 to signify don't change priority
// unless this is the first return in which was we want to creep out of fault state
	if (status < 0 || !WIFEXITED(status) || WEXITSTATUS(status >= 126))
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
check_script_secure(notify_script_t *script, bool full_string)
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
		slash = next + strcspn(next, "/ ");
		if (*slash)
			next = slash + 1;
		else {
			slash = NULL;
			next = NULL;
		}

		if (slash) {
			/* If full_string, then file name can contain spaces, otherwise it terminates the command */
			if (*slash == ' ') {
				if (full_string)
					continue;
				next = NULL;
			}

			/* If there are multiple consecutive '/'s, don't check subsequent ones */
			if (slash > script->name && slash[-1] == '/')
				continue;

			/* We want to check '/' for first time around */
			if (slash == script->name)
				slash++;
			sav = *slash;
			*slash = 0;
		}

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
			if (script_security)
				flags |= SC_INHIBIT;
		}

		if (!slash || (!full_string && *slash == ' ')) {
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

int
check_notify_script_secure(notify_script_t **script_p, bool full_string)
{
	int flags;
	notify_script_t *script = *script_p;

	if (!script)
		return 0;

	flags = check_script_secure(script, full_string);

	/* Mark not to run if needs inhibiting */
	if (flags & SC_INHIBIT) {
		log_message(LOG_INFO, "Disabling notify script %s due to insecure", script->name);
		free_notify_script(script_p);
	}
	else if (flags & SC_NOTFOUND) {
		log_message(LOG_INFO, "Disabling notify script %s since not found", script->name);
		free_notify_script(script_p);
	}
	else if (flags & SC_EXECUTABLE)
		script->executable = true;

	return flags;
}

/* The default script user/group is keepalived_script if it exists, or root otherwise */
void
set_default_script_user(void)
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

	default_script_uid = pwd.pw_uid;
	default_script_gid = pwd.pw_gid;

	log_message(LOG_INFO, "Setting default script user to '%s', uid:gid %d:%d", default_user_name, pwd.pw_uid, pwd.pw_gid);
}

notify_script_t*
notify_script_init(vector_t *strvec)
{
	notify_script_t *script = MALLOC(sizeof(notify_script_t));

	script->name = set_value(strvec);
	script->uid = default_script_uid;
	script->gid = default_script_gid;

	return script;
}

