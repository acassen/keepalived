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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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

static char *path;
static bool path_is_malloced;

/* perform a system call */
static int
system_call(const char *cmdline, uid_t uid, gid_t gid)
{
	int retval;

	/* Drop our privileges if configured */
	if (gid) {
		retval = setgid(gid);
		if (retval < 0) {
			log_message(LOG_ALERT, "Couldn't setgid: %d (%m)", gid);
			return -1;
		}

		/* Clear any extra supplementary groups */
		retval = setgroups(1, &gid);
		if (retval < 0) {
			log_message(LOG_ALERT, "Couldn't setgroups: %d (%m)", gid);
			return -1;
		}
	}

	if (uid) {
		retval = setuid(uid);
		if (retval < 0) {
			log_message(LOG_ALERT, "Couldn't setuid: %d (%m)", uid);
			return -1;
		}
	}

	/* system() fails if SIGCHLD is set to SIG_IGN */
	signal_set(SIGCHLD, (void*)SIG_DFL, NULL);

	retval = system(cmdline);
	if (retval == -1) {
		/* other error */
		log_message(LOG_ALERT, "Error exec-ing command: %s", cmdline);
	} else if (WIFEXITED(retval)) {
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

static bool
is_executable(struct stat *buf, uid_t uid, gid_t gid)
{
	return (uid == 0 && buf->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) ||
	       (uid == buf->st_uid && buf->st_mode & S_IXUSR) ||
	       (uid != buf->st_uid && 
		((gid == buf->st_gid && buf->st_mode & S_IXGRP) ||
		 (gid != buf->st_gid && buf->st_mode & S_IXOTH)));
}

/* The following function is essentially __execve() from glibc */
static int
find_path(notify_script_t *script, bool full_string)
{
	size_t filename_len;
	size_t file_len;
	size_t path_len;
	char *file = script->name;
	struct stat buf;
	int ret;
	int ret_val = ENOENT;
	int sgid_num;
	gid_t *sgid_list = NULL;
	char *space = NULL;
	const char *subp;
	bool got_eacces = false;
	const char *p;

	/* We check the simple case first. */
	if (*file == '\0')
		return ENOENT;

	if (!full_string) {
		if ((space = strchr(file, ' ')))
			*space = '\0';
	}

	filename_len = strlen(file);
	if (filename_len >= PATH_MAX) {
		ret_val = ENAMETOOLONG;
		goto exit1;
	}

	/* Don't search when it contains a slash. */
	if (strchr (file, '/') != NULL) {
		ret_val = 0;
		goto exit1;
	}

	/* Get the path if we haven't already done so, and if that doesn't
	 * exist, use CS_PATH */
	if (!path) {
		path = getenv ("PATH");

		if (!path) {
			int cs_path_len;
			path = MALLOC(cs_path_len = confstr(_CS_PATH, NULL, 0));
			confstr(_CS_PATH, path, cs_path_len);
			path_is_malloced = true;
		}
	}

	/* Although GLIBC does not enforce NAME_MAX, we set it as the maximum
	   size to avoid unbounded stack allocation.  Same applies for
	   PATH_MAX. */
	file_len = strnlen (file, NAME_MAX + 1);
	path_len = strnlen (path, PATH_MAX - 1) + 1;

	if (file_len > NAME_MAX) {
		ret_val = ENAMETOOLONG;
		goto exit1;
	}

	/* Set file access to the relevant uid/gid */
	if (script->gid) {
		if (setegid(script->gid)) {
			log_message(LOG_INFO, "Unable to set egid to %d (%m)", script->gid);
			ret_val = EACCES;
			goto exit1;
		}

		/* Get our supplementary groups */
		sgid_num = getgroups(0, NULL);
		sgid_list = MALLOC((sgid_num + 1) * sizeof(gid_t));
		sgid_num = getgroups(sgid_num, sgid_list);
		sgid_list[sgid_num++] = 0;

		/* Clear the supplementary group list */
		if (setgroups(1, &script->gid)) {
			log_message(LOG_INFO, "Unable to set supplementary gids (%m)");
			ret_val = EACCES;
			goto exit;
		}
	}
	if (script->uid && seteuid(script->uid)) {
		log_message(LOG_INFO, "Unable to set euid to %d (%m)", script->uid);
		ret_val = EACCES;
		goto exit;
	}

	for (p = path; ; p = subp)
	{
		char buffer[path_len + file_len + 1];

		subp = strchrnul (p, ':');

		/* PATH is larger than PATH_MAX and thus potentially larger than
		   the stack allocation. */
		if (subp >= p + path_len) {
			/* There are no more paths, bail out. */
			if (*subp == '\0') {
				ret_val = ENOENT;
				goto exit;
			}

			/* Otherwise skip to next one. */
			continue;
		}

		/* Use the current path entry, plus a '/' if nonempty, plus the file to execute. */
		char *pend = mempcpy (buffer, p, subp - p);
		*pend = '/';
		memcpy (pend + (p < subp), file, file_len + 1);

		ret = stat (buffer, &buf);
		if (!ret) {
			if (!S_ISREG(buf.st_mode))
				ret = EACCES;
			else if (!is_executable(&buf, script->uid, script->gid)) {
				ret = EACCES;
			}
		}
		else
			ret = errno;

		if (!ret) {
			/* Success */
			log_message(LOG_INFO, "WARNING - script `%s` resolved by path search to `%s`. Please specify full path.", script->name, buffer); 

			/* Copy the found file name, and append any parameters */
			file = MALLOC(strlen(buffer) + (space ? strlen(space + 1) + 1 : 0) + 1);
			strcpy(file, buffer);
			if (space) {
				filename_len = strlen(file);
				file[filename_len] = ' ';
				strcpy(file + filename_len + 1, space + 1);
				space = NULL;
			}

			FREE(script->name);
			script->name = file;

			ret_val = 0;
			got_eacces = false;
			goto exit;
		}

		switch (ret)
		{
		case ENOEXEC:
		case EACCES:
			/* Record that we got a 'Permission denied' error.  If we end
			   up finding no executable we can use, we want to diagnose
			   that we did find one but were denied access. */
			got_eacces = true;
		case ENOENT:
		case ESTALE:
		case ENOTDIR:
			/* Those errors indicate the file is missing or not executable
			   by us, in which case we want to just try the next path
			   directory. */
		case ENODEV:
		case ETIMEDOUT:
			/* Some strange filesystems like AFS return even
			   stranger error numbers.  They cannot reasonably mean
			   anything else so ignore those, too. */
			break;

		default:
			/* Some other error means we found an executable file, but
			   something went wrong accessing it; return the error to our
			   caller. */
			ret_val = -1;
			goto exit;
		}

		if (*subp++ == '\0')
			break;
	}

exit:
	/* Restore root euid/egid */
	if (script->uid && seteuid(0))
		log_message(LOG_INFO, "Unable to restore euid after script search (%m)");
	if (script->gid) {
		if (setegid(0))
			log_message(LOG_INFO, "Unable to restore egid after script search (%m)");

		/* restore supplementary groups */
		if (sgid_list) {
			if (setgroups(sgid_num, sgid_list))
				log_message(LOG_INFO, "Unable to restore supplementary groups after script search (%m)");
			FREE(sgid_list);
		}
	}

exit1:
	if (space)
		*space = 0;

	/* We tried every element and none of them worked. */
	if (got_eacces) {
		/* At least one failure was due to permissions, so report that error. */
		return EACCES;
	}

	return ret_val;
}

int
check_script_secure(notify_script_t *script, bool script_security, bool full_string)
{
	int flags;
	char *slash;
	char *space = NULL;
	char *next = script->name;
	char sav;
	int ret;
	struct stat buf, file_buf;
	bool need_script_protection = false;

	if (!script)
		return 0;

	if (!strchr(script->name, '/')) {
		/* It is a bare file name, so do a path search */
		if ((ret = find_path(script, full_string))) {
			if (ret == EACCES)
				log_message(LOG_INFO, "Permissions failure for script %s in path", script->name);
			else
				log_message(LOG_INFO, "Cannot find script %s in path", script->name);
			return SC_NOTFOUND;
		}
	}

	/* Get the permissions for the file itself */
	if (!full_string) {
		space = strchr(script->name, ' ');
		if (space)
			*space = '\0';
	}
	if (stat(script->name, &file_buf)) {
		log_message(LOG_INFO, "Unable to access script `%s`", script->name);
		if (space)
			*space = ' ';
		return SC_NOTFOUND;
	}
	if (space)
		*space = ' ';

	flags = SC_ISSCRIPT;

	/* We have the final file. Check if root is executing it, or it is set uid/gid root. */
	if (is_executable(&file_buf, script->uid, script->gid)) {
		flags |= SC_EXECUTABLE;
		if (script->uid == 0 || script->gid == 0 ||
		    (file_buf.st_uid == 0 && (file_buf.st_mode & S_IXUSR) && (file_buf.st_mode & S_ISUID)) ||
		    (file_buf.st_gid == 0 && (file_buf.st_mode & S_IXGRP) && (file_buf.st_mode & S_ISGID)))
			need_script_protection = true;
	} else
		log_message(LOG_INFO, "WARNING - script '%s' is not executable for uid:gid %d:%d - disabling.", script->name, script->uid, script->gid);

	if (!need_script_protection)
		return flags;

	next = script->name;
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

		if (buf.st_uid ||				/* Owner is not root */
		    ((!(buf.st_mode & S_ISVTX) ||		/* Sticky bit not set */
		      buf.st_mode & S_IFREG) &&			/* This is a file */
		     ((buf.st_gid && buf.st_mode & S_IWGRP) ||	/* Group is not root and group write permission */
		      buf.st_mode & S_IWOTH))) {		/* World has write permission */
			log_message(LOG_INFO, "Unsafe permissions found for script '%s'.", script->name);
			flags |= SC_INSECURE;
			if (script_security)
				flags |= SC_INHIBIT;
			break;
		}

	}

	return flags;
}

int
check_notify_script_secure(notify_script_t **script_p, bool script_security, bool full_string)
{
	int flags;
	notify_script_t *script = *script_p;

	if (!script)
		return 0;

	flags = check_script_secure(script, script_security, full_string);

	/* Mark not to run if needs inhibiting */
	if (flags & SC_INHIBIT) {
		log_message(LOG_INFO, "Disabling notify script %s due to insecure", script->name);
		free_notify_script(script_p);
	}
	else if (flags & SC_NOTFOUND) {
		log_message(LOG_INFO, "Disabling notify script %s since not found", script->name);
		free_notify_script(script_p);
	}
	else if (!(flags & SC_EXECUTABLE))
		free_notify_script(script_p);

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

