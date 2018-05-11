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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <grp.h>
#include <string.h>
#include <sys/stat.h>
#include <pwd.h>
#include <sys/resource.h>
#include <limits.h>
#include <sys/prctl.h>

#include "notify.h"
#include "signals.h"
#include "logger.h"
#include "utils.h"
#include "parser.h"
#include "keepalived_magic.h"
#include "scheduler.h"

/* Default user/group for script execution */
uid_t default_script_uid;
gid_t default_script_gid;

/* Have we got a default user OK? */
static bool default_script_uid_set = false;
static bool default_user_fail = false;			/* Set if failed to set default user,
							   unless it defaults to root */

/* Script security enabled */
bool script_security = false;

/* Buffer length needed for getpwnam_r/getgrname_r */
static size_t getpwnam_buf_len;

static char *path;
static bool path_is_malloced;

/* The priority this process is running at */
static int cur_prio = INT_MAX;

static bool
set_privileges(uid_t uid, gid_t gid)
{
	int retval;

	/* Ensure we receive SIGTERM if our parent process dies */
	prctl(PR_SET_PDEATHSIG, SIGTERM);

	/* If we have increased our priority, set it to default for the script */
	if (cur_prio != INT_MAX)
		cur_prio = getpriority(PRIO_PROCESS, 0);
	if (cur_prio < 0)
		setpriority(PRIO_PROCESS, 0, 0);

	/* Drop our privileges if configured */
	if (gid) {
		retval = setgid(gid);
		if (retval < 0) {
			log_message(LOG_ALERT, "Couldn't setgid: %d (%m)", gid);
			return true;
		}

		/* Clear any extra supplementary groups */
		retval = setgroups(1, &gid);
		if (retval < 0) {
			log_message(LOG_ALERT, "Couldn't setgroups: %d (%m)", gid);
			return true;
		}
	}

	if (uid) {
		retval = setuid(uid);
		if (retval < 0) {
			log_message(LOG_ALERT, "Couldn't setuid: %d (%m)", uid);
			return true;
		}
	}

	/* Prepare for invoking process/script */
	signal_handler_script();
	set_std_fd(false);

	return false;
}

/* Execute external script/program to process FIFO */
static pid_t
notify_fifo_exec(thread_master_t *m, int (*func) (thread_t *), void *arg, const notify_script_t *script)
{
	pid_t pid;
	int retval;

	pid = fork();

	/* In case of fork is error. */
	if (pid < 0) {
		log_message(LOG_INFO, "Failed fork process");
		return -1;
	}

	/* In case of this is parent process */
	if (pid) {
		thread_add_child(m, func, arg, pid, TIMER_NEVER);
		return 0;
	}

#ifdef _MEM_CHECK_
	skip_mem_dump();
#endif

	setpgid(0, 0);
	set_privileges(script->uid, script->gid);

	if (script->flags | SC_EXECABLE) {
		/* If keepalived dies, we want the script to die */
		prctl(PR_SET_PDEATHSIG, SIGTERM);

		execve(script->args[0], script->args, environ);

		if (errno == EACCES)
			log_message(LOG_INFO, "FIFO notify script %s is not executable", script->args[0]);
		else
			log_message(LOG_INFO, "Unable to execute FIFO notify script %s - errno %d - %m", script->args[0], errno);
	}
	else {
		retval = system(script->cmd_str);

		if (retval == 127) {
			/* couldn't exec command */
			log_message(LOG_ALERT, "Couldn't exec FIFO command: %s", script->cmd_str);
		}
		else if (retval == -1)
			log_message(LOG_ALERT, "Error exec-ing FIFO command: %s", script->cmd_str);

		exit(0);
	}

	/* unreached unless error */
	exit(0);
}

static void
fifo_open(notify_fifo_t* fifo, int (*script_exit)(thread_t *), const char *type)
{
	int ret;
	int sav_errno;

	if (fifo->name) {
		sav_errno = 0;

		if (!(ret = mkfifo(fifo->name, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)))
			fifo->created_fifo = true;
		else {
			sav_errno = errno;

			if (sav_errno != EEXIST)
				log_message(LOG_INFO, "Unable to create %snotify fifo %s", type, fifo->name);
		}

		if (!sav_errno || sav_errno == EEXIST) {
			/* Run the notify script if there is one */
			if (fifo->script)
				notify_fifo_exec(master, script_exit, fifo, fifo->script);

			/* Now open the fifo */
			if ((fifo->fd = open(fifo->name, O_RDWR | O_CLOEXEC | O_NONBLOCK)) == -1) {
				log_message(LOG_INFO, "Unable to open %snotify fifo %s - errno %d", type, fifo->name, errno);
				if (fifo->created_fifo) {
					unlink(fifo->name);
					fifo->created_fifo = false;
				}
			}
		}

		if (fifo->fd == -1) {
			FREE(fifo->name);
			fifo->name = NULL;
		}
	}
}

void
notify_fifo_open(notify_fifo_t* global_fifo, notify_fifo_t* fifo, int (*script_exit)(thread_t *), const char *type)
{
	/* Open the global FIFO if specified */
	if (global_fifo->name)
		fifo_open(global_fifo, script_exit, "");

	/* Now the specific FIFO */
	if (fifo->name)
		fifo_open(fifo, script_exit, type);
}

static void
fifo_close(notify_fifo_t* fifo)
{
	if (fifo->fd != -1) {
		close(fifo->fd);
		fifo->fd = -1;
	}
	if (fifo->created_fifo)
		unlink(fifo->name);
}

void
notify_fifo_close(notify_fifo_t* global_fifo, notify_fifo_t* fifo)
{
	if (global_fifo->fd != -1)
		fifo_close(global_fifo);

	fifo_close(fifo);
}

/* perform a system call */
static void system_call(const notify_script_t *) __attribute__ ((noreturn));

static void
system_call(const notify_script_t* script)
{
	size_t num;
	size_t len;
	char *command_line = NULL;
	char *cmd_str;
	int retval;

	if (set_privileges(script->uid, script->gid))
		exit(0);

	/* Move us into our own process group, so if the script needs to be killed
	 * all its child processes will also be killed. */
	setpgid(0, 0);

	if (script->flags & SC_EXECABLE) {
		/* If keepalived dies, we want the script to die */
		prctl(PR_SET_PDEATHSIG, SIGTERM);

		execve(script->args[0], script->args, environ);

		/* error */
		log_message(LOG_ALERT, "Error exec-ing command '%s', error %d: %m", script->args[0], errno);
	}
	else {
		if (script->cmd_str)
			cmd_str = script->cmd_str;
		else {
			/* It is a notify script - we have to build the command line */
			for (num = 0, len = 0; script->args[num]; num++)
				len += strlen(script->args[num]) + 1;	/* Space or '\0' */
			len += 4;	/* Quotes around command and vrrp instance name */

			command_line = MALLOC(len);
			for (num = 0; script->args[num]; num++) {
				if (num)
					strcat(command_line, " ");
				if (num == 0 || num == 2)
					strcat(command_line, "\"");
				strcat(command_line, script->args[num]);
				if (num == 0 || num == 2)
					strcat(command_line, "\"");
			}
			cmd_str = command_line;
		}

		retval = system(cmd_str);

		if (retval == -1)
			log_message(LOG_ALERT, "Error exec-ing command: %s", cmd_str);
		else if (WIFEXITED(retval)) {
			if (WEXITSTATUS(retval) == 127) {
				/* couldn't find command */
				log_message(LOG_ALERT, "Couldn't find command: %s", cmd_str);
			}
			else if (WEXITSTATUS(retval) == 126) {
				/* couldn't find command */
				log_message(LOG_ALERT, "Couldn't execute command: %s", cmd_str);
			}
		}

		if (command_line)
			FREE(command_line);

		if (retval == -1 ||
		    (WIFEXITED(retval) && (WEXITSTATUS(retval) == 126 || WEXITSTATUS(retval) == 127)))
			exit(0);
		if (WIFEXITED(retval))
			exit(WEXITSTATUS(retval));
		if (WIFSIGNALED(retval))
			kill(getpid(), WTERMSIG(retval));
		exit(0);
	}

	exit(0);
}

/* Execute external script/program */
int
notify_exec(const notify_script_t *script)
{
	pid_t pid;

	if (log_file_name)
		flush_log_file();

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

	system_call(script);

	/* We should never get here */
	exit(0);
}

int
system_call_script(thread_master_t *m, int (*func) (thread_t *), void * arg, unsigned long timer, notify_script_t* script)
{
	pid_t pid;

	/* Daemonization to not degrade our scheduling timer */
	if (log_file_name)
		flush_log_file();

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

	system_call(script);

	exit(0); /* Script errors aren't server errors */
}

int
child_killed_thread(thread_t *thread)
{
	thread_master_t *m = thread->master;

	/* If the child didn't die, then force it */
	if (thread->type == THREAD_CHILD_TIMEOUT)
		kill(-getpgid(thread->u.c.pid), SIGKILL);

	/* If all children have died, we can now complete the
	 * termination process */
	if (!m->child.count && !m->shutdown_timer_running)
		thread_add_terminate_event(m);

	return 0;
}

void
script_killall(thread_master_t *m, int signo, bool requeue)
{
	thread_t *thread;
	pid_t p_pgid, c_pgid;
#ifndef HAVE_SIGNALFD
	sigset_t old_set, child_wait;

	sigmask_func(0, NULL, &old_set);
	if (!sigismember(&old_set, SIGCHLD)) {
		sigemptyset(&child_wait);
		sigaddset(&child_wait, SIGCHLD);
		sigmask_func(SIG_BLOCK, &child_wait, NULL);
	}
#endif

	p_pgid = getpgid(0);

	for (thread = m->child.head; thread; thread = thread->next) {
		c_pgid = getpgid(thread->u.c.pid);
		if (c_pgid != p_pgid)
			kill(-c_pgid, signo);
		else {
			log_message(LOG_INFO, "Child process %d in our process group %d", c_pgid, p_pgid);
			kill(thread->u.c.pid, signo);
		}
	}

	/* We want to timeout the killed children in 1 second */
	if (requeue && signo != SIGKILL)
		thread_children_reschedule(m, child_killed_thread, TIMER_HZ);

#ifndef HAVE_SIGNALFD
	if (!sigismember(&old_set, SIGCHLD))
		sigmask_func(SIG_UNBLOCK, &child_wait, NULL);
#endif
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

static void
replace_cmd_name(notify_script_t *script, char *new_cmd)
{
	size_t new_len = sizeof(char *) + strlen(new_cmd) + 1;
	char **word_ptrs = script->args;
	size_t num_words = 1;
	char **new_args;
	char *new_words;
	char **new_word_ptrs;
	char *new_cmd_str;

	while (*++word_ptrs) {
		new_len += sizeof(char *) + strlen(*word_ptrs) + 1;
		num_words++;
	}

	/* Allow for terminating null pointer */
	new_len += sizeof(char *);

	new_args = MALLOC(new_len);
	word_ptrs = script->args;
	new_words = (char *)new_args + (num_words + 1) * sizeof(char *);
	new_word_ptrs = new_args;

	strcpy(new_words, new_cmd);
	*new_word_ptrs = new_words;
	new_words += strlen(new_words) + 1;

	while (*++word_ptrs) {
		strcpy(new_words, *word_ptrs);
		*++new_word_ptrs = new_words;
		new_words += strlen(new_words) + 1;
	}
	*++new_word_ptrs = NULL;

	/* Now do the cmd_str */
	new_cmd_str = MALLOC(strlen(script->cmd_str) - strlen(script->args[0]) + strlen(new_args[0]) + 1);
	strcpy(new_cmd_str, new_args[0]);
	strcat(new_cmd_str, script->cmd_str + strlen(script->args[0]));

	FREE(script->cmd_str);
	script->cmd_str = new_cmd_str;

	FREE(script->args);
	script->args = new_args;
}

/* The following function is essentially __execve() from glibc */
static int
find_path(notify_script_t *script)
{
	size_t filename_len;
	size_t file_len;
	size_t path_len;
	char *file = script->args[0];
	struct stat buf;
	int ret;
	int ret_val = ENOENT;
	int sgid_num;
	gid_t *sgid_list = NULL;
	const char *subp;
	bool got_eacces = false;
	const char *p;

	/* We check the simple case first. */
	if (*file == '\0')
		return ENOENT;

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
			size_t cs_path_len;
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
		sgid_list = MALLOC(((size_t)sgid_num + 1) * sizeof(gid_t));
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
		char *pend = mempcpy (buffer, p, (size_t)(subp - p));
		*pend = '/';
		memcpy (pend + (p < subp), file, file_len + 1);

		ret = stat (buffer, &buf);
		if (!ret) {
			if (!S_ISREG(buf.st_mode))
				errno = EACCES;
			else if (!is_executable(&buf, script->uid, script->gid)) {
				errno = EACCES;
			} else {
				/* Success */
				log_message(LOG_INFO, "WARNING - script `%s` resolved by path search to `%s`. Please specify full path.", script->args[0], buffer);

				/* Copy the found file name, and any parameters */
				replace_cmd_name(script, buffer);

				ret_val = 0;
				got_eacces = false;
				goto exit;
			}
		}

		switch (errno)
		{
		case ENOEXEC:
		case EACCES:
			/* Record that we got a 'Permission denied' error.  If we end
			   up finding no executable we can use, we want to diagnose
			   that we did find one but were denied access. */
			if (!ret)
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
			if (setgroups((size_t)sgid_num, sgid_list))
				log_message(LOG_INFO, "Unable to restore supplementary groups after script search (%m)");
			FREE(sgid_list);
		}
	}

exit1:
	/* We tried every element and none of them worked. */
	if (got_eacces) {
		/* At least one failure was due to permissions, so report that error. */
		return EACCES;
	}

	return ret_val;
}

static int
check_security(char *filename, bool script_security)
{
	char *next;
	char *slash;
	char sav;
	int ret;
	struct stat buf;
	int flags = 0;

	next = filename;
	while (next) {
		slash = strchrnul(next, '/');
		if (*slash)
			next = slash + 1;
		else {
			slash = NULL;
			next = NULL;
		}

		if (slash) {
			/* We want to check '/' for first time around */
			if (slash == filename)
				slash++;
			sav = *slash;
			*slash = 0;
		}

		ret = fstatat(0, filename, &buf, AT_SYMLINK_NOFOLLOW);

		/* Restore the full path name */
		if (slash)
			*slash = sav;

		if (ret) {
			if (errno == EACCES || errno == ELOOP || errno == ENOENT || errno == ENOTDIR)
				log_message(LOG_INFO, "check_script_secure could not find script '%s' - disabling", filename);
			else
				log_message(LOG_INFO, "check_script_secure('%s') returned errno %d - %s - disabling", filename, errno, strerror(errno));
			return flags | SC_NOTFOUND;
		}

		/* If it is not the last item, it must be a directory. If it is the last item
		 * it must be a file or a symbolic link. */
		if ((slash && !S_ISDIR(buf.st_mode)) ||
		    (!slash &&
		     !S_ISREG(buf.st_mode) &&
		     !S_ISLNK(buf.st_mode))) {
			log_message(LOG_INFO, "Wrong file type found in script path '%s'.", filename);
			return flags | SC_INHIBIT;
		}

		if (buf.st_uid ||				/* Owner is not root */
		    (((S_ISDIR(buf.st_mode) &&			/* A directory without the sticky bit set */
		       !(buf.st_mode & S_ISVTX)) ||
		      S_ISREG(buf.st_mode)) &&			/* This is a file */
		     ((buf.st_gid && buf.st_mode & S_IWGRP) ||	/* Group is not root and group write permission */
		      buf.st_mode & S_IWOTH))) {		/* World has write permission */
			log_message(LOG_INFO, "Unsafe permissions found for script '%s'%s.", filename, script_security ? " - disabling" : "");
			flags |= SC_INSECURE;
			return flags | (script_security ? SC_INHIBIT : 0);
		}
	}

	return flags;
}

int
check_script_secure(notify_script_t *script,
#ifndef _HAVE_LIBMAGIC_
					     __attribute__((unused))
#endif
								     magic_t magic)
{
	int flags;
	int ret;
	struct stat file_buf;
	bool need_script_protection = false;
	uid_t old_uid = 0;
	gid_t old_gid = 0;
	char *new_path;
	int sav_errno;
	char *real_file_path;
	char *orig_file_part, *new_file_part;
	char *dir_path;

	if (!script)
		return 0;

	/* If the script starts "</" (possibly with white space between
	 * the '<' and '/'), it is checking for a file being openable,
	 * so it won't be executed */
	if (script->args[0][0] == '<' &&
	    script->args[0][strspn(script->args[0] + 1, " \t") + 1] == '/')
		return SC_SYSTEM;

	if (!strchr(script->args[0], '/')) {
		/* It is a bare file name, so do a path search */
		if ((ret = find_path(script))) {
			if (ret == EACCES)
				log_message(LOG_INFO, "Permissions failure for script %s in path - disabling", script->cmd_str);
			else
				log_message(LOG_INFO, "Cannot find script %s in path - disabling", script->cmd_str);
			return SC_NOTFOUND;
		}
	}

	/* Check script accessible by the user running it */
	if (script->uid)
		old_uid = geteuid();
	if (script->gid)
		old_gid = getegid();

	if ((script->gid && setegid(script->gid)) ||
	    (script->uid && seteuid(script->uid))) {
		log_message(LOG_INFO, "Unable to set uid:gid %d:%d for script %s - disabling", script->uid, script->gid, script->args[0]);

		if ((script->uid && seteuid(old_uid)) ||
		    (script->gid && setegid(old_gid)))
			log_message(LOG_INFO, "Unable to restore uid:gid %d:%d after script %s", script->uid, script->gid, script->args[0]);

		return SC_INHIBIT;
	}

	/* Remove /./, /../, multiple /'s, and resolve symbolic links */
	new_path = realpath(script->args[0], NULL);
	sav_errno = errno;

	if ((script->gid && setegid(old_gid)) ||
	    (script->uid && seteuid(old_uid)))
		log_message(LOG_INFO, "Unable to restore uid:gid %d:%d after checking script %s", script->uid, script->gid, script->args[0]);

	if (!new_path)
	{
		log_message(LOG_INFO, "Script %s cannot be accessed - %s", script->args[0], strerror(sav_errno));

		return SC_NOTFOUND;
	}

	real_file_path = NULL;
	if (strcmp(script->args[0], new_path)) {
		/* The path name is different */
		size_t len;
		size_t num_words = 1;
		char **wp = &script->args[1];
		char **params;
		char **word_ptrs;
		char *words;

		/* If the file name parts don't match, we need to be careful to
		 * ensure that we preserve the file name part since some executables
		 * alter their behaviour based on what they are called */
		orig_file_part = strrchr(script->args[0], '/');
		new_file_part = strrchr(new_path, '/');
		if (strcmp(orig_file_part + 1, new_file_part + 1)) {
			*orig_file_part = '\0';
			dir_path = realpath(script->args[0], NULL);
			*orig_file_part = '/';
			real_file_path = new_path;
			new_path = MALLOC(strlen(dir_path) + 1 + strlen(orig_file_part + 1) + 1);
			strcpy(new_path, dir_path);
			strcat(new_path, "/");
			strcat(new_path, orig_file_part + 1);
		}

		/* We need to set up all the args again */
		len = strlen(new_path) + 1;
		while (*wp) {
			len += strlen(*wp) + 1;
			num_words++;
			wp++;
		}
		params = word_ptrs = MALLOC((num_words + 1) * sizeof(char *) + len);
		words = (char *)params + (num_words + 1) * sizeof(char *);
		strcpy(words, new_path);
		*(word_ptrs++) = words;
		words += strlen(words) + 1;
		wp = &script->args[1];
		while (*wp) {
			strcpy(words, *wp);
			*(word_ptrs++) = words;
			words += strlen(*wp) + 1;
			wp++;
		}
		*word_ptrs = NULL;
		FREE(script->args);
		script->args = params;

		FREE(script->cmd_str);
		script->cmd_str = MALLOC(strlen(new_path) + 1);
		strcpy(script->cmd_str, new_path);
	}
	if (!real_file_path)
		free(new_path);
	else
		FREE(new_path);

	/* Get the permissions for the file itself */
	if (stat(real_file_path ? real_file_path : script->args[0], &file_buf)) {
		log_message(LOG_INFO, "Unable to access script `%s` - disabling", script->cmd_str);
		return SC_NOTFOUND;
	}

	flags = SC_ISSCRIPT;

	/* We have the final file. Check if root is executing it, or it is set uid/gid root. */
	if (is_executable(&file_buf, script->uid, script->gid)) {
		flags |= SC_EXECUTABLE;
		if (script->uid == 0 || script->gid == 0 ||
		    (file_buf.st_uid == 0 && (file_buf.st_mode & S_IXUSR) && (file_buf.st_mode & S_ISUID)) ||
		    (file_buf.st_gid == 0 && (file_buf.st_mode & S_IXGRP) && (file_buf.st_mode & S_ISGID)))
			need_script_protection = true;
	} else
		log_message(LOG_INFO, "WARNING - script '%s' is not executable for uid:gid %d:%d - disabling.", script->cmd_str, script->uid, script->gid);

	/* Default to execable */
	script->flags |= SC_EXECABLE;
#ifdef _HAVE_LIBMAGIC_
	if (magic && flags & SC_EXECUTABLE) {
		const char *magic_desc = magic_file(magic, real_file_path ? real_file_path : script->args[0]);
		if (!strstr(magic_desc, " executable") &&
		    !strstr(magic_desc, " shared object")) {
			log_message(LOG_INFO, "Please add a #! shebang to script %s", script->args[0]);
			script->flags &= ~SC_EXECABLE;
		}
	}
#endif

	if (!need_script_protection) {
		if (real_file_path)
			free(real_file_path);

		return flags;
	}

	/* Make sure that all parts of the path are not non-root writable */
	flags |= check_security(script->args[0], script_security);

	if (real_file_path) {
		flags |= check_security(real_file_path, script_security);
		free(real_file_path);
	}

	return flags;
}

int
check_notify_script_secure(notify_script_t **script_p, magic_t magic)
{
	int flags;
	notify_script_t *script = *script_p;

	if (!script)
		return 0;

	flags = check_script_secure(script, magic);

	/* Mark not to run if needs inhibiting */
	if ((flags & (SC_INHIBIT | SC_NOTFOUND)) ||
	    !(flags & SC_EXECUTABLE))
		free_notify_script(script_p);

	return flags;
}

static void
set_pwnam_buf_len(void)
{
	long buf_len;

	/* Get buffer length needed for getpwnam_r/getgrnam_r */
	if ((buf_len = sysconf(_SC_GETPW_R_SIZE_MAX)) == -1)
		getpwnam_buf_len = 1024;	/* A safe default if no value is returned */
	else
		getpwnam_buf_len = (size_t)buf_len;
	if ((buf_len = sysconf(_SC_GETGR_R_SIZE_MAX)) != -1 &&
	    (size_t)buf_len > getpwnam_buf_len)
		getpwnam_buf_len = (size_t)buf_len;
}

bool
set_uid_gid(const char *username, const char *groupname, uid_t *uid_p, gid_t *gid_p, bool default_user)
{
	uid_t uid;
	gid_t gid;
	struct passwd pwd;
	struct passwd *pwd_p;
	struct group grp;
	struct group *grp_p;
	int ret;
	bool using_default_default_user = false;

	if (!getpwnam_buf_len)
		set_pwnam_buf_len();

	{
		char buf[getpwnam_buf_len];

		if (default_user && !username) {
			using_default_default_user = true;
			username = "keepalived_script";
		}

		if ((ret = getpwnam_r(username, &pwd, buf, sizeof(buf), &pwd_p))) {
			log_message(LOG_INFO, "Unable to resolve %sscript username '%s' - ignoring", default_user ? "default " : "", username);
			return true;
		}
		if (!pwd_p) {
			if (using_default_default_user)
				log_message(LOG_INFO, "WARNING - default user '%s' for script execution does not exist - please create.", username);
			else
				log_message(LOG_INFO, "%script user '%s' does not exist", default_user ? "Default s" : "S", username);
			return true;
		}

		uid = pwd.pw_uid;
		gid = pwd.pw_gid;

		if (groupname) {
			if ((ret = getgrnam_r(groupname, &grp, buf, sizeof(buf), &grp_p))) {
				log_message(LOG_INFO, "Unable to resolve %sscript group name '%s' - ignoring", default_user ? "default " : "", groupname);
				return true;
			}
			if (!grp_p) {
				log_message(LOG_INFO, "%script group '%s' does not exist", default_user ? "Default s" : "S", groupname);
				return true;
			}
			gid = grp.gr_gid;
		}

		*uid_p = uid;
		*gid_p = gid;
	}

	return false;
}

/* The default script user/group is keepalived_script if it exists, or root otherwise */
bool
set_default_script_user(const char *username, const char *groupname)
{
	if (!default_script_uid_set || username) {
		/* Even if we fail to set it, there is no point in trying again */
		default_script_uid_set = true;

		if (set_uid_gid(username, groupname, &default_script_uid, &default_script_gid, true)) {
			if (username || script_security)
				default_user_fail = true;
		}
		else
			default_user_fail = false;
	}

	return default_user_fail;
}

bool
set_script_uid_gid(vector_t *strvec, unsigned keyword_offset, uid_t *uid_p, gid_t *gid_p)
{
	char *username;
	char *groupname;

	username = strvec_slot(strvec, keyword_offset);
	if (vector_size(strvec) > keyword_offset + 1)
		groupname = strvec_slot(strvec, keyword_offset + 1);
	else
		groupname = NULL;

	return set_uid_gid(username, groupname, uid_p, gid_p, false);
}

char **
set_script_params_array(vector_t *strvec, bool with_params)
{
	unsigned num_words = 0;
	size_t len = 0;
	char *w, *save_p;
	char **word_ptrs, **params;
	char *words;
	char *str_cpy;

	/* Count the number of words, and total string length */
	if (!with_params) {
		num_words = 1;
		len = strlen(strvec_slot(strvec, 1)) + 1;
	} else {
		str_cpy = MALLOC(strlen(strvec_slot(strvec, 1)) + 1);
		strcpy(str_cpy, strvec_slot(strvec, 1));
		w = strtok_r(str_cpy, " \t", &save_p);
		while (w) {
			num_words++;
			len += strlen(w) + 1;
			w = strtok_r(NULL, " \t", &save_p);
		}
	}

	/* Allocate memory for pointers to words and words themselves */
	params = word_ptrs = MALLOC((num_words + 1) * sizeof(char *) + len);
	words = (char *)params + (num_words + 1) * sizeof(char *);

	/* Set up pointers to words, and copy the words */
	if (!with_params) {
		strcpy(words, strvec_slot(strvec, 1));
		*(word_ptrs++) = words;
	} else {
		strcpy(str_cpy, strvec_slot(strvec, 1));
		w = strtok_r(str_cpy, " \t", &save_p);
		while (w) {
			strcpy(words, w);
			*(word_ptrs++) = words;
			words += strlen(w) + 1;
			w = strtok_r(NULL, " \t", &save_p);
		}
		FREE(str_cpy);
	}
	*word_ptrs = NULL;

	return params;
}

notify_script_t*
notify_script_init(vector_t *strvec, bool with_params, const char *type)
{
	notify_script_t *script = MALLOC(sizeof(notify_script_t));

	script->args = set_script_params_array(strvec, with_params);
	script->cmd_str = set_value(strvec);
	script->flags = 0;

	if (vector_size(strvec) > 2) {
		if (set_script_uid_gid(strvec, 2, &script->uid, &script->gid)) {
			log_message(LOG_INFO, "Invalid user/group for %s script %s - ignoring", type, script->args[0]);
			FREE(script->args);
			FREE(script->cmd_str);
			FREE(script);
			return NULL;
		}
	}
	else {
		if (set_default_script_user(NULL, NULL)) {
			log_message(LOG_INFO, "Failed to set default user for %s script %s - ignoring", type, script->args[0]);
			FREE(script->args);
			FREE(script->cmd_str);
			FREE(script);
			return NULL;
		}

		script->uid = default_script_uid;
		script->gid = default_script_gid;
	}

	return script;
}

void
add_script_param(notify_script_t *script, char *param)
{
	size_t num = 0;
	size_t len;
	char **new_args;
	char *cmd_str;
	char *args;

	/* We store the args as an array of pointers to the args, terminated
	 * by a NULL pointer, followed by the null terminated strings themselves
	 */

	/* Find out how many args there are */
	for (num = 0, len = 0; script->args[num]; num++) {
		/* For each arg we need char *, the string, and the null termination */
		len += sizeof(char *) + strlen(script->args[num]) + 1;
	}
	len += 2 * sizeof(char *) + strlen(param) + 1;	/* Pointer for new param, termination null pointer, and the string */
	num += 2;

	new_args = MALLOC(len);
	args = (char *)new_args + num * sizeof(char *);

	for (num = 0; script->args[num]; num++) {
		new_args[num] = args;
		strcpy(args, script->args[num]);
		args += strlen(script->args[num]) + 1;
	}
	new_args[num++] = param;
	strcpy(args, param);
	new_args[num] = NULL;

	FREE(script->args);
	script->args = new_args;

	/* Now update the cmd_str */
	len = strlen(script->cmd_str) + strlen(param) + 2;	/* Space and '\0' */
	cmd_str = MALLOC(len);
	strcpy(cmd_str, script->cmd_str);
	strcat(cmd_str, " ");
	strcat(cmd_str, param);
	FREE(script->cmd_str);
	script->cmd_str = cmd_str;
}

void
notify_resource_release(void)
{
	if (path_is_malloced) {
		FREE(path);
		path_is_malloced = false;
		path = NULL;
	}
}
