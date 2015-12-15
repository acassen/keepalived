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

#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include "notify.h"
#include "signals.h"
#include "logger.h"
#include "utils.h"

/* perform a system call */
static int
system_call(const char *cmdline)
{
	int retval;

	/* system() fails if SIGCHLD is set to SIG_IGN */
	signal_set(SIGCHLD, (void*)SIG_DFL, NULL);

	retval = system(cmdline);

	if (retval == 127) {
		/* couldn't exec command */
		log_message(LOG_ALERT, "Couldn't exec command: %s", cmdline);
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
notify_exec(char *cmd)
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

	script_setup();

	system_call(cmd);

	exit(0);
}

int
system_call_script(thread_master_t *m, int (*func) (thread_t *), void * arg, long timer, const char* script)
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
	script_setup();

	status = system_call(script);

	if (status < 0 || !WIFEXITED(status))
		exit(0); /* Script errors aren't server errors */

	exit(WEXITSTATUS(status));
}
