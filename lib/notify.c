/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Forked system call to launch an extra script.
 *
 * Version:     $Id: notify.c,v 1.1.15 2007/09/15 04:07:41 acassen Exp $
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
 * Copyright (C) 2001-2007 Alexandre Cassen, <acassen@freebox.fr>
 */

#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <fcntl.h>
#include "notify.h"

/* perform a system call */
int
system_call(char *cmdline)
{
	int retval;

	retval = system(cmdline);

	if (retval == 127) {
		/* couldn't exec command */
		syslog(LOG_ALERT, "Couldn't exec command: %s", cmdline);
	} else if (retval == -1) {
		/* other error */
		syslog(LOG_ALERT, "Error exec-ing command: %s", cmdline);
	}

	return retval;
}

/* Close all FDs >= a specified value */
void
closeall(int fd)
{
	int fdlimit = sysconf(_SC_OPEN_MAX);
	while (fd < fdlimit)
		close(fd++);
}

/* Execute external script/program */
int
notify_exec(char *cmd)
{
	pid_t pid;

	pid = fork();

	/* In case of fork is error. */
	if (pid < 0) {
		syslog(LOG_INFO, "Failed fork process");
		return -1;
	}

	/* In case of this is parent process */
	if (pid)
		return 0;

	closeall(0);

	open("/dev/null", O_RDWR);
	dup(0);
	dup(0);

	system_call(cmd);

	exit(0);
}
