/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Main program structure.
 *
 * Version:     $Id: main.c,v 0.7.1 2002/09/17 22:03:31 acassen Exp $
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
 */

#include <syslog.h>
#include "daemon.h"
#include "utils.h"

/* Daemonization function coming from zebra source code */
pid_t
xdaemon(int nochdir, int noclose, int exitflag)
{
	pid_t pid;

	/* In case of fork is error. */
	pid = fork();
	if (pid < 0) {
		syslog(LOG_INFO, "xdaemon: fork error");
		return -1;
	}

	/* In case of this is parent process. */
	if (pid != 0) {
		if (!exitflag)
			exit(0);
		else
			return pid;
	}

	/* Become session leader and get pid. */
	pid = setsid();
	if (pid < -1) {
		syslog(LOG_INFO, "xdaemon: setsid error");
		return -1;
	}

	/* Change directory to root. */
	if (!nochdir)
		chdir("/");

	/* File descriptor close. */
	if (!noclose) {
		int fd;

		fd = open("/dev/null", O_RDWR, 0);
		if (fd != -1) {
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			if (fd > 2)
				close(fd);
		}
	}

	umask(0);
	return 0;
}

/* Close all FDs >= a specified value */
void
closeall(int fd)
{
	int fdlimit = sysconf(_SC_OPEN_MAX);
	while (fd < fdlimit)
		close(fd++);
}

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
	} else {
		/* everything is good */
		DBG("Successfully exec command: %s retval is %d",
		    cmdline, retval);
	}

	return retval;
}
