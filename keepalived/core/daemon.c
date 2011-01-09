/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Main program structure.
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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include <syslog.h>
#include "daemon.h"
#include "logger.h"
#include "utils.h"

/* Daemonization function coming from zebra source code */
pid_t
xdaemon(int nochdir, int noclose, int exitflag)
{
	pid_t pid;
	int ret;

	/* In case of fork is error. */
	pid = fork();
	if (pid < 0) {
		log_message(LOG_INFO, "xdaemon: fork error");
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
		log_message(LOG_INFO, "xdaemon: setsid error");
		return -1;
	}

	/* Change directory to root. */
	if (!nochdir)
		ret = chdir("/");

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
