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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include "daemon.h"
#include "logger.h"
#include "utils.h"

/* Daemonization function coming from zebra source code */
pid_t
xdaemon(bool nochdir, bool noclose, bool exitflag)
{
	pid_t pid;
	int ret;

#ifdef ENABLE_LOG_TO_FILE
	if (log_file_name)
		flush_log_file();
#endif

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
	if (!nochdir) {
		ret = chdir("/");
		if (ret < 0) {
			log_message(LOG_INFO, "xdaemon: chdir error");
		}
	}

	/* File descriptor close. */
	if (!noclose)
		set_std_fd(true);

	return 0;
}
