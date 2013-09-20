/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        pidfile utility.
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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "logger.h"
#include "pidfile.h"
extern char *main_pidfile;
extern char *checkers_pidfile;
extern char *vrrp_pidfile;

/* Create the runnnig daemon pidfile */
int
pidfile_write(char *pid_file, int pid)
{
	FILE *pidfile = NULL;
	int pidfd = creat(pid_file, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (pidfd != -1) pidfile = fdopen(pidfd, "w");

	if (!pidfile) {
		log_message(LOG_INFO, "pidfile_write : Can not open %s pidfile",
		       pid_file);
		return 0;
	}
	fprintf(pidfile, "%d\n", pid);
	fclose(pidfile);
	return 1;
}

/* Remove the running daemon pidfile */
void
pidfile_rm(char *pid_file)
{
	unlink(pid_file);
}

/* return the daemon pid, non-zero when running */
int
process_running(char *pid_file)
{
	FILE *pidfile = fopen(pid_file, "r");
	pid_t pid;
	int ret;

	/* No pidfile */
	if (!pidfile)
		return 0;

	ret = fscanf(pidfile, "%d", &pid);
	if (ret == EOF && ferror(pidfile) != 0) {
		log_message(LOG_INFO, "Error opening pid file %s", pid_file);
	}
	fclose(pidfile);

	/* If no process is attached to pidfile, remove it */
	if (kill(pid, 0)) {
		log_message(LOG_INFO, "Remove a zombie pid file %s", pid_file);
		pidfile_rm(pid_file);
		return 0;
	}

	return pid;
}

/* Return parent process daemon state */
int
keepalived_running(int mode)
{
	int pid = process_running(main_pidfile);

	if (pid)
		return pid;
	else if (mode & 1 || mode & 2)
		return process_running((mode & 1) ? vrrp_pidfile :
				       checkers_pidfile);

	if (process_running(vrrp_pidfile) ||
	    process_running(checkers_pidfile))
		return 1;
	return 0;
}
