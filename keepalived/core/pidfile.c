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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdbool.h>

#include "logger.h"
#include "pidfile.h"
#include "main.h"
#include "bitops.h"
#include "utils.h"
#include "memory.h"

const char *pid_directory = KEEPALIVED_PID_DIR;

static bool pid_dir_created;

/* Create the directory for non-standard pid files */
void
create_pid_dir(void)
{
	bool error;

	/* We want to create the PID directory with permissions rwxr-xr-x */
	if (umask_val & (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH))
		umask(umask_val & ~(S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH));

	error = mkdir(pid_directory, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) && errno != EEXIST;

	/* Restore the default umask */
	if (umask_val & (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH))
		umask(umask_val);

	if (error)
		log_message(LOG_INFO, "Unable to create directory %s", pid_directory);
	else
		pid_dir_created = true;
}

void
remove_pid_dir(void)
{
	if (!pid_dir_created)
		return;

	if (rmdir(pid_directory) && errno != ENOTEMPTY && errno != EBUSY)
		log_message(LOG_INFO, "unlink of %s failed - error (%d) '%s'", pid_directory, errno, strerror(errno));
}

char *
make_pidfile_name(const char* start, const char* instance, const char* extn)
{
	size_t len;
	char *name;

	len = strlen(start) + 1;
	if (instance)
		len += strlen(instance) + 1;
	if (extn)
		len += strlen(extn);

	name = MALLOC(len);
	if (!name) {
		log_message(LOG_INFO, "Unable to make pidfile name for %s", start);
		return NULL;
	}

	strcpy(name, start);
	if (instance) {
		strcat(name, "_");
		strcat(name, instance);
	}
	if (extn)
		strcat(name, extn);

	return name;
}

/* Create the running daemon pidfile */
bool
pidfile_write(const char *pid_file, int pid)
{
	FILE *pidfile = NULL;
	int pidfd;

	/* We want to create the file with permissions rx-r--r-- */
	if (umask_val & (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))
		umask(umask_val & ~(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));

	pidfd = open(pid_file, O_NOFOLLOW | O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	/* Restore the default umask */
	if (umask_val & (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))
		umask(umask_val);

	if (pidfd != -1)
		pidfile = fdopen(pidfd, "w");

	if (!pidfile) {
		log_message(LOG_INFO, "pidfile_write : Cannot open %s pidfile",
		       pid_file);
		return false;
	}

	fprintf(pidfile, "%d\n", pid);
	fclose(pidfile);

	return true;
}

/* Remove the running daemon pidfile */
void
pidfile_rm(const char *pid_file)
{
	unlink(pid_file);
}

/* return the daemon running state */
static bool
process_running(const char *pid_file)
{
	FILE *pidfile = fopen(pid_file, "r");
	pid_t pid = 0;
	int ret;

	/* No pidfile */
	if (!pidfile)
		return false;

	ret = fscanf(pidfile, "%d", &pid);
	fclose(pidfile);
	if (ret != 1) {
		log_message(LOG_INFO, "Error reading pid file %s", pid_file);
		pid = 0;
		pidfile_rm(pid_file);
	}

	/* What should we return - we don't know if it is running or not. */
	if (!pid)
		return true;

	/* If no process is attached to pidfile, remove it */
	if (kill(pid, 0)) {
		log_message(LOG_INFO, "Remove a zombie pid file %s", pid_file);
		pidfile_rm(pid_file);
		return false;
	}

	return true;
}

/* Return parent process daemon state */
bool
keepalived_running(unsigned long mode)
{
	if (process_running(main_pidfile))
		return true;
#ifdef _WITH_VRRP_
	if (__test_bit(DAEMON_VRRP, &mode) && process_running(vrrp_pidfile))
		return true;
#endif
#ifdef _WITH_LVS_
	if (__test_bit(DAEMON_CHECKERS, &mode) && process_running(checkers_pidfile))
		return true;
#endif
#ifdef _WITH_BFD_
	if (__test_bit(DAEMON_BFD, &mode) && process_running(bfd_pidfile))
		return true;
#endif
	return false;
}
