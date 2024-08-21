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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
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

void
pidfile_close(pidfile_t *pidf, bool free_path)
{
	if (pidf->fd == -1)
		return;

	close(pidf->fd);
	pidf->fd = -1;

	if (free_path && pidf->free_path) {
		FREE_CONST_PTR(pidf->path);
		pidf->path = NULL;
		pidf->free_path = false;
	}
}

/* Remove the running daemon pidfile */
void
pidfile_rm(pidfile_t *pidf)
{
	unlink(pidf->path);
	if (pidf->fd != -1)
		pidfile_close(pidf, true);
}

void
close_other_pidfiles(void)
{
	if (prog_type != PROG_TYPE_PARENT)
		pidfile_close(&main_pidfile, true);

#ifdef _WITH_VRRP_
	if (prog_type != PROG_TYPE_VRRP)
		pidfile_close(&vrrp_pidfile, true);
#endif

#ifdef _WITH_LVS_
	if (prog_type != PROG_TYPE_CHECKER)
		pidfile_close(&checkers_pidfile, true);
#endif

#ifdef _WITH_BFD_
	if (prog_type != PROG_TYPE_BFD)
		pidfile_close(&bfd_pidfile, true);
#endif
}

/* return the daemon running state */
static bool
create_pidfile(pidfile_t *pidf)
{
	struct stat st, fd_st;
	int error;
	int ret;
	struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0 };

	for (;;) {
		/* We want to create the file with permissions rw-r--r-- */
		if (umask_val & (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))
			umask(umask_val & ~(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));

		while ((pidf->fd = open(pidf->path, O_NOFOLLOW | O_CREAT | O_WRONLY | O_NONBLOCK, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1 && errno == EINTR);
		error = errno;

		/* Restore the default umask */
		if (umask_val & (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))
			umask(umask_val);

		if (pidf->fd == -1) {
			errno = error;
			return true;
		}

		fl.l_pid = 0;
		while ((ret = fcntl(pidf->fd, F_OFD_SETLK, &fl)) && errno == EINTR);
		if (ret) {
			if (errno == EAGAIN)
				log_message(LOG_INFO, "Another process has pid file %s locked", pidf->path);
			else
				log_message(LOG_INFO, "Locking pid file %s error %d - %m", pidf->path, errno);

			break;
		}

		/* Make sure the file has not been removed/moved */
		if (stat(pidf->path, &st)) {
			close(pidf->fd);
			pidf->fd = -1;
			continue;
		}

		if (fstat(pidf->fd, &fd_st)) {
			/* This should not happen since we have the file open */
			break;
		}

		if (st.st_dev != fd_st.st_dev ||
		    st.st_ino != fd_st.st_ino) {
			/* A new file with the same name has been created */
			close(pidf->fd);
			pidf->fd = -1;
			continue;
		}

		while ((ret = ftruncate(pidf->fd, 0)) && errno == EINTR);
		if (ret) {
			/* This should not happen */
			break;
		}

		/* pid file is now opened, locked and 0 length */
		return false;
	}

	if (pidf->fd != -1) {
		close(pidf->fd);
		pidf->fd = -1;
	}

	return true;
}

/* Return parent process daemon state */
bool
keepalived_running(unsigned long mode)
{
	if (create_pidfile(&main_pidfile))
		return true;
#ifdef _WITH_VRRP_
	if (__test_bit(DAEMON_VRRP, &mode) && create_pidfile(&vrrp_pidfile))
		return true;
#endif
#ifdef _WITH_LVS_
	if (__test_bit(DAEMON_CHECKERS, &mode) && create_pidfile(&checkers_pidfile))
		return true;
#endif
#ifdef _WITH_BFD_
	if (__test_bit(DAEMON_BFD, &mode) && create_pidfile(&bfd_pidfile))
		return true;
#endif
	return false;
}

/* Create the running daemon pidfile */
bool
pidfile_write(pidfile_t *pidf)
{
	int ret;

	/* If keepalived originally started with no configuration for this process,
	 * the process won't have originally been started, and the parent process
	 * will not have created and opened a pid file. This means that pidf->fd
	 * could be -1 after a reload. */
	if (!children_started && pidf->fd == -1)
		return false;

	if (children_started) {
		struct stat statb, fstatb;

		/* There could be more error handling, but that will just
		 * complicate the code for minimal benefit. */
		if (stat(pidf->path, &statb)) {
			/* pidfile no longer exists */
			if (pidf->fd != -1)
				close(pidf->fd);
			create_pidfile(pidf);
		} else {
			if (pidf->fd == -1 ||
			    fstat(pidf->fd, &fstatb) ||
			    statb.st_dev != fstatb.st_dev ||
			    statb.st_ino != fstatb.st_ino) {
				if (pidf->fd != -1) {
					/* The pidfile has been deleted and recreated. Open the new one. */
					close(pidf->fd);
				}

				while ((pidf->fd = open(pidf->path, O_NOFOLLOW | O_WRONLY | O_NONBLOCK)) == -1 && errno == EINTR);

				if (pidf->fd == -1)
					return false;
			}

			/* Since we may have already written to the pid file,
			 * we need to reset the file offset and truncate the file. */
			lseek(pidf->fd, 0, SEEK_SET);
			if (ftruncate(pidf->fd, 0))
				log_message(LOG_INFO, "ftruncate error %d - %m", errno);
		}
	}

	ret = dprintf(pidf->fd, "%d\n", getpid());

	if (ret < 0)
		log_message(LOG_INFO, "pidfile_write returned %d, errno %d - %m", ret, errno);
	else
		log_message(LOG_INFO, "pidfile_write returned %d", ret);

	return true;
}
