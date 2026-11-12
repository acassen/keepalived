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
#include "process.h"
#include "global_data.h"

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
make_pidfile_name(const char* fname, const char* extn)
{
	size_t len;
	char *name;
	char *ptr;
	const char *dir;

	dir = !use_pid_dir && !global_data->instance_name ? RUNSTATEDIR "/" : pid_dir ? pid_dir : KEEPALIVED_PID_DIR;

	len = strlen(dir) + strlen(fname) + 1;
	if (global_data->instance_name)
		len += strlen(global_data->instance_name) + 1;
	if (extn)
		len += strlen(extn);

	name = MALLOC(len);
	if (!name) {
		log_message(LOG_INFO, "Unable to make pidfile name for %s%s", dir, fname);
		return NULL;
	}

	ptr = stpcpy(name, dir);
	ptr = stpcpy(ptr, fname);
	if (global_data->instance_name) {
		*ptr++ = '_';
		ptr = stpcpy(ptr, global_data->instance_name);
	}
	if (extn)
		stpcpy(ptr, extn);

	return name;
}

void
pidfile_close(pidfile_t *pidf)
{
	FREE_CONST_PTR(pidf->path);
	pidf->path = NULL;

	if (pidf->fd == -1)
		return;

	close(pidf->fd);
	pidf->fd = -1;
}

/* Remove the running daemon pidfile */
void
pidfile_rm(pidfile_t *pidf)
{
	unlink(pidf->path);
	if (pidf->fd != -1)
		pidfile_close(pidf);
}

void
close_other_pidfiles(void)
{
#ifndef _ONE_PROCESS_DEBUG_
	if (prog_type != PROG_TYPE_PARENT)
		pidfile_close(&main_pidfile);

#ifdef _WITH_VRRP_
	if (prog_type != PROG_TYPE_VRRP)
		pidfile_close(&vrrp_pidfile);
#endif

#ifdef _WITH_LVS_
	if (prog_type != PROG_TYPE_CHECKER)
		pidfile_close(&checkers_pidfile);
#endif

#ifdef _WITH_BFD_
	if (prog_type != PROG_TYPE_BFD)
		pidfile_close(&bfd_pidfile);
#endif
#endif
}

/* return the daemon running state */
static bool
create_pidfile(pidfile_t *pidf)
{
	struct stat st, fd_st;
	int error;
	int ret;
#if HAVE_DECL_F_OFD_SETLK == 1
	struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0 };
#endif

	/* Have we already got the PID file open and locked? */
	if (pidf->fd != -1)
		return false;

	for (;;) {
		/* We want to create the file with permissions rw-r--r-- */
		if (umask_val & (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))
			umask(umask_val & ~(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));

		while ((pidf->fd = open(pidf->path, O_NOFOLLOW | O_CREAT | O_WRONLY | O_NONBLOCK | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1 && errno == EINTR);
		error = errno;

		/* Restore the default umask */
		if (umask_val & (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))
			umask(umask_val);

		if (pidf->fd == -1) {
			errno = error;
			return true;
		}

#if HAVE_DECL_F_OFD_SETLK == 1
		fl.l_pid = 0;
		while ((ret = fcntl(pidf->fd, F_OFD_SETLK, &fl)) && errno == EINTR);
		if (ret) {
			if (errno == EAGAIN)
				log_message(LOG_INFO, "Another process has pid file %s locked", pidf->path);
			else
				log_message(LOG_INFO, "Locking pid file %s error %d - %m", pidf->path, errno);

			break;
		}
#endif

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
keepalived_running(void)
{
	if (create_pidfile(&main_pidfile)) {
		log_message(LOG_INFO, "Unable to acquire lock of main pidfile");
		return true;
	}

#ifdef _WITH_VRRP_
	if (running_vrrp() &&
	    create_pidfile(&vrrp_pidfile)) {
		log_message(LOG_INFO, "Unable to acquire lock of VRRP pidfile");
		return true;
	}
#endif

#ifdef _WITH_LVS_
	if (running_checker() &&
	    create_pidfile(&checkers_pidfile)) {
		log_message(LOG_INFO, "Unable to acquire lock of checkers pidfile");
		return true;
	}
#endif

#ifdef _WITH_BFD_
	if (running_bfd() &&
	    create_pidfile(&bfd_pidfile)) {
		log_message(LOG_INFO, "Unable to acquire lock of BFD pidfile");
		return true;
	}
#endif

	return false;
}

/* Create the running daemon pidfile */
bool
pidfile_write(pidfile_t *pidf)
{
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

			if (pidf->fd == -1)
				return false;
		} else {
			if (pidf->fd == -1 ||
			    fstat(pidf->fd, &fstatb) ||
			    statb.st_dev != fstatb.st_dev ||
			    statb.st_ino != fstatb.st_ino) {
				if (pidf->fd != -1) {
					/* The pidfile has been deleted and recreated. Open the new one. */
					close(pidf->fd);
				}

				/* There is a window where the pid file could be deleted between us closing it and re-opening it,
				 * so allow for creating the pidfile again. */
				create_pidfile(pidf);

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

	dprintf(pidf->fd, "%d\n", our_pid);

	return true;
}
