/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        old_socket.c
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
 * Copyright (C) 2001-2016 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "old_socket.h"
#include "logger.h"

bool set_sock_flags(int fd, int cmd, long flags)
{
	/* This is slightly odd. The man page for fcntl says that the
	   parameter passed to F_SETFD/F_SETFL is a long, but fnctl
	   only returns an int to F_GETFD/F_GETFL */
	long sock_flags;
	int get_cmd = (cmd == F_SETFD) ? F_GETFD : F_GETFL;

	if ((sock_flags = fcntl(fd, get_cmd)) == -1) {
		log_message(LOG_INFO, "Netlink: Cannot get socket flags : (%s)", strerror(errno));
		return true;
	}

	if (fcntl(fd, cmd, sock_flags | flags) < 0) {
		log_message(LOG_INFO, "Netlink: Cannot set socket flags: (%s)", strerror(errno));
		return true;
	}

	return false;
}
