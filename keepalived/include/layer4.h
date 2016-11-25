/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        layer4.c include file.
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

#ifndef _LAYER4_H
#define _LAYER4_H

/* system includes */
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

/* local includes */
#include "scheduler.h"
#include "check_api.h"

enum connect_result {
	connect_error,
	connect_in_progress,
	connect_timeout,
	connect_success
};

/* Prototypes defs */
extern enum connect_result
 socket_bind_connect(int, conn_opts_t *);

extern enum connect_result
 socket_connect(int, struct sockaddr_storage *);

extern enum connect_result
 socket_state(thread_t *, int (*func) (thread_t *));

extern int
 socket_connection_state(int, enum connect_result
		      , thread_t *, int (*func) (thread_t *)
		      , unsigned long);

/* Backward compatibility */
static inline enum connect_result
tcp_bind_connect(int fd, conn_opts_t *co)
{
	return socket_bind_connect(fd, co);
}

static inline enum connect_result
tcp_connect(int fd, struct sockaddr_storage *addr)
{
	return socket_connect(fd, addr);
}

static inline enum connect_result
tcp_socket_state(thread_t * thread, int (*func) (thread_t *))
{
	return socket_state(thread, func);
}

static inline int
tcp_connection_state(int fd, enum connect_result status, thread_t * thread,
             int (*func) (thread_t *), unsigned long timeout)
{
	return socket_connection_state(fd, status, thread, func, timeout);
}
#endif
