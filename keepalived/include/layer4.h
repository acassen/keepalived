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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _LAYER4_H
#define _LAYER4_H

/* system includes */
#include <sys/socket.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>

/* local includes */
#include "scheduler.h"


enum connect_result {
	connect_error,
	connect_in_progress,
	connect_timeout,
	connect_fail,
	connect_success,
	connect_result_next
};

/* connection options structure definition */
typedef struct _conn_opts {
	struct sockaddr_storage		dst;
	struct sockaddr_storage		bindto;
	char				bind_if[IFNAMSIZ];
	unsigned int			connection_to; /* connection time-out */
#ifdef _WITH_SO_MARK_
	unsigned int			fwmark; /* to mark packets going out of the socket using SO_MARK */
#endif
	int				last_errno;	/* Errno from last call to connect */
} conn_opts_t;

/* Prototypes defs */
#ifdef _WITH_LVS_
extern void set_buf(char *, size_t);
extern enum connect_result
socket_bind_connect(int, conn_opts_t *);
#endif

extern enum connect_result
socket_connect(int, const struct sockaddr_storage *);

extern enum connect_result
socket_state(thread_ref_t, thread_func_t, unsigned);

#ifdef _WITH_LVS_
extern bool
socket_connection_state(int, enum connect_result
		      , thread_ref_t, thread_func_t
		      , unsigned long, unsigned);
#endif

/* Backward compatibility */
#ifdef _WITH_LVS_
static inline enum connect_result
tcp_bind_connect(int fd, conn_opts_t *co)
{
	return socket_bind_connect(fd, co);
}
#endif

static inline enum connect_result
tcp_connect(int fd, const struct sockaddr_storage *addr)
{
	return socket_connect(fd, addr);
}

static inline enum connect_result
tcp_socket_state(thread_ref_t thread, thread_func_t func, unsigned extra_flags)
{
	return socket_state(thread, func, extra_flags);
}

#ifdef _WITH_LVS_
static inline bool
tcp_connection_state(int fd, enum connect_result status, thread_ref_t thread,
		     thread_func_t func, unsigned long timeout, unsigned flags)
{
	return socket_connection_state(fd, status, thread, func, timeout, flags);
}

extern enum connect_result udp_bind_connect(int, conn_opts_t *, uint8_t *, uint16_t);
extern enum connect_result udp_socket_state(int, thread_ref_t, uint8_t *, size_t *);
extern bool udp_icmp_check_state(int, enum connect_result, thread_ref_t, thread_func_t, unsigned long);
#endif

#endif
