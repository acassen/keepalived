/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Dynamic data structure definition.
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

#ifndef _VRRP_SOCK_H
#define _VRRP_SOCK_H

/* system includes */
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>

/* local includes */
#include "scheduler.h"
#include "vrrp_if.h"

/*
 * Our instance dispatcher use a socket pool.
 * That way we handle VRRP protocol type per
 * physical interface.
 */
typedef struct _sock {
	sa_family_t		family;
	int			proto;
	interface_t		*ifp;
	bool			unicast;
	int			fd_in;
	int			fd_out;
	int			rx_buf_size;
	thread_ref_t		thread;
	rb_root_t		rb_vrid;
	rb_root_cached_t	rb_sands;
} sock_t;

#endif
