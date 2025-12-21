/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        status_socket.c include file.
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
 * Copyright (C) 2001-2024 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _STATUS_SOCKET_H
#define _STATUS_SOCKET_H

#include "config.h"

#ifdef _WITH_STATUS_SOCKET_

/* System includes */
#include <stdbool.h>

/* Local includes */
#include "scheduler.h"

extern bool status_socket_init(thread_master_t *);
extern void status_socket_close(void);

#ifdef THREAD_DUMP
extern void register_status_socket_addresses(void);
#endif

#endif /* _WITH_STATUS_SOCKET_ */

#endif /* _STATUS_SOCKET_H */
