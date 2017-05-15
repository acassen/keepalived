/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_tcp.c include file.
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

#ifndef _CHECK_TCP_H
#define _CHECK_TCP_H

/* system includes */
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

/* local includes */
#include "scheduler.h"

typedef struct _tcp_check {
	unsigned	n_retry;
	unsigned long	delay_before_retry;
	unsigned	retry_it;
} tcp_check_t;

/* macro utility */
#define FMT_TCP_RS(C) FMT_CHK(C)

/* Prototypes defs */
extern void install_tcp_check_keyword(void);

#endif
