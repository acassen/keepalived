/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_udp.c include file.
 *
 * Author:      Jie Liu, <liujie165@huawei.com>
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
 * Copyright (C) 2019-2019 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _CHECK_UDP_H
#define _CHECK_UDP_H

#include "config.h"


typedef struct _udp_check {
	bool	require_reply;
} udp_check_t;

/* Prototypes defs */
extern void install_udp_check_keyword(void);
#ifdef THREAD_DUMP
extern void register_check_udp_addresses(void);
#endif

#endif
