/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_daemon.c include file.
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

#ifndef _CHECK_DAEMON_H
#define _CHECK_DAEMON_H

/* system include */
#include <stdbool.h>

/* Daemon define */
#define PROG_CHECK	"Keepalived_healthcheckers"

/* Global data */
extern bool using_ha_suspend;

/* Prototypes */
extern int start_check_child(void);
extern void check_validate_config(void);
#ifdef THREAD_DUMP
extern void register_check_parent_addresses(void);
#endif

#endif
