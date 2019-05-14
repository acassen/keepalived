/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_dbus.c include file.
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
 * Copyright (C) 2016-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef VRRP_DBUS_H
#define VRRP_DBUS_H

/* System includes */
#include <stdbool.h>

/* Local includes */
#include "vrrp.h"
#include "list.h"


void dbus_send_state_signal(vrrp_t *);
void dbus_remove_object(const vrrp_t *);
void dbus_reload(const list, const list);
bool dbus_start(void);
void dbus_stop(void);
#ifdef THREAD_DUMP
extern void register_vrrp_dbus_addresses(void);
#endif

#endif
