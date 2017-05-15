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
 * Copyright (C) 2016-2016 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef VRRP_DBUS_H
#define VRRP_DBUS_H

#include <stdbool.h>

/* Local includes */
#include "vrrp.h"
#include "list.h"

/* Defines */
#define DBUS_SERVICE_NAME                       "org.keepalived.Vrrp1"
#define DBUS_VRRP_INTERFACE                     "org.keepalived.Vrrp1.Vrrp"
#define DBUS_VRRP_OBJECT_ROOT                   "/org/keepalived/Vrrp1"
#define DBUS_VRRP_INSTANCE_PATH_DEFAULT_LENGTH  8
#define DBUS_VRRP_INSTANCE_INTERFACE            "org.keepalived.Vrrp1.Instance"
#define DBUS_VRRP_INTERFACE_FILE_PATH           "/usr/share/dbus-1/interfaces/org.keepalived.Vrrp1.Vrrp.xml"
#define DBUS_VRRP_INSTANCE_INTERFACE_FILE_PATH  "/usr/share/dbus-1/interfaces/org.keepalived.Vrrp1.Instance.xml"

void dbus_send_state_signal(vrrp_t *);
void dbus_remove_object(vrrp_t *);
void dbus_reload(list, list);
bool dbus_start(void);
void dbus_stop(void);

#endif
