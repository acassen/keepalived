/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        systemd interface include file.
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
 * Copyright (C) 2020-2020 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_SYSTEM_H
#define _VRRP_SYSTEM_H

#include "config.h"

/* global includes */
#include <stdbool.h>

extern bool check_parent_systemd(void);
extern void systemd_notify_running(void);
extern void systemd_notify_error(int);
extern void systemd_notify_reloading(void);
extern void systemd_notify_stopping(void);
extern void systemd_unset_notify(void);

#endif
