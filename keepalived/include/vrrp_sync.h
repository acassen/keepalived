/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_sync.c include file.
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

#ifndef _VRRP_SYNC_H
#define _VRRP_SYNC_H

/* local include */
#include "vrrp.h"

/* TSM size */
#define VRRP_MAX_TSM_STATE	3

/* MACRO definition */
#define GROUP_STATE(G) ((G)->state)
#define GROUP_NAME(G)  ((G)->gname)

/* extern prototypes */
extern vrrp_t *vrrp_get_instance(char *) __attribute__ ((pure));
extern void vrrp_sync_set_group(vrrp_sgroup_t *);
extern bool vrrp_sync_can_goto_master(vrrp_t *);
extern void vrrp_sync_backup(vrrp_t *);
extern void vrrp_sync_master(vrrp_t *);
extern void vrrp_sync_fault(vrrp_t *);

#endif
