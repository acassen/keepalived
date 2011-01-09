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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

#ifndef _VRRP_SYNC_H
#define _VRRP_SYNC_H

/* system include */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h>

/* local include */
#include "vrrp.h"

/* TSM size */
#define VRRP_MAX_TSM_STATE	3

/* MACRO definition */
#define GROUP_STATE(G) ((G)->state)
#define GROUP_NAME(G)  ((G)->gname)

/* extern prototypes */
extern void vrrp_init_instance_sands(vrrp_rt *);
extern void vrrp_sync_smtp_notifier(vrrp_sgroup *);
extern void vrrp_sync_set_group(vrrp_sgroup *);
extern int vrrp_sync_group_up(vrrp_sgroup *);
extern int vrrp_sync_leave_fault(vrrp_rt *);
extern void vrrp_sync_backup(vrrp_rt *);
extern void vrrp_sync_master(vrrp_rt *);
extern void vrrp_sync_master_election(vrrp_rt *);
extern void vrrp_sync_fault(vrrp_rt *);

#endif
