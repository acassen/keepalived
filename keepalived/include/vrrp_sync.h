/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_sync.c include file.
 * 
 * Version:     $Id: vrrp_sync.h,v 0.6.9 2002/07/31 01:33:12 acassen Exp $
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

/* MACRO definition */
#define GROUP_STATE(G) ((G)->state)
#define GROUP_NAME(G)  ((G)->gname)

/* extern prototypes */
extern vrrp_sgroup *vrrp_get_sync_group(char *iname);
extern int vrrp_sync_group_up(vrrp_sgroup * vgroup);
extern int vrrp_sync_leave_fault(vrrp_rt * vrrp);
extern void vrrp_sync_read_to(vrrp_rt * vrrp, int prev_state);
extern void vrrp_sync_read(vrrp_rt * vrrp, int prev_state);

#endif
