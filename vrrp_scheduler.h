/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_scheduler.c include file.
 * 
 * Version:     $Id: vrrp_scheduler.h,v 0.5.3 2002/02/24 23:50:11 acassen Exp $
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

#ifndef _VRRP_SCHEDULER_H
#define _VRRP_SCHEDULER_H

/* system include */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h>

/* local include */
#include "scheduler.h"
#include "data.h"

/*
 * Our instance dispatcher use a socket pool.
 * That way we handle VRRP protocole type per
 * physical interface.
 */
typedef struct {
  int ifindex;
  int proto;
  int fd;
} sock;

/* extern prototypes */
extern int open_vrrp_socket(const int proto, const int index);
extern int ifname_to_idx(const char *ifname);
extern void vrrp_send_gratuitous_arp(vrrp_instance *vrrp_instance);
extern int vrrp_read_dispatcher_thread(thread *thread);
extern int vrrp_state_master_rx(vrrp_instance *instance, char *buf, int buflen);
extern void vrrp_state_master_tx(vrrp_instance *instance, const int prio);
extern void vrrp_state_backup(vrrp_instance *instance, char *buf, int buflen);
extern void vrrp_state_goto_master(vrrp_instance *vrrp_instance);
extern void vrrp_state_leave_master(vrrp_instance *instance);

#endif
