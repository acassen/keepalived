/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_scheduler.c include file.
 * 
 * Version:     $Id: vrrp_scheduler.h,v 0.5.9 2002/05/30 16:05:31 acassen Exp $
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
#include "vrrp.h"

/*
 * Our instance dispatcher use a socket pool.
 * That way we handle VRRP protocol type per
 * physical interface.
 */
typedef struct {
  int ifindex;
  int proto;
  int fd;
} sock;

/* VRRP FSM Macro */
#define VRRP_FSM_READ_TO(V) \
do { \
  if ((*(FSM[(V)->state].read_to))) \
    (*(FSM[(V)->state].read_to)) (V); \
} while (0)

#define VRRP_FSM_READ(V, B, L) \
do { \
  if ((*(FSM[(V)->state].read))) \
    (*(FSM[(V)->state].read)) (V, B, L); \
} while (0)

/* extern prototypes */
extern int vrrp_read_dispatcher_thread(thread *thread);

#endif
