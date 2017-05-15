/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_scheduler.c include file.
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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_SCHEDULER_H
#define _VRRP_SCHEDULER_H

/* system include */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>

/* local includes */
#include "scheduler.h"
#include "list.h"
#include "vrrp_data.h"

/* global vars */
extern timeval_t garp_next_time;
extern thread_t *garp_thread;

/* VRRP FSM Macro */
#define VRRP_FSM_READ_TO(V)			\
do {						\
  if ((*(VRRP_FSM[(V)->state].read_timeout)))	\
    (*(VRRP_FSM[(V)->state].read_timeout)) (V);	\
} while (0)

#define VRRP_FSM_READ(V, B, L)			\
do {						\
  if ((*(VRRP_FSM[(V)->state].read)))		\
    (*(VRRP_FSM[(V)->state].read)) (V, B, L);	\
} while (0)

/* VRRP TSM Macro */
#define VRRP_TSM_HANDLE(S,V)			\
do {						\
  if ((V)->sync &&				\
      S != VRRP_STATE_GOTO_MASTER)		\
    if ((*(VRRP_TSM[S][(V)->state].handler)))	\
      (*(VRRP_TSM[S][(V)->state].handler)) (V);	\
} while (0)

/* extern prototypes */
extern int vrrp_dispatcher_init(thread_t *);
extern void vrrp_dispatcher_release(vrrp_data_t *);
extern int vrrp_lower_prio_gratuitous_arp_thread(thread_t *);
extern void vrrp_set_effective_priority(vrrp_t *, uint8_t);
extern bool vrrp_child_finder(pid_t, char const **);
extern int vrrp_arp_thread(thread_t *);

#endif
