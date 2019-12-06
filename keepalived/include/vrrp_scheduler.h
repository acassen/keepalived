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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_SCHEDULER_H
#define _VRRP_SCHEDULER_H

/* system include */
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>

/* local includes */
#include "scheduler.h"
#include "timer.h"
#include "vrrp_data.h"
#include "vrrp.h"

/* global vars */
extern timeval_t garp_next_time;
extern thread_ref_t garp_thread;
extern bool vrrp_initialised;

/* VRRP TSM Macro */
#define VRRP_TSM_HANDLE(S,V)			\
do {						\
  if ((V)->sync &&				\
      (*(VRRP_TSM[S][(V)->state].handler)))	\
      (*(VRRP_TSM[S][(V)->state].handler)) (V);	\
} while (0)

#ifdef _TSM_DEBUG_
extern bool do_tsm_debug;
#endif

/* extern prototypes */
extern void vrrp_init_instance_sands(vrrp_t *);
extern void vrrp_thread_requeue_read(vrrp_t *);
extern void vrrp_thread_add_read(vrrp_t *);
extern int vrrp_dispatcher_init(thread_ref_t);
#ifdef _WITH_BFD_
extern void cancel_vrrp_threads(void);
#endif
extern void vrrp_dispatcher_release(vrrp_data_t *);
extern int vrrp_gratuitous_arp_thread(thread_ref_t);
extern int vrrp_lower_prio_gratuitous_arp_thread(thread_ref_t);
extern int vrrp_arp_thread(thread_ref_t);
extern void try_up_instance(vrrp_t *, bool);
#ifdef _WITH_DUMP_THREADS_
extern void dump_threads(void);
#endif
#ifdef THREAD_DUMP
extern void register_vrrp_scheduler_addresses(void);
#endif

#endif
