/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        track_process.c include file.
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
 * Copyright (C) 2018-2018 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_TRACK_PROCESS_H
#define _VRRP_TRACK_PROCESS_H

/* global includes */
#include <stdbool.h>

/* local includes */
#include "list.h"
#include "vrrp.h"

#ifdef _TRACK_PROCESS_DEBUG_
extern bool do_track_process_debug;
extern bool do_track_process_debug_detail;
#endif
extern bool proc_events_not_supported;

/* prototypes */
extern void reload_track_processes(void);
extern bool open_track_processes(void);
extern bool close_track_processes(void);
extern bool init_track_processes(list);
extern void end_process_monitor(void);
#ifdef THREAD_DUMP
extern void register_process_monitor_addresses(void);
#endif

#endif
