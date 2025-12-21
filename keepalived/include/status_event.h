/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Status event structure for IPC between child daemons
 *              and parent process status socket.
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
 * Copyright (C) 2001-2024 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _STATUS_EVENT_H
#define _STATUS_EVENT_H

#include "config.h"

#ifdef _WITH_STATUS_SOCKET_

#include <stdint.h>
#include <stdbool.h>
#include "timer.h"

/* Daemon types for status events */
#define STATUS_DAEMON_VRRP	1
#define STATUS_DAEMON_CHECKER	2
#define STATUS_DAEMON_BFD	3

/* Overall daemon states */
#define STATUS_STATE_INIT	0
#define STATUS_STATE_UP		1
#define STATUS_STATE_DOWN	2
#define STATUS_STATE_FAULT	3

/*
 * Status event structure sent from child daemons to parent.
 * Children write this to their status pipe on state changes.
 * Parent reads and aggregates for unified health reporting.
 */
typedef struct _status_event {
	uint8_t		daemon_type;	/* STATUS_DAEMON_VRRP, etc. */
	uint8_t		overall_state;	/* STATUS_STATE_* */
	uint8_t		pad[2];		/* Alignment padding */
	uint32_t	num_instances;	/* Total instance count */
	uint32_t	num_fault;	/* Instances in fault state */
	uint32_t	num_master;	/* VRRP only: instances in MASTER */
	timeval_t	sent_time;	/* Timestamp for latency tracking */
} status_event_t;

/* Status pipes - one per daemon type, defined in status_socket.c */
#ifdef _WITH_VRRP_
extern int status_vrrp_pipe[2];
#endif
#ifdef _WITH_LVS_
extern int status_checker_pipe[2];
#endif
#ifdef _WITH_BFD_
extern int status_bfd_pipe[2];
#endif

/* Functions for child daemons to send status updates */
extern void status_send_vrrp_event(uint8_t state, uint32_t num_inst,
				   uint32_t num_fault, uint32_t num_master);
extern void status_send_checker_event(uint8_t state, uint32_t num_inst,
				      uint32_t num_fault);
extern void status_send_bfd_event(uint8_t state, uint32_t num_inst,
				  uint32_t num_fault);

#endif /* _WITH_STATUS_SOCKET_ */

#endif /* _STATUS_EVENT_H */
