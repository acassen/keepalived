/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_bfd.c include file.
 *
 * Author:      Quentin Armitage <quentin@armitage.org.uk>
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

#ifndef _CHECK_BFD_H
#define _CHECK_BFD_H

#include "scheduler.h"
#include "check_data.h"

/* external bfd we read to track forwarding to remote systems */
typedef struct _checker_bfd {
	char			*bname;		/* bfd name */
//	int			weight;		/* Default weight */
	list			tracking_rs;	/* List of checker_t */
} checker_tracked_bfd_t;

///* List structure from bfds to tracking rs */
//typedef struct _tracking_checker_bfd {
////	int			weight;		/* Tracking weight, or zero for down instance */
//	checker_t		*checker;	/* The real server */
//} tracking_rs_t;

///* Tracked bfd structure definition */
//typedef struct _tracked_bfd {
//	checker_tracked_bfd_t	*bfd;		/* track bfd pointer, cannot be NULL */
////	int			weight;		/* Weight for bfd */
//} tracked_bfd_t;

/* bfd_checker structure */
typedef struct _bfd_checker {
	checker_tracked_bfd_t	*bfd;		/* track bfd pointer, cannot be NULL */
//	int			weight;		// Set in bfd_weight_handler
} bfd_checker_t;

/* Prototypes defs */
extern void install_bfd_check_keyword(void);
extern void start_bfd_monitoring(thread_master_t *);
extern void checker_bfd_dispatcher_release(void);
#ifdef THREAD_DUMP
extern void register_check_bfd_addresses(void);
#endif

#endif
