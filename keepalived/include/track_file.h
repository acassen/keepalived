/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        track_file.c include file.
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
 * Copyright (C) 2001-2020 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _TRACK_FILE_H
#define _TRACK_FILE_H

/* global includes */
#include <stdbool.h>
#include <stdio.h>

/* local includes */
#include "list.h"
#ifdef _WITH_VRRP_
#include "vrrp.h"
#endif
#include "tracker.h"

/* external file we read to track local processes */
typedef struct _tracked_file {
	const char		*fname;		/* File name */
	const char		*file_path;	/* Path to file */
	const char		*file_part;	/* Pointer to start of filename without directories */
	int			weight;		/* Default weight */
	bool			weight_reverse;	/* which direction is the weight applied */
	int			wd;		/* Watch descriptor */
	list			tracking_obj;	/* List of tracking_obj_t for vrrp instances/real servers tracking this file */
	int			last_status;	/* Last status returned by file. Used to report changes */
} tracked_file_t;

/* Tracked file structure definition */
typedef struct _tracked_file_monitor {
	tracked_file_t		*file;		/* track file pointer, cannot be NULL */
	int			weight;		/* Multiplier for file value */
	bool			weight_reverse;	/* which direction is the weight applied */
} tracked_file_monitor_t;

extern list alloc_track_file_list(void);
extern tracked_file_t * __attribute__ ((pure)) find_tracked_file_by_name(const char *, list);
extern void vrrp_alloc_track_file(const char *, list, list, const vector_t *);
extern void add_track_file_keywords(bool active);

extern void free_track_file_list(void *);
extern void dump_track_file_list(FILE *, const void *);

extern void add_obj_to_track_file(void *, tracked_file_monitor_t *, const char *, void (*)(FILE *, const void *));

extern void init_track_files(list);
extern void stop_track_files(void);

#ifdef THREAD_DUMP
extern void register_track_file_inotify_addresses(void);
#endif

#endif
