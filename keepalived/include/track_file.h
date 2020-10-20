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
#include <stdint.h>

/* local includes */
#include "list_head.h"
#ifdef _WITH_VRRP_
#include "vrrp.h"
#endif
#include "tracker.h"

/* external file we read to track local processes */
typedef void (*obj_dump_func_t) (FILE *, const void *);
typedef struct _tracked_file {
	const char		*fname;		/* File name */
	const char		*file_path;	/* Path to file */
	const char		*file_part;	/* Pointer to start of filename without directories */
	int			weight;		/* Default weight */
	bool			weight_reverse;	/* which direction is the weight applied */
	int			wd;		/* Watch descriptor */
	list_head_t		tracking_obj;	/* tracking_obj_t - for vrrp instances/real servers tracking this file */
	obj_dump_func_t		tracking_obj_dump; /* Dump helper for tracking_obj list */
	int64_t			last_status;	/* Last status returned by file. Used to report changes */
	bool			reloaded;	/* Set if this track_file existing in previous config */

	/* linked list member */
	list_head_t		e_list;
} tracked_file_t;

/* Tracked file structure definition */
typedef struct _tracked_file_monitor {
	tracked_file_t		*file;		/* track file pointer, cannot be NULL */
	int			weight;		/* Multiplier for file value */
	bool			weight_reverse;	/* which direction is the weight applied */

	/* linked list member */
	list_head_t		e_list;
} tracked_file_monitor_t;

static inline int
weight_range(int64_t weight_long)
{
	if (weight_long < INT_MIN)
		return INT_MIN;
	if (weight_long > INT_MAX)
		return INT_MAX;
	return weight_long;
}

extern void dump_track_file_monitor_list(FILE *, const list_head_t *);
extern void free_track_file_monitor(tracked_file_monitor_t *);
extern void free_track_file_monitor_list(list_head_t *);

extern tracked_file_t * __attribute__ ((pure)) find_tracked_file_by_name(const char *, list_head_t *);
extern void vrrp_alloc_track_file(const char *, list_head_t *, list_head_t *, const vector_t *);
extern void add_track_file_keywords(bool active);

extern void free_tracking_obj_list(list_head_t *);
extern void dump_tracking_obj_list(FILE *fp, const list_head_t *, obj_dump_func_t);

extern void free_track_file_list(list_head_t *);
extern void dump_track_file_list(FILE *, const list_head_t *);

extern void add_obj_to_track_file(void *, tracked_file_monitor_t *, const char *, obj_dump_func_t);

extern void process_update_checker_track_file_status(const tracked_file_t *, int, const tracking_obj_t *);

extern void init_track_files(list_head_t *);
extern void stop_track_files(void);

#ifdef THREAD_DUMP
extern void register_track_file_inotify_addresses(void);
#endif

#endif
