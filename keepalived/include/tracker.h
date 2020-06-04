/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        tracker.h include file
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

#ifndef _TRACKER_H
#define _TRACKER_H

/* local includes */
#include "list_head.h"
#ifdef _WITH_VRRP_
#include "vrrp.h"
#endif
#ifdef _WITH_LVS_
#include "check_api.h"
#endif

typedef enum {
	TRACK_VRRP = 0x01,
	TRACK_IF = 0x02,
	TRACK_SG = 0x04,
	TRACK_ADDR = 0x08,
	TRACK_ROUTE = 0x10,
	TRACK_RULE = 0x20,
	TRACK_SADDR = 0x40,
	TRACK_SROUTE = 0x80,
	TRACK_SRULE = 0x100,
	TRACK_VRRP_DYNAMIC = 0x200,
	TRACK_CHECKER = 0x400,
} track_t;

typedef union {
	void *obj;
#ifdef _WITH_VRRP_
	struct _vrrp_t	*vrrp;			/* vrrp instance */
#endif
#ifdef _WITH_LVS_
	checker_t	*checker;		/* checker instance */
#endif
} tracking_obj_p;

/* List structure from scripts, files and interfaces to tracking vrrp */
typedef struct _tracking_obj {
	int			weight;		/* Tracking weight, or zero for down instance */
	int			weight_multiplier; /* Which direction is weight applied */
	tracking_obj_p		obj;		/* The object tracking this */
	track_t			type;		/* Type of object being tracked */

	/* linked list member */
	list_head_t		e_list;
} tracking_obj_t;

static inline void
free_tracking_obj(tracking_obj_t *obj)
{
	list_del_init(&obj->e_list);
	FREE(obj);
}

#endif
