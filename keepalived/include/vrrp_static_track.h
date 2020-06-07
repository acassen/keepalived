/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_static_track.c include file.
 *
 * Author:      Quentin Armitage, <quentin@armitage.org.uk>
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

#ifndef _VRRP_STATIC_TRACK_H
#define _VRRP_STATIC_TRACK_H

/* global includes */
#include <stdio.h>

/* local includes */
#include "vector.h"
#include "vrrp_if.h"

/* Parameters for static track groups */
typedef struct _static_track_group {
	const char		*gname;			/* Group name */
	const vector_t		*iname;			/* Set of VRRP instances in this group, only used during initialisation */
	list_head_t		vrrp_instances;		/* tracking_obj_t - List of VRRP instances */

	/* linked list member */
	list_head_t		e_list;
} static_track_group_t;

extern void free_static_track_group(static_track_group_t *);
extern void dump_static_track_group(FILE *, const static_track_group_t *);
extern static_track_group_t *static_track_group_find(const char *);
extern void static_track_group_init(void);
extern void static_track_group_reinstate_config(interface_t *);

#endif
