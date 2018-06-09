/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Dynamic data structure definition.
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

#ifndef _VRRP_DATA_H
#define _VRRP_DATA_H

/* system includes */
#include <sys/types.h>
#include <stdio.h>

/* local includes */
#include "list.h"
#include "vector.h"

/* Configuration data root */
typedef struct _vrrp_data {
	list			static_track_groups;
	list			static_addresses;
#if _HAVE_FIB_ROUTING_
	list			static_routes;
	list			static_rules;
#endif
	list			vrrp_sync_group;
	list			vrrp;			/* vrrp_t */
	list			vrrp_index;
	list			vrrp_index_fd;
	list			vrrp_socket_pool;
	list			vrrp_script;		/* vrrp_script_t */
	list			vrrp_track_files;	/* vrrp_tracked_file_t */
#ifdef _WITH_BFD_
	list			vrrp_track_bfds;	/* vrrp_tracked_bfd_t */
#endif
} vrrp_data_t;

/* Global Vars exported */
extern vrrp_data_t *vrrp_data;
extern vrrp_data_t *old_vrrp_data;
extern char *vrrp_buffer;
extern size_t vrrp_buffer_len;

/* prototypes */
extern void alloc_static_track_group(char *);
extern void alloc_saddress(vector_t *);
extern void alloc_sroute(vector_t *);
extern void alloc_srule(vector_t *);
extern void alloc_vrrp_sync_group(char *);
extern void alloc_vrrp(char *);
extern void alloc_vrrp_unicast_peer(vector_t *);
extern void alloc_vrrp_track_if(vector_t *);
extern void alloc_vrrp_script(char *);
extern void alloc_vrrp_track_script(vector_t *);
extern void alloc_vrrp_file(char *);
extern void alloc_vrrp_track_file(vector_t *);
#ifdef _WITH_BFD_
extern void alloc_vrrp_track_bfd(vector_t *);
#endif
extern void alloc_vrrp_group_track_if(vector_t *);
extern void alloc_vrrp_group_track_script(vector_t *);
extern void alloc_vrrp_group_track_file(vector_t *);
#ifdef _WITH_BFD_
extern void alloc_vrrp_group_track_bfd(vector_t *);
#endif
extern void alloc_vrrp_vip(vector_t *);
extern void alloc_vrrp_evip(vector_t *);
extern void alloc_vrrp_vroute(vector_t *);
extern void alloc_vrrp_vrule(vector_t *);
extern void alloc_vrrp_buffer(size_t);
extern void free_vrrp_buffer(void);
extern vrrp_data_t *alloc_vrrp_data(void);
extern void free_vrrp_data(vrrp_data_t *);
extern void dump_tracking_vrrp(FILE *, void *);
extern void dump_data_vrrp(FILE *);

#endif
