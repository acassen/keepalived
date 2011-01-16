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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

#ifndef _VRRP_DATA_H
#define _VRRP_DATA_H

/* system includes */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>
#include <arpa/inet.h>

/* local includes */
#include "list.h"
#include "vector.h"

/*
 * Our instance dispatcher use a socket pool.
 * That way we handle VRRP protocol type per
 * physical interface.
 */
typedef struct _sock {
	sa_family_t family;
	int proto;
	int ifindex;
	int fd_in;
	int fd_out;
} sock_t;

/* Configuration data root */
typedef struct _vrrp_conf_data {
	list static_addresses;
	list static_routes;
	list vrrp_sync_group;
	list vrrp;
	list vrrp_index;
	list vrrp_index_fd;
	list vrrp_socket_pool;
	list vrrp_script;
} vrrp_conf_data;

/* Global Vars exported */
extern vrrp_conf_data *vrrp_data;
extern vrrp_conf_data *old_vrrp_data;
extern char *vrrp_buffer;

/* prototypes */
extern void alloc_saddress(vector);
extern void alloc_sroute(vector);
extern void alloc_vrrp_sync_group(char *);
extern void alloc_vrrp(char *);
extern void alloc_vrrp_track(vector);
extern void alloc_vrrp_script(char *);
extern void alloc_vrrp_track_script(vector);
extern void alloc_vrrp_vip(vector);
extern void alloc_vrrp_evip(vector);
extern void alloc_vrrp_vroute(vector);
extern void alloc_vrrp_buffer(void);
extern void free_vrrp_buffer(void);
extern vrrp_conf_data *alloc_vrrp_data(void);
extern void free_vrrp_data(vrrp_conf_data *);
extern void dump_vrrp_data(vrrp_conf_data *);
extern void free_vrrp_sockpool(vrrp_conf_data *);

#endif
