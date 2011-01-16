/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_iproute.c include file.
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

#ifndef _VRRP_IPROUTE_H
#define _VRRP_IPROUTE_H

/* global includes */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* local includes */
#include "list.h"
#include "vector.h"

/* types definition */
typedef struct _ip_route {
	uint32_t dst;		/* RTA_DST */
	uint8_t dmask;
	uint32_t gw;		/* RTA_GATEWAY */
	uint32_t gw2;		/* Will use RTA_MULTIPATH */
	uint32_t src;		/* RTA_PREFSRC */
	uint32_t metric;	/* RTA_PRIORITY */
	int index;		/* RTA_OIF */
	int blackhole;
	int scope;
	int table;
	int set;
} ip_route;

#define IPROUTE_DEL 0
#define IPROUTE_ADD 1

/* Macro definition */
#define ROUTE_ISEQ(X,Y)	((X)->dst    == (Y)->dst   && \
			 (X)->dmask  == (Y)->dmask && \
			 (X)->gw     == (Y)->gw    && \
			 (X)->src    == (Y)->src   && \
			 (X)->table  == (Y)->table && \
			 (X)->scope  == (Y)->scope && \
			 (X)->index  == (Y)->index)

/* prototypes */
extern int netlink_route_ipv4(ip_route *, int);
extern void netlink_rtlist_ipv4(list, int);
extern void free_iproute(void *);
extern void dump_iproute(void *);
extern void alloc_route(list, vector);
extern void clear_diff_routes(list, list);
extern void clear_diff_sroutes(void);

#endif
