/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_ipaddress.c include file.
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

#ifndef _VRRP_IPADDR_H
#define _VRRP_IPADDR_H

/* global includes */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <syslog.h>
#include <linux/if_addr.h>

/* local includes */
#include "vrrp_if.h"
#include "list.h"
#include "vector.h"

/* types definition */
typedef struct {
	struct ifaddrmsg ifa;

	union {
		struct {
			struct in_addr sin_addr;
			struct in_addr sin_brd;
		} sin;
		struct in6_addr sin6_addr;
	} u;

	interface *ifp;		/* Interface owning IP address */
	char *label;		/* Alias name, e.g. eth0:1 */
	int set;		/* TRUE if addr is set */
} ip_address;

#define IPADDRESS_DEL 0
#define IPADDRESS_ADD 1
#define DFLT_INT	"eth0"

/* Macro definition */
#define IP_FAMILY(X)	(X)->ifa.ifa_family
#define IP_IS6(X)	((X)->ifa.ifa_family == AF_INET6)

#define IP_ISEQ(X,Y)   ((X)->u.sin.sin_addr.s_addr == (Y)->u.sin.sin_addr.s_addr	&& \
			(X)->ifa.ifa_prefixlen     == (Y)->ifa.ifa_prefixlen		&& \
			(X)->ifa.ifa_index         == (Y)->ifa.ifa_index		&& \
			(X)->ifa.ifa_scope         == (Y)->ifa.ifa_scope)

#define IP6_ISEQ(X,Y)   ((X)->u.sin6_addr.s6_addr32[0] == (Y)->u.sin6_addr.s6_addr32[0]	&& \
			(X)->u.sin6_addr.s6_addr32[1] == (Y)->u.sin6_addr.s6_addr32[1]	&& \
			(X)->u.sin6_addr.s6_addr32[2] == (Y)->u.sin6_addr.s6_addr32[2]	&& \
			(X)->u.sin6_addr.s6_addr32[3] == (Y)->u.sin6_addr.s6_addr32[3]	&& \
			(X)->ifa.ifa_prefixlen     == (Y)->ifa.ifa_prefixlen		&& \
			(X)->ifa.ifa_index         == (Y)->ifa.ifa_index		&& \
			(X)->ifa.ifa_scope         == (Y)->ifa.ifa_scope)


/* prototypes */
extern void netlink_iplist(list, int);
extern void free_ipaddress(void *);
extern void dump_ipaddress(void *);
extern void alloc_ipaddress(list, vector, interface *);
extern void clear_diff_address(list, list);
extern void clear_diff_saddresses(void);

#endif
