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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_IPADDR_H
#define _VRRP_IPADDR_H

/* global includes */
#include <stdio.h>
#include <stdlib.h>
#ifndef _USE_GNU
#define __USE_GNU 1
#endif
#include <netinet/in.h>
#include <string.h>
#include <syslog.h>
#include <linux/if_addr.h>
#include <stdbool.h>

/* local includes */
#include "vrrp_if.h"
#include "list.h"
#include "vector.h"
#include "utils.h"

/* types definition */
typedef struct _ip_address {
	struct ifaddrmsg ifa;

	union {
		struct {
			struct in_addr sin_addr;
			struct in_addr sin_brd;
		} sin;
		struct in6_addr sin6_addr;
	} u;

	interface_t		*ifp;			/* Interface owning IP address */
	char			*label;			/* Alias name, e.g. eth0:1 */
	int			set;			/* TRUE if addr is set */
	bool			iptable_rule_set;	/* TRUE if iptable drop rule
							 * set to addr
							 */
} ip_address_t;

#define IPADDRESS_DEL 0
#define IPADDRESS_ADD 1
#define DFLT_INT	"eth0"

/* Macro definition */
#define IP_FAMILY(X)	(X)->ifa.ifa_family
#define IP_IS6(X)	((X)->ifa.ifa_family == AF_INET6)
#define IP_IS4(X)	((X)->ifa.ifa_family == AF_INET)
#define IP_SIZE(X)      (IP_IS6(X) ? sizeof((X)->u.sin6_addr) : sizeof((X)->u.sin.sin_addr))

#define IP4_ISEQ(X,Y)   ((X)->u.sin.sin_addr.s_addr == (Y)->u.sin.sin_addr.s_addr	&& \
			 (X)->ifa.ifa_prefixlen     == (Y)->ifa.ifa_prefixlen		&& \
			 (X)->ifa.ifa_index         == (Y)->ifa.ifa_index		&& \
			 (X)->ifa.ifa_scope         == (Y)->ifa.ifa_scope		&& \
			 string_equal((X)->label, (Y)->label))

#define IP6_ISEQ(X,Y)   ((X)->u.sin6_addr.s6_addr32[0] == (Y)->u.sin6_addr.s6_addr32[0]	&& \
			 (X)->u.sin6_addr.s6_addr32[1] == (Y)->u.sin6_addr.s6_addr32[1]	&& \
			 (X)->u.sin6_addr.s6_addr32[2] == (Y)->u.sin6_addr.s6_addr32[2]	&& \
			 (X)->u.sin6_addr.s6_addr32[3] == (Y)->u.sin6_addr.s6_addr32[3]	&& \
			 (X)->ifa.ifa_prefixlen     == (Y)->ifa.ifa_prefixlen		&& \
			 (X)->ifa.ifa_index         == (Y)->ifa.ifa_index		&& \
			 (X)->ifa.ifa_scope         == (Y)->ifa.ifa_scope		&& \
			 string_equal((X)->label, (Y)->label))

#define IP_ISEQ(X,Y)    (((X) && (Y)) ? ((IP_FAMILY(X) == IP_FAMILY(Y)) ? (IP_IS6(X) ? IP6_ISEQ(X, Y) : IP4_ISEQ(X, Y)) : 0) : (((!(X) && (Y))||((X) && !(Y))) ? 0 : 1))

/* prototypes */
extern void netlink_iplist(list, int);
extern void handle_iptable_rule_to_iplist(list, int, char *);
extern void free_ipaddress(void *);
extern char *ipaddresstos(ip_address_t *);
extern void dump_ipaddress(void *);
extern ip_address_t *parse_ipaddress(ip_address_t *, char *);
extern void alloc_ipaddress(list, vector_t *, interface_t *);
extern void clear_diff_address(list, list);
extern void clear_diff_saddresses(void);

#endif
