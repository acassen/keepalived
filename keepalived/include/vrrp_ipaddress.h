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
 * Copyright (C) 2001-2009 Alexandre Cassen, <acassen@freebox.fr>
 */

#ifndef _VRRP_IPADDR_H
#define _VRRP_IPADDR_H

/* global includes */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <syslog.h>

/* local includes */
#include "vrrp_if.h"
#include "list.h"
#include "vector.h"

/* types definition */
typedef struct {
	uint32_t addr;		/* the ip address */
	uint32_t broadcast;	/* the broadcast address */
	uint8_t mask;		/* the ip address CIDR netmask */
	int ifindex;		/* Interface index owning IP address */
	interface *ifp;		/* Interface owning IP address */
	int scope;		/* the ip address scope */
	char *label;		/* Alias name, e.g. eth0:1 */
	int set;		/* TRUE if addr is set */
} ip_address;

#define IPADDRESS_DEL 0
#define IPADDRESS_ADD 1
#define DFLT_INT	"eth0"

/* Macro definition */
#define IP_ISEQ(X,Y)   ((X)->addr    == (Y)->addr     && \
			(X)->mask    == (Y)->mask     && \
			(X)->ifindex == (Y)->ifindex  && \
			(X)->scope   == (Y)->scope)

/* prototypes */
extern int netlink_address_ipv4(ip_address * ipaddr, int cmd);
extern void netlink_iplist_ipv4(list ip_list, int cmd);
extern void free_ipaddress(void *ip_data_obj);
extern void dump_ipaddress(void *ip_data_obj);
extern void alloc_ipaddress(list ip_list, vector strvec, interface * ifp);
extern void clear_diff_address(list l, list n);
extern void clear_diff_saddresses(void);

#endif
