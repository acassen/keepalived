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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_IPADDR_H
#define _VRRP_IPADDR_H

#include "config.h"

/* global includes */
#include <netinet/in.h>
#include <linux/if_addr.h>
#include <stdbool.h>
#include <stdio.h>

/* local includes */
#include "vrrp.h"
#include "vrrp_if.h"
#include "list_head.h"
#include "vector.h"
#include "vrrp_static_track.h"
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
#if HAVE_DECL_IFA_FLAGS
	uint32_t		flags;			/* Address flags */
	uint32_t		flagmask;		/* Bitmaps of flags set */
#else
	uint8_t			flags;			/* Address flags */
	uint8_t			flagmask;		/* Bitmaps of flags set */
#endif
	bool			have_peer;
	bool			use_vmac;
	union {
		struct in_addr sin_addr;
		struct in6_addr sin6_addr;
	} peer;
	bool			dont_track;		/* Don't leave master state if address is deleted */
	static_track_group_t	*track_group;		/* used for static addresses */

	bool			set;			/* TRUE if addr is set */
#ifdef _WITH_IPTABLES_
	bool			iptable_rule_set;	/* TRUE if iptable drop rule
							 * set to addr */
#endif
#ifdef _WITH_NFTABLES_
	bool			nftable_rule_set;	/* TRUE if in nftables set */
#endif
	bool			garp_gna_pending;	/* Is a gratuitous ARP/NA message still to be sent */
	uint32_t		preferred_lft;		/* IPv6 preferred_lft (0 means address deprecated) */

	/* linked list member */
	list_head_t		e_list;
} ip_address_t;

#define IPADDRESS_DEL 0
#define IPADDRESS_ADD 1
#define DFLT_INT	"eth0"

/* Macro definition */
#define IP_FAMILY(X)	(X)->ifa.ifa_family
#define	IP_IS6(X)	((X)->ifa.ifa_family == AF_INET6)

#define CLEAR_IP6_ADDR(X) ((X)->s6_addr32[0] = (X)->s6_addr32[1] = (X)->s6_addr32[2] = (X)->s6_addr32[3] = 0)

#define	IPADDRESSTOS_BUF_LEN	(INET6_ADDRSTRLEN + 4)     /* allow for subnet */

/* Forward reference */
struct ipt_handle;

/* prototypes */
extern const char *ipaddresstos(char *, const ip_address_t *);
extern bool compare_ipaddress(const ip_address_t *, const ip_address_t *) __attribute__((pure));
extern int netlink_ipaddress(ip_address_t *, int);
extern bool netlink_iplist(list_head_t *, int, bool);
extern void free_ipaddress(ip_address_t *);
extern void free_ipaddress_list(list_head_t *);
extern void format_ipaddress(const ip_address_t *, char *, size_t);
extern void dump_ipaddress(FILE *, const ip_address_t *);
extern void dump_ipaddress_list(FILE *, const list_head_t *);
extern ip_address_t *parse_ipaddress(ip_address_t *, const char *, bool);
extern ip_address_t *parse_route(const char *);
extern void alloc_ipaddress(list_head_t *, const vector_t *, bool);
extern void get_diff_address(vrrp_t *, vrrp_t *, list_head_t *);
extern void clear_address_list(list_head_t *, bool);
extern void clear_diff_static_addresses(void);
extern void reinstate_static_address(ip_address_t *);

#endif
