/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_if.c include file.
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

#ifndef _VRRP_IF_H
#define _VRRP_IF_H

/* global includes */
#include <net/if.h>

/* needed to get correct values for SIOC* */
#include <linux/sockios.h>

/* local includes */
#include "scheduler.h"
#include "list.h"

/* types definition */
#ifndef SIOCETHTOOL
/* should not happen, otherwise we have a broken toolchain */
#warning "SIOCETHTOOL not defined. Defaulting to 0x8946, which is probably wrong !"
#define SIOCETHTOOL     0x8946
#endif
#ifndef SIOCGMIIPHY
/* should not happen, otherwise we have a broken toolchain */
#warning "SIOCGMIIPHY not defined. Defaulting to SIOCDEVPRIVATE, which is probably wrong !"
#define SIOCGMIIPHY (SIOCDEVPRIVATE)	/* Get the PHY in use. */
#define SIOCGMIIREG (SIOCGMIIPHY+1)	/* Read a PHY register. */
#endif

/* ethtool.h cannot be included because old versions use kernel-only types
 * which cannot be included from user-land. We don't need much anyway.
 */
#ifndef ETHTOOL_GLINK
#define ETHTOOL_GLINK   0x0000000a
/* for passing single values */
struct ethtool_value {
        uint32_t   cmd;
        uint32_t   data;
};
#endif
#define LINK_UP   1
#define LINK_DOWN 0
#define IF_NAMESIZ    20	/* Max interface lenght size */
#define IF_HWADDR_MAX 20	/* Max MAC address length size */
#define ARPHRD_ETHER 1
#define ARPHRD_LOOPBACK 772
#define POLLING_DELAY TIMER_HZ

/* Interface Linkbeat code selection */
#define LB_IOCTL   0x1
#define LB_MII     0x2
#define LB_ETHTOOL 0x4

/* Interface structure definition */
typedef struct _interface {
	char ifname[IF_NAMESIZ + 1];	/* Interface name */
	unsigned int ifindex;		/* Interface index */
	struct in_addr sin_addr;	/* IPv4 primary IPv4 address */
	struct in6_addr sin6_addr;	/* IPv6 link address */
	unsigned long flags;		/* flags */
	unsigned int mtu;		/* MTU for this interface */
	unsigned short hw_type;		/* Type of hardware address */
	u_char hw_addr[IF_HWADDR_MAX];	/* MAC address */
	int hw_addr_len;		/* MAC addresss length */
	int lb_type;			/* Interface regs selection */
	int linkbeat;			/* LinkBeat from MII BMSR req */
} interface;

/* Tracked interface structure definition */
typedef struct _tracked_if {
	int weight;		/* tracking weight when non-zero */
	interface *ifp;		/* interface backpointer, cannot be NULL */
} tracked_if;

/* Macros */
#define IF_NAME(X) ((X)->ifname)
#define IF_INDEX(X) ((X)->ifindex)
#define IF_ADDR(X) ((X)->sin_addr.s_addr)
#define IF_MTU(X) ((X)->mtu)
#define IF_HWADDR(X) ((X)->hw_addr)
#define IF_MII_SUPPORTED(X) ((X)->lb_type & LB_MII)
#define IF_ETHTOOL_SUPPORTED(X) ((X)->lb_type & LB_ETHTOOL)
#define IF_LINKBEAT(X) ((X)->linkbeat)
#define IF_ISUP(X) (((X)->flags & IFF_UP)      && \
                    ((X)->flags & IFF_RUNNING) && \
                    if_linkbeat(X))

/* prototypes */
extern interface *if_get_by_ifindex(const int);
extern interface *if_get_by_ifname(const char *);
extern int if_linkbeat(const interface *);
extern int if_mii_probe(const char *);
extern int if_ethtool_probe(const char *);
extern void if_add_queue(interface *);
extern int if_monitor_thread(thread_t *);
extern void init_interface_queue(void);
extern void init_interface_linkbeat(void);
extern void free_interface_queue(void);
extern void dump_if(void *);
extern int if_join_vrrp_group(sa_family_t, int *, interface *, int);
extern int if_leave_vrrp_group(sa_family_t, int, interface *);
extern int if_setsockopt_bindtodevice(int *, interface *);
extern int if_setsockopt_hdrincl(int *);
extern int if_setsockopt_mcast_loop(sa_family_t, int *);
extern int if_setsockopt_mcast_hops(sa_family_t, int *);
extern int if_setsockopt_mcast_if(sa_family_t, int *, interface *);

#endif
