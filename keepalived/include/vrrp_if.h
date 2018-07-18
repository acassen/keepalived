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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_IF_H
#define _VRRP_IF_H

#include "config.h"

/* global includes */
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <net/if.h>
#include <stdio.h>
#ifdef _HAVE_NET_LINUX_IF_H_COLLISION_
#define _LINUX_IF_H
#endif
#include <linux/netdevice.h>

/* local includes */
#include "scheduler.h"
#include "list.h"
#include "timer.h"

#define LINK_UP   1
#define LINK_DOWN 0
#define POLLING_DELAY TIMER_HZ

/* Interface Linkbeat code selection */
#define LB_IOCTL   0x1
#define LB_MII     0x2
#define LB_ETHTOOL 0x4

/* I don't know what the correct type is.
 * The kernel has ifindex in the range [1, INT_MAX], but IFLA_LINK is defined
 * to be __u32. See dev_new_index() in net/core/dev.c and net/core/rtnetlink.c.
 * ifaddrmsg.ifa_index (See /usr/include/linux/if_addr.h> is __u32.
 * /usr/include/linux/rtnetlink.h has them as ints.
 * RTA_OIF and RTA_IIF are u32.
 * RFC2553 defines sin6_scopeid to be a uint32_t, and it can hold an ifindex */
typedef uint32_t ifindex_t;

/* Structure for delayed sending of gratuitous ARP/NA messages */
typedef struct _garp_delay {
	timeval_t		garp_interval;		/* Delay between sending gratuitous ARP messages on an interface */
	bool			have_garp_interval;	/* True if delay */
	timeval_t		gna_interval;		/* Delay between sending gratuitous NA messages on an interface */
	bool			have_gna_interval;	/* True if delay */
	timeval_t		garp_next_time;		/* Time when next gratuitous ARP message can be sent */
	timeval_t		gna_next_time;		/* Time when next gratuitous NA message can be sent */
	int			aggregation_group;	/* Index of multi-interface group */
} garp_delay_t;

/* Interface structure definition */
typedef struct _interface {
	char			ifname[IFNAMSIZ];	/* Interface name */
	ifindex_t		ifindex;		/* Interface index */
	struct in_addr		sin_addr;		/* IPv4 primary IPv4 address */
	struct in6_addr		sin6_addr;		/* IPv6 link address */
	unsigned		ifi_flags;		/* Kernel flags */
	bool			linkbeat_use_polling;	/* Poll the interface for status, rather than use netlink */
	uint32_t		mtu;			/* MTU for this interface_t */
	unsigned short		hw_type;		/* Type of hardware address */
	u_char			hw_addr[MAX_ADDR_LEN];	/* MAC address */
	u_char			hw_addr_bcast[MAX_ADDR_LEN]; /* broadcast address */
	size_t			hw_addr_len;		/* MAC addresss length */
	int			lb_type;		/* Interface regs selection */
#ifdef _HAVE_VRRP_VMAC_
	bool			vmac;			/* Set if interface is a VMAC interface */
	ifindex_t		base_ifindex;		/* Only used at startup if we find vmac i/f before base i/f */
	struct _interface	*base_ifp;		/* Base interface (if interface is a VMAC interface),
							   otherwise the physical interface */
#endif
	garp_delay_t		*garp_delay;		/* Delays for sending gratuitous ARP/NA */
	bool			gna_router;		/* Router flag for NA messages */
	int			reset_arp_config;	/* Count of how many vrrps have changed arp parameters on interface */
	uint32_t		reset_arp_ignore_value;	/* Original value of arp_ignore to be restored */
	uint32_t		reset_arp_filter_value;	/* Original value of arp_filter to be restored */
	uint32_t		reset_promote_secondaries; /* Count of how many vrrps have changed promote_secondaries on interface */
#ifdef _HAVE_VRRP_VMAC_
	unsigned		rp_filter;		/* < UINT_MAX if we have changed the value */
#endif
	bool			promote_secondaries_already_set; /* Set if promote_secondaries already set on interface */
	list			tracking_vrrp;		/* List of tracking_vrrp_t for vrrp instances tracking this interface */
} interface_t;

/* Tracked interface structure definition */
typedef struct _tracked_if {
	int			weight;		/* tracking weight when non-zero */
	interface_t		*ifp;		/* interface backpointer, cannot be NULL */
} tracked_if_t;

/* Macros */
#define IF_NAME(X) ((X)->ifname)
#define IF_INDEX(X) ((X)->ifindex)
#ifdef _HAVE_VRRP_VMAC_
#define IF_BASE_INDEX(X) ((X)->base_ifp->ifindex)
#define IF_BASE_IFP(X) ((X)->base_ifp)
#else
#define IF_BASE_INDEX(X) ((X)->ifindex)
#define IF_BASE_IFP(X) (X)
#endif
#define IF_ADDR(X) ((X)->sin_addr.s_addr)
#define IF_ADDR6(X)	((X)->sin6_addr)
#define IF_HWADDR(X) ((X)->hw_addr)
#define IF_MII_SUPPORTED(X) ((X)->lb_type & LB_MII)
#define IF_ETHTOOL_SUPPORTED(X) ((X)->lb_type & LB_ETHTOOL)
#define FLAGS_UP(X) (((X) & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING))
#define IF_FLAGS_UP(X) (FLAGS_UP((X)->ifi_flags))
#ifdef _HAVE_VRRP_VMAC_
#define IF_ISUP(X) (IF_FLAGS_UP(X) && (!(X)->vmac || IF_FLAGS_UP((X)->base_ifp)))
#else
#define IF_ISUP(X) (IF_FLAGS_UP(X))
#endif

typedef enum if_lookup {
	IF_NO_CREATE,
	IF_CREATE_IF_DYNAMIC,
	IF_CREATE_ALWAYS,
	IF_CREATE_NETLINK
} if_lookup_t;

/* Global data */
list garp_delay;

/* prototypes */
extern interface_t *if_get_by_ifindex(ifindex_t);
extern interface_t *base_if_get_by_ifp(interface_t *);
extern interface_t *if_get_by_ifname(const char *, if_lookup_t);
extern list get_if_list(void);
extern void reset_interface_queue(void);
extern void alloc_garp_delay(void);
extern void set_default_garp_delay(void);
extern void if_add_queue(interface_t *);
extern void init_interface_queue(void);
extern void init_interface_linkbeat(void);
extern void free_interface_queue(void);
extern void free_old_interface_queue(void);
extern int if_join_vrrp_group(sa_family_t, int *, interface_t *);
extern int if_leave_vrrp_group(sa_family_t, int, interface_t *);
extern int if_setsockopt_bindtodevice(int *, interface_t *);
extern int if_setsockopt_hdrincl(int *);
extern int if_setsockopt_ipv6_checksum(int *);
#if HAVE_DECL_IP_MULTICAST_ALL  /* Since Linux 2.6.31 */
extern int if_setsockopt_mcast_all(sa_family_t, int *);
#endif
extern int if_setsockopt_mcast_loop(sa_family_t, int *);
extern int if_setsockopt_mcast_hops(sa_family_t, int *);
extern int if_setsockopt_mcast_if(sa_family_t, int *, interface_t *);
extern int if_setsockopt_priority(int *, int);
extern int if_setsockopt_rcvbuf(int *, int);
extern int if_setsockopt_no_receive(int *);
extern void interface_up(interface_t *);
extern void interface_down(interface_t *);
extern void cleanup_lost_interface(interface_t *);
extern int recreate_vmac_thread(thread_t *);
extern void update_added_interface(interface_t *);

#endif
