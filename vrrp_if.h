/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_if.c include file.
 *
 * Version:     $Id: vrrp_if.h,v 0.5.6 2002/04/13 06:21:33 acassen Exp $
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
 */

#ifndef _VRRP_IF_H
#define _VRRP_IF_H

/* global includes */
#include <net/if.h>

/* local includes */
#include "scheduler.h"
#include "list.h"

/* types definition */
#ifndef SIOCGMIIPHY
  #define SIOCGMIIPHY (SIOCDEVPRIVATE)            /* Get the PHY in use. */
  #define SIOCGMIIREG (SIOCDEVPRIVATE+1)          /* Read a PHY register. */
  #define SIOCSMIIREG (SIOCDEVPRIVATE+2)          /* Write a PHY register. */
  #define SIOCGPARAMS (SIOCDEVPRIVATE+3)          /* Read operational parameters. */
  #define SIOCSPARAMS (SIOCDEVPRIVATE+4)          /* Set operational parameters. */
#endif
#define LINK_UP   1
#define LINK_DOWN 0
#define IF_NAMESIZ    20 /* Max interface lenght size */
#define IF_HWADDR_MAX 20 /* Max MAC address length size */
#define ARPHRD_ETHER 1
#define ARPHRD_LOOPBACK 772
#define POLLING_DELAY 1

/* Interface structure definition */
typedef struct _interface {
  char ifname[IF_NAMESIZ + 1];		/* Interface name */
  unsigned int ifindex;			/* Interface index */
  uint32_t address;			/* Interface main primary IP address */
//  list primary;
//  list secondary;
  unsigned long flags;			/* flags */
  unsigned int mtu;			/* MTU for this interface */
  unsigned short hw_type;		/* Type of hardware address */
  u_char hw_addr[IF_HWADDR_MAX];	/* MAC address */
  int hw_addr_len;			/* MAC addresss length */
  int mii;				/* Interface support MII regs ? */
  int mii_linkbeat;			/* LinkBeat from MII BMSR req */
} interface;

/* Global interface queue */
list if_queue;

/* Macros */
#define IF_NAME(X) ((X)->ifname)
#define IF_INDEX(X) ((X)->ifindex)
#define IF_ADDR(X) ((X)->address)
#define IF_HWADDR(X) ((X)->hw_addr)
#define IF_LINK_ISUP(X) (if_mii_probe(X))
#define IF_MII_SUPPORTED(X) ((X)->mii)
#define IF_MII_LINKBEAT(X) ((X)->mii_linkbeat)
#define IF_ISUP(X) (((X)->flags & IFF_UP)      && \
                    ((X)->flags & IFF_RUNNING) && \
                    if_mii_linkbeat(X))

/* prototypes */
extern interface *if_get_by_ifindex(const int ifindex);
extern interface *if_get_by_ifname(const char *ifname);
extern int if_mii_linkbeat(const interface *ifp);
extern int if_mii_probe(const char *ifname);
extern void if_add_queue(interface *ifp);
extern int if_monitor_thread(thread *thread);
extern void init_interface_queue(void);
extern void free_interface_queue(void);
extern void dump_if(void *data);

#endif
