/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_vmac.c include file.
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

#ifndef _VRRP_VMAC_H
#define _VRRP_VMAC_H

/* global includes */
#include <sys/types.h>
#if defined _HAVE_NETINET_LINUX_IF_ETHER_H_COLLISION_ && \
    defined _LINUX_IF_ETHER_H && \
    !defined _NETINET_IF_ETHER_H
#define _NETINET_IF_ETHER_H
#endif
#include <net/ethernet.h>
#include <stdbool.h>

/* local includes */
#include "vrrp.h"
#include "vrrp_if.h"

/* Defines */
enum vrrp_vmac_bits {
	VRRP_VMAC_BIT = 0,
	VRRP_VMAC_UP_BIT = 1,
	VRRP_VMAC_XMITBASE_BIT = 2,
#ifdef _HAVE_VRRP_IPVLAN_
	VRRP_IPVLAN_BIT = 3,
#endif
};

extern const char * const macvlan_ll_kind;
extern u_char ll_addr[ETH_ALEN];

/* prototypes */
extern bool add_link_local_address(interface_t *, struct in6_addr*);
extern bool replace_link_local_address(interface_t *);
#if !HAVE_DECL_IFLA_INET6_ADDR_GEN_MODE
extern void remove_vmac_auto_gen_addr(interface_t *, struct in6_addr *);
#endif
extern bool netlink_link_add_vmac(vrrp_t *);
extern void netlink_link_del_vmac(vrrp_t *);
#ifdef _HAVE_VRRP_IPVLAN_
extern bool netlink_link_add_ipvlan(vrrp_t *);
#endif
#ifdef _HAVE_VRF_
extern void update_vmac_vrfs(interface_t *);
#endif

#endif
