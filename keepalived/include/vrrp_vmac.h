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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_VMAC_H
#define _VRRP_VMAC_H

/* global includes */
#include <sys/types.h>
#include <net/ethernet.h>

/* local includes */
#include "vrrp.h"

/* Defines */
enum vrrp_vmac_bits {
	VRRP_VMAC_BIT = 0,
	VRRP_VMAC_UP_BIT = 1,
	VRRP_VMAC_XMITBASE_BIT = 2,
};

extern const char * const macvlan_ll_kind;
extern u_char ll_addr[ETH_ALEN];

/* prototypes */
extern bool add_link_local_address(interface_t *, struct in6_addr*);
extern bool replace_link_local_address(interface_t *);
#if !HAVE_DECL_IFLA_INET6_ADDR_GEN_MODE
extern void remove_vmac_auto_gen_addr(interface_t *, struct in6_addr *);
#endif
extern int netlink_link_add_vmac(vrrp_t *);
extern int netlink_link_del_vmac(vrrp_t *);

#endif
