/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_firewall.c include file.
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
 * Copyright (C) 2001-2018 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_FIREWALL_H
#define _VRRP_FIREWALL_H

#include "config.h"

/* global includes */
#include <stdbool.h>

/* local includes */
#include "vrrp.h"
#include "list.h"

#ifdef _WITH_IPTABLES_
#include "vrrp_iptables.h"
#endif
#ifdef _WITH_NFTABLES_
#include "vrrp_nftables.h"
#endif

/* Global variables */
extern bool block_ipv4;
extern bool block_ipv6;

/* prototypes */
extern void firewall_handle_accept_mode(vrrp_t *, int, bool);
extern void firewall_remove_rule_to_iplist(list, bool);
#ifdef _WITH_IPTABLES_
extern void firewall_init(void);
#else
extern void firewall_init(void) __attribute__((const));
#endif
#ifdef _WITH_IPTABLES_
extern void firewall_startup(bool);
#else
extern void firewall_startup(bool) __attribute__((const));
#endif
extern void firewall_cleanup(void);
extern void firewall_fini(void);

#endif
