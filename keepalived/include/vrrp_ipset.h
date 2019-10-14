/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_ipset.c include file.
 *
 * Author:      Quentin Armitage, <quentin@armitage.org.uk>
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

#ifndef _VRRP_IPSET_H
#define _VRRP_IPSET_H

#define LIBIPSET_NFPROTO_H
#include "vrrp_ipaddress.h"
#include "vrrp_iptables.h"

#define DEFAULT_IPSET_NAME	"keepalived"

struct ipset_session;

bool add_vip_ipsets(struct ipset_session **, uint8_t, bool);
#ifdef HAVE_IPSET_ATTR_IFACE
bool add_igmp_ipsets(struct ipset_session **, uint8_t, bool);
#endif
bool remove_vip_ipsets(struct ipset_session **, uint8_t);
bool remove_igmp_ipsets(struct ipset_session **, uint8_t);
bool ipset_initialise(void);
void* ipset_session_start(void);
void ipset_session_end(void *);
void ipset_entry(void *, int, const ip_address_t*);
#ifdef HAVE_IPSET_ATTR_IFACE
void ipset_entry_igmp(void*, int, const char *, uint8_t);
#endif

#endif
