/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_iptables.c include file.
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
 * Copyright (C) 2001-2016 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_IPTABLES_H
#define _VRRP_IPTABLES_H

#ifdef _HAVE_LIBIPTC_
#include <libiptc/libxtc.h>
#endif

#include "vrrp_iptables_calls.h"
#include "vrrp_ipaddress.h"

struct ipt_handle;

#define	IPTABLES_MAX_TRIES	3	/* How may times to try adding/deleting when get EAGAIN */


void iptables_init(void);
void iptables_fini(void);
struct ipt_handle *iptables_open(void);
int iptables_close(struct ipt_handle *h);
void handle_iptable_rule_to_vip(ip_address_t *, int, char *, struct ipt_handle *);

#endif
