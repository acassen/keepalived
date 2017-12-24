/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_arp.c include file.
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

#ifndef _VRRP_ARP_H
#define _VRRP_ARP_H

/* system includes */
#include <sys/types.h>

/* local includes */
#include "vrrp.h"
#include "vrrp_if.h"
#include "vrrp_ipaddress.h"

/* prototypes */
extern void gratuitous_arp_init(void);
extern void gratuitous_arp_close(void);
extern void send_gratuitous_arp(vrrp_t *, ip_address_t *);
extern ssize_t send_gratuitous_arp_immediate(interface_t *, ip_address_t *);
#endif
