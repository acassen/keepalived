/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_ipaddress.c include file.
 *
 * Version:     $Id: vrrp_ipaddress.h,v 0.5.5 2002/04/10 02:34:23 acassen Exp $
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

#ifndef _VRRP_IPADDR_H
#define _VRRP_IPADDR_H

/* global includes */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <syslog.h>

/* types definition */
#define VRRP_IPADDRESS_DEL 0
#define VRRP_IPADDRESS_ADD 1

/* prototypes */
extern int netlink_address_ipv4(int ifindex, uint32_t addr, int cmd);

#endif

