/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_ipaddress.c include file.
 *
 * Version:     $Id: vrrp_ipaddress.h,v 0.4.0 2001/08/24 00:35:19 acassen Exp $
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
#include <arpa/inet.h>
#include <syslog.h>

/* types definitions */
typedef struct {
  int    ifindex;
  uint32_t  *addr;
  int    max_elem;
  int    nb_elem;
} iplist_ctx;

/* prototypes */
int ipaddr_list(int ifindex, uint32_t *array, int max_elem);
int ipaddr_op(int ifindex, uint32_t addr, int addF);
 
#endif

