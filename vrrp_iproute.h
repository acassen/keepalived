/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_iproute.c include file.
 *
 * Version:     $Id: vrrp_iproute.h,v 0.4.1 2001/09/14 00:37:56 acassen Exp $
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

#ifndef _VRRP_IPROUTE_H
#define _VRRP_IPROUTE_H

/* global includes */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <syslog.h>

/* specify a routing entry */
struct rt_entry {
  struct rtmsg *rtm;

  uint32_t psrc;
  uint32_t src;
  uint32_t dest;
  uint32_t gate;
  uint32_t flow;
  int iif;
  int oif;
  int prio;
  int metrics;

  struct rt_entry *next;
};

/* prototypes */

extern struct rt_entry *iproute_fetch(struct rt_entry *r);
extern void iproute_dump(struct rt_entry *r);
extern void iproute_clear(struct rt_entry *lstentry);
extern int iproute_restore(struct rt_entry *lstentry, char *dev);
extern struct rt_entry *iproute_list(char *dev);

#endif
