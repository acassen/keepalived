/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_netlink.c include file.
 *
 * Version:     $Id: vrrp_netlink.h,v 0.4.9a 2001/12/20 17:14:25 acassen Exp $
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

#ifndef _VRRP_NETLINK_H
#define _VRRP_NETLINK_H 1

/* Hack for GNU libc version 2. */
#ifndef MSG_TRUNC
#define MSG_TRUNC      0x20
#endif /* MSG_TRUNC */

/* global includes */
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* types definitions */
struct nl_handle {
  int fd;
  struct sockaddr_nl snl;
  __u32 seq;
};

/* prototypes */
extern int addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data, int alen);
extern int netlink_socket(struct nl_handle *nl, unsigned long groups);
extern int netlink_close(struct nl_handle *nl);
extern int netlink_talk (struct nl_handle *nl, struct nlmsghdr *n);

#endif
