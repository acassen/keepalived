/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_netlink.c include file.
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

#ifndef _VRRP_NETLINK_H
#define _VRRP_NETLINK_H 1

/* Hack for GNU libc version 2. */
#ifndef MSG_TRUNC
#define MSG_TRUNC      0x20
#endif				/* MSG_TRUNC */

/* global includes */
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* local includes */
#include "timer.h"

/* types definitions */
typedef struct _nl_handle {
	int			fd;
	struct sockaddr_nl	snl;
	__u32			seq;
	thread_t		*thread;
} nl_handle_t;

/* Define types */
#define NETLINK_TIMER (30 * TIMER_HZ)
#define NLMSG_TAIL(nmsg) ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

/* Global vars exported */
extern nl_handle_t nl_kernel;	/* Kernel reflection channel */
extern nl_handle_t nl_cmd;	/* Command channel */

/* prototypes */
extern int addattr32(struct nlmsghdr *, int, int, uint32_t);
extern int addattr_l(struct nlmsghdr *, int, int, void *, int);
extern int rta_addattr_l(struct rtattr *, int, int, const void *, int);
extern char *netlink_scope_n2a(int);
extern int netlink_scope_a2n(char *);
extern int netlink_socket(nl_handle_t *, unsigned long);
extern int netlink_close(nl_handle_t *);
extern int netlink_talk(nl_handle_t *, struct nlmsghdr *);
extern int netlink_interface_lookup(void);
extern int netlink_interface_refresh(void);
extern void kernel_netlink_init(void);
extern void kernel_netlink_close(void);

#endif
