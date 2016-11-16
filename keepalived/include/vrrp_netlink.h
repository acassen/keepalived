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

/* global includes */
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#ifdef _HAVE_LIBNL3_
#include <netlink/netlink.h>
#include <libnfnetlink/libnfnetlink.h>
#endif
#ifdef _HAVE_LIBNL1_
#include <libnfnetlink/libnfnetlink.h>
#endif

/* local includes */
#include "timer.h"
#include "vrrp_if.h"

/* types definitions */
typedef struct _nl_handle {
#ifdef _HAVE_LIBNL3_
	struct nl_sock*		sk;
#endif
	int			fd;
	uint32_t		nl_pid;
	__u32			seq;
	thread_t		*thread;
} nl_handle_t;

/* Define types */
#define NETLINK_TIMER (30 * TIMER_HZ)
#ifndef _HAVE_LIBNL3_
#ifndef _HAVE_LIBNL1_
#define NLMSG_TAIL(nmsg) ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
#define SOL_NETLINK 270
#endif
#endif

#define RTA_TAIL(rta)	((struct rtattr *) (((void *) (rta)) + RTA_ALIGN((rta)->rta_len)))

/* Global vars exported */
extern nl_handle_t nl_cmd;	/* Command channel */
extern int netlink_error_ignore; /* If we get this error, ignore it */

/* prototypes */
extern void netlink_set_recv_buf_size(void);
extern int addattr_l(struct nlmsghdr *, size_t, unsigned short, void *, size_t);
extern int addattr8(struct nlmsghdr *, size_t, unsigned short, uint8_t);
extern int addattr32(struct nlmsghdr *, size_t, unsigned short, uint32_t);
extern int addattr64(struct nlmsghdr *, size_t, unsigned short, uint64_t);
extern int addattr_l2(struct nlmsghdr *, size_t, unsigned short, void *, size_t, void *, size_t);
extern int addraw_l(struct nlmsghdr *, size_t, const void *, size_t);
extern size_t rta_addattr_l(struct rtattr *, size_t, unsigned short, const void *, size_t);
extern size_t rta_addattr_l2(struct rtattr *, size_t, unsigned short, const void *, size_t, const void*, size_t);
extern size_t rta_addattr64(struct rtattr *, size_t, unsigned short, uint64_t);
extern size_t rta_addattr32(struct rtattr *, size_t, unsigned short, uint32_t);
extern size_t rta_addattr16(struct rtattr *, size_t, unsigned short, uint16_t);
extern size_t rta_addattr8(struct rtattr *, size_t, unsigned short, uint8_t);
extern struct rtattr *rta_nest(struct rtattr *, size_t, unsigned short);
extern size_t rta_nest_end(struct rtattr *, struct rtattr *);
extern ssize_t netlink_talk(nl_handle_t *, struct nlmsghdr *);
extern int netlink_interface_lookup(void);
extern void kernel_netlink_poll(void);
extern void kernel_netlink_init(void);
extern void kernel_netlink_close(void);

#endif
