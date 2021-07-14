/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        keepalived_netlink.c include file.
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

#ifndef _VRRP_NETLINK_H
#define _VRRP_NETLINK_H 1

#include "config.h"

/* global includes */
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* local includes */
#include "scheduler.h"
#ifdef _WITH_VRRP_
#include "vrrp_if.h"
#endif
#include "align.h"

/* types definitions */
typedef struct _nl_handle {
	int			fd;
	uint32_t		nl_pid;
	__u32			seq;
	thread_ref_t		thread;
} nl_handle_t;

/* Define types */
#ifndef NLMSG_TAIL
#define NLMSG_TAIL(nmsg) ((void *)(((char *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
#endif

#define RTA_TAIL(rta)	PTR_CAST(struct rtattr, (char *)(rta) + RTA_ALIGN((rta)->rta_len))

/* Global vars exported */
#ifdef _WITH_VRRP_
extern nl_handle_t nl_cmd;	/* Command channel */
extern int netlink_error_ignore; /* If we get this error, ignore it */
#endif

#ifdef _NETLINK_TIMERS_
extern bool do_netlink_timers;
#endif

/* prototypes */
#ifdef _NETLINK_TIMERS_
extern void report_and_clear_netlink_timers(const char *);
#endif

extern int addattr_l(struct nlmsghdr *, size_t, unsigned short, const void *, size_t) LTO_NOINLINE;
extern int addattr_l2(struct nlmsghdr *, size_t, unsigned short, const void *, size_t, const void *, size_t);
extern int addraw_l(struct nlmsghdr *, size_t, const void *, size_t);

static inline int
addattr8(struct nlmsghdr *n, size_t maxlen, unsigned short type, uint8_t data)
{
	return addattr_l(n, maxlen, type, &data, sizeof data);
}

static inline int
addattr16(struct nlmsghdr *n, size_t maxlen, unsigned short type, uint16_t data)
{
	return addattr_l(n, maxlen, type, &data, sizeof data);
}

static inline int
addattr32(struct nlmsghdr *n, size_t maxlen, unsigned short type, uint32_t data)
{
	return addattr_l(n, maxlen, type, &data, sizeof data);
}

static inline int
addattr64(struct nlmsghdr *n, size_t maxlen, unsigned short type, uint64_t data)
{
	return addattr_l(n, maxlen, type, &data, sizeof(data));
}

#ifdef _WITH_VRRP_
extern size_t rta_addattr_l(struct rtattr *, size_t, unsigned short, const void *, size_t);
extern size_t rta_addattr_l2(struct rtattr *, size_t, unsigned short, const void *, size_t, const void*, size_t);

static inline size_t
rta_addattr8(struct rtattr *rta, size_t maxlen, unsigned short type, uint8_t data)
{
	return rta_addattr_l(rta, maxlen, type, &data, sizeof data);
}

static inline size_t
rta_addattr16(struct rtattr *rta, size_t maxlen, unsigned short type, uint16_t data)
{
	return rta_addattr_l(rta, maxlen, type, &data, sizeof data);
}

static inline size_t
rta_addattr32(struct rtattr *rta, size_t maxlen, unsigned short type, uint32_t data)
{
	return rta_addattr_l(rta, maxlen, type, &data, sizeof data);
}

static inline size_t
rta_addattr64(struct rtattr *rta, size_t maxlen, unsigned short type, uint64_t data)
{
	return rta_addattr_l(rta, maxlen, type, &data, sizeof data);
}

extern struct rtattr *rta_nest(struct rtattr *, size_t, unsigned short);
extern size_t rta_nest_end(struct rtattr *, struct rtattr *);
extern ssize_t netlink_talk(nl_handle_t *, struct nlmsghdr *);
extern int netlink_interface_lookup(char *);
extern void kernel_netlink_poll(void);
extern void process_if_status_change(interface_t *);
#endif
extern void kernel_netlink_set_recv_bufs(void);
#ifdef _WITH_VRRP_
extern void set_extra_netlink_monitoring(bool, bool, bool, bool);
#endif
extern void kernel_netlink_init(void);
extern void cancel_kernel_netlink_threads(void);
#if defined _WITH_VRRP_ || defined _WITH_LVS_
extern void kernel_netlink_read_interfaces(void);
#endif
extern void kernel_netlink_close(void);
extern void kernel_netlink_close_monitor(void);
extern void kernel_netlink_close_cmd(void);
#ifdef THREAD_DUMP
extern void register_keepalived_netlink_addresses(void);
#endif

#endif
