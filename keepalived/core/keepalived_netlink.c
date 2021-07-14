/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK kernel command channel.
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

/* To monitor netlink messages and decode them:
 *   ip link add nlmon0 type nlmon
 *   ip link set nlmon0 up
 *   tcpdump -i nlmon0 -w OP_FILE
 *   wireshare OP_FILE
 */

#include "config.h"

/* global include */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <sys/uio.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <time.h>
#ifdef _WITH_VRRP_
#include <linux/version.h>
#ifdef _WITH_VRRP_
#include <linux/fib_rules.h>
#endif
#endif
#include <linux/ip.h>
#include <unistd.h>
#include <inttypes.h>
#include <linux/if_link.h>

#ifdef THREAD_DUMP
#include "scheduler.h"
#endif

/* local include */
#include "keepalived_netlink.h"
#ifdef _WITH_LVS_
#include "check_api.h"
#endif
#ifdef _WITH_VRRP_
#include "vrrp_scheduler.h"
#include "vrrp_track.h"
#include "vrrp_data.h"
#include "vrrp_if.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_vmac.h"
#endif
#ifdef _WITH_VRRP_
#include "vrrp_iproute.h"
#include "vrrp_iprule.h"
#endif
#endif
#include "logger.h"
#include "scheduler.h"
#include "utils.h"
#include "list_head.h"
#include "bitops.h"
#include "vrrp_ipaddress.h"
#include "global_data.h"
#include "align.h"
#include "warnings.h"

/* This seems a nasty hack, but it's what iproute2 does */
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

/* Default values */
#define IF_DEFAULT_BUFSIZE	(64*1024)

/* Global vars */
nl_handle_t nl_cmd = { .fd = -1 };	/* Command channel */
#ifdef _WITH_VRRP_
int netlink_error_ignore;	/* If we get this error, ignore it */
#endif

/* Static vars */
static nl_handle_t nl_kernel = { .fd = -1 };	/* Kernel reflection channel */

#ifdef _NETLINK_TIMERS_
/* The maximum netlink command we use is RTM_DELRULE.
 * If that changes, the following definition will need changing. */
#define MAX_NETLINK_TIMER	RTM_DELRULE

static struct timeval netlink_times[MAX_NETLINK_TIMER+1];
static unsigned netlink_count[MAX_NETLINK_TIMER+1];
#ifdef _WITH_VRRP_
static struct timeval start_time, end_time;
#endif

bool do_netlink_timers;
#endif

#ifdef _NETLINK_TIMERS_
void
report_and_clear_netlink_timers(const char * str)
{
	int i;

	log_message(LOG_INFO, "Netlink timers - %s", str);
	for (i = 0; i <= MAX_NETLINK_TIMER; i++) {
		if (netlink_count[i]) {
			log_message(LOG_INFO, "  netlink cmd %d (%u calls), time %ld.%6.6ld", i, netlink_count[i], netlink_times[i].tv_sec, netlink_times[i].tv_usec);
			netlink_times[i].tv_sec = netlink_times[i].tv_usec = netlink_count[i] = 0;
		}
	}
}
#endif

static const char *
get_nl_msg_type(unsigned type)
{
	switch (type) {
		switch_define_str(RTM_NEWLINK);
		switch_define_str(RTM_DELLINK);
		switch_define_str(RTM_NEWADDR);
		switch_define_str(RTM_DELADDR);
		switch_define_str(RTM_NEWROUTE);
		switch_define_str(RTM_DELROUTE);
		switch_define_str(RTM_NEWRULE);
		switch_define_str(RTM_DELRULE);
		switch_define_str(RTM_GETLINK);
		switch_define_str(RTM_GETADDR);
	};

	return "";
}

static inline bool
addr_is_equal2(struct ifaddrmsg* ifa, void* addr, ip_address_t* vip_addr, interface_t *ifp, vrrp_t *vrrp)
{
	struct in_addr* sin_addr;
	struct in6_addr* sin6_addr;

	/* If vrrp is specified, we also want to make sure the matching address isn't
	 * being added to the base interface of the vrrp instance */

	if (vip_addr->ifa.ifa_family != ifa->ifa_family)
		return false;
	if (vip_addr->ifp != ifp &&
	    !(vrrp && vrrp->ifp && vip_addr->ifp == vrrp->ifp && VRRP_CONFIGURED_IFP(vrrp) == ifp))
		return false;
	if (vip_addr->ifa.ifa_family == AF_INET) {
		sin_addr = PTR_CAST(struct in_addr, addr);
		return vip_addr->u.sin.sin_addr.s_addr == sin_addr->s_addr;
	}

	sin6_addr = PTR_CAST(struct in6_addr, addr);
	return vip_addr->u.sin6_addr.s6_addr32[0] == sin6_addr->s6_addr32[0] &&
	       vip_addr->u.sin6_addr.s6_addr32[1] == sin6_addr->s6_addr32[1] &&
	       vip_addr->u.sin6_addr.s6_addr32[2] == sin6_addr->s6_addr32[2] &&
	       vip_addr->u.sin6_addr.s6_addr32[3] == sin6_addr->s6_addr32[3];
}

static inline bool
addr_is_equal(struct ifaddrmsg* ifa, void* addr, ip_address_t* vip_addr, interface_t *ifp)
{
	return addr_is_equal2(ifa, addr, vip_addr, ifp, NULL);
}

#ifdef _WITH_VRRP_
static vrrp_t * __attribute__ ((pure))
address_is_ours(struct ifaddrmsg *ifa, struct in_addr *addr, interface_t *ifp)
{
	tracking_obj_t *top;
	vrrp_t *vrrp;
	ip_address_t *ip_addr;
	list_head_t *vip_list;

	list_for_each_entry(top, &ifp->tracking_vrrp, e_list) {
		vrrp = top->obj.vrrp;

		/* If we are not master, then we won't have the address configured */
		if (vrrp->state != VRRP_STATE_MAST)
			continue;

		for (vip_list = ifa->ifa_family == vrrp->family ? &vrrp->vip : &vrrp->evip;
		     vip_list;
		     vip_list = vip_list == &vrrp->vip ? &vrrp->evip : NULL) {
			list_for_each_entry(ip_addr, vip_list, e_list) {
				if (addr_is_equal(ifa, addr, ip_addr, ifp))
					return ip_addr->dont_track ? NULL : vrrp;
			}
		}
	}

	return NULL;
}

static bool __attribute__ ((pure))
ignore_address_if_ours_or_link_local(struct ifaddrmsg *ifa, struct in_addr *addr, interface_t *ifp)
{
	tracking_obj_t *top;
	vrrp_t *vrrp;
	ip_address_t *ip_addr;

	/* We are only interested in link local for IPv6 */
	if (ifa->ifa_family == AF_INET6 &&
	    ifa->ifa_scope != RT_SCOPE_LINK)
		return true;

	list_for_each_entry(top, &ifp->tracking_vrrp, e_list) {
		vrrp = top->obj.vrrp;

		if (ifa->ifa_family == vrrp->family) {
			list_for_each_entry(ip_addr, &vrrp->vip, e_list) {
				if (addr_is_equal2(ifa, addr, ip_addr, ifp, vrrp))
					return true;
			}
		}

		list_for_each_entry(ip_addr, &vrrp->evip, e_list) {
			if (addr_is_equal2(ifa, addr, ip_addr, ifp, vrrp))
				return true;
		}
	}

	return false;
}

#ifdef _WITH_VRRP_
static bool
compare_addr(int family, void *addr1, ip_address_t *addr2)
{
	union {
		struct in_addr *in;
		struct in6_addr *in6;
	} addr1_p = { .in = addr1 };

	if (family == AF_INET)
		return addr1_p.in->s_addr != addr2->u.sin.sin_addr.s_addr;

	return addr1_p.in6->s6_addr32[0] != addr2->u.sin6_addr.s6_addr32[0] ||
	       addr1_p.in6->s6_addr32[1] != addr2->u.sin6_addr.s6_addr32[1] ||
	       addr1_p.in6->s6_addr32[2] != addr2->u.sin6_addr.s6_addr32[2] ||
	       addr1_p.in6->s6_addr32[3] != addr2->u.sin6_addr.s6_addr32[3];
}

static ip_route_t *
route_is_ours(struct rtmsg* rt, struct rtattr *tb[RTA_MAX + 1], vrrp_t** ret_vrrp)
{
	uint32_t table;
	int family;
	int mask_len = rt->rtm_dst_len;
	uint32_t priority = 0;
	uint8_t tos = rt->rtm_tos;
	vrrp_t *vrrp;
	ip_route_t *route;
	union {
		struct in_addr in;
		struct in6_addr in6;
	} default_addr;

	*ret_vrrp = NULL;

	table = tb[RTA_TABLE] ? *PTR_CAST(uint32_t, RTA_DATA(tb[RTA_TABLE])) : rt->rtm_table;
	family = rt->rtm_family;
	if (tb[RTA_PRIORITY])
		priority = *PTR_CAST(uint32_t, RTA_DATA(tb[RTA_PRIORITY]));

	list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
		list_for_each_entry(route, &vrrp->vroutes, e_list) {
			if (table != route->table ||
			    family != route->family ||
			    mask_len != route->dst->ifa.ifa_prefixlen ||
			    priority != route->metric ||
			    tos != route->tos)
				continue;

			if (route->oif) {
				if (!tb[RTA_OIF] || route->oif->ifindex != *PTR_CAST(uint32_t, RTA_DATA(tb[RTA_OIF])))
					continue;
			} else {
				if (route->set && route->configured_ifindex &&
				    (!tb[RTA_OIF] || route->configured_ifindex != *PTR_CAST(uint32_t, RTA_DATA(tb[RTA_OIF]))))
					continue;
			}

			if (!tb[RTA_DST])
				memset(&default_addr, 0, sizeof(default_addr));

			if (compare_addr(family, tb[RTA_DST] ? RTA_DATA(tb[RTA_DST]) : &default_addr, route->dst))
				continue;

			*ret_vrrp = vrrp;
			return route;
		}
	}

	/* Now check the static routes */
	list_for_each_entry(route, &vrrp_data->static_routes, e_list) {
		if (table != route->table ||
		    family != route->family ||
		    mask_len != route->dst->ifa.ifa_prefixlen ||
		    tos != route->tos)
			continue;

		if (compare_addr(family, RTA_DATA(tb[RTA_DST]), route->dst))
			continue;

		return route;
	}

	return NULL;
}

static bool
compare_rule(struct fib_rule_hdr *frh, struct rtattr *tb[FRA_MAX + 1], ip_rule_t *rule)
{
	if (rule->dont_track)
		return false;

	if (rule->family != frh->family)
		return false;

	/* This is a very good descriminator, since our rules will always have a priority */
	if (!tb[FRA_PRIORITY] ||
	    rule->priority != *PTR_CAST(uint32_t, RTA_DATA(tb[FRA_PRIORITY])))
		return false;

	if (frh->action != rule->action)
		return false;

	if (frh->action == FR_ACT_GOTO &&
	    (!tb[FRA_GOTO] ||
	     *PTR_CAST(uint32_t, RTA_DATA(tb[FRA_GOTO])) != rule->goto_target))
		return false;

	if (tb[FRA_TABLE] && rule->table != *PTR_CAST(uint32_t, RTA_DATA(tb[FRA_TABLE])))
		return false;
	if (!tb[FRA_TABLE] && rule->table != frh->table)
		return false;

	if (!rule->invert != !((frh->flags & FIB_RULE_INVERT)))
		return false;

	if (!rule->from_addr != !tb[FRA_SRC])
		return false;
	if (rule->from_addr) {
		if (frh->src_len != rule->from_addr->ifa.ifa_prefixlen)
			return false;
		if (compare_addr(rule->family, RTA_DATA(tb[FRA_SRC]), rule->from_addr))
			return false;
	}

	if (!rule->to_addr != !tb[FRA_DST])
		return false;
	if (rule->to_addr) {
		if (frh->dst_len != rule->to_addr->ifa.ifa_prefixlen)
			return false;
		if (compare_addr(rule->family, RTA_DATA(tb[FRA_DST]), rule->to_addr))
			return false;
	}

	if (rule->tos != frh->tos)
		return false;

	if (!tb[FRA_FWMARK] != !(rule->mask & IPRULE_BIT_FWMARK))
		return false;
	if (rule->mask & IPRULE_BIT_FWMARK &&
	    *PTR_CAST(uint32_t, RTA_DATA(tb[FRA_FWMARK])) != rule->fwmark)
		return false;

	if (!tb[FRA_FWMASK] && (rule->mask & IPRULE_BIT_FWMASK))
		return false;
	if (rule->mask & IPRULE_BIT_FWMASK) {
		if (*PTR_CAST(uint32_t, RTA_DATA(tb[FRA_FWMASK])) != rule->fwmask)
			return false;
	}
	else if (tb[FRA_FWMASK]) {
		if (*PTR_CAST(uint32_t, RTA_DATA(tb[FRA_FWMASK])) != 0xffffffff)
			return false;
	}

	if (!tb[FRA_FLOW] != !rule->realms)
		return false;
	if (rule->realms &&
	    *PTR_CAST(uint32_t, RTA_DATA(tb[FRA_FLOW])) != rule->realms)
		return false;

#if HAVE_DECL_FRA_SUPPRESS_PREFIXLEN
	if (!tb[FRA_SUPPRESS_PREFIXLEN]) {
		if (rule->suppress_prefix_len != -1)
			return false;
	} else if (*PTR_CAST(int32_t, RTA_DATA(tb[FRA_SUPPRESS_PREFIXLEN])) != rule->suppress_prefix_len)
		return false;
#endif

#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
	if (!tb[FRA_SUPPRESS_IFGROUP] != !(rule->mask & IPRULE_BIT_SUP_GROUP))
		return false;
	if (rule->mask & IPRULE_BIT_SUP_GROUP &&
	    *PTR_CAST(uint32_t, RTA_DATA(tb[FRA_SUPPRESS_IFGROUP])) != rule->suppress_group)
		return false;
#endif

	if (!tb[FRA_IFNAME] != !(rule->iif))
		return false;
	if (rule->iif &&
	    strcmp(RTA_DATA(tb[FRA_IFNAME]), rule->iif->ifname))
		return false;

	if (!tb[FRA_OIFNAME] != !(rule->oif))
		return false;
	if (rule->oif &&
	    strcmp(RTA_DATA(tb[FRA_OIFNAME]), rule->oif->ifname))
		return false;

#if HAVE_DECL_FRA_TUN_ID
	uint64_t tunnel_id;
	if (!tb[FRA_TUN_ID] != !(rule->tunnel_id))
		return false;
	if (rule->tunnel_id) {
		tunnel_id = be64toh(*PTR_CAST(uint64_t, RTA_DATA(tb[FRA_TUN_ID])));
		if (tunnel_id != rule->tunnel_id)
			return false;
	}
#endif

#if HAVE_DECL_FRA_UID_RANGE
	if (!tb[FRA_UID_RANGE] != !(rule->mask & IPRULE_BIT_UID_RANGE))
		return false;
	if ((rule->mask & IPRULE_BIT_UID_RANGE) &&
	    memcmp(RTA_DATA(tb[FRA_UID_RANGE]), &rule->uid_range, sizeof rule->uid_range))
		return false;
#endif

#if HAVE_DECL_FRA_L3MDEV
	if (!tb[FRA_L3MDEV] && rule->l3mdev)
		return false;
	if (tb[FRA_L3MDEV] &&
	    *PTR_CAST(uint8_t, RTA_DATA(tb[FRA_L3MDEV])) != rule->l3mdev)
		return false;
#endif

#if HAVE_DECL_FRA_IP_PROTO
	if (!tb[FRA_IP_PROTO] != !(rule->mask & IPRULE_BIT_IP_PROTO))
		return false;
	if (rule->mask & IPRULE_BIT_IP_PROTO &&
	    *PTR_CAST(uint8_t, RTA_DATA(tb[FRA_IP_PROTO])) != rule->ip_proto)
		return false;
#endif

#if HAVE_DECL_FRA_SPORT_RANGE
	if (!tb[FRA_SPORT_RANGE] != !(rule->mask & IPRULE_BIT_SPORT_RANGE))
		return false;
	if (rule->mask & IPRULE_BIT_SPORT_RANGE &&
	    memcmp(RTA_DATA(tb[FRA_SPORT_RANGE]), &rule->src_port, sizeof rule->src_port))
		return false;
#endif

#if HAVE_DECL_FRA_DPORT_RANGE
	if (!tb[FRA_DPORT_RANGE] != !(rule->mask & IPRULE_BIT_DPORT_RANGE))
		return false;
	if (rule->mask & IPRULE_BIT_DPORT_RANGE &&
	    memcmp(RTA_DATA(tb[FRA_DPORT_RANGE]), &rule->dst_port, sizeof rule->dst_port))
		return false;
#endif

	return true;
}

static ip_rule_t *
rule_is_ours(struct fib_rule_hdr* frh, struct rtattr *tb[FRA_MAX + 1], vrrp_t **ret_vrrp)
{
	vrrp_t *vrrp;
	ip_rule_t *rule;

	*ret_vrrp = NULL;

	list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
		list_for_each_entry(rule, &vrrp->vrules, e_list) {
			if (compare_rule(frh, tb, rule)) {
				*ret_vrrp = vrrp;
				return rule;
			}
		}
	}

	list_for_each_entry(rule, &vrrp_data->static_rules, e_list) {
		if (compare_rule(frh, tb, rule))
			return rule;
	}

	return NULL;
}
#endif
#endif

/* Update the netlink socket receive buffer sizes */
static void
netlink_set_rx_buf_size(nl_handle_t *nl, unsigned rcvbuf_size, bool force)
{
	if (!rcvbuf_size)
		rcvbuf_size = IF_DEFAULT_BUFSIZE;

	/* Set rcvbuf size */
	if (force) {
		if (setsockopt(nl->fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf_size, sizeof(rcvbuf_size)) < 0)
			log_message(LOG_INFO, "cant set SO_RCVBUFFORCE IP option. errno=%d (%m)", errno);
	} else {
		if (setsockopt(nl->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0)
			log_message(LOG_INFO, "Cannot set SO_RCVBUF IP option. errno=%d (%m)", errno);
	}
}

#ifdef _WITH_VRRP_
static void
kernel_netlink_set_membership(int group, bool add)
{
	if (setsockopt(nl_kernel.fd, SOL_NETLINK, add ? NETLINK_ADD_MEMBERSHIP : NETLINK_DROP_MEMBERSHIP,
			&group, sizeof(group)) < 0)
		log_message(LOG_INFO, "Netlink: Cannot add membership on netlink socket : (%s)", strerror(errno));
}

void
set_extra_netlink_monitoring(bool ipv4_routes, bool ipv6_routes, bool ipv4_rules, bool ipv6_rules)
{
	kernel_netlink_set_membership(RTNLGRP_IPV4_ROUTE, ipv4_routes);
	kernel_netlink_set_membership(RTNLGRP_IPV6_ROUTE, ipv6_routes);
	kernel_netlink_set_membership(RTNLGRP_IPV4_RULE, ipv4_rules);
	kernel_netlink_set_membership(RTNLGRP_IPV6_RULE, ipv6_rules);
}
#endif

/* Create a socket to netlink interface_t */
static void
netlink_socket(nl_handle_t *nl, unsigned rcvbuf_size, bool force, int flags, unsigned group, ...)
{
	int ret;
	va_list gp;

	memset(nl, 0, sizeof (*nl));

	socklen_t addr_len;
	struct sockaddr_nl snl;
	int sock_flags = flags;

	nl->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | sock_flags, NETLINK_ROUTE);
	if (nl->fd < 0) {
		log_message(LOG_INFO, "Netlink: Cannot open netlink socket : (%s)",
		       strerror(errno));
		return;
	}

	memset(&snl, 0, sizeof (snl));
	snl.nl_family = AF_NETLINK;

	ret = bind(nl->fd, PTR_CAST(struct sockaddr, &snl), sizeof (snl));
	if (ret < 0) {
		log_message(LOG_INFO, "Netlink: Cannot bind netlink socket : (%s)",
		       strerror(errno));
		close(nl->fd);
		nl->fd = -1;
		return;
	}

	/* Join the requested groups */
	va_start(gp, group);
	while (group) {
		ret = setsockopt(nl->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group));
		if (ret < 0)
			log_message(LOG_INFO, "Netlink: Cannot add group %u membership on netlink socket : (%s)",
			       group, strerror(errno));

		group = va_arg(gp, unsigned);
	}
	va_end(gp);

	addr_len = sizeof (snl);
	ret = getsockname(nl->fd, PTR_CAST(struct sockaddr, &snl), &addr_len);
	if (ret < 0 || addr_len != sizeof (snl)) {
		log_message(LOG_INFO, "Netlink: Cannot getsockname : (%s)",
		       strerror(errno));
		close(nl->fd);
		nl->fd = -1;
		return;
	}

	if (snl.nl_family != AF_NETLINK) {
		log_message(LOG_INFO, "Netlink: Wrong address family %d",
		       snl.nl_family);
		close(nl->fd);
		nl->fd = -1;
		return;
	}

	/* Save the port id for checking message source later */
	nl->nl_pid = snl.nl_pid;


#ifdef _INCLUDE_UNUSED_CODE_
	/* There appears to be a kernel bug that manifests itself when we have a large number
	 * of VMAC interfaces to add (i.e. 200 or more). After approx 200 interfaces have been
	 * added the kernel will return ENOBUFS on the nl_kernel socket, and then repeat the
	 * first 30 or so RTM_NEWLINK messages, omitting the first one. Then, at the end of
	 * creating all the interfaces, i.e. after a slight delay with no new messages,
	 * we get another ENOBUFS and all the RTM_NEWLINK messages from the time of the
	 * first ENOBUFS message repeated.
	 *
	 * This problem also happens if the system already has a large (e.g. 200 or more)
	 * number of interfaces configured before keepalived starts.
	 *
	 * This problem feels as though a circular buffer is wrapping around, and causes
	 * all the old messages in the buffer to be resent, but the first one is omitted.
	 * Note that it is only the interfaces that keepalived creates that are resent,
	 * not interfaces that already existed on the system before keepalived starts.
	 *
	 * We can also get ENOBUFS on the nl_cmd socket if the NLM_F_ECHO flag is set as well as
	 * the NLM_F_ACK flag when a command is sent on the nl_cmd socket.
	 *
	 * It appears that this must be a kernel bug, since when it happens on interface creation,
	 * if we are also running `ip -ts monitor link addr route`, i.e. the same as the nl_kernel
	 * socket, then precisely the same messages are repeated (provided we have set the
	 * vrrp_netlink_cmd_rcv_bufs global configuration option to 1048576 (1024k) to match what
	 * ip monitor does).
	 */
	int one = 1;
	if ((ret = setsockopt(nl->fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one))) < 0)
		log_message(LOG_INFO, "Cannot set NETLINK_NO_ENOBUFS option. errno=%d (%m)", errno);
#endif

	nl->seq = (uint32_t)time(NULL);

	if (nl->fd < 0)
		return;

	netlink_set_rx_buf_size(nl, rcvbuf_size, force);
}

/* Close a netlink socket */
static void
netlink_close(nl_handle_t *nl)
{
	if (!nl)
		return;

	/* First of all release pending thread. There is no thread
	 * for nl_cmd since it is used synchronously. */
	if (nl->thread) {
		thread_cancel(nl->thread);
		nl->thread = NULL;
	}

	if (nl->fd != -1)
		close(nl->fd);

	nl->fd = -1;
}

/* iproute2 utility function */
/* GCC, at least up to v11.1.1, ignores the RELAX_STRINGOP_OVERFLOW below,
 * and produces warnings when doing the LTO link of vrrp_vmac.o and vrrp_ipaddress.o.
 * This should be tested periodically to see if specifying noinline can be removed.
 */
int LTO_NOINLINE
addattr_l(struct nlmsghdr *n, size_t maxlen, unsigned short type, const void *data, size_t alen)
{
	size_t len = RTA_LENGTH(alen);
	size_t align_len = NLMSG_ALIGN(len);
	struct rtattr *rta;

	if (n->nlmsg_len + align_len > maxlen)
		return -1;

	rta = PTR_CAST(struct rtattr, (((char *)n) + n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = (unsigned short)len;
RELAX_STRINGOP_OVERFLOW
	memcpy(RTA_DATA(rta), data, alen);
RELAX_END
	n->nlmsg_len += (uint32_t)align_len;

	return 0;
}

#ifdef _WITH_VRRP_
int
addattr_l2(struct nlmsghdr *n, size_t maxlen, unsigned short type, const void *data, size_t alen, const void *data2, size_t alen2)
{
	size_t len = RTA_LENGTH(alen + alen2);
	size_t align_len = NLMSG_ALIGN(len);
	struct rtattr *rta;

	if (n->nlmsg_len + align_len > maxlen)
		return -1;

	rta = PTR_CAST(struct rtattr, (((char *)n) + n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = (unsigned short)len;
	memcpy(RTA_DATA(rta), data, alen);
	memcpy((char *)RTA_DATA(rta) + alen, data2, alen2);
	n->nlmsg_len += (uint32_t)align_len;

	return 0;
}

int
addraw_l(struct nlmsghdr *n, size_t maxlen, const void *data, size_t len)
{
	size_t align_len = NLMSG_ALIGN(len);

	if (n->nlmsg_len + align_len > maxlen)
		return -1;

	memcpy(NLMSG_TAIL(n), data, len);
	if (align_len > len)
		memset(PTR_CAST(char, NLMSG_TAIL(n)) + len, 0, align_len - len);
	n->nlmsg_len += (uint32_t)align_len;
	return 0;
}

size_t
rta_addattr_l(struct rtattr *rta, size_t maxlen, unsigned short type,
		  const void *data, size_t alen)
{
	struct rtattr *subrta;
	size_t len = RTA_LENGTH(alen);
	size_t align_len = RTA_ALIGN(len);

	if (rta->rta_len + align_len > maxlen)
		return 0;

	subrta = PTR_CAST(struct rtattr, (char *)rta + rta->rta_len);
	subrta->rta_type = type;
	subrta->rta_len = (unsigned short)len;
	memcpy(RTA_DATA(subrta), data, alen);
	rta->rta_len = (unsigned short)(rta->rta_len + align_len);
	return align_len;
}

size_t
rta_addattr_l2(struct rtattr *rta, size_t maxlen, unsigned short type,
		  const void *data, size_t alen,
		  const void *data2, size_t alen2)
{
	struct rtattr *subrta;
	size_t len = RTA_LENGTH(alen + alen2);
	size_t align_len = RTA_ALIGN(len);

	if (rta->rta_len + align_len > maxlen)
		return 0;

	subrta = PTR_CAST(struct rtattr, (((char*)rta) + rta->rta_len));
	subrta->rta_type = type;
	subrta->rta_len = (unsigned short)len;
	memcpy(RTA_DATA(subrta), data, alen);
	memcpy((char *)RTA_DATA(subrta) + alen, data2, alen2);
	rta->rta_len = (unsigned short)(rta->rta_len + align_len);
	return align_len;
}

struct rtattr *
rta_nest(struct rtattr *rta, size_t maxlen, unsigned short type)
{
	struct rtattr *nest = RTA_TAIL(rta);

	rta_addattr_l(rta, maxlen, type, NULL, 0);

	return nest;
}

size_t
rta_nest_end(struct rtattr *rta, struct rtattr *nest)
{
	nest->rta_len = (unsigned short)((char *)RTA_TAIL(rta) - (char *)nest);

	return rta->rta_len;
}
#endif

static void
parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta, size_t len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta, len);
	}
}

#ifdef _WITH_VRRP_
static void
parse_rtattr_nested(struct rtattr **tb, int max, struct rtattr *rta)
{
	parse_rtattr(tb, max, RTA_DATA(rta), RTA_PAYLOAD(rta));
}

static void
set_vrrp_backup(vrrp_t *vrrp)
{
	vrrp_t *isync;

	vrrp->wantstate = VRRP_STATE_BACK;
	vrrp_state_leave_master(vrrp, true);
	if (vrrp->sync) {
		list_for_each_entry(isync, &vrrp->sync->vrrp_instances, s_list) {
			if (isync->state == VRRP_STATE_MAST) {
				isync->wantstate = VRRP_STATE_BACK;
				vrrp_state_leave_master(isync, true);

				/* We want a quick transition back to master */
				isync->ms_down_timer = VRRP_TIMER_SKEW(isync);
				vrrp_init_instance_sands(isync);
				vrrp_thread_requeue_read(isync);
			}
		}
		vrrp->sync->state = VRRP_STATE_BACK;
	}

	/* We want a quick transition back to master */
	vrrp->ms_down_timer = VRRP_TIMER_SKEW(vrrp);
	vrrp_init_instance_sands(vrrp);
	vrrp_thread_requeue_read(vrrp);
}

/* Check if we already have the address on the interface */
static bool __attribute__((pure))
have_address(const void *addr_p, const interface_t *ifp, int family)
{
	sin_addr_t *addr;
	const list_head_t *addr_l;

	if (!inet_inaddrcmp(family, addr_p, family == AF_INET ? (const void *)&ifp->sin_addr : (const void *)&ifp->sin6_addr))
		return true;

	addr_l = family == AF_INET ? &ifp->sin_addr_l : &ifp->sin6_addr_l;
	list_for_each_entry(addr, addr_l, e_list) {
		if (!inet_inaddrcmp(family, addr_p, addr))
		       return true;
	}

	return false;
}
#endif

/*
 * Netlink interface address lookup filter
 * We need to handle multiple primary address and
 * multiple secondary address to the same interface.
 * We also need to handle the same address on
 * multiple interfaces, for IPv6 link local addresses.
 */
static int
netlink_if_address_filter(__attribute__((unused)) struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	struct ifaddrmsg *ifa;
	struct rtattr *tb[IFA_MAX + 1];
	size_t len;
	union {
		void *addr;
		struct in_addr *in;
		struct in6_addr *in6;
	} addr;
#ifdef _WITH_VRRP_
	sin_addr_t *saddr;
	char addr_str[INET6_ADDRSTRLEN];
	bool addr_chg = false;
	vrrp_t *vrrp;
	interface_t *ifp;
	ip_address_t *ipaddr;
	vrrp_t *address_vrrp;
	tracking_obj_t *top;
	bool is_tracking_saddr;
#endif

	if (h->nlmsg_type != RTM_NEWADDR && h->nlmsg_type != RTM_DELADDR)
		return 0;

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof (struct ifaddrmsg)))
		return -1;

	ifa = NLMSG_DATA(h);

	/* Only IPv4 and IPv6 are valid for us */
	if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct ifaddrmsg));

	parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), len);

	if (tb[IFA_LOCAL] == NULL)
		tb[IFA_LOCAL] = tb[IFA_ADDRESS];
	if (tb[IFA_ADDRESS] == NULL)
		tb[IFA_ADDRESS] = tb[IFA_LOCAL];

	/* local interface address */
	addr.addr = (tb[IFA_LOCAL] ? RTA_DATA(tb[IFA_LOCAL]) : NULL);

	if (addr.addr == NULL)
		return -1;

#ifdef _WITH_VRRP_
#ifndef _ONE_PROCESS_DEBUG_
	if (prog_type == PROG_TYPE_VRRP || __test_bit(CONFIG_TEST_BIT, &debug))
#endif
	{
		/* Fetch interface_t */
		ifp = if_get_by_ifindex(ifa->ifa_index);
		if (!ifp)
			return 0;

// ?? Only interested in link-local for IPv6 unless unicast
// we take address from vrrp->ifp->base_ifp, unless we have made an IPv6 address
// do we want to set a flag to say it is a generated link local address (or set saddr and track_saddr, but not saddr_from_config)
// or can we just compare address to vrrp->ifp->base_ifp address.
// We still need to consider non-vmac IPv6 if interface doesn't have a
// link local address.
		if (h->nlmsg_type == RTM_NEWADDR) {
			if (!ignore_address_if_ours_or_link_local(ifa, addr.addr, ifp)) {
				/* If no address is set on interface then set the first time */
// TODO if saddr from config && track saddr, addresses must match
				if (ifa->ifa_family == AF_INET) {
					if (!ifp->sin_addr.s_addr) {
						ifp->sin_addr = *addr.in;
						if (!list_empty(&ifp->tracking_vrrp))
							addr_chg = true;
					} else {
						/* Check we don't already have the address -
						 * it might be being promoted from secondary to primary */
						if (!have_address(addr.in, ifp, AF_INET))
							if_extra_ipaddress_alloc(ifp, addr.in, AF_INET);
					}
				} else {
					if (IN6_IS_ADDR_UNSPECIFIED(&ifp->sin6_addr)) {
						ifp->sin6_addr = *addr.in6;
						if (!list_empty(&ifp->tracking_vrrp))
							addr_chg = true;
					}
#if defined _HAVE_VRRP_VMAC_ && !HAVE_DECL_IFLA_INET6_ADDR_GEN_MODE
					else if (ifp->is_ours && ifp->if_type == IF_TYPE_MACVLAN) {
						/* We already have an address; is this an auto generated link local address?
						 * For some reason if we recreate the VMAC when the underlying interface is
						 * recreated, deleting the autogenerated address doesn't get rid of the address */
						remove_vmac_auto_gen_addr(ifp, addr.in6);
					}
#endif
					else {
						/* Check we don't already have the address -
						 * it might be being promoted from secondary to primary */
						if (!have_address(addr.in6, ifp, AF_INET6))
							if_extra_ipaddress_alloc(ifp, addr.in6, AF_INET6);
					}
				}

				if (addr_chg) {
					if (__test_bit(LOG_DETAIL_BIT, &debug)) {
						inet_ntop(ifa->ifa_family, addr.addr, addr_str, sizeof(addr_str));
						log_message(LOG_INFO, "Assigned address %s for interface %s"
								    , addr_str, ifp->ifname);
					}

					/* Now see if any vrrp instances were missing an interface address
					 * and see if they can be brought up */
					list_for_each_entry(top, &ifp->tracking_vrrp, e_list) {
						vrrp = top->obj.vrrp;

						if (vrrp->track_saddr && vrrp->family == ifa->ifa_family)
							is_tracking_saddr = inaddr_equal(ifa->ifa_family, &vrrp->saddr, addr.addr);
						else
							is_tracking_saddr = false;

						if (ifp == (
#ifdef _HAVE_VRRP_VMAC_
							    vrrp->family == AF_INET ? VRRP_CONFIGURED_IFP(vrrp) :
#endif
							    vrrp->ifp) &&
						    vrrp->num_script_if_fault &&
						    vrrp->family == ifa->ifa_family &&
						    vrrp->saddr.ss_family == AF_UNSPEC &&
						    (!vrrp->saddr_from_config || is_tracking_saddr)) {
							/* Copy the address */
							if (ifa->ifa_family == AF_INET)
								inet_ip4tosockaddr(addr.in, &vrrp->saddr);
							else
								inet_ip6tosockaddr(addr.in6, &vrrp->saddr);
							try_up_instance(vrrp, false);
						}
#ifdef _HAVE_VRRP_VMAC_
						/* If IPv6 link local and vmac doesn't have an address, add it to the vmac */
						else if (vrrp->family == AF_INET6 &&
							 vrrp->ifp &&
							 ifp == vrrp->ifp->base_ifp &&
							 IS_MAC_IP_VLAN(vrrp->ifp) &&
							 !__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags) &&
							 vrrp->num_script_if_fault &&
							 vrrp->family == ifa->ifa_family &&
							 vrrp->saddr.ss_family == AF_UNSPEC &&
							 (!vrrp->saddr_from_config || is_tracking_saddr)) {
							if (add_link_local_address(vrrp->ifp, addr.in6)) {
								inet_ip6tosockaddr(addr.in6, &vrrp->saddr);
								try_up_instance(vrrp, false);
							}
						}
#endif
					}
				}
			}
		} else {
			/* Mark the address as needing to go. We can't delete the address
			 * until after down_instance is called, since it sends a prio 0 message */
			if (ifa->ifa_family == AF_INET) {
				if (inaddr_equal(AF_INET, &ifp->sin_addr, addr.in)) {
					if (list_empty(&ifp->sin_addr_l))
						addr_chg = true;
					else {
						saddr = list_last_entry(&ifp->sin_addr_l, sin_addr_t, e_list);
						ifp->sin_addr = saddr->u.sin_addr;
						if_extra_ipaddress_free(saddr);

						list_for_each_entry(top, &ifp->tracking_vrrp, e_list) {
							vrrp = top->obj.vrrp;
							if (VRRP_CONFIGURED_IFP(vrrp) != ifp)
								continue;
							if (vrrp->family != AF_INET || vrrp->saddr_from_config)
								continue;
							inet_ip4tosockaddr(&ifp->sin_addr, &vrrp->saddr);
						}
					}
				} else {
					list_for_each_entry(saddr, &ifp->sin_addr_l, e_list) {
						if (inaddr_equal(AF_INET, &saddr->u.sin_addr, addr.in)) {
							if_extra_ipaddress_free(saddr);
							break;
						}
					}
				}
			}
			else if (ifa->ifa_scope == RT_SCOPE_LINK) {
				if (inaddr_equal(AF_INET6, &ifp->sin6_addr, addr.in6)) {
					if (list_empty(&ifp->sin6_addr_l))
						addr_chg = true;
					else {
						saddr = list_last_entry(&ifp->sin6_addr_l, sin_addr_t, e_list);
						ifp->sin6_addr = saddr->u.sin6_addr;
						if_extra_ipaddress_free(saddr);

						list_for_each_entry(top, &ifp->tracking_vrrp, e_list) {
							vrrp = top->obj.vrrp;
							if (vrrp->ifp != ifp)
								continue;
							if (vrrp->family != AF_INET6 || vrrp->saddr_from_config)
								continue;
							inet_ip6tosockaddr(&ifp->sin6_addr, &vrrp->saddr);
						}
					}
				} else {
					list_for_each_entry(saddr, &ifp->sin6_addr_l, e_list) {
						if (inaddr_equal(AF_INET6, &saddr->u.sin6_addr, addr.in6)) {
							if_extra_ipaddress_free(saddr);
							break;
						}
					}
				}
			}

			if (addr_chg && !list_empty(&ifp->tracking_vrrp)) {
				if (__test_bit(LOG_DETAIL_BIT, &debug)) {
					inet_ntop(ifa->ifa_family, addr.addr, addr_str, sizeof(addr_str));
					log_message(LOG_INFO, "Deassigned address %s from interface %s"
							    , addr_str, ifp->ifname);
				}
				if (ifa->ifa_family == AF_INET)
					ifp->sin_addr.s_addr = 0;
				else
					CLEAR_IP6_ADDR(&ifp->sin6_addr);

				/* See if any vrrp instances need to be downed */
				list_for_each_entry(top, &ifp->tracking_vrrp, e_list) {
					vrrp = top->obj.vrrp;

					if (!vrrp->ifp)
						continue;

					if (ifp != vrrp->ifp
#ifdef _HAVE_VRRP_VMAC_
					    && ifp != VRRP_CONFIGURED_IFP(vrrp)
#endif
									       )
						continue;
					if (vrrp->family != ifa->ifa_family)
						continue;
					if (!inaddr_equal(ifa->ifa_family, vrrp->family == AF_INET ? &(PTR_CAST(struct sockaddr_in, &vrrp->saddr))->sin_addr : (void *)&(PTR_CAST(struct sockaddr_in6, &vrrp->saddr))->sin6_addr, addr.addr))
						continue;

					is_tracking_saddr = vrrp->track_saddr &&
							    vrrp->family == ifa->ifa_family &&
							    inaddr_equal(ifa->ifa_family, &vrrp->saddr, addr.addr);
#ifdef _HAVE_VRRP_VMAC_
					/* If we are a VMAC and took this address from the parent interface, we need to
					 * release the address and create one for ourself */
					if (ifa->ifa_family == AF_INET6 &&
					    __test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags) &&
					    ifp == vrrp->ifp->base_ifp &&
					    !__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags) &&
					    !vrrp->saddr_from_config) {
// This is rubbish if base i/f addr changed. Check against address generated from base i/f's MAC
						if (IF_ISUP(ifp) && replace_link_local_address(vrrp->ifp))
						{
							addr_chg = false;
							inet_ip6tosockaddr(&vrrp->ifp->sin6_addr, &vrrp->saddr);
						}
						else if (IF_ISUP(ifp)) {
							/* We failed to add an address, so down the instance */
							down_instance(vrrp);
							vrrp->saddr.ss_family = AF_UNSPEC;
						}
					}
					else
#endif
					     if (ifp == (
#ifdef _HAVE_VRRP_VMAC_
							 vrrp->family == AF_INET ? VRRP_CONFIGURED_IFP(vrrp) :
#endif
							 vrrp->ifp) &&
						 vrrp->family == ifa->ifa_family &&
						 vrrp->saddr.ss_family != AF_UNSPEC &&
						 (!vrrp->saddr_from_config || is_tracking_saddr)) {
						down_instance(vrrp);
						vrrp->saddr.ss_family = AF_UNSPEC;
					}
				}
			}

			if (addr_chg) {
				/* Now we can remove the address */
				if (ifa->ifa_family == AF_INET)
					ifp->sin_addr.s_addr = 0;
				else
					CLEAR_IP6_ADDR(&ifp->sin6_addr);
			}
		}

		if (!addr_chg || list_empty(&ifp->tracking_vrrp)) {
			if (h->nlmsg_type == RTM_DELADDR)
				address_vrrp = address_is_ours(ifa, addr.addr, ifp);
			else
				address_vrrp = NULL;

			/* Display netlink operation */
			if (
#ifdef _WITH_LVS_
			    __test_bit(LOG_ADDRESS_CHANGES, &debug) ||
#endif
			    (__test_bit(LOG_DETAIL_BIT, &debug) && address_vrrp)) {
				inet_ntop(ifa->ifa_family, addr.addr, addr_str, sizeof(addr_str));
				log_message(LOG_INFO, "Netlink reflector reports IP %s %s %s"
						    , addr_str, h->nlmsg_type == RTM_NEWADDR ? "added to" : "removed from", ifp->ifname);
			}

			/* If one of our VIPs/eVIPs has been deleted, transition to backup */
			if (address_vrrp && address_vrrp->state == VRRP_STATE_MAST) {
				set_vrrp_backup(address_vrrp);
			}
		}

		if (h->nlmsg_type == RTM_DELADDR) {
			/* Check if a static address has been deleted */
			list_for_each_entry(ipaddr, &vrrp_data->static_addresses, e_list) {
				if (!ipaddr->dont_track && addr_is_equal(ifa, addr.addr, ipaddr, ifp)) {
					reinstate_static_address(ipaddr);
					break;
				}
			}
		}
	}
#endif

#ifdef _WITH_LVS_
#ifndef _ONE_PROCESS_DEBUG_
	if (prog_type == PROG_TYPE_CHECKER)
#endif
	{
		/* Refresh checkers state */
		update_checker_activity(ifa->ifa_family, addr.addr,
					(h->nlmsg_type == RTM_NEWADDR));
	}
#endif

	return 0;
}

/* Our netlink parser */
static int
netlink_parse_info(int (*filter) (struct sockaddr_nl *, struct nlmsghdr *),
		   nl_handle_t *nl, struct nlmsghdr *n, bool read_all)
{
	ssize_t len;
	int ret = 0;
	int error;
	char *nlmsg_buf __attribute__((aligned(__alignof__(struct nlmsghdr)))) = NULL;
	int nlmsg_buf_size = 0;

	while (true) {
		struct iovec iov = {
			.iov_len = 0
		};
		struct sockaddr_nl snl;
		struct msghdr msg = {
			.msg_name = &snl,
			.msg_namelen = sizeof(snl),
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = NULL,
			.msg_controllen = 0,
			.msg_flags = 0
		};
		struct nlmsghdr *h;

		/* Find out how big our receive buffer needs to be */
		do {
			len = recvmsg(nl->fd, &msg, MSG_PEEK | MSG_TRUNC);
		} while (len < 0 && check_EINTR(errno));

		if (len < 0) {
			ret = -1;
			break;
		}

		if (len == 0)
			break;

		if (len > nlmsg_buf_size) {
			FREE_PTR(nlmsg_buf);
			nlmsg_buf = MALLOC(len);
			nlmsg_buf_size = len;
		}

		iov.iov_base = nlmsg_buf;
		iov.iov_len = nlmsg_buf_size;

		do {
			len = recvmsg(nl->fd, &msg, 0);
		} while (len < 0 && check_EINTR(errno));

		if (len < 0) {
			if (check_EAGAIN(errno))
				break;
			if (errno == ENOBUFS) {
				log_message(LOG_INFO, "Netlink: Receive buffer overrun on %s socket - (%m)", nl == &nl_kernel ? "monitor" : "cmd");
				log_message(LOG_INFO, "  - increase the relevant netlink_rcv_bufs global parameter and/or set force");
			}
			else
				log_message(LOG_INFO, "Netlink: recvmsg error on %s socket  - %d (%m)", nl == &nl_kernel ? "monitor" : "cmd", errno);
			continue;
		}

		if (len == 0) {
			log_message(LOG_INFO, "Netlink: EOF");
			ret = -1;
			break;
		}

		if (msg.msg_namelen != sizeof snl) {
			log_message(LOG_INFO,
			       "Netlink: Sender address length error: length %u",
			       msg.msg_namelen);
			ret = -1;
			break;
		}

		for (h = PTR_CAST(struct nlmsghdr, nlmsg_buf); NLMSG_OK(h, (size_t)len); h = NLMSG_NEXT(h, len)) {
			/* Finish off reading. */
			if (h->nlmsg_type == NLMSG_DONE) {
				FREE(nlmsg_buf);
				return ret;
			}

			/* Error handling. */
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = PTR_CAST(struct nlmsgerr, NLMSG_DATA(h));

				/*
				 * If error == 0 then this is a netlink ACK.
				 * return if not related to multipart message.
				 */
				if (err->error == 0) {
					if (!(h->nlmsg_flags & NLM_F_MULTI) && !read_all) {
						FREE(nlmsg_buf);
						return 0;
					}
					continue;
				}

				if (h->nlmsg_len < NLMSG_LENGTH(sizeof (struct nlmsgerr))) {
					log_message(LOG_INFO,
					       "Netlink: error: message truncated");
					FREE(nlmsg_buf);
					return -1;
				}

				if (n && (err->error == -EEXIST) &&
				    ((n->nlmsg_type == RTM_NEWROUTE) ||
				     (n->nlmsg_type == RTM_NEWADDR))) {
					FREE(nlmsg_buf);
					return 0;
				}

				/* If have more than one IPv4 address in the same CIDR
				 * and the "primary" address is removed, unless promote_secondaries
				 * is configured on the interface, all the "secondary" addresses
				 * in the same CIDR are deleted */
				if (n && err->error == -EADDRNOTAVAIL &&
				    n->nlmsg_type == RTM_DELADDR) {
					if (!(h->nlmsg_flags & NLM_F_MULTI)) {
						FREE(nlmsg_buf);
						return 0;
					}
					continue;
				}
#ifdef _WITH_VRRP_
				if (netlink_error_ignore != -err->error)
#endif
					log_message(LOG_INFO,
					       "Netlink: error: %s(%d), type=%s(%u), seq=%u, pid=%u",
					       strerror(-err->error), -err->error,
					       get_nl_msg_type(err->msg.nlmsg_type), err->msg.nlmsg_type,
					       err->msg.nlmsg_seq, err->msg.nlmsg_pid);

				FREE(nlmsg_buf);
				return -1;
			}

#ifdef _WITH_VRRP_
			/* Skip messages on the kernel reflection channel
			 * caused by commands from our cmd channel */
			if (
#ifndef _ONE_PROCESS_DEBUG_
			    prog_type == PROG_TYPE_VRRP &&
#endif
			    h->nlmsg_type != RTM_NEWLINK &&
			    h->nlmsg_type != RTM_DELLINK &&
			    h->nlmsg_type != RTM_NEWROUTE &&
// Allow NEWADDR/DELADDR for ipvlans
			    nl != &nl_cmd && h->nlmsg_pid == nl_cmd.nl_pid)
				continue;
#endif

			error = (*filter) (&snl, h);
			if (error < 0) {
				log_message(LOG_INFO, "Netlink: filter function error");
				ret = error;
			}

			if (!(h->nlmsg_flags & NLM_F_MULTI) && !read_all) {
				FREE(nlmsg_buf);
				return ret;
			}
		}

		/* After error care. */
		if (msg.msg_flags & MSG_TRUNC) {
			log_message(LOG_INFO, "Netlink: error: message truncated");
			continue;
		}
		if (len) {
			log_message(LOG_INFO, "Netlink: error: data remnant size %zd",
			       len);

			ret = -1;
			break;
		}
	}

	if (nlmsg_buf)
		FREE(nlmsg_buf);

	return ret;
}

#ifdef _WITH_VRRP_
/* Out talk filter */
static int
netlink_talk_filter(__attribute__((unused)) struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	log_message(LOG_INFO, "Netlink: ignoring message type 0x%04x", h->nlmsg_type);

	return 0;
}

/* send message to netlink kernel socket, then receive response */
ssize_t
netlink_talk(nl_handle_t *nl, struct nlmsghdr *n)
{
	ssize_t status;
	struct sockaddr_nl snl;
	struct iovec iov = {
		.iov_base = n,
		.iov_len = n->nlmsg_len
	};
	struct msghdr msg = {
		.msg_name = &snl,
		.msg_namelen = sizeof(snl),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0
	};

	memset(&snl, 0, sizeof snl);
	snl.nl_family = AF_NETLINK;

	n->nlmsg_seq = ++nl->seq;

	/* Request Netlink acknowledgement */
	n->nlmsg_flags |= NLM_F_ACK;

#ifdef _NETLINK_TIMERS_
	gettimeofday(&start_time, NULL);
#endif

	/* Send message to netlink interface. */
	status = sendmsg(nl->fd, &msg, 0);
	if (status < 0) {
		log_message(LOG_INFO, "Netlink: sendmsg(%d) cmd %d error: %s", nl->fd, n->nlmsg_type,
		       strerror(errno));
		return -1;
	}

	status = netlink_parse_info(netlink_talk_filter, nl, n, false);

#ifdef _NETLINK_TIMERS_
	/* Special case for NEWLINK - treat create separately; it is also used to up an interface etc. */
	int index = n->nlmsg_type == RTM_NEWLINK && (n->nlmsg_flags & NLM_F_CREATE) ? 0 : n->nlmsg_type;
	gettimeofday(&end_time, NULL);
	if (index <= MAX_NETLINK_TIMER) {
		netlink_times[index].tv_sec += end_time.tv_sec - start_time.tv_sec;
		netlink_times[index].tv_usec += end_time.tv_usec - start_time.tv_usec;
		netlink_count[index]++;
		if (netlink_times[index].tv_usec < 0)
			netlink_times[index].tv_usec += 1000000, netlink_times[index].tv_sec--;
		else if (netlink_times[index].tv_usec > 1000000)
			netlink_times[index].tv_usec -= 1000000, netlink_times[index].tv_sec++;
	}
#endif

	return status;
}
#endif

/* Fetch a specific type of information from netlink kernel */
static int
netlink_request(nl_handle_t *nl,
		unsigned char family,
		uint16_t type,
#ifndef _WITH_VRRP_
		__attribute__((unused))
#endif
					char *name)
{
	ssize_t status;
	struct sockaddr_nl snl = { .nl_family = AF_NETLINK };
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg i;
		char buf[64];
	} req = { .nlh.nlmsg_type = type };

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof req.i);
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = ++nl->seq;
	req.i.ifi_family = family;

#ifdef _WITH_VRRP_
	if (name)
		addattr_l(&req.nlh, sizeof req, IFLA_IFNAME, name, strlen(name) + 1);
	else
#endif
		req.nlh.nlmsg_flags |= NLM_F_DUMP;
#if HAVE_DECL_RTEXT_FILTER_SKIP_STATS
	/* The following produces a -Wstringop-overflow warning due to writing
	 * 4 bytes into a region of size 0. This is, however, safe. */
	addattr32(&req.nlh, sizeof req, IFLA_EXT_MASK, RTEXT_FILTER_SKIP_STATS);
#endif

	status = sendto(nl->fd, (void *) &req, sizeof (req)
			, 0, PTR_CAST(struct sockaddr, &snl), sizeof (snl));
	if (status < 0) {
		log_message(LOG_INFO, "Netlink: sendto() failed: %s",
		       strerror(errno));
		return -1;
	}
	return 0;
}

#ifdef _WITH_VRRP_
void
process_if_status_change(interface_t *ifp)
{
	vrrp_t *vrrp;
	tracking_obj_t *top;
	bool now_up = FLAGS_UP(ifp->ifi_flags);

	/* The state of the interface has changed from up to down or vice versa.
	 * Find which vrrp instances are affected */
	list_for_each_entry(top, &ifp->tracking_vrrp, e_list) {
		vrrp = top->obj.vrrp;

		if (top->weight == VRRP_NOT_TRACK_IF) {
			/* We might want to restore things to the interface if it is coming up */
			continue;
		}

		if (top->weight) {
			if (now_up)
				vrrp->total_priority += abs(top->weight) * top->weight_multiplier;
			else
				vrrp->total_priority -= abs(top->weight) * top->weight_multiplier;
			vrrp_set_effective_priority(vrrp);

			continue;
		}

		/* This vrrp's interface or underlying interface has changed */
		if (now_up == (top->weight_multiplier == 1))
			try_up_instance(vrrp, false);
		else
			down_instance(vrrp);
	}
}

static void
update_interface_flags(interface_t *ifp, unsigned ifi_flags)
{
	bool was_up, now_up;

	if (ifi_flags == ifp->ifi_flags)
		return;

	if (!vrrp_data)
		return;

	/* We get called after a VMAC is created, but before tracking_vrrp is set */

	/* For an interface to be really up, any underlying interface must also be up */
	was_up = IF_FLAGS_UP(ifp);
	now_up = FLAGS_UP(ifi_flags);
	ifp->ifi_flags = ifi_flags;

	if (was_up == now_up)
		return;

	if (!list_empty(&ifp->tracking_vrrp)) {
		log_message(LOG_INFO, "Netlink reports %s %s", ifp->ifname, now_up ? "up" : "down");

		process_if_status_change(ifp);
	}

	if (!now_up)
		interface_down(ifp);
	else
		interface_up(ifp);
}

static const char *
get_mac_string(int type)
 {
	switch (type) {
	case IFLA_BROADCAST:
		return "Broadcast";
	case IFLA_ADDRESS:
		return "Address";
	default:
		return "Unknown Type";
	}
}

static bool
netlink_if_get_ll_addr(interface_t *ifp, struct rtattr *tb[],
				  int type, char *name)
{
	size_t i;

	if (tb[type]) {
		size_t hw_addr_len = RTA_PAYLOAD(tb[type]);

		if (hw_addr_len > sizeof(ifp->hw_addr)) {
			log_message(LOG_ERR,
				    " %s MAC address for %s is too large: %zu",
				    get_mac_string(type), name, hw_addr_len);
			return false;
		}

		switch (type) {

		case IFLA_ADDRESS:
			ifp->hw_addr_len = hw_addr_len;
			memcpy(ifp->hw_addr, RTA_DATA(tb[type]), hw_addr_len);
			/*
			 * Don't allow a hardware address of all zeroes
			 * Mark hw_addr_len as 0 to warn
			 */
			for (i = 0; i < hw_addr_len; i++)
				if (ifp->hw_addr[i] != 0)
					break;
			if (i == hw_addr_len)
				ifp->hw_addr_len = 0;
			else
				ifp->hw_addr_len = hw_addr_len;
			break;

		case IFLA_BROADCAST:
			memcpy(ifp->hw_addr_bcast, RTA_DATA(tb[type]),
			       hw_addr_len);
			break;

		default:
			return false;
		}
	}

	return true;
}

#ifdef _HAVE_IPV4_DEVCONF_
static void
parse_af_spec(struct rtattr* attr, interface_t *ifp)
{
	struct rtattr* afspec[AF_INET6 + 1];
	struct rtattr* inet[IFLA_INET_MAX + 1];
	uint32_t* inet_devconf;

	if (!attr)
		return;

	parse_rtattr_nested(afspec, AF_INET6, attr);
	if (afspec[AF_INET]) {
		parse_rtattr_nested(inet, IFLA_INET_MAX, afspec[AF_INET]);
		if (inet[IFLA_INET_CONF]) {
			inet_devconf = RTA_DATA(inet[IFLA_INET_CONF]);
#ifdef _HAVE_VRRP_VMAC_
			ifp->arp_ignore = inet_devconf[IPV4_DEVCONF_ARP_IGNORE - 1];
			ifp->arp_filter = inet_devconf[IPV4_DEVCONF_ARPFILTER - 1];
			if (ifp->rp_filter == UINT_MAX)
				ifp->rp_filter = inet_devconf[IPV4_DEVCONF_RP_FILTER - 1];
#endif
			ifp->promote_secondaries = inet_devconf[IPV4_DEVCONF_PROMOTE_SECONDARIES - 1];
		}
	}
}
#endif

static bool
netlink_if_link_populate(interface_t *ifp, struct rtattr *tb[], struct ifinfomsg *ifi)
{
	char *name;
#ifdef _HAVE_VRRP_VMAC_
	struct rtattr* linkinfo[IFLA_INFO_MAX+1];
#if defined _HAVE_VRRP_IPVLAN_ && defined _HAVE_VRF_
	struct rtattr* linkattr[max(max(IFLA_MACVLAN_MAX, IFLA_IPVLAN_MAX), IFLA_VRF_MAX) + 1];
#elif defined _HAVE_VRRP_IPVLAN_
	struct rtattr* linkattr[max(IFLA_MACVLAN_MAX, IFLA_IPVLAN_MAX) + 1];
#elif defined _HAVE_VRF_
	struct rtattr* linkattr[max(IFLA_MACVLAN_MAX, IFLA_VRF_MAX) + 1];
#else
	struct rtattr* linkattr[IFLA_MACVLAN_MAX + 1];
#endif
	bool was_vlan;
#ifdef _HAVE_VRF_
	struct rtattr *vrf_attr[IFLA_VRF_MAX + 1];
	bool is_vrf = false;
	uint32_t new_vrf_master_index;
	bool is_vrf_master = false;
#endif
#endif

#ifdef _HAVE_VRRP_VMAC_
	was_vlan = IS_MAC_IP_VLAN(ifp);
#endif

	name = (char *)RTA_DATA(tb[IFLA_IFNAME]);

	/* Fill the interface structure */
	strcpy_safe(ifp->ifname, name);
	ifp->ifindex = (ifindex_t)ifi->ifi_index;
#ifdef _HAVE_VRRP_VMAC_
	ifp->if_type = IF_TYPE_STANDARD;
#endif
#ifdef HAVE_IFLA_LINK_NETNSID						/* from Linux v4.0 */
	ifp->base_netns_id = -1;
#endif

#ifdef _HAVE_VRRP_VMAC_
	if (tb[IFLA_LINKINFO]) {
		parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO]);

		if (linkinfo[IFLA_INFO_KIND]) {
			if (!strcmp((char *)RTA_DATA(linkinfo[IFLA_INFO_KIND]), "macvlan") ||
			    !strcmp((char *)RTA_DATA(linkinfo[IFLA_INFO_KIND]), "macvtap")) {
				ifp->if_type = IF_TYPE_MACVLAN;
				parse_rtattr_nested(linkattr, IFLA_MACVLAN_MAX, linkinfo[IFLA_INFO_DATA]);
			}
#ifdef _HAVE_VRRP_IPVLAN_
			else if (!strcmp((char *)RTA_DATA(linkinfo[IFLA_INFO_KIND]), "ipvlan") ||
				 !strcmp((char *)RTA_DATA(linkinfo[IFLA_INFO_KIND]), "ipvtap")) {
				ifp->if_type = IF_TYPE_IPVLAN;
				parse_rtattr_nested(linkattr, IFLA_IPVLAN_MAX, linkinfo[IFLA_INFO_DATA]);
			}
#endif
#ifdef _HAVE_VRF_
			else if (!strcmp((char *)RTA_DATA(linkinfo[IFLA_INFO_KIND]), "vrf") ) {
				is_vrf = true;
				ifp->if_type = IF_TYPE_VRF;
				parse_rtattr_nested(vrf_attr, IFLA_VRF_MAX, linkinfo[IFLA_INFO_DATA]);
			}
#endif
		}
	}

#ifdef _HAVE_IPV4_DEVCONF_
	if (tb[IFLA_AF_SPEC])
		parse_af_spec(tb[IFLA_AF_SPEC], ifp);
#endif

	/* Check there hasn't been an unsupported interface type change */
	if (!global_data->allow_if_changes && ifp->seen_interface) {
		/* If it was a macvlan and now isn't, or vice versa,
		 * then the interface type has changed */
		if (IS_MAC_IP_VLAN(ifp) != was_vlan)
			return false;

		/* If a macvlan, check the underlying interface hasn't changed */
		if (IS_MAC_IP_VLAN(ifp) &&
		    (!tb[IFLA_LINK] || ifp->base_ifp->ifindex != *PTR_CAST(uint32_t, RTA_DATA(tb[IFLA_LINK]))))
			return false;
	}
#endif

	ifp->mtu = *PTR_CAST(uint32_t, RTA_DATA(tb[IFLA_MTU]));
	ifp->hw_type = ifi->ifi_type;

	if (!netlink_if_get_ll_addr(ifp, tb, IFLA_ADDRESS, name))
		return false;
	if (!netlink_if_get_ll_addr(ifp, tb, IFLA_BROADCAST, name))
		return false;

#ifdef _HAVE_VRRP_VMAC_
	ifp->base_ifp = ifp;
	ifp->base_ifindex = 0;

	if (tb[IFLA_LINKINFO]) {
		if (linkinfo[IFLA_INFO_KIND]) {
			/* See if this interface is a MACVLAN */
			if (IS_MAC_IP_VLAN(ifp)) {
				if (((ifp->if_type == IF_TYPE_MACVLAN && linkattr[IFLA_MACVLAN_MODE])
#ifdef _HAVE_VRRP_IPVLAN_
				     || (ifp->if_type == IF_TYPE_IPVLAN && linkattr[IFLA_IPVLAN_MODE])
#endif
												      )	&&
				    tb[IFLA_LINK]) {
					if (ifp->if_type == IF_TYPE_MACVLAN)
						ifp->vmac_type = *PTR_CAST(uint32_t, RTA_DATA(linkattr[IFLA_MACVLAN_MODE]));
#ifdef _HAVE_VRRP_IPVLAN_
					else {
						ifp->vmac_type = *PTR_CAST(uint32_t, RTA_DATA(linkattr[IFLA_IPVLAN_MODE]));
#if HAVE_DECL_IFLA_IPVLAN_FLAGS
						ifp->ipvlan_flags = *PTR_CAST(uint32_t, RTA_DATA(linkattr[IFLA_IPVLAN_FLAGS]));
#endif
					}
#endif
					ifp->base_ifindex = *PTR_CAST(uint32_t, RTA_DATA(tb[IFLA_LINK]));
#ifdef HAVE_IFLA_LINK_NETNSID						/* from Linux v4.0 */
					if (tb[IFLA_LINK_NETNSID])	/* Only use link details if in same network namespace */
						ifp->base_netns_id = *PTR_CAST(int32_t,  RTA_DATA(tb[IFLA_LINK_NETNSID]));
					else
#endif
					{
						ifp->base_ifp = if_get_by_ifindex(ifp->base_ifindex);
						if (ifp->base_ifp)
							ifp->base_ifindex = 0;	/* Make sure this isn't used at runtime */
						else
							ifp->base_ifp = ifp;
					}
				}
			}
#ifdef _HAVE_VRF_
			else if (is_vrf) {
				if (vrf_attr[IFLA_VRF_TABLE])
				{
					ifp->vrf_master_ifp = ifp;
					is_vrf_master = true;
				}
			}
#endif

#ifdef _FIXED_IF_TYPE_
			if (strcmp(_FIXED_IF_TYPE_, (char *)RTA_DATA(linkinfo[IFLA_INFO_KIND])))
#endif
				ifp->changeable_type = true;
		}
	}

#ifdef _HAVE_VRF_
	/* If we don't have the master interface details yet, we won't know
	 * if the master is a VRF master, but we sort that out later */
	if (!is_vrf_master) {
		if (tb[IFLA_MASTER]) {
			new_vrf_master_index = *PTR_CAST(uint32_t, RTA_DATA(tb[IFLA_MASTER]));
			if (!ifp->vrf_master_ifp ||
			    new_vrf_master_index != ifp->vrf_master_ifp->ifindex) {
				ifp->vrf_master_ifindex = new_vrf_master_index;
				ifp->vrf_master_ifp = if_get_by_ifindex(ifp->vrf_master_ifindex);
				if (ifp->vrf_master_ifp) {
					if (ifp->vrf_master_ifp->vrf_master_ifp != ifp->vrf_master_ifp)
						ifp->vrf_master_ifp = NULL;
					ifp->vrf_master_ifindex = 0;	/* Make sure this isn't used at runtime */

					update_vmac_vrfs(ifp);
				}
			}
		} else {
			ifp->vrf_master_ifindex = 0;
			if (ifp->vrf_master_ifp) {
				ifp->vrf_master_ifp = NULL;

				update_vmac_vrfs(ifp);
			}
		}
	}
#endif

	ifp->rp_filter = UINT_MAX;	/* We have not read it yet */
#endif

	ifp->ifi_flags = ifi->ifi_flags;

	return true;
}

/* Netlink interface link lookup filter */
static int
netlink_if_link_filter(__attribute__((unused)) struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	struct ifinfomsg *ifi;
	struct rtattr *tb[IFLA_MAX + 1];
	interface_t *ifp;
	size_t len;
	char *name;

	ifi = NLMSG_DATA(h);

	if (h->nlmsg_type != RTM_NEWLINK)
		return 0;

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof (struct ifinfomsg)))
		return -1;
	len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct ifinfomsg));

	/* Interface name lookup */
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

	if (tb[IFLA_IFNAME] == NULL)
		return -1;
	name = (char *)RTA_DATA(tb[IFLA_IFNAME]);

	/* Skip it if already exists */
	ifp = if_get_by_ifname(name, IF_CREATE_NETLINK);

	/* Fill the interface structure */
	if (!netlink_if_link_populate(ifp, tb, ifi))
		return -1;

	if (ifp->ifindex)
		update_interface_flags(ifp, ifi->ifi_flags);

	return 0;
}

/* Interfaces lookup bootstrap function */
int
netlink_interface_lookup(char *name)
{
	/* Interface lookup */
	if (netlink_request(&nl_cmd, AF_PACKET, RTM_GETLINK, name) < 0)
		return -1;

	return netlink_parse_info(netlink_if_link_filter, &nl_cmd, NULL, false);
}
#endif

/* Addresses lookup bootstrap function */
static int
netlink_address_lookup(void)
{
	int status;

	/* IPv4 Address lookup */
	if (netlink_request(&nl_cmd, AF_INET, RTM_GETADDR, NULL) < 0)
		return -1;

	if ((status = netlink_parse_info(netlink_if_address_filter, &nl_cmd, NULL, false)))
		return status;

	/* IPv6 Address lookup */
	if (netlink_request(&nl_cmd, AF_INET6, RTM_GETADDR, NULL) < 0)
		return -1;

	return netlink_parse_info(netlink_if_address_filter, &nl_cmd, NULL, false);
}

#ifdef _WITH_VRRP_
/* Netlink flag Link update */
static int
netlink_link_filter(__attribute__((unused)) struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	struct ifinfomsg *ifi;
	struct rtattr *tb[IFLA_MAX + 1];
	interface_t *ifp;
	size_t len;
	char *name;
#ifdef _HAVE_VRF_
	uint32_t new_master_index;
	interface_t *new_master_ifp;
#endif
	uint32_t old_mtu;
	size_t hw_addr_len;
	char mac_buf[3 * sizeof(ifp->hw_addr)];
	char old_mac_buf[3 * sizeof(ifp->hw_addr)];
	list_head_t sav_tracking_vrrp;
	list_head_t sav_e_list;
	garp_delay_t *sav_garp_delay;

	if (!(h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK))
		return 0;

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof (struct ifinfomsg)))
		return -1;
	len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct ifinfomsg));

	/* Interface name lookup */
	ifi = NLMSG_DATA(h);
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
	if (tb[IFLA_IFNAME] == NULL)
		return -1;
	name = (char *)RTA_DATA(tb[IFLA_IFNAME]);

	/* Ignore NEWLINK messages with ifi_change == 0 and IFLA_WIRELESS set
	   See for example https://bugs.chromium.org/p/chromium/issues/detail?id=501982 */
	if (!ifi->ifi_change && tb[IFLA_WIRELESS] && h->nlmsg_type == RTM_NEWLINK)
		return 0;

	/* find the interface_t. If the interface doesn't exist in the interface
	 * list and this is a new interface add it to the interface list.
	 * If an interface with the same name exists overwrite the older
	 * structure and fill it with the new interface information.
	 */
	ifp = if_get_by_ifindex((ifindex_t)ifi->ifi_index);

	if (ifp) {
		if (h->nlmsg_type == RTM_DELLINK) {
			if ((!list_empty(&ifp->tracking_vrrp)) ||
			    __test_bit(LOG_DETAIL_BIT, &debug))
				log_message(LOG_INFO, "Interface %s deleted", ifp->ifname);
#ifndef _ONE_PROCESS_DEBUG_
			if (prog_type != PROG_TYPE_VRRP) {
				ifp->ifi_flags = 0;
				ifp->ifindex = 0;
			} else
#endif
				cleanup_lost_interface(ifp);

#ifdef _HAVE_VRRP_VMAC_
			/* If this was a vmac we created, create it again, so long as the underlying i/f exists */
			if (ifp->is_ours &&
			    !ifp->deleting
#ifndef _ONE_PROCESS_DEBUG_
			    && prog_type == PROG_TYPE_VRRP
#endif
							  )
				thread_add_event(master, recreate_vmac_thread, ifp, 0);
#endif
		} else {
			if (tb[IFLA_ADDRESS]) {
				hw_addr_len = RTA_PAYLOAD(tb[IFLA_ADDRESS]);

				if (ifp->hw_addr_len != hw_addr_len || memcmp(ifp->hw_addr, RTA_DATA(tb[IFLA_ADDRESS]), hw_addr_len)) {
					if (hw_addr_len > sizeof(ifp->hw_addr)) {
						log_message(LOG_ERR,
							    "MAC %s for %s is too large: %zu",
							    get_mac_string(IFLA_ADDRESS), ifp->ifname, hw_addr_len);
					} else {
						if (__test_bit(LOG_DETAIL_BIT, &debug)) {
							if (!ifp->hw_addr_len)
								strcpy(old_mac_buf, "none");
							else
								format_mac_buf(old_mac_buf, sizeof old_mac_buf, ifp->hw_addr, ifp->hw_addr_len);
						}
						ifp->hw_addr_len = hw_addr_len;
						memcpy(ifp->hw_addr, RTA_DATA(tb[IFLA_ADDRESS]), hw_addr_len);
						if (__test_bit(LOG_DETAIL_BIT, &debug)) {
							format_mac_buf(mac_buf, sizeof mac_buf, ifp->hw_addr, ifp->hw_addr_len);
							log_message(LOG_INFO, "(%s) MAC %s changed from %s to %s",
								    ifp->ifname, get_mac_string(IFLA_ADDRESS), old_mac_buf, mac_buf);
						}
					}
				}
			}

			if (tb[IFLA_BROADCAST]) {
				hw_addr_len = RTA_PAYLOAD(tb[IFLA_BROADCAST]);

				if (ifp->hw_addr_len && ifp->hw_addr_len != hw_addr_len)
					log_message(LOG_ERR, "MAC broadcast address length %zu does not match MAC address length %zu", hw_addr_len, ifp->hw_addr_len);
				else if(memcmp(ifp->hw_addr_bcast, RTA_DATA(tb[IFLA_BROADCAST]), hw_addr_len)) {
					if (hw_addr_len > sizeof(ifp->hw_addr_bcast)) {
						log_message(LOG_ERR, "MAC %s for %s is too large: %zu",
							    get_mac_string(IFLA_BROADCAST), ifp->ifname, hw_addr_len);
					} else {
						if (__test_bit(LOG_DETAIL_BIT, &debug))
							format_mac_buf(old_mac_buf, sizeof old_mac_buf, ifp->hw_addr_bcast, ifp->hw_addr_len);
						ifp->hw_addr_len = hw_addr_len;
						memcpy(ifp->hw_addr_bcast, RTA_DATA(tb[IFLA_BROADCAST]), hw_addr_len);
						if (__test_bit(LOG_DETAIL_BIT, &debug)) {
							format_mac_buf(mac_buf, sizeof mac_buf, ifp->hw_addr_bcast, ifp->hw_addr_len);
							log_message(LOG_INFO, "(%s) MAC %s changed from %s to %s", ifp->ifname, get_mac_string(IFLA_BROADCAST), old_mac_buf, mac_buf);
						}
					}
				}
			}

			if (strcmp(ifp->ifname, name)) {
				/* The name can change, so handle that here */
				log_message(LOG_INFO, "Interface name has changed from %s to %s", ifp->ifname, name);

#ifndef _ONE_PROCESS_DEBUG_
				if (prog_type != PROG_TYPE_VRRP) {
					ifp->ifi_flags = 0;
					ifp->ifindex = 0;
				} else
#endif
					cleanup_lost_interface(ifp);

#ifdef _HAVE_VRRP_VMAC_
				/* If this was one of our vmacs, create it again */
				if (ifp->is_ours
#ifndef _ONE_PROCESS_DEBUG_
				    && prog_type == PROG_TYPE_VRRP
#endif
								)
				{
					/* Change the mac address on the interface, so we can create a new vmac */

					/* Now create our VMAC again */
					if (ifp->base_ifp->ifindex)
						thread_add_event(master, recreate_vmac_thread, ifp, 0);
				}
				else
#endif
					ifp = NULL;	/* Set ifp to null, to force creating a new interface_t */
			} else if (ifp->ifindex) {
#ifdef _HAVE_VRF_
				/* Now check if the VRF info is changed */
				if (tb[IFLA_MASTER]) {
					new_master_index = *PTR_CAST(uint32_t, RTA_DATA(tb[IFLA_MASTER]));
					new_master_ifp = if_get_by_ifindex(new_master_index);
				} else
					new_master_ifp = NULL;
				if (new_master_ifp != ifp->vrf_master_ifp) {
					ifp->vrf_master_ifp = new_master_ifp;
					update_vmac_vrfs(ifp);
				}
#endif

				/* Check if the MTU has increased */
				if (
#ifndef _ONE_PROCESS_DEBUG_
				    prog_type == PROG_TYPE_VRRP &&
#endif
				    tb[IFLA_MTU]) {
					old_mtu = ifp->mtu;
					ifp->mtu = *PTR_CAST(uint32_t, RTA_DATA(tb[IFLA_MTU]));
					if (!list_empty(&ifp->tracking_vrrp))
						update_mtu(ifp);
				}

#ifdef _HAVE_IPV4_DEVCONF_
				if (tb[IFLA_AF_SPEC])
					parse_af_spec(tb[IFLA_AF_SPEC], ifp);
#endif

#ifdef _WITH_LINKBEAT_
				/* Ignore interface if we are using linkbeat on it */
				if (ifp->linkbeat_use_polling)
					return 0;
#endif
			} else
				ifp = NULL;
		}
	}

	if (!ifp) {
		if (h->nlmsg_type == RTM_NEWLINK) {
			ifp = if_get_by_ifname(name, IF_CREATE_NETLINK);

			/* Since the garp_delay and tracking_vrrp are set up by name,
			 * it is reasonable to preserve them.
			 * If what is created is a vmac, we could end up in a complete mess. */
			sav_garp_delay = ifp->garp_delay;
			list_copy(&sav_tracking_vrrp, &ifp->tracking_vrrp);
			old_mtu = ifp->mtu;
			if_extra_ipaddress_free_list(&ifp->sin_addr_l);
			if_extra_ipaddress_free_list(&ifp->sin6_addr_l);

			/* Save the list_head entry itself */
			sav_e_list = ifp->e_list;

			memset(ifp, 0, sizeof(interface_t));

			/* Restore the list_head entry */
			ifp->e_list = sav_e_list;

			/* Re-establish lists */
			INIT_LIST_HEAD(&ifp->sin_addr_l);
			INIT_LIST_HEAD(&ifp->sin6_addr_l);
			list_copy(&ifp->tracking_vrrp, &sav_tracking_vrrp);
			ifp->garp_delay = sav_garp_delay;

			if (!netlink_if_link_populate(ifp, tb, ifi))
				return -1;

			if (__test_bit(LOG_DETAIL_BIT, &debug))
				log_message(LOG_INFO, "Interface %s added", ifp->ifname);

			update_added_interface(ifp);

#ifndef _ONE_PROCESS_DEBUG_
			if (prog_type == PROG_TYPE_VRRP)
#endif
				if (ifp->mtu > old_mtu)
					alloc_vrrp_buffer(ifp->mtu);

			/* We need to see a transition to up, so mark it down for now */
			ifp->ifi_flags &= ~(IFF_UP | IFF_RUNNING);
		} else {
			if (__test_bit(LOG_DETAIL_BIT, &debug))
				log_message(LOG_INFO, "Unknown interface %s deleted", (char *)tb[IFLA_IFNAME]);
			return 0;
		}
	}

	/* Update flags. Flags == 0 means interface deleted. */
	update_interface_flags(ifp, (h->nlmsg_type == RTM_DELLINK) ? 0 : ifi->ifi_flags);

	return 0;
}

#ifdef _WITH_VRRP_
static int
netlink_route_filter(__attribute__((unused)) struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	struct rtmsg *rt;
	struct rtattr *tb[RTA_MAX + 1];
	size_t len;
	vrrp_t *vrrp;
	ip_route_t *route;

	if (h->nlmsg_type != RTM_NEWROUTE && h->nlmsg_type != RTM_DELROUTE)
		return 0;

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof(*rt)))
		return -1;

	rt = NLMSG_DATA(h);

	if (rt->rtm_protocol != RTPROT_KEEPALIVED) {
		/* It is not a route we are monitoring - ignore it */
		return 0;
	}

	/* Only IPv4 and IPv6 are valid for us */
	if (rt->rtm_family != AF_INET && rt->rtm_family != AF_INET6)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct rtmsg));

	parse_rtattr(tb, RTA_MAX, RTM_RTA(rt), len);

	if (!(route = route_is_ours(rt, tb, &vrrp)))
		return 0;

	route->set = (h->nlmsg_type == RTM_NEWROUTE);

	/* Matching route */
	if (h->nlmsg_type == RTM_NEWROUTE) {
		/* If we haven't specified a dev for the route, save the link the route
		 * has been added to. */
		if (tb[RTA_OIF]) {
			route->configured_ifindex = *PTR_CAST(uint32_t, RTA_DATA(tb[RTA_OIF]));
			if (route->oif && route->oif->ifindex != route->configured_ifindex)
				log_message(LOG_INFO, "route added index %" PRIu32 " != config index %u", route->configured_ifindex, route->oif->ifindex);
		}
		else
			log_message(LOG_INFO, "New route doesn't have i/f index");

		return 0;
	}

	/* We are only interested in route deletions now */

	if (route->dont_track)
		return 0;

	if (vrrp) {
		if (vrrp->state != VRRP_STATE_MAST)
			return 0;

		set_vrrp_backup(vrrp);
	}
	else
		reinstate_static_route(route);

	return 0;
}

static int
netlink_rule_filter(__attribute__((unused)) struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	struct fib_rule_hdr *frh;
	struct rtattr *tb[FRA_MAX + 1];
	size_t len;
	vrrp_t *vrrp;
	ip_rule_t *ip_rule;

	if (h->nlmsg_type != RTM_NEWRULE && h->nlmsg_type != RTM_DELRULE)
		return 0;

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof(*frh)))
		return -1;

	frh = NLMSG_DATA(h);

	/* Only IPv4 and IPv6 are valid for us */
	if (frh->family != AF_INET && frh->family != AF_INET6)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct rtmsg));

	parse_rtattr(tb, FRA_MAX, RTM_RTA(frh), len);

#if HAVE_DECL_FRA_PROTOCOL
	if (tb[FRA_PROTOCOL] &&
	    *PTR_CAST(uint8_t, RTA_DATA(tb[FRA_PROTOCOL])) != RTPROT_KEEPALIVED) {
		/* It is not a rule we are monitoring - ignore it */
		return 0;
	}
#endif

	/* We are only interested in rule deletions now */
	if (h->nlmsg_type != RTM_DELRULE)
		return 0;

	if (!(ip_rule = rule_is_ours(frh, tb, &vrrp)))
		return 0;

	ip_rule->set = false;

	if (ip_rule->dont_track)
		return 0;

	if (vrrp)
		set_vrrp_backup(vrrp);
	else
		reinstate_static_rule(ip_rule);

	return 0;
}
#endif
#endif

/* Netlink kernel message reflection */
static int
netlink_broadcast_filter(struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	switch (h->nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
		/* It appears that older kernels (certainly 2.6.32) can
		 * send RTM_NEWLINK (but not RTM_DELLINK) messages even
		 * when RTNLGRP_LINK has not been subscribed to. This
		 * occurs when the link is set to up state.
		 * Only the VRRP process is interested in link messages. */
#ifdef _WITH_VRRP_
#ifndef _ONE_PROCESS_DEBUG_
		if (prog_type == PROG_TYPE_VRRP)
#endif
			return netlink_link_filter(snl, h);
#endif
		break;
	case RTM_NEWADDR:
	case RTM_DELADDR:
		return netlink_if_address_filter(snl, h);
		break;
#ifdef _WITH_VRRP_
	case RTM_NEWROUTE:
	case RTM_DELROUTE:
		return netlink_route_filter(snl, h);
	case RTM_NEWRULE:
	case RTM_DELRULE:
		return netlink_rule_filter(snl, h);
#endif
	default:
		log_message(LOG_INFO,
		       "Kernel is reflecting an unknown netlink nlmsg_type: %d",
		       h->nlmsg_type);
		break;
	}
	return 0;
}

static void
kernel_netlink(thread_ref_t thread)
{
	nl_handle_t *nl = THREAD_ARG(thread);

	if (thread->type != THREAD_READ_TIMEOUT)
		netlink_parse_info(netlink_broadcast_filter, nl, NULL, true);
	nl->thread = thread_add_read(master, kernel_netlink, nl, nl->fd,
				      TIMER_NEVER, 0);
}

#ifdef _WITH_VRRP_
void
kernel_netlink_poll(void)
{
	if (nl_kernel.fd < 0)
		return;

	netlink_parse_info(netlink_broadcast_filter, &nl_kernel, NULL, true);
}
#endif

void
kernel_netlink_set_recv_bufs(void)
{
#ifdef _ONE_PROCESS_DEBUG_
#ifdef _WITH_VRRP_
	netlink_set_rx_buf_size(&nl_kernel, global_data->vrrp_netlink_monitor_rcv_bufs, global_data->vrrp_netlink_monitor_rcv_bufs_force);
	netlink_set_rx_buf_size(&nl_cmd, global_data->vrrp_netlink_cmd_rcv_bufs, global_data->vrrp_netlink_cmd_rcv_bufs_force);
#else
	netlink_set_rx_buf_size(&nl_kernel, global_data->lvs_netlink_monitor_rcv_bufs, global_data->lvs_netlink_monitor_rcv_bufs_force);
	netlink_set_rx_buf_size(&nl_cmd, global_data->lvs_netlink_cmd_rcv_bufs, global_data->lvs_netlink_cmd_rcv_bufs_force);
#endif
#else
#ifdef _WITH_VRRP_
	if (prog_type == PROG_TYPE_VRRP) {
		netlink_set_rx_buf_size(&nl_kernel, global_data->vrrp_netlink_monitor_rcv_bufs, global_data->vrrp_netlink_monitor_rcv_bufs_force);
		netlink_set_rx_buf_size(&nl_cmd, global_data->vrrp_netlink_cmd_rcv_bufs, global_data->vrrp_netlink_cmd_rcv_bufs_force);
	}
#endif
#ifdef _WITH_LVS_
	if (prog_type == PROG_TYPE_CHECKER)
		netlink_set_rx_buf_size(&nl_kernel, global_data->lvs_netlink_monitor_rcv_bufs, global_data->lvs_netlink_monitor_rcv_bufs_force);
#endif
#endif
}

void
kernel_netlink_close_monitor(void)
{
	netlink_close(&nl_kernel);
}

void
kernel_netlink_close_cmd(void)
{
	netlink_close(&nl_cmd);
}

void
kernel_netlink_close(void)
{
	kernel_netlink_close_monitor();
	kernel_netlink_close_cmd();
}

void
kernel_netlink_init(void)
{
	/*
	 * Prepare netlink kernel broadcast channel
	 * subscription. We subscribe to LINK, ADDR,
	 * and ROUTE netlink broadcast messages, but
	 * the checker process does not need the
	 * route or link messages.
	 */

	/* If the netlink kernel fd is already open, just register a read thread.
	 * This will happen at reload. */
	if (nl_kernel.fd >= 0) {
		nl_kernel.thread = thread_add_read(master, kernel_netlink, &nl_kernel, nl_kernel.fd, TIMER_NEVER, 0);
		return;
	}

#ifdef _ONE_PROCESS_DEBUG_
#ifdef _WITH_VRRP_
	netlink_socket(&nl_kernel, global_data->vrrp_netlink_monitor_rcv_bufs, global_data->vrrp_netlink_monitor_rcv_bufs_force,
			SOCK_NONBLOCK, RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR, 0);
#else
	netlink_socket(&nl_kernel, global_data->lvs_netlink_monitor_rcv_bufs, global_data->lvs_netlink_monitor_rcv_bufs_force,
			SOCK_NONBLOCK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR, 0);
#endif
#else
#ifdef _WITH_VRRP_
	if (prog_type == PROG_TYPE_VRRP)
		netlink_socket(&nl_kernel, global_data->vrrp_netlink_monitor_rcv_bufs, global_data->vrrp_netlink_monitor_rcv_bufs_force,
				SOCK_NONBLOCK, RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR, 0);
#endif
#ifdef _WITH_LVS_
	if (prog_type == PROG_TYPE_CHECKER)
		netlink_socket(&nl_kernel, global_data->lvs_netlink_monitor_rcv_bufs, global_data->lvs_netlink_monitor_rcv_bufs_force,
				SOCK_NONBLOCK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR, 0);
#endif
#endif

	if (nl_kernel.fd >= 0) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "Registering Kernel netlink reflector");
		nl_kernel.thread = thread_add_read(master, kernel_netlink, &nl_kernel, nl_kernel.fd,
						   TIMER_NEVER, 0);
	} else
		log_message(LOG_INFO, "Error while registering Kernel netlink reflector channel");

	/* Prepare netlink command channel. The cmd socket is used synchronously.*/
#ifdef _ONE_PROCESS_DEBUG_
#ifdef _WITH_VRRP_
	netlink_socket(&nl_cmd, global_data->vrrp_netlink_cmd_rcv_bufs, global_data->vrrp_netlink_cmd_rcv_bufs_force, 0, 0);
#else
	netlink_socket(&nl_cmd, global_data->lvs_netlink_cmd_rcv_bufs, global_data->lvs_netlink_cmd_rcv_bufs_force, 0, 0);
#endif
#else
#ifdef _WITH_VRRP_
	if (prog_type == PROG_TYPE_VRRP)
		netlink_socket(&nl_cmd, global_data->vrrp_netlink_cmd_rcv_bufs, global_data->vrrp_netlink_cmd_rcv_bufs_force, 0, 0);
#endif
#ifdef _WITH_LVS_
	if (prog_type == PROG_TYPE_CHECKER)
		netlink_socket(&nl_cmd, global_data->lvs_netlink_cmd_rcv_bufs, global_data->lvs_netlink_cmd_rcv_bufs_force, 0, 0);
#endif
#endif
	if (nl_cmd.fd >= 0) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "Registering Kernel netlink command channel");
	} else
		log_message(LOG_INFO, "Error while registering Kernel netlink cmd channel");

	/* Start with netlink interface and address lookup */
#ifdef _WITH_VRRP_
#ifndef _ONE_PROCESS_DEBUG_
	if (prog_type == PROG_TYPE_VRRP)
#endif
		init_interface_queue();
#endif

	netlink_address_lookup();

#if !defined _ONE_PROCESS_DEBUG_ && defined _WITH_LVS_
	if (prog_type == PROG_TYPE_CHECKER)
		kernel_netlink_close_cmd();
#endif
}

void
cancel_kernel_netlink_threads(void)
{
	if (nl_kernel.fd != -1 && nl_kernel.thread) {
		thread_cancel(nl_kernel.thread);
		nl_kernel.thread = NULL;
	}
}

#ifdef _WITH_VRRP_
void
kernel_netlink_read_interfaces(void)
{
	int ret;

#ifdef _WITH_VRRP_
	netlink_socket(&nl_cmd, global_data->vrrp_netlink_cmd_rcv_bufs, global_data->vrrp_netlink_cmd_rcv_bufs_force, 0, 0);
#else
	netlink_socket(&nl_cmd, global_data->lvs_netlink_cmd_rcv_bufs, global_data->lvs_netlink_cmd_rcv_bufs_force, 0, 0);
#endif

	if (nl_cmd.fd < 0)
		fprintf(stderr, "Error while registering Kernel netlink cmd channel\n");

	init_interface_queue();

	if ((ret = netlink_address_lookup()))
		fprintf(stderr, "netlink_address_lookup() returned %d\n", ret);

	kernel_netlink_close_cmd();
}
#endif

#ifdef THREAD_DUMP
void
register_keepalived_netlink_addresses(void)
{
	register_thread_address("kernel_netlink", kernel_netlink);
}
#endif
