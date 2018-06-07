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

#include "config.h"

#include <netinet/ip.h>
/* global include */
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <sys/uio.h>
#ifdef _HAVE_LIBNL3_
#include <netlink/netlink.h>
#endif
#include <net/if_arp.h>
#include <arpa/inet.h>
#if !defined _HAVE_LIBNL3_ || defined _LIBNL_DYNAMIC_
#ifdef HAVE_LIBNFNETLINK_LIBNFNETLINK_H
#include <libnfnetlink/libnfnetlink.h>
#endif
#endif
#include <time.h>
#ifdef _WITH_VRRP_
#ifdef _HAVE_FIB_ROUTING_
#include <linux/fib_rules.h>
#endif
#endif

/* local include */
#ifdef _LIBNL_DYNAMIC_
#include "libnl_link.h"
#endif
#include "keepalived_netlink.h"
#ifdef _WITH_LVS_
#include "check_api.h"
#endif
#ifdef _WITH_VRRP_
#include "vrrp_scheduler.h"
#include "vrrp_track.h"
#include "vrrp_data.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_vmac.h"
#endif
#ifdef _HAVE_FIB_ROUTING_
#include "vrrp_iproute.h"
#include "vrrp_iprule.h"
#endif
#endif
#include "logger.h"
#include "scheduler.h"
#include "utils.h"
#include "bitops.h"
#if !HAVE_DECL_SOCK_NONBLOCK
#include "old_socket.h"
#endif
#include "vrrp_ipaddress.h"
#include "global_data.h"

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
static int nlmsg_buf_size;	/* Size of netlink message buffer */

#ifdef _NETLINK_TIMERS_
/* The maximum netlink command we use is RTM_DELRULE.
 * If that changes, the following definition will need changing. */
#define MAX_NETLINK_TIMER	RTM_DELRULE

static struct timeval netlink_times[MAX_NETLINK_TIMER+1];
static unsigned netlink_count[MAX_NETLINK_TIMER+1];
static struct timeval start_time, end_time;
#endif

#ifdef _NETLINK_TIMERS_
void
report_and_clear_netlink_timers(const char * str)
{
	int i;

	log_message(LOG_INFO, "Netlink timers - %s", str);
	for (i = 0; i <= MAX_NETLINK_TIMER; i++) {
		if (netlink_count[i]) {
			log_message(LOG_INFO, "  netlink cmd %d (%d calls), time %ld.%6.6ld", i, netlink_count[i], netlink_times[i].tv_sec, netlink_times[i].tv_usec);
			netlink_times[i].tv_sec = netlink_times[i].tv_usec = netlink_count[i] = 0;
		}
	}
}
#endif

static inline bool
addr_is_equal(struct ifaddrmsg* ifa, void* addr, ip_address_t* vip_addr, interface_t *ifp)
{
	struct in_addr* sin_addr;
	struct in6_addr* sin6_addr;

	if (vip_addr->ifa.ifa_family != ifa->ifa_family)
		return false;
	if (vip_addr->ifp != ifp)
		return false;
	if (vip_addr->ifa.ifa_family == AF_INET) {
		sin_addr = (struct in_addr *)addr;
		return vip_addr->u.sin.sin_addr.s_addr == sin_addr->s_addr;
	}

	sin6_addr = (struct in6_addr*)addr;
	return vip_addr->u.sin6_addr.s6_addr32[0] == sin6_addr->s6_addr32[0] &&
	       vip_addr->u.sin6_addr.s6_addr32[1] == sin6_addr->s6_addr32[1] &&
	       vip_addr->u.sin6_addr.s6_addr32[2] == sin6_addr->s6_addr32[2] &&
	       vip_addr->u.sin6_addr.s6_addr32[3] == sin6_addr->s6_addr32[3];
}

#ifdef _WITH_VRRP_
static vrrp_t *
address_is_ours(struct ifaddrmsg* ifa, struct in_addr* addr, interface_t* ifp)
{
	element e, e1;
	tracking_vrrp_t* tvp;
	vrrp_t* vrrp;
	ip_address_t* vaddr;

	LIST_FOREACH(ifp->tracking_vrrp, tvp, e) {
		vrrp = tvp->vrrp;

		/* If we are not master, then we won't have the address configured */
		if (vrrp->state != VRRP_STATE_MAST)
			continue;

		if (ifa->ifa_family == vrrp->family) {
			LIST_FOREACH(vrrp->vip, vaddr, e1) {
				if (addr_is_equal(ifa, addr, vaddr, ifp))
					return vaddr->dont_track ? NULL : vrrp;
			}
		}

		LIST_FOREACH(vrrp->evip, vaddr, e1) {
			if (addr_is_equal(ifa, addr, vaddr, ifp))
				return vaddr->dont_track ? NULL : vrrp;
		}
	}

	return NULL;
}

#ifdef _HAVE_FIB_ROUTING_
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
	element e, e1;
	vrrp_t *vrrp;
	ip_route_t *route;

	*ret_vrrp = NULL;

	table = tb[RTA_TABLE] ? *(uint32_t *)RTA_DATA(tb[RTA_TABLE]) : rt->rtm_table;
	family = rt->rtm_family;
	if (tb[RTA_PRIORITY])
		priority = *(uint32_t *)RTA_DATA(tb[RTA_PRIORITY]);

	LIST_FOREACH(vrrp_data->vrrp, vrrp, e) {
		LIST_FOREACH(vrrp->vroutes, route, e1) {
			if (table != route->table ||
			    family != route->family ||
			    mask_len != route->dst->ifa.ifa_prefixlen ||
			    priority != route->metric ||
			    tos != route->tos)
				continue;

			if (route->oif) {
				if (route->oif->ifindex != *(uint32_t *)RTA_DATA(tb[RTA_OIF]))
					continue;
			} else {
				if (route->set && route->configured_ifindex && route->configured_ifindex != *(uint32_t *)RTA_DATA(tb[RTA_OIF]))
					continue;
			}

			if (compare_addr(family, RTA_DATA(tb[RTA_DST]), route->dst))
				continue;

			*ret_vrrp = vrrp;
			return route;
		}
	}

	/* Now check the static routes */
	LIST_FOREACH(vrrp_data->static_routes, route, e) {
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
	    rule->priority != *(uint32_t*)RTA_DATA(tb[FRA_PRIORITY]))
		return false;

	if (frh->action != rule->action)
		return false;

	if (frh->action == FR_ACT_GOTO &&
	    (!tb[FRA_GOTO] ||
	     *(uint32_t *)RTA_DATA(tb[FRA_GOTO]) != rule->goto_target))
		return false;

	if (tb[FRA_TABLE] && rule->table != *(uint32_t *)RTA_DATA(tb[FRA_TABLE]))
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
	    *(uint32_t*)RTA_DATA(tb[FRA_FWMARK]) != rule->fwmark)
		return false;

	if (!tb[FRA_FWMASK] && (rule->mask & IPRULE_BIT_FWMASK))
		return false;
	if (rule->mask & IPRULE_BIT_FWMASK) {
		if (*(uint32_t*)RTA_DATA(tb[FRA_FWMASK]) != rule->fwmask)
			return false;
	}
	else if (tb[FRA_FWMASK]) {
		if (*(uint32_t *)RTA_DATA(tb[FRA_FWMASK]) != 0xffffffff)
			return false;
	}

	if (!tb[FRA_FLOW] != !rule->realms)
		return false;
	if (rule->realms &&
	    *(uint32_t*)RTA_DATA(tb[FRA_FLOW]) != rule->realms)
		return false;

#if HAVE_DECL_FRA_SUPPRESS_PREFIXLEN
	if (!tb[FRA_SUPPRESS_PREFIXLEN]) {
		if (rule->suppress_prefix_len != -1)
			return false;
	} else if (*(int32_t*)RTA_DATA(tb[FRA_SUPPRESS_PREFIXLEN]) != rule->suppress_prefix_len)
		return false;
#endif

#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
	if (!tb[FRA_SUPPRESS_IFGROUP] != !(rule->mask & IPRULE_BIT_SUP_GROUP))
		return false;
	if (rule->mask & IPRULE_BIT_SUP_GROUP &&
	    *(uint32_t*)RTA_DATA(tb[FRA_SUPPRESS_IFGROUP]) != rule->suppress_group)
		return false;
#endif

	if (!tb[FRA_IFNAME] != !(rule->iif))
		return false;
	if (rule->iif &&
	    strcmp(RTA_DATA(tb[FRA_IFNAME]), rule->iif->ifname))
		return false;

#if HAVE_DECL_FRA_OIFNAME
	if (!tb[FRA_OIFNAME] != !(rule->oif))
		return false;
	if (rule->oif &&
	    strcmp(RTA_DATA(tb[FRA_OIFNAME]), rule->oif->ifname))
		return false;
#endif

#if HAVE_DECL_FRA_TUN_ID
	uint64_t tunnel_id;
	if (!tb[FRA_TUN_ID] != !(rule->tunnel_id))
		return false;
	if (rule->tunnel_id) {
		tunnel_id = be64toh(*(uint64_t *)RTA_DATA(tb[FRA_TUN_ID]));
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
	    *(uint8_t *)RTA_DATA(tb[FRA_L3MDEV]) != rule->l3mdev)
		return false;
#endif

#if HAVE_DECL_FRA_IP_PROTO
	if (!tb[FRA_IP_PROTO] != !(rule->mask & IPRULE_BIT_IP_PROTO))
		return false;
	if (rule->mask & IPRULE_BIT_IP_PROTO &&
	    *(uint8_t *)RTA_DATA(tb[FRA_IP_PROTO]) != rule->ip_proto)
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
	element e, e1;
	vrrp_t *vrrp;
	ip_rule_t *rule;

	*ret_vrrp = NULL;

	LIST_FOREACH(vrrp_data->vrrp, vrrp, e) {
		LIST_FOREACH(vrrp->vrules, rule, e1) {
			if (compare_rule(frh, tb, rule)) {
				*ret_vrrp = vrrp;
				return rule;
			}
		}
	}

	LIST_FOREACH(vrrp_data->static_rules, rule, e) {
		if (compare_rule(frh, tb, rule))
			return rule;
	}

	return NULL;
}
#endif
#endif

void
netlink_set_recv_buf_size(void)
{
	/* The size of the read buffer for the NL socket is based on page
	 * size however, it should not exceed 8192. See the comment in:
	 * linux/include/linux/netlink.h (copied below):
	 * skb should fit one page. This choice is good for headerless malloc.
	 * But we should limit to 8K so that userspace does not have to
	 * use enormous buffer sizes on recvmsg() calls just to avoid
	 * MSG_TRUNC when PAGE_SIZE is very large.
	 */
	nlmsg_buf_size = getpagesize();
	if (nlmsg_buf_size > 8192)
		nlmsg_buf_size = 8192;
}

/* Update the netlink socket receive buffer sizes */
static int
netlink_set_rx_buf_size(nl_handle_t *nl, unsigned rcvbuf_size, bool force)
{
	int ret;

	if (!rcvbuf_size)
		rcvbuf_size = IF_DEFAULT_BUFSIZE;

	if (force) {
		if ((ret = setsockopt(nl->fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf_size, sizeof(rcvbuf_size))) < 0)
			log_message(LOG_INFO, "cant set SO_RCVBUFFORCE IP option. errno=%d (%m)", errno);
	} else {
#ifdef _HAVE_LIBNL3_
#ifdef _LIBNL_DYNAMIC_
		if (use_nl)
#endif
		{
			if ((ret = nl_socket_set_buffer_size(nl->sk, rcvbuf_size, 0)))
				log_message(LOG_INFO, "Netlink: Cannot set netlink buffer size : (%d)", ret);
		}
#endif
#if !defined _HAVE_LIBNL3_ || defined _LIBNL_DYNAMIC_
#if defined _HAVE_LIBNL3_ && defined _LIBNL_DYNAMIC_
		else
#endif
		{
			/* Set rcvbuf size */
			if ((ret = setsockopt(nl->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size))) < 0)
				log_message(LOG_INFO, "Cannot set SO_RCVBUF IP option. errno=%d (%m)", errno);
		}
#endif
	}

	return ret;
}

#ifdef _HAVE_FIB_ROUTING_
static void
kernel_netlink_set_membership(int group, bool add)
{
#ifdef _HAVE_LIBNL3_
#ifdef _LIBNL_DYNAMIC_
	if (use_nl)
#endif
	{
		int ret;

		if (add)
			ret = nl_socket_add_membership(nl_kernel.sk, group);
		else
			ret = nl_socket_drop_membership(nl_kernel.sk, group);
		if (ret) {
			log_message(LOG_INFO, "Netlink: Cannot add socket membership 0x%x : (%d)", group, ret);
			return;
		}
	}
#endif
#if !defined _HAVE_LIBNL3_ || defined _LIBNL_DYNAMIC_
#if defined _HAVE_LIBNL3_ && defined _LIBNL_DYNAMIC_
	else
#endif
	{
		if (setsockopt(nl_kernel.fd, SOL_NETLINK, add ? NETLINK_ADD_MEMBERSHIP : NETLINK_DROP_MEMBERSHIP,
				&group, sizeof(group)) < 0) {
			log_message(LOG_INFO, "Netlink: Cannot add membership on netlink socket : (%s)", strerror(errno));
			return;
		}
	}
#endif
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
static int
netlink_socket(nl_handle_t *nl, unsigned rcvbuf_size, bool force, int flags, int group, ...)
{
	int ret;
	va_list gp;

	memset(nl, 0, sizeof (*nl));

#ifdef _HAVE_LIBNL3_
#ifdef _LIBNL_DYNAMIC_
	if (use_nl)
#endif
	{
		/* We need to keep libnl3 in step with our netlink socket creation.  */
		nl->sk = nl_socket_alloc();
		if (nl->sk == NULL) {
			log_message(LOG_INFO, "Netlink: Cannot allocate netlink socket" );
			return -1;
		}

		ret = nl_connect(nl->sk, NETLINK_ROUTE);
		if (ret != 0) {
			log_message(LOG_INFO, "Netlink: Cannot open netlink socket : (%d)", ret);
			return -1;
		}

		/* Unfortunately we can't call nl_socket_add_memberships() with variadic arguments
		 * from a variadic argument list passed to us
		 */
		va_start(gp, group);
		while (group != 0) {
			if (group < 0) {
				va_end(gp);
				return -1;
			}

			if ((ret = nl_socket_add_membership(nl->sk, group))) {
				log_message(LOG_INFO, "Netlink: Cannot add socket membership 0x%x : (%d)", group, ret);
				va_end(gp);
				return -1;
			}

			group = va_arg(gp,int);
		}
		va_end(gp);

		if (flags & SOCK_NONBLOCK) {
			if ((ret = nl_socket_set_nonblocking(nl->sk))) {
				log_message(LOG_INFO, "Netlink: Cannot set netlink socket non-blocking : (%d)", ret);
				return -1;
			}
		}

		nl->nl_pid = nl_socket_get_local_port(nl->sk);

		nl->fd = nl_socket_get_fd(nl->sk);

		/* Set CLOEXEC */
		fcntl(nl->fd, F_SETFD, fcntl(nl->fd, F_GETFD) | FD_CLOEXEC);
	}
#endif
#if !defined _HAVE_LIBNL3_ || defined _LIBNL_DYNAMIC_
#if defined _HAVE_LIBNL3_ && defined _LIBNL_DYNAMIC_
	else
#endif
	{
		socklen_t addr_len;
		struct sockaddr_nl snl;
		int sock_flags = flags;
#if !HAVE_DECL_SOCK_NONBLOCK
		sock_flags &= ~SOCK_NONBLOCK;
#endif

		nl->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | sock_flags, NETLINK_ROUTE);
		if (nl->fd < 0) {
			log_message(LOG_INFO, "Netlink: Cannot open netlink socket : (%s)",
			       strerror(errno));
			return -1;
		}

#if !HAVE_DECL_SOCK_NONBLOCK
		if ((flags & SOCK_NONBLOCK) &&
		    set_sock_flags(nl->fd, F_SETFL, O_NONBLOCK))
			return -1;
#endif

		memset(&snl, 0, sizeof (snl));
		snl.nl_family = AF_NETLINK;

		ret = bind(nl->fd, (struct sockaddr *) &snl, sizeof (snl));
		if (ret < 0) {
			log_message(LOG_INFO, "Netlink: Cannot bind netlink socket : (%s)",
			       strerror(errno));
			close(nl->fd);
			nl->fd = -1;
			return -1;
		}

		/* Join the requested groups */
		va_start(gp, group);
		while (group != 0) {
			if (group < 0) {
				va_end(gp);
				return -1;
			}

			ret = setsockopt(nl->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group));
			if (ret < 0) {
				log_message(LOG_INFO, "Netlink: Cannot add membership on netlink socket : (%s)",
				       strerror(errno));
				va_end(gp);
				return -1;
			}

			group = va_arg(gp,int);
		}
		va_end(gp);

		addr_len = sizeof (snl);
		ret = getsockname(nl->fd, (struct sockaddr *) &snl, &addr_len);
		if (ret < 0 || addr_len != sizeof (snl)) {
			log_message(LOG_INFO, "Netlink: Cannot getsockname : (%s)",
			       strerror(errno));
			close(nl->fd);
			return -1;
		}

		if (snl.nl_family != AF_NETLINK) {
			log_message(LOG_INFO, "Netlink: Wrong address family %d",
			       snl.nl_family);
			close(nl->fd);
			return -1;
		}

		/* Save the port id for checking message source later */
		nl->nl_pid = snl.nl_pid;
	}
#endif

#ifdef _UNUSED_CODE_
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
	 *
	 * NETLINK_NO_ENOBUFS was introduced in Linux 2.6.30
	 */
	int one = 1;
	if ((ret = setsockopt(nl->fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one))) < 0)
		log_message(LOG_INFO, "Cannot set NETLINK_NO_ENOBUFS option. errno=%d (%m)", errno);
#endif

	nl->seq = (uint32_t)time(NULL);

	if (nl->fd < 0)
		return -1;

	ret = netlink_set_rx_buf_size(nl, rcvbuf_size, force);

	return ret;
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

#ifdef _HAVE_LIBNL3_
#ifdef _LIBNL_DYNAMIC_
	if (use_nl)
#endif
	{
		if (nl->sk) {
			nl_socket_free(nl->sk);
			nl->sk = NULL;
		}
	}
#endif
#if !defined _HAVE_LIBNL3_ || defined _LIBNL_DYNAMIC_
#if defined _HAVE_LIBNL3_ && defined _LIBNL_DYNAMIC_
	else
#endif
	{
		if (nl->fd != -1)
			close(nl->fd);
	}
#endif
	nl->fd = -1;
}

/* iproute2 utility function */
int
addattr_l(struct nlmsghdr *n, size_t maxlen, unsigned short type, void *data, size_t alen)
{
	size_t len = RTA_LENGTH(alen);
	size_t align_len = NLMSG_ALIGN(len);
	struct rtattr *rta;

	if (n->nlmsg_len + align_len > maxlen)
		return -1;

	rta = (struct rtattr *) (((char *) n) + n->nlmsg_len);
	rta->rta_type = type;
	rta->rta_len = (unsigned short)len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len += (uint32_t)align_len;

	return 0;
}

#ifdef _WITH_VRRP_
int
addattr8(struct nlmsghdr *n, size_t maxlen, unsigned short type, uint8_t data)
{
	return addattr_l(n, maxlen, type, &data, sizeof data);
}
#endif

int
addattr32(struct nlmsghdr *n, size_t maxlen, unsigned short type, uint32_t data)
{
	return addattr_l(n, maxlen, type, &data, sizeof data);
}

#ifdef _WITH_VRRP_
int
addattr64(struct nlmsghdr *n, size_t maxlen, unsigned short type, uint64_t data)
{
	return addattr_l(n, maxlen, type, &data, sizeof(data));
}

int
addattr_l2(struct nlmsghdr *n, size_t maxlen, unsigned short type, void *data, size_t alen, void *data2, size_t alen2)
{
	size_t len = RTA_LENGTH(alen + alen2);
	size_t align_len = NLMSG_ALIGN(len);
	struct rtattr *rta;

	if (n->nlmsg_len + align_len > maxlen)
		return -1;

	rta = (struct rtattr *) (((char *) n) + n->nlmsg_len);
	rta->rta_type = type;
	rta->rta_len = (unsigned short)len;
	memcpy(RTA_DATA(rta), data, alen);
	memcpy(RTA_DATA(rta) + alen, data2, alen2);
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
	memset((void *) NLMSG_TAIL(n) + len, 0, align_len - len);
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

	subrta = (struct rtattr*)(((char*)rta) + rta->rta_len);
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

	subrta = (struct rtattr*)(((char*)rta) + rta->rta_len);
	subrta->rta_type = type;
	subrta->rta_len = (unsigned short)len;
	memcpy(RTA_DATA(subrta), data, alen);
	memcpy(RTA_DATA(subrta) + alen, data2, alen2);
	rta->rta_len = (unsigned short)(rta->rta_len + align_len);
	return align_len;
}

size_t
rta_addattr64(struct rtattr *rta, size_t maxlen, unsigned short type, uint64_t data)
{
	return rta_addattr_l(rta, maxlen, type, &data, sizeof data);
}

size_t
rta_addattr32(struct rtattr *rta, size_t maxlen, unsigned short type, uint32_t data)
{
	struct rtattr *subrta;
	size_t len = RTA_LENGTH(sizeof data);
	size_t align_len = RTA_ALIGN(len);

	if (rta->rta_len + align_len > maxlen)
		return 0;

	subrta = (struct rtattr*)(((char*)rta) + rta->rta_len);
	subrta->rta_type = type;
	subrta->rta_len = (unsigned short)len;
	memcpy(RTA_DATA(subrta), &data, sizeof data);
	rta->rta_len = (unsigned short)(rta->rta_len + align_len);
	return align_len;
}

size_t
rta_addattr16(struct rtattr *rta, size_t maxlen, unsigned short type, uint16_t data)
{
	return rta_addattr_l(rta, maxlen, type, &data, sizeof data);
}

size_t
rta_addattr8(struct rtattr *rta, size_t maxlen, unsigned short type, uint8_t data)
{
	return rta_addattr_l(rta, maxlen, type, &data, sizeof data);
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
	nest->rta_len = (unsigned short)((void *)RTA_TAIL(rta) - (void *)nest);

	return rta->rta_len;
}
#endif

static inline __u8 rta_getattr_u8(const struct rtattr *rta)
{
	return *(__u8 *)RTA_DATA(rta);
}

static void
parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta, size_t len)
{
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta, len);
	}
}

#ifdef _WITH_VRRP_
#ifdef _HAVE_VRRP_VMAC_
static void
parse_rtattr_nested(struct rtattr **tb, int max, struct rtattr *rta)
{
	parse_rtattr(tb, max, RTA_DATA(rta), RTA_PAYLOAD(rta));
}
#endif

static void
set_vrrp_backup(vrrp_t *vrrp)
{
	vrrp_t *sync_vrrp;
	element e;

	vrrp->wantstate = VRRP_STATE_BACK;
	vrrp_state_leave_master(vrrp, true);
	if (vrrp->sync) {
		LIST_FOREACH(vrrp->sync->vrrp_instances, sync_vrrp, e) {
			if (sync_vrrp->state == VRRP_STATE_MAST) {
				sync_vrrp->wantstate = VRRP_STATE_BACK;
				vrrp_state_leave_master(sync_vrrp, true);

				/* We want a quick transition back to master */
				sync_vrrp->ms_down_timer = VRRP_TIMER_SKEW(sync_vrrp);
				vrrp_init_instance_sands(sync_vrrp);
				vrrp_thread_requeue_read(sync_vrrp);
			}
		}
		vrrp->sync->state = VRRP_STATE_BACK;
	}

	/* We want a quick transition back to master */
	vrrp->ms_down_timer = VRRP_TIMER_SKEW(vrrp);
	vrrp_init_instance_sands(vrrp);
	vrrp_thread_requeue_read(vrrp);
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
#ifdef _WITH_VRRP_
	interface_t *ifp;
	ip_address_t *ipaddr;
#endif
	size_t len;
	union {
		void *addr;
		struct in_addr *in;
		struct in6_addr *in6;
	} addr;
#ifdef _WITH_VRRP_
	char addr_str[INET6_ADDRSTRLEN];
	bool addr_chg = false;
	element e;
	vrrp_t *vrrp;
	vrrp_t *address_vrrp;
	tracking_vrrp_t *tvp;
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

	memset(tb, 0, sizeof (tb));
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
#ifndef _DEBUG_
	if (prog_type == PROG_TYPE_VRRP)
#endif
	{
		/* Fetch interface_t */
		ifp = if_get_by_ifindex(ifa->ifa_index);
		if (!ifp)
			return 0;

// ?? Only interested in link-local for IPv6 unless unicast
// we take address from vrrp->ifp->base-ifp, unless we have made an IPv6 address
// do we want to set a flag to say it is a generated link local address (or set saddr and track_saddr, but not saddr_from_config)
// or can we just compare address to vrrp->ifp->base_ifp address.
// We still need to consider non-vmac IPv6 if interface doesn't have a
// link local address.
		if (!ifp->vmac || ifa->ifa_family == AF_INET6) {
			if (h->nlmsg_type == RTM_NEWADDR) {
				/* If no address is set on interface then set the first time */
// TODO if saddr from config && track saddr, addresses must match
				if (ifa->ifa_family == AF_INET) {
					if (!ifp->sin_addr.s_addr) {
						ifp->sin_addr = *addr.in;
						if (!LIST_ISEMPTY(ifp->tracking_vrrp))
							addr_chg = true;
					}
				} else {
// TODO  might not be link local if configured address
					if (ifa->ifa_scope == RT_SCOPE_LINK) {
						if (!ifp->sin6_addr.s6_addr32[0]) {
							ifp->sin6_addr = *addr.in6;
							if (!LIST_ISEMPTY(ifp->tracking_vrrp))
								addr_chg = true;
						}
#if defined _HAVE_VRRP_VMAC_ && !HAVE_DECL_IFLA_INET6_ADDR_GEN_MODE
						else if (ifp->vmac) {
							/* We already have an address; is this an auto generated link local address?
							 * For some reason if we recreate the VMAC when the underlying interface is
							 * recreated, deleting the autogenerated address doesn't get rid of the address */
							remove_vmac_auto_gen_addr(ifp, addr.in6);
						}
#endif
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
					for (e = LIST_HEAD(ifp->tracking_vrrp); e; ELEMENT_NEXT(e)) {
						tvp = ELEMENT_DATA(e);
						vrrp = tvp->vrrp;

						is_tracking_saddr = false;
						if (vrrp->track_saddr) {
							if (vrrp->family == ifa->ifa_family)
								is_tracking_saddr = inaddr_equal(ifa->ifa_family, &vrrp->saddr, addr.addr);
						}

						if (ifp == (vrrp->family == AF_INET ? vrrp->ifp->base_ifp : vrrp->ifp) &&
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
						// If IPv6 link local and vmac doesn't have an address, add it to the vmac
						else if (vrrp->family == AF_INET6 &&
							 ifp == vrrp->ifp->base_ifp &&
							 vrrp->ifp->vmac &&
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
			} else {
				/* Mark the address as needing to go. We can't delete the address
				 * until after down_instance is called, since it sends a prio 0 message */
				if (ifa->ifa_family == AF_INET) {
					if (ifp->sin_addr.s_addr == addr.in->s_addr)
						addr_chg = true;
				}
				else {
					if (ifp->sin6_addr.s6_addr32[0] == addr.in6->s6_addr32[0] &&
					    ifp->sin6_addr.s6_addr32[1] == addr.in6->s6_addr32[1] &&
					    ifp->sin6_addr.s6_addr32[2] == addr.in6->s6_addr32[2] &&
					    ifp->sin6_addr.s6_addr32[3] == addr.in6->s6_addr32[3])
						addr_chg = true;
				}

				if (addr_chg && !LIST_ISEMPTY(ifp->tracking_vrrp)) {
					if (__test_bit(LOG_DETAIL_BIT, &debug)) {
						inet_ntop(ifa->ifa_family, addr.addr, addr_str, sizeof(addr_str));
						log_message(LOG_INFO, "Deassigned address %s from interface %s"
								    , addr_str, ifp->ifname);
					}

					/* See if any vrrp instances need to be downed */
					for (e = LIST_HEAD(ifp->tracking_vrrp); e; ELEMENT_NEXT(e)) {
						tvp = ELEMENT_DATA(e);
						vrrp = tvp->vrrp;

						is_tracking_saddr = false;
						if (vrrp->track_saddr) {
							if (vrrp->family == ifa->ifa_family)
								is_tracking_saddr = inaddr_equal(ifa->ifa_family, &vrrp->saddr, addr.addr);
						}
#ifdef _HAVE_VRRP_VMAC_
						/* If we are a VMAC and took this address from the parent interface, we need to
						 * release the address and create one for ourself */
						if (ifa->ifa_family == AF_INET6 &&
						    __test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags) &&
						    ifp == vrrp->ifp->base_ifp &&
						    ifa->ifa_scope == RT_SCOPE_LINK &&
						    !vrrp->saddr_from_config &&
						    vrrp->ifp->base_ifp->sin6_addr.s6_addr32[0] == addr.in6->s6_addr32[0] &&
						    vrrp->ifp->base_ifp->sin6_addr.s6_addr32[1] == addr.in6->s6_addr32[1] &&
						    vrrp->ifp->base_ifp->sin6_addr.s6_addr32[2] == addr.in6->s6_addr32[2] &&
						    vrrp->ifp->base_ifp->sin6_addr.s6_addr32[3] == addr.in6->s6_addr32[3]) {
							if (IF_ISUP(ifp) && replace_link_local_address(vrrp->ifp))
								inet_ip6tosockaddr(&vrrp->ifp->sin6_addr, &vrrp->saddr);
							else if (IF_ISUP(ifp)) {
								/* We failed to add an address, so down the instance */
								down_instance(vrrp);
								vrrp->saddr.ss_family = AF_UNSPEC;
							}
						}
						else
#endif
						     if (ifp == (vrrp->family == AF_INET ? vrrp->ifp->base_ifp : vrrp->ifp) &&
							 vrrp->family == ifa->ifa_family &&
							 vrrp->saddr.ss_family != AF_UNSPEC &&
							 (!vrrp->saddr_from_config || is_tracking_saddr)) {
/* There might be another address available. Either send a netlink request for current addresses, or we keep a list */
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
						ifp->sin6_addr.s6_addr32[0] = 0;
				}
			}
		}

		if (!addr_chg || LIST_ISEMPTY(ifp->tracking_vrrp)) {
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
			LIST_FOREACH(vrrp_data->static_addresses, ipaddr, e) {
				if (!ipaddr->dont_track && addr_is_equal(ifa, addr.addr, ipaddr, ifp)) {
					reinstate_static_address(ipaddr);
					break;
				}
			}
		}
	}
#endif

#ifdef _WITH_LVS_
#ifndef _DEBUG_
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
	ssize_t status;
	int ret = 0;
	int error;

	while (true) {
		char buf[nlmsg_buf_size];
		struct iovec iov = {
			.iov_base = buf,
			.iov_len = sizeof buf
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

		status = recvmsg(nl->fd, &msg, 0);

		if (status < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;
			if (errno == ENOBUFS) {
				log_message(LOG_INFO, "Netlink: Receive buffer overrun on %s socket - (%m)", nl == &nl_kernel ? "monitor" : "cmd");
				log_message(LOG_INFO, "  - increase the relevant netlink_rcv_bufs global parameter and/or set force");
			}
			else
				log_message(LOG_INFO, "Netlink: recvmsg error on %s socket  - %d (%m)", nl == &nl_kernel ? "monitor" : "cmd", errno);
			continue;
		}

		if (status == 0) {
			log_message(LOG_INFO, "Netlink: EOF");
			return -1;
		}

		if (msg.msg_namelen != sizeof snl) {
			log_message(LOG_INFO,
			       "Netlink: Sender address length error: length %d",
			       msg.msg_namelen);
			return -1;
		}

		for (h = (struct nlmsghdr *) buf; NLMSG_OK(h, (size_t)status); h = NLMSG_NEXT(h, status)) {
			/* Finish off reading. */
			if (h->nlmsg_type == NLMSG_DONE)
				return ret;

			/* Error handling. */
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA(h);

				/*
				 * If error == 0 then this is a netlink ACK.
				 * return if not related to multipart message.
				 */
				if (err->error == 0) {
					if (!(h->nlmsg_flags & NLM_F_MULTI) && !read_all)
						return 0;
					continue;
				}

				if (h->nlmsg_len < NLMSG_LENGTH(sizeof (struct nlmsgerr))) {
					log_message(LOG_INFO,
					       "Netlink: error: message truncated");
					return -1;
				}

				if (n && (err->error == -EEXIST) &&
				    ((n->nlmsg_type == RTM_NEWROUTE) ||
				     (n->nlmsg_type == RTM_NEWADDR)))
					return 0;

				/* If have more than one IPv4 address in the same CIDR
				 * and the "primary" address is removed, unless promote_secondaries
				 * is configured on the interface, all the "secondary" addresses
				 * in the same CIDR are deleted */
				if (n && err->error == -EADDRNOTAVAIL &&
				    n->nlmsg_type == RTM_DELADDR) {
					if (!(h->nlmsg_flags & NLM_F_MULTI))
						return 0;
					continue;
				}
#ifdef _WITH_VRRP_
				if (netlink_error_ignore != -err->error)
#endif
					log_message(LOG_INFO,
					       "Netlink: error: %s, type=(%u), seq=%u, pid=%d",
					       strerror(-err->error),
					       err->msg.nlmsg_type,
					       err->msg.nlmsg_seq, err->msg.nlmsg_pid);

				return -1;
			}

#ifdef _WITH_VRRP_
			/* Skip unsolicited messages from cmd channel */
			if (
#ifndef _DEBUG_
			    prog_type == PROG_TYPE_VRRP &&
#endif
			    h->nlmsg_type != RTM_NEWROUTE &&
			    nl != &nl_cmd && h->nlmsg_pid == nl_cmd.nl_pid)

				continue;
#endif

			error = (*filter) (&snl, h);
			if (error < 0) {
				log_message(LOG_INFO, "Netlink: filter function error");
				ret = error;
			}

			if (!(h->nlmsg_flags & NLM_F_MULTI) && !read_all)
				return ret;
		}

		/* After error care. */
		if (msg.msg_flags & MSG_TRUNC) {
			log_message(LOG_INFO, "Netlink: error: message truncated");
			continue;
		}
		if (status) {
			log_message(LOG_INFO, "Netlink: error: data remnant size %zd",
			       status);
			return -1;
		}
	}

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
	struct sockaddr_nl snl;
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg i;
		char buf[64];
	} req;

	/* Cleanup the room */
	memset(&snl, 0, sizeof (snl));
	snl.nl_family = AF_NETLINK;

	memset(&req, 0, sizeof req);
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof req.i);
	req.nlh.nlmsg_type = type;
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
	addattr32(&req.nlh, sizeof req, IFLA_EXT_MASK, RTEXT_FILTER_SKIP_STATS);
#endif

	status = sendto(nl->fd, (void *) &req, sizeof (req)
			, 0, (struct sockaddr *) &snl, sizeof (snl));
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
	element e;
	tracking_vrrp_t *tvp;
	bool now_up = FLAGS_UP(ifp->ifi_flags);

	/* The state of the interface has changed from up to down or vice versa.
	 * Find which vrrp instances are affected */
	LIST_FOREACH(ifp->tracking_vrrp, tvp, e) {
		vrrp = tvp->vrrp;

		if (tvp->weight == VRRP_NOT_TRACK_IF) {
			/* We might want to restore things to the interface if it is coming up */
			continue;
		}

		if (tvp->weight) {
			if (now_up)
				vrrp->total_priority += abs(tvp->weight);
			else
				vrrp->total_priority -= abs(tvp->weight);
			vrrp_set_effective_priority(vrrp);

			continue;
		}

		/* This vrrp's interface or underlying interface has changed */
		if (now_up)
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
	was_up = IF_FLAGS_UP(ifp);
	now_up = FLAGS_UP(ifi_flags);

	ifp->ifi_flags = ifi_flags;

	if (was_up == now_up)
		return;

	if (ifp->tracking_vrrp) {
		log_message(LOG_INFO, "Netlink reports %s %s", ifp->ifname, now_up ? "up" : "down");

		process_if_status_change(ifp);
	}

	if (!now_up)
		interface_down(ifp);
	else
		interface_up(ifp);
}

static char *get_mac_string(int type)
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

static int netlink_if_get_ll_addr(interface_t *ifp, struct rtattr *tb[],
				  int type, char *name)
{
	size_t i;

	if (tb[type]) {
		size_t hw_addr_len = RTA_PAYLOAD(tb[type]);

		if (hw_addr_len > sizeof(ifp->hw_addr)) {
			log_message(LOG_ERR,
				    " %s MAC address for %s is too large: %zu",
				    get_mac_string(type), name, hw_addr_len);
			return -1;
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
			return -1;
		}
	}

	return 0;
}

static bool
netlink_if_link_populate(interface_t *ifp, struct rtattr *tb[], struct ifinfomsg *ifi)
{
	char *name;
#ifdef _HAVE_VRRP_VMAC_
	struct rtattr* linkinfo[IFLA_INFO_MAX+1];
	struct rtattr* linkattr[IFLA_MACVLAN_MAX+1];
#endif

	name = (char *)RTA_DATA(tb[IFLA_IFNAME]);
	/* Fill the interface structure */
	memcpy(ifp->ifname, name, strlen(name));
	ifp->ifindex = (ifindex_t)ifi->ifi_index;
	ifp->mtu = *(uint32_t *)RTA_DATA(tb[IFLA_MTU]);
	ifp->hw_type = ifi->ifi_type;
#ifdef _HAVE_VRRP_VMAC_
	ifp->base_ifp = ifp;
#endif

	if (netlink_if_get_ll_addr(ifp, tb, IFLA_ADDRESS, name) == -1)
		return -1;
	if (netlink_if_get_ll_addr(ifp, tb, IFLA_BROADCAST, name) == -1)
		return -1;

#ifdef _HAVE_VRRP_VMAC_
	/* See if this interface is a MACVLAN of ours */
	if (tb[IFLA_LINKINFO] && tb[IFLA_LINK]){
		/* If appears that the value of *(int*)RTA_DATA(tb[IFLA_LINKINFO]) is 0x1000c
		 *   for macvlan.  0x10000 for nested data, or'ed with 0x0c for macvlan;
		 *   other values are 0x09 for vlan, 0x0b for bridge, 0x08 for tun, -1 for no
		 *   underlying interface.
		 *
		 * I can't find where in the kernel these values are set or defined, so use
		 * the string as below.
		 */
		parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO]);

		if (linkinfo[IFLA_INFO_KIND] &&
		    RTA_PAYLOAD(linkinfo[IFLA_INFO_KIND]) >= strlen(macvlan_ll_kind) &&
		    !strncmp(macvlan_ll_kind, RTA_DATA(linkinfo[IFLA_INFO_KIND]), strlen(macvlan_ll_kind)) &&
		    linkinfo[IFLA_INFO_DATA]) {
			parse_rtattr_nested(linkattr, IFLA_MACVLAN_MAX, linkinfo[IFLA_INFO_DATA]);

			if (linkattr[IFLA_MACVLAN_MODE] &&
			    *(uint32_t*)RTA_DATA(linkattr[IFLA_MACVLAN_MODE]) == MACVLAN_MODE_PRIVATE) {
				ifp->base_ifindex = *(uint32_t *)RTA_DATA(tb[IFLA_LINK]);
				ifp->base_ifp = if_get_by_ifindex(ifp->base_ifindex);
				if (ifp->base_ifp)
					ifp->base_ifindex = 0;	/* Make sure this isn't used at runtime */
				ifp->vmac = true;
			}
		}
	}

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
	memset(tb, 0, sizeof (tb));
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

	if (tb[IFLA_IFNAME] == NULL)
		return -1;
	name = (char *) RTA_DATA(tb[IFLA_IFNAME]);

	/* Skip it if already exists */
	ifp = if_get_by_ifname(name, IF_CREATE_NETLINK);

	if (ifp->ifindex) {
		update_interface_flags(ifp, ifi->ifi_flags);

		return 0;
	}

	/* Fill the interface structure */
	if (!netlink_if_link_populate(ifp, tb, ifi))
		return -1;

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

	if (!(h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK))
		return 0;

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof (struct ifinfomsg)))
		return -1;
	len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct ifinfomsg));

	/* Interface name lookup */
	memset(tb, 0, sizeof (tb));
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
			if (!LIST_ISEMPTY(ifp->tracking_vrrp) || __test_bit(LOG_DETAIL_BIT, &debug))
				log_message(LOG_INFO, "Interface %s deleted", ifp->ifname);
#ifndef _DEBUG_
			if (prog_type == PROG_TYPE_VRRP)
				cleanup_lost_interface(ifp);
			else {
				ifp->ifi_flags = 0;
				ifp->ifindex = 0;
			}
#else
			cleanup_lost_interface(ifp);
#endif

#ifdef _HAVE_VRRP_VMAC_
			/* If this was a vmac we created, create it again, so long as the underlying i/f exists */
			if (!LIST_ISEMPTY(ifp->tracking_vrrp) && ifp->vmac && ifp->base_ifp->ifindex)
				thread_add_event(master, recreate_vmac_thread, ifp, 0);
#endif
		} else if (strcmp(ifp->ifname, name)) {
			/* The name can change, so handle that here */
			log_message(LOG_INFO, "Interface name has changed from %s to %s", ifp->ifname, name);

#ifndef _DEBUG_
			if (prog_type == PROG_TYPE_VRRP)
				cleanup_lost_interface(ifp);
			else {
				ifp->ifi_flags = 0;
				ifp->ifindex = 0;
			}
#else
			cleanup_lost_interface(ifp);
#endif
// What if this is an interface we want ? */

#ifdef _HAVE_VRRP_VMAC_
			/* If this was one of our vmacs, create it again */
			if (!LIST_ISEMPTY(ifp->tracking_vrrp) && ifp->vmac) {
				/* Change the mac address on the interface, so we can create a new vmac */

				/* Now create our VMAC again */
				if (ifp->base_ifp->ifindex)
					thread_add_event(master, recreate_vmac_thread, ifp, 0);
			}
			else
#endif
				ifp = NULL;	/* Set ifp to null, to force creating a new interface_t */
		} else if (ifp->linkbeat_use_polling) {
			/* Ignore interface if we are using linkbeat on it */
			return 0;
		}
	}

	if (!ifp) {
		if (h->nlmsg_type == RTM_NEWLINK) {
			ifp = if_get_by_ifname(name, IF_CREATE_NETLINK);

			/* Since the garp_delay and tracking_vrrp are set up by name,
			 * it is reasonable to preserve them.
			 * If what is created is a vmac, we could end up in a complete mess. */
			garp_delay_t *sav_garp_delay = ifp->garp_delay;
			list sav_tracking_vrrp = ifp->tracking_vrrp;

			memset(ifp, 0, sizeof(interface_t));

			ifp->garp_delay = sav_garp_delay;
			ifp->tracking_vrrp = sav_tracking_vrrp;

			if (!netlink_if_link_populate(ifp, tb, ifi))
				return -1;

			if (__test_bit(LOG_DETAIL_BIT, &debug))
				log_message(LOG_INFO, "Interface %s added", ifp->ifname);

			update_added_interface(ifp);
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

#ifdef _HAVE_FIB_ROUTING_
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

	memset(tb, 0, sizeof (tb));
	parse_rtattr(tb, RTA_MAX, RTM_RTA(rt), len);

	if (!(route = route_is_ours(rt, tb, &vrrp)))
		return 0;

	route->set = (h->nlmsg_type == RTM_NEWROUTE);

	/* Matching route */
	if (h->nlmsg_type == RTM_NEWROUTE) {
		/* If we haven't specified a dev for the route, save the link the route
		 * has been added to. */
		if (tb[RTA_OIF]) {
			route->configured_ifindex = *(uint32_t*)RTA_DATA(tb[RTA_OIF]);
			if (route->oif && route->oif->ifindex != route->configured_ifindex)
				log_message(LOG_INFO, "route added index %d != config index %d", route->configured_ifindex, route->oif->ifindex);
		}
		else
			log_message(LOG_INFO, "New route doesn't have i/f index");

		return 0;
	}

	/* We are only interested in route deletions now */

	if (route->dont_track)
		return 0;

	if (vrrp)
		set_vrrp_backup(vrrp);
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

	memset(tb, 0, sizeof (tb));
	parse_rtattr(tb, FRA_MAX, RTM_RTA(frh), len);

#if HAVE_DECL_FRA_PROTOCOL
	if (tb[FRA_PROTOCOL] &&
	    *(uint8_t *)RTA_DATA(tb[FRA_PROTOCOL]) != RTPROT_KEEPALIVED) {
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
#ifndef _DEBUG_
		if (prog_type == PROG_TYPE_VRRP)
#endif
			return netlink_link_filter(snl, h);
#endif
		break;
	case RTM_NEWADDR:
	case RTM_DELADDR:
		return netlink_if_address_filter(snl, h);
		break;
#ifdef _HAVE_FIB_ROUTING_
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

static int
kernel_netlink(thread_t * thread)
{
	nl_handle_t *nl = THREAD_ARG(thread);

	if (thread->type != THREAD_READ_TIMEOUT)
		netlink_parse_info(netlink_broadcast_filter, nl, NULL, true);
	nl->thread = thread_add_read(master, kernel_netlink, nl, nl->fd,
				      NETLINK_TIMER);
	return 0;
}

#ifdef _WITH_VRRP_
void
kernel_netlink_poll(void)
{
	if (!nl_kernel.fd)
		return;

	netlink_parse_info(netlink_broadcast_filter, &nl_kernel, NULL, true);
}
#endif

void
kernel_netlink_set_recv_bufs(void)
{
#ifdef _DEBUG_
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
	if (prog_type == PROG_TYPE_CHECKER) {
		netlink_set_rx_buf_size(&nl_kernel, global_data->lvs_netlink_monitor_rcv_bufs, global_data->lvs_netlink_monitor_rcv_bufs_force);
		netlink_set_rx_buf_size(&nl_cmd, global_data->lvs_netlink_cmd_rcv_bufs, global_data->lvs_netlink_cmd_rcv_bufs_force);
	}
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
	/* TODO
	 * If an interface goes down, or an address is removed, any routes that specify the interface or address are deleted.
	 * If an interface goes down, any address on that interface is deleted. In this case, the vrrp instance should go to fault state.
	 * If an interface goes down, any VMACs are deleted. We need to recreate them when the interface returns.
	 * If a static route/ip_address goes down, some vrrp instances maybe should go down - add a tracking_instance option
	 * We need to reinstate routes/addresses/VMACs when we can.
	 * We need an option on routes to put the instance in fault state if the route disappears.
	 * When i/f deleted (? or down), close any sockets
	 * No ipaddr on i/f <=> link down, for us
	 * Do LVS services get lost on addr/link deletion?
	 */

	/* If the netlink kernel fd is already open, just register a read thread.
	 * This will happen at reload. */
	if (nl_kernel.fd > 0) {
		nl_kernel.thread = thread_add_read(master, kernel_netlink, &nl_kernel, nl_kernel.fd, NETLINK_TIMER);
		return;
	}

#ifdef _DEBUG_
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

	if (nl_kernel.fd > 0) {
		log_message(LOG_INFO, "Registering Kernel netlink reflector");
		nl_kernel.thread = thread_add_read(master, kernel_netlink, &nl_kernel, nl_kernel.fd,
						   NETLINK_TIMER);
	} else
		log_message(LOG_INFO, "Error while registering Kernel netlink reflector channel");

	/* Prepare netlink command channel. The cmd socket is used synchronously.*/
#ifdef _DEBUG_
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
	if (nl_cmd.fd > 0)
		log_message(LOG_INFO, "Registering Kernel netlink command channel");
	else
		log_message(LOG_INFO, "Error while registering Kernel netlink cmd channel");

	/* Start with netlink interface and address lookup */
#ifdef _WITH_VRRP_
#ifndef _DEBUG_
	if (prog_type == PROG_TYPE_VRRP)
#endif
		init_interface_queue();
#endif

	netlink_address_lookup();

#if !defined _DEBUG_ && defined _WITH_CHECKER_
	if (prog_type == PROG_TYPE_CHECKER)
		kernel_netlink_close_cmd();
#endif
}

#ifdef _TIMER_DEBUG_
void
print_vrrp_netlink_addresses(void)
{
	log_message(LOG_INFO, "Address of kernel_netlink() is 0x%p", kernel_netlink);
}
#endif
