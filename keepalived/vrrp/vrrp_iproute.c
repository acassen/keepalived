/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK IPv4 routes manipulation.
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

#include <linux/icmpv6.h>
#include <inttypes.h>
#if HAVE_DECL_RTA_ENCAP
#include <linux/lwtunnel.h>
#if HAVE_DECL_LWTUNNEL_ENCAP_MPLS
#include <linux/mpls_iptunnel.h>
#endif
#if HAVE_DECL_LWTUNNEL_ENCAP_ILA
#include <linux/ila.h>
#endif
#endif
#include <stdbool.h>
#include <stdio.h>
#include <linux/rtnetlink.h>

/* local include */
#include "vrrp_iproute.h"
#include "keepalived_netlink.h"
#include "vrrp_data.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "rttables.h"
#include "vrrp_ip_rule_route_parser.h"
#include "parser.h"

/* Buffer sizes for netlink messages. Increase if needed. */
#define	RTM_SIZE		1024
#define	RTA_SIZE		1024
#define	ENCAP_RTA_SIZE		 128

/* Utility functions */
unsigned short
add_addr2req(struct nlmsghdr *n, size_t maxlen, unsigned short type, ip_address_t *ip_address)
{
	void *addr;
	size_t alen;

	if (!ip_address)
		return 0;

	if (IP_IS6(ip_address)) {
		addr = (void *) &ip_address->u.sin6_addr;
		alen = sizeof(ip_address->u.sin6_addr);
	}
	else
	{
	     addr = (void *) &ip_address->u.sin.sin_addr;
	     alen = sizeof(ip_address->u.sin.sin_addr);
	}

	return (unsigned short)addattr_l(n, maxlen, type, addr, alen);
}

#if HAVE_DECL_RTA_VIA
static unsigned short
add_addr_fam2req(struct nlmsghdr *n, size_t maxlen, unsigned short type, ip_address_t *ip_address)
{
	void *addr;
	size_t alen;
	uint16_t family;

	if (!ip_address)
		return 0;

	if (IP_IS6(ip_address)) {
		addr = (void *)&ip_address->u.sin6_addr;
		alen = sizeof(ip_address->u.sin6_addr);
	}
	else {
		addr = (void *)&ip_address->u.sin.sin_addr;
		alen = sizeof(ip_address->u.sin.sin_addr);
	}
	family = ip_address->ifa.ifa_family;

	return (unsigned short)addattr_l2(n, maxlen, type, &family, sizeof(family), addr, alen);
}
#endif

static unsigned short
add_addr2rta(struct rtattr *rta, size_t maxlen, unsigned short type, ip_address_t *ip_address)
{
	void *addr;
	size_t alen;

	if (!ip_address)
		return 0;

	if (IP_IS6(ip_address)) {
		addr = (void *)&ip_address->u.sin6_addr;
		alen = sizeof(ip_address->u.sin6_addr);
	}
	else {
		addr = (void *)&ip_address->u.sin.sin_addr;
		alen = sizeof(ip_address->u.sin.sin_addr);
	}

	return (unsigned short)rta_addattr_l(rta, maxlen, type, addr, alen);
}

#if HAVE_DECL_RTA_VIA
static unsigned short
add_addrfam2rta(struct rtattr *rta, size_t maxlen, unsigned short type, ip_address_t *ip_address)
{
	void *addr;
	size_t alen;
	uint16_t family;

	if (!ip_address)
		return 0;

	if (IP_IS6(ip_address)) {
		addr = (void *)&ip_address->u.sin6_addr;
		alen = sizeof(ip_address->u.sin6_addr);
	}
	else {
		addr = (void *)&ip_address->u.sin.sin_addr;
		alen = sizeof(ip_address->u.sin.sin_addr);
	}
	family = ip_address->ifa.ifa_family;

	return (unsigned short)rta_addattr_l2(rta, maxlen, type, &family, sizeof(family), addr, alen);
}
#endif

#if HAVE_DECL_RTA_ENCAP
#if HAVE_DECL_LWTUNNEL_ENCAP_MPLS
static void
add_encap_mpls(struct rtattr *rta, size_t len, const encap_t *encap)
{
	rta_addattr_l(rta, len, MPLS_IPTUNNEL_DST, &encap->mpls.addr, encap->mpls.num_labels * sizeof(encap->mpls.addr[0]));
}
#endif

static void
add_encap_ip(struct rtattr *rta, size_t len, const encap_t *encap)
{
	if (encap->flags & IPROUTE_BIT_ENCAP_ID)
		rta_addattr64(rta, len, LWTUNNEL_IP_ID, htobe64(encap->ip.id));
	if (encap->ip.dst)
		rta_addattr_l(rta, len, LWTUNNEL_IP_DST, &encap->ip.dst->u.sin.sin_addr.s_addr, sizeof(encap->ip.dst->u.sin.sin_addr.s_addr));
	if (encap->ip.src)
		rta_addattr_l(rta, len, LWTUNNEL_IP_SRC, &encap->ip.src->u.sin.sin_addr.s_addr, sizeof(encap->ip.src->u.sin.sin_addr.s_addr));
	if (encap->flags & IPROUTE_BIT_ENCAP_DSFIELD)
		rta_addattr8(rta, len, LWTUNNEL_IP_TOS, encap->ip.tos);
	if (encap->flags & IPROUTE_BIT_ENCAP_HOPLIMIT)
		rta_addattr8(rta, len, LWTUNNEL_IP_TTL, encap->ip.ttl);
	if (encap->flags & IPROUTE_BIT_ENCAP_FLAGS)
		rta_addattr16(rta, len, LWTUNNEL_IP_FLAGS, encap->ip.flags);
}

#if HAVE_DECL_LWTUNNEL_ENCAP_ILA
static void
add_encap_ila(struct rtattr *rta, size_t len, const encap_t *encap)
{
	rta_addattr64(rta, len, ILA_ATTR_LOCATOR, encap->ila.locator);
}
#endif

static void
add_encap_ip6(struct rtattr *rta, size_t len, const encap_t *encap)
{
	if (encap->flags & IPROUTE_BIT_ENCAP_ID)
		rta_addattr64(rta, len, LWTUNNEL_IP6_ID, htobe64(encap->ip6.id));
	if (encap->ip6.dst)
		rta_addattr_l(rta, len, LWTUNNEL_IP6_DST, &encap->ip6.dst->u.sin6_addr, sizeof(encap->ip6.dst->u.sin6_addr));
	if (encap->ip6.src)
		rta_addattr_l(rta, len, LWTUNNEL_IP6_SRC, &encap->ip6.src->u.sin6_addr, sizeof(encap->ip6.src->u.sin6_addr));
	if (encap->flags & IPROUTE_BIT_ENCAP_DSFIELD)
		rta_addattr8(rta, len, LWTUNNEL_IP6_TC, encap->ip6.tc);
	if (encap->flags & IPROUTE_BIT_ENCAP_HOPLIMIT)
		rta_addattr8(rta, len, LWTUNNEL_IP6_HOPLIMIT, encap->ip6.hoplimit);
	if (encap->flags & IPROUTE_BIT_ENCAP_FLAGS)
		rta_addattr16(rta, len, LWTUNNEL_IP6_FLAGS, encap->ip6.flags);
}

static bool
add_encap(struct rtattr *rta, size_t len, encap_t *encap)
{
	struct rtattr *nest;

	nest = rta_nest(rta, len, RTA_ENCAP);
	switch (encap->type) {
#if HAVE_DECL_LWTUNNEL_ENCAP_MPLS
	case LWTUNNEL_ENCAP_MPLS:
		add_encap_mpls(rta, len, encap);
		break;
#endif
	case LWTUNNEL_ENCAP_IP:
		add_encap_ip(rta, len, encap);
		break;
#if HAVE_DECL_LWTUNNEL_ENCAP_ILA
	case LWTUNNEL_ENCAP_ILA:
		add_encap_ila(rta, len, encap);
		break;
#endif
	case LWTUNNEL_ENCAP_IP6:
		add_encap_ip6(rta, len, encap);
		break;
	default:
		log_message(LOG_INFO, "unknown encap type %d", encap->type);
		break;
	}
	rta_nest_end(rta, nest);

	rta_addattr16(rta, len, RTA_ENCAP_TYPE, encap->type);

	return true;
}
#endif

static void
add_nexthop(nexthop_t *nh, struct rtmsg *rtm, struct rtattr *rta, size_t len, struct rtnexthop *rtnh)
{
	if (nh->addr) {
		if (rtm->rtm_family == nh->addr->ifa.ifa_family)
			rtnh->rtnh_len = (unsigned short)(rtnh->rtnh_len + add_addr2rta(rta, len, RTA_GATEWAY, nh->addr));
#if HAVE_DECL_RTA_VIA
		else
			rtnh->rtnh_len = (unsigned short)(rtnh->rtnh_len + add_addrfam2rta(rta, len, RTA_VIA, nh->addr));
#endif
	}
	if (nh->ifp)
		rtnh->rtnh_ifindex = (int)nh->ifp->ifindex;

	if (nh->mask & IPROUTE_BIT_WEIGHT)
		rtnh->rtnh_hops = nh->weight;

	rtnh->rtnh_flags = nh->flags;

	if (nh->realms)
		rtnh->rtnh_len = (unsigned short)(rtnh->rtnh_len + rta_addattr32(rta, len, RTA_FLOW, nh->realms));

#if HAVE_DECL_RTA_ENCAP
	if (nh->encap.type != LWTUNNEL_ENCAP_NONE) {
		unsigned short rta_len = rta->rta_len;
		add_encap(rta, rta_len, &nh->encap);
		rtnh->rtnh_len = (unsigned short)(rtnh->rtnh_len + rta->rta_len - rta_len);
	}
#endif
}

static void
add_nexthops(ip_route_t *route, struct nlmsghdr *nlh, struct rtmsg *rtm)
{
	char buf[ENCAP_RTA_SIZE] __attribute__((aligned(__alignof__(struct rtattr))));
	struct rtattr *rta = PTR_CAST(struct rtattr, buf);
	struct rtnexthop *rtnh;
	nexthop_t *nh;

	rta->rta_type = RTA_MULTIPATH;
	rta->rta_len = RTA_LENGTH(0);
	rtnh = RTA_DATA(rta);

	list_for_each_entry(nh, &route->nhs, e_list) {
		memset(rtnh, 0, sizeof(*rtnh));
		rtnh->rtnh_len = sizeof(*rtnh);
		rta->rta_len = (unsigned short)(rta->rta_len + rtnh->rtnh_len);
		add_nexthop(nh, rtm, rta, sizeof(buf), rtnh);
		rtnh = RTNH_NEXT(rtnh);
	}

	if (rta->rta_len > RTA_LENGTH(0))
		addattr_l(nlh, sizeof(buf), RTA_MULTIPATH, RTA_DATA(rta), RTA_PAYLOAD(rta));
}

/* Add/Delete IP route to/from a specific interface.
 * Note: We do not set the NLM_F_EXCL flag, and so the equivalent ip route
 * command to add a route is: ip route prepend ...
 */
static bool
netlink_route(ip_route_t *iproute, int cmd)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[RTM_SIZE];
	} req;
	char buf[RTA_SIZE] __attribute__((aligned(__alignof__(struct rtattr))));
	struct rtattr *rta = PTR_CAST(struct rtattr, buf);

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
	if (cmd == IPROUTE_DEL) {
		req.n.nlmsg_flags = NLM_F_REQUEST;
		req.n.nlmsg_type  = RTM_DELROUTE;
	}
	else {
		req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
		if (cmd == IPROUTE_REPLACE)
			req.n.nlmsg_flags |= NLM_F_REPLACE;
		req.n.nlmsg_type  = RTM_NEWROUTE;
	}

	rta->rta_type = RTA_METRICS;
	rta->rta_len = RTA_LENGTH(0);

	req.r.rtm_family = iproute->family;
	if (iproute->table < 256)
		req.r.rtm_table = (unsigned char)iproute->table;
	else {
		req.r.rtm_table = RT_TABLE_UNSPEC;
		addattr32(&req.n, sizeof(req), RTA_TABLE, iproute->table);
	}

	if (cmd == IPROUTE_DEL) {
		req.r.rtm_scope = RT_SCOPE_NOWHERE;
		if (iproute->mask & IPROUTE_BIT_TYPE)
			req.r.rtm_type = iproute->type;
	}
	else {
		req.r.rtm_scope = RT_SCOPE_UNIVERSE;
		req.r.rtm_type = iproute->type;
	}

	if (iproute->mask & IPROUTE_BIT_PROTOCOL)
		req.r.rtm_protocol = iproute->protocol;
	else
		req.r.rtm_protocol = RTPROT_KEEPALIVED;

	if (iproute->mask & IPROUTE_BIT_SCOPE)
		req.r.rtm_scope = iproute->scope;

	if (iproute->dst) {
		req.r.rtm_dst_len = iproute->dst->ifa.ifa_prefixlen;
		add_addr2req(&req.n, sizeof(req), RTA_DST, iproute->dst);
	}

	if (iproute->src) {
		req.r.rtm_src_len = iproute->src->ifa.ifa_prefixlen;
		add_addr2req(&req.n, sizeof(req), RTA_SRC, iproute->src);
	}

	if (iproute->pref_src)
		add_addr2req(&req.n, sizeof(req), RTA_PREFSRC, iproute->pref_src);

//#if HAVE_DECL_RTA_NEWDST
//	if (iproute->as_to)
//		add_addr2req(&req.n, sizeof(req), RTA_NEWDST, iproute->as_to);
//#endif

	if (iproute->via) {
		if (iproute->via->ifa.ifa_family == iproute->family)
			add_addr2req(&req.n, sizeof(req), RTA_GATEWAY, iproute->via);
#if HAVE_DECL_RTA_VIA
		else
			add_addr_fam2req(&req.n, sizeof(req), RTA_VIA, iproute->via);
#endif
	}

#if HAVE_DECL_RTA_ENCAP
	if (iproute->encap.type != LWTUNNEL_ENCAP_NONE) {
		char encap_buf[ENCAP_RTA_SIZE] __attribute__((aligned(__alignof__(struct rtattr))));
		struct rtattr *encap_rta = PTR_CAST(struct rtattr, encap_buf);

		encap_rta->rta_type = RTA_ENCAP;
		encap_rta->rta_len = RTA_LENGTH(0);
		add_encap(encap_rta, sizeof(encap_buf), &iproute->encap);

		if (encap_rta->rta_len > RTA_LENGTH(0))
			addraw_l(&req.n, sizeof(encap_buf), RTA_DATA(encap_rta), RTA_PAYLOAD(encap_rta));
	}
#endif

	if (iproute->mask & IPROUTE_BIT_DSFIELD)
		req.r.rtm_tos = iproute->tos;

	if (iproute->oif)
		addattr32(&req.n, sizeof(req), RTA_OIF, iproute->oif->ifindex);

	if (iproute->mask & IPROUTE_BIT_METRIC)
		addattr32(&req.n, sizeof(req), RTA_PRIORITY, iproute->metric);

	req.r.rtm_flags = iproute->flags;

	if (iproute->realms)
		addattr32(&req.n, sizeof(req), RTA_FLOW, iproute->realms);

#if HAVE_DECL_RTA_EXPIRES
	if (iproute->mask & IPROUTE_BIT_EXPIRES)
		addattr32(&req.n, sizeof(req), RTA_EXPIRES, iproute->expires);
#endif

#if HAVE_DECL_RTAX_CC_ALGO
	if (iproute->congctl)
		rta_addattr_l(rta, sizeof(buf), RTAX_CC_ALGO, iproute->congctl, strlen(iproute->congctl));
#endif

	if (iproute->mask & IPROUTE_BIT_RTT)
		rta_addattr32(rta, sizeof(buf), RTAX_RTT, iproute->rtt);

	if (iproute->mask & IPROUTE_BIT_RTTVAR)
		rta_addattr32(rta, sizeof(buf), RTAX_RTTVAR, iproute->rttvar);

	if (iproute->mask & IPROUTE_BIT_RTO_MIN)
		rta_addattr32(rta, sizeof(buf), RTAX_RTO_MIN, iproute->rto_min);

	if (iproute->features)
		rta_addattr32(rta, sizeof(buf), RTAX_FEATURES, iproute->features);

	if (iproute->mask & IPROUTE_BIT_MTU)
		rta_addattr32(rta, sizeof(buf), RTAX_MTU, iproute->mtu);

	if (iproute->mask & IPROUTE_BIT_WINDOW)
		rta_addattr32(rta, sizeof(buf), RTAX_WINDOW, iproute->window);

	if (iproute->mask & IPROUTE_BIT_SSTHRESH)
		rta_addattr32(rta, sizeof(buf), RTAX_SSTHRESH, iproute->ssthresh);

	if (iproute->mask & IPROUTE_BIT_CWND)
		rta_addattr32(rta, sizeof(buf), RTAX_CWND, iproute->cwnd);

	if (iproute->mask & IPROUTE_BIT_ADVMSS)
		rta_addattr32(rta, sizeof(buf), RTAX_ADVMSS, iproute->advmss);

	if (iproute->mask & IPROUTE_BIT_REORDERING)
		rta_addattr32(rta, sizeof(buf), RTAX_REORDERING, iproute->reordering);

	if (iproute->mask & IPROUTE_BIT_HOPLIMIT)
		rta_addattr32(rta, sizeof(buf), RTAX_HOPLIMIT, iproute->hoplimit);

	if (iproute->mask & IPROUTE_BIT_INITCWND)
		rta_addattr32(rta, sizeof(buf), RTAX_INITCWND, iproute->initcwnd);

	if (iproute->mask & IPROUTE_BIT_INITRWND)
		rta_addattr32(rta, sizeof(buf), RTAX_INITRWND, iproute->initrwnd);

#if HAVE_DECL_RTAX_QUICKACK
	if (iproute->mask & IPROUTE_BIT_QUICKACK)
		rta_addattr32(rta, sizeof(buf), RTAX_QUICKACK, iproute->quickack);
#endif

#if HAVE_DECL_RTA_PREF
	if (iproute->mask & IPROUTE_BIT_PREF)
		addattr8(&req.n, sizeof(req), RTA_PREF, iproute->pref);
#endif

#if HAVE_DECL_RTAX_FASTOPEN_NO_COOKIE
	if (iproute->mask & IPROUTE_BIT_FASTOPEN_NO_COOKIE)
		rta_addattr32(rta, sizeof(buf), RTAX_FASTOPEN_NO_COOKIE, iproute->fastopen_no_cookie);
#endif

#if HAVE_DECL_RTA_TTL_PROPAGATE
	if (iproute->mask & IPROUTE_BIT_TTL_PROPAGATE)
		addattr8(&req.n, sizeof(req), RTA_TTL_PROPAGATE, iproute->ttl_propagate);
#endif

	if (rta->rta_len > RTA_LENGTH(0)) {
		if (iproute->lock)
			rta_addattr32(rta, sizeof(buf), RTAX_LOCK, iproute->lock);
		addattr_l(&req.n, sizeof(req), RTA_METRICS, RTA_DATA(rta), RTA_PAYLOAD(rta));
	}

	if (!list_empty(&iproute->nhs))
		add_nexthops(iproute, &req.n, &req.r);

#ifdef DEBUG_NETLINK_MSG
	size_t i, j;
	uint8_t *p;
	char lbuf[3072];
	char *op = lbuf;

	log_message(LOG_INFO, "rtmsg buffer used %lu, rtattr buffer used %d", req.n.nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg)), rta->rta_len);

	op += (size_t)snprintf(op, sizeof(lbuf) - (op - lbuf), "nlmsghdr %p(%u):", &req.n, req.n.nlmsg_len);
	for (i = 0, p = PTR_CAST(uint8_t, &req.n); i < sizeof(struct nlmsghdr); i++)
		op += (size_t)snprintf(op, sizeof(lbuf) - (op - lbuf), " %2.2hhx", *(p++));
	log_message(LOG_INFO, "%s", lbuf);

	op = lbuf;
	op += (size_t)snprintf(op, sizeof(lbuf) - (op - lbuf), "rtmsg %p(%lu):", &req.r, req.n.nlmsg_len - sizeof(struct nlmsghdr));
	for (i = 0, p = PTR_CAST(uint8_t, &req.r); i < req.n.nlmsg_len - sizeof(struct nlmsghdr); i++)
		op += (size_t)snprintf(op, sizeof(lbuf) - (op - lbuf), " %2.2hhx", *(p++));

	for (j = 0; lbuf + j < op; j+= MAX_LOG_MSG)
		log_message(LOG_INFO, "%.*", MAX_LOG_MSG, lbuf+j);
#endif

	/* This returns ESRCH if the address of via address doesn't exist */
	/* ENETDOWN if dev p33p1.40 for example is down */
	if (netlink_talk(&nl_cmd, &req.n) < 0) {
#if HAVE_DECL_RTA_EXPIRES
		/* If an expiry was set on the route, it may have disappeared already */
		if (cmd != IPROUTE_DEL || !(iproute->mask & IPROUTE_BIT_EXPIRES))
#endif
			return true;
	}

	return false;
}

/* Add/Delete a list of IP routes */
bool
netlink_rtlist(list_head_t *rt_list, int cmd, bool force)
{
	ip_route_t *ip_route;

	/* No routes to add */
	if (list_empty(rt_list))
		return false;

	list_for_each_entry(ip_route, rt_list, e_list) {
		if ((cmd == IPROUTE_DEL) == ip_route->set || force) {
			if (!netlink_route(ip_route, cmd))
				ip_route->set = (cmd == IPROUTE_ADD);
			else if (cmd != IPROUTE_ADD)
				ip_route->set = false;
		}
	}

	return true;
}

/* Route dump/allocation */
static void
free_nh(nexthop_t *nh)
{
	FREE_PTR(nh->addr);
//#if HAVE_DECL_RTA_NEWDST
//	FREE_PTR(nh->as_to);
//#endif
	FREE(nh);
}

static void
free_nh_list(list_head_t *l)
{
	nexthop_t *nh, *nh_tmp;

	list_for_each_entry_safe(nh, nh_tmp, l, e_list)
		free_nh(nh);
}

void
free_iproute(ip_route_t *route)
{
	FREE_PTR(route->dst);
	FREE_PTR(route->src);
	FREE_PTR(route->pref_src);
	FREE_PTR(route->via);
	free_nh_list(&route->nhs);
#if HAVE_DECL_RTAX_CC_ALGO
	FREE_PTR(route->congctl);
#endif
	FREE(route);
}

void
free_iproute_list(list_head_t *l)
{
	ip_route_t *route, *route_tmp;

	list_for_each_entry_safe(route, route_tmp, l, e_list)
		free_iproute(route);
}

#if HAVE_DECL_RTA_ENCAP
#if HAVE_DECL_LWTUNNEL_ENCAP_MPLS
static size_t
print_encap_mpls(char *op, size_t len, const encap_t* encap)
{
	char *buf = op;
	const char* buf_end = op + len;
	unsigned i;

	op += snprintf(op, (size_t)(buf_end - op), " encap mpls");
	/* LGTM does not seem to be able to recognise the op < buf_end -1 in the loop control */
	for (i = 0; i < encap->mpls.num_labels && op < buf_end - 1; i++)
		op += snprintf(op, (size_t)(buf_end - op), "%s%x", i ? "/" : " ", ntohl(encap->mpls.addr[i].entry));	/* lgtm [cpp/overflowing-snprintf] */

	return (size_t)(op - buf);
}
#endif

static size_t
print_encap_ip(char *op, size_t len, const encap_t* encap)
{
	char *buf = op;
	const char *buf_end = op + len;

	op += snprintf(op, (size_t)(buf_end - op), " encap ip");

	if (encap->flags & IPROUTE_BIT_ENCAP_ID)
		op += snprintf(op, (size_t)(buf_end - op), " id %" PRIu64, encap->ip.id);
	if (encap->ip.dst)
		op += snprintf(op, (size_t)(buf_end - op), " dst %s", ipaddresstos(NULL, encap->ip.dst));
	if (encap->ip.src)
		op += snprintf(op, (size_t)(buf_end - op), " src %s", ipaddresstos(NULL, encap->ip.src));
	if (encap->flags & IPROUTE_BIT_ENCAP_DSFIELD)
		op += snprintf(op, (size_t)(buf_end - op), " tos %d", encap->ip.tos);
	if (encap->flags & IPROUTE_BIT_ENCAP_TTL)
		op += snprintf(op, (size_t)(buf_end - op), " ttl %d", encap->ip.ttl);
	if (encap->flags & IPROUTE_BIT_ENCAP_FLAGS)
		op += snprintf(op, (size_t)(buf_end - op), " flags 0x%x", encap->ip.flags);

	return (size_t)(op - buf);
}

#if HAVE_DECL_LWTUNNEL_ENCAP_ILA
static size_t
print_encap_ila(char *op, size_t len, const encap_t* encap)
{
	return (size_t)snprintf(op, len, " encap ila %" PRIu64, encap->ila.locator);
}
#endif

static size_t
print_encap_ip6(char *op, size_t len, const encap_t* encap)
{
	char *buf = op;
	const char *buf_end = op + len;

	op += snprintf(op, (size_t)(buf_end - op), " encap ip6");

	if (encap->flags & IPROUTE_BIT_ENCAP_ID)
		op += snprintf(op, (size_t)(buf_end - op), " id %" PRIu64, encap->ip6.id);
	if (encap->ip.dst)
		op += snprintf(op, (size_t)(buf_end - op), " dst %s", ipaddresstos(NULL, encap->ip6.dst));
	if (encap->ip.src)
		op += snprintf(op, (size_t)(buf_end - op), " src %s", ipaddresstos(NULL, encap->ip6.src));
	if (encap->flags & IPROUTE_BIT_ENCAP_DSFIELD)
		op += snprintf(op, (size_t)(buf_end - op), " tc %d", encap->ip6.tc);
	if (encap->flags & IPROUTE_BIT_ENCAP_HOPLIMIT)
		op += snprintf(op, (size_t)(buf_end - op), " hoplimit %d", encap->ip6.hoplimit);
	if (encap->flags & IPROUTE_BIT_ENCAP_FLAGS)
		op += snprintf(op, (size_t)(buf_end - op), " flags 0x%x", encap->ip6.flags);

	return (size_t)(op - buf);
}

static size_t
print_encap(char *op, size_t len, const encap_t* encap)
{
	switch (encap->type) {
#if HAVE_DECL_LWTUNNEL_ENCAP_MPLS
	case LWTUNNEL_ENCAP_MPLS:
		return print_encap_mpls(op, len, encap);
#endif
	case LWTUNNEL_ENCAP_IP:
		return print_encap_ip(op, len, encap);
#if HAVE_DECL_LWTUNNEL_ENCAP_ILA
	case LWTUNNEL_ENCAP_ILA:
		return print_encap_ila(op, len, encap);
#endif
	case LWTUNNEL_ENCAP_IP6:
		return print_encap_ip6(op, len, encap);
	}

	return (size_t)snprintf(op, len, "unknown encap type %d", encap->type);
}
#endif

void
format_iproute(const ip_route_t *route, char *buf, size_t buf_len)
{
	char *op = buf;
	const char *buf_end = buf + buf_len;
	nexthop_t *nh;
	interface_t *ifp;

	/* The do {...} while(false) loop is so that we can break out of the loop if the buffer is filled */
	do {
		if (route->type != RTN_UNICAST)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), "%s ", get_rttables_rtntype(route->type))) >= buf_end - 1)
				break;
		if (route->dst) {
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), "%s", ipaddresstos(NULL, route->dst))) >= buf_end - 1)
				break;
		} else {
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), "%s", "default")) >= buf_end - 1)
				break;
		}

		if (route->src)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " from %s", ipaddresstos(NULL, route->src))) >= buf_end - 1)
				break;

//#if HAVE_DECL_RTA_NEWDST
//		/* MPLS only */
//		if (route->as_to)
//			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " as to %s", ipaddresstos(NULL, route->as_to))) >= buf_end - 1)
//				break;
//#endif

		if (route->pref_src)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " src %s", ipaddresstos(NULL, route->pref_src))) >= buf_end - 1)
				break;

		if (route->mask & IPROUTE_BIT_DSFIELD)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " tos %u", route->tos)) >= buf_end - 1)
				break;

#if HAVE_DECL_RTA_ENCAP
		if (route->encap.type != LWTUNNEL_ENCAP_NONE)
			if ((op += print_encap(op, (size_t)(buf_end - op), &route->encap)) >= buf_end - 1)
				break;
#endif

		if (route->via)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " via %s %s", route->via->ifa.ifa_family == AF_INET6 ? "inet6" : "inet", ipaddresstos(NULL, route->via))) >= buf_end - 1)
				break;

		if (route->oif)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " dev %s", route->oif->ifname)) >= buf_end - 1)
				break;

		if (route->table != RT_TABLE_MAIN)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " table %u", route->table)) >= buf_end - 1)
				break;

		if (route->mask & IPROUTE_BIT_PROTOCOL)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " proto %u", route->protocol)) >= buf_end - 1)
				break;

		if (route->mask & IPROUTE_BIT_SCOPE)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " scope %u", route->scope)) >= buf_end - 1)
				break;

		if (route->mask & IPROUTE_BIT_METRIC)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " metric %u", route->metric)) >= buf_end - 1)
				break;

		if (route->family == AF_INET && route->flags & RTNH_F_ONLINK)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " %s", "onlink")) >= buf_end - 1)
				break;

		if (route->realms) {
			if (route->realms & 0xFFFF0000) {
				if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " realms %" PRIu32 "/", route->realms >> 16)) >= buf_end - 1)
					break;
			} else {
				if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " realm ")) >= buf_end - 1)
					break;
			}

			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), "%u", route->realms & 0xFFFF)) >= buf_end - 1)
					break;
		}

#if HAVE_DECL_RTA_EXPIRES
		if (route->mask & IPROUTE_BIT_EXPIRES)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " expires %" PRIu32 "sec", route->expires)) >= buf_end - 1)
				break;
#endif

#if HAVE_DECL_RTAX_CC_ALGO
		if (route->congctl)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " congctl %s%s", route->congctl, route->lock & (1<<RTAX_CC_ALGO) ? "lock " : "")) >= buf_end - 1)
				break;
#endif

		if (route->mask & IPROUTE_BIT_RTT) {
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " %s%s ", "rtt", route->lock & (1<<RTAX_RTT) ? " lock" : "")) >= buf_end - 1)
				break;
			if (route->rtt >= 8000) {
				if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), "%gs", route->rtt / (double)8000.0F)) >= buf_end - 1)
					break;
			} else {
				if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), "%ums", route->rtt / 8)) >= buf_end - 1)
					break;
			}
		}

		if (route->mask & IPROUTE_BIT_RTTVAR) {
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " %s%s ", "rttvar", route->lock & (1<<RTAX_RTTVAR) ? " lock" : "")) >= buf_end - 1)
				break;
			if (route->rttvar >= 4000) {
				if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), "%gs", route->rttvar / (double)4000.0F)) >= buf_end - 1)
					break;
			} else {
				if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), "%ums", route->rttvar / 4)) >= buf_end - 1)
					break;
			}
		}

		if (route->mask & IPROUTE_BIT_RTO_MIN) {
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " %s%s ", "rto_min", route->lock & (1<<RTAX_RTO_MIN) ? " lock" : "")) >= buf_end - 1)
				break;
			if (route->rto_min >= 1000) {
				if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), "%gs", route->rto_min / (double)1000.0F)) >= buf_end - 1)
					break;
			} else {
				if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), "%ums", route->rto_min)) >= buf_end - 1)
					break;
			}
		}

		if (route->features & RTAX_FEATURE_ECN)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " %s", "features ecn")) >= buf_end - 1)
				break;

		if (route->mask & IPROUTE_BIT_MTU) {
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " mtu %s%u",
				   route->lock & (1<<RTAX_MTU) ? "lock " : "",
				   route->mtu)) >= buf_end - 1)
				break;
		}

		if (route->mask & IPROUTE_BIT_WINDOW)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " window %u", route->window)) >= buf_end - 1)
				break;

		if (route->mask & IPROUTE_BIT_SSTHRESH) {
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " ssthresh %s%u",
				  route->lock & (1<<RTAX_SSTHRESH) ? "lock " : "",
				  route->ssthresh)) >= buf_end - 1)
				break;
		}

		if (route->mask & IPROUTE_BIT_CWND) {
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " cwnd %s%u",
				   route->lock & (1<<RTAX_CWND) ? "lock " : "",
				   route->cwnd)) >= buf_end)
				break;
		}

		if (route->mask & IPROUTE_BIT_ADVMSS) {
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " advmss %s%u",
				   route->lock & (1<<RTAX_ADVMSS) ? "lock " : "",
				   route->advmss)) >= buf_end - 1)
				break;
		}

		if (route->mask & IPROUTE_BIT_REORDERING) {
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " reordering %s%u",
				   route->lock & (1<<RTAX_REORDERING) ? "lock " : "",
				   route->reordering)) >= buf_end - 1)
				break;
		}

		if (route->mask & IPROUTE_BIT_HOPLIMIT)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " hoplimit %u", route->hoplimit)) >= buf_end - 1)
				break;

		if (route->mask & IPROUTE_BIT_INITCWND)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " initcwnd %u", route->initcwnd)) >= buf_end - 1)
				break;

		if (route->mask & IPROUTE_BIT_INITRWND)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " initrwnd %u", route->initrwnd)) >= buf_end - 1)
				break;

#if HAVE_DECL_RTAX_QUICKACK
		if (route->mask & IPROUTE_BIT_QUICKACK)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " quickack %d", route->quickack)) >= buf_end - 1)
				break;
#endif

#if HAVE_DECL_RTA_PREF
		if (route->mask & IPROUTE_BIT_PREF)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " %s %s", "pref",
				   route->pref == ICMPV6_ROUTER_PREF_LOW ? "low" :
				   route->pref == ICMPV6_ROUTER_PREF_MEDIUM ? "medium" :
				   route->pref == ICMPV6_ROUTER_PREF_HIGH ? "high" :
				   "unknown")) >= buf_end - 1)
				break;
#endif

#if HAVE_DECL_RTAX_FASTOPEN_NO_COOKIE
		if (route->mask & IPROUTE_BIT_FASTOPEN_NO_COOKIE)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " %s %d", "fastopen_no_cookie", route->fastopen_no_cookie)) >= buf_end - 1)
				break;
#endif

#if HAVE_DECL_RTA_TTL_PROPAGATE
		if (route->mask & IPROUTE_BIT_TTL_PROPAGATE)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " %s %sabled", "ttl-propagate", route->ttl_propagate ? "en" : "dis")) >= buf_end - 1)
				break;
#endif

		/* LGTM does not seem to be able to recognise the op < buf_end -1 break in the loop within a loop */
		list_for_each_entry(nh, &route->nhs, e_list) {
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " nexthop")) >= buf_end - 1)	/* lgtm [cpp/overflowing-snprintf] */
				break;
			if (nh->addr)
				if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " via inet%s %s"	/* lgtm [cpp/overflowing-snprintf] */
							    , nh->addr->ifa.ifa_family == AF_INET ? "" : "6"
							    , ipaddresstos(NULL,nh->addr))) >= buf_end - 1)
					break;
			if (nh->ifp)
				if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " dev %s", nh->ifp->ifname)) >= buf_end - 1)	/* lgtm [cpp/overflowing-snprintf] */
					break;
			if (nh->mask & IPROUTE_BIT_WEIGHT)
				if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " weight %d", nh->weight + 1)) >= buf_end - 1)	/* lgtm [cpp/overflowing-snprintf] */
					break;
			if (nh->flags & RTNH_F_ONLINK)
				if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " onlink")) >= buf_end - 1)	/* lgtm [cpp/overflowing-snprintf] */
					break;
			if (nh->realms) {
				if (route->realms & 0xFFFF0000) {
					if ((op += (size_t)snprintf(op, (size_t)(buf_end - op)	/* lgtm [cpp/overflowing-snprintf] */
								 , " realms %" PRIu32 "/", nh->realms >> 16)) >= buf_end - 1)
						break;
				} else {
					if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " realm ")) >= buf_end - 1)	/* lgtm [cpp/overflowing-snprintf] */
						break;
				}

				if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), "%" PRIu32, nh->realms & 0xFFFF)) >= buf_end - 1)	/* lgtm [cpp/overflowing-snprintf] */
					break;
			}
#if HAVE_DECL_RTA_ENCAP
			if (nh->encap.type != LWTUNNEL_ENCAP_NONE)
				if ((op += print_encap(op, (size_t)(buf_end - op), &nh->encap)) >= buf_end - 1)
					break;
#endif
		}
		if (op >= buf_end - 1)
			break;

		if (route->dont_track)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " no_track")) >= buf_end - 1)
				break;

		if (route->track_group)
			if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " track_group %s", route->track_group->gname)) >= buf_end - 1)
				break;

		if (route->set &&
		    !route->dont_track &&
		    (!route->oif || route->oif->ifindex != route->configured_ifindex)) {
			if ((ifp = if_get_by_ifindex(route->configured_ifindex))) {
				if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " [dev %s]", ifp->ifname)) >= buf_end - 1)
					break;
			} else {
				if ((op += (size_t)snprintf(op, (size_t)(buf_end - op), " [installed ifindex %" PRIu32 "]", route->configured_ifindex)) >= buf_end - 1)
					break;
			}
		}
	} while (false);
}

void
dump_iproute(FILE *fp, const ip_route_t *route)
{
	char *buf = MALLOC(ROUTE_BUF_SIZE);
	size_t len;
	size_t i;

	format_iproute(route, buf, ROUTE_BUF_SIZE);

	if (fp)
		conf_write(fp, "%*s%s", 5, "", buf);
	else {
		for (i = 0, len = strlen(buf); i < len; i += i ? MAX_LOG_MSG - 7 : MAX_LOG_MSG - 5)
			conf_write(fp, "%*s%s", i ? 6 : 5, "", buf + i);
	}

	FREE(buf);
}

void
dump_iproute_list(FILE *fp, const list_head_t *l)
{
	ip_route_t *route;

	list_for_each_entry(route, l, e_list)
		dump_iproute(fp, route);
}

#if HAVE_DECL_RTA_ENCAP
#if HAVE_DECL_LWTUNNEL_ENCAP_MPLS
static int parse_encap_mpls(const vector_t *strvec, unsigned int *i_ptr, encap_t *encap)
{
	const char *str;

	encap->type = LWTUNNEL_ENCAP_MPLS;

	if (*i_ptr >= vector_size(strvec)) {
		report_config_error(CONFIG_GENERAL_ERROR, "missing address for MPLS encapsulation");
		return true;
	}

	str = strvec_slot(strvec, (*i_ptr)++);
	if (parse_mpls_address(str, &encap->mpls)) {
		report_config_error(CONFIG_GENERAL_ERROR, "invalid mpls address %s for encapsulation", str);
		return true;
	}

	return false;
}
#endif

static int parse_encap_ip(const vector_t *strvec, unsigned int *i_ptr, encap_t *encap)
{
	unsigned int i = *i_ptr;
	const char *str, *str1;

	encap->type = LWTUNNEL_ENCAP_IP;

	while (i + 1 < vector_size(strvec)) {
		str = strvec_slot(strvec, i);
		str1 = strvec_slot(strvec, i + 1);

		if (!strcmp(str, "id")) {
			if (get_u64(&encap->ip.id, str1, UINT64_MAX, "encap id %s value is invalid"))
				goto err;
			encap->flags |= IPROUTE_BIT_ENCAP_ID;
		} else if (!strcmp(str, "dst")) {
			if (encap->ip.dst)
				FREE_PTR(encap->ip.dst);
			encap->ip.dst = parse_ipaddress(NULL, str1, false);
			if (!encap->ip.dst) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid encap ip dst %s", str1);
				goto err;
			}
			if (encap->ip.dst->ifa.ifa_family != AF_INET) {
				report_config_error(CONFIG_GENERAL_ERROR, "IPv6 address %s not valid for ip encapsulation", str1);
				goto err;
			}
		} else if (!strcmp(str, "src")) {
			if (encap->ip.src)
				FREE_PTR(encap->ip.src);
			encap->ip.src = parse_ipaddress(NULL, str1, false);
			if (!encap->ip.src) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid encap ip src %s", str1);
				goto err;
			}
			if (encap->ip.src->ifa.ifa_family != AF_INET) {
				report_config_error(CONFIG_GENERAL_ERROR, "IPv6 address %s not valid for ip encapsulation", str1);
				goto err;
			}
		} else if (!strcmp(str, "tos")) {
			if (!find_rttables_dsfield(str1, &encap->ip.tos)) {
				report_config_error(CONFIG_GENERAL_ERROR, "dsfield %s not valid for ip encapsulation", str1);
				goto err;
			}
			encap->flags |= IPROUTE_BIT_ENCAP_DSFIELD;
		} else if (!strcmp(str, "ttl")) {
			if (get_u8(&encap->ip.ttl, str1, UINT8_MAX, "ttl %s is not valid for ip encapsulation"))
				goto err;
			encap->flags |= IPROUTE_BIT_ENCAP_TTL;
		} else if (!strcmp(str, "flags")) {
			if (get_u16(&encap->ip.flags, str1, UINT16_MAX, "flags %s is not valid for ip encapsulation"))
				goto err;
			encap->flags |= IPROUTE_BIT_ENCAP_FLAGS;
		} else
			break;

		i += 2;
	}

	if (!encap->ip.dst && !(encap->flags & IPROUTE_BIT_ENCAP_ID)) {
		report_config_error(CONFIG_GENERAL_ERROR, "address or id missing for ip encapsulation");
		goto err;
	}

	*i_ptr = i;

	return false;

err:
	*i_ptr = i;

	if (encap->ip.dst) {
		FREE_PTR(encap->ip.dst);
		encap->ip.dst = NULL;
	}
	if (encap->ip.src){
		FREE_PTR(encap->ip.src);
		encap->ip.src = NULL;
	}

	return true;
}

#if HAVE_DECL_LWTUNNEL_ENCAP_ILA
static
int parse_encap_ila(const vector_t *strvec, unsigned int *i_ptr, encap_t *encap)
{
	const char *str;

	encap->type = LWTUNNEL_ENCAP_ILA;

	if (*i_ptr >= vector_size(strvec)) {
		report_config_error(CONFIG_GENERAL_ERROR, "missing locator for ILA encapsulation");
		return true;
	}

	str = strvec_slot(strvec, (*i_ptr)++);

	if (get_addr64(&encap->ila.locator, str)) {
		report_config_error(CONFIG_GENERAL_ERROR, "invalid locator %s for ila encapsulation", str);
		return true;
	}

	return false;
}
#endif

static
int parse_encap_ip6(const vector_t *strvec, unsigned int *i_ptr, encap_t *encap)
{
	unsigned int i = *i_ptr;
	const char *str, *str1;

	encap->type = LWTUNNEL_ENCAP_IP6;

	while (i + 1 < vector_size(strvec)) {
		str = strvec_slot(strvec, i);
		str1 = strvec_slot(strvec, i + 1);

		if (!strcmp(str, "id")) {
			if (get_u64(&encap->ip6.id, str1, UINT64_MAX, "id %s value invalid for IPv6 encapsulation"))
				goto err;
			encap->flags |= IPROUTE_BIT_ENCAP_ID;
		} else if (!strcmp(str, "dst")) {
			if (encap->ip6.dst)
				FREE_PTR(encap->ip6.dst);
			encap->ip6.dst = parse_ipaddress(NULL, str1, false);
			if (!encap->ip6.dst) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid encap ip6 dst %s", str1);
				goto err;
			}
			if (encap->ip6.dst->ifa.ifa_family != AF_INET6) {
				report_config_error(CONFIG_GENERAL_ERROR, "IPv4 address %s not valid for ip6 encapsulation", str1);
				goto err;
			}
		} else if (!strcmp(str, "src")) {
			if (encap->ip6.src)
				FREE_PTR(encap->ip6.src);
			encap->ip6.src = parse_ipaddress(NULL, str1, false);
			if (!encap->ip6.src) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid encap ip6 src %s", str1);
				goto err;
			}
			if (encap->ip6.src->ifa.ifa_family != AF_INET6) {
				report_config_error(CONFIG_GENERAL_ERROR, "IPv4 address %s not valid for ip6 encapsulation", str1);
				goto err;
			}
		} else if (!strcmp(str, "tc")) {
			if (!find_rttables_dsfield(str1, &encap->ip6.tc)) {
				report_config_error(CONFIG_GENERAL_ERROR, "tc value %s is invalid for ip6 encapsulation", str);
				goto err;
			}
			encap->flags |= IPROUTE_BIT_ENCAP_DSFIELD;
		} else if (!strcmp(str, "hoplimit")) {
			if (get_u8(&encap->ip6.hoplimit, str1, UINT8_MAX, "Invalid hoplimit %s specified for ip6 encapsulation"))
				goto err;
			encap->flags |= IPROUTE_BIT_ENCAP_HOPLIMIT;
		} else if (!strcmp(str, "flags")) {
			if (get_u16(&encap->ip6.flags, str1, UINT16_MAX, "flags %s is not valid for ip6 encapsulation"))
				goto err;
			encap->flags |= IPROUTE_BIT_ENCAP_FLAGS;
		} else
			break;

		i += 2;
	}

	if (!encap->ip.dst && !(encap->flags & IPROUTE_BIT_ENCAP_ID)) {
		report_config_error(CONFIG_GENERAL_ERROR, "address or id missing for ip6 encapsulation");
		goto err;
	}

	*i_ptr = i;
	return false;

err:
	*i_ptr = i;
	if (encap->ip6.dst) {
		FREE_PTR(encap->ip6.dst);
		encap->ip6.dst = NULL;
	}
	if (encap->ip6.src) {
		FREE_PTR(encap->ip6.src);
		encap->ip6.src = NULL;
	}

	return true;
}

static bool
parse_encap(const vector_t *strvec, unsigned int *i, encap_t *encap)
{
	const char *str;

	if (vector_size(strvec) <= ++*i) {
		report_config_error(CONFIG_GENERAL_ERROR, "Missing encap type");
		return false;
	}

	str = strvec_slot(strvec, (*i)++);

	if (!strcmp(str, "ip"))
		parse_encap_ip(strvec, i, encap);
	else if (!strcmp(str, "ip6"))
		parse_encap_ip6(strvec, i, encap);
#if HAVE_DECL_LWTUNNEL_ENCAP_MPLS
	else if (!strcmp(str, "mpls"))
		parse_encap_mpls(strvec, i, encap);
#endif
#if HAVE_DECL_LWTUNNEL_ENCAP_ILA
	else if (!strcmp(str, "ila"))
		parse_encap_ila(strvec, i, encap);
#endif
	else {
		report_config_error(CONFIG_GENERAL_ERROR, "Unknown encap type - %s", str);
		return false;
	}

	--*i;
	return true;
}
#endif

static void
parse_nexthops(const vector_t *strvec, unsigned int i, ip_route_t *route)
{
	uint8_t family = AF_UNSPEC;
	nexthop_t *new;
	const char *str;
	uint32_t val;

	while (i < vector_size(strvec) && !strcmp("nexthop", strvec_slot(strvec, i))) {
		i++;
		new = MALLOC(sizeof(nexthop_t));
		INIT_LIST_HEAD(&new->e_list);

		while (i < vector_size(strvec)) {
			str = strvec_slot(strvec, i);

			if (!strcmp(str, "via")) {
				str = strvec_slot(strvec, ++i);
				if (!strcmp(str, "inet")) {
					family = AF_INET;
					str = strvec_slot(strvec, ++i);
				}
				else if (!strcmp(str, "inet6")) {
					family = AF_INET6;
					str = strvec_slot(strvec, ++i);
				}

				if (family != AF_UNSPEC) {
					if (route->family == AF_UNSPEC)
						route->family = family;
					else if (route->family != family) {
						report_config_error(CONFIG_GENERAL_ERROR, "IPv4/6 mismatch for nexthop");
						goto err;
					}
				}

				new->addr = parse_ipaddress(NULL, str, false);
				if (!new->addr) {
					report_config_error(CONFIG_GENERAL_ERROR, "invalid nexthop address %s", str);
					goto err;
				}
				if (route->family != AF_UNSPEC && new->addr->ifa.ifa_family != route->family) {
					report_config_error(CONFIG_GENERAL_ERROR, "Address family mismatch for next hop");
					goto err;
				}
				if (route->family == AF_UNSPEC)
					route->family = new->addr->ifa.ifa_family;
			}
			else if (!strcmp(str, "dev")) {
				str = strvec_slot(strvec, ++i);
				new->ifp = if_get_by_ifname(str, IF_CREATE_IF_DYNAMIC);
				if (!new->ifp) {
					report_config_error(CONFIG_GENERAL_ERROR, "WARNING - interface %s for VROUTE nexthop doesn't exist", str);
					goto err;
				}
			}
			else if (!strcmp(str, "weight")) {
				if (get_u32(&val, strvec_slot(strvec, ++i), 256, "Invalid weight %s specified for route"))
					goto err;
				if (!val) {
					report_config_error(CONFIG_GENERAL_ERROR, "Invalid weight 0 specified for route");
					goto err;
				}
				new->weight = (uint8_t)(--val & 0xff);
				new->mask |= IPROUTE_BIT_WEIGHT;
			}
			else if (!strcmp(str, "onlink")) {
				/* Note: IPv4 only */
				new->flags |= RTNH_F_ONLINK;
			}
			else if (!strcmp(str, "encap")) {	// New in 4.4
#if HAVE_DECL_RTA_ENCAP
				parse_encap(strvec, &i, &new->encap);
#else
				report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "encap");
#endif
			}
			else if (!strcmp(str, "realms")) {
				/* Note: IPv4 only */
				if (get_realms(&new->realms, strvec_slot(strvec, ++i))) {
					report_config_error(CONFIG_GENERAL_ERROR, "Invalid realms %s for route", strvec_slot(strvec,i));
					goto err;
				}
				if (route->family == AF_UNSPEC)
					route->family = AF_INET;
				else if (route->family != AF_INET) {
					report_config_error(CONFIG_GENERAL_ERROR, "realms are only supported for IPv4");
					goto err;
				}
			}
			else if (!strcmp(str, "as")) {
				if (!strcmp("to", strvec_slot(strvec, ++i)))
					i++;
				report_config_error(CONFIG_GENERAL_ERROR, "'as [to]' (nat) not supported");
				goto err;
			}
			else
				break;

			i++;
		}

		list_add_tail(&new->e_list, &route->nhs);
		new = NULL;
	}

	if (i < vector_size(strvec)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Route has trailing nonsense after nexthops - %s", strvec_slot(strvec, i));
		goto err;
	}

	return;

err:
	FREE_PTR(new);
}

void
alloc_route(list_head_t *rt_list, const vector_t *strvec, bool allow_track_group)
{
	ip_route_t *new;
	interface_t *ifp;
	const char *str;
	uint32_t val;
	uint8_t val8;
	unsigned int i = 0;
	bool do_nexthop = false;
	bool raw;
	uint8_t family;
	const char *dest = NULL;

	PMALLOC(new);
	if (!new) {
		log_message(LOG_INFO, "Unable to allocate new ip_route");
		return;
	}
	INIT_LIST_HEAD(&new->e_list);
	INIT_LIST_HEAD(&new->nhs);

	new->table = RT_TABLE_MAIN;
	new->scope = RT_SCOPE_UNIVERSE;
	new->type = RTN_UNICAST;
	new->family = AF_UNSPEC;

	/* FMT parse */
	while (i < vector_size(strvec)) {
		str = strvec_slot(strvec, i);

		/* cmd parsing */
		if (!strcmp(str, "inet6")) {
			if (new->family == AF_UNSPEC)
				new->family = AF_INET6;
			else if (new->family != AF_INET6) {
				report_config_error(CONFIG_GENERAL_ERROR, "inet6 specified for IPv4 route");
				goto err;
			}
			i++;
		}
		else if (!strcmp(str, "inet")) {
			if (new->family == AF_UNSPEC)
				new->family = AF_INET;
			else if (new->family != AF_INET) {
				report_config_error(CONFIG_GENERAL_ERROR, "inet specified for IPv6 route");
				goto err;
			}
			i++;
		}
		else if (!strcmp(str, "src")) {
			if (new->pref_src)
				FREE(new->pref_src);
			new->pref_src = parse_ipaddress(NULL, strvec_slot(strvec, ++i), false);
			if (!new->pref_src) {
				report_config_error(CONFIG_GENERAL_ERROR, "invalid route src address %s", strvec_slot(strvec, i));
				goto err;
			}
			if (new->family == AF_UNSPEC)
				new->family = new->pref_src->ifa.ifa_family;
			else if (new->family != new->pref_src->ifa.ifa_family) {
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot mix IPv4 and IPv6 addresses for route");
				goto err;
			}
		}
		else if (!strcmp(str, "as")) {
			if (!strcmp("to", strvec_slot(strvec, ++i)))
				i++;
#if HAVE_DECL_RTA_NEWDST
			report_config_error(CONFIG_GENERAL_ERROR, "\"as to\" for MPLS only - ignoring");
#else
			report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "'as [to]'");
#endif
		}
		else if (!strcmp(str, "via") || !strcmp(str, "gw")) {

			/* "gw" maintained for backward keepalived compatibility */
			if (str[0] == 'g')	/* "gw" */
				report_config_error(CONFIG_GENERAL_ERROR, "\"gw\" for routes is deprecated. Please use \"via\"");

			str = strvec_slot(strvec, ++i);
			if (!strcmp(str, "inet")) {
				family = AF_INET;
				str = strvec_slot(strvec, ++i);
			}
			else if (!strcmp(str, "inet6")) {
				family = AF_INET6;
				str = strvec_slot(strvec, ++i);
			}
			else
				family = new->family;

			if (new->family == AF_UNSPEC)
				new->family = family;
			else if (new->family != family) {
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot mix IPv4 and IPv6 addresses for route");
				goto err;
			}

			if (new->via)
				FREE(new->via);
			new->via = parse_ipaddress(NULL, str, false);
			if (!new->via) {
				report_config_error(CONFIG_GENERAL_ERROR, "invalid route via address %s", strvec_slot(strvec, i));
				goto err;
			}
			if (new->family == AF_UNSPEC)
				new->family = new->via->ifa.ifa_family;
			else if (new->family != new->via->ifa.ifa_family) {
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot mix IPv4 and IPv6 addresses for route");
				goto err;
			}
		}
		else if (!strcmp(str, "from")) {
			if (new->src)
				FREE(new->src);
			new->src = parse_route(strvec_slot(strvec, ++i));
			if (!new->src) {
				report_config_error(CONFIG_GENERAL_ERROR, "invalid route from address %s", strvec_slot(strvec, i));
				goto err;
			}
			if (new->src->ifa.ifa_family != AF_INET6) {
				report_config_error(CONFIG_GENERAL_ERROR, "route from address only supported with IPv6 (%s)", strvec_slot(strvec, i));
				goto err;
			}
			if (new->family == AF_UNSPEC)
				new->family = new->src->ifa.ifa_family;
			else if (new->family != new->src->ifa.ifa_family) {
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot mix IPv4 and IPv6 addresses for route");
				goto err;
			}
		}
		else if (!strcmp(str, "tos") || !strcmp(str,"dsfield")) {
			/* Note: IPv4 only */
			if (!find_rttables_dsfield(strvec_slot(strvec, ++i), &val8)) {
				report_config_error(CONFIG_GENERAL_ERROR, "TOS value %s is invalid", strvec_slot(strvec, i));
				goto err;
			}

			new->tos = val8;
			new->mask |= IPROUTE_BIT_DSFIELD;
		}
		else if (!strcmp(str, "table")) {
			if (!find_rttables_table(strvec_slot(strvec, ++i), &val)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Routing table %s not found for route", strvec_slot(strvec, i));
				goto err;
			}
			new->table = val;
		}
		else if (!strcmp(str, "protocol")) {
			if (!find_rttables_proto(strvec_slot(strvec, ++i), &val8)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Protocol %s not found or invalid for route", strvec_slot(strvec, i));
				goto err;
			}
			new->protocol = val8;
			new->mask |= IPROUTE_BIT_PROTOCOL;
		}
		else if (!strcmp(str, "scope")) {
			/* Note: IPv4 only */
			if (!find_rttables_scope(strvec_slot(strvec, ++i), &val8)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Scope %s not found or invalid for route", strvec_slot(strvec, i));
				goto err;
			}
			new->scope = val8;
			new->mask |= IPROUTE_BIT_SCOPE;
		}
		else if (!strcmp(str, "metric") ||
			 !strcmp(str, "priority") ||
			 !strcmp(str, "preference")) {
			if (get_u32(&new->metric, strvec_slot(strvec, ++i), UINT32_MAX, "Invalid metric %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_METRIC;
		}
		else if (!strcmp(str, "dev") || !strcmp(str, "oif")) {
			str = strvec_slot(strvec, ++i);
			ifp = if_get_by_ifname(str, IF_CREATE_IF_DYNAMIC);
			if (!ifp) {
				report_config_error(CONFIG_GENERAL_ERROR, "WARNING - interface %s for VROUTE nexthop doesn't exist", str);
				goto err;
			}
			new->oif = ifp;
		}
		else if (!strcmp(str, "onlink")) {
			/* Note: IPv4 only */
			new->flags |= RTNH_F_ONLINK;
		}
		else if (!strcmp(str, "encap")) {	// New in 4.4
#if HAVE_DECL_RTA_ENCAP
			parse_encap(strvec, &i, &new->encap);
#else
			report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "encap");
#endif
		}
		else if (!strcmp(str, "expires")) {	// New in 4.4
			i++;
#if HAVE_DECL_RTA_EXPIRES
			if (new->family == AF_INET) {
				report_config_error(CONFIG_GENERAL_ERROR, "expires is only valid for IPv6");
				goto err;
			}
			new->family = AF_INET6;
			if (get_u32(&new->expires, strvec_slot(strvec, i), UINT32_MAX, "Invalid expires time %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_EXPIRES;
#else
			report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "expires");
#endif
		}
		else if (!strcmp(str, "mtu")) {
			if (!strcmp(strvec_slot(strvec, ++i), "lock")) {
				new->lock |= 1 << RTAX_MTU;
				i++;
			}
			if (get_u32(&new->mtu, strvec_slot(strvec, i), UINT32_MAX, "Invalid MTU %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_MTU;
		}
		else if (!strcmp(str, "hoplimit")) {
			if (get_u8(&val8, strvec_slot(strvec, ++i), 255, "Invalid hoplimit %s specified for route"))
				goto err;
			new->hoplimit = val8;
			new->mask |= IPROUTE_BIT_HOPLIMIT;
		}
		else if (!strcmp(str, "advmss")) {
			if (!strcmp(strvec_slot(strvec, ++i), "lock")) {
				new->lock |= 1 << RTAX_ADVMSS;
				i++;
			}
			if (get_u32(&new->advmss, strvec_slot(strvec, i), UINT32_MAX, "Invalid advmss %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_ADVMSS;
		}
		else if (!strcmp(str, "rtt")) {
			if (!strcmp(strvec_slot(strvec, ++i), "lock")) {
				new->lock |= 1 << RTAX_RTT;
				i++;
			}
			if (get_time_rtt(&new->rtt, strvec_slot(strvec, i), &raw) ||
			    (!raw && new->rtt >= UINT32_MAX / 8)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid rtt %s for route", strvec_slot(strvec,i));
				goto err;
			}
			if (raw)
				new->rtt *= 8;
			new->mask |= IPROUTE_BIT_RTT;
		}
		else if (!strcmp(str, "rttvar")) {
			if (!strcmp(strvec_slot(strvec, ++i), "lock")) {
				new->lock |= 1 << RTAX_RTTVAR;
				i++;
			}
			if (get_time_rtt(&new->rttvar, strvec_slot(strvec, i), &raw) ||
			    (!raw && new->rttvar >= UINT32_MAX / 4)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid rttvar %s for route", strvec_slot(strvec,i));
				goto err;
			}
			if (raw)
				new->rttvar *= 4;
			new->mask |= IPROUTE_BIT_RTTVAR;
		}
		else if (!strcmp(str, "reordering")) {
			if (!strcmp(strvec_slot(strvec, ++i), "lock")) {
				new->lock |= 1 << RTAX_REORDERING;
				i++;
			}
			if (get_u32(&new->reordering, strvec_slot(strvec, i), UINT32_MAX, "Invalid reordering value %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_REORDERING;
		}
		else if (!strcmp(str, "window")) {
			if (get_u32(&new->window, strvec_slot(strvec, ++i), UINT32_MAX, "Invalid window value %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_WINDOW;
		}
		else if (!strcmp(str, "cwnd")) {
			if (!strcmp(strvec_slot(strvec, ++i), "lock")) {
				new->lock |= 1 << RTAX_CWND;
				i++;
			}
			if (get_u32(&new->cwnd, strvec_slot(strvec, i), UINT32_MAX, "Invalid cwnd value %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_CWND;
		}
		else if (!strcmp(str, "ssthresh")) {
			if (!strcmp(strvec_slot(strvec, ++i), "lock")) {
				new->lock |= 1 << RTAX_SSTHRESH;
				i++;
			}
			if (get_u32(&new->ssthresh, strvec_slot(strvec, i), UINT32_MAX, "Invalid ssthresh value %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_SSTHRESH;
		}
		else if (!strcmp(str, "realms")) {
			if (get_realms(&new->realms, strvec_slot(strvec, ++i))) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid realms %s for route", strvec_slot(strvec,i));
				goto err;
			}
			if (new->family == AF_INET6) {
				report_config_error(CONFIG_GENERAL_ERROR, "realms are only valid for IPv4");
				goto err;
			}
			new->family = AF_INET;
		}
		else if (!strcmp(str, "rto_min")) {
			if (!strcmp(strvec_slot(strvec, ++i), "lock")) {
				new->lock |= 1 << RTAX_RTO_MIN;
				i++;
			}
			if (get_time_rtt(&new->rto_min, strvec_slot(strvec, i), &raw)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid rto_min value %s specified for route", strvec_slot(strvec, i));
				goto err;
			}
			new->mask |= IPROUTE_BIT_RTO_MIN;
		}
		else if (!strcmp(str, "initcwnd")) {
			if (get_u32(&new->initcwnd, strvec_slot(strvec, ++i), UINT32_MAX, "Invalid initcwnd value %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_INITCWND;
		}
		else if (!strcmp(str, "initrwnd")) {
			i++;
			if (get_u32(&new->initrwnd, strvec_slot(strvec, i), UINT32_MAX, "Invalid initrwnd value %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_INITRWND;
		}
		else if (!strcmp(str, "features")) {
			i++;
			if (!strcmp("ecn", strvec_slot(strvec, i)))
				new->features |= RTAX_FEATURE_ECN;
			else
				report_config_error(CONFIG_GENERAL_ERROR, "feature %s not supported", strvec_slot(strvec,i));
		}
		else if (!strcmp(str, "quickack")) {
			i++;
#if HAVE_DECL_RTAX_QUICKACK
			if (get_u32(&val, strvec_slot(strvec, i), 1, "Invalid quickack value %s specified for route"))
				goto err;
			new->quickack = val;
			new->mask |= IPROUTE_BIT_QUICKACK;
#else
			report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "quickack for route");
#endif
		}
		else if (!strcmp(str, "congctl")) {
			i++;
#if HAVE_DECL_RTAX_CC_ALGO
			if (!strcmp(strvec_slot(strvec, i), "lock")) {
				new->lock |= 1 << RTAX_CC_ALGO;
				i++;
			}
			str = strvec_slot(strvec, i);
			new->congctl = STRDUP(str);
#else
			report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "congctl for route");
#endif
		}
		else if (!strcmp(str, "pref")) {
			i++;
#if HAVE_DECL_RTA_PREF
			if (new->family == AF_INET) {
				report_config_error(CONFIG_GENERAL_ERROR, "pref is only valid for IPv6");
				goto err;
			}
			new->family = AF_INET6;
			str = strvec_slot(strvec, i);
			if (!strcmp(str, "low"))
				new->pref = ICMPV6_ROUTER_PREF_LOW;
			else if (!strcmp(str, "medium"))
				new->pref = ICMPV6_ROUTER_PREF_MEDIUM;
			else if (!strcmp(str, "high"))
				new->pref = ICMPV6_ROUTER_PREF_HIGH;
			else if (!get_u8(&val8, str, UINT8_MAX, "Invalid pref value %s specified for route"))
				new->pref = val8;
			else
				goto err;
			new->mask |= IPROUTE_BIT_PREF;
#else
			report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "pref");
#endif
		}
		else if (!strcmp(str, "ttl-propagate")) {
			i++;
#if HAVE_DECL_RTA_TTL_PROPAGATE
			str = strvec_slot(strvec, i);
			if (!strcmp(str, "enabled"))
				new->ttl_propagate = 1;
			else if (!strcmp(str, "disabled"))
				new->ttl_propagate = 0;
			else
				report_config_error(CONFIG_GENERAL_ERROR, "%s value %s not recognised", "ttl-propagate", str);
			new->mask |= IPROUTE_BIT_TTL_PROPAGATE;
#else
			report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "ttl-propagate");
#endif
		}
		else if (!strcmp(str, "fastopen_no_cookie")) {
			i++;
#if HAVE_DECL_RTAX_FASTOPEN_NO_COOKIE
			if (get_u32(&val, strvec_slot(strvec, i), 1, "Invalid fastopen_no_cookie value %s specified for route"))
				goto err;
			new->fastopen_no_cookie = !!val;
			new->mask |= IPROUTE_BIT_FASTOPEN_NO_COOKIE;
#else
			report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "fastopen_no_cookie");
#endif
		}
		/* Maintained for backward compatibility */
		else if (!strcmp(str, "or")) {
			report_config_error(CONFIG_GENERAL_ERROR, "\"or\" for routes is deprecated. Please use \"nexthop\"");

			if (!list_empty(&new->nhs)) {
				report_config_error(CONFIG_GENERAL_ERROR, "\"or\" route already specified - ignoring subsequent");
				i += 2;
				continue;
			}

			/* Transfer the via address to the first nexthop */
			nexthop_t *nh = MALLOC(sizeof(nexthop_t));
			INIT_LIST_HEAD(&nh->e_list);
			nh->addr = new->via;
			new->via = NULL;
			list_add_tail(&nh->e_list, &new->nhs);

			/* Now handle the "or" address */
			nh = MALLOC(sizeof(nexthop_t));
			INIT_LIST_HEAD(&nh->e_list);
			nh->addr = parse_ipaddress(NULL, strvec_slot(strvec, ++i), false);
			if (!nh->addr) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid \"or\" address %s"
									, strvec_slot(strvec, i));
				FREE(nh);
				goto err;
			}
			list_add_tail(&nh->e_list, &new->nhs);
		}
		else if (!strcmp(str, "nexthop")) {
			if (!list_empty(&new->nhs))
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify nexthops with \"or\" route");
			else
				do_nexthop = true;
			break;
		}
		else if (!strcmp(str, "no_track"))
			new->dont_track = true;
		else if (allow_track_group && !strcmp(str, "track_group")) {
			i++;
			if (new->track_group) {
				report_config_error(CONFIG_GENERAL_ERROR, "track_group %s is a duplicate", strvec_slot(strvec, i));
				break;
			}
			if (!(new->track_group = static_track_group_find(strvec_slot(strvec, i))))
				report_config_error(CONFIG_GENERAL_ERROR, "track_group %s not found", strvec_slot(strvec, i));
		}
		else {
			if (!strcmp(str, "to"))
				i++;

			if (find_rttables_rtntype(str, &val8)) {
				new->type = val8;
				new->mask |= IPROUTE_BIT_TYPE;
				i++;
			}
			if (new->dst)
				FREE(new->dst);
			dest = strvec_slot(strvec, i);
			new->dst = parse_route(dest);
			if (!new->dst) {
				report_config_error(CONFIG_GENERAL_ERROR, "unknown route keyword %s", dest);
				goto err;
			}
			if (new->family == AF_UNSPEC)
				new->family = new->dst->ifa.ifa_family;
			else if (new->family != new->dst->ifa.ifa_family) {
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot mix IPv4 and IPv6 addresses for route (%s)", dest);
				goto err;
			}
		}
		i++;
	}

	if (do_nexthop)
		parse_nexthops(strvec, i, new);
	else if (i < vector_size(strvec)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Route has trailing nonsense - %s", strvec_slot(strvec, i));
		goto err;
	}

	if (!new->dst) {
		report_config_error(CONFIG_GENERAL_ERROR, "Route must have a destination");
		goto err;
	}

	if (!new->dont_track) {
		if ((new->mask & IPROUTE_BIT_PROTOCOL) && new->protocol != RTPROT_KEEPALIVED)
			report_config_error(CONFIG_GENERAL_ERROR, "Route cannot be tracked if protocol is not RTPROT_KEEPALIVED(%d), resetting protocol", RTPROT_KEEPALIVED);
		new->protocol = RTPROT_KEEPALIVED;
		new->mask |= IPROUTE_BIT_PROTOCOL;

		if (!new->oif) {
			/* Alternative is to track oif from when route last added.
			 * The interface will need to be added temporarily. tracking_obj_t will need
			 * a flag to specify permanent track, and a counter for number of temporary
			 * trackers. If the termporary tracker count becomes 0 and there is no permanent
			 * track, then the tracking_obj_t will need to be removed.
			 *
			 * We also have a problem if using nexthop, since the route will only be deleted
			 * when the interfaces for all of the hops have gone down. We would need to track
			 * all of the interfaces being used, and only mark the route as down if all the
			 * interfaces are down. */
			report_config_error(CONFIG_GENERAL_ERROR, "Warning - cannot track route %s with no interface specified, not tracking", dest);
			new->dont_track = true;
		}
	}

	if (new->track_group && !new->oif) {
		report_config_error(CONFIG_GENERAL_ERROR, "Static route cannot have track group if no oif specified");
		new->track_group = NULL;
	}

	/* Check that family is set */
	if (new->family == AF_UNSPEC)
		new->family = AF_INET;
	if (new->dst->ifa.ifa_family == AF_UNSPEC)
		new->dst->ifa.ifa_family = new->family;
	if (new->src && new->src->ifa.ifa_family == AF_UNSPEC)
		new->src->ifa.ifa_family = new->family;

	list_add_tail(&new->e_list, rt_list);
	return;

err:
	free_iproute(new);
}

static bool __attribute__ ((pure))
compare_nexthops(const list_head_t *a, const list_head_t *b)
{
	nexthop_t *nh_a;
	nexthop_t *nh_b;

	if (list_empty(a) != list_empty(b))
		return false;

	if (list_empty(a))
		return true;

	nh_b = list_first_entry(b, nexthop_t, e_list);
	list_for_each_entry(nh_a, a, e_list) {
		if (list_is_last(&nh_a->e_list, a) != list_is_last(&nh_b->e_list, b))
			return false;

		/* Do some comparisons */
		if (nh_a->mask != nh_b->mask ||
		    compare_ipaddress(nh_a->addr, nh_b->addr) ||
		    nh_a->ifp != nh_b->ifp ||
		    nh_a->weight != nh_b->weight ||
		    nh_a->flags != nh_b->flags ||
		    nh_a->realms != nh_b->realms)
			return false;

#if HAVE_DECL_RTA_ENCAP
		if (nh_a->encap.type != nh_b->encap.type ||
		    nh_a->encap.flags != nh_b->encap.flags)
			return false;

		if (nh_a->encap.type == LWTUNNEL_ENCAP_NONE) {
			/* Don't keep checking encap type if none */
		}
		else if (nh_a->encap.type == LWTUNNEL_ENCAP_IP) {
			if (nh_a->encap.ip.id != nh_b->encap.ip.id ||
			    compare_ipaddress(nh_a->encap.ip.dst, nh_b->encap.ip.dst) ||
			    compare_ipaddress(nh_a->encap.ip.src, nh_b->encap.ip.src) ||
			    nh_a->encap.ip.tos != nh_b->encap.ip.tos ||
			    nh_a->encap.ip.flags != nh_b->encap.ip.flags ||
			    nh_a->encap.ip.ttl != nh_b->encap.ip.ttl)
				return false;
		}
		else if (nh_a->encap.type == LWTUNNEL_ENCAP_IP6) {
			if (nh_a->encap.ip6.id != nh_b->encap.ip6.id ||
			    compare_ipaddress(nh_a->encap.ip6.dst, nh_b->encap.ip6.dst) ||
			    compare_ipaddress(nh_a->encap.ip6.src, nh_b->encap.ip6.src) ||
			    nh_a->encap.ip6.tc != nh_b->encap.ip6.tc ||
			    nh_a->encap.ip6.flags != nh_b->encap.ip6.flags ||
			    nh_a->encap.ip6.hoplimit != nh_b->encap.ip6.hoplimit)
				return false;
		}
#if HAVE_DECL_LWTUNNEL_ENCAP_ILA
		else if (nh_a->encap.type == LWTUNNEL_ENCAP_ILA) {
			if (nh_a->encap.ila.locator |= nh_b->encap.ila.locator)
				return false;
		}
#endif
#if HAVE_DECL_LWTUNNEL_ENCAP_MPLS
		else if (nh_a->encap.type == LWTUNNEL_ENCAP_MPLS) {
			size_t label;

			if (nh_a->encap.mpls.num_labels != nh_b->encap.mpls.num_labels)
				return false;
			for (label = 0; label < nh_a->encap.mpls.num_labels; label++) {
				if (nh_a->encap.mpls.addr[label].entry != nh_b->encap.mpls.addr[label].entry)
					return false;
			}
		}
#endif
#endif

		if (list_is_last(&nh_b->e_list, b))
			return true;

		nh_b = list_first_entry(&nh_b->e_list, nexthop_t, e_list);
	}

	/* NOT REACHED */
	return false;
}

/* Try to find a route in a list */
static ip_route_t *
route_exist(list_head_t *l, ip_route_t *route)
{
	ip_route_t *ip_route;

	list_for_each_entry(ip_route, l, e_list) {
		/* The kernel's key to a route is (to, tos, preference, table),
		 * but since we don't specify NLM_F_EXCL when adding a route we
		 * also need to check via/nexthops, scope and type. */
		if (!compare_ipaddress(ip_route->dst, route->dst) &&
		    ip_route->dst->ifa.ifa_prefixlen == route->dst->ifa.ifa_prefixlen &&
		    ip_route->tos == route->tos &&
		    (!((ip_route->mask ^ route->mask) & IPROUTE_BIT_METRIC)) &&
		    (!(ip_route->mask & IPROUTE_BIT_METRIC) ||
		     ip_route->metric == route->metric) &&
		    ip_route->table == route->table &&
		    ip_route->scope == route->scope &&
		    ip_route->type == route->type &&
		    !ip_route->via == !route->via &&
		    (!ip_route->via || !compare_ipaddress(ip_route->via, route->via)) &&
		    ip_route->oif == route->oif &&
		    compare_nexthops(&ip_route->nhs, &route->nhs)) {
			ip_route->set = route->set;
			return ip_route;
		}
	}
	return NULL;
}

/* Clear diff routes */
void
clear_diff_routes(list_head_t *l, list_head_t *n)
{
	ip_route_t *route, *new_route;

	/* No route in previous conf */
	if (list_empty(l))
		return;

	/* All routes removed */
	if (list_empty(n)) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "Removing a VirtualRoute block");
		netlink_rtlist(l, IPROUTE_DEL, false);
		return;
	}

	list_for_each_entry(route, l, e_list) {
		if (route->set) {
			if (!(new_route = route_exist(n, route))) {
				if (__test_bit(LOG_DETAIL_BIT, &debug))
					log_message(LOG_INFO, "Removing route %s"
							    , ipaddresstos(NULL, route->dst));
				netlink_route(route, IPROUTE_DEL);
				continue;
			}

			/* There are too many route options to compare to see if the
			 * routes are the same or not, so just replace the existing route
			 * with the new one.
			 * We try replacing the route, but if, for example, it has a src
			 * address that is a new VIP, then the route won't be able to be
			 * added (replaced) now. In this case delete the old route, mark
			 * it as not set, and then it will be added later when any new
			 * routes are added. */
			netlink_error_ignore = EINVAL;
			if (netlink_route(new_route, IPROUTE_REPLACE)) {
				netlink_error_ignore = 0;
				netlink_route(route, IPROUTE_DEL);
				new_route->set = false;
			} else
				netlink_error_ignore = 0;
		}
	}
}

/* Diff conf handler */
void
clear_diff_static_routes(void)
{
	clear_diff_routes(&old_vrrp_data->static_routes, &vrrp_data->static_routes);
}

void
reinstate_static_route(ip_route_t *route)
{
	char buf[256];

	route->set = !netlink_route(route, IPROUTE_ADD);

	format_iproute(route, buf, sizeof(buf));
	log_message(LOG_INFO, "Restoring deleted static route %s", buf);
}
