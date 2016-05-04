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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

/* local include */
#include "vrrp_ipaddress.h"
#include "vrrp_iproute.h"
#include "vrrp_netlink.h"
#include "vrrp_if.h"
#include "vrrp_data.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "rttables.h"

/* Utility functions */
static int
add_addr2req(struct nlmsghdr *n, int maxlen, int type, ip_address_t *ip_address)
{
	void *addr;
	int alen;

	if (!ip_address)
		return -1;

	addr = (IP_IS6(ip_address)) ? (void *) &ip_address->u.sin6_addr :
				     (void *) &ip_address->u.sin.sin_addr;
	alen = (IP_IS6(ip_address)) ? sizeof(ip_address->u.sin6_addr) :
				     sizeof(ip_address->u.sin.sin_addr);

	return addattr_l(n, maxlen, type, addr, alen);
}

static int
add_addr2rta(struct rtattr *rta, int maxlen, int type, ip_address_t *ip_address)
{
	void *addr;
	int alen;

	if (!ip_address)
		return -1;

	addr = (IP_IS6(ip_address)) ? (void *) &ip_address->u.sin6_addr :
				     (void *) &ip_address->u.sin.sin_addr;
	alen = (IP_IS6(ip_address)) ? sizeof(ip_address->u.sin6_addr) :
				     sizeof(ip_address->u.sin.sin_addr);

	return rta_addattr_l(rta, maxlen, type, addr, alen);
}

/* Add/Delete IP route to/from a specific interface */
static int
netlink_route(ip_route_t *iproute, int cmd)
{
	int status = 1;
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1024];
	} req;

	char buf[1024];
	struct rtattr *rta = (void*)buf;
	struct rtnexthop *rtnh;

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	req.n.nlmsg_type  = cmd ? RTM_NEWROUTE : RTM_DELROUTE;
	req.r.rtm_family  = IP_FAMILY(iproute->dst);
	if (iproute->table < 256)
		req.r.rtm_table   = iproute->table ? iproute->table : RT_TABLE_MAIN;
	else {
		req.r.rtm_table = RT_TABLE_UNSPEC;
		addattr32(&req.n, sizeof(req), RTA_TABLE, iproute->table);
	}
	req.r.rtm_scope   = RT_SCOPE_NOWHERE;

	if (cmd) {
		req.r.rtm_protocol = RTPROT_BOOT;
		req.r.rtm_scope = iproute->scope;
		req.r.rtm_type = RTN_UNICAST;
	}
	if (iproute->blackhole)
		req.r.rtm_type = RTN_BLACKHOLE;

	/* Set routing entry */
	req.r.rtm_dst_len = iproute->dmask;
	add_addr2req(&req.n, sizeof(req), RTA_DST, iproute->dst);
	if ((!iproute->blackhole) && (!iproute->gw2))
		add_addr2req(&req.n, sizeof(req), RTA_GATEWAY, iproute->gw);
	if (iproute->gw2) {
		rta->rta_type = RTA_MULTIPATH;
		rta->rta_len = RTA_LENGTH(0);
		rtnh = RTA_DATA(rta);
#define MULTIPATH_ADD_GW(x) \
	memset(rtnh, 0, sizeof(*rtnh)); \
	rtnh->rtnh_len = sizeof(*rtnh); \
	if (iproute->index) rtnh->rtnh_ifindex = iproute->index; \
	rta->rta_len += rtnh->rtnh_len;	\
	add_addr2rta(rta, 1024, RTA_GATEWAY, x); \
	rtnh->rtnh_len += sizeof(struct rtattr) + IP_SIZE(x); \
	rtnh = RTNH_NEXT(rtnh);
		MULTIPATH_ADD_GW(iproute->gw);
		MULTIPATH_ADD_GW(iproute->gw2);
		addattr_l(&req.n, sizeof(req), RTA_MULTIPATH, RTA_DATA(rta), RTA_PAYLOAD(rta));
	}
	if ((iproute->index) && (!iproute->gw2))
		addattr32(&req.n, sizeof(req), RTA_OIF, iproute->index);
	if (iproute->src)
		add_addr2req(&req.n, sizeof(req), RTA_PREFSRC, iproute->src);
	if (iproute->metric)
		addattr32(&req.n, sizeof(req), RTA_PRIORITY, iproute->metric);

	/* This returns ESRCH if the address of via address doesn't exist */
	/* ENETDOWN if dev p33p1.40 for example is down */
	if (netlink_talk(&nl_cmd, &req.n) < 0)
		status = -1;
	return status;
}

/* Add/Delete a list of IP routes */
void
netlink_rtlist(list rt_list, int cmd)
{
	ip_route_t *iproute;
	element e;

	/* No routes to add */
	if (LIST_ISEMPTY(rt_list))
		return;

	for (e = LIST_HEAD(rt_list); e; ELEMENT_NEXT(e)) {
		iproute = ELEMENT_DATA(e);
		if ((cmd && !iproute->set) ||
		    (!cmd && iproute->set)) {
			if (netlink_route(iproute, cmd) > 0)
				iproute->set = (cmd) ? 1 : 0;
			else
				iproute->set = 0;
		}
	}
}

/* Route dump/allocation */
void
free_iproute(void *rt_data)
{
	ip_route_t *route = rt_data;

	FREE_PTR(route->dst);
	FREE_PTR(route->src);
	FREE_PTR(route->gw);
	FREE_PTR(route->gw2);
	FREE(rt_data);
}
void
dump_iproute(void *rt_data)
{
	ip_route_t *route = rt_data;
	char *log_msg = MALLOC(1024);
	char *op = log_msg;

	if (route->blackhole) {
		strncat(log_msg, "blackhole ", 30);
	}
	if (route->dst)
		op += snprintf(op, log_msg + 1024 - op, "%s/%d", ipaddresstos(NULL, route->dst), route->dmask);
	if (route->gw)
		op += snprintf(op, log_msg + 1024 - op, " gw %s", ipaddresstos(NULL, route->gw));
	if (route->gw2)
		op += snprintf(op, log_msg + 1024 - op, " or gw %s", ipaddresstos(NULL, route->gw2));
	if (route->src)
		op += snprintf(op, log_msg + 1024 - op, " src %s", ipaddresstos(NULL, route->src));
	if (route->index)
		op += snprintf(op, log_msg + 1024 - op, " dev %s",
			 IF_NAME(if_get_by_ifindex(route->index)));
	if (route->table)
		op += snprintf(op, log_msg + 1024 - op, " table %d", route->table);
	if (route->scope)
		op += snprintf(op, log_msg + 1024 - op, " scope %s",
			 netlink_scope_n2a(route->scope));
	if (route->metric)
		op += snprintf(op, log_msg + 1024 - op, " metric %d", route->metric);

	log_message(LOG_INFO, "     %s", log_msg);

	FREE(log_msg);
}
void
alloc_route(list rt_list, vector_t *strvec)
{
	ip_route_t *new;
	interface_t *ifp;
	char *str;
	unsigned int i = 0;
	unsigned int table_id;

	new = (ip_route_t *) MALLOC(sizeof(ip_route_t));

	/* FMT parse */
	while (i < vector_size(strvec)) {
		str = vector_slot(strvec, i);

		/* cmd parsing */
		if (!strcmp(str, "blackhole")) {
			new->blackhole = 1;
			new->dst = parse_ipaddress(NULL, vector_slot(strvec, ++i), true);
			new->dmask = new->dst->ifa.ifa_prefixlen;
		} else if (!strcmp(str, "via") || !strcmp(str, "gw")) {
			new->gw = parse_ipaddress(NULL, vector_slot(strvec, ++i), false);
		} else if (!strcmp(str, "or")) {
			new->gw2 = parse_ipaddress(NULL, vector_slot(strvec, ++i), false);
		} else if (!strcmp(str, "src")) {
			new->src = parse_ipaddress(NULL, vector_slot(strvec, ++i), false);
		} else if (!strcmp(str, "dev") || !strcmp(str, "oif")) {
			ifp = if_get_by_ifname(vector_slot(strvec, ++i));
			if (!ifp) {
				log_message(LOG_INFO, "VRRP is trying to assign VROUTE to unknown "
				       "%s interface !!! go out and fix your conf !!!",
				       (char *)vector_slot(strvec, i));
				FREE(new);
				return;
			}
			new->index = IF_INDEX(ifp);
		} else if (!strcmp(str, "table")) {
			if (!find_rttables_table(vector_slot(strvec, ++i), &table_id))
				log_message(LOG_INFO, "Routing table %s not found for route"
						    , (char *)vector_slot(strvec, i));
			else
				new->table = table_id;
		} else if (!strcmp(str, "metric")) {
			new->metric = atoi(vector_slot(strvec, ++i));
		} else if (!strcmp(str, "scope")) {
			new->scope = netlink_scope_a2n(vector_slot(strvec, ++i));
		} else {
			if (!strcmp(str, "to")) i++;

			new->dst = parse_ipaddress(NULL, vector_slot(strvec, i), true);
			if (new->dst) {
				new->dmask = new->dst->ifa.ifa_prefixlen;
			}
		}
		i++;
	}

	list_add(rt_list, new);
}

/* Try to find a route in a list */
static int
route_exist(list l, ip_route_t *iproute)
{
	ip_route_t *ipr;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		ipr = ELEMENT_DATA(e);
		if (ROUTE_ISEQ(ipr, iproute)) {
			ipr->set = iproute->set;
			return 1;
		}
	}
	return 0;
}

/* Clear diff routes */
void
clear_diff_routes(list l, list n)
{
	ip_route_t *iproute;
	element e;

	/* No route in previous conf */
	if (LIST_ISEMPTY(l))
		return;

	/* All Static routes removed */
	if (LIST_ISEMPTY(n)) {
		log_message(LOG_INFO, "Removing a VirtualRoute block");
		netlink_rtlist(l, IPROUTE_DEL);
		return;
	}

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		iproute = ELEMENT_DATA(e);
		if (!route_exist(n, iproute) && iproute->set) {
			log_message(LOG_INFO, "ip route %s/%d ... , no longer exist"
					    , ipaddresstos(NULL, iproute->dst), iproute->dmask);
			netlink_route(iproute, IPROUTE_DEL);
		}
	}
}

/* Diff conf handler */
void
clear_diff_sroutes(void)
{
	clear_diff_routes(old_vrrp_data->static_routes, vrrp_data->static_routes);
}
