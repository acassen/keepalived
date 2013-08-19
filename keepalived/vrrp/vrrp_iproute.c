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
#include "vrrp_iproute.h"
#include "vrrp_netlink.h"
#include "vrrp_if.h"
#include "vrrp_data.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"

/* Add/Delete IP route to/from a specific interface */
int
netlink_route_ipv4(ip_route_t *iproute, int cmd)
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
	req.r.rtm_family  = AF_INET;
	req.r.rtm_table   = iproute->table ? iproute->table : RT_TABLE_MAIN;
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
	addattr_l(&req.n, sizeof(req), RTA_DST,		&iproute->dst, 4);
	if ((!iproute->blackhole) && (!iproute->gw2))
		addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &iproute->gw,  4);
	if (iproute->gw2) {
		rta->rta_type = RTA_MULTIPATH;
		rta->rta_len = RTA_LENGTH(0);
		rtnh = RTA_DATA(rta);
#define MULTIPATH_ADD_GW(x) \
	memset(rtnh, 0, sizeof(*rtnh)); \
	rtnh->rtnh_len = sizeof(*rtnh); \
	if (iproute->index) rtnh->rtnh_ifindex = iproute->index; \
	rta->rta_len += rtnh->rtnh_len;	\
	rta_addattr_l(rta, 1024, RTA_GATEWAY, x, 4); \
	rtnh->rtnh_len += sizeof(struct rtattr) + 4; \
	rtnh = RTNH_NEXT(rtnh);
		MULTIPATH_ADD_GW(&iproute->gw);
		MULTIPATH_ADD_GW(&iproute->gw2);
		addattr_l(&req.n, sizeof(req), RTA_MULTIPATH, RTA_DATA(rta), RTA_PAYLOAD(rta));
	}
	if ((iproute->index) && (!iproute->gw2))
		addattr32(&req.n, sizeof(req), RTA_OIF, iproute->index);
	if (iproute->src)
		addattr_l(&req.n, sizeof(req), RTA_PREFSRC, &iproute->src, 4);
	if (iproute->metric)
		addattr32(&req.n, sizeof(req), RTA_PRIORITY, iproute->metric);

	if (netlink_talk(&nl_cmd, &req.n) < 0)
		status = -1;
	return status;
}

/* Add/Delete a list of IP routes */
void
netlink_rtlist_ipv4(list rt_list, int cmd)
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
			if (netlink_route_ipv4(iproute, cmd) > 0)
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
	FREE(rt_data);
}
void
dump_iproute(void *rt_data)
{
	ip_route_t *route = rt_data;
	char *log_msg = MALLOC(150);
	char *tmp = MALLOC(30);

	if (route->blackhole) {
		strncat(log_msg, "blackhole ", 30);
	}
	if (route->dst) {
		snprintf(tmp, 30, "%s/%d", inet_ntop2(route->dst), route->dmask);
		strncat(log_msg, tmp, 30);
	}
	if (route->gw) {
		snprintf(tmp, 30, " gw %s", inet_ntop2(route->gw));
		strncat(log_msg, tmp, 30);
	}
	if (route->gw2) {
		snprintf(tmp, 30, " or gw %s", inet_ntop2(route->gw2));
		strncat(log_msg, tmp, 30);
	}
	if (route->src) {
		snprintf(tmp, 30, " src %s", inet_ntop2(route->src));
		strncat(log_msg, tmp, 30);
	}
	if (route->index) {
		snprintf(tmp, 30, " dev %s",
			 IF_NAME(if_get_by_ifindex(route->index)));
		strncat(log_msg, tmp, 30);
	}
	if (route->table) {
		snprintf(tmp, 30, " table %d", route->table);
		strncat(log_msg, tmp, 30);
	}
	if (route->scope) {
		snprintf(tmp, 30, " scope %s",
			 netlink_scope_n2a(route->scope));
		strncat(log_msg, tmp, 30);
	}
	if (route->metric) {
		snprintf(tmp, 30, " metric %d", route->metric);
		strncat(log_msg, tmp, 30);
	}

	log_message(LOG_INFO, "     %s", log_msg);

	FREE(tmp);
	FREE(log_msg);
}
void
alloc_route(list rt_list, vector_t *strvec)
{
	ip_route_t *new;
	uint32_t ipaddr = 0;
	interface_t *ifp;
	char *str;
	int i = 0;

	new = (ip_route_t *) MALLOC(sizeof(ip_route_t));

	/* FMT parse */
	while (i < vector_size(strvec)) {
		str = vector_slot(strvec, i);

		/* cmd parsing */
		if (!strcmp(str, "blackhole")) {
			new->blackhole = 1;
			inet_ston(vector_slot(strvec, ++i), &new->dst);
			new->dmask = inet_stom(vector_slot(strvec, i));
		} else if (!strcmp(str, "via") || !strcmp(str, "gw")) {
			inet_ston(vector_slot(strvec, ++i), &new->gw);
		} else if (!strcmp(str, "or")) {
			inet_ston(vector_slot(strvec, ++i), &new->gw2);
		} else if (!strcmp(str, "src")) {
			inet_ston(vector_slot(strvec, ++i), &new->src);
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
			new->table = atoi(vector_slot(strvec, ++i));
		} else if (!strcmp(str, "metric")) {
			new->metric = atoi(vector_slot(strvec, ++i));
		} else if (!strcmp(str, "scope")) {
			new->scope = netlink_scope_a2n(vector_slot(strvec, ++i));
		} else {
			if (!strcmp(str, "to")) i++;
			if (inet_ston(vector_slot(strvec, i), &ipaddr)) {
				inet_ston(vector_slot(strvec, i), &new->dst);
				new->dmask = inet_stom(vector_slot(strvec, i));
			}
		}
		i++;
	}

	list_add(rt_list, new);
}

/* Try to find a route in a list */
int
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
		netlink_rtlist_ipv4(l, IPROUTE_DEL);
		return;
	}

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		iproute = ELEMENT_DATA(e);
		if (!route_exist(n, iproute) && iproute->set) {
			log_message(LOG_INFO, "ip route %s/%d ... , no longer exist"
			       , inet_ntop2(iproute->dst), iproute->dmask);
			netlink_route_ipv4(iproute, IPROUTE_DEL);
		}
	}
}

/* Diff conf handler */
void
clear_diff_sroutes(void)
{
	clear_diff_routes(old_vrrp_data->static_routes, vrrp_data->static_routes);
}
