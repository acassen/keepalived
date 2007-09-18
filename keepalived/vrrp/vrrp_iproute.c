/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK IPv4 routes manipulation.
 *
 * Version:     $Id: vrrp_iproute.c,v 1.1.15 2007/09/15 04:07:41 acassen Exp $
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
 * Copyright (C) 2001-2007 Alexandre Cassen, <acassen@freebox.fr>
 */

/* local include */
#include "vrrp_iproute.h"
#include "vrrp_netlink.h"
#include "vrrp_if.h"
#include "vrrp_data.h"
#include "memory.h"
#include "utils.h"

/* Add/Delete IP route to/from a specific interface */
int
netlink_route_ipv4(ip_route *iproute, int cmd)
{
	int status = 1;
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1024];
	} req;

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

	/* Set routing entry */
	req.r.rtm_dst_len = iproute->dmask;
	addattr_l(&req.n, sizeof(req), RTA_DST,		&iproute->dst, 4);
	addattr_l(&req.n, sizeof(req), RTA_GATEWAY,	&iproute->gw,  4);
	if (iproute->index)
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
	ip_route *iproute;
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
free_iproute(void *rt_data_obj)
{
	FREE(rt_data_obj);
}
void
dump_iproute(void *rt_data_obj)
{
	ip_route *route = rt_data_obj;
	char *log_msg = MALLOC(150);
	char *tmp = MALLOC(30);

	if (route->dst) {
		snprintf(tmp, 30, "%s/%d", inet_ntop2(route->dst), route->dmask);
		strncat(log_msg, tmp, 30);
	}
	if (route->gw) {
		snprintf(tmp, 30, " gw %s", inet_ntop2(route->gw));
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

	syslog(LOG_INFO, "     %s", log_msg);

	FREE(tmp);
	FREE(log_msg);
}
void
alloc_route(list rt_list, vector strvec)
{
	ip_route *new;
	uint32_t ipaddr = 0;
	interface *ifp;
	char *str;
	int i = 0;

	new = (ip_route *) MALLOC(sizeof(ip_route));

	/* FMT parse */
	while (i < VECTOR_SIZE(strvec)) {
		str = VECTOR_SLOT(strvec, i);

		/* cmd parsing */
		if (!strcmp(str, "via") || !strcmp(str, "gw")) {
			inet_ston(VECTOR_SLOT(strvec, ++i), &new->gw);
		} else if (!strcmp(str, "src")) {
			inet_ston(VECTOR_SLOT(strvec, ++i), &new->src);
		} else if (!strcmp(str, "dev") || !strcmp(str, "oif")) {
			ifp = if_get_by_ifname(VECTOR_SLOT(strvec, ++i));
			if (!ifp) {
				syslog(LOG_INFO, "VRRP is trying to assign VROUTE to unknown "
				       "%s interface !!! go out and fixe your conf !!!",
				       (char *)VECTOR_SLOT(strvec, i));
				FREE(new);
				return;
			}
			new->index = IF_INDEX(ifp);
		} else if (!strcmp(str, "table")) {
			new->table = atoi(VECTOR_SLOT(strvec, ++i));
		} else if (!strcmp(str, "metric")) {
			new->metric = atoi(VECTOR_SLOT(strvec, ++i));
		} else if (!strcmp(str, "scope")) {
			new->scope = netlink_scope_a2n(VECTOR_SLOT(strvec, ++i));
		} else {
			if (!strcmp(str, "to")) i++;
			if (inet_ston(VECTOR_SLOT(strvec, i), &ipaddr)) {
				inet_ston(VECTOR_SLOT(strvec, i), &new->dst);
				new->dmask = inet_stom(VECTOR_SLOT(strvec, i));
			}
		}
		i++;
	}

	list_add(rt_list, new);
}

/* Try to find a route in a list */
int
route_exist(list l, ip_route *iproute)
{
	ip_route *ipr;
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
	ip_route *iproute;
	element e;

	/* No route in previous conf */
	if (LIST_ISEMPTY(l))
		return;

	/* All Static routes removed */
	if (LIST_ISEMPTY(n)) {
		syslog(LOG_INFO, "Removing a VirtualRoute block");
		netlink_rtlist_ipv4(l, IPROUTE_DEL);
		return;
	}

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		iproute = ELEMENT_DATA(e);
		if (!route_exist(n, iproute) && iproute->set) {
			syslog(LOG_INFO, "ip route %s/%d ... , no longer exist"
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
