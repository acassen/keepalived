/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK IPv4 routes manipulation.
 *
 * Version:     $Id: vrrp_iproute.c,v 1.0.1 2003/03/17 22:14:34 acassen Exp $
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

/* local include */
#include "vrrp_iproute.h"
#include "vrrp_netlink.h"
#include "vrrp_if.h"
#include "memory.h"
#include "utils.h"
#include "data.h"

/* extern global vars */
extern data *conf_data;
extern data *old_data;

/* Add/Delete IP route to/from a specific interface */
int
netlink_route_ipv4(ip_route *iproute, int cmd)
{
	struct nl_handle nlh;
	int status = 1;
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1024];
	} req;

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	req.n.nlmsg_type = cmd ? RTM_NEWROUTE : RTM_DELROUTE;
	req.r.rtm_family = AF_INET;
	req.r.rtm_table = RT_TABLE_MAIN;
	req.r.rtm_scope = RT_SCOPE_NOWHERE;

	if (cmd) {
		req.r.rtm_protocol = RTPROT_BOOT;
		req.r.rtm_scope = RT_SCOPE_UNIVERSE;
		req.r.rtm_type = RTN_UNICAST;
	}

	/* Set routing entry */
	addattr_l(&req.n, sizeof(req), RTA_DST,		&iproute->dst, 4);
	addattr_l(&req.n, sizeof(req), RTA_GATEWAY,	&iproute->gw,  4);
	if (iproute->index)
		addattr32(&req.n, sizeof(req), RTA_OIF, iproute->index);
	req.r.rtm_dst_len = iproute->dmask;

	if (netlink_socket(&nlh, 0) < 0)
		return -1;

	if (netlink_talk(&nlh, &req.n) < 0)
		status = -1;

	/* to close the clocket */
	netlink_close(&nlh);
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
free_route(void *data)
{
	FREE(data);
}
void
dump_route(void *data)
{
	ip_route *route = data;
	char *log_msg = MALLOC(100);
	char *to_msg = NULL;
	char *gw_msg = NULL;
	char *dev_msg = NULL;

	if (route->dst) {
		to_msg = MALLOC(30);
		snprintf(to_msg, 30, "%s/%d",
		         inet_ntop2(route->dst), route->dmask);
		strncat(log_msg, to_msg, 30);
		FREE(to_msg);
	}
	if (route->gw) {
		gw_msg = MALLOC(30);
		snprintf(gw_msg, 30, " gw %s", inet_ntop2(route->gw));
		strncat(log_msg, gw_msg, 30);
		FREE(gw_msg);
	}
	if (route->index) {
		dev_msg = MALLOC(30);
		snprintf(dev_msg, 30, " dev %s",
		         IF_NAME(if_get_by_ifindex(route->index)));
		strncat(log_msg, dev_msg, 30);
		FREE(dev_msg);
	}

	syslog(LOG_INFO, "     %s", log_msg);
	FREE(log_msg);
}
void
alloc_route(list rt_list, vector strvec)
{
	ip_route *new;
	uint32_t ipaddr = 0;
	char *str;
	int i = 0;

	new = (ip_route *) MALLOC(sizeof(ip_route));

	/* FMT parse */
	while (i < VECTOR_SIZE(strvec)) {
		str = VECTOR_SLOT(strvec, i);

		/* cmd parsing */
		if (!strcmp(str, "via") || !strcmp(str, "gw")) {
			inet_ston(VECTOR_SLOT(strvec, ++i), &new->gw);
		} else if (!strcmp(str, "dev") || !strcmp(str, "oif")) {
			new->index = IF_INDEX(if_get_by_ifname(VECTOR_SLOT(strvec, ++i)));
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
	clear_diff_routes(old_data->static_routes, conf_data->static_routes);
}
