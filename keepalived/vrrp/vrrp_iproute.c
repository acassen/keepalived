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

void
add_addr2req(struct nlmsghdr *n, int maxlen, int type, ip_address_t *ipaddress) {
	if (IP_IS6(ipaddress)) {
		addattr_l(n, maxlen, type, &ipaddress->u.sin6_addr, sizeof(ipaddress->u.sin6_addr));
	} else {
		addattr_l(n, maxlen, type, &ipaddress->u.sin.sin_addr, sizeof(ipaddress->u.sin.sin_addr));
	}
}

void
add_addr2rta(struct rtattr *rta, int maxlen, int type, ip_address_t *ipaddress) {
	if (IP_IS6(ipaddress)) {
		rta_addattr_l(rta, maxlen, type, &ipaddress->u.sin6_addr, sizeof(ipaddress->u.sin6_addr));
	} else {
		rta_addattr_l(rta, maxlen, type, &ipaddress->u.sin.sin_addr, sizeof(ipaddress->u.sin.sin_addr));
	}
}

/* Add/Delete IP route to/from a specific interface */
int
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

	log_message(LOG_DEBUG, "route command: %d", cmd);
	dump_iproute(iproute);

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	req.n.nlmsg_type  = cmd ? RTM_NEWROUTE : RTM_DELROUTE;
	req.r.rtm_family  = IP_FAMILY(&iproute->dst);
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
	add_addr2req(&req.n, sizeof(req), RTA_DST, &iproute->dst);
	if ((!iproute->blackhole) && (!iproute->gw2.parsed))
		add_addr2req(&req.n, sizeof(req), RTA_GATEWAY, &iproute->gw);
	if (iproute->gw2.parsed) {
		rta->rta_type = RTA_MULTIPATH;
		rta->rta_len = RTA_LENGTH(0);
		rtnh = RTA_DATA(rta);

#define MULTIPATH_ADD_GW(x) \
	memset(rtnh, 0, sizeof(*rtnh)); \
	rtnh->rtnh_len = sizeof(*rtnh); \
	if (iproute->index) rtnh->rtnh_ifindex = iproute->index; \
	rta->rta_len += rtnh->rtnh_len;	\
	add_addr2rta(rta, 1024, RTA_GATEWAY, x); \
	rtnh->rtnh_len += sizeof(struct rtattr) + IP_SIZE(x);	\
	rtnh = RTNH_NEXT(rtnh);

		MULTIPATH_ADD_GW(&iproute->gw);
		MULTIPATH_ADD_GW(&iproute->gw2);
		addattr_l(&req.n, sizeof(req), RTA_MULTIPATH, RTA_DATA(rta), RTA_PAYLOAD(rta));
	}
	if ((iproute->index) && (!iproute->gw2.parsed))
		addattr32(&req.n, sizeof(req), RTA_OIF, iproute->index);
	if (iproute->src.parsed)
		add_addr2req(&req.n, sizeof(req), RTA_PREFSRC, &iproute->src);
	if (iproute->metric)
		addattr32(&req.n, sizeof(req), RTA_PRIORITY, iproute->metric);

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
	FREE(rt_data);
}
void
dump_iproute(void *rt_data)
{
	ip_route_t *route = rt_data;
	char *log_msg = MALLOC(1024);
	char *tmp = MALLOC(INET6_ADDRSTRLEN + 30);
	char *dst_addr = 0;
	char *gw_addr = 0;
	char *gw2_addr = 0;
	char *src_addr = 0;

	if (route->blackhole) {
		strncat(log_msg, "blackhole ", 30);
	}
	if (route->dst.parsed) {
		dst_addr = ipaddresstos(&route->dst);
		snprintf(tmp, INET6_ADDRSTRLEN + 30, "%s/%d", dst_addr, route->dmask);
		strncat(log_msg, tmp, INET6_ADDRSTRLEN + 30);
	}
	if (route->gw.parsed) {
		gw_addr = ipaddresstos(&route->gw);
		snprintf(tmp, INET6_ADDRSTRLEN + 30, " gw %s", gw_addr);
		strncat(log_msg, tmp, INET6_ADDRSTRLEN + 30);
	}
	if (route->gw2.parsed) {
		gw2_addr = ipaddresstos(&route->gw2);
		snprintf(tmp, INET6_ADDRSTRLEN + 30, " or gw %s", gw2_addr);
		strncat(log_msg, tmp, INET6_ADDRSTRLEN + 30);
	}
	if (route->src.parsed) {
		src_addr = ipaddresstos(&route->src);
		snprintf(tmp, INET6_ADDRSTRLEN + 30, " src %s", src_addr);
		strncat(log_msg, tmp, INET6_ADDRSTRLEN + 30);
	}
	if (route->index) {
		snprintf(tmp, INET6_ADDRSTRLEN + 30, " dev %s",
			 IF_NAME(if_get_by_ifindex(route->index)));
		strncat(log_msg, tmp, INET6_ADDRSTRLEN + 30);
	}
	if (route->table) {
		snprintf(tmp, INET6_ADDRSTRLEN + 30, " table %d", route->table);
		strncat(log_msg, tmp, INET6_ADDRSTRLEN + 30);
	}
	if (route->scope) {
		snprintf(tmp, INET6_ADDRSTRLEN + 30, " scope %s",
			 netlink_scope_n2a(route->scope));
		strncat(log_msg, tmp, INET6_ADDRSTRLEN + 30);
	}
	if (route->metric) {
		snprintf(tmp, INET6_ADDRSTRLEN + 30, " metric %d", route->metric);
		strncat(log_msg, tmp, INET6_ADDRSTRLEN + 30);
	}

	log_message(LOG_INFO, "     %s", log_msg);

	if (dst_addr) FREE(dst_addr);
	if (gw_addr) FREE(gw_addr);
	if (gw2_addr) FREE(gw2_addr);
	if (src_addr) FREE(src_addr);
	FREE(tmp);
	FREE(log_msg);
}
void
alloc_route(list rt_list, vector_t *strvec)
{
	ip_route_t *new;
	interface_t *ifp;
	char *str;
	int i = 0;

	new = (ip_route_t *) MALLOC(sizeof(ip_route_t));

	new->dst.parsed = 0;
	new->gw.parsed = 0;
	new->gw2.parsed = 0;
	new->src.parsed = 0;

	/* FMT parse */
	while (i < vector_size(strvec)) {
		str = vector_slot(strvec, i);

		log_message(LOG_DEBUG, "parsing part of route: %s", str);

		/* cmd parsing */
		if (!strcmp(str, "blackhole")) {
			new->blackhole = 1;
			parse_ipaddress(&new->dst, vector_slot(strvec, ++i));
			new->dmask = new->dst.ifa.ifa_prefixlen;
		} else if (!strcmp(str, "via") || !strcmp(str, "gw")) {
			if (! parse_ipaddress(&new->gw, vector_slot(strvec, ++i))) {
				log_message(LOG_ERR, "unable to parse gateway: %s", vector_slot(strvec, i));
				FREE(new);
				return;
			}
		} else if (!strcmp(str, "or")) {
			if (! parse_ipaddress(&new->gw2, vector_slot(strvec, ++i))) {
				log_message(LOG_ERR, "unable to parse second gateway: %s", vector_slot(strvec, i));
				FREE(new);
				return;
			}
		} else if (!strcmp(str, "src")) {
			if (! parse_ipaddress(&new->src, vector_slot(strvec, ++i))) {
				log_message(LOG_ERR, "unable to parse source: %s", vector_slot(strvec, i));
				FREE(new);
				return;
			}
		} else if (!strcmp(str, "dev") || !strcmp(str, "oif")) {
			ifp = if_get_by_ifname(vector_slot(strvec, ++i));
			if (!ifp) {
				log_message(LOG_ERR, "VRRP is trying to assign VROUTE to unknown "
				       "%s interface !!! go out and fixe your conf !!!",
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
			if ( parse_ipaddress(&new->dst, vector_slot(strvec, i))) {
				new->dmask = new->dst.ifa.ifa_prefixlen;
			} else {
				log_message(LOG_ERR, "unable to parse destination: %s", vector_slot(strvec, i));
				FREE(new);
				return;
			}
		}
		i++;
	}

	log_message(LOG_DEBUG, "new route parsed");
	dump_iproute(new);

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
	char *dst_addr = 0;

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
			dst_addr = ipaddresstos(&iproute->dst);
			log_message(LOG_INFO, "ip route %s/%d ... , no longer exist"
			       , dst_addr, iproute->dmask);
			netlink_route(iproute, IPROUTE_DEL);
			FREE(dst_addr);
		}
	}
}

/* Diff conf handler */
void
clear_diff_sroutes(void)
{
	clear_diff_routes(old_vrrp_data->static_routes, vrrp_data->static_routes);
}

/* Local Variables: */
/* indent-tabs-mode: t */
/* tab-width: 8 */
/* c-basic-offset: 8 */
/* End: */
