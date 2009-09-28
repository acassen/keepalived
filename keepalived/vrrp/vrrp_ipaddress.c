/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK IPv4 address manipulation.
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
 * Copyright (C) 2001-2009 Alexandre Cassen, <acassen@freebox.fr>
 */

/* local include */
#include "vrrp_ipaddress.h"
#include "vrrp_netlink.h"
#include "vrrp_data.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"

/* Add/Delete IP address to a specific interface */
int
netlink_address_ipv4(ip_address *ipaddr, int cmd)
{
	int status = 1;
	struct {
		struct nlmsghdr n;
		struct ifaddrmsg ifa;
		char buf[256];
	} req;

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = cmd ? RTM_NEWADDR : RTM_DELADDR;
	req.ifa.ifa_family = AF_INET;
	req.ifa.ifa_index = ipaddr->ifindex;
	req.ifa.ifa_scope = ipaddr->scope;
	req.ifa.ifa_prefixlen = ipaddr->mask;
	addattr_l(&req.n, sizeof (req), IFA_LOCAL, &ipaddr->addr, sizeof (ipaddr->addr));
	if (ipaddr->broadcast)
		addattr_l(&req.n, sizeof (req), IFA_BROADCAST,
			  &ipaddr->broadcast, sizeof (ipaddr->broadcast));

	if (ipaddr->label)
		addattr_l(&req.n, sizeof (req), IFA_LABEL,
			  ipaddr->label, strlen(ipaddr->label) + 1);

	if (netlink_talk(&nl_cmd, &req.n) < 0)
		status = -1;
	return status;
}

/* Add/Delete a list of IP addresses */
void
netlink_iplist_ipv4(list ip_list, int cmd)
{
	ip_address *ipaddress;
	element e;

	/* No addresses in this list */
	if (LIST_ISEMPTY(ip_list))
		return;

	/*
	 * If "--dont-release-vrrp" (debug & 8) is set then try to release
	 * addresses that may be there, even if we didn't set them.
	 */
	for (e = LIST_HEAD(ip_list); e; ELEMENT_NEXT(e)) {
		ipaddress = ELEMENT_DATA(e);
		if ((cmd && !ipaddress->set) ||
		    (!cmd && (ipaddress->set || debug & 8))) {
			if (netlink_address_ipv4(ipaddress, cmd) > 0)
				ipaddress->set = (cmd) ? 1 : 0;
			else
				ipaddress->set = 0;
		}
	}
}

/* IP address dump/allocation */
void
free_ipaddress(void *if_data_obj)
{
	ip_address *ip_addr = if_data_obj;

	FREE_PTR(ip_addr->label);
	FREE(ip_addr);
}
void
dump_ipaddress(void *if_data_obj)
{
	ip_address *ip_addr = if_data_obj;
	log_message(LOG_INFO, "     %s/%d brd %s dev %s scope %s%s%s"
	       , inet_ntop2(ip_addr->addr)
	       , ip_addr->mask
	       , inet_ntop2(ip_addr->broadcast)
	       , IF_NAME(if_get_by_ifindex(ip_addr->ifindex))
	       , netlink_scope_n2a(ip_addr->scope)
	       , ip_addr->label ? " label " : ""
	       , ip_addr->label ? ip_addr->label : "");
}
void
alloc_ipaddress(list ip_list, vector strvec, interface *ifp)
{
	ip_address *new;
	uint32_t ipaddr = 0;
	char *str;
	int i = 0;

	new = (ip_address *) MALLOC(sizeof(ip_address));
	if (ifp) {
		new->ifp = ifp;
		new->ifindex = IF_INDEX(ifp);
	} else {
		new->ifp = if_get_by_ifname(DFLT_INT);
		new->ifindex = IF_INDEX(new->ifp);
	}

	/* FMT parse */
	while (i < VECTOR_SIZE(strvec)) {
		str = VECTOR_SLOT(strvec, i);

		/* cmd parsing */
		if (!strcmp(str, "dev")) {
			new->ifp = if_get_by_ifname(VECTOR_SLOT(strvec, ++i));
			if (!new->ifp) {
				log_message(LOG_INFO, "VRRP is trying to assign VIP to unknown %s"
				       " interface !!! go out and fixe your conf !!!",
				       (char *)VECTOR_SLOT(strvec, i));
				FREE(new);
				return;
			}
			new->ifindex = IF_INDEX(new->ifp);
		} else if (!strcmp(str, "scope")) {
			new->scope = netlink_scope_a2n(VECTOR_SLOT(strvec, ++i));
		} else if (!strcmp(str, "broadcast") || !strcmp(str, "brd")) {
			inet_ston(VECTOR_SLOT(strvec, ++i), &new->broadcast);
		} else if (!strcmp(str, "label")) {
			new->label = MALLOC(IFNAMSIZ);
			strncpy(new->label, VECTOR_SLOT(strvec, ++i), IFNAMSIZ);
		} else {
			if (inet_ston(VECTOR_SLOT(strvec, i), &ipaddr)) {
				inet_ston(VECTOR_SLOT(strvec, i), &new->addr);
				new->mask = inet_stom(VECTOR_SLOT(strvec, i));
			}
		}
		i++;
	}
	list_add(ip_list, new);
}

/* Find an address in a list */
int
address_exist(list l, ip_address *ipaddress)
{
	ip_address *ipaddr;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		ipaddr = ELEMENT_DATA(e);
		if (IP_ISEQ(ipaddr, ipaddress)) {
			ipaddr->set = ipaddress->set;
			return 1;
		}
	}

	return 0;
}

/* Clear diff addresses */
void
clear_diff_address(list l, list n)
{
	ip_address *ipaddress;
	element e;

	/* No addresses in previous conf */
	if (LIST_ISEMPTY(l))
		return;

	/* All addresses removed */
	if (LIST_ISEMPTY(n)) {
		log_message(LOG_INFO, "Removing a VIP|E-VIP block");
		netlink_iplist_ipv4(l, IPADDRESS_DEL);
		return;
	}

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		ipaddress = ELEMENT_DATA(e);
		if (!address_exist(n, ipaddress) && ipaddress->set) {
			log_message(LOG_INFO, "ip address %s/%d dev %s, no longer exist"
			       , inet_ntop2(ipaddress->addr)
			       , ipaddress->mask
			       , IF_NAME(if_get_by_ifindex(ipaddress->ifindex)));
			netlink_address_ipv4(ipaddress, IPADDRESS_DEL);
		}
	}
}

/* Clear static ip address */
void
clear_diff_saddresses(void)
{
	clear_diff_address(old_vrrp_data->static_addresses, vrrp_data->static_addresses);
}
