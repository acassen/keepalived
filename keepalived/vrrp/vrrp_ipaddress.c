/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK IPv4 address manipulation.
 *
 * Version:     $Id: vrrp_ipaddress.c,v 1.0.3 2003/05/11 02:28:03 acassen Exp $
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
#include "vrrp_ipaddress.h"
#include "vrrp_netlink.h"
#include "vrrp_if.h"
#include "memory.h"
#include "utils.h"

/* Add/Delete IP address to a specific interface */
int
netlink_address_ipv4(ip_address *ipaddr, int cmd)
{
	struct nl_handle nlh;
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

	if (netlink_socket(&nlh, 0) < 0)
		return -1;

	if (netlink_talk(&nlh, &req.n) < 0)
		status = -1;

	/* to close the socket */
	netlink_close(&nlh);
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

	for (e = LIST_HEAD(ip_list); e; ELEMENT_NEXT(e)) {
		ipaddress = ELEMENT_DATA(e);
		if ((cmd && !ipaddress->set) ||
		    (!cmd && ipaddress->set)) {
			if (netlink_address_ipv4(ipaddress, cmd) > 0)
				ipaddress->set = (cmd) ? 1 : 0;
			else
				ipaddress->set = 0;
		}
	}
}

/* IP address dump/allocation */
void
free_ipaddress(void *data)
{
	FREE(data);
}
void
dump_ipaddress(void *data)
{
	ip_address *ip_addr = data;
	syslog(LOG_INFO, "     %s/%d dev %s scope %s"
	       , inet_ntop2(ip_addr->addr)
	       , ip_addr->mask
	       , IF_NAME(if_get_by_ifindex(ip_addr->ifindex))
	       , netlink_scope_n2a(ip_addr->scope));
}
void
alloc_ipaddress(list ip_list, vector strvec, int ifindex)
{
	ip_address *new;
	uint32_t ipaddr = 0;
	char *str;
	int i = 0;

	new = (ip_address *) MALLOC(sizeof(ip_address));
	new->ifindex = ifindex;

	/* FMT parse */
	while (i < VECTOR_SIZE(strvec)) {
		str = VECTOR_SLOT(strvec, i);

		/* cmd parsing */
		if (!strcmp(str, "dev")) {
			new->ifindex = IF_INDEX(if_get_by_ifname(VECTOR_SLOT(strvec, ++i)));
		} else if (!strcmp(str, "scope")) {
			new->scope = netlink_scope_a2n(VECTOR_SLOT(strvec, ++i));
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
		syslog(LOG_INFO, "Removing a VIP|E-VIP block");
		netlink_iplist_ipv4(l, IPADDRESS_DEL);
		return;
	}

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		ipaddress = ELEMENT_DATA(e);
		if (!address_exist(n, ipaddress) && ipaddress->set) {
			syslog(LOG_INFO, "ip address %s/%d dev %s, no longer exist"
			       , inet_ntop2(ipaddress->addr)
			       , ipaddress->mask
			       , IF_NAME(if_get_by_ifindex(ipaddress->ifindex)));
			netlink_address_ipv4(ipaddress, IPADDRESS_DEL);
		}
	}
}
