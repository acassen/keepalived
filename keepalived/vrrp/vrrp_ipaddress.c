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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

/* local include */
#include "vrrp_ipaddress.h"
#include "vrrp_netlink.h"
#include "vrrp_data.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"

/* Add/Delete IP address to a specific interface */
static int
netlink_ipaddress(ip_address *ipaddress, int cmd)
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
	req.ifa = ipaddress->ifa;

	if (IP_IS6(ipaddress)) {
		addattr_l(&req.n, sizeof(req), IFA_LOCAL,
			  &ipaddress->u.sin6_addr, sizeof(ipaddress->u.sin6_addr));
	} else {
		addattr_l(&req.n, sizeof(req), IFA_LOCAL,
			  &ipaddress->u.sin.sin_addr, sizeof(ipaddress->u.sin.sin_addr));
		if (ipaddress->u.sin.sin_brd.s_addr)
			addattr_l(&req.n, sizeof(req), IFA_BROADCAST,
				  &ipaddress->u.sin.sin_brd, sizeof(ipaddress->u.sin.sin_brd));
	}

	if (ipaddress->label)
		addattr_l(&req.n, sizeof (req), IFA_LABEL,
			  ipaddress->label, strlen(ipaddress->label) + 1);

	if (netlink_talk(&nl_cmd, &req.n) < 0)
		status = -1;

	return status;
}

/* Add/Delete a list of IP addresses */
void
netlink_iplist(list ip_list, int cmd)
{
	ip_address *ipaddr;
	element e;

	/* No addresses in this list */
	if (LIST_ISEMPTY(ip_list))
		return;

	/*
	 * If "--dont-release-vrrp" (debug & 8) is set then try to release
	 * addresses that may be there, even if we didn't set them.
	 */
	for (e = LIST_HEAD(ip_list); e; ELEMENT_NEXT(e)) {
		ipaddr = ELEMENT_DATA(e);
		if ((cmd && !ipaddr->set) ||
		    (!cmd && (ipaddr->set || debug & 8))) {
			if (netlink_ipaddress(ipaddr, cmd) > 0)
				ipaddr->set = (cmd) ? 1 : 0;
			else
				ipaddr->set = 0;
		}
	}
}

/* IP address dump/allocation */
void
free_ipaddress(void *if_data)
{
	ip_address *ipaddr = if_data;

	FREE_PTR(ipaddr->label);
	FREE(ipaddr);
}
void
dump_ipaddress(void *if_data)
{
	ip_address *ipaddr = if_data;
	char *broadcast = (char *) MALLOC(21);
	char *addr_str = (char *) MALLOC(41);

	if (IP_IS6(ipaddr)) {
		inet_ntop(AF_INET6, &ipaddr->u.sin6_addr, addr_str, 41);
	} else {
		inet_ntop(AF_INET, &ipaddr->u.sin.sin_addr, addr_str, 41);
		if (ipaddr->u.sin.sin_brd.s_addr)
			snprintf(broadcast, sizeof(broadcast), " brd %s",
				 inet_ntop2(ipaddr->u.sin.sin_brd.s_addr));
	}

	log_message(LOG_INFO, "     %s/%d%s dev %s scope %s%s%s"
	       , addr_str
	       , ipaddr->ifa.ifa_prefixlen
	       , broadcast
	       , IF_NAME(ipaddr->ifp)
	       , netlink_scope_n2a(ipaddr->ifa.ifa_scope)
	       , ipaddr->label ? " label " : ""
	       , ipaddr->label ? ipaddr->label : "");
	FREE(broadcast);
	FREE(addr_str);
}
void
alloc_ipaddress(list ip_list, vector strvec, interface *ifp)
{
	ip_address *new;
	interface *ifp_local;
	char *str, *p;
	void *addr;
	int i = 0, addr_idx =0;

	new = (ip_address *) MALLOC(sizeof(ip_address));
	if (ifp) {
		new->ifa.ifa_index = IF_INDEX(ifp);
		new->ifp = ifp;
	} else {
		ifp_local = if_get_by_ifname(DFLT_INT);
		if (!ifp_local) {
			log_message(LOG_INFO, "Default interface " DFLT_INT
				    " does not exist and no interface specified. "
				    "Skip VRRP address.");
			FREE(new);
			return;
		}
		new->ifa.ifa_index = IF_INDEX(ifp_local);
		new->ifp = ifp_local;
	}

	/* FMT parse */
	while (i < VECTOR_SIZE(strvec)) {
		str = VECTOR_SLOT(strvec, i);

		/* cmd parsing */
		if (!strcmp(str, "dev")) {
			ifp_local = if_get_by_ifname(VECTOR_SLOT(strvec, ++i));
			if (!ifp_local) {
				log_message(LOG_INFO, "VRRP is trying to assign VIP to unknown %s"
				       " interface !!! go out and fixe your conf !!!",
				       (char *)VECTOR_SLOT(strvec, i));
				FREE(new);
				return;
			}
			new->ifa.ifa_index = IF_INDEX(ifp_local);
			new->ifp = ifp_local;
		} else if (!strcmp(str, "scope")) {
			new->ifa.ifa_scope = netlink_scope_a2n(VECTOR_SLOT(strvec, ++i));
		} else if (!strcmp(str, "broadcast") || !strcmp(str, "brd")) {
			if (IP_IS6(new)) {
				log_message(LOG_INFO, "VRRP is trying to assign a broadcast %s to the IPv6 address %s !!?? "
						      "WTF... skipping VIP..."
						    , VECTOR_SLOT(strvec, i), VECTOR_SLOT(strvec, addr_idx));
				FREE(new);
				return;
			} else if (!inet_pton(AF_INET, VECTOR_SLOT(strvec, ++i), &new->u.sin.sin_brd)) {
				log_message(LOG_INFO, "VRRP is trying to assign invalid broadcast %s. "
						      "skipping VIP...", VECTOR_SLOT(strvec, i));
				FREE(new);
				return;
			}
		} else if (!strcmp(str, "label")) {
			new->label = MALLOC(IFNAMSIZ);
			strncpy(new->label, VECTOR_SLOT(strvec, ++i), IFNAMSIZ);
		} else {
			p = strchr(str, '/');
			if (p) {
				new->ifa.ifa_prefixlen = atoi(p + 1);
				*p = 0;
			}

			new->ifa.ifa_family = (strchr(str, ':')) ? AF_INET6 : AF_INET;
			if (!new->ifa.ifa_prefixlen)
				new->ifa.ifa_prefixlen = (IP_IS6(new)) ? 128 : 32;
			addr = (IP_IS6(new)) ? (void *) &new->u.sin6_addr :
					       (void *) &new->u.sin.sin_addr;
			if (!inet_pton(IP_FAMILY(new), str, addr)) {
				log_message(LOG_INFO, "VRRP is trying to assign invalid VIP %s. "
						      "skipping VIP...", str);
				FREE(new);
				return;
			}
			addr_idx  = i;
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
		if (IP_FAMILY(ipaddr) == IP_FAMILY(ipaddress)) {
			if ((IP_IS6(ipaddress) && IP6_ISEQ(ipaddr, ipaddress)) ||
			    (!IP_IS6(ipaddress) && IP_ISEQ(ipaddr, ipaddress))) {
				ipaddr->set = ipaddress->set;
				return 1;
			}
		}
	}

	return 0;
}

/* Clear diff addresses */
void
clear_diff_address(list l, list n)
{
	ip_address *ipaddr;
	element e;
	char *addr_str;
	void *addr;

	/* No addresses in previous conf */
	if (LIST_ISEMPTY(l))
		return;

	/* All addresses removed */
	if (LIST_ISEMPTY(n)) {
		log_message(LOG_INFO, "Removing a VIP|E-VIP block");
		netlink_iplist(l, IPADDRESS_DEL);
		return;
	}

	addr_str = (char *) MALLOC(41);
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		ipaddr = ELEMENT_DATA(e);

		if (!address_exist(n, ipaddr) && ipaddr->set) {
			addr = (IP_IS6(ipaddr)) ? (void *) &ipaddr->u.sin6_addr :
						  (void *) &ipaddr->u.sin.sin_addr;
			inet_ntop(IP_FAMILY(ipaddr), addr, addr_str, 41);

			log_message(LOG_INFO, "ip address %s/%d dev %s, no longer exist"
					    , addr_str
					    , ipaddr->ifa.ifa_prefixlen
					    , IF_NAME(if_get_by_ifindex(ipaddr->ifa.ifa_index)));
			netlink_ipaddress(ipaddr, IPADDRESS_DEL);
		}
	}
	FREE(addr_str);
}

/* Clear static ip address */
void
clear_diff_saddresses(void)
{
	clear_diff_address(old_vrrp_data->static_addresses, vrrp_data->static_addresses);
}
