/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK IPv4 address manipulation.
 *
 * Version:     $Id: vrrp_ipaddress.c,v 0.7.6 2002/11/20 21:34:18 acassen Exp $
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
#include "utils.h"

/* Add/Delete IP address to a specific interface */
int
netlink_address_ipv4(int ifindex, uint32_t addr, uint8_t mask, int cmd)
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
	req.ifa.ifa_index = ifindex;
	req.ifa.ifa_prefixlen = mask;
	addattr_l(&req.n, sizeof (req), IFA_LOCAL, &addr, sizeof (addr));

	if (netlink_socket(&nlh, 0) < 0)
		return -1;

	if (netlink_talk(&nlh, &req.n) < 0)
		status = -1;

	/* to close the clocket */
	netlink_close(&nlh);
	return status;
}
