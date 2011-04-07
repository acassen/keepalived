/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK VMAC address manipulation.
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
#include "vrrp_vmac.h"
#include "vrrp_netlink.h"
#include "vrrp_data.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"

/* private matter */
static const char *ll_kind = "macvlan";

/* Link layer handling */
static int
netlink_link_setlladdr(vrrp_rt *vrrp)
{
	int status = 1;
	u_char ll_addr[ETH_ALEN] = {0x00, 0x00, 0x5e, 0x00, 0x01, vrrp->vrid};
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[256];
	} req;

	memset(&req, 0, sizeof (req));
	
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.ifi.ifi_family = AF_INET;
	req.ifi.ifi_index = IF_INDEX(vrrp->ifp);

	addattr_l(&req.n, sizeof(req), IFLA_ADDRESS, ll_addr, ETH_ALEN);

	if (netlink_talk(&nl_cmd, &req.n) < 0)
		status = -1;
	else
		memcpy(vrrp->ifp->hw_addr, ll_addr, ETH_ALEN);

	return status;
}

static int
netlink_link_up(vrrp_rt *vrrp)
{
	int status = 1;
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[256];
	} req;

	memset(&req, 0, sizeof (req));
	
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = IF_INDEX(vrrp->ifp);
	req.ifi.ifi_change |= IFF_UP;
	req.ifi.ifi_flags |= IFF_UP;

	if (netlink_talk(&nl_cmd, &req.n) < 0)
		status = -1;

	return status;
}

int
netlink_link_add_vmac(vrrp_rt *vrrp)
{
	struct rtattr *linkinfo;
	interface *ifp;
	char ifname[IFNAMSIZ];
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[256];
	} req;

	if (!vrrp->ifp)
		return -1;

	memset(&req, 0, sizeof (req));
	snprintf(ifname, IFNAMSIZ, "vrrp.%d", vrrp->vrid);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.ifi.ifi_family = AF_INET;

	/* macvlan settings */
	linkinfo = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, sizeof(req), IFLA_LINKINFO, NULL, 0);
	addattr_l(&req.n, sizeof(req), IFLA_INFO_KIND, (void *)ll_kind, strlen(ll_kind));
	linkinfo->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)linkinfo;
	addattr_l(&req.n, sizeof(req), IFLA_LINK, &IF_INDEX(vrrp->ifp), sizeof(uint32_t));
	addattr_l(&req.n, sizeof(req), IFLA_IFNAME, ifname, strlen(ifname));

	if (netlink_talk(&nl_cmd, &req.n) < 0)
		return -1;

	/*
	 * Update interface queue and vrrp instance interface binding.
	 * bring it UP !
	 */
	netlink_interface_lookup();
	ifp = if_get_by_ifname(ifname);
	if (!ifp)
		return -1;
	vrrp->ifp = ifp;
	vrrp->vmac |= 2;
	netlink_link_setlladdr(vrrp);
	netlink_link_up(vrrp);

	return 1;
}

int
netlink_link_del_vmac(vrrp_rt *vrrp)
{
	int status = 1;
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[256];
	} req;

	if (!vrrp->ifp)
		return -1;

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_DELLINK;
	req.ifi.ifi_family = AF_INET;
	req.ifi.ifi_index = IF_INDEX(vrrp->ifp);

	if (netlink_talk(&nl_cmd, &req.n) < 0)
		status = -1;

	return status;
}
