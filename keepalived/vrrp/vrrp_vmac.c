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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

/* local include */
#include "vrrp_vmac.h"
#include "vrrp_netlink.h"
#include "vrrp_data.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "parser.h"

/* private matter */
static const char *ll_kind = "macvlan";

#ifdef _HAVE_VRRP_VMAC_
/* Link layer handling */
static int
netlink_link_setlladdr(vrrp_t *vrrp)
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
netlink_link_setmode(vrrp_t *vrrp)
{
	int status = 1;
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[256];
	} req;
	struct rtattr *linkinfo;
	struct rtattr *data;

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.ifi.ifi_family = AF_INET;
	req.ifi.ifi_index = IF_INDEX(vrrp->ifp);

	linkinfo = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, sizeof(req), IFLA_LINKINFO, NULL, 0);
	addattr_l(&req.n, sizeof(req), IFLA_INFO_KIND, (void *) ll_kind, strlen(ll_kind));
	data = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, sizeof(req), IFLA_INFO_DATA, NULL, 0);

	/*
	 * In private mode, macvlan will receive frames with same MAC addr
	 * as configured on the interface.
	 */
	addattr32(&req.n, sizeof(req), IFLA_MACVLAN_MODE,
		  MACVLAN_MODE_PRIVATE);
	data->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)data;
	linkinfo->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)linkinfo;

	if (netlink_talk(&nl_cmd, &req.n) < 0)
		status = -1;

	return status;
}

static int
netlink_link_up(vrrp_t *vrrp)
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
#endif

int
netlink_link_add_vmac(vrrp_t *vrrp)
{
#ifdef _HAVE_VRRP_VMAC_
	struct rtattr *linkinfo;
	unsigned int base_ifindex;
	interface_t *ifp;
	char ifname[IFNAMSIZ];
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[256];
	} req;

	if (!vrrp->ifp || vrrp->vmac_flags & VRRP_VMAC_FL_UP || !vrrp->vrid)
		return -1;

	memset(&req, 0, sizeof (req));
	memset(ifname, 0, IFNAMSIZ);
	strncpy(ifname, vrrp->vmac_ifname, IFNAMSIZ - 1);

	/* 
	 * Check to see if this vmac interface was created 
	 * by a previous instance.
	 */
	if (reload && (ifp = if_get_by_ifname(ifname))) {
		/* (re)set VMAC properties (if deleted on reload) */
		ifp->base_ifindex = vrrp->ifp->ifindex;
		ifp->vmac = 1;
		ifp->flags = vrrp->ifp->flags; /* Copy base interface flags */
		vrrp->ifp = ifp;
		/* Save ifindex for use on delete */
		vrrp->vmac_ifindex = IF_INDEX(vrrp->ifp);
		vrrp->vmac_flags |= VRRP_VMAC_FL_UP;
		return 1;
	}
	
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

	if (netlink_talk(&nl_cmd, &req.n) < 0) {
		log_message(LOG_INFO, "vmac: Error creating VMAC interface %s for vrrp_instance %s!!!"
				    , ifname, vrrp->iname);
		return -1;
	}

	log_message(LOG_INFO, "vmac: Success creating VMAC interface %s for vrrp_instance %s"
			    , ifname, vrrp->iname);

	/*
	 * Update interface queue and vrrp instance interface binding.
	 * bring it UP !
	 */
	netlink_interface_lookup();
	ifp = if_get_by_ifname(ifname);
	if (!ifp)
		return -1;
	base_ifindex = vrrp->ifp->ifindex;
	ifp->flags = vrrp->ifp->flags; /* Copy base interface flags */
	vrrp->ifp = ifp;
	vrrp->ifp->base_ifindex = base_ifindex;
	vrrp->ifp->vmac = 1;
	vrrp->vmac_ifindex = IF_INDEX(vrrp->ifp); /* For use on delete */
	vrrp->vmac_flags |= VRRP_VMAC_FL_UP;
	netlink_link_setlladdr(vrrp);
	netlink_link_up(vrrp);

	/*
	 * By default MACVLAN interface are in VEPA mode which filters
	 * out received packets whose MAC source address matches that
	 * of the MACVLAN interface. Setting MACVLAN interface in private
	 * mode will not filter based on source MAC address.
	 */
	netlink_link_setmode(vrrp);
#endif
	return 1;
}

int
netlink_link_del_vmac(vrrp_t *vrrp)
{
	int status = 1;

#ifdef _HAVE_VRRP_VMAC_
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
	req.ifi.ifi_index = vrrp->vmac_ifindex;

	if (netlink_talk(&nl_cmd, &req.n) < 0) {
		log_message(LOG_INFO, "vmac: Error removing VMAC interface %s for vrrp_instance %s!!!"
				    , vrrp->vmac_ifname, vrrp->iname);
		status = -1;
	}

	log_message(LOG_INFO, "vmac: Success removing VMAC interface %s for vrrp_instance %s"
			    , vrrp->vmac_ifname, vrrp->iname);
#endif

	return status;
}
