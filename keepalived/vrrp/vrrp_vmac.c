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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

/* global include */
#ifdef _HAVE_LINUX_IF_ETHER_H_COLLISION_
#include <netinet/in.h>
#endif
#include <linux/if_link.h>
#include <stdint.h>

/* local include */
#include "vrrp_vmac.h"
#include "keepalived_netlink.h"
#include "logger.h"
#include "bitops.h"
#include "utils.h"
#include "vrrp_if_config.h"
#include "vrrp_ipaddress.h"
#include "vrrp_firewall.h"
#include "global_data.h"

const char * const macvlan_ll_kind = "macvlan";
#ifdef _HAVE_VRRP_IPVLAN_
const char * const ipvlan_ll_kind = "ipvlan";
#endif
u_char ll_addr[ETH_ALEN] = {0x00, 0x00, 0x5e, 0x00, 0x01, 0x00};

static void
make_link_local_address(struct in6_addr* l3_addr, const u_char* if_ll_addr)
{
	l3_addr->s6_addr[0] = 0xfe;
	l3_addr->s6_addr[1] = 0x80;
	l3_addr->s6_addr16[1] = 0;
	l3_addr->s6_addr32[1] = 0;
	l3_addr->s6_addr[8] = if_ll_addr[0] ^ 0x02;
	l3_addr->s6_addr[9] = if_ll_addr[1];
	l3_addr->s6_addr[10] = if_ll_addr[2];
	l3_addr->s6_addr[11] = 0xff;
	l3_addr->s6_addr[12] = 0xfe;
	l3_addr->s6_addr[13] = if_ll_addr[3];
	l3_addr->s6_addr[14] = if_ll_addr[4];
	l3_addr->s6_addr[15] = if_ll_addr[5];
}

bool
add_link_local_address(interface_t *ifp, struct in6_addr* sin6_addr)
{
	ip_address_t ipaddress;

	memset(&ipaddress, 0, sizeof(ipaddress));

	/* Delete the old address */
	ipaddress.ifp = ifp;
	ipaddress.u.sin6_addr = *sin6_addr;

	ipaddress.ifa.ifa_family = AF_INET6;
	ipaddress.ifa.ifa_prefixlen = 64;
	ipaddress.ifa.ifa_index = ifp->ifindex;

	if (netlink_ipaddress(&ipaddress, IPADDRESS_ADD) != 1) {
		log_message(LOG_INFO, "Adding link-local address to vmac failed");
		CLEAR_IP6_ADDR(&ifp->sin6_addr);

		return false;
	}

	/* Save the new address */
	ifp->sin6_addr = ipaddress.u.sin6_addr;

	return true;
}

bool
del_link_local_address(interface_t *ifp)
{
	ip_address_t ipaddress;

	memset(&ipaddress, 0, sizeof(ipaddress));

	/* Delete the old address */
	ipaddress.ifp = ifp;
	ipaddress.u.sin6_addr = ifp->sin6_addr;

	ipaddress.ifa.ifa_family = AF_INET6;
	ipaddress.ifa.ifa_prefixlen = 64;
	ipaddress.ifa.ifa_index = ifp->ifindex;

	if (netlink_ipaddress(&ipaddress, IPADDRESS_DEL) != 1) {
		log_message(LOG_INFO, "Deleting link-local address from vmac failed");

		return false;
	}

	CLEAR_IP6_ADDR(&ifp->sin6_addr);

	return true;
}

bool
replace_link_local_address(interface_t *ifp)
{
	ip_address_t ipaddress;
	struct in6_addr ipaddress_new;

	memset(&ipaddress, 0, sizeof(ipaddress));

	/* Create a new address */
	make_link_local_address(&ipaddress_new, ifp->base_ifp->hw_addr);

	/* There is no point in replacing the address with the same address */
	if (inaddr_equal(AF_INET6, &ipaddress_new, &ifp->sin6_addr))
		return true;

	/* Delete the old address */
	ipaddress.ifp = ifp;
	ipaddress.u.sin6_addr = ifp->sin6_addr;

	ipaddress.ifa.ifa_family = AF_INET6;
	ipaddress.ifa.ifa_prefixlen = 64;
	ipaddress.ifa.ifa_index = ifp->ifindex;

	if (netlink_ipaddress(&ipaddress, IPADDRESS_DEL) != 1)
		log_message(LOG_INFO, "Deleting link-local address from vmac failed");
	else
		CLEAR_IP6_ADDR(&ifp->sin6_addr);

	ipaddress.u.sin6_addr = ipaddress_new;
	if (netlink_ipaddress(&ipaddress, IPADDRESS_ADD) != 1) {
		log_message(LOG_INFO, "Adding link-local address to vmac failed");
		CLEAR_IP6_ADDR(&ifp->sin6_addr);

		return false;
	}

	/* Save the new address */
	ifp->sin6_addr = ipaddress.u.sin6_addr;

	return true;
}

#if !HAVE_DECL_IFLA_INET6_ADDR_GEN_MODE
void
remove_vmac_auto_gen_addr(interface_t *ifp, struct in6_addr *addr)
{
	struct in6_addr auto_addr;
	ip_address_t ipaddress;

	make_link_local_address(&auto_addr, ifp->hw_addr);

	if (!inaddr_equal(AF_INET6, &auto_addr, addr))
		return;

	/* Delete the new address */
	memset(&ipaddress, 0, sizeof(ipaddress));

	ipaddress.ifp = ifp;
	ipaddress.u.sin6_addr = *addr;

	ipaddress.ifa.ifa_family = AF_INET6;
	ipaddress.ifa.ifa_prefixlen = 64;
	ipaddress.ifa.ifa_index = ifp->ifindex;

	if (netlink_ipaddress(&ipaddress, IPADDRESS_DEL) != 1)
		log_message(LOG_INFO, "Deleting auto generated link-local address from vmac failed");
}
#endif

static int
netlink_link_up(vrrp_t *vrrp)
{
	int status = 1;
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
	} req;

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = (int)IF_INDEX(vrrp->ifp);
	req.ifi.ifi_change |= IFF_UP;
	req.ifi.ifi_flags |= IFF_UP;

	if (netlink_talk(&nl_cmd, &req.n) < 0)
		status = -1;

	return status;
}

bool
set_link_local_address(const vrrp_t *vrrp)
{
	/* Add link-local address. If a source address has been specified, use it,
	 * else use link-local address from underlying interface to vmac if there is one,
	 * otherwise construct a link-local address based on underlying interface's
	 * MAC address.
	 * This is so that VRRP advertisements will be sent from a non-VIP address, but
	 * using the VRRP MAC address */
	struct in6_addr addr;

	if (vrrp->saddr.ss_family == AF_INET6)
		addr = PTR_CAST_CONST(struct sockaddr_in6, &vrrp->saddr)->sin6_addr;
	else if (!IN6_IS_ADDR_UNSPECIFIED(&vrrp->configured_ifp->sin6_addr))
		addr = vrrp->configured_ifp->sin6_addr;
	else
		make_link_local_address(&addr, vrrp->configured_ifp->base_ifp->hw_addr);

	return add_link_local_address(vrrp->ifp, &addr);
}

bool
netlink_link_add_vmac(vrrp_t *vrrp)
{
	struct rtattr *linkinfo;
	struct rtattr *data;
	interface_t *ifp;
	bool create_interface = true;
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[256];
	} req;

	if (!vrrp->ifp || __test_bit(VRRP_VMAC_UP_BIT, &vrrp->vmac_flags) || !vrrp->vrid)
		return false;

	if (vrrp->family == AF_INET6)
		ll_addr[ETH_ALEN-2] = 0x02;
	else
		ll_addr[ETH_ALEN-2] = 0x01;

	ll_addr[ETH_ALEN-1] = vrrp->vrid;

	memset(&req, 0, sizeof (req));

	/*
	 * Check to see if this vmac interface was created
	 * by a previous instance.
	 */
	ifp = if_get_by_ifname(vrrp->vmac_ifname, IF_CREATE_ALWAYS);

	if (ifp->ifindex) {
		/* Check to see whether this interface has wrong mac ? */
		if (memcmp((const void *)ifp->hw_addr, (const void *)ll_addr, ETH_ALEN) != 0 ||
		     ifp->base_ifindex != vrrp->ifp->ifindex ||
		     ifp->vmac_type != MACVLAN_MODE_PRIVATE) {
			/* Be safe here - we don't want to remove a physical interface */
			if (ifp->vmac_type) {
				/* We have found a VIF but the vmac or type do not match */
				log_message(LOG_INFO, "(%s) Removing old VMAC interface %s due to conflicting "
						      "interface or MAC"
						    , vrrp->iname, vrrp->vmac_ifname);

				/* Request that NETLINK remove the VIF interface first */
				memset(&req, 0, sizeof (req));
				req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
				req.n.nlmsg_flags = NLM_F_REQUEST;
				req.n.nlmsg_type = RTM_DELLINK;
				req.ifi.ifi_family = AF_INET;
				req.ifi.ifi_index = (int)IF_INDEX(ifp);

				if (netlink_talk(&nl_cmd, &req.n) < 0) {
					log_message(LOG_INFO, "(%s) Error removing VMAC interface %s"
							    , vrrp->iname, vrrp->vmac_ifname);
					return false;
				}

				kernel_netlink_poll();	/* Update our local info */
			} else {
				log_message(LOG_INFO, "VMAC %s conflicts with existing interface", vrrp->vmac_ifname);
				return false;
			}
		}
		else
			create_interface = false;
	}

	ifp->is_ours = true;
	if (create_interface && vrrp->configured_ifp->base_ifp->ifindex) {
		/* Request that NETLINK create the VIF interface */
		req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
		req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
		req.n.nlmsg_type = RTM_NEWLINK;
		req.ifi.ifi_family = AF_UNSPEC;

		/* macvlan settings */
		linkinfo = PTR_CAST(struct rtattr, NLMSG_TAIL(&req.n));
		addattr_l(&req.n, sizeof(req), IFLA_LINKINFO, NULL, 0);
		addattr_l(&req.n, sizeof(req), IFLA_INFO_KIND, (const void *)macvlan_ll_kind, strlen(macvlan_ll_kind));
		data = PTR_CAST(struct rtattr, NLMSG_TAIL(&req.n));
		addattr_l(&req.n, sizeof(req), IFLA_INFO_DATA, NULL, 0);

		/*
		 * In private mode, macvlan will receive frames with same MAC addr
		 * as configured on the interface.
		 */
		addattr32(&req.n, sizeof(req), IFLA_MACVLAN_MODE,
			  MACVLAN_MODE_PRIVATE);
		data->rta_len = (unsigned short)((char *)NLMSG_TAIL(&req.n) - (char *)data);
		/* coverity[overrun-local] */
		linkinfo->rta_len = (unsigned short)((char *)NLMSG_TAIL(&req.n) - (char *)linkinfo);

		/* Note: if the underlying interface is a macvlan, then the kernel will configure the
		 * interface only the underlying interface of the macvlan */
		addattr32(&req.n, sizeof(req), IFLA_LINK, vrrp->configured_ifp->ifindex);
		addattr_l(&req.n, sizeof(req), IFLA_IFNAME, vrrp->vmac_ifname, strlen(vrrp->vmac_ifname));
		addattr_l(&req.n, sizeof(req), IFLA_ADDRESS, ll_addr, ETH_ALEN);

#ifdef _HAVE_VRF_
		/* If the underlying interface is enslaved to a VRF master, then this
		 * interface should be as well. */
		if (vrrp->configured_ifp->vrf_master_ifp)
			addattr32(&req.n, sizeof(req), IFLA_MASTER, vrrp->configured_ifp->vrf_master_ifp->ifindex);
#endif

		if (netlink_talk(&nl_cmd, &req.n) < 0) {
			log_message(LOG_INFO, "(%s): Unable to create VMAC interface %s"
					    , vrrp->iname, vrrp->vmac_ifname);
			return false;
		}

		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "(%s): Success creating VMAC interface %s"
					    , vrrp->iname, vrrp->vmac_ifname);

		/*
		 * Update interface queue and vrrp instance interface binding.
		 */
		netlink_interface_lookup(vrrp->vmac_ifname);
		if (!ifp->ifindex)
			return false;

		if (!ifp->base_ifp &&
		    IS_MAC_IP_VLAN(vrrp->configured_ifp) &&
		    vrrp->configured_ifp == vrrp->configured_ifp->base_ifp) {
			/* If the base interface is a MACVLAN/IPVLAN that has been moved into a
			 * different network namespace from its parent, we can't find the parent */
			ifp->base_ifp = ifp;
		}

		/* If we do anything that might cause the interface state to change, we must
		 * read the reflected netlink messages to ensure that the link status doesn't
		 * get updated by out of date queued messages */
		kernel_netlink_poll();
	}

	ifp->vmac_type = MACVLAN_MODE_PRIVATE;

	if (!ifp->ifindex)
		return false;

	if (vrrp->family == AF_INET) {
		/* Set the necessary kernel parameters to make macvlans work for us */
// If this saves current base_ifp's settings, we need to be careful if multiple VMACs on same i/f
		if (create_interface)
			set_interface_parameters(ifp, ifp->base_ifp);

		/* We don't want IPv6 running on the interface unless we have some IPv6
		 * eVIPs, so disable it if not needed */
		if (vrrp->family == AF_INET && !vrrp->evip_other_family)
			link_set_ipv6(ifp, false);
		else if (!create_interface) {
			/* If we didn't create the VMAC we don't know what state it is in */
			link_set_ipv6(ifp, true);
		}
	}

	if (vrrp->family == AF_INET6 || vrrp->evip_other_family) {
		/* Make sure IPv6 is enabled for the interface, in case the
		 * sysctl net.ipv6.conf.default.disable_ipv6 is set true. */
		link_set_ipv6(ifp, true);

		/* We don't want a link-local address auto assigned - see RFC5798 paragraph 7.4.
		 * If we have a sufficiently recent kernel, we can stop a link local address
		 * based on the MAC address being automatically assigned. If not, then we have
		 * to delete the generated address after bringing the interface up (see below).
		 */
#if HAVE_DECL_IFLA_INET6_ADDR_GEN_MODE
		memset(&req, 0, sizeof (req));
		req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
		req.n.nlmsg_flags = NLM_F_REQUEST ;
		req.n.nlmsg_type = RTM_NEWLINK;
		req.ifi.ifi_family = AF_UNSPEC;
		req.ifi.ifi_index = (int)vrrp->ifp->ifindex;

		struct rtattr* spec;

		spec = PTR_CAST(struct rtattr, NLMSG_TAIL(&req.n));
		addattr_l(&req.n, sizeof(req), IFLA_AF_SPEC, NULL,0);
		data = PTR_CAST(struct rtattr, NLMSG_TAIL(&req.n));
		addattr_l(&req.n, sizeof(req), AF_INET6, NULL,0);
		addattr8(&req.n, sizeof(req), IFLA_INET6_ADDR_GEN_MODE, IN6_ADDR_GEN_MODE_NONE);
		/* coverity[overrun-local] */
		data->rta_len = (unsigned short)((char *)NLMSG_TAIL(&req.n) - (char *)data);
		spec->rta_len = (unsigned short)((char *)NLMSG_TAIL(&req.n) - (char *)spec);

		if (netlink_talk(&nl_cmd, &req.n) < 0)
			log_message(LOG_INFO, "(%s) Error setting ADDR_GEN_MODE to NONE on %s", vrrp->iname, vrrp->ifp->ifname);
#endif

		if (vrrp->family == AF_INET6 &&
		    !__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags)) {
			if (!set_link_local_address(vrrp) && create_interface)
				log_message(LOG_INFO, "(%s) adding link-local address to %s failed", vrrp->iname, vrrp->ifp->ifname);
		}
	}

#ifdef _WITH_FIREWALL_
	if (vrrp->family == AF_INET6 || !global_data->disable_local_igmp)
		firewall_add_vmac(vrrp);
#endif

	/* bring it UP ! */
	__set_bit(VRRP_VMAC_UP_BIT, &vrrp->vmac_flags);
	netlink_link_up(vrrp);

#if !HAVE_DECL_IFLA_INET6_ADDR_GEN_MODE
	if (vrrp->family == AF_INET6 || vrrp->evip_other_family) {
		/* Delete the automatically created link-local address based on the
		 * MAC address if we weren't able to configure the interface not to
		 * create the address (see above).
		 * This isn't ideal, since the invalid address will exist momentarily,
		 * but is there any better way to do it? probably not otherwise
		 * ADDR_GEN_MODE wouldn't have been added to the kernel. */
		ip_address_t ipaddress;

		memset(&ipaddress, 0, sizeof(ipaddress));

		ipaddress.u.sin6_addr = ifp->base_ifp->sin6_addr;
		make_link_local_address(&ipaddress.u.sin6_addr, ll_addr);
		ipaddress.ifa.ifa_family = AF_INET6;
		ipaddress.ifa.ifa_prefixlen = 64;
		ipaddress.ifa.ifa_index = vrrp->ifp->ifindex;
		ipaddress.ifp = vrrp->ifp;

		if (netlink_ipaddress(&ipaddress, IPADDRESS_DEL) != 1 && create_interface)
			log_message(LOG_INFO, "Deleting auto link-local address from vmac failed");
	}
#endif

	/* If we are adding a large number of interfaces, the netlink socket
	 * may run out of buffers if we don't receive the netlink messages
	 * as we progress */
	kernel_netlink_poll();

	return true;
}

#ifdef _INCLUDE_UNUSED_CODE_
typedef struct {
	struct nlmsghdr n;
	struct ifinfomsg ifi;
	char buf[256];
} req_t;
static void
dump_bufn(const char *msg, req_t *req)
{
	size_t i;
	char buf[3 * req->n.nlmsg_len + 3];
	char *ptr = buf;

	log_message(LOG_INFO, "%s: message length is %d\n", msg, req->n.nlmsg_len);
	for (i = 0; i < req->n.nlmsg_len; i++)
		ptr += snprintf(ptr, buf + sizeof buf - ptr, "%2.2x ", PTR_CAST(unsigned char, &req->n)[i]);
	log_message(LOG_INFO, "%s", buf);
}
#endif

#ifdef _HAVE_VRRP_IPVLAN_
bool
netlink_link_add_ipvlan(vrrp_t *vrrp)
{
	struct rtattr *linkinfo;
	struct rtattr *data;
	interface_t *ifp;
	bool create_interface = true;
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[256];
	} req;

	if (!vrrp->ifp || __test_bit(VRRP_VMAC_UP_BIT, &vrrp->vmac_flags) || !vrrp->vrid)
		return false;

	memset(&req, 0, sizeof (req));

	/*
	 * Check to see if this ipvlan interface was created
	 * by a previous instance.
	 */
	ifp = if_get_by_ifname(vrrp->vmac_ifname, IF_CREATE_ALWAYS);

	if (ifp->ifindex)
		create_interface = false;

	ifp->is_ours = true;
	if (create_interface && vrrp->configured_ifp->base_ifp->ifindex) {
		/* Request that NETLINK create the VIF interface */
		req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
		req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
		req.n.nlmsg_type = RTM_NEWLINK;
		req.ifi.ifi_family = AF_UNSPEC;

		/* ipvlan settings */

		/* Note: if the underlying interface is a ipvlan, then the kernel will configure the
		 * interface only the underlying interface of the ipvlan */
		addattr32(&req.n, sizeof(req), IFLA_LINK, vrrp->configured_ifp->ifindex);
		addattr_l(&req.n, sizeof(req), IFLA_IFNAME, vrrp->vmac_ifname, strlen(vrrp->vmac_ifname));
		linkinfo = PTR_CAST(struct rtattr, NLMSG_TAIL(&req.n));
		addattr_l(&req.n, sizeof(req), IFLA_LINKINFO, NULL, 0);
		addattr_l(&req.n, sizeof(req), IFLA_INFO_KIND, (const void *)ipvlan_ll_kind, strlen(ipvlan_ll_kind));
		data = PTR_CAST(struct rtattr, NLMSG_TAIL(&req.n));
		addattr_l(&req.n, sizeof(req), IFLA_INFO_DATA, NULL, 0);

		/*
		 * In l2 mode, ipvlan will receive frames.
		 */
		addattr16(&req.n, sizeof(req), IFLA_IPVLAN_MODE, IPVLAN_MODE_L2);
#ifdef IFLA_IPVLAN_FLAGS
		addattr16(&req.n, sizeof(req), IFLA_IPVLAN_FLAGS, vrrp->ipvlan_type);
#endif
		/* coverity[overrun-local] */
		data->rta_len = (unsigned short)((char *)NLMSG_TAIL(&req.n) - (char *)data);
		linkinfo->rta_len = (unsigned short)((char *)NLMSG_TAIL(&req.n) - (char *)linkinfo);

#ifdef _HAVE_VRF_
		/* If the underlying interface is enslaved to a VRF master, then this
		 * interface should be as well. */
		if (vrrp->configured_ifp->vrf_master_ifp)
			addattr32(&req.n, sizeof(req), IFLA_MASTER, vrrp->configured_ifp->vrf_master_ifp->ifindex);
#endif

		if (netlink_talk(&nl_cmd, &req.n) < 0) {
			log_message(LOG_INFO, "(%s): Unable to create ipvlan interface %s"
					    , vrrp->iname, vrrp->vmac_ifname);
			return false;
		}

		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "(%s): Success creating ipvlan interface %s"
					    , vrrp->iname, vrrp->vmac_ifname);

		/*
		 * Update interface queue and vrrp instance interface binding.
		 */
		netlink_interface_lookup(vrrp->vmac_ifname);
		if (!ifp->ifindex)
			return false;

		if (!ifp->base_ifp &&
		    (vrrp->configured_ifp->if_type == IF_TYPE_MACVLAN ||
		     vrrp->configured_ifp->if_type == IF_TYPE_IPVLAN) &&
		    vrrp->configured_ifp == vrrp->configured_ifp->base_ifp) {
			/* If the base interface is a MACVLAN that has been moved into a
			 * different network namespace from its parent, we can't find the parent */
			ifp->base_ifp = ifp;
		}

		/* If we do anything that might cause the interface state to change, we must
		 * read the reflected netlink messages to ensure that the link status doesn't
		 * get updated by out of date queued messages */
		kernel_netlink_poll();
	}

	ifp->vmac_type = IPVLAN_MODE_L2;

	if (!ifp->ifindex)
		return false;

	if (vrrp->family == AF_INET) {
		/* We don't want IPv6 running on the interface unless we have some IPv6
		 * eVIPs, so disable it if not needed */
		if (vrrp->family == AF_INET && !vrrp->evip_other_family)
			link_set_ipv6(ifp, false);
		else if (!create_interface) {
			/* If we didn't create the VMAC we don't know what state it is in */
			link_set_ipv6(ifp, true);
		}
	}

	if (vrrp->family == AF_INET6 || vrrp->evip_other_family) {
		/* Make sure IPv6 is enabled for the interface, in case the
		 * sysctl net.ipv6.conf.default.disable_ipv6 is set true. */
		link_set_ipv6(ifp, true);
	}

	/* bring it UP ! */
	__set_bit(VRRP_VMAC_UP_BIT, &vrrp->vmac_flags);
	netlink_link_up(vrrp);
	kernel_netlink_poll();

	if (vrrp->ipvlan_addr) {
		if (netlink_ipaddress(vrrp->ipvlan_addr, IPADDRESS_ADD) != 1)
			log_message(LOG_INFO, "%s: Failed to add interface address to %s", vrrp->iname, ifp->ifname);
		else {
			if (vrrp->ipvlan_addr->ifa.ifa_family == AF_INET)
				ifp->sin_addr = vrrp->ipvlan_addr->u.sin.sin_addr;
			else
				ifp->sin6_addr = vrrp->ipvlan_addr->u.sin6_addr;
		}
	}

	return true;
}
#endif

void
netlink_link_del_vmac(vrrp_t *vrrp)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[256];
	} req;

	if (!vrrp->ifp)
		return;

	/* Don't delete the VMAC if it isn't an interface we created */
	if (!vrrp->ifp->is_ours) {
		log_message(LOG_INFO, "BUG - Attempt to remove VMAC interface %s which we didn't create", vrrp->ifp->ifname);
		return;
	}

	/* Reset arp_ignore and arp_filter on the base interface if necessary */
	if (vrrp->family == AF_INET) {
		if (vrrp->ifp->base_ifp)
			reset_interface_parameters(vrrp->ifp->base_ifp);
		else
			log_message(LOG_INFO, "Unable to find base interface for vrrp instance %s", vrrp->iname);
	}

	/* If the interface doesn't exist, don't try to delete it */
	if (!vrrp->ifp->ifindex)
		return;

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_DELLINK;
	req.ifi.ifi_family = AF_INET;
	req.ifi.ifi_index = (int)vrrp->ifp->ifindex;

	if (netlink_talk(&nl_cmd, &req.n) < 0) {
		log_message(LOG_INFO, "(%s) Error removing VMAC interface %s"
				    , vrrp->iname, vrrp->vmac_ifname);
		return;
	}

#ifdef _WITH_FIREWALL_
// Why do we need this test?
// PROBLEM !!! We have deleted the link, but firewall_remove_vmac uses the ifindex.
	if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags) &&
	    (vrrp->family == AF_INET6 || !global_data->disable_local_igmp))
		firewall_remove_vmac(vrrp);
#endif

	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "(%s) Success removing VMAC interface %s"
				    , vrrp->iname, vrrp->vmac_ifname);

	/* Ensure we don't try and recreate the interface */
	vrrp->ifp->deleting = true;

	kernel_netlink_poll();

	vrrp->ifp->deleting = false;

	vrrp->ifp->is_ours = false;

	return;
}

#ifdef _HAVE_VRF_
static void
netlink_update_vrf(vrrp_t *vrrp)
{
	int ifindex = 0;
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[256];
	} req;

	if (!vrrp->ifp)
		return;

	/* Don't update the VMAC if it isn't an interface we created */
	if (!vrrp->ifp->is_ours) {
		log_message(LOG_INFO, "BUG - Attempt to update VRF on VMAC interface %s which we didn't create", vrrp->ifp->ifname);
		return;
	}

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.ifi.ifi_family = AF_INET;
	req.ifi.ifi_index = (int)vrrp->ifp->ifindex;

	if (vrrp->ifp->vrf_master_ifp)
		ifindex = vrrp->ifp->vrf_master_ifp->ifindex;

	addattr32(&req.n, sizeof(req), IFLA_MASTER, ifindex);

	if (netlink_talk(&nl_cmd, &req.n) < 0) {
		log_message(LOG_INFO, "vmac: Error changing VRF of VMAC interface %s for vrrp_instance %s!!!", vrrp->ifp->ifname, vrrp->iname);
		return;
	}

	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "vmac: Success changing VRF of VMAC interface %s for vrrp_instance %s", vrrp->ifp->ifname, vrrp->iname);

	kernel_netlink_poll();

	return;
}

void
update_vmac_vrfs(interface_t *ifp)
{
	tracking_obj_t *top;
	vrrp_t *vrrp;

	list_for_each_entry(top, &ifp->tracking_vrrp, e_list) {
		vrrp = top->obj.vrrp;

		/* We only need to look for vmacs we created that
		 * are configured on the interface which has changed
		 * VRF */
		if (vrrp->configured_ifp != ifp ||
		    !vrrp->ifp->is_ours)
			continue;

		vrrp->ifp->vrf_master_ifp = ifp->vrf_master_ifp;

		if (vrrp->ifp->ifindex)
			netlink_update_vrf(vrrp);
	}
}
#endif
