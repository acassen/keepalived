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
#ifdef NETLINK_H_NEEDS_SYS_SOCKET_H
#include <sys/socket.h>
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

const char * const macvlan_ll_kind = "macvlan";
u_char ll_addr[ETH_ALEN] = {0x00, 0x00, 0x5e, 0x00, 0x01, 0x00};

static void
make_link_local_address(struct in6_addr* l3_addr, const u_char* ll_addr)
{
	l3_addr->s6_addr[0] = 0xfe;
	l3_addr->s6_addr[1] = 0x80;
	l3_addr->s6_addr16[1] = 0;
	l3_addr->s6_addr32[1] = 0;
	l3_addr->s6_addr[8] = ll_addr[0] ^ 0x02;
	l3_addr->s6_addr[9] = ll_addr[1];
	l3_addr->s6_addr[10] = ll_addr[2];
	l3_addr->s6_addr[11] = 0xff;
	l3_addr->s6_addr[12] = 0xfe;
	l3_addr->s6_addr[13] = ll_addr[3];
	l3_addr->s6_addr[14] = ll_addr[4];
	l3_addr->s6_addr[15] = ll_addr[5];
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
		ifp->sin6_addr.s6_addr32[0] = 0;

		return false;
	}

	/* Save the new address */
	ifp->sin6_addr = ipaddress.u.sin6_addr;

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
		ifp->sin6_addr.s6_addr32[0] = 0;

	ipaddress.u.sin6_addr = ipaddress_new;
	if (netlink_ipaddress(&ipaddress, IPADDRESS_ADD) != 1) {
		log_message(LOG_INFO, "Adding link-local address to vmac failed");
		ifp->sin6_addr.s6_addr32[0] = 0;

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
	if ((ifp = if_get_by_ifname(vrrp->vmac_ifname, IF_CREATE_ALWAYS)) &&
	     ifp->ifindex) {
		/* Check to see whether this interface has wrong mac ? */
		if ((memcmp((const void *) ifp->hw_addr, (const void *) ll_addr, ETH_ALEN) != 0 ||
		     ifp->base_ifindex != vrrp->ifp->ifindex)) {

			/* Be safe here - we don't want to remove a physical interface */
			if (ifp->vmac) {
				/* We have found a VIF but the vmac do not match */
				log_message(LOG_INFO, "vmac: Removing old VMAC interface %s due to conflicting "
						      "interface or MAC for vrrp_instance %s!!!"
						    , vrrp->vmac_ifname, vrrp->iname);

				/* Request that NETLINK remove the VIF interface first */
				memset(&req, 0, sizeof (req));
				req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
				req.n.nlmsg_flags = NLM_F_REQUEST;
				req.n.nlmsg_type = RTM_DELLINK;
				req.ifi.ifi_family = AF_INET;
				req.ifi.ifi_index = (int)IF_INDEX(ifp);

				if (netlink_talk(&nl_cmd, &req.n) < 0) {
					log_message(LOG_INFO, "vmac: Error removing VMAC interface %s for "
							      "vrrp_instance %s!!!"
							    , vrrp->vmac_ifname, vrrp->iname);
					return false;
				}
			}
		}
		else
			create_interface = false;
	}

	if (create_interface && vrrp->ifp->base_ifp->ifindex) {
		/* Request that NETLINK create the VIF interface */
		req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
		req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
		req.n.nlmsg_type = RTM_NEWLINK;
		req.ifi.ifi_family = AF_INET;

		/* macvlan settings */
		linkinfo = NLMSG_TAIL(&req.n);
		addattr_l(&req.n, sizeof(req), IFLA_LINKINFO, NULL, 0);
		addattr_l(&req.n, sizeof(req), IFLA_INFO_KIND, (void *)macvlan_ll_kind, strlen(macvlan_ll_kind));
		data = NLMSG_TAIL(&req.n);
		addattr_l(&req.n, sizeof(req), IFLA_INFO_DATA, NULL, 0);

		/*
		 * In private mode, macvlan will receive frames with same MAC addr
		 * as configured on the interface.
		 */
		addattr32(&req.n, sizeof(req), IFLA_MACVLAN_MODE,
			  MACVLAN_MODE_PRIVATE);
		data->rta_len = (unsigned short)((void *)NLMSG_TAIL(&req.n) - (void *)data);
		linkinfo->rta_len = (unsigned short)((void *)NLMSG_TAIL(&req.n) - (void *)linkinfo);
		addattr_l(&req.n, sizeof(req), IFLA_LINK, &vrrp->ifp->base_ifp->ifindex, sizeof(uint32_t));
		addattr_l(&req.n, sizeof(req), IFLA_IFNAME, vrrp->vmac_ifname, strlen(vrrp->vmac_ifname));
		addattr_l(&req.n, sizeof(req), IFLA_ADDRESS, ll_addr, ETH_ALEN);

		if (netlink_talk(&nl_cmd, &req.n) < 0) {
			log_message(LOG_INFO, "(%s): Unable to create VMAC interface %s"
					    , vrrp->iname, vrrp->vmac_ifname);
			return false;
		}

		log_message(LOG_INFO, "(%s): Success creating VMAC interface %s"
				    , vrrp->iname, vrrp->vmac_ifname);

		/*
		 * Update interface queue and vrrp instance interface binding.
		 */
		netlink_interface_lookup(vrrp->vmac_ifname);
		if (!ifp->ifindex)
			return false;

		/* If we do anything that might cause the interface state to change, we must
		 * read the reflected netlink messages to ensure that the link status doesn't
		 * get updated by out of date queued messages */
		kernel_netlink_poll();
	}

	ifp->vmac = true;

	if (!ifp->ifindex)
		return false;

	if (vrrp->family == AF_INET) {
		/* Set the necessary kernel parameters to make macvlans work for us */
		if (create_interface)
			set_interface_parameters(ifp, ifp->base_ifp);

		/* We don't want IPv6 running on the interface unless we have some IPv6
		 * eVIPs, so disable it if not needed */
		if (!vrrp->evip_add_ipv6)
			link_set_ipv6(ifp, false);
		else if (!create_interface) {
			/* If we didn't create the VMAC we don't know what state it is in */
			link_set_ipv6(ifp, true);
		}
	}

	if (vrrp->family == AF_INET6 || vrrp->evip_add_ipv6) {
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

		spec = NLMSG_TAIL(&req.n);
		addattr_l(&req.n, sizeof(req), IFLA_AF_SPEC, NULL,0);
		data = NLMSG_TAIL(&req.n);
		addattr_l(&req.n, sizeof(req), AF_INET6, NULL,0);
		addattr8(&req.n, sizeof(req), IFLA_INET6_ADDR_GEN_MODE, IN6_ADDR_GEN_MODE_NONE);
		data->rta_len = (unsigned short)((void *)NLMSG_TAIL(&req.n) - (void *)data);
		spec->rta_len = (unsigned short)((void *)NLMSG_TAIL(&req.n) - (void *)spec);

		if (netlink_talk(&nl_cmd, &req.n) < 0)
			log_message(LOG_INFO, "vmac: Error setting ADDR_GEN_MODE to NONE");
#endif

		if (vrrp->family == AF_INET6 &&
		    !__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags)) {
			/* Add link-local address. If a source address has been specified, use it,
			 * else use link-local address from underlying interface to vmac if there is one,
			 * otherwise construct a link-local address based on underlying interface's
			 * MAC address.
			 * This is so that VRRP advertisements will be sent from a non-VIP address, but
			 * using the VRRP MAC address */
			ip_address_t ipaddress;

			memset(&ipaddress, 0, sizeof(ipaddress));

			ipaddress.ifp = ifp;
			if (vrrp->saddr.ss_family == AF_INET6)
				ipaddress.u.sin6_addr = ((struct sockaddr_in6*)&vrrp->saddr)->sin6_addr;
			else if (ifp->base_ifp->sin6_addr.s6_addr32[0])
				ipaddress.u.sin6_addr = ifp->base_ifp->sin6_addr;
			else
				make_link_local_address(&ipaddress.u.sin6_addr, ifp->base_ifp->hw_addr);
			ipaddress.ifa.ifa_family = AF_INET6;
			ipaddress.ifa.ifa_prefixlen = 64;
			ipaddress.ifa.ifa_index = vrrp->ifp->ifindex;

			if (netlink_ipaddress(&ipaddress, IPADDRESS_ADD) != 1 && create_interface)
				log_message(LOG_INFO, "Adding link-local address to vmac failed");
		}
	}

	/* bring it UP ! */
	__set_bit(VRRP_VMAC_UP_BIT, &vrrp->vmac_flags);
	netlink_link_up(vrrp);
	kernel_netlink_poll();

#if !HAVE_DECL_IFLA_INET6_ADDR_GEN_MODE
	if (vrrp->family == AF_INET6 || vrrp->evip_add_ipv6) {
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

bool
netlink_link_del_vmac(vrrp_t *vrrp)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[256];
	} req;

	if (!vrrp->ifp)
		return false;

	/* Make sure we don't remove a real interface */
	if (!vrrp->ifp->vmac) {
		log_message(LOG_INFO, "BUG - Attempting to remove non VMAC i/f %s", vrrp->ifp->ifname);
		return false;
	}

	/* Reset arp_ignore and arp_filter on the base interface if necessary */
	if (vrrp->family == AF_INET) {
		if (vrrp->ifp->base_ifp)
			reset_interface_parameters(vrrp->ifp->base_ifp);
		else
			log_message(LOG_INFO, "Unable to find base interface for vrrp instance %s", vrrp->iname);
	}

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_DELLINK;
	req.ifi.ifi_family = AF_INET;
	req.ifi.ifi_index = (int)vrrp->ifp->ifindex;

	if (netlink_talk(&nl_cmd, &req.n) < 0) {
		log_message(LOG_INFO, "vmac: Error removing VMAC interface %s for vrrp_instance %s!!!"
				    , vrrp->vmac_ifname, vrrp->iname);
		return false;
	}

	log_message(LOG_INFO, "vmac: Success removing VMAC interface %s for vrrp_instance %s"
			    , vrrp->vmac_ifname, vrrp->iname);

	return true;
}
