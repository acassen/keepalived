/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Interfaces manipulation.
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
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <syslog.h>
#include <inttypes.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <stdio.h>
#include <linux/mii.h>
#if defined _HAVE_NETINET_LINUX_IF_ETHER_H_COLLISION_ && \
    defined _LINUX_IF_ETHER_H && \
    !defined _NETINET_IF_ETHER_H
/* musl libc throws an error if <linux/if_ether.h> is included before <netinet/if_ether.h>,
 * so we stop <netinet/if_ether.h> being included if <linux/if_ether.h> has been included. */
#define _NETINET_IF_ETHER_H
#endif
#include <linux/sockios.h>	/* needed to get correct values for SIOC* */
#include <linux/ethtool.h>
#include <net/if_arp.h>
#include <time.h>
#include <linux/filter.h>

/* local include */
#include "global_data.h"
#include "vrrp.h"
#include "vrrp_if.h"
#include "vrrp_daemon.h"
#include "keepalived_netlink.h"
#include "utils.h"
#include "logger.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_vmac.h"
#include "bitops.h"
#endif
#include "track_file.h"
#include "vrrp_track.h"
#include "vrrp_scheduler.h"
#include "vrrp_iproute.h"
#ifdef THREAD_DUMP
#include "scheduler.h"
#endif
#ifdef _WITH_FIREWALL_
#include "vrrp_firewall.h"
#endif


/* Local vars */
static LIST_HEAD_INITIALIZE(if_queue);
#ifdef _WITH_LINKBEAT_
static struct ifreq ifr;
static int linkbeat_fd = -1;
#endif

static LIST_HEAD_INITIALIZE(old_garp_delay);

/* Global vars */
LIST_HEAD_INITIALIZE(garp_delay);

/* Helper functions */
interface_t * __attribute__ ((pure))
if_get_by_ifindex(ifindex_t ifindex)
{
	interface_t *ifp;

	list_for_each_entry(ifp, &if_queue, e_list) {
		if (ifp->ifindex == ifindex)
			return ifp;
	}

	return NULL;
}

#ifdef _HAVE_VRRP_VMAC_
interface_t * __attribute__ ((pure))
if_get_by_vmac(uint8_t vrid, int family, const interface_t *base_ifp)
{
	interface_t *ifp;

	list_for_each_entry(ifp, &if_queue, e_list) {
		if (ifp->if_type != IF_TYPE_MACVLAN || ifp->vmac_type !=  MACVLAN_MODE_PRIVATE)
			continue;
		if (ifp->base_ifp != base_ifp)
			continue;
		if (ifp->hw_addr[0] || ifp->hw_addr[1] || ifp->hw_addr[2] != 0x5e || ifp->hw_addr[3])
			continue;
		if ((family == AF_INET && ifp->hw_addr[4] != 0x01) ||
		    (family == AF_INET6 && ifp->hw_addr[4] != 0x02))
			continue;
		if (ifp->hw_addr[5] != vrid)
			continue;

		ifp->is_ours = true;

		return ifp;
	}

	return NULL;
}
#endif

interface_t *
get_default_if(void)
{
	const char *ifname = global_data->default_ifname ? global_data->default_ifname : DFLT_INT;

	if (!global_data->default_ifp)
		global_data->default_ifp = if_get_by_ifname(ifname, IF_CREATE_IF_DYNAMIC);

	return global_data->default_ifp;
}

sin_addr_t *
if_extra_ipaddress_alloc(interface_t *ifp, void *addr, unsigned char family)
{
	sin_addr_t *saddr;

	PMALLOC(saddr);
	INIT_LIST_HEAD(&saddr->e_list);

	if (family == AF_INET) {
		saddr->u.sin_addr = *PTR_CAST(struct in_addr, addr);
		list_add_tail(&saddr->e_list, &ifp->sin_addr_l);
		return saddr;
	}

	if (family == AF_INET6) {
		saddr->u.sin6_addr = *PTR_CAST(struct in6_addr, addr);
		list_add_tail(&saddr->e_list, &ifp->sin6_addr_l);
		return saddr;
	}

	FREE(saddr);
	return NULL;
}

void
if_extra_ipaddress_free(sin_addr_t *addr)
{
	list_del_init(&addr->e_list);
	FREE(addr);
}

void
if_extra_ipaddress_free_list(list_head_t *l)
{
	sin_addr_t *addr, *addr_tmp;

	list_for_each_entry_safe(addr, addr_tmp, l, e_list)
		if_extra_ipaddress_free(addr);
}

static void
if_tracking_vrrp_dump_list(FILE *fp, const list_head_t *l)
{
	tracking_obj_t *top;

	list_for_each_entry(top, l, e_list)
		dump_tracking_vrrp(fp, top);
}

interface_t *
if_get_by_ifname(const char *ifname, if_lookup_t create)
{
	interface_t *ifp;

	list_for_each_entry(ifp, &if_queue, e_list) {
		if (!strcmp(ifp->ifname, ifname))
			return create == IF_CREATE_NOT_EXIST ? NULL : ifp;
	}

	if (create == IF_NO_CREATE ||
	    (create == IF_CREATE_IF_DYNAMIC && (!global_data || !global_data->dynamic_interfaces))) {
		if (create == IF_CREATE_IF_DYNAMIC)
			non_existent_interface_specified = true;
		return NULL;
	}

	if (!(ifp = MALLOC(sizeof(interface_t))))
		return NULL;

	strcpy_safe(ifp->ifname, ifname);
#ifdef _HAVE_VRRP_VMAC_
	ifp->base_ifp = ifp;
	ifp->if_type = IF_TYPE_STANDARD;
#endif
	INIT_LIST_HEAD(&ifp->sin_addr_l);
	INIT_LIST_HEAD(&ifp->sin6_addr_l);
	INIT_LIST_HEAD(&ifp->tracking_vrrp);
	INIT_LIST_HEAD(&ifp->e_list);
	list_add_tail(&ifp->e_list, &if_queue);

	if (create == IF_CREATE_IF_DYNAMIC)
		log_message(LOG_INFO, "Configuration specifies interface %s which doesn't currently exist - will use if created", ifname);

	return ifp;
}

#ifdef _HAVE_VRRP_VMAC_
/* Set the base_ifp for VMACs and IPVLANs and vrf_master_ifp for VRFs - only used at startup */
static void
set_base_ifp(void)
{
	interface_t *ifp;
#ifdef _HAVE_VRF_
	interface_t *master_ifp;
#endif

	list_for_each_entry(ifp, &if_queue, e_list) {
		if ((!ifp->base_ifp || ifp == ifp->base_ifp) && ifp->base_ifindex) {
#ifdef HAVE_IFLA_LINK_NETNSID
			if (ifp->base_netns_id != -1)
				ifp->base_ifp = NULL;
			else
#endif
				ifp->base_ifp = if_get_by_ifindex(ifp->base_ifindex);

			/* If this is a MACVLAN/IPVLAN that has been moved into a separate network namespace
			 * from its parent, then we can't get information about the parent. */
			if (!ifp->base_ifp)
				ifp->base_ifp = ifp;
			else
				ifp->base_ifindex = 0;	/* This is only used at startup, so ensure not used later */
		}

#ifdef _HAVE_VRF_
		/* Now see if the interface is enslaved to a VRF */
		if (ifp->vrf_master_ifindex) {
			master_ifp = if_get_by_ifindex(ifp->vrf_master_ifindex);
			if (master_ifp && master_ifp->vrf_master_ifp == master_ifp)
				ifp->vrf_master_ifp = master_ifp;
			ifp->vrf_master_ifindex = 0;
		}
#endif
	}
}
#endif


#ifdef _WITH_LINKBEAT_
/* MII Transceiver Registers poller functions */
static uint16_t
if_mii_read(int fd, uint16_t phy_id, uint16_t reg_num)
{
	struct mii_ioctl_data *data = PTR_CAST(struct mii_ioctl_data, &ifr.ifr_data);

	data->phy_id = phy_id;
	data->reg_num = reg_num;

	if (ioctl(fd, SIOCGMIIREG, &ifr) < 0) {
		log_message(LOG_ERR, "SIOCGMIIREG on %s failed: %s", ifr.ifr_name, strerror(errno));
		return 0xffff;
	}
	return data->val_out;
}

#ifdef _INCLUDE_UNUSED_CODE_
static void if_mii_dump(const uint16_t *mii_regs, size_t num_regs, unsigned phy_id)
{
	int mii_reg;

	printf(" MII PHY #%d transceiver registers:", phy_id);
	for (mii_reg = 0; mii_reg < num_regs; mii_reg++)
		printf("%s %4.4x", (mii_reg % 8) == 0 ? "\n ":"", mii_regs[mii_reg]);
	printf("\n");
}
#endif

static int
if_mii_status(const int fd)
{
	struct mii_ioctl_data *data = PTR_CAST(struct mii_ioctl_data, &ifr.ifr_data);
	uint16_t phy_id = data->phy_id;
	uint16_t bmsr, new_bmsr;

	if (if_mii_read(fd, phy_id, MII_BMCR) == 0xffff ||
	    (bmsr = if_mii_read(fd, phy_id, MII_BMSR)) == 0) {
		log_message(LOG_ERR, "No MII transceiver present for %s !!!", ifr.ifr_name);
		return -1;
	}

// if_mii_dump(mii_regs, sizeof(mii_regs)/ sizeof(mii_regs[0], phy_id);

	/*
	 * For Basic Mode Status Register (BMSR).
	 * Sticky field (Link established & Jabber detected), we need to read
	 * a second time the BMSR to get current status.
	 */
	new_bmsr = if_mii_read(fd, phy_id, MII_BMSR);

// log_message(LOG_INFO, " \nBasic Mode Status Register 0x%4.4x ... 0x%4.4x\n", bmsr, new_bmsr);

	if (bmsr & BMSR_LSTATUS ||
	    new_bmsr & BMSR_LSTATUS)
		return LINK_UP;

	return LINK_DOWN;
}

static int
if_mii_probe(const int fd, const char *ifname)
{
	struct mii_ioctl_data *data = PTR_CAST(struct mii_ioctl_data, &ifr.ifr_data);
	uint16_t phy_id;

	memset(&ifr, 0, sizeof (struct ifreq));
	strcpy_safe(ifr.ifr_name, ifname);
	if (ioctl(fd, SIOCGMIIPHY, &ifr) < 0)
		return -1;

	/* check if the driver reports BMSR using the MII interface, as we
	 * will need this and we already know that some don't support it.
	 */
	phy_id = data->phy_id; /* save it in case it is overwritten */
	data->reg_num = MII_BMSR;
	if (ioctl(fd, SIOCGMIIREG, &ifr) < 0)
		return -1;
	data->phy_id = phy_id;

	/* Dump the MII transceiver */
	return if_mii_status(fd);
}

static inline int
if_ethtool_status(const int fd)
{
	struct ethtool_value edata;

	edata.cmd = ETHTOOL_GLINK;
	ifr.ifr_data = (caddr_t) & edata;
	if (ioctl(fd, SIOCETHTOOL, &ifr))
		return -1;

	return (edata.data) ? LINK_UP : LINK_DOWN;
}

static int
if_ethtool_probe(const int fd, const interface_t *ifp)
{
	int status;

	memset(&ifr, 0, sizeof (struct ifreq));
	strcpy_safe(ifr.ifr_name, ifp->ifname);

	status = if_ethtool_status(fd);

	return status;
}

/* Returns false if interface is down */
static bool
if_ioctl_flags(const int fd, interface_t *ifp)
{
	memset(&ifr, 0, sizeof (struct ifreq));
	strcpy(ifr.ifr_name, ifp->ifname);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
		return (errno != ENODEV) ? LINK_UP : LINK_DOWN;

	return FLAGS_UP(ifr.ifr_flags) ? LINK_UP : LINK_DOWN;
}
#endif

/* garp_delay facility function */
void
free_garp_delay(garp_delay_t *gd)
{
	list_del_init(&gd->e_list);
	FREE(gd);
}
static void
free_garp_delay_list(list_head_t *l)
{
	garp_delay_t *gd, *gd_tmp;

	list_for_each_entry_safe(gd, gd_tmp, l, e_list)
		free_garp_delay(gd);
}

static void
dump_garp_delay(FILE *fp, const garp_delay_t *gd)
{
	char time_str[26];
	interface_t *ifp;

	conf_write(fp, "------< GARP delay group %d >------", gd->aggregation_group);

	if (gd->have_garp_interval) {
		conf_write(fp, " GARP interval = %g", gd->garp_interval.tv_sec + ((double)gd->garp_interval.tv_usec) / 1000000);
		if (!ctime_r(&gd->garp_next_time.tv_sec, time_str))
			strcpy(time_str, "invalid time ");
		conf_write(fp, " GARP next time %ld.%6.6ld (%.19s.%6.6ld)", gd->garp_next_time.tv_sec, gd->garp_next_time.tv_usec, time_str, gd->garp_next_time.tv_usec);
	}

	if (gd->have_gna_interval) {
		conf_write(fp, " GNA interval = %g", gd->gna_interval.tv_sec + ((double)gd->gna_interval.tv_usec) / 1000000);
		if (!ctime_r(&gd->gna_next_time.tv_sec, time_str))
			strcpy(time_str, "invalid time ");
		conf_write(fp, " GNA next time %ld.%6.6ld (%.19s.%6.6ld)", gd->gna_next_time.tv_sec, gd->gna_next_time.tv_usec, time_str, gd->gna_next_time.tv_usec);
	}
	else if (!gd->have_garp_interval)
		conf_write(fp, " No configuration");

	conf_write(fp, " Interfaces");
	list_for_each_entry(ifp, &if_queue, e_list) {
		if (ifp->garp_delay == gd)
			conf_write(fp, "  %s", ifp->ifname);
	}
}
void
dump_garp_delay_list(FILE *fp, list_head_t *l)
{
	garp_delay_t *gd;

	list_for_each_entry(gd, l, e_list)
		dump_garp_delay(fp, gd);
}

garp_delay_t *
alloc_garp_delay(void)
{
	garp_delay_t *gd;

	PMALLOC(gd);
	INIT_LIST_HEAD(&gd->e_list);

	list_add_tail(&gd->e_list, &garp_delay);
	return gd;
}

static void
set_garp_delay(interface_t *ifp, const garp_delay_t *delay)
{
	ifp->garp_delay = alloc_garp_delay();

	ifp->garp_delay->garp_interval = delay->garp_interval;
	ifp->garp_delay->have_garp_interval = delay->have_garp_interval;
	ifp->garp_delay->gna_interval = delay->gna_interval;
	ifp->garp_delay->have_gna_interval = delay->have_gna_interval;
}

void
set_default_garp_delay(void)
{
	garp_delay_t default_delay = {};
	interface_t *ifp;
	vrrp_t *vrrp;
	list_head_t *vip_list;
	ip_address_t *vip;

	if (global_data->vrrp_garp_interval) {
		default_delay.garp_interval.tv_sec = global_data->vrrp_garp_interval / 1000000;
		default_delay.garp_interval.tv_usec = global_data->vrrp_garp_interval % 1000000;
		default_delay.have_garp_interval = true;
	}
	if (global_data->vrrp_gna_interval) {
		default_delay.gna_interval.tv_sec = global_data->vrrp_gna_interval / 1000000;
		default_delay.gna_interval.tv_usec = global_data->vrrp_gna_interval % 1000000;
		default_delay.have_gna_interval = true;
	}

	/* Allocate a delay structure to each physical interface that doesn't have one and
	 * is being used by a VRRP instance */
	list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
		if (!vrrp->ifp)
			continue;
		ifp = IF_BASE_IFP(vrrp->ifp);
		if (!ifp->garp_delay)
			set_garp_delay(ifp, &default_delay);

		/* We also need delays for any i/fs used by VIPs/eVIPs */
		for (vip_list = &vrrp->vip; vip_list; vip_list = vip_list == &vrrp->vip ? &vrrp->evip : NULL) {
			list_for_each_entry(vip, vip_list, e_list) {
				ifp = IF_BASE_IFP(vip->ifp);
				if (!ifp->garp_delay)
					set_garp_delay(ifp, &default_delay);
			}
		}
	}
}

static void
free_if(interface_t *ifp)
{
	free_tracking_obj_list(&ifp->tracking_vrrp);
	if_extra_ipaddress_free_list(&ifp->sin_addr_l);
	if_extra_ipaddress_free_list(&ifp->sin6_addr_l);
	FREE(ifp);
}

static void
dump_if(FILE *fp, const interface_t *ifp)
{
	char addr_str[INET6_ADDRSTRLEN];
	char mac_buf[3 * sizeof ifp->hw_addr];
	sin_addr_t *saddr;
	char time_str[26];

	conf_write(fp, " Name = %s", ifp->ifname);
	conf_write(fp, "   index = %u%s", ifp->ifindex, ifp->ifindex ? "" : " (deleted)");
	conf_write(fp, "   IPv4 address = %s",
			ifp->sin_addr.s_addr ? inet_ntop2(ifp->sin_addr.s_addr) : "(none)");
	if (!list_empty(&ifp->sin_addr_l)) {
		conf_write(fp, "   Additional IPv4 addresses :");
		list_for_each_entry(saddr, &ifp->sin_addr_l, e_list)
			conf_write(fp, "     %s", inet_ntop2(saddr->u.sin_addr.s_addr));
	}
	if (!IN6_IS_ADDR_UNSPECIFIED(&ifp->sin6_addr)) {
		inet_ntop(AF_INET6, &ifp->sin6_addr, addr_str, sizeof(addr_str));
		conf_write(fp, "   IPv6 address = %s", addr_str);
	} else
		conf_write(fp, "   IPv6 address = (none)");
	if (!list_empty(&ifp->sin6_addr_l)) {
		conf_write(fp, "   Additional IPv6 addresses :");
		list_for_each_entry(saddr, &ifp->sin6_addr_l, e_list) {
			inet_ntop(AF_INET6, &saddr->u.sin6_addr, addr_str, sizeof(addr_str));
			conf_write(fp, "     %s", addr_str);
		}
	}

	if (ifp->hw_addr_len) {
		format_mac_buf(mac_buf, sizeof mac_buf, ifp->hw_addr, ifp->hw_addr_len);
		conf_write(fp, "   MAC = %s", mac_buf);

		format_mac_buf(mac_buf, sizeof mac_buf, ifp->hw_addr_bcast, ifp->hw_addr_len);
		conf_write(fp, "   MAC broadcast = %s", mac_buf);
	}

	conf_write(fp, "   State = %sUP, %sRUNNING%s%s%s%s%s%s", ifp->ifi_flags & IFF_UP ? "" : "not ", ifp->ifi_flags & IFF_RUNNING ? "" : "not ",
			!(ifp->ifi_flags & IFF_BROADCAST) ? ", no broadcast" : "",
			ifp->ifi_flags & IFF_LOOPBACK ? ", loopback" : "",
			ifp->ifi_flags & IFF_POINTOPOINT ? ", point to point" : "",
			ifp->ifi_flags & IFF_NOARP ? ", no arp" : "",
			!(ifp->ifi_flags & IFF_MULTICAST) ? ", no multicast" : "",
#ifdef _HAVE_VRRP_VMAC_
			ifp != ifp->base_ifp && !(ifp->base_ifp->ifi_flags & IFF_UP) ? ", master down" : ""
#else
			""
#endif
		  );

#ifdef _HAVE_VRRP_VMAC_
	if (IS_MAC_IP_VLAN(ifp)) {
		const char *if_type =
#ifdef _HAVE_VRRP_IPVLAN_
				      ifp->if_type == IF_TYPE_IPVLAN ? "IPVLAN" :
#endif
										  "VMAC";
		const char *vlan_type =
				ifp->if_type == IF_TYPE_MACVLAN ?
					ifp->vmac_type == MACVLAN_MODE_PRIVATE ? "private" :
					ifp->vmac_type == MACVLAN_MODE_VEPA ? "vepa" :
					ifp->vmac_type == MACVLAN_MODE_BRIDGE ? "bridge" :
#ifdef MACVLAN_MODE_PASSTHRU
					ifp->vmac_type == MACVLAN_MODE_PASSTHRU ? "passthru" :
#endif
#ifdef MACVLAN_MODE_SOURCE
					ifp->vmac_type == MACVLAN_MODE_SOURCE ? "source" :
#endif
					"unknown" :
#if defined _HAVE_VRRP_IPVLAN_ && HAVE_DECL_IFLA_IPVLAN_FLAGS
					ifp->ipvlan_flags & IPVLAN_F_PRIVATE ? "private" :
					ifp->ipvlan_flags & IPVLAN_F_VEPA ? "vepa" :
#endif
					"bridge";
		const char *ipvlan_mode =
#ifdef _HAVE_VRRP_IPVLAN_
				ifp->if_type == IF_TYPE_IPVLAN ?
						(ifp->vmac_type == IPVLAN_MODE_L2 ? "L2 " :
						 ifp->vmac_type == IPVLAN_MODE_L3 ? "L3 " :
#if HAVE_DECL_IPVLAN_MODE_L3S
						 ifp->vmac_type == IPVLAN_MODE_L3S ? "L3S " :
#endif
						 "unknown mode ") : "";
#else
					   "";
#endif
		if (ifp != ifp->base_ifp)
			conf_write(fp, "   %s type %s%s, underlying interface = %s, state = %sUP, %sRUNNING",
					if_type, ipvlan_mode, vlan_type,
					ifp->base_ifp->ifname,
					ifp->base_ifp->ifi_flags & IFF_UP ? "" : "not ", ifp->base_ifp->ifi_flags & IFF_RUNNING ? "" : "not ");
		else if (ifp->base_ifindex) {
#ifdef HAVE_IFLA_LINK_NETNSID
			conf_write(fp, "   %s type %s, underlying ifindex = %u, netns id = %d", if_type, vlan_type, ifp->base_ifindex, ifp->base_netns_id);
#else
			conf_write(fp, "   %s type %s, underlying ifindex = %u", if_type, vlan_type, ifp->base_ifindex);
#endif
		}
		else
			conf_write(fp, "   %s type %s, underlying interface in different namespace", if_type, vlan_type);
	}
	if (ifp->is_ours)
		conf_write(fp, "   I/f created by keepalived");
	else if (global_data->allow_if_changes && ifp->changeable_type)
		conf_write(fp, "   Interface type/base can be changed");
	if (ifp->seen_interface)
		conf_write(fp, "   Done VRID check");
#endif
	conf_write(fp, "   MTU = %" PRIu32, ifp->mtu);

	switch (ifp->hw_type) {
	case ARPHRD_LOOPBACK:
		conf_write(fp, "   HW Type = LOOPBACK");
		break;
	case ARPHRD_ETHER:
		conf_write(fp, "   HW Type = ETHERNET");
		break;
	case ARPHRD_INFINIBAND:
		log_message(LOG_INFO, " HW Type = INFINIBAND");
		break;
	default:
		conf_write(fp, "   HW Type = UNKNOWN (%d)", ifp->hw_type);
		break;
	}

#ifdef _WITH_LINKBEAT_
	if (!ifp->linkbeat_use_polling)
		conf_write(fp, "   NIC netlink status update");
	else if (IF_MII_SUPPORTED(ifp))
		conf_write(fp, "   NIC support MII regs");
	else if (IF_ETHTOOL_SUPPORTED(ifp))
		conf_write(fp, "   NIC support ETHTOOL GLINK interface");
	else
		conf_write(fp, "   NIC ioctl refresh polling");
#endif
#ifdef _HAVE_VRF_
	if (ifp->vrf_master_ifp == ifp)
		conf_write(fp, "   VRF master");
	else if (ifp->vrf_master_ifp)
		conf_write(fp, "   VRF slave of %s", ifp->vrf_master_ifp->ifname);
#endif

	if (ifp->garp_delay) {
		if (ifp->garp_delay->have_garp_interval)
			conf_write(fp, "   Gratuitous ARP interval %ldms",
				    ifp->garp_delay->garp_interval.tv_sec * 1000 +
				     ifp->garp_delay->garp_interval.tv_usec / (TIMER_HZ / 1000));

		if (ifp->garp_delay->have_gna_interval)
			conf_write(fp, "   Gratuitous NA interval %ldms",
				    ifp->garp_delay->gna_interval.tv_sec * 1000 +
				     ifp->garp_delay->gna_interval.tv_usec / (TIMER_HZ / 1000));
		if (ifp->garp_delay->aggregation_group)
			conf_write(fp, "   Gratuitous ARP aggregation group %d", ifp->garp_delay->aggregation_group);
	}

#ifdef _HAVE_VRRP_VMAC_
	conf_write(fp, "   Reset ARP config counter %d", ifp->reset_arp_config);
	conf_write(fp, "   Original arp_ignore %d", ifp->arp_ignore);
	conf_write(fp, "   Original arp_filter %d", ifp->arp_filter);
	if (ifp->rp_filter < UINT_MAX)
		conf_write(fp, "   rp_filter %u", ifp->rp_filter);
#endif
	conf_write(fp, "   Original promote_secondaries %d", ifp->promote_secondaries);
	conf_write(fp, "   Reset promote_secondaries counter %" PRIu32, ifp->reset_promote_secondaries);
	if (timerisset(&ifp->last_gna_router_check)) {
		ctime_r(&ifp->last_gna_router_check.tv_sec, time_str);
		conf_write(fp, "   %sIPv6 forwarding. Last checked %ld.%6.6ld (%.24s.%6.6ld)", ifp->gna_router ? "" : "Not ", ifp->last_gna_router_check.tv_sec, ifp->last_gna_router_check.tv_usec, time_str, ifp->last_gna_router_check.tv_usec);

	}

	if (!list_empty(&ifp->tracking_vrrp)) {
		conf_write(fp, "   Tracking VRRP instances :");
		if_tracking_vrrp_dump_list(fp, &ifp->tracking_vrrp);
	}
}

#ifdef _WITH_LINKBEAT_
static bool
init_linkbeat_status(int fd, interface_t *ifp)
{
	int status;
	bool if_up = false;
	int configured_type = ifp->lb_type;

	if ((!ifp->lb_type || ifp->lb_type == LB_MII)) {
		if ((status = if_mii_probe(fd, ifp->ifname)) >= 0) {
			ifp->lb_type = LB_MII;
			if_up = !!status;
		}
		else
			ifp->lb_type = 0;
	}

	if ((!ifp->lb_type || ifp->lb_type == LB_ETHTOOL)) {
		if ((status = if_ethtool_probe(fd, ifp)) >= 0) {
			ifp->lb_type = LB_ETHTOOL;
			if_up = !!status;
		} else {
			/* If ETHTOOL was configured on i/f but doesn't work, try MII */
			if (ifp->lb_type &&
			    (status = if_mii_probe(fd, ifp->ifname)) >= 0) {
				ifp->lb_type = LB_MII;
				if_up = !!status;
			}
			else
				ifp->lb_type = 0;
		}
	}

	if ((!ifp->lb_type || ifp->lb_type == LB_IOCTL)) {
		ifp->lb_type = LB_IOCTL;
		if_up = true;
	}

	if (if_up)
		if_up = if_ioctl_flags(fd, ifp);

	if (configured_type && configured_type != ifp->lb_type)
		log_message(LOG_INFO, "(%s): Configured linkbeat type %s not supported, using %s",
				      ifp->ifname,
				      configured_type == LB_MII ? "MII" : configured_type == LB_ETHTOOL ? "ETHTOOL" : "IOCTL",
				      ifp->lb_type == LB_MII ? "MII" : ifp->lb_type == LB_ETHTOOL ? "ETHTOOL" : "IOCTL");

	return if_up;
}

static void
if_linkbeat_refresh_thread(thread_ref_t thread)
{
	interface_t *ifp = THREAD_ARG(thread);
	bool if_up = true, was_up;

	was_up = IF_FLAGS_UP(ifp);

	if (!ifp->ifindex) {
		if_up = false;
	} else {
		if (!ifp->lb_type) {
			/* If this is a new interface, we need to find linkbeat type */
			if_up = init_linkbeat_status(linkbeat_fd, ifp);
		} else {
			if (IF_MII_SUPPORTED(ifp))
				if_up = if_mii_probe(linkbeat_fd, ifp->ifname);
			else if (IF_ETHTOOL_SUPPORTED(ifp))
				if_up = if_ethtool_probe(linkbeat_fd, ifp);

			/*
			 * update ifp->flags to get the new IFF_RUNNING status.
			 * Some buggy drivers need this...
			 */
			if (if_up)
				if_up = if_ioctl_flags(linkbeat_fd, ifp);
		}
	}

	if (if_up)
		ifp->ifi_flags |= IFF_UP | IFF_RUNNING;
	else
		ifp->ifi_flags &= ~(IFF_UP | IFF_RUNNING);

	if (if_up != was_up) {
		log_message(LOG_INFO, "Linkbeat reports %s %s", ifp->ifname, if_up ? "up" : "down");

		process_if_status_change(ifp);
	}

	/* Register next polling thread */
	thread_add_timer(master, if_linkbeat_refresh_thread, ifp, POLLING_DELAY);
}

void
init_interface_linkbeat(void)
{
	interface_t *ifp;
	bool linkbeat_in_use = false;
	bool if_up;

	list_for_each_entry(ifp, &if_queue, e_list) {
		if (!ifp->linkbeat_use_polling)
			continue;

		/* Don't poll an interface that we aren't using */
		if (list_empty(&ifp->tracking_vrrp)) {
			log_message(LOG_INFO, "Turning off linkbeat for %s since not used for tracking", ifp->ifname);
			ifp->linkbeat_use_polling = false;
			ifp->lb_type = 0;
			continue;
		}

#ifdef _HAVE_VRRP_VMAC_
		/* netlink messages work for vmacs */
		if (IS_MAC_IP_VLAN(ifp)) {
			log_message(LOG_INFO, "Turning off linkbeat for %s since netlink works for vmacs/ipvlans", ifp->ifname);
			ifp->linkbeat_use_polling = false;
			continue;
		}
#endif

		if (linkbeat_fd == -1) {
			if ((linkbeat_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1) {
				log_message(LOG_INFO, "open linkbeat init socket failed - errno %d - %m\n", errno);
				return;
			}
		}

		linkbeat_in_use = true;
		if (!ifp->ifindex) {
			/* Interface doesn't exist yet */
			ifp->ifi_flags = 0;
		} else {
			if_up = init_linkbeat_status(linkbeat_fd, ifp);

			if (if_up)
				ifp->ifi_flags |= IFF_UP | IFF_RUNNING;
			else
				ifp->ifi_flags &= ~(IFF_UP | IFF_RUNNING);
		}

		/* Register new monitor thread */
		thread_add_timer(master, if_linkbeat_refresh_thread, ifp, POLLING_DELAY);
	}

	if (linkbeat_in_use)
		log_message(LOG_INFO, "Using MII-BMSR/ETHTOOL NIC polling thread(s)...");
}

void
close_interface_linkbeat(void)
{
	if (linkbeat_fd != -1) {
		close(linkbeat_fd);
		linkbeat_fd = -1;
	}
}
#endif

/* Interface queue helpers*/
void
free_interface_queue(void)
{
	interface_t *ifp, *ifp_tmp;

	list_for_each_entry_safe(ifp, ifp_tmp, &if_queue, e_list)
		free_if(ifp);

	free_garp_delay_list(&garp_delay);
}

void
free_old_interface_queue(void)
{
	free_garp_delay_list(&old_garp_delay);
}

void
dump_interface_queue(FILE *fp, list_head_t *l)
{
	interface_t *ifp;

	list_for_each_entry(ifp, l, e_list)
		dump_if(fp, ifp);
}

list_head_t *
get_interface_queue(void)
{
	return &if_queue;
}

void
reset_interface_queue(void)
{
	interface_t *ifp;

	list_copy(&old_garp_delay, &garp_delay);
	INIT_LIST_HEAD(&garp_delay);

	list_for_each_entry(ifp, &if_queue, e_list) {
#ifdef _WITH_LINKBEAT_
		ifp->linkbeat_use_polling = false;
#endif
		ifp->garp_delay = NULL;
		free_tracking_obj_list(&ifp->tracking_vrrp);
	}
}

void
init_interface_queue(void)
{
	netlink_interface_lookup(NULL);
#ifdef _HAVE_VRRP_VMAC_
	/* Since we are reading all the interfaces, we might have received details of
	 * a vmac/vrf before the underlying interface, so now we need to ensure the
	 * interface pointers are all set */
	set_base_ifp();
#endif
//	dump_interface_queue(NULL, &if_queue);
}

int
if_join_vrrp_group(sa_family_t family, int *sd, const interface_t *ifp)
{
	struct ip_mreqn imr;
	struct ipv6_mreq imr6;
	int ret = 0;
#if defined _HAVE_VRRP_VMAC_
	bool send_on_base_if;
#endif

	if (*sd < 0)
		return -1;

	/* -> outbound processing option
	 * join the multicast group.
	 * binding the socket to the interface for outbound multicast
	 * traffic.
	 */

	/* We don't really want to send the IGMP/MLD messages on a VMAC
	 * interface, since that will send using the 00:00:5e:00:0x:xx mac
	 * address, and snooping switches will then be updated, even if we
	 * are backup.
	 * We have to join the group on the VMAC interface, otherwise we cannot
	 * receive the messages to the multicast address (if we try receiving
	 * on the base interface we don't see the messages since there is an
	 * interface on the system with the MAC address matching the source address
	 * of the packet). If we are using nftables and the dup statement is supported,
	 * we just let nftables move the IGMP join message to the physical interface,
	 * otherwise we need to join on both the VMAC interface and the physical
	 * interface, and use nftables/iptables to drop the packet on the VMAC
	 * interface.
	 * If we are using neither nftables or iptables, there is no point in
	 * duplicating the join, since we can't block it on the VMAC interface.
	 *
	 * This might all be better achieved using eBPF.
	 */
#if defined _HAVE_VRRP_VMAC_
	send_on_base_if = false;
	if (IS_MAC_IP_VLAN(ifp) &&
	    ifp->if_type == IF_TYPE_MACVLAN &&
	    ifp->is_ours) {
#ifdef _WITH_IPTABLES_
		if (global_data->vrrp_iptables_outchain)
			send_on_base_if = true;
#endif
#ifdef _WITH_NFTABLES_
		if (global_data->vrrp_nf_table_name) {
#if HAVE_DECL_NFTA_DUP_MAX
			send_on_base_if = false;
#else
			send_on_base_if = true;
#endif
		}
#endif
	}
#endif

	if (family == AF_INET) {
		memset(&imr, 0, sizeof(imr));
		imr.imr_multiaddr = global_data->vrrp_mcast_group4.sin_addr;

		/* -> Need to handle multicast convergance after takeover.
		 * We retry until multicast is available on the interface.
		 */
#if defined _HAVE_VRRP_VMAC_
		/* coverity[dead_error_condition] */
		if (send_on_base_if)
		{
			imr.imr_ifindex = IF_INDEX(IF_BASE_IFP(ifp));
			if (setsockopt(*sd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
					 PTR_CAST(char, &imr), (socklen_t)sizeof(struct ip_mreqn)) < 0)
				log_message(LOG_INFO, "Failed to set GARP on base if - errno %d (%m)", errno);
		}
#endif
		imr.imr_ifindex = (int)IF_INDEX(ifp);
		ret = setsockopt(*sd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
				 PTR_CAST(char, &imr), (socklen_t)sizeof(struct ip_mreqn));
	} else {
		memset(&imr6, 0, sizeof(imr6));
		imr6.ipv6mr_multiaddr = global_data->vrrp_mcast_group6.sin6_addr;
#if defined _HAVE_VRRP_VMAC_
		/* coverity[dead_error_condition] */
		if (send_on_base_if) {
			imr6.ipv6mr_interface = IF_INDEX(IF_BASE_IFP(ifp));
			if (setsockopt(*sd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
					 PTR_CAST(char, &imr6), (socklen_t)sizeof(struct ipv6_mreq)) < 0)
				log_message(LOG_INFO, "Failed to set MLD on base if - errno %d (%m)", errno);
		}
#endif
		imr6.ipv6mr_interface = IF_INDEX(ifp);
		ret = setsockopt(*sd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
				 PTR_CAST(char, &imr6), (socklen_t)sizeof(struct ipv6_mreq));
	}

	if (ret < 0) {
		log_message(LOG_INFO, "(%s) cant do IP%s_ADD_MEMBERSHIP errno=%s (%d)",
			    ifp->ifname, (family == AF_INET) ? "" : "V6", strerror(errno), errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

#ifdef _INCLUDE_UNUSED_CODE_
int
if_leave_vrrp_group(sa_family_t family, int sd, const interface_t *ifp)
{
	struct ip_mreqn imr;
	struct ipv6_mreq imr6;
	int ret = 0;

	/* If fd is -1 then we add a membership trouble */
	if (sd < 0 || !ifp)
		return -1;

	/* Leaving the VRRP multicast group */
	if (family == AF_INET) {
		memset(&imr, 0, sizeof(imr));
		imr.imr_multiaddr = global_data->vrrp_mcast_group4.sin_addr;
#if defined _HAVE_VRRP_VMAC_ && defined _WITH_NFTABLES_ && !HAVE_DECL_NFTA_DUP_MAX
		/* See description in if_join_vrrp_group */
		if (IS_MAC_IP_VLAN(ifp) &&
		    ifp->if_type == IF_TYPE_MACVLAN &&
		    ifp->is_ours) {
			imr.imr_ifindex = IF_INDEX(IF_BASE_IFP(ifp));
			setsockopt(sd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
					 PTR_CAST(char, &imr), sizeof(imr));
		}
		imr.imr_ifindex = (int)IF_INDEX(ifp);
		ret = setsockopt(sd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
				 PTR_CAST(char, &imr), sizeof(imr));
#endif
	} else {
		memset(&imr6, 0, sizeof(imr6));
		imr6.ipv6mr_multiaddr = global_data->vrrp_mcast_group6.sin6_addr;
#if defined _HAVE_VRRP_VMAC_ && defined _WITH_NFTABLES_ && !HAVE_DECL_NFTA_DUP_MAX
		/* See description in if_join_vrrp_group */
		if (IS_MAC_IP_VLAN(ifp) &&
		    ifp->if_type == IF_TYPE_MACVLAN &&
		    ifp->is_ours) {
			imr6.ipv6mr_interface = IF_INDEX(IF_BASE_IFP(ifp));
			setsockopt(sd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
					 PTR_CAST(char, &imr6), sizeof(struct ipv6_mreq));
		}
#endif
		imr6.ipv6mr_interface = IF_INDEX(ifp);
		ret = setsockopt(sd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
				 PTR_CAST(char, &imr6), sizeof(struct ipv6_mreq));
	}

	if (ret < 0) {
		/* coverity[deadcode] */
		log_message(LOG_INFO, "(%s) cant do IP%s_DROP_MEMBERSHIP errno=%s (%d)",
			    ifp->ifname, (family == AF_INET) ? "" : "V6", strerror(errno), errno);
		return -1;
	}

	return 0;
}
#endif

int
if_setsockopt_bindtodevice(int *sd, const interface_t *ifp)
{
	int ret;

	if (*sd < 0)
		return -1;

	/* -> inbound processing option
	 * Specify the bound_dev_if.
	 * why IP_ADD_MEMBERSHIP & IP_MULTICAST_IF doesnt set
	 * sk->bound_dev_if themself ??? !!!
	 * Needed for filter multicasted advert per interface.
	 *
	 * -- If you read this !!! and know the answer to the question
	 *    please feel free to answer me ! :)
	 */
	ret = setsockopt(*sd, SOL_SOCKET, SO_BINDTODEVICE, IF_NAME(ifp), (socklen_t)strlen(IF_NAME(ifp)) + 1);
	if (ret < 0) {
		log_message(LOG_INFO, "can't bind to device %s. errno=%d. (try to run it as root)",
			    IF_NAME(ifp), errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

int
if_setsockopt_hdrincl(int *sd)
{
	int ret;
	int on = 1;

	if (*sd < 0)
		return -1;

	/* Include IP header into RAW protocol packet */
	ret = setsockopt(*sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
	if (ret < 0) {
		log_message(LOG_INFO, "cant set HDRINCL IP option. errno=%d (%m)", errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

int
if_setsockopt_ipv6_checksum(int *sd)
{
	int ret;
	int offset = 6;

	if (!sd || *sd < 0)
		return -1;

	ret = setsockopt(*sd, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset));
	if (ret < 0) {
		log_message(LOG_INFO, "cant set IPV6_CHECKSUM IP option. errno=%d (%m)", errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

int
if_setsockopt_mcast_all(sa_family_t family, int *sd)
{
	int ret;
	unsigned char no = 0;

	if (*sd < 0)
		return -1;

	if (family == AF_INET6)
		return *sd;

	/* Don't accept multicast packets we haven't requested */
	ret = setsockopt(*sd, IPPROTO_IP, IP_MULTICAST_ALL, &no, sizeof(no));

	if (ret < 0) {
		log_message(LOG_INFO, "cant set IP_MULTICAST_ALL IP option. errno=%d (%m)",
			    errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

int
if_setsockopt_mcast_loop(sa_family_t family, int *sd)
{
	int ret;
	unsigned char loop = 0;
	int loopv6 = 0;

	if (*sd < 0)
		return -1;

	/* Set Multicast loop */
	if (family == AF_INET)
		ret = setsockopt(*sd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
	else
		ret = setsockopt(*sd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loopv6, sizeof(loopv6));

	if (ret < 0) {
		log_message(LOG_INFO, "cant set IP%s_MULTICAST_LOOP IP option. errno=%d (%m)",
			    (family == AF_INET) ? "" : "V6", errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

int
if_setsockopt_mcast_hops(sa_family_t family, int *sd)
{
	int ret;
	int hops = 255;

	/* Not applicable for IPv4 */
	if (*sd < 0 || family == AF_INET)
		return -1;

	/* Set HOP limit */
	ret = setsockopt(*sd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops));
	if (ret < 0) {
		log_message(LOG_INFO, "cant set IPV6_MULTICAST_HOPS IP option. errno=%d (%m)", errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

int
if_setsockopt_mcast_if(sa_family_t family, int *sd, const interface_t *ifp)
{
	int ret;
	ifindex_t ifindex;
	int int_ifindex;

	if (*sd < 0)
		return -1;

	/* Set interface for sending outbound datagrams */
	ifindex = IF_INDEX(ifp);
	if ( family == AF_INET)
	{
		struct ip_mreqn imr;

		memset(&imr, 0, sizeof(imr));
		imr.imr_ifindex = (int)IF_INDEX(ifp);
		ret = setsockopt(*sd, IPPROTO_IP, IP_MULTICAST_IF, &imr, sizeof(imr));
	}
	else {
		int_ifindex = (int)ifindex;
		ret = setsockopt(*sd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &int_ifindex, sizeof(int_ifindex));
	}

	if (ret < 0) {
		log_message(LOG_INFO, "cant set IP%s_MULTICAST_IF IP option. errno=%d (%m)", (family == AF_INET) ? "" : "V6", errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

int
if_setsockopt_priority(int *sd, int family)
{
	int ret;
	int val;

	if (*sd < 0)
		return -1;

	/* Set PRIORITY for VRRP traffic */
	if (family == AF_INET) {
		val = IPTOS_PREC_INTERNETCONTROL;
		ret = setsockopt(*sd, IPPROTO_IP, IP_TOS, &val, sizeof(val));
	}
	else {
		/* set tos to internet network control */
		val = 0xc0;	/* 192, which translates to DCSP value 48, or cs6 */
		ret = setsockopt(*sd, IPPROTO_IPV6, IPV6_TCLASS, &val, sizeof(val));
	}

	if (ret < 0) {
		log_message(LOG_INFO, "can't set %s option. errno=%d (%m)", (family == AF_INET) ? "IP_TOS" : "IPV6_TCLASS",  errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

int
if_setsockopt_rcvbuf(int *sd, int val)
{
	int ret;

	if (*sd < 0)
		return -1;

	/* rcvbuf option */
	ret = setsockopt(*sd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
	if (ret < 0) {
		log_message(LOG_INFO, "cant set SO_RCVBUF IP option. errno=%d (%m)", errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

int
if_setsockopt_no_receive(int *sd)
{
	int ret;
	struct sock_filter bpfcode[1] = {
		{0x06, 0, 0, 0},	/* ret #0 - means that all packets will be filtered out */
	};
	struct sock_fprog bpf = {1, bpfcode};

	if (*sd < 0)
		return -1;

	ret = setsockopt(*sd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
	if (ret < 0) {
		log_message(LOG_INFO, "Can't set SO_ATTACH_FILTER option. errno=%d (%m)", errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

void
interface_up(interface_t *ifp)
{
	/* We need to re-add static addresses and static routes */
	static_track_group_reinstate_config(ifp);
}

void
interface_down(interface_t *ifp)
{
	vrrp_t *vrrp;
	ip_route_t *route;
	bool route_found;

	/* Unfortunately the kernel doesn't send RTM_DELROUTE for userspace added
	 * routes that are deleted when the link goes down (?kernel bug). */

	list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
		if (vrrp->state != VRRP_STATE_MAST)
			continue;

		route_found = false;

		list_for_each_entry(route, &vrrp->vroutes, e_list) {
			if (!route->set)
				continue;

			/* Any route that has an oif will be tracking the interface,
			 * so we only need to check for routes that dont specify an
			 * oif */
			/* Don't track route if it's not configured with this down
			 * interface. */
			if (!route->oif || route->configured_ifindex != ifp->ifindex)
				continue;

			route->set = false;

			if (route->dont_track)
				continue;

			route_found = true;
		}

		if (route_found) {
			/* Bring down vrrp instance/sync group */
			down_instance(vrrp);
		}
	}

	/* Now check the static routes */
	list_for_each_entry(route, &vrrp_data->static_routes, e_list) {
		if (route->set && route->oif == ifp) {
			/* This route will have been deleted */
			route->set = false;
		}
	}
}

void
cleanup_lost_interface(interface_t *ifp)
{
	tracking_obj_t *top;
	vrrp_t *vrrp;

	list_for_each_entry(top, &ifp->tracking_vrrp, e_list) {
		vrrp = top->obj.vrrp;

		/* If this instance does not have an interface, we don't need to do anything,
		   but I don't this can ever be true */
		if (!vrrp->ifp)
			continue;

		if (vrrp->ifp != ifp
#ifdef _HAVE_VRRP_VMAC_
		    && IF_BASE_IFP(vrrp->ifp) != ifp && VRRP_CONFIGURED_IFP(vrrp) != ifp
#endif
											) {
			/* We must be a tracked interface */
			if (IF_ISUP(ifp)) {
				if (top->weight) {
					vrrp->total_priority -= top->weight * top->weight_multiplier;
					vrrp_set_effective_priority(vrrp);
				} else
					down_instance(vrrp);
			}
			continue;
		}

		/* If the vrrp instance's interface doesn't exist, skip it */
		if (!vrrp->ifp->ifindex)
			continue;

#ifdef _HAVE_VRRP_VMAC_
		/* If vmac going, clear VMAC_UP_BIT on vrrp instance */
		if (vrrp->ifp->is_ours) {
			__clear_bit(VRRP_VMAC_UP_BIT, &vrrp->vmac_flags);
#ifdef _WITH_FIREWALL_
			firewall_remove_vmac(vrrp);
#endif
		}

		if (vrrp->configured_ifp == ifp &&
		    vrrp->configured_ifp->base_ifp == vrrp->ifp->base_ifp &&
		    vrrp->ifp->is_ours) {
			/* This is a changeable interface that the vrrp instance
			 * was configured on. Delete the macvlan/ipvlan we created */
			netlink_link_del_vmac(vrrp);
// HERE
		}

		if (vrrp->configured_ifp == ifp &&
		    vrrp->configured_ifp->base_ifp != vrrp->configured_ifp)
			del_vrrp_from_interface(vrrp, vrrp->configured_ifp->base_ifp);

		/* If the interface type can be changed, and the vrrp had a
		 * duplicate VRID, clear the error since when the underlying
		 * interface is created again, it may be on another underlying
		 * interface, and there may not be a duplicate VRID. */
		if (global_data->allow_if_changes &&
		    ifp->changeable_type &&
		    vrrp->configured_ifp == ifp &&
		    vrrp->duplicate_vrid_fault) {
			vrrp->duplicate_vrid_fault = false;
			vrrp->num_script_if_fault--;
		}
#endif

		/* Find the sockpool entry. If none, then we have closed the socket */
		if (vrrp->sockets) {
			if (vrrp->sockets->fd_in != -1) {
				thread_cancel_read(master, vrrp->sockets->fd_in);
				close(vrrp->sockets->fd_in);
				vrrp->sockets->fd_in = -1;
			}
			if (vrrp->sockets->fd_out != -1) {
				close(vrrp->sockets->fd_out);
				vrrp->sockets->fd_out = -1;
			}
		}

		if (IF_ISUP(ifp))
			down_instance(vrrp);
	}

	interface_down(ifp);

	ifp->ifindex = 0;
	ifp->ifi_flags = 0;
#ifdef _HAVE_VRRP_VMAC_
	if (!ifp->is_ours)
		ifp->base_ifp = ifp;
#endif
#ifdef _HAVE_VRF_
	ifp->vrf_master_ifp = NULL;
	ifp->vrf_master_ifindex = 0;
#endif
}

static void
setup_interface(vrrp_t *vrrp)
{
	vrrp_t *vrrp_l;

#ifdef _HAVE_VRRP_VMAC_
	/* If the vrrp instance uses a vmac, and that vmac i/f doesn't
	 * exist, then create it */
	if (!vrrp->ifp->ifindex) {
		if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags) &&
		    !netlink_link_add_vmac(vrrp))
			return;
#ifdef _HAVE_VRRP_IPVLAN_
		else if (__test_bit(VRRP_IPVLAN_BIT, &vrrp->vmac_flags) &&
		    !netlink_link_add_ipvlan(vrrp))
			return;
#endif
	}
#endif

	/* Find the sockpool entry. If none, then we open the socket */
	if (vrrp->sockets->fd_in == -1) {
		/* If the MTU has changed we may need to recalculate the socket receive buffer size */
		if (global_data->vrrp_rx_bufs_policy & RX_BUFS_POLICY_MTU) {
			vrrp->sockets->rx_buf_size = 0;
			rb_for_each_entry(vrrp_l, &vrrp->sockets->rb_vrid, rb_vrid) {
				if (vrrp_l->kernel_rx_buf_size)
					vrrp->sockets->rx_buf_size += vrrp_l->kernel_rx_buf_size;
				else
					vrrp->sockets->rx_buf_size += global_data->vrrp_rx_bufs_multiples * vrrp_l->ifp->mtu;
			}
		}

		open_sockpool_socket(vrrp->sockets);

		if (vrrp_initialised) {
			vrrp->state = vrrp->num_script_if_fault ? VRRP_STATE_FAULT : VRRP_STATE_BACK;
			vrrp_init_instance_sands(vrrp);
			vrrp_thread_add_read(vrrp);
		}
	}

	return;
}

#ifdef _HAVE_VRRP_VMAC_
void
recreate_vmac_thread(thread_ref_t thread)
{
	interface_t *ifp = THREAD_ARG(thread);
	tracking_obj_t *top;
	vrrp_t *vrrp;

	list_for_each_entry(top, &ifp->tracking_vrrp, e_list) {
		vrrp = top->obj.vrrp;

		/* If this isn't the vrrp's interface, skip */
		if (vrrp->ifp != ifp)
			continue;

		if (!__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags)
#ifdef _HAVE_VRRP_IPVLAN_
		    && !__test_bit(VRRP_IPVLAN_BIT, &vrrp->vmac_flags)
#endif
								      )
			continue;

		/* Don't attempt to create the VMAC if the configured
		 * interface doesn't exist */
		if (!VRRP_CONFIGURED_IFP(vrrp)->ifindex)
			continue;

		netlink_error_ignore = ENODEV;
		setup_interface(vrrp);
		netlink_error_ignore = 0;

		break;
	}
}
#endif

void update_mtu(interface_t *ifp)
{
	sock_t *sock;
	bool updated_vrrp_buffer = false;
	vrrp_t *vrrp;

	list_for_each_entry(sock, &vrrp_data->vrrp_socket_pool, e_list) {
		if (sock->ifp != ifp ||
		    sock->fd_in == -1)
			continue;

		if (!updated_vrrp_buffer) {
			alloc_vrrp_buffer(ifp->mtu);
			updated_vrrp_buffer = true;
		}

		/* If the MTU has changed we may need to recalculate the socket receive buffer size */
		if (global_data->vrrp_rx_bufs_policy & RX_BUFS_POLICY_MTU) {
			sock->rx_buf_size = 0;
			rb_for_each_entry(vrrp, &sock->rb_vrid, rb_vrid) {
				if (vrrp->kernel_rx_buf_size)
					sock->rx_buf_size += vrrp->kernel_rx_buf_size;
				else
					sock->rx_buf_size += global_data->vrrp_rx_bufs_multiples * ifp->mtu;
			}

			if (setsockopt(sock->fd_in, SOL_SOCKET, SO_RCVBUF, &sock->rx_buf_size, sizeof(sock->rx_buf_size)))
				log_message(LOG_INFO, "vrrp update receive socket buffer size error %d", errno);
		}
	}
}

void
update_added_interface(interface_t *ifp)
{
	vrrp_t *vrrp;
	tracking_obj_t *top;
#ifdef _HAVE_VRRP_VMAC_
	vrrp_t *vrrp1;
	tracking_obj_t *top1;
#endif

	list_for_each_entry(top, &ifp->tracking_vrrp, e_list) {
		vrrp = top->obj.vrrp;

#ifdef _HAVE_VRRP_VMAC_
		/* If this interface is a macvlan that we haven't created,
		 * and the interface type can be changed or we haven't checked
		 * this interface before, make sure that there is no VRID
		 * conflict. */
		if (!ifp->is_ours &&
		    (global_data->allow_if_changes || !ifp->seen_interface) &&
		    !list_empty(&ifp->base_ifp->tracking_vrrp)) {
// TODO - handle unicast - see check_vrrp_conflicts() - in fact, can we use it?
			list_for_each_entry(top1, &ifp->base_ifp->tracking_vrrp, e_list) {
				vrrp1 = top1->obj.vrrp;
				if (vrrp == vrrp1)
					continue;

				if (!vrrp1->ifp)
					continue;

				if (!VRRP_CONFIGURED_IFP(vrrp1)->ifindex)
					continue;

				if (IF_BASE_IFP(VRRP_CONFIGURED_IFP(vrrp)) == IF_BASE_IFP(VRRP_CONFIGURED_IFP(vrrp1)) &&
				    vrrp->family == vrrp1->family &&
				    vrrp->vrid == vrrp1->vrid) {
					vrrp->num_script_if_fault++;
					vrrp->duplicate_vrid_fault = true;
					log_message(LOG_INFO, "VRID conflict between %s and %s IPv%d vrid %d",
							vrrp->iname, vrrp1->iname, vrrp->family == AF_INET ? 4 : 6, vrrp->vrid);
					break;
				}
			}
		}

		if (vrrp->vmac_flags) {
			if (top->type & TRACK_VRRP) {
				add_vrrp_to_interface(vrrp, ifp->base_ifp, top->weight, top->weight_multiplier == -1, false, TRACK_VRRP_DYNAMIC);
				if (!IF_ISUP(vrrp->configured_ifp->base_ifp) && !vrrp->dont_track_primary) {
					log_message(LOG_INFO, "(%s) interface %s is down",
							vrrp->iname, vrrp->configured_ifp->base_ifp->ifname);
					vrrp->num_script_if_fault++;
				}
			}

			/* We might be the configured interface for a vrrp instance that itself uses
			 * a macvlan. If so, we can create the macvlans */
			if (vrrp->configured_ifp == ifp &&
			    !vrrp->ifp->ifindex)
				thread_add_event(master, recreate_vmac_thread, vrrp->ifp, 0);
		}
#endif

		if (!vrrp->ifp)
			continue;

		/* If this is just a tracking interface, we don't need to do anything */
		if (vrrp->ifp != ifp
#ifdef _HAVE_VRRP_VMAC_
		    && IF_BASE_IFP(vrrp->ifp) != ifp
#endif
						    )
			continue;

		/* Reopen any socket on this interface if necessary */
		if (
#ifdef _HAVE_VRRP_VMAC_
		    !vrrp->vmac_flags &&
#endif
		    vrrp->sockets->fd_in == -1)
			setup_interface(vrrp);
	}

#ifdef _HAVE_VRRP_VMAC_
	ifp->seen_interface = true;
#endif
}

#ifdef THREAD_DUMP
void
register_vrrp_if_addresses(void)
{
#ifdef _WITH_LINKBEAT_
	register_thread_address("if_linkbeat_refresh_thread", if_linkbeat_refresh_thread);
#endif
#ifdef _HAVE_VRRP_VMAC_
	register_thread_address("recreate_vmac_thread", recreate_vmac_thread);
#endif
}
#endif
