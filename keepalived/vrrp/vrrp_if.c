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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

/* global include */
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <syslog.h>
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
#if !HAVE_DECL_SOCK_CLOEXEC
#include "old_socket.h"
#endif
#include <linux/sockios.h>	/* needed to get correct values for SIOC* */
#include <net/if_arp.h>

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
#include "vrrp_index.h"
#include "vrrp_track.h"
#include "vrrp_sync.h"
#include "vrrp_scheduler.h"

/* Local vars */
static list if_queue;
static struct ifreq ifr;

static list old_if_queue;
static list old_garp_delay;

/* Global vars */
list garp_delay;

/* Helper functions */
/* Return interface from interface index */
interface_t *
if_get_by_ifindex(ifindex_t ifindex)
{
	interface_t *ifp;
	element e;

	if (LIST_ISEMPTY(if_queue))
		return NULL;

	for (e = LIST_HEAD(if_queue); e; ELEMENT_NEXT(e)) {
		ifp = ELEMENT_DATA(e);
		if (ifp->ifindex == ifindex)
			return ifp;
	}
	return NULL;
}

/* Return base interface from interface index incase of VMAC */
interface_t *
base_if_get_by_ifp(interface_t *ifp)
{
#ifdef _HAVE_VRRP_VMAC_
	return (ifp && ifp->vmac) ? ifp->base_ifp : ifp;
#else
	return ifp;
#endif
}

interface_t *
if_get_by_ifname(const char *ifname, if_lookup_t create)
{
	interface_t *ifp;
	element e;

	if (!LIST_ISEMPTY(if_queue)) {
		for (e = LIST_HEAD(if_queue); e; ELEMENT_NEXT(e)) {
			ifp = ELEMENT_DATA(e);
			if (!strcmp(ifp->ifname, ifname))
				return ifp;
		}
	}

	if (create == IF_NO_CREATE ||
	    (create == IF_CREATE_IF_DYNAMIC && (!global_data || !global_data->dynamic_interfaces))) {
		if (create == IF_CREATE_IF_DYNAMIC)
			non_existent_interface_specified = true;
		return NULL;
	}

	if (!(ifp = MALLOC(sizeof(interface_t))))
		return NULL;

	strcpy(ifp->ifname, ifname);
#ifdef _HAVE_VRRP_VMAC_
	ifp->base_ifp = ifp;
#endif
	if_add_queue(ifp);

	if (create == IF_CREATE_IF_DYNAMIC)
		log_message(LOG_INFO, "Configuration specifies interface %s which doesn't currently exist - will use if created", ifname);

	return ifp;
}

#ifdef _HAVE_VRRP_VMAC_
/* Set the base_ifp for vmacs - only used at startup */
void
set_base_ifp(void)
{
	interface_t *ifp;
	element e;

	if (LIST_ISEMPTY(if_queue))
		return;

	for (e = LIST_HEAD(if_queue); e; ELEMENT_NEXT(e)) {
		ifp = ELEMENT_DATA(e);
		if (!ifp->base_ifp &&
		    ifp->base_ifindex) {
			ifp->base_ifp = if_get_by_ifindex(ifp->base_ifindex);
			ifp->base_ifindex = 0;	/* This is only used at startup, so ensure not used later */
		}
	}
}
#endif

/* Return the interface list itself */
list
get_if_list(void)
{
	return if_queue;
}

void
reset_interface_queue(void)
{
	old_if_queue = if_queue;
	old_garp_delay = garp_delay;

	if_queue = NULL;
	garp_delay = NULL;
}

/* MII Transceiver Registers poller functions */
static uint16_t
if_mii_read(int fd, uint16_t phy_id, uint16_t reg_num)
{
	struct mii_ioctl_data *data = (struct mii_ioctl_data *)&ifr.ifr_data;

	data->phy_id = phy_id;
	data->reg_num = reg_num;

	if (ioctl(fd, SIOCGMIIREG, &ifr) < 0) {
		log_message(LOG_ERR, "SIOCGMIIREG on %s failed: %s", ifr.ifr_name, strerror(errno));
		return 0xffff;
	}
	return data->val_out;
}

#ifdef _INCLUDE_UNUSED_CODE_
static void if_mii_dump(const uint16_t *mii_regs, size_t num_regs unsigned phy_id)
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
	struct mii_ioctl_data *data = (struct mii_ioctl_data *)&ifr.ifr_data;
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

// printf(" \nBasic Mode Status Register 0x%4.4x ... 0x%4.4x\n", bmsr, new_bmsr);

	if (bmsr & BMSR_LSTATUS)
		return LINK_UP;
	else if (new_bmsr & BMSR_LSTATUS)
		return LINK_UP;
	else
		return LINK_DOWN;
}

static int
if_mii_probe(const char *ifname)
{
	struct mii_ioctl_data *data = (struct mii_ioctl_data *)&ifr.ifr_data;
	uint16_t phy_id;
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	int status;

	if (fd < 0)
		return -1;

#if !HAVE_DECL_SOCK_CLOEXEC
	if (set_sock_flags(fd, F_SETFD, FD_CLOEXEC))
		log_message(LOG_INFO, "Unable to set CLOEXEC on mii_probe socket - %s (%d)", strerror(errno), errno);
#endif

	memset(&ifr, 0, sizeof (struct ifreq));
	strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	if (ioctl(fd, SIOCGMIIPHY, &ifr) < 0) {
		close(fd);
		return -1;
	}

	/* check if the driver reports BMSR using the MII interface, as we
	 * will need this and we already know that some don't support it.
	 */
	phy_id = data->phy_id; /* save it in case it is overwritten */
	data->reg_num = MII_BMSR;
	if (ioctl(fd, SIOCGMIIREG, &ifr) < 0) {
		close(fd);
		return -1;
	}
	data->phy_id = phy_id;

	/* Dump the MII transceiver */
	status = if_mii_status(fd);
	close(fd);
	return status;
}

static int
if_ethtool_status(const int fd)
{
	struct ethtool_value edata;

	edata.cmd = ETHTOOL_GLINK;
	ifr.ifr_data = (caddr_t) & edata;
	if (!ioctl(fd, SIOCETHTOOL, &ifr))
		return (edata.data) ? 1 : 0;
	return -1;
}

static int
if_ethtool_probe(const char *ifname)
{
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	int status;

	if (fd < 0)
		return -1;

#if !HAVE_DECL_SOCK_CLOEXEC
	if (set_sock_flags(fd, F_SETFD, FD_CLOEXEC))
		log_message(LOG_INFO, "Unable to set CLOEXEC on ethtool_probe socket - %s (%d)", strerror(errno), errno);
#endif

	memset(&ifr, 0, sizeof (struct ifreq));
	strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));

	status = if_ethtool_status(fd);
	close(fd);
	return status;
}

/* Returns false if interface is down */
static bool
if_ioctl_flags(interface_t *ifp)
{
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return true;

#if !HAVE_DECL_SOCK_CLOEXEC
	if (set_sock_flags(fd, F_SETFD, FD_CLOEXEC))
		log_message(LOG_INFO, "Unable to set CLOEXEC on ioctl_flags socket - %s (%d)", strerror(errno), errno);
#endif

	memset(&ifr, 0, sizeof (struct ifreq));
	strncpy(ifr.ifr_name, ifp->ifname, sizeof (ifr.ifr_name));
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		close(fd);
		return true;
	}

	close(fd);

	return FLAGS_UP(ifr.ifr_flags);
}

/* Interfaces lookup */
static void
free_if(void *data)
{
	interface_t *ifp = data;

	free_list(&ifp->tracking_vrrp);
	FREE(data);
}

/* garp_delay facility function */
void
alloc_garp_delay(void)
{
	if (!LIST_EXISTS(garp_delay))
		garp_delay = alloc_list(NULL, NULL);

	list_add(garp_delay, MALLOC(sizeof(garp_delay_t)));
}

void
set_default_garp_delay(void)
{
	garp_delay_t default_delay;
	element e;
	interface_t *ifp;
	garp_delay_t *delay;

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

	/* Allocate a delay structure to each physical interface that doesn't have one */
	for (e = LIST_HEAD(if_queue); e; ELEMENT_NEXT(e)) {
		ifp = ELEMENT_DATA(e);
		if (!ifp->garp_delay
#ifdef _HAVE_VRRP_VMAC_
				     && !ifp->vmac
#endif
						  )
		{
			alloc_garp_delay();
			delay = LIST_TAIL_DATA(garp_delay);
			*delay = default_delay;
			ifp->garp_delay = delay;
		}
	}
}

static void
dump_if(void *data)
{
	interface_t *ifp = data;
#ifdef _HAVE_VRRP_VMAC_
	interface_t *ifp_u;
#endif
	char addr_str[INET6_ADDRSTRLEN];
	unsigned ifi_flags;
	char mac_str[3 * ifp->hw_addr_len];
	char *mac_ptr = mac_str;
	unsigned int i;

	log_message(LOG_INFO, "------< NIC >------");
	log_message(LOG_INFO, " Name = %s", ifp->ifname);
	log_message(LOG_INFO, " index = %u", ifp->ifindex);
	log_message(LOG_INFO, " IPv4 address = %s", inet_ntop2(ifp->sin_addr.s_addr));
	inet_ntop(AF_INET6, &ifp->sin6_addr, addr_str, sizeof(addr_str));
	log_message(LOG_INFO, " IPv6 address = %s", addr_str);

	mac_ptr[0] = '\0';
	for (i = 0; i < ifp->hw_addr_len; i++)
		mac_ptr += sprintf(mac_ptr, "%s%.2x", i ? ":" : "", ifp->hw_addr[i]);
	log_message(LOG_INFO, " MAC = %s", mac_str);

	ifi_flags = ifp->ifi_flags & (IFF_UP | IFF_RUNNING);
#ifdef _HAVE_VRRP_VMAC_
	ifi_flags &= ifp->base_ifp->ifi_flags;
#endif
	if (ifi_flags == (IFF_UP | IFF_RUNNING))
		log_message(LOG_INFO, " is UP");
	else if (ifi_flags & IFF_UP)
		log_message(LOG_INFO, " is UP not RUNNING");
	else if (ifi_flags & IFF_RUNNING)
		log_message(LOG_INFO, " is RUNNING not UP");
	else
		log_message(LOG_INFO, " is DOWN");

	log_message(LOG_INFO, " MTU = %d", ifp->mtu);

	switch (ifp->hw_type) {
	case ARPHRD_LOOPBACK:
		log_message(LOG_INFO, " HW Type = LOOPBACK");
		break;
	case ARPHRD_ETHER:
		log_message(LOG_INFO, " HW Type = ETHERNET");
		break;
	default:
		log_message(LOG_INFO, " HW Type = UNKNOWN");
		break;
	}

#ifdef _HAVE_VRRP_VMAC_
	if (ifp->vmac && (ifp_u = ifp->base_ifp))
		log_message(LOG_INFO, " VMAC underlying interface = %s", ifp_u->ifname);
#endif

	if (ifp->linkbeat_use_polling) {
		/* MII channel supported ? */
		if (IF_MII_SUPPORTED(ifp))
			log_message(LOG_INFO, " NIC support MII regs");
		else if (IF_ETHTOOL_SUPPORTED(ifp))
			log_message(LOG_INFO, " NIC support ETHTOOL GLINK interface");
		else
			log_message(LOG_INFO, " NIC ioctl refresh polling");
	}

	if (ifp->garp_delay) {
		if (ifp->garp_delay->have_garp_interval)
			log_message(LOG_INFO, " Gratuitous ARP interval %ldms",
				    ifp->garp_delay->garp_interval.tv_sec * 100 +
				     ifp->garp_delay->garp_interval.tv_usec / (TIMER_HZ / 100));

		if (ifp->garp_delay->have_gna_interval)
			log_message(LOG_INFO, " Gratuitous NA interval %ldms",
				    ifp->garp_delay->gna_interval.tv_sec * 100 +
				     ifp->garp_delay->gna_interval.tv_usec / (TIMER_HZ / 100));
		if (ifp->garp_delay->aggregation_group)
			log_message(LOG_INFO, " Gratuitous ARP aggregation group %d", ifp->garp_delay->aggregation_group);
	}
	log_message(LOG_INFO, " Tracking VRRP = %d", !LIST_ISEMPTY(ifp->tracking_vrrp) ? LIST_SIZE(ifp->tracking_vrrp) : 0);
	if (!LIST_ISEMPTY(ifp->tracking_vrrp))
		dump_list(ifp->tracking_vrrp);
}

static void
init_if_queue(void)
{
	if_queue = alloc_list(free_if, dump_if);
}

void
if_add_queue(interface_t * ifp)
{
	list_add(if_queue, ifp);
}

static int
if_linkbeat_refresh_thread(thread_t * thread)
{
	interface_t *ifp = THREAD_ARG(thread);
	bool if_up = true, was_up;

	was_up = IF_FLAGS_UP(ifp);

	if (IF_MII_SUPPORTED(ifp))
		if_up = if_mii_probe(ifp->ifname);
	else if (IF_ETHTOOL_SUPPORTED(ifp))
		if_up = if_ethtool_probe(ifp->ifname);

	/*
	 * update ifp->flags to get the new IFF_RUNNING status.
	 * Some buggy drivers need this...
	 */
	if (if_up)
		if_up = if_ioctl_flags(ifp);

	ifp->ifi_flags = if_up ? IFF_UP | IFF_RUNNING : 0;

	if (if_up != was_up) {
		log_message(LOG_INFO, "Linkbeat reports %s %s", ifp->ifname, if_up ? "up" : "down");

		process_if_status_change(ifp);
	}

	/* Register next polling thread */
	thread_add_timer(master, if_linkbeat_refresh_thread, ifp, POLLING_DELAY);
	return 0;
}

void
init_interface_linkbeat(void)
{
	interface_t *ifp;
	element e;
	int status;
	bool linkbeat_in_use = false;
	bool if_up;

	for (e = LIST_HEAD(if_queue); e; ELEMENT_NEXT(e)) {
		ifp = ELEMENT_DATA(e);

		if (!ifp->linkbeat_use_polling)
			continue;

		/* Don't poll an interface that we aren't using */
		if (!ifp->tracking_vrrp)
			continue;

#ifdef _HAVE_VRRP_VMAC_
		/* netlink messages work for vmacs */
		if (ifp->vmac)
			continue;
#endif

		linkbeat_in_use = true;
		ifp->ifi_flags = IFF_UP | IFF_RUNNING;

		ifp->lb_type = LB_IOCTL;
		status = if_mii_probe(ifp->ifname);
		if (status >= 0) {
			ifp->lb_type = LB_MII;
			if_up = !!status;
		} else if ((status = if_ethtool_probe(ifp->ifname)) >= 0) {
			ifp->lb_type = LB_ETHTOOL;
			if_up = !!status;
		}
		else
			if_up = true;
		if (if_up)
			if_up = if_ioctl_flags(ifp);

		ifp->ifi_flags = if_up ? IFF_UP | IFF_RUNNING : 0;

		/* Register new monitor thread */
		thread_add_timer(master, if_linkbeat_refresh_thread, ifp, POLLING_DELAY);
	}

	if (linkbeat_in_use)
		log_message(LOG_INFO, "Using MII-BMSR/ETHTOOL NIC polling thread...");
}

/* Interface queue helpers*/
void
free_interface_queue(void)
{
	free_list(&if_queue);
	free_list(&garp_delay);
}

void
free_old_interface_queue(void)
{
	free_list(&old_if_queue);
	free_list(&old_garp_delay);
}

void
init_interface_queue(void)
{
	init_if_queue();
	netlink_interface_lookup(NULL);
#ifdef _HAVE_VRRP_VMAC_
	/* Since we are reading all the interfaces, we might have received details of
	 * a vmac before the underlying interface, so now we need to ensure the
	 * interface pointers are all set */
	set_base_ifp();
#endif
//	dump_list(if_queue);
}

int
if_join_vrrp_group(sa_family_t family, int *sd, interface_t *ifp)
{
	struct ip_mreqn imr;
	struct ipv6_mreq imr6;
	int ret = 0;

	if (*sd < 0)
		return -1;

	/* -> outbound processing option
	 * join the multicast group.
	 * binding the socket to the interface for outbound multicast
	 * traffic.
	 */

	if (family == AF_INET) {
		memset(&imr, 0, sizeof(imr));
		imr.imr_multiaddr = global_data->vrrp_mcast_group4.sin_addr;
		imr.imr_ifindex = (int)IF_INDEX(ifp);

		/* -> Need to handle multicast convergance after takeover.
		 * We retry until multicast is available on the interface.
		 */
		ret = setsockopt(*sd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
				 (char *) &imr, (socklen_t)sizeof(struct ip_mreqn));
	} else {
		memset(&imr6, 0, sizeof(imr6));
		imr6.ipv6mr_multiaddr = global_data->vrrp_mcast_group6.sin6_addr;
		imr6.ipv6mr_interface = IF_INDEX(ifp);
		ret = setsockopt(*sd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
				 (char *) &imr6, (socklen_t)sizeof(struct ipv6_mreq));
	}

	if (ret < 0) {
		log_message(LOG_INFO, "(%s) cant do IP%s_ADD_MEMBERSHIP errno=%s (%d)",
			    ifp->ifname, (family == AF_INET) ? "" : "V6", strerror(errno), errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

int
if_leave_vrrp_group(sa_family_t family, int sd, interface_t *ifp)
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
		imr.imr_ifindex = (int)IF_INDEX(ifp);
		ret = setsockopt(sd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
				 (char *) &imr, sizeof(imr));
	} else {
		memset(&imr6, 0, sizeof(imr6));
		imr6.ipv6mr_multiaddr = global_data->vrrp_mcast_group6.sin6_addr;
		imr6.ipv6mr_interface = IF_INDEX(ifp);
		ret = setsockopt(sd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
				 (char *) &imr6, sizeof(struct ipv6_mreq));
	}

	if (ret < 0) {
		log_message(LOG_INFO, "(%s) cant do IP%s_DROP_MEMBERSHIP errno=%s (%d)",
			    ifp->ifname, (family == AF_INET) ? "" : "V6", strerror(errno), errno);
		return -1;
	}

	return 0;
}

int
if_setsockopt_bindtodevice(int *sd, interface_t *ifp)
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

	if (!sd && *sd < 0)
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
#ifndef IP_MULTICAST_ALL	/* Since Linux 2.6.31 */
if_setsockopt_mcast_all(__attribute__((unused)) sa_family_t family, __attribute__((unused)) int *sd)
{
	/* It seems reasonable to just skip the calls to if_setsockopt_mcast_all
	 * if there is no support for that feature in header files */
	return -1;
#else
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
#endif
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
if_setsockopt_mcast_if(sa_family_t family, int *sd, interface_t *ifp)
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

#ifdef _TIMER_DEBUG_
void
print_vrrp_if_addresses(void)
{
	log_message(LOG_INFO, "Address of if_linkbeat_refresh_thread() is 0x%p", if_linkbeat_refresh_thread);
}
#endif

void
cleanup_lost_interface(interface_t *ifp)
{
	vrrp_t *vrrp;
	tracking_vrrp_t *tvp;
	element e;

	ifp->ifindex = 0;
	ifp->ifi_flags = 0;

	if (LIST_ISEMPTY(ifp->tracking_vrrp))
		return;

	for (e = LIST_HEAD(ifp->tracking_vrrp); e; ELEMENT_NEXT(e)) {
		tvp = ELEMENT_DATA(e);
		vrrp = tvp->vrrp;

		/* If this is just a tracking interface, we don't need to do anything */
		if (vrrp->ifp != ifp && IF_BASE_IFP(ifp) != ifp)
			continue;

#ifdef _HAVE_VRRP_VMAC_
		/* If vmac going, clear VMAC_UP_BIT on vrrp instance */
		if (vrrp->ifp->vmac) {
			__clear_bit(VRRP_VMAC_UP_BIT, &vrrp->vmac_flags);
//			vrrp->ifp = vrrp->ifp->base_ifp;
		}
#endif

		/* Find the sockpool entry. If none, then we have closed the socket */
		if (vrrp->sockets->fd_in != -1) {
			remove_vrrp_fd_bucket(vrrp->sockets->fd_in);
			thread_cancel_read(master, vrrp->sockets->fd_in);
			close(vrrp->sockets->fd_in);
			vrrp->sockets->fd_in = -1;
		}
		if (vrrp->sockets->fd_out != -1) {
			close(vrrp->sockets->fd_out);
			vrrp->sockets->fd_out = -1;
		}
		vrrp->sockets->ifindex = 0;
	}
}

void
update_added_interface(interface_t *ifp)
{
	vrrp_t *vrrp;
	tracking_vrrp_t *tvp;
	element e;

	if (LIST_ISEMPTY(ifp->tracking_vrrp))
		return;

	for (e = LIST_HEAD(ifp->tracking_vrrp); e; ELEMENT_NEXT(e)) {
		tvp = ELEMENT_DATA(e);
		vrrp = tvp->vrrp;

		/* If this is just a tracking interface, we don't need to do anything */
		if (vrrp->ifp != ifp && IF_BASE_IFP(ifp) != ifp)
			continue;

#ifdef _HAVE_VRRP_VMAC_
		if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags))
			netlink_link_add_vmac(vrrp);
#endif

		/* Find the sockpool entry. If none, then we open the socket */
		if (vrrp->sockets->fd_in == -1) {
			vrrp->sockets->fd_in = open_vrrp_read_socket(vrrp->sockets->family, vrrp->sockets->proto,
								ifp, vrrp->sockets->unicast);
			if (vrrp->sockets->fd_in == -1)
				vrrp->sockets->fd_out = -1;
			else
				vrrp->sockets->fd_out = open_vrrp_send_socket(vrrp->sockets->family, vrrp->sockets->proto,
								ifp, vrrp->sockets->unicast);

			if (vrrp->sockets->fd_out > master->max_fd)
				master->max_fd = vrrp->sockets->fd_out;
			if (vrrp->sockets->fd_in > master->max_fd)
				master->max_fd = vrrp->sockets->fd_in;
			vrrp->sockets->ifindex = ifp->ifindex;

			alloc_vrrp_fd_bucket(vrrp);

			if (vrrp_initialised) {
				vrrp->state = VRRP_STATE_FAULT;
				vrrp_init_instance_sands(vrrp);
				vrrp_thread_add_read(vrrp);
			}
		}
		else
			alloc_vrrp_fd_bucket(vrrp);
	}
}
