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

/* global include */
#include <unistd.h>
#include <string.h>
#include <stdint.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <ctype.h>
#ifdef use_linux_libc5
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#ifdef _KRNL_2_4_
#include <linux/ethtool.h>
#endif

/* local include */
#include "scheduler.h"
#include "global_data.h"
#include "vrrp_data.h"
#include "vrrp.h"
#include "vrrp_if.h"
#include "vrrp_netlink.h"
#include "memory.h"
#include "utils.h"
#include "logger.h"

/* Global vars */
static list if_queue;
static struct ifreq ifr;

/* Helper functions */
/* Return interface from interface index */
interface_t *
if_get_by_ifindex(const int ifindex)
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
base_if_get_by_ifindex(const int ifindex)
{
	interface_t *ifp = if_get_by_ifindex(ifindex);

	return (ifp && ifp->vmac) ? if_get_by_ifindex(ifp->base_ifindex) : ifp;
}

interface_t *
if_get_by_ifname(const char *ifname)
{
	interface_t *ifp;
	element e;

	if (LIST_ISEMPTY(if_queue))
		return NULL;

	for (e = LIST_HEAD(if_queue); e; ELEMENT_NEXT(e)) {
		ifp = ELEMENT_DATA(e);
		if (!strcmp(ifp->ifname, ifname))
			return ifp;
	}
	return NULL;
}

/*
 * Reflect base interface flags on VMAC interfaces.
 * VMAC interfaces should never update it own flags, only be reflected
 * by the base interface flags.
 */
void
if_vmac_reflect_flags(const int ifindex, const unsigned long flags)
{
	interface_t *ifp;
	element e;

	if (LIST_ISEMPTY(if_queue) || !ifindex)
		return;

	for (e = LIST_HEAD(if_queue); e; ELEMENT_NEXT(e)) {
		ifp = ELEMENT_DATA(e);
		if (ifp->vmac && ifp->base_ifindex == ifindex)
			ifp->flags = flags;
	}
}

/* MII Transceiver Registers poller functions */
static int
if_mii_read(const int fd, const int phy_id, int location)
{
	uint16_t *data = (uint16_t *) (&ifr.ifr_data);

	data[0] = phy_id;
	data[1] = location;

	if (ioctl(fd, SIOCGMIIREG, &ifr) < 0) {
		log_message(LOG_ERR, "SIOCGMIIREG on %s failed: %s", ifr.ifr_name,
		       strerror(errno));
		return -1;
	}
	return data[3];
}

/*
static void if_mii_dump(const uint16_t mii_regs[32], unsigned phy_id)
{
  int mii_reg;

  printf(" MII PHY #%d transceiver registers:\n", phy_id);
  for (mii_reg = 0; mii_reg < 32; mii_reg++)
    printf("%s %4.4x", (mii_reg % 8) == 0 ? "\n ":"", mii_regs[mii_reg]);
}
*/

static int
if_mii_status(const int fd)
{
	uint16_t *data = (uint16_t *) (&ifr.ifr_data);
	unsigned phy_id = data[0];
	uint16_t mii_regs[32];
	int mii_reg;
	uint16_t bmsr, new_bmsr;

	/* Reset MII registers */
	memset(mii_regs, 0, sizeof (mii_regs));

	for (mii_reg = 0; mii_reg < 32; mii_reg++)
		mii_regs[mii_reg] = if_mii_read(fd, phy_id, mii_reg);

// if_mii_dump(mii_regs, phy_id);

	if (mii_regs[0] == 0xffff) {
		log_message(LOG_ERR, "No MII transceiver present for %s !!!",
		       ifr.ifr_name);
		return -1;
	}

	bmsr = mii_regs[1];

	/*
	 * For Basic Mode Status Register (BMSR).
	 * Sticky field (Link established & Jabber detected), we need to read
	 * a second time the BMSR to get current status.
	 */
	new_bmsr = if_mii_read(fd, phy_id, 1);

// printf(" \nBasic Mode Status Register 0x%4.4x ... 0x%4.4x\n", bmsr, new_bmsr);

	if (bmsr & 0x0004)
		return LINK_UP;
	else if (new_bmsr & 0x0004)
		return LINK_UP;
	else
		return LINK_DOWN;
}

int
if_mii_probe(const char *ifname)
{
	uint16_t *data = (uint16_t *) (&ifr.ifr_data);
	int phy_id;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	int status = 0;

	if (fd < 0)
		return -1;
	memset(&ifr, 0, sizeof (struct ifreq));
	strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	if (ioctl(fd, SIOCGMIIPHY, &ifr) < 0) {
		close(fd);
		return -1;
	}

	/* check if the driver reports BMSR using the MII interface, as we
	 * will need this and we already know that some don't support it.
	 */
	phy_id = data[0]; /* save it in case it is overwritten */
	data[1] = 1;
	if (ioctl(fd, SIOCGMIIREG, &ifr) < 0) {
		close(fd);
		return -1;
	}
	data[0] = phy_id;

	/* Dump the MII transceiver */
	status = if_mii_status(fd);
	close(fd);
	return status;
}

static int
if_ethtool_status(const int fd)
{
#ifdef ETHTOOL_GLINK
	struct ethtool_value edata;
	int err = 0;

	edata.cmd = ETHTOOL_GLINK;
	ifr.ifr_data = (caddr_t) & edata;
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err == 0)
		return (edata.data) ? 1 : 0;
	else
#endif
		return -1;
}

int
if_ethtool_probe(const char *ifname)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	int status = 0;

	if (fd < 0)
		return -1;
	memset(&ifr, 0, sizeof (struct ifreq));
	strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));

	status = if_ethtool_status(fd);
	close(fd);
	return status;
}

void
if_ioctl_flags(interface_t * ifp)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		return;
	memset(&ifr, 0, sizeof (struct ifreq));
	strncpy(ifr.ifr_name, ifp->ifname, sizeof (ifr.ifr_name));
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		close(fd);
		return;
	}
	ifp->flags = ifr.ifr_flags;
	close(fd);
}

/* Interfaces lookup */
static void
free_if(void *data)
{
	FREE(data);
}

void
dump_if(void *data)
{
	interface_t *ifp = data;
	char addr_str[41];

	log_message(LOG_INFO, "------< NIC >------");
	log_message(LOG_INFO, " Name = %s", ifp->ifname);
	log_message(LOG_INFO, " index = %d", ifp->ifindex);
	log_message(LOG_INFO, " IPv4 address = %s", inet_ntop2(ifp->sin_addr.s_addr));
	inet_ntop(AF_INET6, &ifp->sin6_addr, addr_str, 41);
	log_message(LOG_INFO, " IPv6 address = %s", addr_str);

	/* FIXME: Harcoded for ethernet */
	if (ifp->hw_type == ARPHRD_ETHER)
		log_message(LOG_INFO, " MAC = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
		       ifp->hw_addr[0], ifp->hw_addr[1], ifp->hw_addr[2]
		       , ifp->hw_addr[3], ifp->hw_addr[4], ifp->hw_addr[5]);

	if (ifp->flags & IFF_UP)
		log_message(LOG_INFO, " is UP");

	if (ifp->flags & IFF_RUNNING)
		log_message(LOG_INFO, " is RUNNING");

	if (!(ifp->flags & IFF_UP) && !(ifp->flags & IFF_RUNNING))
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

	/* MII channel supported ? */
	if (IF_MII_SUPPORTED(ifp))
		log_message(LOG_INFO, " NIC support MII regs");
	else if (IF_ETHTOOL_SUPPORTED(ifp))
		log_message(LOG_INFO, " NIC support EHTTOOL GLINK interface");
	else
		log_message(LOG_INFO, " Enabling NIC ioctl refresh polling");
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

	if (IF_MII_SUPPORTED(ifp))
		ifp->linkbeat = (if_mii_probe(ifp->ifname)) ? 1 : 0;
	else if (IF_ETHTOOL_SUPPORTED(ifp))
		ifp->linkbeat = (if_ethtool_probe(ifp->ifname)) ? 1 : 0;
	else
		ifp->linkbeat = 1;

	/*
	 * update ifp->flags to get the new IFF_RUNNING status.
	 * Some buggy drivers need this...
	 */
	if_ioctl_flags(ifp);

	/* Register next polling thread */
	thread_add_timer(master, if_linkbeat_refresh_thread, ifp, POLLING_DELAY);
	return 0;
}

static void
init_if_linkbeat(void)
{
	interface_t *ifp;
	element e;
	int status;

	for (e = LIST_HEAD(if_queue); e; ELEMENT_NEXT(e)) {
		ifp = ELEMENT_DATA(e);
		ifp->lb_type = LB_IOCTL;
		status = if_mii_probe(ifp->ifname);
		if (status >= 0) {
			ifp->lb_type = LB_MII;
			ifp->linkbeat = (status) ? 1 : 0;
		} else {
			status = if_ethtool_probe(ifp->ifname);
			if (status >= 0) {
				ifp->lb_type = LB_ETHTOOL;
				ifp->linkbeat = (status) ? 1 : 0;
			}
		}

		/* Register new monitor thread */
		thread_add_timer(master, if_linkbeat_refresh_thread, ifp, POLLING_DELAY);
	}
}

int
if_linkbeat(const interface_t * ifp)
{
	if (!global_data->linkbeat_use_polling)
		return 1;

	if (IF_MII_SUPPORTED(ifp) || IF_ETHTOOL_SUPPORTED(ifp))
		return IF_LINKBEAT(ifp);

	return 1;
}

/* Interface queue helpers*/
void
free_interface_queue(void)
{
	if (!LIST_ISEMPTY(if_queue))
		free_list(if_queue);
	if_queue = NULL;
}

void
init_interface_queue(void)
{
	init_if_queue();
	netlink_interface_lookup();
//	dump_list(if_queue);
}

void
init_interface_linkbeat(void)
{
	if (global_data->linkbeat_use_polling) {
		log_message(LOG_INFO, "Using MII-BMSR NIC polling thread...");
		init_if_linkbeat();
	} else {
		log_message(LOG_INFO, "Using LinkWatch kernel netlink reflector...");
	}
}

int
if_join_vrrp_group(sa_family_t family, int *sd, interface_t *ifp, int proto)
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
		imr.imr_multiaddr = ((struct sockaddr_in *) &global_data->vrrp_mcast_group4)->sin_addr;
		imr.imr_address.s_addr = IF_ADDR(ifp);
		imr.imr_ifindex = IF_INDEX(ifp);

		/* -> Need to handle multicast convergance after takeover.
		 * We retry until multicast is available on the interface.
		 */
		ret = setsockopt(*sd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
				 (char *) &imr, sizeof(struct ip_mreqn));
	} else {
		memset(&imr6, 0, sizeof(imr6));
		imr6.ipv6mr_multiaddr = ((struct sockaddr_in6 *) &global_data->vrrp_mcast_group6)->sin6_addr;
		imr6.ipv6mr_interface = IF_INDEX(ifp);
		ret = setsockopt(*sd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
				 (char *) &imr6, sizeof(struct ipv6_mreq));
	}

	if (ret < 0) {
		log_message(LOG_INFO, "cant do IP%s_ADD_MEMBERSHIP errno=%s (%d)",
			    (family == AF_INET) ? "" : "V6", strerror(errno), errno);
		close(*sd);
		*sd = -1;
        }

	return *sd;
}

int
if_leave_vrrp_group(sa_family_t family, int sd, interface_t *ifp)
{
	struct ip_mreq imr;
	struct ipv6_mreq imr6;
	int ret = 0;

	/* If fd is -1 then we add a membership trouble */
	if (sd < 0 || !ifp)
		return -1;

	/* Leaving the VRRP multicast group */
	if (family == AF_INET) {
		memset(&imr, 0, sizeof(imr));
		imr.imr_multiaddr = ((struct sockaddr_in *) &global_data->vrrp_mcast_group4)->sin_addr;
		imr.imr_interface.s_addr = IF_ADDR(ifp);
		ret = setsockopt(sd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
				 (char *) &imr, sizeof(struct ip_mreq));
	} else {
		memset(&imr6, 0, sizeof(imr6));
		imr6.ipv6mr_multiaddr = ((struct sockaddr_in6 *) &global_data->vrrp_mcast_group6)->sin6_addr;
		imr6.ipv6mr_interface = IF_INDEX(ifp);
		ret = setsockopt(sd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
				 (char *) &imr6, sizeof(struct ipv6_mreq));
	}

	if (ret < 0) {
		log_message(LOG_INFO, "cant do IP%s_DROP_MEMBERSHIP errno=%s (%d)",
			    (family == AF_INET) ? "" : "V6", strerror(errno), errno);
		close(sd);
		return -1;
	}

	/* Finally close the desc */
	close(sd);
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
	ret = setsockopt(*sd, SOL_SOCKET, SO_BINDTODEVICE, IF_NAME(ifp), strlen(IF_NAME(ifp)) + 1);
	if (ret < 0) {
		log_message(LOG_INFO, "cant bind to device %s. errno=%d. (try to run it as root)",
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
	unsigned int ifindex;

	/* Not applicable for IPv4 */
	if (*sd < 0 || family == AF_INET)
		return -1;

	/* Set interface for sending outbound datagrams */
	ifindex = IF_INDEX(ifp);
	ret = setsockopt(*sd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex));
	if (ret < 0) {
		log_message(LOG_INFO, "cant set IPV6_MULTICAST_IF IP option. errno=%d (%m)", errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

int
if_setsockopt_priority(int *sd)
{
	int ret;
	int priority = 6;

	if (*sd < 0)
		return -1;

	/* Set SO_PRIORITY for VRRP traffic */
	ret = setsockopt(*sd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	if (ret < 0) {
		log_message(LOG_INFO, "cant set SO_PRIORITY IP option. errno=%d (%m)", errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

int
if_setsockopt_sndbuf(int *sd, int val)
{
	int ret;

	if (*sd < 0)
		return -1;

	/* sndbuf option */
        ret = setsockopt(*sd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
        if (ret < 0) {
		log_message(LOG_INFO, "cant set SO_SNDBUF IP option. errno=%d (%m)", errno);
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
