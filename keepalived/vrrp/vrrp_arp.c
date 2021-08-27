/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        ARP primitives.
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

/* system includes */
#include <unistd.h>
#ifdef _HAVE_LINUX_IF_ETHER_H_COLLISION_
#include <netinet/in.h>
#endif
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <errno.h>

/* local includes */
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "bitops.h"
#include "vrrp_scheduler.h"
#include "vrrp_arp.h"

/*
 * The size of the garp_buffer should be the large enough to hold
 * the largest arp packet to be sent + the size of the link layer header
 * for the corresponding protocol
 * For infiniband the link layer header consists of the destination MAC
 * address(20 bytes) and protocol identifier of the encapsulated
 * datagram(4 bytes). This is larger than the space required for Ethernet
 */
#define GARP_BUFFER_SIZE (sizeof(inf_arphdr_t) + sizeof (ipoib_hdr_t) +\
			  (INFINIBAND_ALEN))

/*
 * Private link layer socket structure to hold infiniband size address
 * The infiniband MAC address is 20 bytes long
 */
struct sockaddr_large_ll {
	unsigned short	sll_family;
	__be16		sll_protocol;
	int		sll_ifindex;
	unsigned short	sll_hatype;
	unsigned char	sll_pkttype;
	unsigned char	sll_halen;
	unsigned char	sll_addr[INFINIBAND_ALEN];
};

/* static vars */
static char *garp_buffer;
static int garp_fd = -1;

/* Send the gratuitous ARP message */
static ssize_t send_arp(ip_address_t *ipaddress, ssize_t pack_len)
{
	interface_t *ifp = ipaddress->ifp;
	struct sockaddr_storage ss;
	struct sockaddr_large_ll *sll = PTR_CAST(struct sockaddr_large_ll, &ss);
	ssize_t len;

	/* Build the dst device */
	memset(&ss, 0, sizeof(ss));
	sll->sll_family = AF_PACKET;
	sll->sll_hatype = ifp->hw_type;
	sll->sll_protocol = htons(ETHERTYPE_ARP);
	sll->sll_ifindex = (int) ifp->ifindex;

	/* The values in sll_addr and sll_halen appear to be ignored */
	sll->sll_halen = ifp->hw_addr_len;
	memcpy(sll->sll_addr,
	       ifp->hw_addr_bcast, ifp->hw_addr_len);

	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "Sending gratuitous ARP on %s for %s",
			    ifp->ifname,
			    inet_ntop2(ipaddress->u.sin.sin_addr.s_addr));

	/* Send packet */
	len = sendto(garp_fd, garp_buffer, pack_len, 0,
		     PTR_CAST(struct sockaddr, sll), sizeof(*sll));
	if (len < 0) {
		/* coverity[bad_printf_format_string] */
		log_message(LOG_INFO, "Error %d (%m) sending gratuitous ARP on %s for %s", errno,
			    IF_NAME(ipaddress->ifp), inet_ntop2(ipaddress->u.sin.sin_addr.s_addr));
	}
	return len;
}

/* Build a gratuitous ARP message over a specific interface */
ssize_t send_gratuitous_arp_immediate(interface_t *ifp, ip_address_t *ipaddress)
{
	char *hwaddr = PTR_CAST(char, IF_HWADDR(ipaddress->ifp));
	struct arphdr *arph;
	char *arp_ptr;
	ssize_t len, pack_len;

	if (ifp->hw_addr_len == 0)
		return -1;

	/* Setup link layer header */
	if (ifp->hw_type == ARPHRD_INFINIBAND) {
		struct ipoib_hdr  *ipoib;

		/*  Add ipoib link layer header MAC + proto */
		memcpy(garp_buffer, ifp->hw_addr_bcast, ifp->hw_addr_len);
		ipoib = PTR_CAST(struct ipoib_hdr, (garp_buffer + ifp->hw_addr_len));
		ipoib->proto = htons(ETHERTYPE_ARP);
		ipoib->reserved = 0;
		arph = PTR_CAST(struct arphdr, garp_buffer + ifp->hw_addr_len +
					 sizeof(*ipoib));
	} else {
		struct ether_header *eth;

		eth = PTR_CAST(struct ether_header, garp_buffer);
		memcpy(eth->ether_dhost, ifp->hw_addr_bcast, ETH_ALEN < ifp->hw_addr_len ? ETH_ALEN : ifp->hw_addr_len);
		memcpy(eth->ether_shost, hwaddr, ETH_ALEN < ifp->hw_addr_len ? ETH_ALEN : ifp->hw_addr_len);
		eth->ether_type = htons(ETHERTYPE_ARP);
		arph = PTR_CAST(struct arphdr, (garp_buffer + ETHER_HDR_LEN));
	}

	/* ARP payload */
	arph->ar_hrd = htons(ifp->hw_type);
	arph->ar_pro = htons(ETHERTYPE_IP);
	arph->ar_hln = ifp->hw_addr_len;
	arph->ar_pln = sizeof(struct in_addr);
	arph->ar_op = htons(ARPOP_REQUEST);
	arp_ptr = PTR_CAST(char, (arph + 1));
	memcpy(arp_ptr, hwaddr, ifp->hw_addr_len);
	arp_ptr += ifp->hw_addr_len;
	memcpy(arp_ptr, &ipaddress->u.sin.sin_addr.s_addr,
	       sizeof(struct in_addr));
	arp_ptr += sizeof (struct in_addr);
	memcpy(arp_ptr, ifp->hw_addr_bcast, ifp->hw_addr_len);
	arp_ptr += ifp->hw_addr_len;
	memcpy(arp_ptr, &ipaddress->u.sin.sin_addr.s_addr,
	       sizeof(struct in_addr));
	arp_ptr += sizeof(struct in_addr);

	pack_len = arp_ptr - garp_buffer;
	len = send_arp(ipaddress, pack_len);

	/* If we have to delay between sending garps, note the next time we can */
	if (ifp->garp_delay && ifp->garp_delay->have_garp_interval)
		ifp->garp_delay->garp_next_time = timer_add_now(ifp->garp_delay->garp_interval);

	/* Cleanup room for next round */
	memset(garp_buffer, 0, GARP_BUFFER_SIZE);

	return len;
}

static void queue_garp(vrrp_t *vrrp, interface_t *ifp, ip_address_t *ipaddress)
{
	timeval_t next_time = timer_add_now(ifp->garp_delay->garp_interval);

	vrrp->garp_pending = true;
	ipaddress->garp_gna_pending = true;

	/* Do we need to reschedule the garp thread? */
	if (!garp_thread || timercmp(&next_time, &garp_next_time, <)) {
		if (garp_thread)
			thread_cancel(garp_thread);

		garp_next_time = next_time;

		garp_thread = thread_add_timer(master, vrrp_arp_thread, NULL, timer_long(timer_sub_now(garp_next_time)));
	}
}

void send_gratuitous_arp(vrrp_t *vrrp, ip_address_t *ipaddress)
{
	interface_t *ifp = IF_BASE_IFP(ipaddress->ifp);

	/* If the interface doesn't support ARP, don't try sending */
	if (ifp->ifi_flags & IFF_NOARP)
		return;

	set_time_now();

	/* Do we need to delay sending the garp? */
	if (ifp->garp_delay &&
	    ifp->garp_delay->have_garp_interval &&
	    ifp->garp_delay->garp_next_time.tv_sec) {
		if (timercmp(&time_now, &ifp->garp_delay->garp_next_time, <)) {
			queue_garp(vrrp, ifp, ipaddress);
			return;
		}
	}

	send_gratuitous_arp_immediate(ifp, ipaddress);
}

/*
 *	Gratuitous ARP init/close
 */
void gratuitous_arp_init(void)
{
	if (garp_buffer)
		return;

	/* Create the socket descriptor */
	garp_fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(ETH_P_RARP));

	if (garp_fd >= 0) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "Registering gratuitous ARP shared channel");
	} else {
		log_message(LOG_INFO, "Error %d while registering gratuitous ARP shared channel", errno);
		return;
	}

	/* We don't want to receive any data on this socket */
	if_setsockopt_no_receive(&garp_fd);

	/* Initalize shared buffer */
	garp_buffer = PTR_CAST(char, MALLOC(GARP_BUFFER_SIZE));
}

void gratuitous_arp_close(void)
{
	if (garp_buffer) {
		FREE(garp_buffer);
		garp_buffer = NULL;
	}

	if (garp_fd != -1) {
		close(garp_fd);
		garp_fd = -1;
	}
}
