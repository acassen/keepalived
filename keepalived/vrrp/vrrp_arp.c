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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

/* system includes */
#include <unistd.h>
#include <netpacket/packet.h>

/* local includes */
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "bitops.h"
#include "vrrp_scheduler.h"
#include "vrrp_arp.h"
#if !HAVE_DECL_SOCK_CLOEXEC
#include "old_socket.h"
#endif

/* static vars */
static char *garp_buffer;
static int garp_fd;

/* Send the gratuitous ARP message */
static ssize_t send_arp(ip_address_t *ipaddress)
{
	struct sockaddr_ll sll;
	ssize_t len;

	/* Build the dst device */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	memcpy(sll.sll_addr, IF_HWADDR(ipaddress->ifp), ETH_ALEN);
	sll.sll_halen = ETHERNET_HW_LEN;
	sll.sll_ifindex = (int)IF_INDEX(ipaddress->ifp);

	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "Sending gratuitous ARP on %s for %s",
			    IF_NAME(ipaddress->ifp), inet_ntop2(ipaddress->u.sin.sin_addr.s_addr));

	/* Send packet */
	len = sendto(garp_fd, garp_buffer, sizeof(arphdr_t) + ETHER_HDR_LEN
		     , 0, (struct sockaddr *)&sll, sizeof(sll));
	if (len < 0)
		log_message(LOG_INFO, "Error sending gratuitous ARP on %s for %s",
			    IF_NAME(ipaddress->ifp), inet_ntop2(ipaddress->u.sin.sin_addr.s_addr));
	return len;
}

/* Build a gratuitous ARP message over a specific interface */
ssize_t send_gratuitous_arp_immediate(interface_t *ifp, ip_address_t *ipaddress)
{
	struct ether_header *eth = (struct ether_header *) garp_buffer;
	arphdr_t *arph		 = (arphdr_t *) (garp_buffer + ETHER_HDR_LEN);
	char *hwaddr		 = (char *) IF_HWADDR(ipaddress->ifp);
	ssize_t len;

	/* Ethernet header */
	memset(eth->ether_dhost, 0xFF, ETH_ALEN);
	memcpy(eth->ether_shost, hwaddr, ETH_ALEN);
	eth->ether_type = htons(ETHERTYPE_ARP);

	/* ARP payload */
	arph->ar_hrd = htons(ARPHRD_ETHER);
	arph->ar_pro = htons(ETHERTYPE_IP);
	arph->ar_hln = ETHERNET_HW_LEN;
	arph->ar_pln = IPPROTO_ADDR_LEN;
	arph->ar_op = htons(ARPOP_REQUEST);
	memcpy(arph->__ar_sha, hwaddr, ETH_ALEN);
	memcpy(arph->__ar_sip, &ipaddress->u.sin.sin_addr.s_addr, sizeof(struct in_addr));
	memset(arph->__ar_tha, 0xFF, ETH_ALEN);
	memcpy(arph->__ar_tip, &ipaddress->u.sin.sin_addr.s_addr, sizeof(struct in_addr));

	/* Send the ARP message */
	len = send_arp(ipaddress);

	/* If we have to delay between sending garps, note the next time we can */
	if (ifp->garp_delay && ifp->garp_delay->have_garp_interval)
		ifp->garp_delay->garp_next_time = timer_add_now(ifp->garp_delay->garp_interval);

	/* Cleanup room for next round */
	memset(garp_buffer, 0, sizeof(arphdr_t) + ETHER_HDR_LEN);
	return len;
}

static void queue_garp(vrrp_t *vrrp, interface_t *ifp, ip_address_t *ipaddress)
{
	timeval_t next_time = timer_add_now(ifp->garp_delay->garp_interval);

	vrrp->garp_pending = true;
	ipaddress->garp_gna_pending = true;

	/* Do we need to reschedule the garp thread? */
	if (!garp_thread || timer_cmp(next_time, garp_next_time) < 0) {
		if (garp_thread)
			thread_cancel(garp_thread);

		garp_next_time = next_time;

		garp_thread = thread_add_timer(master, vrrp_arp_thread, NULL, timer_long(timer_sub_now(garp_next_time)));
	}
}

void send_gratuitous_arp(vrrp_t *vrrp, ip_address_t *ipaddress)
{
	interface_t *ifp = IF_BASE_IFP(ipaddress->ifp);

	set_time_now();

	/* Do we need to delay sending the garp? */
	if (ifp->garp_delay &&
	    ifp->garp_delay->have_garp_interval &&
	    ifp->garp_delay->garp_next_time.tv_sec) {
		if (timer_cmp(time_now, ifp->garp_delay->garp_next_time) < 0) {
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
	/* Initalize shared buffer */
	garp_buffer = (char *)MALLOC(sizeof(arphdr_t) + ETHER_HDR_LEN);

	/* Create the socket descriptor */
	garp_fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_RARP));

	if (garp_fd > 0)
		log_message(LOG_INFO, "Registering gratuitous ARP shared channel");
	else {
		log_message(LOG_INFO, "Error while registering gratuitous ARP shared channel");
		return;
	}

#if !HAVE_DECL_SOCK_CLOEXEC
	if (set_sock_flags(garp_fd, F_SETFD, FD_CLOEXEC))
		log_message(LOG_INFO, "Unable to set CLOEXEC on gratuitous ARP socket");
#endif
}
void gratuitous_arp_close(void)
{
	FREE(garp_buffer);
	close(garp_fd);
}
