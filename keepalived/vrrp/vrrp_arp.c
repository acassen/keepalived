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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

/* system includes */
#include <netpacket/packet.h>

/* local includes */
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "vrrp_arp.h"

/* global vars */
char *garp_buffer;
int garp_fd;

/* Send the gratuitous ARP message */
static int send_arp(ip_address *ipaddress)
{
	struct sockaddr_ll sll;
	int len;

	/* Build the dst device */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	memcpy(sll.sll_addr, IF_HWADDR(ipaddress->ifp), ETH_ALEN);
	sll.sll_halen = ETHERNET_HW_LEN;
	sll.sll_ifindex = IF_INDEX(ipaddress->ifp);

	/* Send packet */
	len = sendto(garp_fd, garp_buffer, sizeof(m_arphdr) + ETHER_HDR_LEN
		     , 0, (struct sockaddr *)&sll, sizeof(sll));
	if (len < 0)
		log_message(LOG_INFO, "Error sending gratutious ARP on %s for %s",
			    IF_NAME(ipaddress->ifp), inet_ntop2(ipaddress->u.sin.sin_addr.s_addr));
	return len;
}

/* Build a gratuitous ARP message over a specific interface */
int send_gratuitous_arp(ip_address *ipaddress)
{
	struct ether_header *eth = (struct ether_header *) garp_buffer;
	m_arphdr *arph		 = (m_arphdr *) (garp_buffer + ETHER_HDR_LEN);
	char *hwaddr		 = (char *) IF_HWADDR(ipaddress->ifp);
	int len;

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

	/* Cleanup room for next round */
	memset(garp_buffer, 0, sizeof(m_arphdr) + ETHER_HDR_LEN);
	return len;
}


/*
 *	Gratuitous ARP init/close
 */
void gratuitous_arp_init(void)
{
	/* Initalize shared buffer */
	garp_buffer = (char *)MALLOC(sizeof(m_arphdr) + ETHER_HDR_LEN);

	/* Create the socket descriptor */
	garp_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_RARP));

	if (garp_fd > 0)
		log_message(LOG_INFO, "Registering gratutious ARP shared channel");
	else
		log_message(LOG_INFO, "Error while registering gratutious ARP shared channel");
}
void gratuitous_arp_close(void)
{
	FREE(garp_buffer);
	close(garp_fd);
}
