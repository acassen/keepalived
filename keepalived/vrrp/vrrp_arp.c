/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        ARP primitives.
 *
 * Version:     $Id: vrrp_arp.c,v 1.0.1 2003/03/17 22:14:34 acassen Exp $
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
 */

/* system includes */
#include <linux/if_packet.h>

/* local includes */
#include "vrrp_arp.h"
#include "memory.h"
#include "utils.h"

/* Send the gratuitous ARP message */
static int send_arp(vrrp_rt *vrrp, char *buffer, int buflen)
{
	int fd;
	int len;
	struct sockaddr_ll sll;

	/* Create the socket descriptor */
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_RARP));

	/* Build the dst device */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	strncpy(sll.sll_addr, IF_HWADDR(vrrp->ifp), sizeof(sll.sll_addr));
	sll.sll_halen = ETHERNET_HW_LEN;
	sll.sll_ifindex = IF_INDEX(vrrp->ifp);

	/* Send packet */
	len = sendto(fd, buffer, buflen, 0,(struct sockaddr *)&sll, sizeof(sll));

	close(fd);
	return len;
}

/* Build a gratuitous ARP message over a specific interface */
int send_gratuitous_arp(vrrp_rt * vrrp, int addr)
{
	char buflen			= sizeof(m_arphdr) + ETHER_HDR_LEN;
	char *buf			= (char *)MALLOC(buflen);
	struct ether_header *eth	= (struct ether_header *) buf;
	m_arphdr *arph			= (m_arphdr *) (buf + ETHER_HDR_LEN);
	char *hwaddr			= IF_HWADDR(vrrp->ifp);
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
	memcpy(arph->__ar_sip, &addr, sizeof (addr));
	memcpy(arph->__ar_tip, &addr, sizeof (addr));

	/* Send the ARP message */
	len = send_arp(vrrp, buf, buflen);

	FREE(buf);
	return len;
}
