/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        IPv6 Neighbour Discovery part.
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

/* system includes */
#include <unistd.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

/* local includes */
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "vrrp_ipaddress.h"
#include "vrrp_ndisc.h"

/* global vars */
char *ndisc_buffer;
int ndisc_fd;

/*
 *	Neighbour Advertisement sending routine.
 */
static int
ndisc_send_na(ip_address_t *ipaddress)
{
	struct sockaddr_ll sll;
	int len;

	/* Build the dst device */
	memset(&sll, 0, sizeof (sll));
	sll.sll_family = AF_PACKET;
	memcpy(sll.sll_addr, IF_HWADDR(ipaddress->ifp), ETH_ALEN);
	sll.sll_halen = ETHERNET_HW_LEN;
	sll.sll_ifindex = IF_INDEX(ipaddress->ifp);

	/* Send packet */
	len = sendto(ndisc_fd, ndisc_buffer,
		     ETHER_HDR_LEN + sizeof(struct ip6hdr) + sizeof(struct ndhdr) +
		     sizeof(struct nd_opt_hdr) + ETH_ALEN, 0,
		     (struct sockaddr *) &sll, sizeof (sll));
	if (len < 0)
		log_message(LOG_INFO, "VRRP: Error sending ndisc unsolicited neighbour advert on %s",
			    IF_NAME(ipaddress->ifp));
	return len;
}

/*
 *	ICMPv6 Checksuming.
 */
static uint32_t
ndisc_icmp6_cksum(const struct ip6hdr *ip6, const struct icmp6hdr *icp, uint32_t len)
{
	size_t i;
	register const uint16_t *sp;
	uint32_t sum;
	union {
		struct {
			struct in6_addr ph_src;
			struct in6_addr ph_dst;
			uint32_t	ph_len;
			uint8_t	ph_zero[3];
			uint8_t	ph_nxt;
		} ph;
		uint16_t pa[20];
	} phu;

	/* pseudo-header */
	memset(&phu, 0, sizeof(phu));
	memcpy(&phu.ph.ph_src, &ip6->saddr, sizeof(struct in6_addr));
	memcpy(&phu.ph.ph_dst, &ip6->daddr, sizeof(struct in6_addr));
	phu.ph.ph_len = htonl(len);
	phu.ph.ph_nxt = IPPROTO_ICMPV6;

	sum = 0;
	for (i = 0; i < sizeof(phu.pa) / sizeof(phu.pa[0]); i++)
		sum += phu.pa[i];

	sp = (const uint16_t *)icp;

	for (i = 0; i < (len & ~1); i += 2)
		sum += *sp++;

	if (len & 1)
		sum += htons((*(const uint8_t *)sp) << 8);

	while (sum > 0xffff)
		sum = (sum & 0xffff) + (sum >> 16);
	sum = ~sum & 0xffff;

	return (sum);
}

/*
 *	Build an unsolicited Neighbour Advertisement.
 *	As explained in rfc4861.4.4, a node sends unsolicited
 *	Neighbor Advertisements in order to (unreliably) propagate
 *	new information quickly.
 */
int
ndisc_send_unsolicited_na(ip_address_t *ipaddress)
{
	struct ether_header *eth = (struct ether_header *) ndisc_buffer;
	struct ip6hdr *ip6h = (struct ip6hdr *) ((char *)eth + ETHER_HDR_LEN);
	struct ndhdr *ndh = (struct ndhdr*) ((char *)ip6h + sizeof(struct ip6hdr));
	struct icmp6hdr *icmp6h = &ndh->icmph;
	struct nd_opt_hdr *nd_opt_h = (struct nd_opt_hdr *) ((char *)ndh + sizeof(struct ndhdr));
	char *nd_opt_lladdr = (char *) ((char *)nd_opt_h + sizeof(struct nd_opt_hdr));
	char *lladdr = (char *) IF_HWADDR(ipaddress->ifp);
	int len;

	/* Ethernet header:
	 * Destination ethernet address MUST use specific address Mapping
	 * as specified in rfc2464.7 Address Mapping for
	 */
	memset(eth->ether_dhost, 0, ETH_ALEN);
	eth->ether_dhost[0] = eth->ether_dhost[1] = 0x33;
	eth->ether_dhost[5] = 1;
	memcpy(eth->ether_shost, lladdr, ETH_ALEN);
	eth->ether_type = htons(ETHERTYPE_IPV6);

	/* IPv6 Header */
	ip6h->version = 6;
	ip6h->payload_len = htons(sizeof(struct ndhdr) + sizeof(struct nd_opt_hdr) + ETH_ALEN);
	ip6h->nexthdr = NEXTHDR_ICMP;
	ip6h->hop_limit = NDISC_HOPLIMIT;
	memcpy(&ip6h->saddr, &ipaddress->u.sin6_addr, sizeof(struct in6_addr));
	ip6h->daddr.s6_addr16[0] = htons(0xff02);
	ip6h->daddr.s6_addr16[7] = htons(1);

	/* ICMPv6 Header */
	icmp6h->icmp6_type = NDISC_NEIGHBOUR_ADVERTISEMENT;

	/* Override flag is set to indicate that the advertisement
	 * should override an existing cache entry and update the
	 * cached link-layer address.
	 */
	icmp6h->icmp6_override = 1;
	ndh->target = ipaddress->u.sin6_addr;

	/* NDISC Option header */
	nd_opt_h->nd_opt_type = ND_OPT_TARGET_LL_ADDR;
	nd_opt_h->nd_opt_len = 1;
	memcpy(nd_opt_lladdr, lladdr, ETH_ALEN);

	/* Compute checksum */
	icmp6h->icmp6_cksum = ndisc_icmp6_cksum(ip6h, icmp6h,
						sizeof(struct ndhdr) + sizeof(struct nd_opt_hdr) + ETH_ALEN);

	/* Send the neighbor advertisement message */
	len = ndisc_send_na(ipaddress);

	/* Cleanup room for next round */
	memset(ndisc_buffer, 0, ETHER_HDR_LEN + sizeof(struct ip6hdr) +
	       sizeof(struct ndhdr) + sizeof(struct nd_opt_hdr) + ETH_ALEN);

	return len;
}


/*
 *	Neighbour Discovery init/close
 */
void
ndisc_init(void)
{
	/* Initalize shared buffer */
	ndisc_buffer = (char *) MALLOC(ETHER_HDR_LEN + sizeof(struct ip6hdr) +
				       sizeof(struct ndhdr) + sizeof(struct nd_opt_hdr) + ETH_ALEN);

	/* Create the socket descriptor */
	ndisc_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
}

void
ndisc_close(void)
{
	FREE(ndisc_buffer);
	close(ndisc_fd);
}
