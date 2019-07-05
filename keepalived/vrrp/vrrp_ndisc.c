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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

/* system includes */
#include <unistd.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <stdint.h>
#include <errno.h>

/* local includes */
#include "logger.h"
#include "utils.h"
#include "vrrp_if_config.h"
#include "vrrp_scheduler.h"
#include "vrrp_ndisc.h"
#if !HAVE_DECL_SOCK_CLOEXEC
#include "old_socket.h"
#endif
#include "bitops.h"

/* static vars */
static char *ndisc_buffer;
static int ndisc_fd = -1;

/*
 *	Neighbour Advertisement sending routine.
 */
static void
ndisc_send_na(ip_address_t *ipaddress)
{
	struct sockaddr_ll sll;
	ssize_t len;
	char addr_str[INET6_ADDRSTRLEN] = "";
	interface_t *ifp = ipaddress->ifp;

	/* Build the dst device */
	memset(&sll, 0, sizeof (sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = (int)IF_INDEX(ifp);

	/* The values in sll_ha_type, sll_addr and sll_halen appear to be ignored */
	sll.sll_hatype = ifp->hw_type;
	sll.sll_halen = ifp->hw_addr_len;
	sll.sll_protocol = htons(ETH_P_IPV6);
	memcpy(sll.sll_addr, IF_HWADDR(ifp), ifp->hw_addr_len);

	if (__test_bit(LOG_DETAIL_BIT, &debug)) {
		inet_ntop(AF_INET6, &ipaddress->u.sin6_addr, addr_str, sizeof(addr_str));
		log_message(LOG_INFO, "Sending unsolicited Neighbour Advert on %s for %s",
			    IF_NAME(ifp), addr_str);
	}

	/* Send packet */
	len = sendto(ndisc_fd, ndisc_buffer,
		     ETHER_HDR_LEN + sizeof(struct ip6hdr) + sizeof(struct nd_neighbor_advert) +
		     sizeof(struct nd_opt_hdr) + ifp->hw_addr_len, 0,
		     (struct sockaddr *) &sll, sizeof (sll));
	if (len < 0) {
		if (!addr_str[0])
			inet_ntop(AF_INET6, &ipaddress->u.sin6_addr, addr_str, sizeof(addr_str));
		log_message(LOG_INFO, "Error %d sending ndisc unsolicited neighbour advert on %s for %s",
			    errno, IF_NAME(ifp), addr_str);
	}
}

/*
 *	ICMPv6 Checksuming.
 */
static __sum16
ndisc_icmp6_cksum(const struct ip6hdr *ip6, const struct icmp6_hdr *icp, uint32_t len)
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

	for (i = 1; i < len; i += 2)
		sum += *sp++;

	if (len & 1)
		sum += htons((*(const uint8_t *)sp) << 8);

	while (sum > 0xffff)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum & 0xffff;
}

/*
 *	Build an unsolicited Neighbour Advertisement.
 *	As explained in rfc4861.4.4, a node sends unsolicited
 *	Neighbor Advertisements in order to (unreliably) propagate
 *	new information quickly.
 */
void
ndisc_send_unsolicited_na_immediate(interface_t *ifp, ip_address_t *ipaddress)
{
	struct ether_header *eth = (struct ether_header *) ndisc_buffer;
	struct ip6hdr *ip6h = (struct ip6hdr *) ((char *)eth + ETHER_HDR_LEN);
	struct nd_neighbor_advert *ndh = (struct nd_neighbor_advert*) ((char *)ip6h + sizeof(struct ip6hdr));
	struct icmp6_hdr *icmp6h = &ndh->nd_na_hdr;
	struct nd_opt_hdr *nd_opt_h = (struct nd_opt_hdr *) ((char *)ndh + sizeof(struct nd_neighbor_advert));
	char *nd_opt_lladdr = (char *) ((char *)nd_opt_h + sizeof(struct nd_opt_hdr));
	char *lladdr = (char *) IF_HWADDR(ipaddress->ifp);

	/* This needs updating to support IPv6 over Infiniband
	 * (see vrrp_arp.c) */

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
	ip6h->payload_len = htons(sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr) + ETH_ALEN);
	ip6h->nexthdr = IPPROTO_ICMPV6;
	ip6h->hop_limit = NDISC_HOPLIMIT;
	memcpy(&ip6h->saddr, &ipaddress->u.sin6_addr, sizeof(struct in6_addr));
	ip6h->daddr.s6_addr16[0] = htons(0xff02);
	ip6h->daddr.s6_addr16[7] = htons(1);

	/* ICMPv6 Header */
	ndh->nd_na_type = ND_NEIGHBOR_ADVERT;

	/* Set the router flag if necessary. We recheck each interface if not
	 * checked in the last 5 seconds. */
	if (timer_cmp_now_diff(ifp->last_gna_router_check, 5 * TIMER_HZ))
		set_ipv6_forwarding(ifp);
	if (ifp->gna_router)
		ndh->nd_na_flags_reserved |= ND_NA_FLAG_ROUTER;

	/* Override flag is set to indicate that the advertisement
	 * should override an existing cache entry and update the
	 * cached link-layer address.
	 */
//	icmp6h->icmp6_override = 1;
	ndh->nd_na_flags_reserved |= ND_NA_FLAG_OVERRIDE;
	ndh->nd_na_target = ipaddress->u.sin6_addr;

	/* NDISC Option header */
	nd_opt_h->nd_opt_type = ND_OPT_TARGET_LINKADDR;
	nd_opt_h->nd_opt_len = 1;
	memcpy(nd_opt_lladdr, lladdr, ETH_ALEN);

	/* Compute checksum */
	icmp6h->icmp6_cksum = ndisc_icmp6_cksum(ip6h, icmp6h,
						sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr) + ETH_ALEN);

	/* Send the neighbor advertisement message */
	ndisc_send_na(ipaddress);

	/* Cleanup room for next round */
	memset(ndisc_buffer, 0, ETHER_HDR_LEN + sizeof(struct ip6hdr) +
	       sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr) + ETH_ALEN);

	/* If we have to delay between sending NAs, note the next time we can */
	if (ifp->garp_delay && ifp->garp_delay->have_gna_interval)
		ifp->garp_delay->gna_next_time = timer_add_now(ifp->garp_delay->gna_interval);
}

static void
queue_ndisc(vrrp_t *vrrp, interface_t *ifp, ip_address_t *ipaddress)
{
	timeval_t next_time = timer_add_now(ifp->garp_delay->gna_interval);

	vrrp->gna_pending = true;
	ipaddress->garp_gna_pending = true;

	/* Do we need to schedule/reschedule the garp thread? */
	if (!garp_thread || timercmp(&next_time, &garp_next_time, <)) {
		if (garp_thread)
			thread_cancel(garp_thread);

		garp_next_time = next_time;

		garp_thread = thread_add_timer(master, vrrp_arp_thread, NULL, timer_long(ifp->garp_delay->gna_interval));
	}
}

void
ndisc_send_unsolicited_na(vrrp_t *vrrp, ip_address_t *ipaddress)
{
	interface_t *ifp = IF_BASE_IFP(ipaddress->ifp);

	/* If the interface doesn't support NDISC, don't try sending */
        if (ifp->ifi_flags & IFF_NOARP)
                return;

	set_time_now();

	/* Do we need to delay sending the ndisc? */
	if (ifp->garp_delay && ifp->garp_delay->have_gna_interval && ifp->garp_delay->gna_next_time.tv_sec) {
		if (timercmp(&time_now, &ifp->garp_delay->gna_next_time, <)) {
			queue_ndisc(vrrp, ifp, ipaddress);
			return;
		}
	}

	ndisc_send_unsolicited_na_immediate(ifp, ipaddress);
}

/*
 *	Neighbour Discovery init/close
 */
void
ndisc_init(void)
{
	if (ndisc_buffer)
		return;

	/* Create the socket descriptor */
	ndisc_fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(ETH_P_IPV6));

	if (ndisc_fd >= 0)
		log_message(LOG_INFO, "Registering gratuitous NDISC shared channel");
	else {
		log_message(LOG_INFO, "Error %d while registering gratuitous NDISC shared channel", errno);
		return;
	}

#if !HAVE_DECL_SOCK_CLOEXEC
	if (set_sock_flags(ndisc_fd, F_SETFD, FD_CLOEXEC))
		log_message(LOG_INFO, "Unable to set CLOEXEC on gratuitous NA socket");
#endif
#if !HAVE_DECL_SOCK_NONBLOCK
	if (set_sock_flags(garp_fd, F_SETFL, O_NONBLOCK))
		log_message(LOG_INFO, "Unable to set NONBLOCK on gratuitous NA socket");
#endif

	/* Initalize shared buffer */
	ndisc_buffer = (char *) MALLOC(ETHER_HDR_LEN + sizeof(struct ip6hdr) +
				       sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr) + sizeof(((interface_t *)NULL)->hw_addr));
}

void
ndisc_close(void)
{
	if (ndisc_buffer) {
		FREE(ndisc_buffer);
		ndisc_buffer = NULL;
	}

	if (ndisc_fd != -1) {
		close(ndisc_fd);
		ndisc_fd = -1;
	}
}
