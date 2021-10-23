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
#ifdef _HAVE_LINUX_IF_ETHER_H_COLLISION_
#include <netinet/in.h>
#endif
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>

/* local includes */
#include "logger.h"
#include "utils.h"
#include "vrrp_if_config.h"
#include "vrrp_scheduler.h"
#include "vrrp_ndisc.h"
#include "bitops.h"

/* static vars */
static int ndisc_fd = -1;

/*
 *	Neighbour Advertisement sending routine.
 */
static void
ndisc_send_na(ip_address_t *ipaddress, struct iovec *iov, int iovlen)
{
	struct sockaddr_ll sll;
	ssize_t len;
	char addr_str[INET6_ADDRSTRLEN] = "";
	interface_t *ifp = ipaddress->ifp;
	struct msghdr msg = { .msg_iov = iov, .msg_iovlen = iovlen };

	/* Build the dst device */
	memset(&sll, 0, sizeof (sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = (int)IF_INDEX(ifp);

	/* The values in sll_ha_type, sll_addr and sll_halen appear to be ignored */
	sll.sll_hatype = ifp->hw_type;
	sll.sll_halen = ifp->hw_addr_len;
	sll.sll_protocol = htons(ETH_P_IPV6);
	memcpy(sll.sll_addr, IF_HWADDR(ifp), ifp->hw_addr_len);

	msg.msg_name = &sll;
	msg.msg_namelen = sizeof(sll);

	if (__test_bit(LOG_DETAIL_BIT, &debug)) {
		inet_ntop(AF_INET6, &ipaddress->u.sin6_addr, addr_str, sizeof(addr_str));
		log_message(LOG_INFO, "Sending unsolicited Neighbour Advert on %s for %s",
			    IF_NAME(ifp), addr_str);
	}

	/* Send packet */
	len = sendmsg(ndisc_fd, &msg, 0);
	if (len < 0) {
		if (!addr_str[0])
			inet_ntop(AF_INET6, &ipaddress->u.sin6_addr, addr_str, sizeof(addr_str));
		log_message(LOG_INFO, "Error %d sending ndisc unsolicited neighbour advert on %s for %s",
			    errno, IF_NAME(ifp), addr_str);
	}
}

/*
 *	ICMPv6 Checksumming.
 */
static __sum16
ndisc_icmp6_cksum(const struct ip6hdr *ip6, struct iovec *iov, int iovcnt)
{
	size_t i;
	int j;
	size_t len;
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
	phu.ph.ph_len = 0;
	phu.ph.ph_nxt = IPPROTO_ICMPV6;

	sum = 0;

	for (j = 0; j < iovcnt; j++) {
		sp = PTR_CAST_CONST(uint16_t, iov[j].iov_base);
		len = iov[j].iov_len;

		for (i = 1; i < len; i += 2)
			sum += *sp++;

		if (len & 1)
			sum += htons((*PTR_CAST_CONST(uint8_t, sp)) << 8);

		phu.ph.ph_len += len;
	}
	phu.ph.ph_len = htons(phu.ph.ph_len);

	for (i = 0; i < sizeof(phu.pa) / sizeof(phu.pa[0]); i++)
		sum += phu.pa[i];

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
	struct ether_header eth = { .ether_type = htons(ETHERTYPE_IPV6) };
	struct ip6hdr ip6h = { .version = 6, .nexthdr = IPPROTO_ICMPV6, .hop_limit = NDISC_HOPLIMIT };
	struct nd_neighbor_advert ndh = { .nd_na_type = ND_NEIGHBOR_ADVERT };
	struct nd_opt_hdr nd_opt_h = { .nd_opt_type = ND_OPT_TARGET_LINKADDR, .nd_opt_len = 1 };
	char *lladdr = PTR_CAST(char, IF_HWADDR(ipaddress->ifp));
	struct iovec iov[5];

	/* This needs updating to support IPv6 over Infiniband
	 * (see vrrp_arp.c) */

	/* Ethernet header:
	 * Destination ethernet address MUST use specific address Mapping
	 * as specified in rfc2464.7 Address Mapping for
	 */
	eth.ether_dhost[0] = eth.ether_dhost[1] = 0x33;
	eth.ether_dhost[5] = 1;
	memcpy(eth.ether_shost, lladdr, ETH_ALEN);
	iov[0].iov_base = &eth;
	iov[0].iov_len = sizeof(eth);

	/* IPv6 Header */
	ip6h.payload_len = htons(sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr) + ETH_ALEN);
	memcpy(&ip6h.saddr, &ipaddress->u.sin6_addr, sizeof(struct in6_addr));
	ip6h.daddr.s6_addr16[0] = htons(0xff02);
	ip6h.daddr.s6_addr16[7] = htons(1);
	iov[1].iov_base = &ip6h;
	iov[1].iov_len = sizeof(ip6h);

	/* ICMPv6 Header */

	/* Set the router flag if necessary. We recheck each interface if not
	 * checked in the last 5 seconds. */
	if (timer_cmp_now_diff(ifp->last_gna_router_check, 5 * TIMER_HZ))
		set_ipv6_forwarding(ifp);
	if (ifp->gna_router)
		ndh.nd_na_flags_reserved |= ND_NA_FLAG_ROUTER;

	/* Override flag is set to indicate that the advertisement
	 * should override an existing cache entry and update the
	 * cached link-layer address.
	 */
	ndh.nd_na_flags_reserved |= ND_NA_FLAG_OVERRIDE;
	ndh.nd_na_target = ipaddress->u.sin6_addr;
	iov[2].iov_base = &ndh;
	iov[2].iov_len = sizeof(ndh);

	/* NDISC Option header */
	iov[3].iov_base = &nd_opt_h;
	iov[3].iov_len = sizeof(nd_opt_h);

	/* MAC address */
	iov[4].iov_base = lladdr;
	iov[4].iov_len = ETH_ALEN;

	/* Compute checksum  - ICMP6 header onwards*/
	ndh.nd_na_hdr.icmp6_cksum = ndisc_icmp6_cksum(&ip6h, &iov[2], 3);

	/* Send the neighbor advertisement message */
	ndisc_send_na(ipaddress, iov, 5);

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
bool
ndisc_init(void)
{
	if (ndisc_fd != -1)
		return true;

	/* Create the socket descriptor */
	ndisc_fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(ETH_P_IPV6));

	if (ndisc_fd < 0) {
		log_message(LOG_INFO, "Error %d while registering gratuitous NDISC shared channel", errno);
		return (errno != EAFNOSUPPORT && errno != EPERM);
	}

	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "Registering gratuitous NDISC shared channel");

	/* We don't want to receive any data on this socket */
	if_setsockopt_no_receive(&ndisc_fd);

	return true;
}

void
ndisc_close(void)
{
	if (ndisc_fd != -1) {
		close(ndisc_fd);
		ndisc_fd = -1;
	}
}
