/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_ndisc.c include file.
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

#ifndef _VRRP_NDISC_H
#define _VRRP_NDISC_H

/* system includes */
#include <linux/icmpv6.h>

/* local definitions */
#define ETHERNET_HW_LEN 6
#define NEXTHDR_ICMP	58
#define NDISC_HOPLIMIT	255

/*
 *	ICMPv6 codes for Neighbour Discovery messages
 */
#define NDISC_ROUTER_SOLICITATION       133
#define NDISC_ROUTER_ADVERTISEMENT      134
#define NDISC_NEIGHBOUR_SOLICITATION    135
#define NDISC_NEIGHBOUR_ADVERTISEMENT   136
#define NDISC_REDIRECT                  137

/*
 *	Neighbour Discovery option codes
 */
#define ND_OPT_TARGET_LL_ADDR	2

/*
 *	IPv6 Header
 */
struct ip6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8			priority:4,
				version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8			version:4,
				priority:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	__u8			flow_lbl[3];

	__be16			payload_len;
	__u8			nexthdr;
	__u8			hop_limit;

	struct	in6_addr	saddr;
	struct	in6_addr	daddr;
};

/*
 *	NDISC Neighbour Advertisement related	
 */
struct ndhdr {
	struct icmp6hdr		icmph;
	struct in6_addr		target;
	__u8			opt[0];
};

struct nd_opt_hdr {
	__u8			nd_opt_type;
	__u8			nd_opt_len;
} __attribute__((__packed__));


/* prototypes */
extern void ndisc_init(void);
extern void ndisc_close(void);
extern int ndisc_send_unsolicited_na(ip_address *);

#endif

