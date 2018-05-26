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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_NDISC_H
#define _VRRP_NDISC_H

/* system includes */
#include <asm/byteorder.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

/* local includes */
#include "vrrp.h"
#include "vrrp_if.h"
#include "vrrp_ipaddress.h"

/* local definitions */
#define NDISC_HOPLIMIT	255

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

/* prototypes */
extern void ndisc_init(void);
extern void ndisc_close(void);
extern void ndisc_send_unsolicited_na(vrrp_t *, ip_address_t *);
extern void ndisc_send_unsolicited_na_immediate(interface_t *, ip_address_t *);

#endif

