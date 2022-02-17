/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_arp.c include file.
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

#ifndef _VRRP_ARP_H
#define _VRRP_ARP_H

/* system includes */
#include <sys/types.h>
#include <linux/if_infiniband.h>
#include <stdbool.h>

/* local includes */
#include "vrrp.h"
#include "vrrp_if.h"
#include "vrrp_ipaddress.h"

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

typedef struct inf_arphdr {
	uint16_t	ar_hrd;
	uint16_t	ar_pro;
	uint8_t		ar_hln;
	uint8_t		ar_pln;
	uint16_t	ar_op;

	/* Infiniband arp looks like this */
	unsigned char	__ar_sha[INFINIBAND_ALEN];
	unsigned char	__ar_sip[4];
	unsigned char	__ar_tha[INFINIBAND_ALEN];
	unsigned char	__ar_tip[4];
} inf_arphdr_t;

typedef struct ipoib_hdr {
	u_int16_t proto;
	u_int16_t reserved;
} ipoib_hdr_t;

/* prototypes */
extern bool gratuitous_arp_init(void);
extern void gratuitous_arp_close(void);
extern void send_gratuitous_arp(vrrp_t *, ip_address_t *);
extern ssize_t send_gratuitous_arp_immediate(interface_t *, ip_address_t *);
#endif
