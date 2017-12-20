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
 * Copyright (C) 2001-2016 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_ARP_H
#define _VRRP_ARP_H

/* system includes */
#include <sys/types.h>
#include <netinet/if_ether.h>	/* musl libc has name collisions if use <linux/if_ether.h> */

/* local includes */
#include "vrrp.h"
#include "vrrp_if.h"
#include "vrrp_ipaddress.h"

/* local definitions */
#define IPPROTO_ADDR_LEN	4

/* types definition */
typedef struct _arphdr {
	unsigned short int	ar_hrd;	/* Format of hardware address.  */
	unsigned short int	ar_pro;	/* Format of protocol address.  */
	unsigned char		ar_hln;	/* Length of hardware address.  */
	unsigned char		ar_pln;	/* Length of protocol address.  */
	unsigned short int	ar_op;	/* ARP opcode (command).  */

	/* Ethernet looks like this : This bit is variable sized however...  */
	unsigned char		__ar_sha[ETH_ALEN];	/* Sender hardware address.  */
	unsigned char		__ar_sip[4];		/* Sender IP address.  */
	unsigned char		__ar_tha[ETH_ALEN];	/* Target hardware address.  */
	unsigned char		__ar_tip[4];		/* Target IP address.  */
} arphdr_t;

/* prototypes */
extern void gratuitous_arp_init(void);
extern void gratuitous_arp_close(void);
extern void send_gratuitous_arp(vrrp_t *, ip_address_t *);
extern ssize_t send_gratuitous_arp_immediate(interface_t *, ip_address_t *);
#endif
