/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_dns.c include file.
 *
 * Author:      Masanobu Yasui, <yasui-m@klab.com>
 *              Masaya Yamamoto, <yamamoto-ma@klab.com>
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
 * Copyright (C) 2016 KLab Inc.
 * Copyright (C) 2016-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _CHECK_DNS_CHECK_H
#define _CHECK_DNS_CHECK_H

#include <stdint.h>
#include <sys/types.h>

#define DNS_DEFAULT_RETRY    3
#define DNS_DEFAULT_TYPE  DNS_TYPE_SOA
#define DNS_DEFAULT_NAME    "."
#define DNS_BUFFER_SIZE    768

#define DNS_QR(flags) ((flags >> 15) & 0x0001)
/* UNUSED
#define DNS_OP(flags) ((flags >> 11) & 0x000F)
#define DNS_AA(flags) ((flags >> 10) & 0x0001)
#define DNS_TC(flags) ((flags >>  9) & 0x0001)
#define DNS_RD(flags) ((flags >>  8) & 0x0001)
#define DNS_RA(flags) ((flags >>  7) & 0x0001)
#define DNS_Z(flags)  ((flags >>  4) & 0x0007)
*/
#define DNS_RC(flags) ((flags >>  0) & 0x000F)

/* UNUSED
#define DNS_SET_QR(flags, val) (flags |= ((val & 0x0001) << 15))
#define DNS_SET_OP(flags, val) (flags |= ((val & 0x000F) << 11))
#define DNS_SET_AA(flags, val) (flags |= ((val & 0x0001) << 10))
#define DNS_SET_TC(flags, val) (flags |= ((val & 0x0001) <<  9))
*/
#define DNS_SET_RD(flags, val) (flags |= ((val & 0x0001) <<  8))
/* UNUSED
#define DNS_SET_RA(flags, val) (flags |= ((val & 0x0001) <<  7))
#define DNS_SET_Z(flags, val)  (flags |= ((val & 0x0007) <<  4))
#define DNS_SET_RC(flags, val) (flags |= ((val & 0x000F) <<  0))
*/

#define DNS_TYPE_A       1
#define DNS_TYPE_NS      2
#define DNS_TYPE_CNAME   5
#define DNS_TYPE_SOA     6
#define DNS_TYPE_MX     15
#define DNS_TYPE_TXT    16
#define DNS_TYPE_AAAA   28
#define DNS_TYPE_RRSIG  46
#define DNS_TYPE_DNSKEY 48

typedef struct _dns_type {
	uint16_t type;
	const char * const label;
} dns_type_t;

extern const dns_type_t DNS_TYPE[];

typedef struct _dns_header {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} dns_header_t;

typedef struct _dns_check {
	uint16_t type;
	const char *name;
	uint8_t sbuf[DNS_BUFFER_SIZE];
	size_t slen;
} dns_check_t;

extern void install_dns_check_keyword(void);
#ifdef THREAD_DUMP
extern void register_check_dns_addresses(void);
#endif

#endif
