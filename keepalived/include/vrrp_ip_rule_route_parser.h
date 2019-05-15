/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        iprule and iproute parser
 *
 * Author:      Quentin Armitage, <quentin@armitage.org.uk>
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
 * Copyright (C) 2016 Quentin Armitage, <quentin@armitage.org.uk>
 * Copyright (C) 2016-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_IP_RULE_ROUTE_PARSER_H
#define _VRRP_IP_RULE_ROUTE_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#if HAVE_DECL_RTA_ENCAP && HAVE_DECL_LWTUNNEL_ENCAP_MPLS
#include "vrrp_iproute.h"
#endif

extern bool get_realms(uint32_t *, const char *);
extern bool get_u8(uint8_t *, const char *, uint8_t, const char*);
extern bool get_u32(uint32_t *, const char *, uint32_t, const char*);
extern bool get_u16(uint16_t *, const char *, uint16_t, const char*);
extern bool get_u64(uint64_t *, const char *, uint64_t, const char*);
extern bool get_time_rtt(uint32_t *, const char *, bool *);
extern bool get_addr64(uint64_t *, const char *);
#if HAVE_DECL_RTA_ENCAP && HAVE_DECL_LWTUNNEL_ENCAP_MPLS
extern bool parse_mpls_address(const char *, encap_mpls_t *);
#endif

#endif
