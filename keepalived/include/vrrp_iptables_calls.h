/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_iptables_calls.c include file.
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
 * Copyright (C) 2001-2016 Alexandre Cassen, <acassen@gmail.com>
 */


#ifndef _VRRP_IPTABLES_CALLS_H
#define	_VRRP_IPTABLES_CALLS_H

#include "vrrp_ipaddress.h"

#ifdef _HAVE_LIBIPSET_
int load_mod_xt_set(void);
#endif

struct iptc_handle* ip4tables_open ( const char*);
int ip4tables_close ( struct iptc_handle*, int);
int ip4tables_is_chain(struct iptc_handle*, const char*);
int ip4tables_process_entry( struct iptc_handle* handle, const char* chain_name, int rulenum, const char* target_name, const ip_address_t* src_ip_address, const ip_address_t* dst_ip_address, const char* in_iface, const char* out_iface, uint16_t protocol, uint16_t type, int cmd);
struct ip6tc_handle* ip6tables_open ( const char* tablename );
int ip6tables_close ( struct ip6tc_handle* handle, int updated );
int ip6tables_is_chain(struct ip6tc_handle* handle, const char* chain_name);
int ip6tables_process_entry( struct ip6tc_handle* handle, const char* chain_name, int rulenum, const char* target_name, const ip_address_t* src_ip_address, const ip_address_t* dst_ip_address, const char* in_iface, const char* out_iface, uint16_t protocol, uint16_t type, int cmd);
int ip4tables_add_rules(struct iptc_handle* handle, const char* chain_name, int rulenum, int dim, int src_dst, const char* target_name, const char* set_name, uint16_t protocol, int param, int cmd);
int ip6tables_add_rules(struct ip6tc_handle* handle, const char* chain_name, int rulenum, int dim, int src_dst, const char* target_name, const char* set_name, uint16_t protocol, int param, int cmd);

#endif
