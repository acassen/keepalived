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

#include <limits.h>
#include <stdint.h>
#include <stdbool.h>

#include "vrrp_ipaddress.h"

#define	APPEND_RULE	UINT_MAX

#ifdef _HAVE_LIBIPTC_
#ifdef _LIBXTABLES_DYNAMIC_ 
extern void xtables_unload(void);
#endif
extern bool load_xtables_module(const char *, const char *);
#endif

extern struct iptc_handle* ip4tables_open ( const char*);
extern int ip4tables_close ( struct iptc_handle*, int);
extern int ip4tables_is_chain(struct iptc_handle*, const char*);
extern int ip4tables_process_entry( struct iptc_handle* handle, const char* chain_name, unsigned int rulenum, const char* target_name, const ip_address_t* src_ip_address, const ip_address_t* dst_ip_address, const char* in_iface, const char* out_iface, uint16_t protocol, uint8_t type, int cmd, bool force);
extern struct ip6tc_handle* ip6tables_open ( const char* tablename );
extern int ip6tables_close ( struct ip6tc_handle* handle, int updated );
extern int ip6tables_is_chain(struct ip6tc_handle* handle, const char* chain_name);
extern int ip6tables_process_entry( struct ip6tc_handle* handle, const char* chain_name, unsigned int rulenum, const char* target_name, const ip_address_t* src_ip_address, const ip_address_t* dst_ip_address, const char* in_iface, const char* out_iface, uint16_t protocol, uint8_t type, int cmd, bool force);
extern int ip4tables_add_rules(struct iptc_handle* handle, const char* chain_name, unsigned int rulenum, uint8_t dim, uint8_t src_dst, const char* target_name, const char* set_name, uint16_t protocol, uint8_t param, int cmd, bool ignore_errors);
extern int ip6tables_add_rules(struct ip6tc_handle* handle, const char* chain_name, unsigned int rulenum, uint8_t dim, uint8_t src_dst, const char* target_name, const char* set_name, uint16_t protocol, uint8_t param, int cmd, bool ignore_errors);
extern void check_chains_exist_lib(void);
#ifdef _LIBIPTC_DYNAMIC_
extern bool iptables_lib_init(void);
#endif

#endif
