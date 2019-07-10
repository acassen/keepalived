/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        snmp.c include file.
 *
 * Authors:     Vincent Bernat <bernat@luffy.cx>
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

#ifndef _SNMP_H
#define _SNMP_H

#include "config.h"

#include <sys/types.h>
#include <stdbool.h>

#define USING_AGENTX_SUBAGENT_MODULE

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>
#if HAVE_NET_SNMP_AGENT_UTIL_FUNCS_H
#include <net-snmp/agent/util_funcs.h>
#else
/* The above header may be buggy. We just need those two functions. */
int header_simple_table(struct variable *, oid *, size_t *,
			int, size_t *, WriteMethod **, int);
int header_generic(struct variable *, oid *, size_t *, int,
		   size_t *, WriteMethod **);
#endif
#undef FREE

#include "list.h"

#define SNMP_DEFAULT_NETWORK_SOCKET	"udp:localhost:705"

#define KEEPALIVED_OID 1, 3, 6, 1, 4, 1, 9586, 100, 5
#define SNMPTRAP_OID 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0
#define GLOBAL_OID {KEEPALIVED_OID, 1}

typedef union {
	unsigned char uc;
	unsigned long u;
	long s;
} longret_t;
/* The type of a FindVarMethod function should be const unsigned char *, but
 * it is declared unsigned char *. We use this simple work around to be able
 * to return const char *, and other types. */
typedef union {
	const char *cp;
	u_char *p;
} snmp_ret_t;

extern unsigned long snmp_scope(int ) __attribute__ ((const));
extern void* snmp_header_list_table(struct variable *, oid *, size_t *,
				    int, size_t *, WriteMethod **,
				    list);
extern element snmp_find_element(struct variable *, oid *, size_t *,
				 int, size_t *, WriteMethod **,
				 list, size_t);
extern void snmp_agent_init(const char *, bool);
extern void snmp_register_mib(oid *, size_t, const char *,
			      struct variable *, size_t, size_t);
extern void snmp_unregister_mib(oid *, size_t);
extern void snmp_agent_close(bool);
#ifdef THREAD_DUMP
extern void register_snmp_addresses(void);
#endif

#endif
