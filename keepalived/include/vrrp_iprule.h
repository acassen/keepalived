/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_iprule.c include file.
 *
 * Author:      Chris Riley, <kernelchris@gmail.com>
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
 * Copyright (C) 2015 Chris Riley, <kernelchris@gmail.com>
 */

#ifndef _VRRP_IPRULE_H
#define _VRRP_IPRULE_H

/* global includes */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <linux/fib_rules.h>

/* local includes */
#include "list.h"
#include "vector.h"
#include "utils.h"

/* print buffer sizes */
#define	RULE_BUF_SIZE	256

enum iprule_param_mask {
	IPRULE_BIT_PRIORITY = 0x01,
	IPRULE_BIT_DSFIELD = 0x02,
	IPRULE_BIT_FWMARK = 0x04,
	IPRULE_BIT_FWMASK = 0x08,
	IPRULE_BIT_SUP_PREFIXLEN = 0x10,
	IPRULE_BIT_SUP_GROUP = 0x20,
} ;

 /* types definition */
typedef struct _ip_rule {
	uint32_t	mask;
	bool		invert;
	ip_address_t	*from_addr;
	ip_address_t	*to_addr;
	uint32_t	priority;
	uint8_t		tos;
	uint32_t	fwmark;
	uint32_t	fwmask;
	uint32_t	realms;
#if HAVE_DECL_FRA_SUPPRESS_PREFIXLEN
	uint32_t	suppress_prefix_len;
#endif
#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
	uint32_t	suppress_group;
#endif
	interface_t	*iif;
	interface_t	*oif;
	uint32_t	goto_target;
	uint32_t	table;
	uint8_t		action;
#if HAVE_DECL_FRA_TUN_ID
	uint64_t	tunnel_id;
#endif
	bool		set;
} ip_rule_t;

#define IPRULE_DEL 0
#define IPRULE_ADD 1

#define VRRP_RULE_FROM	1
#define VRRP_RULE_TO	2

/* prototypes */
extern void netlink_rulelist(list, int, bool);
extern void free_iprule(void *);
extern void format_iprule(ip_rule_t *, char *, size_t);
extern void dump_iprule(void *);
extern void alloc_rule(list, vector_t *);
extern void clear_diff_rules(list, list);
extern void clear_diff_srules(void);

#endif
