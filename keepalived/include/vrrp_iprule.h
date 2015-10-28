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

/* local includes */
#include "list.h"
#include "vector.h"
#include "utils.h"

 /* types definition */
typedef struct _ip_rule {
	char			*dir;
	ip_address_t	*addr;
	uint8_t			mask;
	int				table;
	int				set;
} ip_rule_t;

#define IPRULE_DEL 0
#define IPRULE_ADD 1

/* Macro definition */
#define RULE_ISEQ(X,Y) (string_equal((X)->dir, (Y)->dir)	&& \
						IP_ISEQ((X)->addr, (Y)->addr)		&& \
						(X)->mask  == (Y)->mask				&& \
						(X)->table  == (Y)->table)

/* prototypes */
extern int netlink_rule(ip_rule_t *, int);
extern void netlink_rulelist(list, int);
extern void free_iprule(void *);
extern void dump_iprule(void *);
extern void alloc_rule(list, vector_t *);
extern void clear_diff_rules(list, list);
extern void clear_diff_srules(void);

#endif
