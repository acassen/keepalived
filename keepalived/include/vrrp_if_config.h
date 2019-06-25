/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_if_config.c include file.
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

#ifndef _VRRP_IF_CONFIG_H
#define _VRRP_IF_CONFIG_H 1

#include "config.h"

#include <stdbool.h>

#include "vrrp_if.h"

/* prototypes */
extern void set_promote_secondaries(interface_t*);
extern void reset_promote_secondaries(interface_t*);
#ifdef _HAVE_VRRP_VMAC_
extern void restore_rp_filter(void);
extern void set_interface_parameters(const interface_t*, interface_t*);
extern void reset_interface_parameters(interface_t*);
extern void link_set_ipv6(const interface_t*, bool);
#endif
extern void set_ipv6_forwarding(interface_t *);

#endif
