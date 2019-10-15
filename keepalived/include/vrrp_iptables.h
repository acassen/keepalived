/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_iptables.c include file.
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
 * Copyright (C) 2001-2018 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_IPTABLES_H
#define _VRRP_IPTABLES_H

#include "config.h"

/* global includes */
#include <stdbool.h>

/* local includes */
#include "list.h"
#include "vrrp.h"
#ifdef _HAVE_LIBIPSET_
#include "vrrp_ipset.h"
#endif

#define DEFAULT_IPTABLES_CHAIN_IN	"INPUT"
#define DEFAULT_IPTABLES_CHAIN_OUT	"OUTPUT"

typedef enum {
        NOT_INIT,
        INIT_SUCCESS,
        INIT_FAILED,
} init_state_t;

/* prototypes */
extern void handle_iptable_rule_to_iplist(list, list, int, bool force);
extern void handle_iptables_accept_mode(vrrp_t *, int, bool);
#ifdef _HAVE_VRRP_VMAC_
extern void iptables_add_vmac(const vrrp_t *);
extern void iptables_remove_vmac(const vrrp_t *);
#endif
extern void iptables_startup(bool);
extern void iptables_cleanup(void);
extern void iptables_fini(void);

#endif
