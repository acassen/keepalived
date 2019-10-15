/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_iptables_lib.c include file.
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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_IPTABLES_LIB_H
#define _VRRP_IPTABLES_LIB_H

#include "config.h"

#include <stdbool.h>

#include "vrrp_ipaddress.h"
#include "vrrp_iptables.h"

struct ipt_handle;

#define	IPTABLES_MAX_TRIES	3	/* How many times to try adding/deleting when get EAGAIN */

extern struct ipt_handle *iptables_open(int) __attribute__ ((malloc));
extern int iptables_close(struct ipt_handle *h);
extern init_state_t check_chains_exist_lib(uint8_t);
extern void handle_iptable_rule_to_vip_lib(ip_address_t *, int, struct ipt_handle *, bool);
extern void handle_iptable_rule_for_igmp_lib(const char *, int, uint8_t, struct ipt_handle *);
#ifdef _HAVE_LIBIPSET_
extern void iptables_startup_lib(bool);
extern void iptables_cleanup_lib(void);
#endif
extern void iptables_fini_lib(void);
extern init_state_t iptables_init_lib(uint8_t);

#endif
