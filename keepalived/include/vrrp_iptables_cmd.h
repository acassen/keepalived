/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_iptables_cmd.c include file.
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

#ifndef _VRRP_IPTABLES_CMD_H
#define _VRRP_IPTABLES_CMD_H

#include "config.h"

#include "vrrp_ipaddress.h"
#include "vrrp_iptables.h"

/* prototypes */
extern void handle_iptable_rule_to_vip_cmd(ip_address_t *, int, bool);
#ifdef _HAVE_VRRP_VMAC_
extern void handle_iptable_rule_for_igmp_cmd(const char *, int, uint8_t);
#endif
extern init_state_t check_chains_exist_cmd(uint8_t);
extern init_state_t iptables_init_cmd(uint8_t);
extern void iptables_fini_cmd(void);

#endif
