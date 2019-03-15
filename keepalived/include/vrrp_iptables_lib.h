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

struct ipt_handle;

#define	IPTABLES_MAX_TRIES	3	/* How many times to try adding/deleting when get EAGAIN */

#ifdef _LIBIPTC_DYNAMIC_
extern bool using_libip4tc;		/* Set if using lib4iptc - for dynamic linking */
extern bool using_libip6tc;		/* Set if using lib6iptc - for dynamic linking */
#endif

extern struct ipt_handle *iptables_open(void) __attribute__ ((malloc));
extern int iptables_close(struct ipt_handle *h);
extern void check_chains_exist_lib(void);
extern void handle_iptable_rule_to_vip_lib(ip_address_t *, int, struct ipt_handle *, bool);
#ifdef _HAVE_LIBIPSET_
extern void iptables_startup_lib(bool);
extern void iptables_cleanup_lib(void);
extern void iptables_fini_lib(void);
#endif
extern void iptables_init_lib(void);

#endif
