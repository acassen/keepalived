
/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        iptables management
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

#include "config.h"

#include <errno.h>

#include "warnings.h"
#include "vrrp_iptables.h"

#include "global_data.h"
#include "vrrp_ipaddress.h"
#include "vrrp.h"
#ifdef _HAVE_LIBIPTC_
#include "vrrp_iptables_lib.h"
#endif
#ifdef _USE_IPTABLES_CMD_
#include "vrrp_iptables_cmd.h"
#endif
#include "vrrp_firewall.h"

static inline void
handle_iptable_rule_to_vip(ip_address_t *ipaddr, int cmd,
#ifdef _HAVE_LIBIPTC_
							     struct ipt_handle *h,
#else
							     __attribute__((unused)) void *unused,
#endif
												   bool force)
{
	if (IP_IS6(ipaddr)) {
		if (!block_ipv6)
			return;
	} else {
		if (!block_ipv4)
			return;
	}

#ifdef _HAVE_LIBIPTC_
#ifdef _LIBIPTC_DYNAMIC_
	if ((IP_IS6(ipaddr) && using_libip6tc) ||
	    (!IP_IS6(ipaddr) && using_libip4tc))
#endif
	{
		handle_iptable_rule_to_vip_lib(ipaddr, cmd, h, force);
// Does this work - what if have done IPv4 and not IPv6?
		return;
	}
#endif

#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
	handle_iptable_rule_to_vip_cmd(ipaddr, cmd, force);
#endif
}

/* add/remove iptable drop rules to iplist */
void
handle_iptable_rule_to_iplist(list ip_list1, list ip_list2, int cmd, bool force)
{
	ip_address_t *ipaddr;
	element e;
#ifdef _HAVE_LIBIPTC_
	struct ipt_handle *h = NULL;
	int tries = 0;
	int res;
#else
	void *h = NULL;
#endif

	/* No addresses in this list */
	if (LIST_ISEMPTY(ip_list1) && LIST_ISEMPTY(ip_list2))
		return;

#ifdef _HAVE_LIBIPTC_
        do {
#ifndef _LIBIPTC_DYNAMIC_
		h = iptables_open();
#endif
#endif
		LIST_FOREACH(ip_list1, ipaddr, e) {
			if ((cmd == IPADDRESS_DEL) == ipaddr->iptable_rule_set ||
			    force)
			{
#if defined _HAVE_LIBIPTC_ && defined _LIBIPTC_DYNAMIC_
				if (!h &&
				    ((IP_IS6(ipaddr) && using_libip6tc) ||
				     (!IP_IS6(ipaddr) && using_libip4tc)))
					h = iptables_open();
#endif
				handle_iptable_rule_to_vip(ipaddr, cmd, h, force);
			}
		}

		LIST_FOREACH(ip_list2, ipaddr, e) {
			if ((cmd == IPADDRESS_DEL) == ipaddr->iptable_rule_set ||
			    force)
			{
#if defined _HAVE_LIBIPTC_ && defined _LIBIPTC_DYNAMIC_
				if (!h &&
				    ((IP_IS6(ipaddr) && using_libip6tc) ||
				     (!IP_IS6(ipaddr) && using_libip4tc)))
					h = iptables_open();
#endif
				handle_iptable_rule_to_vip(ipaddr, cmd, h, force);
			}
		}

#ifdef _HAVE_LIBIPTC_
#ifdef _LIBIPTC_DYNAMIC_
                if (h)
#endif
                        res = iptables_close(h);
        } while (res == EAGAIN && ++tries < IPTABLES_MAX_TRIES);
#endif
}

void
handle_iptables_accept_mode(vrrp_t *vrrp, int cmd, bool force)
{
	handle_iptable_rule_to_iplist(vrrp->vip, vrrp->evip, cmd, force);
}

static void
check_chains_exist(void)
{
#ifdef _HAVE_LIBIPTC_
#ifdef _LIBIPTC_DYNAMIC_
	if (using_libip4tc || using_libip6tc)
#endif
		check_chains_exist_lib();
#endif

#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
	check_chains_exist_cmd();
#endif
}

RELAX_SUGGEST_ATTRIBUTE_CONST_START
void
iptables_init(void)
{
	if (!block_ipv4 && !block_ipv6) {
#ifdef _HAVE_LIBIPSET_
		global_data->using_ipsets = false;
#endif
		return;
	}

#ifdef _HAVE_LIBIPTC_
	iptables_init_lib();
#endif

#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
	iptables_init_cmd();
#endif

	if (block_ipv4 || block_ipv6)
		check_chains_exist();
#ifdef _HAVE_LIBIPSET_
	else
		global_data->using_ipsets = false;
#endif
}

void
iptables_startup(
#ifndef _HAVE_LIBIPSET_
		 __attribute__((unused))
#endif
					 bool reload)
{
#ifdef _HAVE_LIBIPSET_
	if (global_data->using_ipsets)
		iptables_startup_lib(reload);
#endif
}

void
iptables_cleanup(void)
{
#ifdef _HAVE_LIBIPSET_
	if (global_data->using_ipsets)
		iptables_cleanup_lib();
#endif
}

void
iptables_fini(void)
{
#ifdef _HAVE_LIBIPSET_
	if (global_data->using_ipsets)
		iptables_fini_lib();
#endif
}
RELAX_SUGGEST_ATTRIBUTE_CONST_END
