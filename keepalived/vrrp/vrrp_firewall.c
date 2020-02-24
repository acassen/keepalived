/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        accept mode management
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

#include "vrrp_firewall.h"
#ifdef _WITH_IPTABLES_
#include "vrrp_iptables.h"
#endif
#ifdef _WITH_NFTABLES_
#include "vrrp_nftables.h"
#endif
#include "global_data.h"
#include "vrrp_ipaddress.h"


/* add/remove iptables/nftables drop rules */
void
firewall_handle_accept_mode(vrrp_t *vrrp, int cmd,
#ifndef _WITH_IPTABLES_
			    __attribute__((unused))
#endif
						    bool force)
{
#ifdef _WITH_IPTABLES_
	if (global_data->vrrp_iptables_inchain[0])
		handle_iptables_accept_mode(vrrp, cmd, force);
#endif

#ifdef _WITH_NFTABLES_
	if (global_data->vrrp_nf_table_name) {
		if (cmd == IPADDRESS_ADD)
			nft_add_addresses(vrrp);
		else
			nft_remove_addresses(vrrp);
	}
#endif

	vrrp->firewall_rules_set = (cmd == IPADDRESS_ADD);
}

void
firewall_remove_rule_to_iplist(list ip_list)
{
#ifdef _WITH_IPTABLES_
	if (global_data->vrrp_iptables_inchain[0])
		handle_iptable_rule_to_iplist(ip_list, NULL, IPADDRESS_DEL, false);
#endif

#ifdef _WITH_NFTABLES_
	if (global_data->vrrp_nf_table_name)
		nft_remove_addresses_iplist(ip_list);
#endif
}

#ifdef _HAVE_VRRP_VMAC_
void
firewall_add_vmac(const vrrp_t *vrrp)
{
#ifdef _WITH_IPTABLES_
	if (global_data->vrrp_iptables_outchain[0])
		iptables_add_vmac(vrrp);
#endif

#ifdef _WITH_NFTABLES_
	if (global_data->vrrp_nf_table_name)
		nft_add_vmac(vrrp);
#endif
}

void
firewall_remove_vmac(const vrrp_t *vrrp)
{
#ifdef _WITH_IPTABLES_
	if (global_data->vrrp_iptables_outchain[0])
		iptables_remove_vmac(vrrp);
#endif

#ifdef _WITH_NFTABLES_
	if (global_data->vrrp_nf_table_name)
		nft_remove_vmac(vrrp);
#endif
}
#endif

void
firewall_fini(void)
{
#ifdef _WITH_IPTABLES_
	if (global_data->vrrp_iptables_inchain[0] ||
	    global_data->vrrp_iptables_outchain[0])
		iptables_fini();
#endif

#ifdef _WITH_NFTABLES_
	if (global_data->vrrp_nf_table_name)
		nft_end();
#endif
}
