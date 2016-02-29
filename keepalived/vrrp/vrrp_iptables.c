/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        iptables manipulation directly without invoking iptables program.
 * 		This will use ipsets if they are available, in preference to
 * 		multiple entries in iptables.
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
 * Copyright (C) 2001-2016 Alexandre Cassen, <acassen@gmail.com>
 */

/* The way iptables appears to work is that when we do an iptc_init, we get a
 * snapshot of the iptables table, which internally includes an update number.
 * When iptc_commit is called, it checks the update number, and if it has been
 * updated by someone else, returns EAGAIN.
 *
 * Note: iptc_commit only needs to be called if we are changing something. In
 *   all cases though, iptc_free must be called.
 *
 * Rules are numbered from 0 - despite what some documentation says
 *
 * Note: as insertions/deletions are made, rule numbers are changing.
 *
 * See http://www.tldp.org/HOWTO/Querying-libiptc-HOWTO/qfunction.html for
 *   some documentation
*/

#include <libiptc/libiptc.h>

#include "vrrp_iptables.h"
#include "vrrp_iptables_calls.h"
#ifdef _HAVE_LIBIPSET_
#include "vrrp_ipset.h"
#endif
#include "logger.h"
#include "memory.h"
#include "global_data.h"

#ifdef _HAVE_LIBIPSET_
#include <xtables.h>
#include "vrrp_ipset.h"
#endif

struct ipt_handle {
	struct iptc_handle *h4;
	struct ip6tc_handle *h6;
	bool updated_v4;
	bool updated_v6;
#ifdef _HAVE_LIBIPSET_
	struct ipset_session* session;
#endif
} ;

/* If the chains don't exist, we can't use iptables */
static bool use_iptables = true;

#ifdef _HAVE_LIBIPSET_
static
void add_del_sets(int cmd)
{
	if (cmd == IPADDRESS_ADD) {
		if (!add_ipsets())
			global_data->using_ipsets = false;
		return;
	}

	remove_ipsets();
}

static
void add_del_rules(int cmd)
{
	struct iptc_handle *h4;
	struct ip6tc_handle *h6;

	if (global_data->block_ipv4 &&
	    (global_data->vrrp_iptables_inchain[0] ||
	     global_data->vrrp_iptables_outchain[0])) {
		h4 = ip4tables_open("filter");

		if (global_data->vrrp_iptables_inchain[0])
			ip4tables_add_rules(h4, global_data->vrrp_iptables_inchain, -1, IPSET_DIM_ONE, 0, XTC_LABEL_DROP, global_data->vrrp_ipset_address, IPPROTO_NONE, 0, cmd) ;
		if (global_data->vrrp_iptables_outchain[0])
			ip4tables_add_rules(h4, global_data->vrrp_iptables_outchain, -1, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_DROP, global_data->vrrp_ipset_address, IPPROTO_NONE, 0, cmd) ;
		ip4tables_close(h4, true);
	}

	if (global_data->block_ipv6 &&
	    (global_data->vrrp_iptables_inchain[0] ||
	     global_data->vrrp_iptables_outchain[0])) {
		h6 = ip6tables_open("filter");

		if (global_data->vrrp_iptables_inchain[0]) {
			ip6tables_add_rules ( h6, global_data->vrrp_iptables_inchain, -1, IPSET_DIM_TWO, IPSET_DIM_TWO_SRC, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 135, cmd) ;
			ip6tables_add_rules ( h6, global_data->vrrp_iptables_inchain, -1, IPSET_DIM_TWO, IPSET_DIM_TWO_SRC, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 136, cmd) ;
			ip6tables_add_rules ( h6, global_data->vrrp_iptables_inchain, -1, IPSET_DIM_TWO, IPSET_DIM_TWO_SRC, XTC_LABEL_DROP, global_data->vrrp_ipset_address_iface6, IPPROTO_NONE, 0, cmd) ;
			ip6tables_add_rules ( h6, global_data->vrrp_iptables_inchain, -1, IPSET_DIM_ONE, 0, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address6, IPPROTO_ICMPV6, 135, cmd) ;
			ip6tables_add_rules ( h6, global_data->vrrp_iptables_inchain, -1, IPSET_DIM_ONE, 0, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address6, IPPROTO_ICMPV6, 136, cmd) ;
			ip6tables_add_rules ( h6, global_data->vrrp_iptables_inchain, -1, IPSET_DIM_ONE, 0, XTC_LABEL_DROP, global_data->vrrp_ipset_address6, IPPROTO_NONE, 0, cmd) ;
		}

		if (global_data->vrrp_iptables_outchain[0]) {
			ip6tables_add_rules ( h6, global_data->vrrp_iptables_outchain, -1, IPSET_DIM_TWO, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 135, cmd) ;
			ip6tables_add_rules ( h6, global_data->vrrp_iptables_outchain, -1, IPSET_DIM_TWO, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 136, cmd) ;
			ip6tables_add_rules ( h6, global_data->vrrp_iptables_outchain, -1, IPSET_DIM_TWO, IPSET_DIM_ONE_SRC, XTC_LABEL_DROP, global_data->vrrp_ipset_address_iface6, IPPROTO_NONE, 0, cmd) ;
			ip6tables_add_rules ( h6, global_data->vrrp_iptables_outchain, -1, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address6, IPPROTO_ICMPV6, 135, cmd) ;
			ip6tables_add_rules ( h6, global_data->vrrp_iptables_outchain, -1, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address6, IPPROTO_ICMPV6, 136, cmd) ;
			ip6tables_add_rules ( h6, global_data->vrrp_iptables_outchain, -1, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_DROP, global_data->vrrp_ipset_address6, IPPROTO_NONE, 0, cmd) ;
		}

		ip6tables_close(h6, true);
	}
}
#endif

struct ipt_handle* iptables_open()
{
	struct ipt_handle *h = MALLOC(sizeof(struct ipt_handle));

	return h;
}

int iptables_close(struct ipt_handle* h)
{
	int res = 0;

	if (h->h4)
		res = ip4tables_close(h->h4, h->updated_v4);
	if (h->h6)
		res += ip6tables_close(h->h6, h->updated_v6);

#ifdef _HAVE_LIBIPSET_
	if (h->session)
		ipset_session_end(h->session);
#endif

	FREE(h);

	return res;
}

static int check_chains_exist(void)
{
	struct iptc_handle *h4;
	struct ip6tc_handle *h6;
	bool status = true;

	if (global_data->block_ipv4) {
		h4 = ip4tables_open("filter");

		if (global_data->vrrp_iptables_inchain[0] &&
		    !ip4tables_is_chain(h4, global_data->vrrp_iptables_inchain)) {
			log_message(LOG_INFO, "iptables chain %s doesn't exist", global_data->vrrp_iptables_inchain);
			status = false;
		}
		if (global_data->vrrp_iptables_outchain[0] &&
		    !ip4tables_is_chain(h4, global_data->vrrp_iptables_outchain)) {
			log_message(LOG_INFO, "iptables chain %s doesn't exist", global_data->vrrp_iptables_outchain);
			status = false;
		}

		ip4tables_close(h4, false);
	}

	if (global_data->block_ipv6) {
		h6 = ip6tables_open("filter");

		if (global_data->vrrp_iptables_inchain[0] &&
		    !ip6tables_is_chain(h6, global_data->vrrp_iptables_inchain)) {
			log_message(LOG_INFO, "ip6tables chain %s doesn't exist", global_data->vrrp_iptables_inchain);
			status = false;
		}
		if (global_data->vrrp_iptables_outchain[0] &&
		    !ip6tables_is_chain(h6, global_data->vrrp_iptables_outchain)) {
			log_message(LOG_INFO, "ip6tables chain %s doesn't exist", global_data->vrrp_iptables_outchain);
			status = false;
		}

		ip6tables_close(h6, false);
	}

	return status;
}

static int iptables_entry(struct ipt_handle* h, const char* chain_name, int rulenum, char* target_name, const ip_address_t* src_ip_address, const ip_address_t* dst_ip_address, const char* in_iface, const char* out_iface, uint16_t protocol, uint16_t type, int cmd)
{
	int res;

	if ((src_ip_address && src_ip_address->ifa.ifa_family == AF_INET) ||
	    (dst_ip_address && dst_ip_address->ifa.ifa_family == AF_INET )) {
		if (!h->h4)
			h->h4 = ip4tables_open ("filter");

		res = ip4tables_process_entry( h->h4, chain_name, rulenum, target_name, src_ip_address, dst_ip_address, in_iface, out_iface, protocol, type, cmd);
		if (!res)
			h->updated_v4 = true ;
		return res;
	}
	else if ((src_ip_address && src_ip_address->ifa.ifa_family == AF_INET6) ||
		 (dst_ip_address && dst_ip_address->ifa.ifa_family == AF_INET6)) {
		if (!h->h6)
			h->h6 = ip6tables_open ("filter");

		res = ip6tables_process_entry( h->h6, chain_name, rulenum, target_name, src_ip_address, dst_ip_address, in_iface, out_iface, protocol, type, cmd);
		if (!res)
			h->updated_v6 = true;
		return res;
	}

	return 0;
}

static void
handle_iptable_rule_to_NA(ip_address_t *ipaddress, int cmd, char *ifname, void *h)
{
	if (global_data->vrrp_iptables_inchain[0] == '\0')
		return;

	iptables_entry(h, global_data->vrrp_iptables_inchain, -1,
			XTC_LABEL_ACCEPT, NULL, ipaddress,
			ifname, NULL,
			IPPROTO_ICMPV6, 135, cmd);
	iptables_entry(h, global_data->vrrp_iptables_inchain, -1,
			XTC_LABEL_ACCEPT, NULL, ipaddress,
			ifname, NULL,
			IPPROTO_ICMPV6, 136, cmd);

	if (global_data->vrrp_iptables_outchain[0] == '\0')
		return;

	iptables_entry(h, global_data->vrrp_iptables_outchain, -1,
			XTC_LABEL_ACCEPT, ipaddress, NULL,
			NULL, ifname,
			IPPROTO_ICMPV6, 135, cmd);
	iptables_entry(h, global_data->vrrp_iptables_outchain, -1,
			XTC_LABEL_ACCEPT, ipaddress, NULL,
			NULL, ifname,
			IPPROTO_ICMPV6, 136, cmd);
}

void
handle_iptable_rule_to_vip(ip_address_t *ipaddress, int cmd, char *ifname, struct ipt_handle *h)
{
	char *my_ifname = NULL;

	if (!use_iptables)
		return;

	if (global_data->vrrp_iptables_inchain[0] == '\0')
		return;

#ifdef _HAVE_LIBIPSET_
	if (global_data->using_ipsets)
	{
		if (!h->session)
			h->session = ipset_session_start();

		ipset_entry(h->session, cmd, ipaddress, ifname);

		return;
	}
#endif

	if (IP_IS6(ipaddress)) {
		if (IN6_IS_ADDR_LINKLOCAL(&ipaddress->u.sin6_addr))
			my_ifname = ifname;

		handle_iptable_rule_to_NA(ipaddress, cmd, my_ifname, h);
	}

	iptables_entry(h, global_data->vrrp_iptables_inchain, -1,
			XTC_LABEL_DROP, NULL, ipaddress,
			my_ifname, NULL,
			IPPROTO_NONE, 0, cmd);

	ipaddress->iptable_rule_set = (cmd != IPADDRESS_DEL) ? true : false;

	if (global_data->vrrp_iptables_outchain[0] == '\0')
		return;

	iptables_entry(h, global_data->vrrp_iptables_outchain, -1,
			XTC_LABEL_DROP, ipaddress, NULL,
			NULL, my_ifname,
			IPPROTO_NONE, 0, cmd);
}

void iptables_init()
{
	if (!check_chains_exist()) {
		use_iptables = false;
#ifdef _HAVE_LIBIPSET_
		global_data->using_ipsets = false;
#endif

		return;
	}
#ifdef _HAVE_LIBIPSET_
	if (global_data->using_ipsets)
		add_del_sets(IPADDRESS_ADD);
	if (global_data->using_ipsets)
		add_del_rules(IPADDRESS_ADD);
#endif
}

void iptables_fini()
{
#ifdef _HAVE_LIBIPSET_
	if (global_data->using_ipsets) {
		add_del_rules(IPADDRESS_DEL);
		add_del_sets(IPADDRESS_DEL);
	}
#endif
}
