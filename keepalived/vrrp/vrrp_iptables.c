/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        iptables manipulation directly without invoking iptables program.
 *		This will use ipsets if they are available, in preference to
 *		multiple entries in iptables.
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

#include "config.h"

#ifdef _HAVE_LINUX_NET_IF_H_COLLISION_
/* The following is a horrible workaround. Linux 4.5 introduced a namespace
 * collision when including libiptc/libiptc.h due to both net/if.h and linux/if.h
 * being included.
 *
 * See: http://bugzilla.netfilter.org/show_bug.cgi?id=1067
 *
 * Defining _LINUX_IF_H stops linux/if.h being included.
 */

#define _LINUX_IF_H
#endif

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

/* If the chains don't exist, or modules not loaded, we can't use iptables/ip6tables */
bool use_ip4tables = true;
bool use_ip6tables = true;

#ifdef _HAVE_LIBIPSET_
static
void add_del_sets(int cmd, bool reload)
{
	if (!global_data->using_ipsets)
		return;

	if (cmd == IPADDRESS_ADD)
		add_ipsets(reload);
	else
		remove_ipsets();
}

static
void add_del_rules(int cmd, bool ignore_errors)
{
	struct iptc_handle *h4;
	struct ip6tc_handle *h6;

	if (use_ip4tables &&
	    global_data->block_ipv4 &&
	    (global_data->vrrp_iptables_inchain[0] ||
	     global_data->vrrp_iptables_outchain[0])) {
		if ((h4 = ip4tables_open("filter"))) {
			if (global_data->vrrp_iptables_inchain[0])
				ip4tables_add_rules(h4, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_DROP, global_data->vrrp_ipset_address, IPPROTO_NONE, 0, cmd, ignore_errors);
			if (global_data->vrrp_iptables_outchain[0])
				ip4tables_add_rules(h4, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_DROP, global_data->vrrp_ipset_address, IPPROTO_NONE, 0, cmd, ignore_errors);
			ip4tables_close(h4, true);
		}
	}

	if (use_ip6tables &&
	    global_data->block_ipv6 &&
	    (global_data->vrrp_iptables_inchain[0] ||
	     global_data->vrrp_iptables_outchain[0])) {
		if ((h6 = ip6tables_open("filter"))) {
			if (global_data->vrrp_iptables_inchain[0]) {
#ifdef HAVE_IPSET_ATTR_IFACE
				ip6tables_add_rules(h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_TWO_SRC, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 135, cmd, ignore_errors);
				ip6tables_add_rules(h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_TWO_SRC, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 136, cmd, ignore_errors);
				ip6tables_add_rules(h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_TWO_SRC, XTC_LABEL_DROP, global_data->vrrp_ipset_address_iface6, IPPROTO_NONE, 0, cmd, ignore_errors);
#else
				ip6tables_add_rules(h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 135, cmd, ignore_errors);
				ip6tables_add_rules(h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 136, cmd, ignore_errors);
				ip6tables_add_rules(h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_DROP, global_data->vrrp_ipset_address_iface6, IPPROTO_NONE, 0, cmd, ignore_errors);
#endif
				ip6tables_add_rules(h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address6, IPPROTO_ICMPV6, 135, cmd, ignore_errors);
				ip6tables_add_rules(h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address6, IPPROTO_ICMPV6, 136, cmd, ignore_errors);
				ip6tables_add_rules(h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_DROP, global_data->vrrp_ipset_address6, IPPROTO_NONE, 0, cmd, ignore_errors);
			}

			if (global_data->vrrp_iptables_outchain[0]) {
#ifdef HAVE_IPSET_ATTR_IFACE
				ip6tables_add_rules(h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 135, cmd, ignore_errors);
				ip6tables_add_rules(h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 136, cmd, ignore_errors);
				ip6tables_add_rules(h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_ONE_SRC, XTC_LABEL_DROP, global_data->vrrp_ipset_address_iface6, IPPROTO_NONE, 0, cmd, ignore_errors);
#else
				ip6tables_add_rules(h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 135, cmd, ignore_errors);
				ip6tables_add_rules(h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 136, cmd, ignore_errors);
				ip6tables_add_rules(h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_DROP, global_data->vrrp_ipset_address_iface6, IPPROTO_NONE, 0, cmd, ignore_errors);
#endif
				ip6tables_add_rules(h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address6, IPPROTO_ICMPV6, 135, cmd, ignore_errors);
				ip6tables_add_rules(h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, global_data->vrrp_ipset_address6, IPPROTO_ICMPV6, 136, cmd, ignore_errors);
				ip6tables_add_rules(h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_DROP, global_data->vrrp_ipset_address6, IPPROTO_NONE, 0, cmd, ignore_errors);
			}

			ip6tables_close(h6, true);
		}
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

static void check_chains_exist(void)
{
	struct iptc_handle *h4;
	struct ip6tc_handle *h6;

	if (global_data->block_ipv4) {
		h4 = ip4tables_open("filter");

		if (!h4) {
			log_message(LOG_INFO, "WARNING, ip_tables module not installed - can't filter IPv4 addresses");
			use_ip4tables = false;
		} else {
			if (global_data->vrrp_iptables_inchain[0] &&
			    !ip4tables_is_chain(h4, global_data->vrrp_iptables_inchain)) {
				log_message(LOG_INFO, "iptables chain %s doesn't exist", global_data->vrrp_iptables_inchain);
				use_ip4tables = false;
			}
			if (global_data->vrrp_iptables_outchain[0] &&
			    !ip4tables_is_chain(h4, global_data->vrrp_iptables_outchain)) {
				log_message(LOG_INFO, "iptables chain %s doesn't exist", global_data->vrrp_iptables_outchain);
				use_ip4tables = false;
			}

			ip4tables_close(h4, false);
		}
	}
	else
		use_ip4tables = false;

	if (global_data->block_ipv6) {
		h6 = ip6tables_open("filter");

		if (!h6) {
			log_message(LOG_INFO, "WARNING, ip6_tables module not installed - can't filter IPv6 addresses");
			use_ip6tables = false;
		} else {
			if (global_data->vrrp_iptables_inchain[0] &&
			    !ip6tables_is_chain(h6, global_data->vrrp_iptables_inchain)) {
				log_message(LOG_INFO, "ip6tables chain %s doesn't exist", global_data->vrrp_iptables_inchain);
				use_ip6tables = false;
			}
			if (global_data->vrrp_iptables_outchain[0] &&
			    !ip6tables_is_chain(h6, global_data->vrrp_iptables_outchain)) {
				log_message(LOG_INFO, "ip6tables chain %s doesn't exist", global_data->vrrp_iptables_outchain);
				use_ip6tables = false;
			}

			ip6tables_close(h6, false);
		}
	}
	else
		use_ip6tables = false;
}

static int iptables_entry(struct ipt_handle* h, const char* chain_name, unsigned int rulenum, char* target_name, const ip_address_t* src_ip_address, const ip_address_t* dst_ip_address, const char* in_iface, const char* out_iface, uint16_t protocol, uint8_t type, int cmd, bool force)
{
	int res;

	if ((src_ip_address && src_ip_address->ifa.ifa_family == AF_INET) ||
	    (dst_ip_address && dst_ip_address->ifa.ifa_family == AF_INET )) {
		if (!h->h4)
			h->h4 = ip4tables_open ("filter");

		res = ip4tables_process_entry(h->h4, chain_name, rulenum, target_name, src_ip_address, dst_ip_address, in_iface, out_iface, protocol, type, cmd, force);
		if (!res)
			h->updated_v4 = true ;
		return res;
	}
	else if ((src_ip_address && src_ip_address->ifa.ifa_family == AF_INET6) ||
		 (dst_ip_address && dst_ip_address->ifa.ifa_family == AF_INET6)) {
		if (!h->h6)
			h->h6 = ip6tables_open ("filter");

		res = ip6tables_process_entry(h->h6, chain_name, rulenum, target_name, src_ip_address, dst_ip_address, in_iface, out_iface, protocol, type, cmd, force);
		if (!res)
			h->updated_v6 = true;
		return res;
	}

	return 0;
}

static void
handle_iptable_rule_to_NA(ip_address_t *ipaddress, int cmd, void *h, bool force)
{

	char *ifname = NULL;

	if (global_data->vrrp_iptables_inchain[0] == '\0')
		return;

	if (IN6_IS_ADDR_LINKLOCAL(&ipaddress->u.sin6_addr))
		ifname = ipaddress->ifp->ifname;

	iptables_entry(h, global_data->vrrp_iptables_inchain, APPEND_RULE,
			XTC_LABEL_ACCEPT, NULL, ipaddress, ifname, NULL,
			IPPROTO_ICMPV6, 135, cmd, force);
	iptables_entry(h, global_data->vrrp_iptables_inchain, APPEND_RULE,
			XTC_LABEL_ACCEPT, NULL, ipaddress, ifname, NULL,
			IPPROTO_ICMPV6, 136, cmd, force);

	if (global_data->vrrp_iptables_outchain[0] == '\0')
		return;

	iptables_entry(h, global_data->vrrp_iptables_outchain, APPEND_RULE,
			XTC_LABEL_ACCEPT, ipaddress, NULL, NULL, ifname,
			IPPROTO_ICMPV6, 135, cmd, force);
	iptables_entry(h, global_data->vrrp_iptables_outchain, APPEND_RULE,
			XTC_LABEL_ACCEPT, ipaddress, NULL, NULL, ifname,
			IPPROTO_ICMPV6, 136, cmd, force);
}

void
handle_iptable_rule_to_vip(ip_address_t *ipaddress, int cmd, struct ipt_handle *h, bool force)
{
	char *ifname = NULL;

	/* If iptables for the address family isn't in use, skip */
	if ((ipaddress->ifa.ifa_family == AF_INET && !use_ip4tables) ||
	    (ipaddress->ifa.ifa_family == AF_INET6 && !use_ip6tables))
		return;

	if (global_data->vrrp_iptables_inchain[0] == '\0')
		return;

#ifdef _HAVE_LIBIPSET_
	if (global_data->using_ipsets)
	{
		if (!h->session)
			h->session = ipset_session_start();

		ipset_entry(h->session, cmd, ipaddress);
		ipaddress->iptable_rule_set = (cmd != IPADDRESS_DEL);

		return;
	}
#endif

	if (IP_IS6(ipaddress)) {
		if (IN6_IS_ADDR_LINKLOCAL(&ipaddress->u.sin6_addr))
			ifname = ipaddress->ifp->ifname;
		handle_iptable_rule_to_NA(ipaddress, cmd, h, force);
	}

	iptables_entry(h, global_data->vrrp_iptables_inchain, APPEND_RULE,
			XTC_LABEL_DROP, NULL, ipaddress, ifname, NULL,
			IPPROTO_NONE, 0, cmd, force);

	ipaddress->iptable_rule_set = (cmd != IPADDRESS_DEL);

	if (global_data->vrrp_iptables_outchain[0] == '\0')
		return;

	iptables_entry(h, global_data->vrrp_iptables_outchain, APPEND_RULE,
			XTC_LABEL_DROP, ipaddress, NULL, NULL, ifname,
			IPPROTO_NONE, 0, cmd, force);
}

static void
iptables_remove_structure(bool ignore_errors)
{
#ifdef _HAVE_LIBIPSET_
	if (global_data->using_ipsets) {
		add_del_rules(IPADDRESS_DEL, ignore_errors);
		add_del_sets(IPADDRESS_DEL, false);
	}
#endif
}

void
iptables_startup(bool reload)
{
	if (!reload) {
		check_chains_exist();
#ifdef _HAVE_LIBIPSET_
		if (!use_ip4tables && !use_ip6tables)
			global_data->using_ipsets = false;
#endif
	}

#ifdef _HAVE_LIBIPSET_
	if (global_data->using_ipsets) {
		add_del_sets(IPADDRESS_ADD, reload);
		add_del_rules(IPADDRESS_ADD, false);
	}
#endif
}

void
iptables_cleanup(void)
{
	iptables_remove_structure(true);
}

bool
iptables_init(void)
{
#ifdef _HAVE_LIBIPSET_
	if (!ipset_init()) {
		global_data->using_ipsets = false;

		return false;
	}
#endif

	return true;
}

void
iptables_fini(void)
{
	iptables_remove_structure(false);
}
