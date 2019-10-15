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
 * Copyright (C) 2001-2018 Alexandre Cassen, <acassen@gmail.com>
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

#ifdef _HAVE_LIBIPTC_LINUX_NET_IF_H_COLLISION_
/* Linux 4.5 introduced a namespace collision when including
 * libiptc/libiptc.h due to both net/if.h and linux/if.h
 * being included.
 *
 * See: http://bugzilla.netfilter.org/show_bug.cgi?id=1067
 *
 * Including net/if.h first resolves the issue.
 */

#include <net/if.h>
#endif

#ifdef _HAVE_LIBIPTC_
#include <libiptc/libxtc.h>
#endif
#include <stdint.h>
#ifdef _HAVE_LIBIPSET_
#ifdef USE_LIBIPSET_LINUX_IP_SET_H
#include <libipset/linux_ip_set.h>
#else
#include <linux/netfilter/ipset/ip_set.h>
#endif
#endif
#include <stdbool.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include "vrrp_iptables_lib.h"
#include "vrrp_iptables_calls.h"
#include "vrrp_firewall.h"
#ifdef _HAVE_LIBIPSET_
#include "vrrp_ipset.h"
#endif
#include "logger.h"
#include "global_data.h"
#include "memory.h"
#include "warnings.h"

struct ipt_handle {
	struct iptc_handle *h4;
	struct ip6tc_handle *h6;
	bool updated_v4;
	bool updated_v6;
#ifdef _HAVE_LIBIPSET_
	struct ipset_session* session;
#endif
	int	cmd;
} ;

/* element 0 is IPv4, element 1 is IPv6 */
#ifdef _HAVE_LIBIPSET_
static bool vips_setup[2];
#endif
#ifdef _HAVE_VRRP_VMAC_
static bool igmp_setup[2];
#endif

static int
iptables_entry(struct ipt_handle* h, uint8_t family, const char* chain_name, unsigned int rulenum, const char* target_name, const ip_address_t* src_ip_address, const ip_address_t* dst_ip_address, const char* in_iface, const char* out_iface, uint16_t protocol, uint8_t type, int cmd, uint8_t flags, bool force)
{
	int res;

	if (family == AF_INET) {
		if (!h->h4)
			h->h4 = ip4tables_open ("filter");

		res = ip4tables_process_entry(h->h4, chain_name, rulenum, target_name, src_ip_address, dst_ip_address, in_iface, out_iface, protocol, type, cmd, flags, force);
		if (!res)
			h->updated_v4 = true ;
		return res;
	}
	else {
		if (!h->h6)
			h->h6 = ip6tables_open ("filter");

		res = ip6tables_process_entry(h->h6, chain_name, rulenum, target_name, src_ip_address, dst_ip_address, in_iface, out_iface, protocol, type, cmd, flags, force);
		if (!res)
			h->updated_v6 = true;
		return res;
	}

	return 0;
}

#ifdef _HAVE_LIBIPSET_
static void
add_del_vip_sets(struct ipt_handle *h, int cmd, uint8_t family, bool reload)
{
	if (!global_data->using_ipsets)
		return;

	if (cmd == IPADDRESS_ADD)
		add_vip_ipsets(&h->session, family, reload);
	else
		remove_vip_ipsets(&h->session, family);
}

static void
add_del_igmp_sets(struct ipt_handle *h, int cmd, uint8_t family, bool reload)
{
	if (cmd == IPADDRESS_ADD)
		add_igmp_ipsets(&h->session, family, reload);
	else
		remove_igmp_ipsets(&h->session, family);
}

static void
add_del_vip_rules(struct ipt_handle *h, int cmd, uint8_t family, bool ignore_errors)
{
	if (family == AF_INET) {
		if (h->h4 || (h->h4 = ip4tables_open("filter"))) {
			if (global_data->vrrp_iptables_inchain[0])
				ip4tables_add_rules(h->h4, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_DROP, NULL, NULL, global_data->vrrp_ipset_address, IPPROTO_NONE, 0, cmd, ignore_errors);
			if (global_data->vrrp_iptables_outchain[0])
				ip4tables_add_rules(h->h4, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_DROP, NULL, NULL, global_data->vrrp_ipset_address, IPPROTO_NONE, 0, cmd, ignore_errors);
		}

		h->updated_v4 = true;
		return;
	}

	if (h->h6 || (h->h6 = ip6tables_open("filter"))) {
		if (global_data->vrrp_iptables_inchain[0]) {
#ifdef HAVE_IPSET_ATTR_IFACE
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_TWO_SRC, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 135, cmd, ignore_errors);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_TWO_SRC, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 136, cmd, ignore_errors);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_TWO_SRC, XTC_LABEL_DROP, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_NONE, 0, cmd, ignore_errors);
#else
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 135, cmd, ignore_errors);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 136, cmd, ignore_errors);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_DROP, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_NONE, 0, cmd, ignore_errors);
#endif
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address6, IPPROTO_ICMPV6, 135, cmd, ignore_errors);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address6, IPPROTO_ICMPV6, 136, cmd, ignore_errors);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_DROP, NULL, NULL, global_data->vrrp_ipset_address6, IPPROTO_NONE, 0, cmd, ignore_errors);

			h->updated_v6 = true;
		}

		if (global_data->vrrp_iptables_outchain[0]) {
#ifdef HAVE_IPSET_ATTR_IFACE
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 135, cmd, ignore_errors);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 136, cmd, ignore_errors);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_ONE_SRC, XTC_LABEL_DROP, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_NONE, 0, cmd, ignore_errors);
#else
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 135, cmd, ignore_errors);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, 136, cmd, ignore_errors);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_DROP, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_NONE, 0, cmd, ignore_errors);
#endif
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address6, IPPROTO_ICMPV6, 135, cmd, ignore_errors);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address6, IPPROTO_ICMPV6, 136, cmd, ignore_errors);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_DROP, NULL, NULL, global_data->vrrp_ipset_address6, IPPROTO_NONE, 0, cmd, ignore_errors);

			h->updated_v6 = true;
		}
	}
}
#endif

#ifdef _HAVE_VRRP_VMAC_
static void
add_del_igmp_rules(struct ipt_handle *h, int cmd, uint8_t family, bool ignore_errors)
{
	ip_address_t igmp_addr;

	if (!global_data->vrrp_iptables_outchain[0])
		return;

	if (family == AF_INET) {
		igmp_addr.ifa.ifa_family = AF_INET;
		igmp_addr.u.sin.sin_addr.s_addr = htonl(0xe0000016);
	} else {
		igmp_addr.ifa.ifa_family = AF_INET6;
		igmp_addr.u.sin6_addr.s6_addr32[0] = htonl(0xff020000);
		igmp_addr.u.sin6_addr.s6_addr32[1] = 0;
		igmp_addr.u.sin6_addr.s6_addr32[2] = 0;
		igmp_addr.u.sin6_addr.s6_addr32[3] = htonl(0x16);
	}

#ifdef HAVE_IPSET_ATTR_IFACE
	if (global_data->using_ipsets) {
		if (family == AF_INET) {
			if (h->h4 || (h->h4 = ip4tables_open("filter"))) {
				ip4tables_add_rules(h->h4, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_TWO, 0, XTC_LABEL_DROP, NULL, &igmp_addr, global_data->vrrp_ipset_igmp, IPPROTO_NONE, 0, cmd, ignore_errors);
				h->updated_v4 = true;
			}

			return;
		}

		if (h->h6 || (h->h6 = ip6tables_open("filter"))) {
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_TWO, 0, XTC_LABEL_DROP, NULL, &igmp_addr, global_data->vrrp_ipset_mld, IPPROTO_NONE, 0, cmd, ignore_errors);
			h->updated_v6 = true;
		}

		return;
	}
#endif

	iptables_entry(h, family, global_data->vrrp_iptables_outchain, APPEND_RULE,
			XTC_LABEL_RETURN, NULL, &igmp_addr, NULL, NULL,
			IPPROTO_NONE, 0, cmd, IPT_INV_DSTIP, ignore_errors);
}
#endif

struct ipt_handle*
iptables_open(int cmd)
{
	struct ipt_handle *h = MALLOC(sizeof(struct ipt_handle));

	h->cmd = cmd;

	return h;
}

int
iptables_close(struct ipt_handle* h)
{
	int res = 0;

#ifdef _HAVE_LIBIPSET_
	if (h->cmd == IPADDRESS_ADD && h->session) {
		ipset_session_end(h->session);
		h->session = NULL;
	}
#endif

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

init_state_t
check_chains_exist_lib(uint8_t family)
{
	struct iptc_handle *h4;
	struct ip6tc_handle *h6;
	init_state_t ret = INIT_SUCCESS;

	if (family == AF_INET) {
		h4 = ip4tables_open("filter");

		if (!h4) {
			log_message(LOG_INFO, "WARNING, ip_tables module not installed - can't filter IPv4 addresses");
			return INIT_FAILED;
		}

		if (global_data->vrrp_iptables_inchain[0] &&
		    !ip4tables_is_chain(h4, global_data->vrrp_iptables_inchain)) {
			log_message(LOG_INFO, "iptables chain %s doesn't exist", global_data->vrrp_iptables_inchain);
			ret = INIT_FAILED;
		}
		if (global_data->vrrp_iptables_outchain[0] &&
		    !ip4tables_is_chain(h4, global_data->vrrp_iptables_outchain)) {
			log_message(LOG_INFO, "iptables chain %s doesn't exist", global_data->vrrp_iptables_outchain);
			ret = INIT_FAILED;
		}

		ip4tables_close(h4, false);

		return ret;
	}

	h6 = ip6tables_open("filter");

	if (!h6) {
		log_message(LOG_INFO, "WARNING, ip6_tables module not installed - can't filter IPv6 addresses");
		return INIT_FAILED;
	}

	if (global_data->vrrp_iptables_inchain[0] &&
	    !ip6tables_is_chain(h6, global_data->vrrp_iptables_inchain)) {
		log_message(LOG_INFO, "ip6tables chain %s doesn't exist", global_data->vrrp_iptables_inchain);
		ret = INIT_FAILED;
	}
	if (global_data->vrrp_iptables_outchain[0] &&
	    !ip6tables_is_chain(h6, global_data->vrrp_iptables_outchain)) {
		log_message(LOG_INFO, "ip6tables chain %s doesn't exist", global_data->vrrp_iptables_outchain);
		ret = INIT_FAILED;
	}

	ip6tables_close(h6, false);

	return ret;
}

RELAX_SUGGEST_ATTRIBUTE_CONST_START
init_state_t
iptables_init_lib(
#ifndef _LIBIPTC_DYNAMIC_
		  __attribute__((unused))
#endif
					  uint8_t family)
{
#ifdef _LIBIPTC_DYNAMIC_
	if (!iptables_lib_init(family))
		return INIT_FAILED;
#endif

#ifdef _HAVE_LIBIPSET_
	if (global_data->using_ipsets && !ipset_initialise())
		global_data->using_ipsets = false;
#endif

	return INIT_SUCCESS;
}
RELAX_SUGGEST_ATTRIBUTE_CONST_END

#ifdef _HAVE_LIBIPSET_
static bool
setup_vip(struct ipt_handle *h, uint8_t family)
{
// Is last parameter for next two calls ever used ?
	add_del_vip_sets(h, IPADDRESS_ADD, family, false);
	add_del_vip_rules(h, IPADDRESS_ADD, family, false);

	vips_setup[family != AF_INET] = true;

	return true;
}
#endif

#if defined _HAVE_VRRP_VMAC_
static bool
setup_igmp(struct ipt_handle *h, uint8_t family)
{
// Is last parameter for next two calls ever used ?
#ifdef HAVE_IPSET_ATTR_IFACE
	if (global_data->using_ipsets)
		add_del_igmp_sets(h, IPADDRESS_ADD, family, false);
#endif

	add_del_igmp_rules(h, IPADDRESS_ADD, family, false);

	igmp_setup[family != AF_INET] = true;

	return true;
}

static void
handle_iptable_rule_to_NA_lib(ip_address_t *ipaddress, const char *ifname, int cmd, void *h, bool force)
{
	if (global_data->vrrp_iptables_inchain[0] == '\0')
		return;

	if (global_data->vrrp_iptables_outchain[0]) {
		iptables_entry(h, AF_INET6, global_data->vrrp_iptables_outchain, 0,
				XTC_LABEL_ACCEPT, ipaddress, NULL, NULL, ifname,
				IPPROTO_ICMPV6, 135, cmd, 0, force);
		iptables_entry(h, AF_INET6, global_data->vrrp_iptables_outchain, 1,
				XTC_LABEL_ACCEPT, ipaddress, NULL, NULL, ifname,
				IPPROTO_ICMPV6, 136, cmd, 0, force);
	}

	iptables_entry(h, AF_INET6, global_data->vrrp_iptables_inchain, 0,
			XTC_LABEL_ACCEPT, NULL, ipaddress, ifname, NULL,
			IPPROTO_ICMPV6, 135, cmd, 0, force);
	iptables_entry(h, AF_INET6, global_data->vrrp_iptables_inchain, 1,
			XTC_LABEL_ACCEPT, NULL, ipaddress, ifname, NULL,
			IPPROTO_ICMPV6, 136, cmd, 0, force);

}

void
handle_iptable_rule_to_vip_lib(ip_address_t *ipaddress, int cmd, struct ipt_handle *h, bool force)
{
	char *ifname = NULL;
	uint8_t family = ipaddress->ifa.ifa_family;

#ifdef _HAVE_LIBIPSET_
	if (global_data->using_ipsets)
	{
		if (!vips_setup[family != AF_INET])
			setup_vip(h, ipaddress->ifa.ifa_family);

		if (!h->session)
			h->session = ipset_session_start();

		ipset_entry(h->session, cmd, ipaddress);
		ipaddress->iptable_rule_set = (cmd != IPADDRESS_DEL);

		return;
	}
#endif

	if (family == AF_INET6 &&
	    IN6_IS_ADDR_LINKLOCAL(&ipaddress->u.sin6_addr))
		ifname = ipaddress->ifp->ifname;

	iptables_entry(h, family, global_data->vrrp_iptables_inchain, 0,
			XTC_LABEL_DROP, NULL, ipaddress, ifname, NULL,
			IPPROTO_NONE, 0, cmd, 0, force);

	if (global_data->vrrp_iptables_outchain[0])
		iptables_entry(h, family, global_data->vrrp_iptables_outchain, 0,
				XTC_LABEL_DROP, ipaddress, NULL, NULL, ifname,
				IPPROTO_NONE, 0, cmd, 0, force);

	if (family == AF_INET6)
		handle_iptable_rule_to_NA_lib(ipaddress, ifname, cmd, h, force);

	ipaddress->iptable_rule_set = (cmd != IPADDRESS_DEL);
}

#ifdef _HAVE_VRRP_VMAC_
void
handle_iptable_rule_for_igmp_lib(const char *ifname, int cmd, uint8_t family, struct ipt_handle *h)
{
	if (global_data->vrrp_iptables_outchain[0] == '\0')
		return;

	if (!igmp_setup[family != AF_INET])
		setup_igmp(h, family);

#ifdef HAVE_IPSET_ATTR_IFACE
// Check sets with ifname
	if (global_data->using_ipsets)
	{
		if (!h->session)
			h->session = ipset_session_start();

		ipset_entry_igmp(h->session, cmd, ifname, family);

		return;
	}
#endif

	iptables_entry(h, family, global_data->vrrp_iptables_outchain, APPEND_RULE,
			XTC_LABEL_DROP, NULL, NULL, NULL, ifname,
			IPPROTO_NONE, 0, cmd, 0, false);
#endif
}
#endif

void
iptables_fini_lib(void)
{
	uint8_t family = AF_INET;
	struct ipt_handle *h = iptables_open(IPADDRESS_DEL);

// TODO - just have a single call to remove all sets
	do {
#ifdef _HAVE_LIBIPSET_
		if (global_data->using_ipsets) {
			if (vips_setup[family != AF_INET])
				add_del_vip_rules(h, IPADDRESS_DEL, family, false);
			if (igmp_setup[family != AF_INET])
				add_del_igmp_rules(h, IPADDRESS_DEL, family, false);
		}
		else
#endif
		{
			if (igmp_setup[family != AF_INET]) {
				add_del_igmp_rules(h, IPADDRESS_DEL, family, false);
				igmp_setup[family != AF_INET] = false;
			}
		}
		family = family == AF_INET ? AF_INET6 : 0;
	} while (family);

	iptables_close(h);

	/* The sets must not be in use when the ipset session starts */
#ifdef _HAVE_LIBIPSET_
	if (global_data->using_ipsets) {
		h = iptables_open(IPADDRESS_DEL);
		family = AF_INET;
		do {
				if (vips_setup[family != AF_INET]) {
					add_del_vip_sets(h, IPADDRESS_DEL, family, false);
					vips_setup[family != AF_INET] = false;
				}
				if (igmp_setup[family != AF_INET]) {
					add_del_igmp_sets(h, IPADDRESS_DEL, family, false);
					igmp_setup[family != AF_INET] = false;
				}
			family = family == AF_INET ? AF_INET6 : 0;
		} while (family);

		iptables_close(h);
	}
#endif
}
