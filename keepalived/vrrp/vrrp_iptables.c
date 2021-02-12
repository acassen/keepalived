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
#include <sys/stat.h>
#include <sys/vfs.h>
#include <linux/magic.h>

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

#include <libiptc/libxtc.h>
#include <stdint.h>
#ifdef _HAVE_LIBIPSET_
#include <linux/netfilter/ipset/ip_set.h>
#endif
#include <stdbool.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <netinet/icmp6.h>

#include "vrrp_iptables.h"

#include "global_data.h"
#include "vrrp_ipaddress.h"
#include "vrrp.h"
#include "vrrp_firewall.h"
#include "vrrp_iptables_calls.h"
#ifdef _HAVE_LIBIPSET_
#include "vrrp_ipset.h"
#endif
#include "logger.h"
#include "memory.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_firewall.h"
#endif


#define IPTABLES_MAX_TRIES      3       /* How many times to try adding/deleting when get EAGAIN */

typedef enum {
	NOT_INIT,
	INIT_SUCCESS,
	INIT_FAILED,
} init_state_t;

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

/* Element [0] is IPv4, element [1] is IPv6 */
static init_state_t setup[2];
static init_state_t vips_setup[2];
#ifdef _HAVE_VRRP_VMAC_
static init_state_t igmp_setup[2];
#endif

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
add_del_vip_sets(struct ipt_handle *h, int cmd, uint8_t family)
{
	if (!global_data->using_ipsets)
		return;

	if (cmd == IPADDRESS_ADD)
		add_vip_ipsets(&h->session, family, false);
	else
		remove_vip_ipsets(&h->session, family);
}

#ifdef _HAVE_VRRP_VMAC_
static void
add_del_igmp_sets(struct ipt_handle *h, int cmd, uint8_t family)
{
	if (cmd == IPADDRESS_ADD)
		add_igmp_ipsets(&h->session, family, false);
	else
		remove_igmp_ipsets(&h->session, family);
}
#endif

static void
add_del_vip_rules(struct ipt_handle *h, int cmd, uint8_t family)
{
	if (family == AF_INET) {
		if (h->h4 || (h->h4 = ip4tables_open("filter"))) {
			if (global_data->vrrp_iptables_inchain)
				ip4tables_add_rules(h->h4, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_DROP, NULL, NULL, global_data->vrrp_ipset_address, IPPROTO_NONE, 0, cmd, false);
			if (global_data->vrrp_iptables_outchain)
				ip4tables_add_rules(h->h4, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_DROP, NULL, NULL, global_data->vrrp_ipset_address, IPPROTO_NONE, 0, cmd, false);
		}

		h->updated_v4 = true;
		return;
	}

	if (h->h6 || (h->h6 = ip6tables_open("filter"))) {
		if (global_data->vrrp_iptables_inchain) {
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_TWO_SRC, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, ND_NEIGHBOR_SOLICIT, cmd, false);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_TWO_SRC, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, ND_NEIGHBOR_ADVERT, cmd, false);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_TWO_SRC, XTC_LABEL_DROP, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_NONE, 0, cmd, false);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address6, IPPROTO_ICMPV6, ND_NEIGHBOR_SOLICIT, cmd, false);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address6, IPPROTO_ICMPV6, ND_NEIGHBOR_ADVERT, cmd, false);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_inchain, APPEND_RULE, IPSET_DIM_ONE, 0, XTC_LABEL_DROP, NULL, NULL, global_data->vrrp_ipset_address6, IPPROTO_NONE, 0, cmd, false);

			h->updated_v6 = true;
		}

		if (global_data->vrrp_iptables_outchain) {
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, ND_NEIGHBOR_SOLICIT, cmd, false);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_ICMPV6, ND_NEIGHBOR_ADVERT, cmd, false);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_TWO, IPSET_DIM_ONE_SRC, XTC_LABEL_DROP, NULL, NULL, global_data->vrrp_ipset_address_iface6, IPPROTO_NONE, 0, cmd, false);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address6, IPPROTO_ICMPV6, ND_NEIGHBOR_SOLICIT, cmd, false);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_ACCEPT, NULL, NULL, global_data->vrrp_ipset_address6, IPPROTO_ICMPV6, ND_NEIGHBOR_ADVERT, cmd, false);
			ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_ONE, IPSET_DIM_ONE_SRC, XTC_LABEL_DROP, NULL, NULL, global_data->vrrp_ipset_address6, IPPROTO_NONE, 0, cmd, false);

			h->updated_v6 = true;
		}
	}
}

#ifdef _HAVE_VRRP_VMAC_
static void
add_del_igmp_rules(struct ipt_handle *h, int cmd, uint8_t family)
{
	if (!global_data->vrrp_iptables_outchain || !global_data->using_ipsets)
		return;

	if (family == AF_INET) {
		if (h->h4 || (h->h4 = ip4tables_open("filter"))) {
			ip4tables_add_rules(h->h4, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_TWO, 0, XTC_LABEL_DROP, NULL, NULL, global_data->vrrp_ipset_igmp, IPPROTO_IGMP, 0, cmd, false);
			h->updated_v4 = true;
		}

		return;
	}

	if (h->h6 || (h->h6 = ip6tables_open("filter"))) {
		ip6tables_add_rules(h->h6, global_data->vrrp_iptables_outchain, APPEND_RULE, IPSET_DIM_TWO, 0, XTC_LABEL_DROP, NULL, NULL, global_data->vrrp_ipset_mld, IPPROTO_ICMPV6, ICMPV6_MLD2_REPORT, cmd, false);
		h->updated_v6 = true;
	}
}
#endif
#endif

static struct ipt_handle*
iptables_open(int cmd)
{
	struct ipt_handle *h = MALLOC(sizeof(struct ipt_handle));

	h->cmd = cmd;

	return h;
}

static int
iptables_close(struct ipt_handle* h)
{
	int res = 0;

	/* We need to do the sets first in case we are adding sets, and then rules
	 * that reference them.
	 * If deleting sets, the rules must have been deleted prior to starting the
	 * ipset session, so we can't delete the rules and the sets at the same time.
	 */
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

static init_state_t
check_chains_exist(uint8_t family)
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

		if (global_data->vrrp_iptables_inchain &&
		    !ip4tables_is_chain(h4, global_data->vrrp_iptables_inchain)) {
			log_message(LOG_INFO, "iptables chain %s doesn't exist", global_data->vrrp_iptables_inchain);
			ret = INIT_FAILED;
		}
		if (global_data->vrrp_iptables_outchain &&
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

	if (global_data->vrrp_iptables_inchain &&
	    !ip6tables_is_chain(h6, global_data->vrrp_iptables_inchain)) {
		log_message(LOG_INFO, "ip6tables chain %s doesn't exist", global_data->vrrp_iptables_inchain);
		ret = INIT_FAILED;
	}
	if (global_data->vrrp_iptables_outchain &&
	    !ip6tables_is_chain(h6, global_data->vrrp_iptables_outchain)) {
		log_message(LOG_INFO, "ip6tables chain %s doesn't exist", global_data->vrrp_iptables_outchain);
		ret = INIT_FAILED;
	}

	ip6tables_close(h6, false);

	return ret;
}

static void
handle_iptable_rule_to_vip(ip_address_t *ipaddress, int cmd, struct ipt_handle *h, bool force)
{
	char *ifname = NULL;
	uint8_t family = ipaddress->ifa.ifa_family;

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

	if (family == AF_INET6 &&
	    IN6_IS_ADDR_LINKLOCAL(&ipaddress->u.sin6_addr))
		ifname = ipaddress->ifp->ifname;

	iptables_entry(h, family, global_data->vrrp_iptables_inchain, 0,
			XTC_LABEL_DROP, NULL, ipaddress, ifname, NULL,
			IPPROTO_NONE, 0, cmd, 0, force);

	if (global_data->vrrp_iptables_outchain)
		iptables_entry(h, family, global_data->vrrp_iptables_outchain, 0,
				XTC_LABEL_DROP, ipaddress, NULL, NULL, ifname,
				IPPROTO_NONE, 0, cmd, 0, force);

	if (family == AF_INET6 && global_data->vrrp_iptables_inchain) {
		if (global_data->vrrp_iptables_outchain) {
			iptables_entry(h, AF_INET6, global_data->vrrp_iptables_outchain, 0,
					XTC_LABEL_ACCEPT, ipaddress, NULL, NULL, ifname,
					IPPROTO_ICMPV6, ND_NEIGHBOR_SOLICIT, cmd, 0, force);
			iptables_entry(h, AF_INET6, global_data->vrrp_iptables_outchain, 1,
					XTC_LABEL_ACCEPT, ipaddress, NULL, NULL, ifname,
					IPPROTO_ICMPV6, ND_NEIGHBOR_ADVERT, cmd, 0, force);
		}

		iptables_entry(h, AF_INET6, global_data->vrrp_iptables_inchain, 0,
				XTC_LABEL_ACCEPT, NULL, ipaddress, ifname, NULL,
				IPPROTO_ICMPV6, ND_NEIGHBOR_SOLICIT, cmd, 0, force);
		iptables_entry(h, AF_INET6, global_data->vrrp_iptables_inchain, 1,
				XTC_LABEL_ACCEPT, NULL, ipaddress, ifname, NULL,
				IPPROTO_ICMPV6, ND_NEIGHBOR_ADVERT, cmd, 0, force);
	}

	ipaddress->iptable_rule_set = (cmd != IPADDRESS_DEL);
}

/* return true if a given file exists within procfs */
/* Taken from iptables code */
static bool
proc_file_exists(const char *filename)
{
	struct stat s;
	struct statfs f;

	if (lstat(filename, &s))
		return false;
	if (!S_ISREG(s.st_mode))
		return false;
	if (statfs(filename, &f))
		return false;
	if (f.f_type != PROC_SUPER_MAGIC)
		return false;

	return true;
}

static bool
iptables_init(int family)
{
	if (family == AF_INET) {
		if (!proc_file_exists("/proc/net/ip_tables_names"))
		{
			log_message(LOG_INFO, "iptables chain not setup");
			setup[family != AF_INET] = INIT_FAILED;
			return false;
		}
	} else {
		if (!proc_file_exists("/proc/net/ip6_tables_names"))
		{
			log_message(LOG_INFO, "ip6tables chain not setup");
			setup[family != AF_INET] = INIT_FAILED;
			return false;
		}
	}

#ifdef _LIBIPTC_DYNAMIC_
	if (!iptables_lib_init(family)) {
		setup[family != AF_INET] = INIT_FAILED;
		return false;
	}
#endif

#ifdef _HAVE_LIBIPSET_
	if (global_data->using_ipsets && !ipset_initialise())
		global_data->using_ipsets = false;
#endif

	setup[family != AF_INET] = check_chains_exist(family);

	return setup[family != AF_INET] == INIT_SUCCESS;
}

void
iptables_fini(void)
{
#ifdef _HAVE_LIBIPSET_
	uint8_t family;
	struct ipt_handle *h;

	if (!global_data->using_ipsets)
		return;

	h = iptables_open(IPADDRESS_DEL);
	family = AF_INET;
	do {
		if (vips_setup[family != AF_INET] == INIT_SUCCESS)
			add_del_vip_rules(h, IPADDRESS_DEL, family);
#ifdef _HAVE_VRRP_VMAC_
		if (igmp_setup[family != AF_INET] == INIT_SUCCESS)
			add_del_igmp_rules(h, IPADDRESS_DEL, family);
#endif

		family = family == AF_INET ? AF_INET6 : 0;
	} while (family);

	iptables_close(h);

	/* The sets must not be in use when the ipset session starts */
	h = iptables_open(IPADDRESS_DEL);
	family = AF_INET;
	do {
		if (vips_setup[family != AF_INET] == INIT_SUCCESS) {
			add_del_vip_sets(h, IPADDRESS_DEL, family);
			vips_setup[family != AF_INET] = NOT_INIT;
		}
#ifdef _HAVE_VRRP_VMAC_
		if (igmp_setup[family != AF_INET] == INIT_SUCCESS)
			add_del_igmp_sets(h, IPADDRESS_DEL, family);
		igmp_setup[family != AF_INET] = NOT_INIT;
#endif

		family = family == AF_INET ? AF_INET6 : 0;
		} while (family);

	iptables_close(h);
#endif
}

/* add/remove iptable drop rules to iplist */
static void
handle_iptable_vip_list(struct ipt_handle *h, list_head_t *ip_list, int cmd, bool force)
{
	ip_address_t *ipaddr;
	uint8_t family;

	list_for_each_entry(ipaddr, ip_list, e_list) {
		family = ipaddr->ifa.ifa_family;
		if (vips_setup[family != AF_INET] == NOT_INIT) {
			if (setup[family != AF_INET] == NOT_INIT)
				iptables_init(family);

			if (setup[family != AF_INET] == INIT_FAILED) {
				vips_setup[family != AF_INET] = INIT_FAILED;
				continue;
			}

#ifdef _HAVE_LIBIPSET_
			if (global_data->using_ipsets) {
				add_del_vip_sets(h, IPADDRESS_ADD, family);
				add_del_vip_rules(h, IPADDRESS_ADD, family);
			}
#endif

			vips_setup[family != AF_INET] = INIT_SUCCESS;
		}

		if (vips_setup[family != AF_INET] == INIT_FAILED)
			continue;

		if ((cmd == IPADDRESS_DEL) == ipaddr->iptable_rule_set || force)
			handle_iptable_rule_to_vip(ipaddr, cmd, h, force);
	}
}

void
handle_iptable_rule_to_iplist(list_head_t *ip_list1, list_head_t *ip_list2, int cmd, bool force)
{
	struct ipt_handle *h;
	int tries = 0;
	int res = 0;

	/* No addresses in this list */
	if ((!ip_list1 || list_empty(ip_list1)) &&
	    (!ip_list2 || list_empty(ip_list2)))
		return;

	do {
		h = iptables_open(cmd);

		if (ip_list1 && !list_empty(ip_list1))
			handle_iptable_vip_list(h, ip_list1, cmd, force);
		if (ip_list2 && !list_empty(ip_list2))
			handle_iptable_vip_list(h, ip_list2, cmd, force);

		res = iptables_close(h);
	} while (res == EAGAIN && ++tries < IPTABLES_MAX_TRIES);
}

void
handle_iptables_accept_mode(vrrp_t *vrrp, int cmd, bool force)
{
	handle_iptable_rule_to_iplist(&vrrp->vip, &vrrp->evip, cmd, force);
}

#ifdef _HAVE_VRRP_VMAC_
static void
handle_iptable_rule_for_igmp(const char *ifname, int cmd, int family, struct ipt_handle *h)
{
	if (!global_data->vrrp_iptables_outchain ||
	    igmp_setup[family != AF_INET] == INIT_FAILED)
		return;

	if (igmp_setup[family != AF_INET] == NOT_INIT) {
		if (setup[family != AF_INET] == NOT_INIT)
			iptables_init(family);

		if (setup[family != AF_INET] == INIT_FAILED) {
			igmp_setup[family != AF_INET] = INIT_FAILED;
			return;
		}

#ifdef _HAVE_LIBIPSET_
		if (global_data->using_ipsets) {
			add_del_igmp_sets(h, IPADDRESS_ADD, family);
			add_del_igmp_rules(h, IPADDRESS_ADD, family);
		}
#endif

		igmp_setup[family != AF_INET] = INIT_SUCCESS;
	}

#ifdef _HAVE_LIBIPSET_
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
			family == AF_INET ? IPPROTO_IGMP : IPPROTO_ICMPV6, family == AF_INET ? 0 : ICMPV6_MLD2_REPORT,
			cmd, 0, false);
}

static void
iptables_update_vmac(const interface_t *ifp, int family, bool other_family, int cmd)
{
	struct ipt_handle *h;
	int tries = 0;
	int res = 0;

	do {
		h = iptables_open(cmd);

		handle_iptable_rule_for_igmp(ifp->ifname, cmd, family, h);

		if (other_family)
			handle_iptable_rule_for_igmp(ifp->ifname, cmd, family == AF_INET ? AF_INET6 : AF_INET, h);
		res = iptables_close(h);
	} while (res == EAGAIN && ++tries < IPTABLES_MAX_TRIES);
}

void
iptables_add_vmac(const interface_t *ifp, int family, bool other_family)
{
	iptables_update_vmac(ifp, family, other_family, IPADDRESS_ADD);
}

void
iptables_remove_vmac(const interface_t *ifp, int family, bool other_family)
{
	iptables_update_vmac(ifp, family, other_family, IPADDRESS_DEL);
}
#endif
