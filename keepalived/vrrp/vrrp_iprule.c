/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK IPv4 rules manipulation.
 *
 * Author:      Chris Riley, <kernelchris@gmail.com>
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
 * Copyright (C) 2015 Chris Riley, <kernelchris@gmail.com>
 */

#include "config.h"

/* global includes */
#include <sys/socket.h>
#include <linux/fib_rules.h>
#include <inttypes.h>

/* local include */
#include "vrrp_ipaddress.h"
#include "vrrp_iproute.h"
#include "vrrp_iprule.h"
#include "vrrp_netlink.h"
#include "vrrp_if.h"
#include "vrrp_data.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "rttables.h"
#include "vrrp_ip_rule_route_parser.h"

/* Utility functions */
static inline bool
rule_is_equal(const ip_rule_t *x, const ip_rule_t *y)
{
	if (x->mask != y->mask ||
	    x->invert != y->invert ||
	    !IP_ISEQ(x->from_addr, y->from_addr) ||
	    !IP_ISEQ(x->to_addr, y->to_addr) ||
	    x->priority != y->priority ||
	    x->tos != y->tos ||
	    x->fwmark != y->fwmark ||
	    x->fwmask != y->fwmask ||
	    x->realms != y->realms ||
#if HAVE_DECL_FRA_SUPPRESS_PREFIXLEN
	    x->suppress_prefix_len != y->suppress_prefix_len ||
#endif
#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
	    x->suppress_group != y->suppress_group ||
#endif
#if HAVE_DECL_FRA_TUN_ID
	    x->tunnel_id != y->tunnel_id ||
#endif
	    !(x->iif) != !(y->iif) ||
	    !(x->oif) != !(y->oif) ||
	    x->goto_target != y->goto_target ||
	    x->table != y->table ||
	    x->action != y->action)
		return false;

	if (x->iif && x->iif->ifindex != y->iif->ifindex)
		return false;
	if (x->oif && x->oif->ifindex != y->oif->ifindex)
		return false;

	return true;
}

/* Add/Delete IP rule to/from a specific IP/network */
static int
netlink_rule(ip_rule_t *iprule, int cmd)
{
	int status = 1;
	struct {
		struct nlmsghdr n;
		struct fib_rule_hdr frh;
		char buf[1024];
	} req;

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;

	if (cmd != IPRULE_DEL) {
		req.n.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
		req.n.nlmsg_type = RTM_NEWRULE;
		req.frh.action = FR_ACT_UNSPEC;
	}
	else {
		req.frh.action = FR_ACT_UNSPEC;
		req.n.nlmsg_type = RTM_DELRULE;
	}
	req.frh.table = RT_TABLE_UNSPEC;
	req.frh.flags = 0;

	if (iprule->from_addr)
		req.frh.family = IP_FAMILY(iprule->from_addr);
	else if (iprule->to_addr)
		req.frh.family = IP_FAMILY(iprule->to_addr);
	else
		req.frh.family = AF_INET;

	if (iprule->action == FR_ACT_TO_TBL) {
		if (iprule->table < 256)	// "Table" or "lookup"
			req.frh.table = iprule->table ? iprule->table & 0xff : RT_TABLE_MAIN;
		else {
			req.frh.table = RT_TABLE_UNSPEC;
			addattr32(&req.n, sizeof(req), FRA_TABLE, iprule->table);
		}
	}

	if (iprule->invert)
		req.frh.flags |= FIB_RULE_INVERT;	// "not"

	/* Set rule entry */
	if (iprule->from_addr) {	// can be "default"/"any"/"all" - and to addr => bytelen == bitlen == 0
		add_addr2req(&req.n, sizeof(req), FRA_SRC, iprule->from_addr);
		req.frh.src_len = iprule->from_addr->ifa.ifa_prefixlen;
	}
	if (iprule->to_addr) {
		add_addr2req(&req.n, sizeof(req), FRA_DST, iprule->to_addr);
		req.frh.dst_len = iprule->to_addr->ifa.ifa_prefixlen;
	}

	if (iprule->mask & IPRULE_BIT_PRIORITY)	// "priority/order/preference"
		addattr32(&req.n, sizeof(req), FRA_PRIORITY, iprule->priority);

	if (iprule->mask & IPRULE_BIT_DSFIELD)	// "tos/dsfield"
		req.frh.tos = iprule->tos;	// Hex value - 0xnn <= 255, or name from rt_dsfield

	if (iprule->mask & IPRULE_BIT_FWMARK)	// "fwmark"
		addattr32(&req.n, sizeof(req), FRA_FWMARK, iprule->fwmark);

	if (iprule->mask & IPRULE_BIT_FWMASK)	// "fwmark number followed by /nn"
		addattr32(&req.n, sizeof(req), FRA_FWMASK, iprule->fwmask);

	if (iprule->realms)	// "realms u16[/u16] using rt_realms. after / is 16 msb (src), pre slash is 16 lsb (dest)"
		addattr32(&req.n, sizeof(req), FRA_FLOW, iprule->realms);

#if HAVE_DECL_FRA_SUPPRESS_PREFIXLEN
	if (iprule->mask & IPRULE_BIT_SUP_PREFIXLEN)	// "suppress_prefixlength" - only valid if table !=0
		addattr32(&req.n, sizeof(req), FRA_SUPPRESS_PREFIXLEN, iprule->suppress_prefix_len);
#endif

#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
	if (iprule->mask & IPRULE_BIT_SUP_GROUP)	// "suppress_ifgroup" or "sup_group" int32 - only valid if table !=0
		addattr32(&req.n, sizeof(req), FRA_SUPPRESS_IFGROUP, iprule->suppress_group);
#endif

	if (iprule->iif)	// "dev/iif"
		addattr_l(&req.n, sizeof(req), FRA_IFNAME, iprule->iif, strlen(iprule->iif->ifname)+1);

#if HAVE_DECL_FRA_OIFNAME
	if (iprule->oif)	// "oif"
		addattr_l(&req.n, sizeof(req), FRA_OIFNAME, iprule->oif, strlen(iprule->oif->ifname)+1);
#endif

#if HAVE_DECL_FRA_TUN_ID
	if (iprule->tunnel_id)
		addattr64(&req.n, sizeof(req), FRA_TUN_ID, htobe64(iprule->tunnel_id));
#endif
	if (iprule->action == FR_ACT_GOTO) {	// "goto"
		addattr32(&req.n, sizeof(req), FRA_GOTO, iprule->goto_target);
		req.frh.action = FR_ACT_GOTO;
	}

	req.frh.action = iprule->action;

	if (netlink_talk(&nl_cmd, &req.n) < 0)
		status = -1;

	return status;
}

void
netlink_rulelist(list rule_list, int cmd, bool force)
{
	ip_rule_t *iprule;
	element e;

	/* No rules to add */
	if (LIST_ISEMPTY(rule_list))
		return;

	/* If force is set, we try to remove all the rules, but the
	 * rule might not exist. That's not an error, so indicate not
	 * to report such a situation */
	if (force && cmd == IPRULE_DEL)
	         netlink_error_ignore = ENOENT;

	for (e = LIST_HEAD(rule_list); e; ELEMENT_NEXT(e)) {
		iprule = ELEMENT_DATA(e);
		if (force ||
		    (cmd == IPRULE_ADD && !iprule->set) ||
		    (cmd == IPRULE_DEL && iprule->set)) {
			if (netlink_rule(iprule, cmd) > 0)
				iprule->set = (cmd == IPRULE_ADD);
			else
				iprule->set = false;
		}
	}

	netlink_error_ignore = 0;
}

/* Rule dump/allocation */
void
free_iprule(void *rule_data)
{
	ip_rule_t *rule = rule_data;

	FREE_PTR(rule->from_addr);
	FREE_PTR(rule->to_addr);
	FREE(rule_data);
}

void
format_iprule(ip_rule_t *rule, char *buf, size_t buf_len)
{
	char *op = buf;
	char *buf_end = buf + buf_len;

	if (rule->invert)
		op += snprintf(op, (size_t)(buf_end - op), " not");

	if (rule->from_addr) {
		op += snprintf(op, (size_t)(buf_end - op), "from %s", ipaddresstos(NULL, rule->from_addr));
		if ((rule->from_addr->ifa.ifa_family == AF_INET && rule->from_addr->ifa.ifa_prefixlen != 32 ) ||
		    (rule->from_addr->ifa.ifa_family == AF_INET6 && rule->from_addr->ifa.ifa_prefixlen != 128 ))
			op += snprintf(op, (size_t)(buf_end - op), "/%d", rule->from_addr->ifa.ifa_prefixlen);
	}
	else
		op += snprintf(op, (size_t)(buf_end - op), "from all" );

	if (rule->to_addr) {
		op += snprintf(op, (size_t)(buf_end - op), " to %s", ipaddresstos(NULL, rule->to_addr));
		if ((rule->to_addr->ifa.ifa_family == AF_INET && rule->to_addr->ifa.ifa_prefixlen != 32 ) ||
		    (rule->to_addr->ifa.ifa_family == AF_INET6 && rule->to_addr->ifa.ifa_prefixlen != 128 ))
			op += snprintf(op, (size_t)(buf_end - op), "/%d", rule->to_addr->ifa.ifa_prefixlen);
	}

	if (rule->mask & IPRULE_BIT_PRIORITY)
		op += snprintf(op, (size_t)(buf_end - op), " priority %u", rule->priority);

	if (rule->mask & IPRULE_BIT_DSFIELD)
		op += snprintf(op, (size_t)(buf_end - op), " tos 0x%x", rule->tos);

	if (rule->mask & (IPRULE_BIT_FWMARK | IPRULE_BIT_FWMASK)) {
		op += snprintf(op, (size_t)(buf_end - op), " fwmark 0x%x", rule->fwmark);

		if (rule->mask & IPRULE_BIT_FWMASK && rule->fwmask != 0xffffffff)
			op += snprintf(op, (size_t)(buf_end - op), "/0x%x", rule->fwmask);
	}

	if (rule->iif)
#if HAVE_DECL_FRA_OIFNAME
		op += snprintf(op, (size_t)(buf_end - op), " iif %s", rule->iif->ifname);
#else
		op += snprintf(op, (size_t)(buf_end - op), " dev %s", rule->iif->ifname);
#endif

#if HAVE_DECL_FRA_OIFNAME
	if (rule->oif)
		op += snprintf(op, (size_t)(buf_end - op), " oif %s", rule->oif->ifname);
#endif

#if HAVE_DECL_FRA_SUPPRESS_PREFIXLEN
	if (rule->mask & IPRULE_BIT_SUP_PREFIXLEN)
		op += snprintf(op, (size_t)(buf_end - op), " suppress_prefixlen %u", rule->suppress_prefix_len);
#endif

#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
	if (rule->mask & IPRULE_BIT_SUP_GROUP)
		op += snprintf(op, (size_t)(buf_end - op), " suppress_ifgroup %d", rule->suppress_group);
#endif

#if HAVE_DECL_FRA_TUN_ID
	if (rule->tunnel_id)
		op += snprintf(op, (size_t)(buf_end - op), " tunnel-id %" PRIu64, rule->tunnel_id);
#endif

	if (rule->realms)
		op += snprintf(op, (size_t)(buf_end - op), " realms %d/%d", rule->realms >> 16, rule->realms & 0xffff);

	if (rule->action == FR_ACT_TO_TBL)
		op += snprintf(op, (size_t)(buf_end - op), " lookup %u", rule->table);
	else if (rule->action == FR_ACT_GOTO)
		op += snprintf(op, (size_t)(buf_end - op), " goto %u", rule->goto_target);
	else if (rule->action == FR_ACT_NOP)
		op += snprintf(op, (size_t)(buf_end - op), " nop");
	else
		op += snprintf(op, (size_t)(buf_end - op), " type %s", get_rttables_rtntype(rule->action));
}

void
dump_iprule(void *rule_data)
{
	ip_rule_t *rule = rule_data;
	char *buf = MALLOC(RULE_BUF_SIZE);

	format_iprule(rule, buf, RULE_BUF_SIZE);

	log_message(LOG_INFO, "     %s", buf);

	FREE(buf);
}

void
alloc_rule(list rule_list, vector_t *strvec)
{
	ip_rule_t *new;
	char *str;
	unsigned int i = 0;
	unsigned long val, val1;
	uint32_t uval32;
	uint8_t uval8;
	int family = AF_UNSPEC;
	interface_t *ifp;
	char *end;
	bool table_option = false;

	new = (ip_rule_t *)MALLOC(sizeof(ip_rule_t));
	if (!new) {
		log_message(LOG_INFO, "Unable to allocate new rule");
		goto err;
	}

	new->action = FR_ACT_UNSPEC;

	/* FMT parse */
	while (i < vector_size(strvec)) {
		str = strvec_slot(strvec, i);

		if (!strcmp(str, "from")) {
			if (new->from_addr)
				FREE(new->from_addr);
			new->from_addr = parse_ipaddress(NULL, strvec_slot(strvec, ++i), false);
			if (!new->from_addr) {
				log_message(LOG_INFO, "Invalid rule from address %s", FMT_STR_VSLOT(strvec, i));
				goto err;
			}
			if (family == AF_UNSPEC)
				family = new->from_addr->ifa.ifa_family;
			else if (new->from_addr->ifa.ifa_family != family)
			{
				log_message(LOG_INFO, "rule specification has mixed IPv4 and IPv6");
				goto err;
			}
		}
		else if (!strcmp(str, "to")) {
			if (new->to_addr)
				FREE(new->to_addr);
			new->to_addr = parse_ipaddress(NULL, strvec_slot(strvec, ++i), false);
			if (!new->to_addr) {
				log_message(LOG_INFO, "Invalid rule to address %s", FMT_STR_VSLOT(strvec, i));
				goto err;
			}
			if (family == AF_UNSPEC)
				family = new->to_addr->ifa.ifa_family;
			else if (new->to_addr->ifa.ifa_family != family)
			{
				log_message(LOG_INFO, "rule specification has mixed IPv4 and IPv6");
				goto err;
			}
		}
		else if (!strcmp(str, "table") ||
			 !strcmp(str, "lookup")) {
			if (!find_rttables_table(strvec_slot(strvec, ++i), &uval32)) {
				log_message(LOG_INFO, "Routing table %s not found for rule", FMT_STR_VSLOT(strvec, i));
				goto err;
			}
			if (uval32 == 0) {
				log_message(LOG_INFO, "Table 0 is not valid");
				goto err;
			}
			new->table = uval32;
			if (new->action != FR_ACT_UNSPEC) {
				log_message(LOG_INFO, "Cannot specify more than one of table/nop/goto/blackhole/prohibit/unreachable for rule");
				goto err;
			}
			new->action = FR_ACT_TO_TBL;
		}
		else if (!strcmp(str,"not"))
			new->invert = true;
		else if (!strcmp(str, "preference") ||
			 !strcmp(str, "order") ||
			 !strcmp(str, "priority")) {
			str = strvec_slot(strvec, ++i);
			val = strtoul(str, &end, 0);
			if (*end || val > UINT32_MAX) {
				log_message(LOG_INFO, "Invalid rule preference %s specified", str);
				goto err;
			}

			new->priority = (uint32_t)val;
			new->mask |= IPRULE_BIT_PRIORITY;
		}
		else if (!strcmp(str, "tos") || !strcmp(str, "dsfield")) {
			if (!find_rttables_dsfield(strvec_slot(strvec, ++i), &uval8)) {
				log_message(LOG_INFO, "TOS value %s is invalid", FMT_STR_VSLOT(strvec, i));
				goto err;
			}

			new->tos = uval8;
			new->mask |= IPRULE_BIT_DSFIELD;
		}
		else if (!strcmp(str, "fwmark")) {
			str = strvec_slot(strvec, ++i);
			if (str[0] == '-')
				goto fwmark_err;
			val = strtoul(str, &end, 0);
			if (val > UINT32_MAX)
				goto fwmark_err;

			if (*end == '/') {
				if (end[1] == '-')
					goto fwmark_err;
					
				val1 = strtoul(end+1, &end, 0);
				if (val1 > UINT32_MAX)
					goto fwmark_err;
				new->mask |= IPRULE_BIT_FWMASK;
			}
			else
				val1 = 0;

			if (*end)
				goto fwmark_err;

			new->fwmark = (uint32_t)val;
			new->fwmask = (uint32_t)val1;
			new->mask |= IPRULE_BIT_FWMARK;

			if (true) {
			} else {
fwmark_err:
				log_message(LOG_INFO, "Invalid rule fwmark %s specified", str);
				new->mask &= (uint32_t)~IPRULE_BIT_FWMASK;
				goto err;
			}
		}
		else if (!strcmp(str, "realms")) {
			str = strvec_slot(strvec, ++i);
			if (get_realms(&uval32, str)) {
				log_message(LOG_INFO, "invalid realms %s for rule", FMT_STR_VSLOT(strvec, i));
				goto err;
			}

			new->realms = uval32;
			table_option = true;
			if (family == AF_UNSPEC)
				family = AF_INET;
			else if (family != AF_INET) {
				log_message(LOG_INFO, "realms is only valid for IPv4");
				goto err;
			}
		}
#if HAVE_DECL_FRA_SUPPRESS_PREFIXLEN
		else if (!strcmp(str, "suppress_prefixlength") || !strcmp(str, "sup_pl")) {
			str = strvec_slot(strvec, ++i);
			val = strtoul(str, &end, 0);
			if (*end || val > INT32_MAX) {
				log_message(LOG_INFO, "Invalid suppress_prefixlength %s specified", str);
				goto err;
			}
			new->suppress_prefix_len = (uint32_t)val;
			new->mask |= IPRULE_BIT_SUP_PREFIXLEN;
			table_option = true;
		}
#endif
#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
		else if (!strcmp(str, "suppress_ifgroup") || !strcmp(str, "sup_group")) {
			if (!find_rttables_group(strvec_slot(strvec, ++i), &uval32)) {
				log_message(LOG_INFO, "suppress_group %s is invalid", FMT_STR_VSLOT(strvec, i));
				goto err;
			}
			new->suppress_group = uval32;
			new->mask |= IPRULE_BIT_SUP_GROUP;
			table_option = true;
		}
#endif
		else if (!strcmp(str, "dev") || !strcmp(str, "iif")) {
			str = strvec_slot(strvec, ++i);
			ifp = if_get_by_ifname(str);
			if (!ifp) {
				log_message(LOG_INFO, "Unknown interface %s for rule",  str);
				goto err;
			}
			new->iif = ifp;
		}
#if HAVE_DECL_FRA_OIFNAME
		else if (!strcmp(str, "oif")) {
			str = strvec_slot(strvec, ++i);
			ifp = if_get_by_ifname(str);
			if (!ifp) {
				log_message(LOG_INFO, "Unknown interface %s for rule",  str);
				goto err;
			}
			new->oif = ifp;
		}
#endif
#if HAVE_DECL_FRA_TUN_ID
		else if (!strcmp(str, "tunnel-id")) {
			uint64_t val64;
			val64 = strtoull(strvec_slot(strvec, ++i), &end, 0);
			if (*end) {
				log_message(LOG_INFO, "Invalid tunnel-id %s specified", str);
				goto err;
			}
			new->tunnel_id = val64;
		}
#endif
		else {
			uint8_t action = FR_ACT_UNSPEC;

			if (!strcmp(str, "type"))
				str = strvec_slot(strvec, ++i);

			if (!strcmp(str, "goto")) {
				val = strtoul(strvec_slot(strvec, ++i), &end, 0);
				if (*end || val > UINT32_MAX) {
					log_message(LOG_INFO, "Invalid target %s specified", str);
					goto err;
				}
				new->goto_target = (uint32_t)val;
				action = FR_ACT_GOTO;
			}
			else if (!strcmp(str, "nop")) {
				action = FR_ACT_NOP;
			}
			else if (find_rttables_rtntype(str, &action)) {
				if (action == RTN_BLACKHOLE)
					action = FR_ACT_BLACKHOLE;
				else if (action == RTN_UNREACHABLE)
					action = FR_ACT_UNREACHABLE;
				else if (action == RTN_PROHIBIT)
					action = FR_ACT_PROHIBIT;
				else {
					log_message(LOG_INFO, "Invalid rule action %s", str);
					goto err;
				}
			}
			else {
				log_message(LOG_INFO, "Unknown rule option %s", str);
				goto err;
			}
			if (new->action != FR_ACT_UNSPEC) {
				log_message(LOG_INFO, "Cannot specify more than one of table/nop/goto/blackhole/prohibit/unreachable for rule");
				goto err;
			}
			new->action = action;
		}
		i++;
	}

	if (new->action == FR_ACT_GOTO &&
	    new->mask & IPRULE_BIT_PRIORITY &&
	    new->priority >= new->goto_target)
	{
		log_message(LOG_INFO, "Invalid rule - preference %u >= goto target %u", new->priority, new->goto_target);
		goto err;
	}

	if (new->action == FR_ACT_UNSPEC) {
		log_message(LOG_INFO, "No action specified for rule - ignoring");
		goto err;
	}

	if (new->action != FR_ACT_TO_TBL && table_option) {
		log_message(LOG_INFO, "suppressor/realm specified for non table action - skipping");
		goto err;
	}

	list_add(rule_list, new);
	return;

err:
	FREE_PTR(new);
}

/* Try to find a rule in a list */
static int
rule_exist(list l, ip_rule_t *iprule)
{
	ip_rule_t *ipr;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		ipr = ELEMENT_DATA(e);
		if (rule_is_equal(ipr, iprule)) {
			ipr->set = iprule->set;
			return 1;
		}
	}
	return 0;
}

/* Clear diff rules */
void
clear_diff_rules(list l, list n)
{
	ip_rule_t *iprule;
	element e;

	/* No rule in previous conf */
	if (LIST_ISEMPTY(l))
		return;

	/* All Static rules removed */
	if (LIST_ISEMPTY(n)) {
		log_message(LOG_INFO, "Removing a VirtualRule block");
		netlink_rulelist(l, IPRULE_DEL, false);
		return;
	}

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		iprule = ELEMENT_DATA(e);
		if (!rule_exist(n, iprule) && iprule->set) {
			log_message(LOG_INFO, "ip rule %s/%d ... , no longer exist"
					    , ipaddresstos(NULL, iprule->from_addr), iprule->from_addr->ifa.ifa_prefixlen);
			netlink_rule(iprule, IPRULE_DEL);
		}
	}
}

/* Diff conf handler */
void
clear_diff_srules(void)
{
	clear_diff_rules(old_vrrp_data->static_rules, vrrp_data->static_rules);
}
