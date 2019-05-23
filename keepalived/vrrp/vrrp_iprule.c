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
 * Copyright (C) 2016-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

/* global includes */
#include <errno.h>
#ifdef NETLINK_H_NEEDS_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <linux/fib_rules.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#if HAVE_DECL_FRA_IP_PROTO
#include <netdb.h>
#include <inttypes.h>
#endif
#include <ctype.h>

/* local include */
#include "vrrp_iproute.h"
#include "vrrp_iprule.h"
#include "keepalived_netlink.h"
#include "vrrp_data.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "rttables.h"
#include "vrrp_ip_rule_route_parser.h"
#include "parser.h"

/* Since we will be adding and deleting rules in potentially random
 * orders due to master/backup transitions, we therefore need to
 * pre-allocate priorities to ensure the rules are added in a consistent
 * sequence. Really the configuration should specify a priority for each
 * rule to ensure they are configured in the order the user wants. */
#define RULE_START_PRIORITY 16384
static unsigned next_rule_priority_ipv4 = RULE_START_PRIORITY;
static unsigned next_rule_priority_ipv6 = RULE_START_PRIORITY;

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
#if HAVE_DECL_FRA_UID_RANGE
	    x->uid_range.start != y->uid_range.start ||
	    x->uid_range.end != y->uid_range.end ||
#endif
#if HAVE_DECL_FRA_L3MDEV
	    x->l3mdev != y->l3mdev ||
#endif
	    x->iif != y->iif ||
#if HAVE_DECL_FRA_OIFNAME
	    x->oif != y->oif ||
#endif
#if HAVE_DECL_FRA_PROTOCOL
	    x->protocol != y->protocol ||
#endif
#if HAVE_DECL_FRA_IP_PROTO
	    x->ip_proto != y->ip_proto ||
#endif
#if HAVE_DECL_FRA_SPORT_RANGE
	    x->src_port.start != y->src_port.start ||
	    x->src_port.end != y->src_port.end ||
#endif
#if HAVE_DECL_FRA_DPORT_RANGE
	    x->dst_port.start != y->dst_port.start ||
	    x->dst_port.end != y->dst_port.end ||
#endif
	    x->goto_target != y->goto_target ||
	    x->table != y->table ||
	    x->action != y->action)
		return false;

	return true;
}

#if HAVE_DECL_FRA_IP_PROTO
static int
inet_proto_a2n(const char *buf)
{
	struct protoent *pe;
	unsigned long proto_num;
	char *endptr;

	/* Skip white space */
	buf += strspn(buf, WHITE_SPACE);

	if (!*buf || *buf == '-')
		return -1;

	proto_num = strtoul(buf, &endptr, 10);
	if (proto_num > INT8_MAX)
		return -1;
	if (!*endptr)
		return proto_num;

	pe = getprotobyname(buf);
	endprotoent();

	if (pe)
		return pe->p_proto;

	return -1;
}
#endif

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
	req.frh.tos = iprule->tos;	// Hex value - 0xnn <= 255, or name from rt_dsfield
	req.frh.family = iprule->family;

	if (iprule->action == FR_ACT_TO_TBL
#if HAVE_DECL_FRA_L3MDEV
	    && !iprule->l3mdev
#endif
					   ) {
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

	if (iprule->mask & IPRULE_BIT_FWMARK)	// "fwmark"
		addattr32(&req.n, sizeof(req), FRA_FWMARK, iprule->fwmark);

	if (iprule->mask & IPRULE_BIT_FWMASK)	// "fwmark number followed by /nn"
		addattr32(&req.n, sizeof(req), FRA_FWMASK, iprule->fwmask);

	if (iprule->realms)	// "realms u16[/u16] using rt_realms. after / is 16 msb (src), pre slash is 16 lsb (dest)"
		addattr32(&req.n, sizeof(req), FRA_FLOW, iprule->realms);

#if HAVE_DECL_FRA_SUPPRESS_PREFIXLEN
	if (iprule->suppress_prefix_len != -1)	// "suppress_prefixlength" - only valid if table != 0
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

#if HAVE_DECL_FRA_UID_RANGE
	if (iprule->mask & IPRULE_BIT_UID_RANGE)
		addattr_l(&req.n, sizeof(req), FRA_UID_RANGE, &iprule->uid_range, sizeof(iprule->uid_range));
#endif

#if HAVE_DECL_FRA_L3MDEV
	if (iprule->l3mdev)
		addattr8(&req.n, sizeof(req), FRA_L3MDEV, 1);
#endif

#if HAVE_DECL_FRA_PROTOCOL
	if (iprule->mask & IPRULE_BIT_PROTOCOL)
		addattr8(&req.n, sizeof(req), FRA_PROTOCOL, iprule->protocol);
#endif

#if HAVE_DECL_FRA_IP_PROTO
	if (iprule->mask & IPRULE_BIT_IP_PROTO)
		addattr8(&req.n, sizeof(req), FRA_IP_PROTO, iprule->ip_proto);
#endif

#if HAVE_DECL_FRA_SPORT_RANGE
	if (iprule->mask & IPRULE_BIT_SPORT_RANGE)
		addattr_l(&req.n, sizeof(req), FRA_SPORT_RANGE, &iprule->src_port, sizeof(iprule->src_port));
#endif

#if HAVE_DECL_FRA_DPORT_RANGE
	if (iprule->mask & IPRULE_BIT_DPORT_RANGE)
		addattr_l(&req.n, sizeof(req), FRA_DPORT_RANGE, &iprule->dst_port, sizeof(iprule->dst_port));
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
reinstate_static_rule(ip_rule_t *rule)
{
	char buf[256];

	rule->set = (netlink_rule(rule, IPRULE_ADD) > 0);

	format_iprule(rule, buf, sizeof(buf));
	log_message(LOG_INFO, "Restoring deleted static rule %s", buf);
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
format_iprule(const ip_rule_t *rule, char *buf, size_t buf_len)
{
	char *op = buf;
	char *buf_end = buf + buf_len;

	if (!rule->to_addr && !rule->from_addr && rule->family == AF_INET6)
		op += snprintf(op, (size_t)(buf_end - op), "inet6 ");

	if (rule->invert)
		op += snprintf(op, (size_t)(buf_end - op), "not ");

	if (rule->from_addr)
		op += snprintf(op, (size_t)(buf_end - op), "from %s", ipaddresstos(NULL, rule->from_addr));
	else
		op += snprintf(op, (size_t)(buf_end - op), "from all" );

	if (rule->to_addr)
		op += snprintf(op, (size_t)(buf_end - op), " to %s", ipaddresstos(NULL, rule->to_addr));

	if (rule->mask & IPRULE_BIT_PRIORITY)
		op += snprintf(op, (size_t)(buf_end - op), " priority %u", rule->priority);

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
	if (rule->suppress_prefix_len != -1)
		op += snprintf(op, (size_t)(buf_end - op), " suppress_prefixlen %" PRIi32, rule->suppress_prefix_len);
#endif

#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
	if (rule->mask & IPRULE_BIT_SUP_GROUP)
		op += snprintf(op, (size_t)(buf_end - op), " suppress_ifgroup %" PRIu32, rule->suppress_group);
#endif

#if HAVE_DECL_FRA_TUN_ID
	if (rule->tunnel_id)
		op += snprintf(op, (size_t)(buf_end - op), " tunnel-id %" PRIu64, rule->tunnel_id);
#endif

#if HAVE_DECL_FRA_UID_RANGE
	if (rule->mask & IPRULE_BIT_UID_RANGE)
		op += snprintf(op, (size_t)(buf_end - op), " uidrange %" PRIu32 "-%" PRIu32, rule->uid_range.start, rule->uid_range.end);
#endif

#if HAVE_DECL_FRA_L3MDEV
	if (rule->l3mdev)
		op += snprintf(op, (size_t)(buf_end - op), " l3mdev");
#endif

#if HAVE_DECL_FRA_PROTOCOL
	if (rule->mask & IPRULE_BIT_PROTOCOL)
		op += snprintf(op, (size_t)(buf_end - op), " protocol %u", rule->protocol);
#endif

#if HAVE_DECL_FRA_IP_PROTO
	if (rule->mask & IPRULE_BIT_IP_PROTO)
		op += snprintf(op, (size_t)(buf_end - op), " ipproto %u", rule->ip_proto);
#endif

#if HAVE_DECL_FRA_SPORT_RANGE
	if (rule->mask & IPRULE_BIT_SPORT_RANGE)
		op += snprintf(op, (size_t)(buf_end - op), " sport %hu-%hu", rule->src_port.start, rule->src_port.end);
#endif

#if HAVE_DECL_FRA_DPORT_RANGE
	if (rule->mask & IPRULE_BIT_DPORT_RANGE)
		op += snprintf(op, (size_t)(buf_end - op), " dport %hu-%hu", rule->dst_port.start, rule->dst_port.end);
#endif

	if (rule->realms)
		op += snprintf(op, (size_t)(buf_end - op), " realms %" PRIu32 "/%u", rule->realms >> 16, rule->realms & 0xffff);

	if (rule->action == FR_ACT_TO_TBL)
		op += snprintf(op, (size_t)(buf_end - op), " lookup %u", rule->table);
	else if (rule->action == FR_ACT_GOTO)
		op += snprintf(op, (size_t)(buf_end - op), " goto %u", rule->goto_target);
	else if (rule->action == FR_ACT_NOP)
		op += snprintf(op, (size_t)(buf_end - op), " nop");
	else
		op += snprintf(op, (size_t)(buf_end - op), " type %s", get_rttables_rtntype(rule->action));
	if (rule->dont_track)
		op += snprintf(op, (size_t)(buf_end - op), " no_track");
	if (rule->track_group)
		op += snprintf(op, (size_t)(buf_end - op), " track_group %s", rule->track_group->gname);
}

void
dump_iprule(FILE *fp, const void *rule_data)
{
	const ip_rule_t *rule = rule_data;
	char *buf = MALLOC(RULE_BUF_SIZE);

	format_iprule(rule, buf, RULE_BUF_SIZE);

	conf_write(fp, "     %s", buf);

	FREE(buf);
}

void
alloc_rule(list rule_list, const vector_t *strvec, __attribute__((unused)) bool allow_track_group)
{
	ip_rule_t *new;
	const char *str;
	unsigned int i = 0;
	unsigned long val, val1;
	unsigned val_unsigned;
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
#if HAVE_DECL_FRA_SUPPRESS_PREFIXLEN
	new->suppress_prefix_len = -1;
#endif

	/* FMT parse */
	while (i < vector_size(strvec)) {
		str = strvec_slot(strvec, i);

		/* Check if inet4/6 specified */
		if (!strcmp(str, "inet6")) {
			if (family == AF_UNSPEC)
				family = AF_INET6;
			else if (family != AF_INET6) {
				report_config_error(CONFIG_GENERAL_ERROR, "inet6 specified for IPv4 rule");
				goto err;
			}
			i++;
		}
		else if (!strcmp(str, "inet")) {
			if (family == AF_UNSPEC)
				family = AF_INET;
			else if (family != AF_INET) {
				report_config_error(CONFIG_GENERAL_ERROR, "inet specified for IPv6 rule");
				goto err;
			}
			i++;
		}
		else if (!strcmp(str, "from")) {
			if (new->from_addr)
				FREE(new->from_addr);
			new->from_addr = parse_route(strvec_slot(strvec, ++i));
			if (!new->from_addr) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid rule from address %s", strvec_slot(strvec, i));
				goto err;
			}
			if (family == AF_UNSPEC)
				family = new->from_addr->ifa.ifa_family;
			else if (new->from_addr->ifa.ifa_family != family)
			{
				report_config_error(CONFIG_GENERAL_ERROR, "rule specification has mixed IPv4 and IPv6");
				goto err;
			}
		}
		else if (!strcmp(str, "to")) {
			if (new->to_addr)
				FREE(new->to_addr);
			new->to_addr = parse_route(strvec_slot(strvec, ++i));
			if (!new->to_addr) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid rule to address %s", strvec_slot(strvec, i));
				goto err;
			}
			if (family == AF_UNSPEC)
				family = new->to_addr->ifa.ifa_family;
			else if (new->to_addr->ifa.ifa_family != family)
			{
				report_config_error(CONFIG_GENERAL_ERROR, "rule specification has mixed IPv4 and IPv6");
				goto err;
			}
		}
		else if (!strcmp(str, "table") ||
			 !strcmp(str, "lookup")) {
			if (!find_rttables_table(strvec_slot(strvec, ++i), &uval32)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Routing table %s not found for rule", strvec_slot(strvec, i));
				goto err;
			}
			if (uval32 == 0) {
				report_config_error(CONFIG_GENERAL_ERROR, "Table 0 is not valid");
				goto err;
			}
			new->table = uval32;
			if (new->action != FR_ACT_UNSPEC) {
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify more than one of table/nop/goto/blackhole/prohibit/unreachable for rule");
				goto err;
			}
			new->action = FR_ACT_TO_TBL;
		}
		else if (!strcmp(str,"not"))
			new->invert = true;
		else if (!strcmp(str, "preference") ||
			 !strcmp(str, "order") ||
			 !strcmp(str, "priority")) {
			if (!read_unsigned_base_strvec(strvec, ++i, 0, &val_unsigned, 0, UINT32_MAX, false)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid rule preference %s specified", str);
				goto err;
			}

			new->priority = (uint32_t)val_unsigned;
			new->mask |= IPRULE_BIT_PRIORITY;
		}
		else if (!strcmp(str, "tos") || !strcmp(str, "dsfield")) {
			if (!find_rttables_dsfield(strvec_slot(strvec, ++i), &uval8)) {
				report_config_error(CONFIG_GENERAL_ERROR, "TOS value %s is invalid", strvec_slot(strvec, i));
				goto err;
			}

			new->tos = uval8;
		}
		else if (!strcmp(str, "fwmark")) {
			str = strvec_slot(strvec, ++i);
			str += strspn(str, WHITE_SPACE);
			if (str[0] == '-')
				goto fwmark_err;
			val = strtoul(str, &end, 0);
			if (val > UINT32_MAX)
				goto fwmark_err;

			if (*end == '/') {
				if (isspace(end[1]) || end[1] == '-')
					goto fwmark_err;

				val1 = strtoul(end + 1, &end, 0);
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
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid rule fwmark %s specified", str);
				new->mask &= (uint32_t)~IPRULE_BIT_FWMASK;
				goto err;
			}
		}
		else if (!strcmp(str, "realms")) {
			str = strvec_slot(strvec, ++i);
			if (get_realms(&uval32, str)) {
				report_config_error(CONFIG_GENERAL_ERROR, "invalid realms %s for rule", strvec_slot(strvec, i));
				goto err;
			}

			new->realms = uval32;
			table_option = true;
			if (family == AF_UNSPEC)
				family = AF_INET;
			else if (family != AF_INET) {
				report_config_error(CONFIG_GENERAL_ERROR, "realms is only valid for IPv4");
				goto err;
			}
		}
#if HAVE_DECL_FRA_SUPPRESS_PREFIXLEN
		else if (!strcmp(str, "suppress_prefixlength") || !strcmp(str, "sup_pl")) {
			if (!read_unsigned_strvec(strvec, ++i, &val_unsigned, 0, INT32_MAX, false)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid suppress_prefixlength %s specified", str);
				goto err;
			}
			new->suppress_prefix_len = (int32_t)val_unsigned;
			table_option = true;
		}
#endif
#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
		else if (!strcmp(str, "suppress_ifgroup") || !strcmp(str, "sup_group")) {
			if (!find_rttables_group(strvec_slot(strvec, ++i), &uval32)) {
				report_config_error(CONFIG_GENERAL_ERROR, "suppress_group %s is invalid", strvec_slot(strvec, i));
				goto err;
			}
			new->suppress_group = uval32;
			new->mask |= IPRULE_BIT_SUP_GROUP;
			table_option = true;
		}
#endif
		else if (!strcmp(str, "dev") || !strcmp(str, "iif")) {
			str = strvec_slot(strvec, ++i);
			ifp = if_get_by_ifname(str, IF_CREATE_IF_DYNAMIC);
			if (!ifp) {
				report_config_error(CONFIG_GENERAL_ERROR, "WARNING - interface %s for rule doesn't exist",  str);
				goto err;
			}
			new->iif = ifp;
		}
#if HAVE_DECL_FRA_OIFNAME
		else if (!strcmp(str, "oif")) {
			str = strvec_slot(strvec, ++i);
			ifp = if_get_by_ifname(str, IF_CREATE_IF_DYNAMIC);
			if (!ifp) {
				report_config_error(CONFIG_GENERAL_ERROR, "WARNING - interface %s for rule doesn't exist",  str);
				goto err;
			}
			new->oif = ifp;
		}
#endif
#if HAVE_DECL_FRA_TUN_ID
		else if (!strcmp(str, "tunnel-id")) {
			uint64_t val64;
			if (!read_unsigned64_strvec(strvec, ++i, &val64, 0, UINT64_MAX, false)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid tunnel-id %s specified", str);
				goto err;
			}
			new->tunnel_id = val64;
		}
#endif
#if HAVE_DECL_FRA_UID_RANGE
		else if (!strcmp(str, "uidrange")) {
			uint32_t range_start, range_end;
			if (sscanf(strvec_slot(strvec, ++i), "%" PRIu32 "-%" PRIu32, &range_start, &range_end) != 2) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid uidrange %s specified", str);
				goto err;
			}
			new->mask |= IPRULE_BIT_UID_RANGE;
			new->uid_range.start = range_start;
			new->uid_range.end = range_end;
		}
#endif
#if HAVE_DECL_FRA_L3MDEV
		else if (!strcmp(str, "l3mdev")) {
			new->l3mdev = true;
			if (new->action != FR_ACT_UNSPEC) {
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify l3mdev with other action");
				goto err;
			}
			new->action = FR_ACT_TO_TBL;
		}
#endif
#if HAVE_DECL_FRA_PROTOCOL
		else if (!strcmp(str, "protocol")) {
			if (!read_unsigned_strvec(strvec, ++i, &val_unsigned, 0, UINT8_MAX, false))
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid protocol %s", strvec_slot(strvec, i));
			else {
				new->protocol = val_unsigned;
				new->mask |= IPRULE_BIT_PROTOCOL;
			}
		}
#endif
#if HAVE_DECL_FRA_IP_PROTO
		else if (!strcmp(str, "ipproto")) {
			int ip_proto = inet_proto_a2n(strvec_slot(strvec, ++i));
			if (ip_proto < 0 || ip_proto > UINT8_MAX)
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid ipproto %s", strvec_slot(strvec, i));
			else {
				new->ip_proto = ip_proto;
				new->mask |= IPRULE_BIT_IP_PROTO;
			}
		}
#endif
#if HAVE_DECL_FRA_SPORT_RANGE
		else if (!strcmp(str, "sport")) {
			struct fib_rule_port_range sport;
			int ret;

			ret = sscanf(strvec_slot(strvec, ++i), "%hu-%hu", &sport.start, &sport.end);
			if (ret == 1)
				sport.end = sport.start;
			if (ret != 2)
				report_config_error(CONFIG_GENERAL_ERROR, "invalid sport range %s", strvec_slot(strvec, i));
			else {
				new->src_port = sport;
				new->mask |= IPRULE_BIT_SPORT_RANGE;
			}
		}
#endif
#if HAVE_DECL_FRA_DPORT_RANGE
		else if (!strcmp(str, "dport")) {
			struct fib_rule_port_range dport;
			int ret;

			ret = sscanf(strvec_slot(strvec, ++i), "%hu-%hu", &dport.start, &dport.end);
			if (ret == 1)
				dport.end = dport.start;
			if (ret != 2)
				report_config_error(CONFIG_GENERAL_ERROR, "invalid dport range %s", strvec_slot(strvec, i));
			else {
				new->dst_port = dport;
				new->mask |= IPRULE_BIT_DPORT_RANGE;
			}
		}
#endif

		else if (!strcmp(str, "no_track"))
			new->dont_track = true;
#if HAVE_DECL_FRA_OIFNAME
		else if (allow_track_group && !strcmp(str, "track_group")) {
			i++;
			if (new->track_group) {
				report_config_error(CONFIG_GENERAL_ERROR, "track_group %s is a duplicate", strvec_slot(strvec, i));
				break;
			}
			if (!(new->track_group = find_track_group(strvec_slot(strvec, i))))
                                report_config_error(CONFIG_GENERAL_ERROR, "track_group %s not found", strvec_slot(strvec, i));
		}
#endif
		else {
			uint8_t action = FR_ACT_UNSPEC;

			if (!strcmp(str, "type"))
				str = strvec_slot(strvec, ++i);

			if (!strcmp(str, "goto")) {
				if (!read_unsigned_strvec(strvec, ++i, &val_unsigned, 0, UINT32_MAX, false)) {
					report_config_error(CONFIG_GENERAL_ERROR, "Invalid target %s specified", str);
					goto err;
				}
				new->goto_target = (uint32_t)val_unsigned;
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
					report_config_error(CONFIG_GENERAL_ERROR, "Invalid rule action %s", str);
					goto err;
				}
			}
			else {
				report_config_error(CONFIG_GENERAL_ERROR, "Unknown rule option %s", str);
				goto err;
			}
			if (new->action != FR_ACT_UNSPEC) {
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify more than one of table/nop/goto/blackhole/prohibit/unreachable/l3mdev for rule");
				goto err;
			}
			new->action = action;
		}
		i++;
	}

	if (new->action == FR_ACT_GOTO) {
		if (new->mask & IPRULE_BIT_PRIORITY) {
			if (new->priority >= new->goto_target) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid rule - preference %u >= goto target %u", new->priority, new->goto_target);
				goto err;
			}
		} else {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid rule - goto target %u specified without preference", new->goto_target);
			goto err;
		}
	}

	if (new->action == FR_ACT_UNSPEC) {
		report_config_error(CONFIG_GENERAL_ERROR, "No action specified for rule - ignoring");
		goto err;
	}

	if (new->action != FR_ACT_TO_TBL && table_option) {
		report_config_error(CONFIG_GENERAL_ERROR, "suppressor/realm specified for non table action - skipping");
		goto err;
	}

#if HAVE_DECL_FRA_L3MDEV
	if (new->table && new->l3mdev) {
		report_config_error(CONFIG_GENERAL_ERROR, "table cannot be specified for l3mdev rules");
		goto err;
	}
#endif

#if HAVE_DECL_FRA_PROTOCOL
	if (!new->dont_track) {
		if ((new->mask & IPRULE_BIT_PROTOCOL) && new->protocol != RTPROT_KEEPALIVED)
			report_config_error(CONFIG_GENERAL_ERROR, "Rule cannot be tracked if protocol is not RTPROT_KEEPALIVED(%d), resetting protocol", RTPROT_KEEPALIVED);
		new->protocol = RTPROT_KEEPALIVED;
		new->mask |= IPRULE_BIT_PROTOCOL;
	}
#endif

	if (new->track_group && !new->iif) {
		report_config_error(CONFIG_GENERAL_ERROR, "Static rule cannot have track_group if dev/iif not specified");
		new->track_group = NULL;
	}

	new->family = (family == AF_UNSPEC) ? AF_INET : family;
	if (new->to_addr && new->to_addr->ifa.ifa_family == AF_UNSPEC)
		new->to_addr->ifa.ifa_family = new->family;
	if (new->from_addr && new->from_addr->ifa.ifa_family == AF_UNSPEC)
		new->from_addr->ifa.ifa_family = new->family;

	if (!(new->mask & IPRULE_BIT_PRIORITY)) {
		new->priority = new->family == AF_INET ? next_rule_priority_ipv4-- : next_rule_priority_ipv6--;
		new->mask |= IPRULE_BIT_PRIORITY;
		report_config_error(CONFIG_GENERAL_ERROR, "Rule has no preference specified - setting to %u. This is probably not what you want.", new->priority);
	}

	list_add(rule_list, new);
	return;

err:
	FREE_PTR(new->to_addr);
	FREE_PTR(new->from_addr);
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

void
reset_next_rule_priority(void)
{
	next_rule_priority_ipv4 = RULE_START_PRIORITY;
	next_rule_priority_ipv6 = RULE_START_PRIORITY;
}
