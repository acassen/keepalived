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

/* global includes */
#include <sys/socket.h>
#include <linux/fib_rules.h>

/* local include */
#include "vrrp_ipaddress.h"
#include "vrrp_iprule.h"
#include "vrrp_netlink.h"
#include "vrrp_if.h"
#include "vrrp_data.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "rttables.h"

/* Utility functions */
static int
add_addr2req(struct nlmsghdr *n, int maxlen, int type, ip_address_t *ip_address)
{
	void *addr;
	int alen;

	if (!ip_address)
		return -1;

	addr = (IP_IS6(ip_address)) ? (void *) &ip_address->u.sin6_addr :
				     (void *) &ip_address->u.sin.sin_addr;
	alen = (IP_IS6(ip_address)) ? sizeof(ip_address->u.sin6_addr) :
				     sizeof(ip_address->u.sin.sin_addr);

	return addattr_l(n, maxlen, type, addr, alen);
}

/* Add/Delete IP rule to/from a specific IP/network */
static int
netlink_rule(ip_rule_t *iprule, int cmd)
{
	int status = 1;
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1024];
	} req;

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len    = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags  = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.n.nlmsg_type   = cmd ? RTM_NEWRULE : RTM_DELRULE;
	req.r.rtm_family   = IP_FAMILY(iprule->addr);
	if (iprule->table < 256)
		req.r.rtm_table = iprule->table ? iprule->table : RT_TABLE_MAIN;
	else {
		req.r.rtm_table = RT_TABLE_UNSPEC;
		addattr32(&req.n, sizeof(req), FRA_TABLE, iprule->table);
	}
	req.r.rtm_type     = RTN_UNSPEC;
	req.r.rtm_scope    = RT_SCOPE_UNIVERSE;
	req.r.rtm_flags    = 0;

	if (cmd) {
		req.r.rtm_protocol = RTPROT_BOOT;
		req.r.rtm_type     = RTN_UNICAST;
	}

	/* Set rule entry */
	if (iprule->dir == VRRP_RULE_FROM) {
		req.r.rtm_src_len = iprule->mask;
		add_addr2req(&req.n, sizeof(req), FRA_SRC, iprule->addr);
	} else if (iprule->dir == VRRP_RULE_TO) {
		req.r.rtm_dst_len = iprule->mask;
		add_addr2req(&req.n, sizeof(req), FRA_DST, iprule->addr);
	}

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
		    (cmd == IPRULE_DEL&& iprule->set)) {
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

	FREE_PTR(rule->addr);
	FREE(rule_data);
}
void
dump_iprule(void *rule_data)
{
	ip_rule_t *rule = rule_data;
	char *log_msg = MALLOC(1024);
	char *op = log_msg;

	if (rule->dir)
		op += snprintf(op, log_msg + 1024 - op, "%s ", (rule->dir == VRRP_RULE_FROM) ? "from" : "to");
	if (rule->addr)
		op += snprintf(op, log_msg + 1024 - op, "%s/%d", ipaddresstos(NULL, rule->addr), rule->mask);
	if (rule->table)
		op += snprintf(op, log_msg + 1024 - op, " table %d", rule->table);

	log_message(LOG_INFO, "     %s", log_msg);

	FREE(log_msg);
}
void
alloc_rule(list rule_list, vector_t *strvec)
{
	ip_rule_t *new;
	char *str;
	unsigned int i = 0;
	unsigned int table_id;

	new  = (ip_rule_t *) MALLOC(sizeof(ip_rule_t));

	/* FMT parse */
	while (i < vector_size(strvec)) {
		str = vector_slot(strvec, i);

		if (!strcmp(str, "from")) {
			new->dir  = VRRP_RULE_FROM;
			new->addr = parse_ipaddress(NULL, vector_slot(strvec, ++i),false);
			new->mask = new->addr->ifa.ifa_prefixlen;
		} else if (!strcmp(str, "to")) {
			new->dir  = VRRP_RULE_TO;
			new->addr = parse_ipaddress(NULL, vector_slot(strvec, ++i),false);
			new->mask = new->addr->ifa.ifa_prefixlen;
		} else if (!strcmp(str, "table")) {
			if (!find_rttables_table(vector_slot(strvec, ++i), &table_id))
				log_message(LOG_INFO, "Routing table %s not found for rule", FMT_STR_VSLOT(strvec, i));
			else
				new->table = table_id;
		}
		i++;
	}

	list_add(rule_list, new);
}

/* Try to find a rule in a list */
static int
rule_exist(list l, ip_rule_t *iprule)
{
	ip_rule_t *ipr;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		ipr = ELEMENT_DATA(e);
		if (RULE_ISEQ(ipr, iprule)) {
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
					    , ipaddresstos(NULL, iprule->addr), iprule->mask);
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
