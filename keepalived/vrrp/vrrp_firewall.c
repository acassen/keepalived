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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "vrrp_firewall.h"
#ifdef _WITH_IPTABLES_
#include "vrrp_iptables.h"
#endif
#ifdef _WITH_NFTABLES_
#include "vrrp_nftables.h"
#endif
#include "global_data.h"
#include "vrrp_ipaddress.h"
#include "utils.h"
#include "bitops.h"
#include "logger.h"

#if defined _WITH_IPTABLES_ && defined _WITH_NFTABLES_
static bool checked_iptables_nft;

static void
check_iptables_nft(void)
{
	FILE *fp;
	char buf[40];
	size_t len;
	char *res;

	/* Increasingly the iptables command is being provided as a front end to nftables. If so,
	 * then if we are built with nftables support, we should use nftables. */
	checked_iptables_nft = true;

	/* If using iptables is not configured, we don't need to do anything */
	if (!global_data->vrrp_iptables_inchain &&
	    !global_data->vrrp_iptables_outchain)
		return;

	fp = popen("iptables -V", "r");
	if (!fp) {
		/* No iptables command, so we need to use nftables */
		log_message(LOG_INFO, "Using nftables since no iptables command found - please update configuration");
	} else {
		res = fgets(buf, sizeof buf, fp);
		pclose(fp);

		if (!res) {
			if (__test_bit(LOG_DETAIL_BIT, &debug))
				log_message(LOG_INFO, "popen(\"iptables -V\" read failed - errno %d - %m", errno);
			return;
		}

		/* iptables will either have no type, or the type will be "nf_tables" or "legacy" */
		if ((len = strlen(buf)) && buf[len-1] == '\n')
			buf[--len] = '\0';

		if (len <= 10 || buf[len-1] != ')')
			return;

		/* If the type is not nf_tables, then iptables command is creating iptables configuration */
		if (strncmp(buf + len - 1 - 9, "nf_tables", 9))
			return;

#ifdef ALLOW_IPTABLES_LEGACY
		fp = popen("iptables-legacy -V", "r");
		fclose(fp);

		if (fp) {
			/* The iptables-legacy command exists, so can use iptables */
			return;
		}
#endif

		log_message(LOG_INFO, "Not using iptables since iptables uses nf_tables - please update configuration");
	}

	FREE_CONST_PTR(global_data->vrrp_iptables_inchain);
	FREE_CONST_PTR(global_data->vrrp_iptables_outchain);
#ifdef _HAVE_LIBISPET_
	if (global_data->using_ipsets)
		disable_ipsets();
#endif

	/* If nftables table name not set up, set it to default */
	if (!global_data->vrrp_nf_table_name)
		global_data->vrrp_nf_table_name = STRDUP(DEFAULT_NFTABLES_TABLE);
}
#endif

/* add/remove iptables/nftables drop rules */
void
firewall_handle_accept_mode(vrrp_t *vrrp, int cmd,
#ifndef _WITH_IPTABLES_
			    __attribute__((unused))
#endif
						    bool force)
{
#if defined _WITH_IPTABLES_ && defined _WITH_NFTABLES_
	if (!checked_iptables_nft)
		check_iptables_nft();
#endif

#ifdef _WITH_IPTABLES_
	if (global_data->vrrp_iptables_inchain)
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
firewall_remove_rule_to_iplist(list_head_t *l)
{
#ifdef _WITH_IPTABLES_
	if (global_data->vrrp_iptables_inchain)
		handle_iptable_rule_to_iplist(l, NULL, IPADDRESS_DEL, false);
#endif

#ifdef _WITH_NFTABLES_
	if (global_data->vrrp_nf_table_name)
		nft_remove_addresses_iplist(l);
#endif
}

#ifdef _HAVE_VRRP_VMAC_
void
firewall_add_vmac(const vrrp_t *vrrp)
{
#if defined _WITH_IPTABLES_ && defined _WITH_NFTABLES_
	if (!checked_iptables_nft)
		check_iptables_nft();
#endif

#ifdef _WITH_IPTABLES_
	if (global_data->vrrp_iptables_outchain)
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
	if (global_data->vrrp_iptables_outchain)
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
	if (global_data->vrrp_iptables_inchain ||
	    global_data->vrrp_iptables_outchain)
		iptables_fini();
#endif

#ifdef _WITH_NFTABLES_
	if (global_data->vrrp_nf_table_name)
		nft_end();
#endif
}
