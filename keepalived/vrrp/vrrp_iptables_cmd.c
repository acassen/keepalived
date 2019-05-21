/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        iptables manipulation by invoking iptables program.
 *		This does not use ipsets.
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

/* global includes */
#include <stdbool.h>

/* local includes */
#include "vrrp_iptables_cmd.h"
#include "logger.h"
#include "vrrp_ipaddress.h"
#include "global_data.h"
#ifdef _HAVE_LIBIPTC_
#include "vrrp_iptables_lib.h"
#endif
#include "vrrp_firewall.h"

#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
static bool iptables_cmd_available;
static bool ip6tables_cmd_available;
#endif

#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
static void
handle_iptable_rule_to_NA_cmd(ip_address_t *ipaddress, int cmd, bool force)
{
	const char *argv[14];
	int i = 0;
	int if_specifier = -1;
	int type_specifier ;
	const char *addr_str;

	if (global_data->vrrp_iptables_inchain[0] == '\0')
		return;

	addr_str = ipaddresstos(NULL, ipaddress);

	argv[i++] = "ip6tables";
	argv[i++] = cmd ? "-A" : "-D";
	argv[i++] = global_data->vrrp_iptables_inchain;
	argv[i++] = "-d";
	argv[i++] = addr_str;
	if (IN6_IS_ADDR_LINKLOCAL(&ipaddress->u.sin6_addr)) {
		if_specifier = i;
		argv[i++] = "-i";
		argv[i++] = ipaddress->ifp->ifname;
	}
	argv[i++] = "-p";
	argv[i++] = "icmpv6";
	argv[i++] = "--icmpv6-type";
	type_specifier = i;
	argv[i++] = "136";
	argv[i++] = "-j";
	argv[i++] = "ACCEPT";
	argv[i] = NULL;

	if (fork_exec(argv) < 0 && !force)
		log_message(LOG_ERR, "Failed to %s ip6table rule to accept NAs sent"
				     " to vip %s", (cmd) ? "set" : "remove", addr_str);

	argv[type_specifier] = "135";

	if (fork_exec(argv) < 0 && !force)
		log_message(LOG_ERR, "Failed to %s ip6table rule to accept NSs sent"
				     " to vip %s", (cmd) ? "set" : "remove", addr_str);

	if (global_data->vrrp_iptables_outchain[0] == '\0')
		return;

	argv[2] = global_data->vrrp_iptables_outchain;
	argv[3] = "-s";
	if (if_specifier >= 0)
		argv[if_specifier] = "-o";

	/* Allow NSs to be sent - this should only happen if the underlying interface
	   doesn't have an IPv6 address */
	if (fork_exec(argv) < 0 && !force)
		log_message(LOG_ERR, "Failed to %s ip6table rule to allow NSs to be"
				     " sent from vip %s", (cmd) ? "set" : "remove", addr_str);

	argv[type_specifier] = "136";

	/* Allow NAs to be sent in reply to an NS */
	if (fork_exec(argv) < 0 && !force)
		log_message(LOG_ERR, "Failed to %s ip6table rule to allow NAs to be"
				     " sent from vip %s", (cmd) ? "set" : "remove", addr_str);
}

/* add/remove iptable drop rule to VIP */
void
handle_iptable_rule_to_vip_cmd(ip_address_t *ipaddress, int cmd, bool force)
{
	const char *argv[10];
	int i = 0;
	int if_specifier = -1;
	const char *addr_str;
	const char *ifname = NULL;

	if (IP_IS6(ipaddress)) {
		if (!ip6tables_cmd_available)
			return;
	} else {
		if (!iptables_cmd_available)
			return;
	}

	if (IP_IS6(ipaddress)) {
		if (IN6_IS_ADDR_LINKLOCAL(&ipaddress->u.sin6_addr))
			ifname = ipaddress->ifp->ifname;
		handle_iptable_rule_to_NA_cmd(ipaddress, cmd, force);
		argv[i++] = "ip6tables";
	} else {
		argv[i++] = "iptables";
	}

	addr_str = ipaddresstos(NULL, ipaddress);

	argv[i++] = cmd ? "-A" : "-D";
	argv[i++] = global_data->vrrp_iptables_inchain;
	argv[i++] = "-d";
	argv[i++] = addr_str;
	if (ifname) {
		if_specifier = i;
		argv[i++] = "-i";
		argv[i++] = ifname;
	}
	argv[i++] = "-j";
	argv[i++] = "DROP";
	argv[i] = NULL;

	if (fork_exec(argv) < 0) {
		if (!force)
			log_message(LOG_ERR, "Failed to %s ip%stable drop rule"
					     " to vip %s", (cmd) ? "set" : "remove", IP_IS6(ipaddress) ? "6" : "", addr_str);
	}
	else
		ipaddress->iptable_rule_set = (cmd != IPADDRESS_DEL);

	if (global_data->vrrp_iptables_outchain[0] == '\0')
		return;

	argv[2] = global_data->vrrp_iptables_outchain ;
	argv[3] = "-s";
	if (if_specifier >= 0)
		argv[if_specifier] = "-o";

	if (fork_exec(argv) < 0 && !force)
		log_message(LOG_ERR, "Failed to %s ip%stable drop rule"
				     " from vip %s", (cmd) ? "set" : "remove", IP_IS6(ipaddress) ? "6" : "", addr_str);
}
#endif

void
check_chains_exist_cmd(void)
{
#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
	const char *argv[4];

	argv[1] = "-nL";
	argv[2] = global_data->vrrp_iptables_inchain;
	argv[3] = NULL;

	if (block_ipv4)
	{
#ifdef _LIBIPTC_DYNAMIC_
		if (!using_libip4tc)
#endif
		{
			argv[0] = "iptables";

			if (fork_exec(argv) < 0) {
				log_message(LOG_INFO, "iptables chain %s does not exist", global_data->vrrp_iptables_inchain);
				block_ipv4 = false;
			}
			else if (global_data->vrrp_iptables_outchain[0]) {
				argv[2] = global_data->vrrp_iptables_outchain;
				if (fork_exec(argv) < 0) {
					log_message(LOG_INFO, "iptables chain %s does not exist", global_data->vrrp_iptables_outchain);
					block_ipv4 = false;
				}
			}
		}
	}

	if (block_ipv6)
	{
#ifdef _LIBIPTC_DYNAMIC_
		if (!using_libip6tc)
#endif
		{
			argv[0] = "ip6tables";
			argv[2] = global_data->vrrp_iptables_inchain;

			if (fork_exec(argv) < 0) {
				log_message(LOG_INFO, "ip6tables chain %s does not exist", global_data->vrrp_iptables_inchain);
				block_ipv6 = false;
			}
			else if (global_data->vrrp_iptables_outchain[0]) {
				argv[2] = global_data->vrrp_iptables_outchain;
				if (fork_exec(argv) < 0) {
					log_message(LOG_INFO, "ip6tables chain %s does not exist", global_data->vrrp_iptables_outchain);
					block_ipv6 = false;
				}
			}
		}
	}
#endif
}

void
iptables_init_cmd(void)
{
#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
	const char *argv[3];

	/* If can't use libiptc, check iptables command available */
	argv[1] = "-V";
	argv[2] = NULL;

	if (block_ipv4
#ifdef _LIBIPTC_DYNAMIC_
		       && !using_libip4tc
#endif
				       )
	{
		argv[0] = "iptables";
		if (!(iptables_cmd_available = (fork_exec(argv) >= 0))) {
			log_message(LOG_INFO, "iptables command not available - can't filter IPv4 VIP address destinations");
			block_ipv4 = false;
		}
	}

	if (block_ipv6
#ifdef _LIBIPTC_DYNAMIC_
		       && !using_libip6tc
#endif
					 )
	{
		argv[0] = "ip6tables";
		if (!(ip6tables_cmd_available = (fork_exec(argv) >= 0))) {
			log_message(LOG_INFO, "ip6tables command not available - can't filter IPv6 VIP address destinations");
			block_ipv6 = false;
		}
	}
#endif
}
