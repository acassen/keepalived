/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Dynamic data structure definition.
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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#include <syslog.h>
#include <unistd.h>
#include <pwd.h>
#include <netdb.h>
#include "global_data.h"
#include "memory.h"
#include "list.h"
#include "logger.h"
#include "utils.h"
#include "vrrp.h"

/* global vars */
data_t *global_data = NULL;

/* Default settings */
static void
set_default_router_id(data_t * data)
{
	char *new_id = NULL;

	new_id = get_local_name();
	if (!new_id || !new_id[0])
		return;

	data->router_id = new_id;
}

static void
set_default_email_from(data_t * data)
{
	struct passwd *pwd = NULL;
	char *hostname = NULL;
	int len = 0;

	hostname = get_local_name();
	if (!hostname || !hostname[0])
		return;

	pwd = getpwuid(getuid());
	if (!pwd)
		goto end;

	len = strlen(hostname) + strlen(pwd->pw_name) + 2;
	data->email_from = MALLOC(len);
	if (!data->email_from)
		goto end;

	snprintf(data->email_from, len, "%s@%s", pwd->pw_name, hostname);
  end:
	FREE(hostname);
}

static void
set_default_smtp_connection_timeout(data_t * data)
{
	data->smtp_connection_to = DEFAULT_SMTP_CONNECTION_TIMEOUT;
}

static void
set_default_mcast_group(data_t * data)
{
	inet_stosockaddr("224.0.0.18", 0, &data->vrrp_mcast_group4);
	inet_stosockaddr("ff02::12", 0, &data->vrrp_mcast_group6);
}

static void
set_vrrp_defaults(data_t * data)
{
	data->vrrp_garp_rep = VRRP_GARP_REP;
	data->vrrp_garp_refresh_rep = VRRP_GARP_REFRESH_REP;
	data->vrrp_garp_delay = VRRP_GARP_DELAY;
	data->vrrp_version = VRRP_VERSION_2;
	strcpy(data->vrrp_iptables_inchain, "INPUT");
	data->block_ipv4 = 0;
	data->block_ipv6 = 0;
#ifdef _HAVE_LIBIPSET_
	data->using_ipsets = 1;
	strcpy(data->vrrp_ipset_address, "keepalived");
	strcpy(data->vrrp_ipset_address6, "keepalived6");
	strcpy(data->vrrp_ipset_address_iface6, "keepalived_if6");
#endif
	data->vrrp_check_unicast_src = 0;
	data->vrrp_skip_check_adv_addr = 0;
	data->vrrp_strict = 0;
}

/* email facility functions */
static void
free_email(void *data)
{
	FREE(data);
}
static void
dump_email(void *data)
{
	char *addr = data;
	log_message(LOG_INFO, " Email notification = %s", addr);
}

void
alloc_email(char *addr)
{
	int size = strlen(addr);
	char *new;

	new = (char *) MALLOC(size + 1);
	memcpy(new, addr, size + 1);

	list_add(global_data->email, new);
}

/* data facility functions */
data_t *
alloc_global_data(void)
{
	data_t *new;

	new = (data_t *) MALLOC(sizeof(data_t));
	new->email = alloc_list(free_email, dump_email);

	set_default_mcast_group(new);
	set_vrrp_defaults(new);

	return new;
}

void
init_global_data(data_t * data)
{
	if (!data->router_id) {
		set_default_router_id(data);
	}

	if (data->smtp_server.ss_family) {
		if (!data->smtp_connection_to) {
			set_default_smtp_connection_timeout(data);
		}
		if (!data->email_from) {
			set_default_email_from(data);
		}
	}
}

void
free_global_data(data_t * data)
{
	free_list(data->email);
	FREE_PTR(data->router_id);
	FREE_PTR(data->email_from);
	FREE(data);
}

void
dump_global_data(data_t * data)
{
	if (!data)
		return;

	if (data->router_id ||
	    data->smtp_server.ss_family || data->smtp_connection_to || data->email_from) {
		log_message(LOG_INFO, "------< Global definitions >------");
	}
	if (data->router_id)
		log_message(LOG_INFO, " Router ID = %s", data->router_id);
	if (data->smtp_server.ss_family)
		log_message(LOG_INFO, " Smtp server = %s", inet_sockaddrtos(&data->smtp_server));
	if (data->smtp_connection_to)
		log_message(LOG_INFO, " Smtp server connection timeout = %lu"
				    , data->smtp_connection_to / TIMER_HZ);
	if (data->email_from) {
		log_message(LOG_INFO, " Email notification from = %s"
				    , data->email_from);
		dump_list(data->email);
	}
	if (data->vrrp_mcast_group4.ss_family) {
		log_message(LOG_INFO, " VRRP IPv4 mcast group = %s"
				    , inet_sockaddrtos(&data->vrrp_mcast_group4));
	}
	if (data->vrrp_mcast_group6.ss_family) {
		log_message(LOG_INFO, " VRRP IPv6 mcast group = %s"
				    , inet_sockaddrtos(&data->vrrp_mcast_group6));
	}
	if (data->vrrp_garp_delay)
		log_message(LOG_INFO, " Gratuitous ARP delay = %d",
		       data->vrrp_garp_delay/TIMER_HZ);
	if (!timer_isnull(data->vrrp_garp_refresh))
		log_message(LOG_INFO, " Gratuitous ARP refresh timer = %lu",
		       data->vrrp_garp_refresh.tv_sec);
	log_message(LOG_INFO, " Gratuitous ARP repeat = %d", data->vrrp_garp_rep);
	log_message(LOG_INFO, " Gratuitous ARP refresh repeat = %d", data->vrrp_garp_refresh_rep);
	log_message(LOG_INFO, " VRRP default protocol version = %d", data->vrrp_version);
	if (data->vrrp_iptables_inchain[0])
		log_message(LOG_INFO," Iptables input chain = %s", data->vrrp_iptables_inchain);
	if (data->vrrp_iptables_outchain[0])
		log_message(LOG_INFO," Iptables output chain = %s", data->vrrp_iptables_outchain);
#ifdef _HAVE_LIBIPSET_
	log_message(LOG_INFO, " Using ipsets = %d", data->using_ipsets);
	if (data->vrrp_ipset_address[0])
		log_message(LOG_INFO," ipset IPv4 address set = %s", data->vrrp_ipset_address);
	if (data->vrrp_ipset_address6[0])
		log_message(LOG_INFO," ipset IPv6 address set = %s", data->vrrp_ipset_address6);
	if (data->vrrp_ipset_address_iface6[0])
		log_message(LOG_INFO," ipset IPv6 address,iface set = %s", data->vrrp_ipset_address_iface6);
#endif

	log_message(LOG_INFO, " VRRP check unicast_src = %d", data->vrrp_check_unicast_src);
	log_message(LOG_INFO, " VRRP skip check advert addresses = %d", data->vrrp_skip_check_adv_addr);
	log_message(LOG_INFO, " VRRP strict mode = %d", data->vrrp_strict);
#ifdef _WITH_SNMP_
	if (data->enable_traps)
		log_message(LOG_INFO, " SNMP Trap enabled");
	else
		log_message(LOG_INFO, " SNMP Trap disabled");
#endif
}
