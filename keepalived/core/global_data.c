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

#include "config.h"

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
#include "main.h"

/* global vars */
data_t *global_data = NULL;

/* Default settings */
static void
set_default_router_id(data_t *data, char *new_id)
{
	if (!new_id || !new_id[0])
		return;

	data->router_id = MALLOC(strlen(new_id)+1);
	strcpy(data->router_id, new_id);
}

static void
set_default_email_from(data_t * data, const char *hostname)
{
	struct passwd *pwd = NULL;
	size_t len;

	if (!hostname || !hostname[0])
		return;

	pwd = getpwuid(getuid());
	if (!pwd)
		return;

	len = strlen(hostname) + strlen(pwd->pw_name) + 2;
	data->email_from = MALLOC(len);
	if (!data->email_from)
		return;

	snprintf(data->email_from, len, "%s@%s", pwd->pw_name, hostname);
}

static void
set_default_smtp_connection_timeout(data_t * data)
{
	data->smtp_connection_to = DEFAULT_SMTP_CONNECTION_TIMEOUT;
}

#ifdef _WITH_VRRP_
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
	data->vrrp_garp_refresh.tv_sec = VRRP_GARP_REFRESH;
	data->vrrp_garp_refresh_rep = VRRP_GARP_REFRESH_REP;
	data->vrrp_garp_delay = VRRP_GARP_DELAY;
	data->vrrp_garp_lower_prio_delay = PARAMETER_UNSET;
	data->vrrp_garp_lower_prio_rep = PARAMETER_UNSET;
	data->vrrp_lower_prio_no_advert = false;
	data->vrrp_version = VRRP_VERSION_2;
	strcpy(data->vrrp_iptables_inchain, "INPUT");
	data->block_ipv4 = false;
	data->block_ipv6 = false;
#ifdef _HAVE_LIBIPSET_
	data->using_ipsets = true;
	strcpy(data->vrrp_ipset_address, "keepalived");
	strcpy(data->vrrp_ipset_address6, "keepalived6");
	strcpy(data->vrrp_ipset_address_iface6, "keepalived_if6");
#endif
	data->vrrp_check_unicast_src = false;
	data->vrrp_skip_check_adv_addr = false;
	data->vrrp_strict = false;
}
#endif

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
	size_t size = strlen(addr);
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

#ifdef _WITH_VRRP_
	set_default_mcast_group(new);
	set_vrrp_defaults(new);
#endif

#ifdef _WITH_SNMP_
	if (snmp) {
#ifdef _WITH_SNMP_KEEPALIVED_
		new->enable_snmp_keepalived = true;
#endif
#ifdef _WITH_SNMP_RFCV2_
		new->enable_snmp_rfcv2 = true;
#endif
#ifdef _WITH_SNMP_RFCV3_
		new->enable_snmp_rfcv3 = true;
#endif
#ifdef _WITH_SNMP_CHECKER_
		new->enable_snmp_checker = true;
#endif
	}

	if (snmp_socket) {
		new->snmp_socket = MALLOC(strlen(snmp_socket + 1));
		strcpy(new->snmp_socket, snmp_socket);
	}
#endif

#ifdef _WITH_LVS_
	new->lvs_syncd.syncid = PARAMETER_UNSET;
#ifdef _HAVE_IPVS_SYNCD_ATTRIBUTES_
	new->lvs_syncd.mcast_group.ss_family = AF_UNSPEC;
#endif
#endif

	return new;
}

void
init_global_data(data_t * data)
{
	char* local_name = NULL;

	if (!data->router_id ||
	    (data->smtp_server.ss_family &&
	     (!data->smtp_helo_name ||
	      !data->email_from)))
		local_name = get_local_name();

	if (!data->router_id)
		set_default_router_id(data, local_name);

	if (data->smtp_server.ss_family) {
		if (!data->smtp_connection_to)
			set_default_smtp_connection_timeout(data);

		if (local_name) {
			if (!data->email_from)
				set_default_email_from(data, local_name);

			if (!data->smtp_helo_name) {
				data->smtp_helo_name = local_name;
				local_name = NULL;	/* We have taken over the pointer */
			}
		}
	}

	FREE_PTR(local_name);
}

void
free_global_data(data_t * data)
{
	free_list(&data->email);
	FREE_PTR(data->router_id);
	FREE_PTR(data->email_from);
	FREE_PTR(data->smtp_helo_name);
#ifdef _WITH_SNMP_
	FREE_PTR(data->snmp_socket);
#endif
#ifdef _WITH_LVS_
	FREE_PTR(data->lvs_syncd.ifname);
	FREE_PTR(data->lvs_syncd.vrrp_name);
#endif
#if HAVE_DECL_CLONE_NEWNET
	if (!reload)
		FREE_PTR(network_namespace);
#endif
	FREE(data);
}

void
dump_global_data(data_t * data)
{
	if (!data)
		return;

	log_message(LOG_INFO, "------< Global definitions >------");

	if (data->router_id)
		log_message(LOG_INFO, " Router ID = %s", data->router_id);
	if (data->smtp_server.ss_family) {
		log_message(LOG_INFO, " Smtp server = %s", inet_sockaddrtos(&data->smtp_server));
		log_message(LOG_INFO, " Smtp server port = %u", inet_sockaddrport(&data->smtp_server));
	}
	if (data->smtp_helo_name)
		log_message(LOG_INFO, " Smtp HELO name = %s" , data->smtp_helo_name);
	if (data->smtp_connection_to)
		log_message(LOG_INFO, " Smtp server connection timeout = %lu"
				    , data->smtp_connection_to / TIMER_HZ);
	if (data->email_from) {
		log_message(LOG_INFO, " Email notification from = %s"
				    , data->email_from);
		dump_list(data->email);
	}
	log_message(LOG_INFO, " Default interface = %s", data->default_ifp ? data->default_ifp->ifname : DFLT_INT);
#ifdef _WITH_LVS_
	if (data->lvs_tcp_timeout)
		log_message(LOG_INFO, " LVS TCP timeout = %d", data->lvs_tcp_timeout);
	if (data->lvs_tcpfin_timeout)
		log_message(LOG_INFO, " LVS TCP FIN timeout = %d", data->lvs_tcpfin_timeout);
	if (data->lvs_udp_timeout)
		log_message(LOG_INFO, " LVS TCP timeout = %d", data->lvs_udp_timeout);
#ifdef _WITH_LVS_
	if (data->lvs_syncd.vrrp) {
		log_message(LOG_INFO, " LVS syncd vrrp instance = %s"
				    , data->lvs_syncd.vrrp->iname);
		if (data->lvs_syncd.ifname)
			log_message(LOG_INFO, " LVS syncd interface = %s"
				    , data->lvs_syncd.ifname);
		log_message(LOG_INFO, " LVS syncd syncid = %u"
				    , data->lvs_syncd.syncid);
#ifdef _HAVE_IPVS_SYNCD_ATTRIBUTES_
		if (data->lvs_syncd.sync_maxlen)
			log_message(LOG_INFO, " LVS syncd maxlen = %u", data->lvs_syncd.sync_maxlen);
		if (data->lvs_syncd.mcast_group.ss_family != AF_UNSPEC)
			log_message(LOG_INFO, " LVS mcast group %s", inet_sockaddrtos(&data->lvs_syncd.mcast_group));
		if (data->lvs_syncd.mcast_port)
			log_message(LOG_INFO, " LVS syncd mcast port = %d", data->lvs_syncd.mcast_port);
		if (data->lvs_syncd.mcast_ttl)
			log_message(LOG_INFO, " LVS syncd mcast ttl = %u", data->lvs_syncd.mcast_ttl);
#endif
	}
#endif
	log_message(LOG_INFO, " LVS flush = %s", data->lvs_flush ? "true" : "false");
#endif
#ifdef _WITH_VRRP_
	if (data->vrrp_mcast_group4.ss_family) {
		log_message(LOG_INFO, " VRRP IPv4 mcast group = %s"
				    , inet_sockaddrtos(&data->vrrp_mcast_group4));
	}
	if (data->vrrp_mcast_group6.ss_family) {
		log_message(LOG_INFO, " VRRP IPv6 mcast group = %s"
				    , inet_sockaddrtos(&data->vrrp_mcast_group6));
	}
	log_message(LOG_INFO, " Gratuitous ARP delay = %u",
		       data->vrrp_garp_delay/TIMER_HZ);
	log_message(LOG_INFO, " Gratuitous ARP repeat = %u", data->vrrp_garp_rep);
	log_message(LOG_INFO, " Gratuitous ARP refresh timer = %lu",
		       data->vrrp_garp_refresh.tv_sec);
	log_message(LOG_INFO, " Gratuitous ARP refresh repeat = %d", data->vrrp_garp_refresh_rep);
	log_message(LOG_INFO, " Gratuitous ARP lower priority delay = %d", data->vrrp_garp_lower_prio_delay / TIMER_HZ);
	log_message(LOG_INFO, " Gratuitous ARP lower priority repeat = %d", data->vrrp_garp_lower_prio_rep);
	log_message(LOG_INFO, " Send advert after receive lower priority advert = %s", data->vrrp_lower_prio_no_advert ? "false" : "true");
	log_message(LOG_INFO, " Gratuitous ARP interval = %d", data->vrrp_garp_interval);
	log_message(LOG_INFO, " Gratuitous NA interval = %d", data->vrrp_gna_interval);
	log_message(LOG_INFO, " VRRP default protocol version = %d", data->vrrp_version);
	if (data->vrrp_iptables_inchain[0])
		log_message(LOG_INFO," Iptables input chain = %s", data->vrrp_iptables_inchain);
	if (data->vrrp_iptables_outchain[0])
		log_message(LOG_INFO," Iptables output chain = %s", data->vrrp_iptables_outchain);
#ifdef _HAVE_LIBIPSET_
	log_message(LOG_INFO, " Using ipsets = %s", data->using_ipsets ? "true" : "false");
	if (data->vrrp_ipset_address[0])
		log_message(LOG_INFO," ipset IPv4 address set = %s", data->vrrp_ipset_address);
	if (data->vrrp_ipset_address6[0])
		log_message(LOG_INFO," ipset IPv6 address set = %s", data->vrrp_ipset_address6);
	if (data->vrrp_ipset_address_iface6[0])
		log_message(LOG_INFO," ipset IPv6 address,iface set = %s", data->vrrp_ipset_address_iface6);
#endif

	log_message(LOG_INFO, " VRRP check unicast_src = %s", data->vrrp_check_unicast_src ? "true" : "false");
	log_message(LOG_INFO, " VRRP skip check advert addresses = %s", data->vrrp_skip_check_adv_addr ? "true" : "false");
	log_message(LOG_INFO, " VRRP strict mode = %s", data->vrrp_strict ? "true" : "false");
	log_message(LOG_INFO, " VRRP process priority = %d", data->vrrp_process_priority);
	log_message(LOG_INFO, " VRRP don't swap = %s", data->vrrp_no_swap ? "true" : "false");
#endif
#ifdef _WITH_LVS_
	log_message(LOG_INFO, " Checker process priority = %d", data->checker_process_priority);
	log_message(LOG_INFO, " Checker don't swap = %s", data->checker_no_swap ? "true" : "false");
#endif
#ifdef _WITH_SNMP_KEEPALIVED_
	log_message(LOG_INFO, " SNMP keepalived %s", data->enable_snmp_keepalived ? "enabled" : "disabled");
#endif
#ifdef _WITH_SNMP_CHECKER_
	log_message(LOG_INFO, " SNMP checker %s", data->enable_snmp_checker ? "enabled" : "disabled");
#endif
#ifdef _WITH_SNMP_RFCV2_
	log_message(LOG_INFO, " SNMP RFCv2 %s", data->enable_snmp_rfcv2 ? "enabled" : "disabled");
#endif
#ifdef _WITH_SNMP_RFCV3_
	log_message(LOG_INFO, " SNMP RFCv3 %s", data->enable_snmp_rfcv3 ? "enabled" : "disabled");
#endif
#ifdef _WITH_SNMP_
	log_message(LOG_INFO, " SNMP traps %s", data->enable_traps ? "enabled" : "disabled");
	log_message(LOG_INFO, " SNMP socket = %s", data->snmp_socket ? data->snmp_socket : "default (unix:/var/agentx/master)");
#endif
#if HAVE_DECL_CLONE_NEWNET
	log_message(LOG_INFO, " Network namespace = %s", network_namespace ? network_namespace : "(default)");
#endif
#ifdef _WITH_DBUS_
	log_message(LOG_INFO, " DBus %s", data->enable_dbus ? "enabled" : "disabled");
#endif
	log_message(LOG_INFO, " Script security %s", data->script_security ? "enabled" : "disabled");
	log_message(LOG_INFO, " Default script uid:gid %d:%d", default_script_uid, default_script_gid);
}
