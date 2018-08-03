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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <unistd.h>
#include <pwd.h>

#include "global_data.h"
#include "list.h"
#include "logger.h"
#include "parser.h"
#include "utils.h"
#include "main.h"
#include "memory.h"
#ifdef _WITH_VRRP_
#include "vrrp.h"
#include "vrrp_ipaddress.h"
#endif
#if HAVE_DECL_RLIMIT_RTTIME == 1
#include "process.h"
#endif

/* global vars */
data_t *global_data = NULL;
data_t *old_global_data = NULL;

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
	inet_stosockaddr(INADDR_VRRP_GROUP, 0, (struct sockaddr_storage *)&data->vrrp_mcast_group4);
	inet_stosockaddr(INADDR6_VRRP_GROUP, 0, (struct sockaddr_storage *)&data->vrrp_mcast_group6);
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
	data->vrrp_higher_prio_send_advert = false;
	data->vrrp_version = VRRP_VERSION_2;
	strcpy(data->vrrp_iptables_inchain, "INPUT");
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
dump_email(FILE *fp, void *data)
{
	char *addr = data;
	conf_write(fp, " Email notification = %s", addr);
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

	if (global_data)
		return global_data;

	new = (data_t *) MALLOC(sizeof(data_t));
	new->email = alloc_list(free_email, dump_email);
	new->smtp_alert = -1;
#ifdef _WITH_VRRP_
	new->smtp_alert_vrrp = -1;
#endif
#ifdef _WITH_LVS_
	new->smtp_alert_checker = -1;
#endif

#ifdef _WITH_VRRP_
	set_default_mcast_group(new);
	set_vrrp_defaults(new);
#endif
	new->notify_fifo.fd = -1;
#ifdef _WITH_VRRP_
	new->vrrp_notify_fifo.fd = -1;
#if HAVE_DECL_RLIMIT_RTTIME == 1
	new->vrrp_rlimit_rt = RT_RLIMIT_DEFAULT;
#endif
	new->vrrp_rx_bufs_multiples = 3;
#endif
#ifdef _WITH_LVS_
	new->lvs_notify_fifo.fd = -1;
#if HAVE_DECL_RLIMIT_RTTIME == 1
	new->checker_rlimit_rt = RT_RLIMIT_DEFAULT;
#endif
#ifdef _WITH_BFD_
#if HAVE_DECL_RLIMIT_RTTIME == 1
	new->bfd_rlimit_rt = RT_RLIMIT_DEFAULT;
#endif
#endif
#endif

#ifdef _WITH_SNMP_
	if (snmp) {
#ifdef _WITH_SNMP_VRRP_
		new->enable_snmp_vrrp = true;
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
#ifdef _WITH_VRRP_
	new->lvs_syncd.syncid = PARAMETER_UNSET;
#ifdef _HAVE_IPVS_SYNCD_ATTRIBUTES_
	new->lvs_syncd.mcast_group.ss_family = AF_UNSPEC;
#endif
#endif
#endif

	return new;
}

void
init_global_data(data_t * data)
{
	char* local_name = NULL;
	char unknown_name[] = "[unknown]";
	bool using_unknown_name = false;

	if (!data->router_id ||
	    (data->smtp_server.ss_family &&
	     (!data->smtp_helo_name ||
	      !data->email_from))) {
		local_name = get_local_name();

		/* If for some reason get_local_name() fails, we need to have
		 * some string in local_name, otherwise keepalived can segfault */
		if (!local_name) {
			local_name = MALLOC(sizeof(unknown_name));
			strcpy(local_name, unknown_name);
			using_unknown_name = true;
		}
	}

	if (!data->router_id)
		set_default_router_id(data, local_name);

	if (data->smtp_server.ss_family) {
		if (!data->smtp_connection_to)
			set_default_smtp_connection_timeout(data);

		if (!using_unknown_name) {
			if (!data->email_from)
				set_default_email_from(data, local_name);

			if (!data->smtp_helo_name) {
				data->smtp_helo_name = local_name;
				local_name = NULL;	/* We have taken over the pointer */
			}
		}
	}

	/* Check that there aren't conflicts with the notify FIFOs */
#ifdef _WITH_VRRP_
	/* If the global and vrrp notify FIFOs are the same, then data will be
	 * duplicated on the FIFO */
	if (
#ifndef _DEBUG_
	    prog_type == PROG_TYPE_VRRP &&
#endif
	    data->notify_fifo.name && data->vrrp_notify_fifo.name &&
	    !strcmp(data->notify_fifo.name, data->vrrp_notify_fifo.name)) {
		log_message(LOG_INFO, "notify FIFO %s has been specified for global and vrrp FIFO - ignoring vrrp FIFO", data->vrrp_notify_fifo.name);
		FREE_PTR(data->vrrp_notify_fifo.name);
		data->vrrp_notify_fifo.name = NULL;
		free_notify_script(&data->vrrp_notify_fifo.script);
	}
#endif
#ifdef _WITH_LVS_
	/* If the global and LVS notify FIFOs are the same, then data will be
	 * duplicated on the FIFO */
#ifndef _DEBUG_
	if (prog_type == PROG_TYPE_CHECKER)
#endif
	{
		if (data->notify_fifo.name && data->lvs_notify_fifo.name &&
		    !strcmp(data->notify_fifo.name, data->lvs_notify_fifo.name)) {
			log_message(LOG_INFO, "notify FIFO %s has been specified for global and LVS FIFO - ignoring LVS FIFO", data->lvs_notify_fifo.name);
			FREE_PTR(data->lvs_notify_fifo.name);
			data->lvs_notify_fifo.name = NULL;
			free_notify_script(&data->lvs_notify_fifo.script);
		}

#ifdef _WITH_VRRP_
		/* If LVS and VRRP use the same FIFO, they cannot both have a script for the FIFO.
		 * Use the VRRP script and ignore the LVS script */
		if (data->lvs_notify_fifo.name && data->vrrp_notify_fifo.name &&
		    !strcmp(data->lvs_notify_fifo.name, data->vrrp_notify_fifo.name) &&
		    data->lvs_notify_fifo.script &&
		    data->vrrp_notify_fifo.script) {
			log_message(LOG_INFO, "LVS notify FIFO and vrrp FIFO are the same both with scripts - ignoring LVS FIFO script");
			free_notify_script(&data->lvs_notify_fifo.script);
		}

		/* If there is a script for global notify FIFO, it must only be run once, so let VRRP run it */
		if (data->notify_fifo.script)
			free_notify_script(&data->notify_fifo.script);
#endif
	}
#endif

	FREE_PTR(local_name);
}

void
free_global_data(data_t * data)
{
	if (!data)
		return;

	free_list(&data->email);
#if HAVE_DECL_CLONE_NEWNET
	FREE_PTR(data->network_namespace);
#endif
	FREE_PTR(data->instance_name);
	FREE_PTR(data->router_id);
	FREE_PTR(data->email_from);
	FREE_PTR(data->smtp_helo_name);
#ifdef _WITH_SNMP_
	FREE_PTR(data->snmp_socket);
#endif
#if defined _WITH_LVS_ && defined _WITH_VRRP_
	FREE_PTR(data->lvs_syncd.ifname);
	FREE_PTR(data->lvs_syncd.vrrp_name);
#endif
	FREE_PTR(data->notify_fifo.name);
	free_notify_script(&data->notify_fifo.script);
#ifdef _WITH_VRRP_
	FREE_PTR(data->default_ifname);
	FREE_PTR(data->vrrp_notify_fifo.name);
	free_notify_script(&data->vrrp_notify_fifo.script);
#endif
#ifdef _WITH_LVS_
	FREE_PTR(data->lvs_notify_fifo.name);
	free_notify_script(&data->lvs_notify_fifo.script);
#endif
	FREE(data);
}

void
dump_global_data(FILE *fp, data_t * data)
{
#ifdef _WITH_VRRP_
	char buf[64];
#endif

	if (!data)
		return;

	conf_write(fp, "------< Global definitions >------");

#if HAVE_DECL_CLONE_NEWNET
	conf_write(fp, " Network namespace = %s", data->network_namespace ? data->network_namespace : "(default)");
#endif
	if (data->instance_name)
		conf_write(fp, " Instance name = %s", data->instance_name);
	if (data->router_id)
		conf_write(fp, " Router ID = %s", data->router_id);
	if (data->smtp_server.ss_family) {
		conf_write(fp, " Smtp server = %s", inet_sockaddrtos(&data->smtp_server));
		conf_write(fp, " Smtp server port = %u", ntohs(inet_sockaddrport(&data->smtp_server)));
	}
	if (data->smtp_helo_name)
		conf_write(fp, " Smtp HELO name = %s" , data->smtp_helo_name);
	if (data->smtp_connection_to)
		conf_write(fp, " Smtp server connection timeout = %lu"
				    , data->smtp_connection_to / TIMER_HZ);
	if (data->email_from) {
		conf_write(fp, " Email notification from = %s"
				    , data->email_from);
		dump_list(fp, data->email);
	}
	conf_write(fp, " Default smtp_alert = %s",
			data->smtp_alert == -1 ? "unset" : data->smtp_alert ? "on" : "off");
#ifdef _WITH_VRRP_
	conf_write(fp, " Default smtp_alert_vrrp = %s",
			data->smtp_alert_vrrp == -1 ? "unset" : data->smtp_alert_vrrp ? "on" : "off");
#endif
#ifdef _WITH_LVS_
	conf_write(fp, " Default smtp_alert_checker = %s",
			data->smtp_alert_checker == -1 ? "unset" : data->smtp_alert_checker ? "on" : "off");
#endif
#ifdef _WITH_VRRP_
	conf_write(fp, " Dynamic interfaces = %s", data->dynamic_interfaces ? "true" : "false");
	if (data->no_email_faults)
		conf_write(fp, " Send emails for fault transitions = off");
#endif
#ifdef _WITH_LVS_
	if (data->lvs_tcp_timeout)
		conf_write(fp, " LVS TCP timeout = %d", data->lvs_tcp_timeout);
	if (data->lvs_tcpfin_timeout)
		conf_write(fp, " LVS TCP FIN timeout = %d", data->lvs_tcpfin_timeout);
	if (data->lvs_udp_timeout)
		conf_write(fp, " LVS TCP timeout = %d", data->lvs_udp_timeout);
#ifdef _WITH_VRRP_
#ifndef _DEBUG_
	if (prog_type == PROG_TYPE_VRRP)
#endif
		conf_write(fp, " Default interface = %s", data->default_ifp ? data->default_ifp->ifname : DFLT_INT);
	if (data->lvs_syncd.vrrp) {
		conf_write(fp, " LVS syncd vrrp instance = %s"
				    , data->lvs_syncd.vrrp->iname);
		if (data->lvs_syncd.ifname)
			conf_write(fp, " LVS syncd interface = %s"
				    , data->lvs_syncd.ifname);
		conf_write(fp, " LVS syncd syncid = %u"
				    , data->lvs_syncd.syncid);
#ifdef _HAVE_IPVS_SYNCD_ATTRIBUTES_
		if (data->lvs_syncd.sync_maxlen)
			conf_write(fp, " LVS syncd maxlen = %u", data->lvs_syncd.sync_maxlen);
		if (data->lvs_syncd.mcast_group.ss_family != AF_UNSPEC)
			conf_write(fp, " LVS mcast group %s", inet_sockaddrtos(&data->lvs_syncd.mcast_group));
		if (data->lvs_syncd.mcast_port)
			conf_write(fp, " LVS syncd mcast port = %d", data->lvs_syncd.mcast_port);
		if (data->lvs_syncd.mcast_ttl)
			conf_write(fp, " LVS syncd mcast ttl = %u", data->lvs_syncd.mcast_ttl);
#endif
	}
#endif
	conf_write(fp, " LVS flush = %s", data->lvs_flush ? "true" : "false");
#endif
	if (data->notify_fifo.name) {
		conf_write(fp, " Global notify fifo = %s", data->notify_fifo.name);
		if (data->notify_fifo.script)
			conf_write(fp, " Global notify fifo script = %s, uid:gid %d:%d",
				    cmd_str(data->notify_fifo.script),
				    data->notify_fifo.script->uid,
				    data->notify_fifo.script->gid);
	}
#ifdef _WITH_VRRP_
	if (data->vrrp_notify_fifo.name) {
		conf_write(fp, " VRRP notify fifo = %s", data->vrrp_notify_fifo.name);
		if (data->vrrp_notify_fifo.script)
			conf_write(fp, " VRRP notify fifo script = %s, uid:gid %d:%d",
				    cmd_str(data->vrrp_notify_fifo.script),
				    data->vrrp_notify_fifo.script->uid,
				    data->vrrp_notify_fifo.script->gid);
	}
#endif
#ifdef _WITH_LVS_
	if (data->lvs_notify_fifo.name) {
		conf_write(fp, " LVS notify fifo = %s", data->lvs_notify_fifo.name);
		if (data->lvs_notify_fifo.script)
			conf_write(fp, " LVS notify fifo script = %s, uid:gid %d:%d",
				    cmd_str(data->lvs_notify_fifo.script),
				    data->lvs_notify_fifo.script->uid,
				    data->lvs_notify_fifo.script->gid);
	}
#endif
#ifdef _WITH_VRRP_
	if (data->vrrp_mcast_group4.sin_family) {
		conf_write(fp, " VRRP IPv4 mcast group = %s"
				    , inet_sockaddrtos((struct sockaddr_storage *)&data->vrrp_mcast_group4));
	}
	if (data->vrrp_mcast_group6.sin6_family) {
		conf_write(fp, " VRRP IPv6 mcast group = %s"
				    , inet_sockaddrtos((struct sockaddr_storage *)&data->vrrp_mcast_group6));
	}
	conf_write(fp, " Gratuitous ARP delay = %u",
		       data->vrrp_garp_delay/TIMER_HZ);
	conf_write(fp, " Gratuitous ARP repeat = %u", data->vrrp_garp_rep);
	conf_write(fp, " Gratuitous ARP refresh timer = %lu",
		       data->vrrp_garp_refresh.tv_sec);
	conf_write(fp, " Gratuitous ARP refresh repeat = %d", data->vrrp_garp_refresh_rep);
	conf_write(fp, " Gratuitous ARP lower priority delay = %d", data->vrrp_garp_lower_prio_delay == PARAMETER_UNSET ? PARAMETER_UNSET : data->vrrp_garp_lower_prio_delay / TIMER_HZ);
	conf_write(fp, " Gratuitous ARP lower priority repeat = %d", data->vrrp_garp_lower_prio_rep);
	conf_write(fp, " Send advert after receive lower priority advert = %s", data->vrrp_lower_prio_no_advert ? "false" : "true");
	conf_write(fp, " Send advert after receive higher priority advert = %s", data->vrrp_higher_prio_send_advert ? "true" : "false");
	conf_write(fp, " Gratuitous ARP interval = %d", data->vrrp_garp_interval);
	conf_write(fp, " Gratuitous NA interval = %d", data->vrrp_gna_interval);
	conf_write(fp, " VRRP default protocol version = %d", data->vrrp_version);
	if (data->vrrp_iptables_inchain[0])
		conf_write(fp," Iptables input chain = %s", data->vrrp_iptables_inchain);
	if (data->vrrp_iptables_outchain[0])
		conf_write(fp," Iptables output chain = %s", data->vrrp_iptables_outchain);
#ifdef _HAVE_LIBIPSET_
	conf_write(fp, " Using ipsets = %s", data->using_ipsets ? "true" : "false");
	if (data->vrrp_ipset_address[0])
		conf_write(fp," ipset IPv4 address set = %s", data->vrrp_ipset_address);
	if (data->vrrp_ipset_address6[0])
		conf_write(fp," ipset IPv6 address set = %s", data->vrrp_ipset_address6);
	if (data->vrrp_ipset_address_iface6[0])
		conf_write(fp," ipset IPv6 address,iface set = %s", data->vrrp_ipset_address_iface6);
#endif

	conf_write(fp, " VRRP check unicast_src = %s", data->vrrp_check_unicast_src ? "true" : "false");
	conf_write(fp, " VRRP skip check advert addresses = %s", data->vrrp_skip_check_adv_addr ? "true" : "false");
	conf_write(fp, " VRRP strict mode = %s", data->vrrp_strict ? "true" : "false");
	conf_write(fp, " VRRP process priority = %d", data->vrrp_process_priority);
	conf_write(fp, " VRRP don't swap = %s", data->vrrp_no_swap ? "true" : "false");
#ifdef _HAVE_SCHED_RT_
	conf_write(fp, " VRRP realtime priority = %u", data->vrrp_realtime_priority);
#if HAVE_DECL_RLIMIT_RTTIME
	conf_write(fp, " VRRP realtime limit = %lu", data->vrrp_rlimit_rt);
#endif
#endif
#endif
#ifdef _WITH_LVS_
	conf_write(fp, " Checker process priority = %d", data->checker_process_priority);
	conf_write(fp, " Checker don't swap = %s", data->checker_no_swap ? "true" : "false");
#ifdef _HAVE_SCHED_RT_
	conf_write(fp, " Checker realtime priority = %u", data->checker_realtime_priority);
#if HAVE_DECL_RLIMIT_RTTIME
	conf_write(fp, " Checker realtime limit = %lu", data->checker_rlimit_rt);
#endif
#endif
#endif
#ifdef _WITH_BFD_
	conf_write(fp, " BFD process priority = %d", data->bfd_process_priority);
	conf_write(fp, " BFD don't swap = %s", data->bfd_no_swap ? "true" : "false");
#ifdef _HAVE_SCHED_RT_
	conf_write(fp, " BFD realtime priority = %u", data->bfd_realtime_priority);
#if HAVE_DECL_RLIMIT_RTTIME
	conf_write(fp, " BFD realtime limit = %lu", data->bfd_rlimit_rt);
#endif
#endif
#endif
#ifdef _WITH_SNMP_VRRP_
	conf_write(fp, " SNMP vrrp %s", data->enable_snmp_vrrp ? "enabled" : "disabled");
#endif
#ifdef _WITH_SNMP_CHECKER_
	conf_write(fp, " SNMP checker %s", data->enable_snmp_checker ? "enabled" : "disabled");
#endif
#ifdef _WITH_SNMP_RFCV2_
	conf_write(fp, " SNMP RFCv2 %s", data->enable_snmp_rfcv2 ? "enabled" : "disabled");
#endif
#ifdef _WITH_SNMP_RFCV3_
	conf_write(fp, " SNMP RFCv3 %s", data->enable_snmp_rfcv3 ? "enabled" : "disabled");
#endif
#ifdef _WITH_SNMP_
	conf_write(fp, " SNMP traps %s", data->enable_traps ? "enabled" : "disabled");
	conf_write(fp, " SNMP socket = %s", data->snmp_socket ? data->snmp_socket : "default (unix:/var/agentx/master)");
#endif
#ifdef _WITH_DBUS_
	conf_write(fp, " DBus %s", data->enable_dbus ? "enabled" : "disabled");
	conf_write(fp, " DBus service name = %s", data->dbus_service_name ? data->dbus_service_name : "");
#endif
	conf_write(fp, " Script security %s", script_security ? "enabled" : "disabled");
	conf_write(fp, " Default script uid:gid %d:%d", default_script_uid, default_script_gid);
#ifdef _WITH_VRRP_
	conf_write(fp, " vrrp_netlink_cmd_rcv_bufs = %u", global_data->vrrp_netlink_cmd_rcv_bufs);
	conf_write(fp, " vrrp_netlink_cmd_rcv_bufs_force = %u", global_data->vrrp_netlink_cmd_rcv_bufs_force);
	conf_write(fp, " vrrp_netlink_monitor_rcv_bufs = %u", global_data->vrrp_netlink_monitor_rcv_bufs);
	conf_write(fp, " vrrp_netlink_monitor_rcv_bufs_force = %u", global_data->vrrp_netlink_monitor_rcv_bufs_force);
#endif
#ifdef _WITH_LVS_
	conf_write(fp, " lvs_netlink_cmd_rcv_bufs = %u", global_data->lvs_netlink_cmd_rcv_bufs);
	conf_write(fp, " lvs_netlink_cmd_rcv_bufs_force = %u", global_data->lvs_netlink_cmd_rcv_bufs_force);
	conf_write(fp, " lvs_netlink_monitor_rcv_bufs = %u", global_data->lvs_netlink_monitor_rcv_bufs);
	conf_write(fp, " lvs_netlink_monitor_rcv_bufs_force = %u", global_data->lvs_netlink_monitor_rcv_bufs_force);
	conf_write(fp, " rs_init_notifies = %u", global_data->rs_init_notifies);
	conf_write(fp, " no_checker_emails = %u", global_data->no_checker_emails);
#endif
#ifdef _WITH_VRRP_
	buf[0] = '\0';
	if (global_data->vrrp_rx_bufs_policy & RX_BUFS_POLICY_MTU)
		strcpy(buf, " rx_bufs_policy = MTU");
	else if (global_data->vrrp_rx_bufs_policy & RX_BUFS_POLICY_ADVERT)
		strcpy(buf, " rx_bufs_policy = ADVERT");
	else if (global_data->vrrp_rx_bufs_policy & RX_BUFS_SIZE)
		sprintf(buf, " rx_bufs_size = %lu", global_data->vrrp_rx_bufs_size);
	if (buf[0])
		conf_write(fp, "%s", buf);
	conf_write(fp, " rx_bufs_multiples = %u", global_data->vrrp_rx_bufs_multiples);
#endif
}
