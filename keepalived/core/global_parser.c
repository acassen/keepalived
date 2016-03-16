/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Configuration file parser/reader. Place into the dynamic
 *              data structure representation the conf file representing
 *              the loadbalanced server pool.
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

#include <netdb.h>
#include "global_parser.h"
#include "global_data.h"
#include "check_data.h"
#include "parser.h"
#include "memory.h"
#include "smtp.h"
#include "utils.h"
#include "logger.h"

/* data handlers */
/* Global def handlers */
static void
use_polling_handler(vector_t *strvec)
{
	global_data->linkbeat_use_polling = 1;
}
static void
routerid_handler(vector_t *strvec)
{
	FREE_PTR(global_data->router_id);
	global_data->router_id = set_value(strvec);
}
static void
emailfrom_handler(vector_t *strvec)
{
	FREE_PTR(global_data->email_from);
	global_data->email_from = set_value(strvec);
}
static void
smtpto_handler(vector_t *strvec)
{
	global_data->smtp_connection_to = atoi(vector_slot(strvec, 1)) * TIMER_HZ;
}
static void
smtpserver_handler(vector_t *strvec)
{
	int ret;
	ret = inet_stosockaddr(vector_slot(strvec, 1), SMTP_PORT_STR, &global_data->smtp_server);
	if (ret < 0) {
		domain_stosockaddr(vector_slot(strvec, 1), SMTP_PORT_STR, &global_data->smtp_server);
	}
}
static void
smtphelo_handler(vector_t *strvec)
{
	char *helo_name;

	if (vector_size(strvec) < 2)
		return;

	helo_name = MALLOC(strlen(vector_slot(strvec, 1)) + 1);
	if (!helo_name)
		return;

	strcpy(helo_name, vector_slot(strvec, 1));
	global_data->smtp_helo_name = helo_name;
}
static void
email_handler(vector_t *strvec)
{
	vector_t *email_vec = read_value_block(strvec);
	int i;
	char *str;

	for (i = 0; i < vector_size(email_vec); i++) {
		str = vector_slot(email_vec, i);
		alloc_email(str);
	}

	free_strvec(email_vec);
}
static void
lvs_syncd_handler(vector_t *strvec)
{
	int syncid;

	if (global_data->lvs_syncd_if) {
		log_message(LOG_INFO, "lvs_sync_daemon has already been specified as %s %s - ignoring", global_data->lvs_syncd_if, global_data->lvs_syncd_vrrp_name);
		return;
	}

	if (vector_size(strvec) < 3 || vector_size(strvec) > 4) {
		log_message(LOG_INFO, "lvs_sync_daemon requires interface, VRRP instance and optional syncid");
		return;
	}

	global_data->lvs_syncd_if = set_value(strvec);

	global_data->lvs_syncd_vrrp_name = MALLOC(strlen(vector_slot(strvec, 2)) + 1);
	if (!global_data->lvs_syncd_vrrp_name)
		return;
	strcpy(global_data->lvs_syncd_vrrp_name, vector_slot(strvec, 2));
	if (vector_size(strvec) >= 4) {
		syncid = atoi(vector_slot(strvec,3));
		if (syncid < 0 || syncid > 255)
			log_message(LOG_INFO, "Invalid syncid - defaulting to vrid");
		else
			global_data->lvs_syncd_syncid = syncid;
	}
}
static void
vrrp_mcast_group4_handler(vector_t *strvec)
{
	struct sockaddr_storage *mcast = &global_data->vrrp_mcast_group4;
	int ret;

	ret = inet_stosockaddr(vector_slot(strvec, 1), 0, mcast);
	if (ret < 0) {
		log_message(LOG_ERR, "Configuration error: Cant parse vrrp_mcast_group4 [%s]. Skipping"
				   , FMT_STR_VSLOT(strvec, 1));
	}
}
static void
vrrp_mcast_group6_handler(vector_t *strvec)
{
	struct sockaddr_storage *mcast = &global_data->vrrp_mcast_group6;
	int ret;

	ret = inet_stosockaddr(vector_slot(strvec, 1), 0, mcast);
	if (ret < 0) {
		log_message(LOG_ERR, "Configuration error: Cant parse vrrp_mcast_group6 [%s]. Skipping"
				   , FMT_STR_VSLOT(strvec, 1));
	}
}
static void
vrrp_garp_delay_handler(vector_t *strvec)
{
	global_data->vrrp_garp_delay = atoi(vector_slot(strvec, 1)) * TIMER_HZ;
}
static void
vrrp_garp_rep_handler(vector_t *strvec)
{
	global_data->vrrp_garp_rep = atoi(vector_slot(strvec, 1));
	if (global_data->vrrp_garp_rep < 1)
		global_data->vrrp_garp_rep = 1;
}
static void
vrrp_garp_refresh_handler(vector_t *strvec)
{
	global_data->vrrp_garp_refresh.tv_sec = atoi(vector_slot(strvec, 1));
}
static void
vrrp_garp_refresh_rep_handler(vector_t *strvec)
{
	global_data->vrrp_garp_refresh_rep = atoi(vector_slot(strvec, 1));
	if (global_data->vrrp_garp_refresh_rep < 1)
		global_data->vrrp_garp_refresh_rep = 1;
}
static void
vrrp_garp_lower_prio_delay_handler(vector_t *strvec)
{
	global_data->vrrp_garp_lower_prio_delay = atoi(vector_slot(strvec, 1)) * TIMER_HZ;
}
static void
vrrp_garp_lower_prio_rep_handler(vector_t *strvec)
{
	global_data->vrrp_garp_lower_prio_rep = atoi(vector_slot(strvec, 1));
	/* Allow 0 GARP messages to be sent */
	if (global_data->vrrp_garp_lower_prio_rep < 0)
		global_data->vrrp_garp_lower_prio_rep = 0;
}
static void
vrrp_lower_prio_no_advert_handler(vector_t *strvec)
{
	int res;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(vector_slot(strvec,1));
		if (res < 0)
			log_message(LOG_INFO, "Invalid value for vrrp_lower_prio_no_advert specified");
		else
			global_data->vrrp_lower_prio_no_advert = res;
	}
	else
		global_data->vrrp_lower_prio_no_advert = true;
}
static void
vrrp_iptables_handler(vector_t *strvec)
{
	global_data->vrrp_iptables_inchain[0] = '\0';
	global_data->vrrp_iptables_outchain[0] = '\0';
	if (vector_size(strvec) >= 2) {
		if (strlen(vector_slot(strvec,1)) >= sizeof(global_data->vrrp_iptables_inchain)-1) {
			log_message(LOG_INFO, "VRRP Error : iptables in chain name too long - ignored");
			return;
		}
		strcpy(global_data->vrrp_iptables_inchain, vector_slot(strvec,1));
	}
	if (vector_size(strvec) >= 3) {
		if (strlen(vector_slot(strvec,2)) >= sizeof(global_data->vrrp_iptables_outchain)-1) {
			log_message(LOG_INFO, "VRRP Error : iptables out chain name too long - ignored");
			return;
		}
		strcpy(global_data->vrrp_iptables_outchain, vector_slot(strvec,2));
	}
}
#ifdef _HAVE_LIBIPSET_
static void
vrrp_ipsets_handler(vector_t *strvec)
{
	size_t len;

	if (vector_size(strvec) >= 2) {
		if (strlen(vector_slot(strvec,1)) >= sizeof(global_data->vrrp_ipset_address)-1) {
			log_message(LOG_INFO, "VRRP Error : ipset address name too long - ignored");
			return;
		}
		strcpy(global_data->vrrp_ipset_address, vector_slot(strvec,1));
	}
	else {
		global_data->using_ipsets = false;
		return;
	}

	if (vector_size(strvec) >= 3) {
		if (strlen(vector_slot(strvec,2)) >= sizeof(global_data->vrrp_ipset_address6)-1) {
			log_message(LOG_INFO, "VRRP Error : ipset IPv6 address name too long - ignored");
			return;
		}
		strcpy(global_data->vrrp_ipset_address6, vector_slot(strvec,2));
	}
	else {
		/* No second set specified, copy first name and add "6" */
		strcpy(global_data->vrrp_ipset_address6, global_data->vrrp_ipset_address);
		global_data->vrrp_ipset_address6[sizeof(global_data->vrrp_ipset_address6) - 2] = '\0';
		strcat(global_data->vrrp_ipset_address6, "6");
	}
	if (vector_size(strvec) >= 4) {
		if (strlen(vector_slot(strvec,3)) >= sizeof(global_data->vrrp_ipset_address_iface6)-1) {
			log_message(LOG_INFO, "VRRP Error : ipset IPv6 address_iface name too long - ignored");
			return;
		}
		strcpy(global_data->vrrp_ipset_address_iface6, vector_slot(strvec,3));
	}
	else {
		/* No third set specified, copy second name and add "_if6" */
		strcpy(global_data->vrrp_ipset_address_iface6, global_data->vrrp_ipset_address6);
		len = strlen(global_data->vrrp_ipset_address_iface6);
		if (global_data->vrrp_ipset_address_iface6[len-1] == '6')
			global_data->vrrp_ipset_address_iface6[--len] = '\0';
		global_data->vrrp_ipset_address_iface6[sizeof(global_data->vrrp_ipset_address_iface6) - 5] = '\0';
		strcat(global_data->vrrp_ipset_address_iface6, "_if6");
	}
}
#endif
static void
vrrp_version_handler(vector_t *strvec)
{
	uint8_t version = atoi(vector_slot(strvec, 1));
	if (VRRP_IS_BAD_VERSION(version)) {
		log_message(LOG_INFO, "VRRP Error : Version not valid !");
		log_message(LOG_INFO, "             must be between either 2 or 3. reconfigure !");
		return;
	}
	global_data->vrrp_version = version;
}
static void
vrrp_check_unicast_src_handler(vector_t *strvec)
{
	global_data->vrrp_check_unicast_src = 1;
}
static void
vrrp_check_adv_addr_handler(vector_t *strvec)
{
	global_data->vrrp_skip_check_adv_addr = 1;
}
static void
vrrp_strict_handler(vector_t *strvec)
{
	global_data->vrrp_strict = 1;
}
static void
vrrp_prio_handler(vector_t *strvec)
{
	int priority;

	if (vector_size(strvec) < 2) {
		log_message(LOG_INFO, "No vrrp process priority specified");
		return;
	}

	priority = atoi(vector_slot(strvec, 1));
	if (priority < -20 || priority > 19) {
		log_message(LOG_INFO, "Invalid vrrp process priority specified");
		return;
	}

	global_data->vrrp_process_priority = priority;
}
static void
checker_prio_handler(vector_t *strvec)
{
	int priority;

	if (vector_size(strvec) < 2) {
		log_message(LOG_INFO, "No checker process priority specified");
		return;
	}

	priority = atoi(vector_slot(strvec, 1));
	if (priority < -20 || priority > 19) {
		log_message(LOG_INFO, "Invalid checker process priority specified");
		return;
	}

	global_data->checker_process_priority = priority;
}
static void
vrrp_no_swap_handler(vector_t *strvec)
{
	global_data->vrrp_no_swap = true;
}
static void
checker_no_swap_handler(vector_t *strvec)
{
	global_data->checker_no_swap = true;
}
#ifdef _WITH_SNMP_
static void
snmp_socket_handler(vector_t *strvec)
{
	if (vector_size(strvec) > 2) {
		log_message(LOG_INFO, "Too many parameters specified for snmp_socket - ignoring");
		return;
	}

	if (vector_size(strvec) < 2) {
		log_message(LOG_INFO, "SNMP error : snmp socket name missing");
		return;
	}

	if (strlen(vector_slot(strvec,1)) > PATH_MAX - 1) {
		log_message(LOG_INFO, "SNMP error : snmp socket name too long - ignored");
		return;
	}

	if (global_data->snmp_socket) {
		log_message(LOG_INFO, "SNMP socket already set to %s - ignoring", global_data->snmp_socket);
		return;
	}

	global_data->snmp_socket = MALLOC(strlen(vector_slot(strvec, 1) + 1));
	strcpy(global_data->snmp_socket, vector_slot(strvec,1));
}
static void
trap_handler(vector_t *strvec)
{
	global_data->enable_traps = true;
}
#ifdef _WITH_SNMP_KEEPALIVED_
static void
snmp_keepalived_handler(vector_t *strvec)
{
	global_data->enable_snmp_keepalived = true;
}
#endif
#ifdef _WITH_SNMP_RFC_
static void
snmp_rfc_handler(vector_t *strvec)
{
	global_data->enable_snmp_rfcv2 = true;
	global_data->enable_snmp_rfcv3 = true;
}
#endif
#ifdef _WITH_SNMP_RFCV2_
static void
snmp_rfcv2_handler(vector_t *strvec)
{
	global_data->enable_snmp_rfcv2 = true;
}
#endif
#ifdef _WITH_SNMP_RFCV3_
static void
snmp_rfcv3_handler(vector_t *strvec)
{
	global_data->enable_snmp_rfcv3 = true;
}
#endif
#ifdef _WITH_SNMP_CHECKER_
static void
snmp_checker_handler(vector_t *strvec)
{
	global_data->enable_snmp_checker = true;
}
#endif
#endif

void
global_init_keywords(void)
{
	/* global definitions mapping */
	install_keyword_root("linkbeat_use_polling", use_polling_handler, true);
	install_keyword_root("global_defs", NULL, true);
	install_keyword("router_id", &routerid_handler);
	install_keyword("notification_email_from", &emailfrom_handler);
	install_keyword("smtp_server", &smtpserver_handler);
	install_keyword("smtp_helo_name", &smtphelo_handler);
	install_keyword("smtp_connect_timeout", &smtpto_handler);
	install_keyword("notification_email", &email_handler);
	install_keyword("lvs_sync_daemon", &lvs_syncd_handler);
	install_keyword("vrrp_mcast_group4", &vrrp_mcast_group4_handler);
	install_keyword("vrrp_mcast_group6", &vrrp_mcast_group6_handler);
	install_keyword("vrrp_garp_master_delay", &vrrp_garp_delay_handler);
	install_keyword("vrrp_garp_master_repeat", &vrrp_garp_rep_handler);
	install_keyword("vrrp_garp_master_refresh", &vrrp_garp_refresh_handler);
	install_keyword("vrrp_garp_master_refresh_repeat", &vrrp_garp_refresh_rep_handler);
	install_keyword("vrrp_garp_lower_prio_delay", &vrrp_garp_lower_prio_delay_handler);
	install_keyword("vrrp_garp_lower_prio_repeat", &vrrp_garp_lower_prio_rep_handler);
	install_keyword("vrrp_lower_prio_no_advert", &vrrp_lower_prio_no_advert_handler);
	install_keyword("vrrp_version", &vrrp_version_handler);
	install_keyword("vrrp_iptables", &vrrp_iptables_handler);
#ifdef _HAVE_LIBIPSET_
	install_keyword("vrrp_ipsets", &vrrp_ipsets_handler);
#endif
	install_keyword("vrrp_check_unicast_src", &vrrp_check_unicast_src_handler);
	install_keyword("vrrp_skip_check_adv_addr", &vrrp_check_adv_addr_handler);
	install_keyword("vrrp_strict", &vrrp_strict_handler);
	install_keyword("vrrp_priority", &vrrp_prio_handler);
	install_keyword("checker_priority", &checker_prio_handler);
	install_keyword("vrrp_no_swap", &vrrp_no_swap_handler);
	install_keyword("checker_no_swap", &checker_no_swap_handler);
#ifdef _WITH_SNMP_
	install_keyword("snmp_socket", &snmp_socket_handler);
	install_keyword("enable_traps", &trap_handler);
#ifdef _WITH_SNMP_KEEPALIVED_
	install_keyword("enable_snmp_keepalived", &snmp_keepalived_handler);
#endif
#ifdef _WITH_SNMP_RFC_
	install_keyword("enable_snmp_rfc", &snmp_rfc_handler);
#endif
#ifdef _WITH_SNMP_RFCV2_
	install_keyword("enable_snmp_rfcv2", &snmp_rfcv2_handler);
#endif
#ifdef _WITH_SNMP_RFCV3_
	install_keyword("enable_snmp_rfcv3", &snmp_rfcv3_handler);
#endif
#ifdef _WITH_SNMP_CHECKER_
	install_keyword("enable_snmp_checker", &snmp_checker_handler);
#endif
#endif
}
