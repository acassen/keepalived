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
vrrp_garp_refresh_handler(vector_t *strvec)
{
	global_data->vrrp_garp_refresh.tv_sec = atoi(vector_slot(strvec, 1));
}
static void
vrrp_garp_rep_handler(vector_t *strvec)
{
	global_data->vrrp_garp_rep = atoi(vector_slot(strvec, 1));
	if ( global_data->vrrp_garp_rep < 1 )
		global_data->vrrp_garp_rep = 1;
}
static void
vrrp_garp_refresh_rep_handler(vector_t *strvec)
{
	global_data->vrrp_garp_refresh_rep = atoi(vector_slot(strvec, 1));
	if ( global_data->vrrp_garp_refresh_rep < 1 )
		global_data->vrrp_garp_refresh_rep = 1;
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
		/* No second set specified, copy first name and add "_if" */
		strcpy(global_data->vrrp_ipset_address6, global_data->vrrp_ipset_address);
		if (strlen(global_data->vrrp_ipset_address6) < sizeof(global_data->vrrp_ipset_address6) - 2)
			strcat(global_data->vrrp_ipset_address6, "6");
		else
			strcpy(global_data->vrrp_ipset_address_iface6 + sizeof(global_data->vrrp_ipset_address_iface6) - 2, "6");

	}
	if (vector_size(strvec) >= 4) {
		if (strlen(vector_slot(strvec,3)) >= sizeof(global_data->vrrp_ipset_address_iface6)-1) {
			log_message(LOG_INFO, "VRRP Error : ipset IPv6 address_iface name too long - ignored");
			return;
		}
		strcpy(global_data->vrrp_ipset_address_iface6, vector_slot(strvec,3));
	}
	else {
		/* No third set specified, copy second name and add "_if" */
		strcpy(global_data->vrrp_ipset_address_iface6, global_data->vrrp_ipset_address6);
		len = strlen(global_data->vrrp_ipset_address_iface6);
		if (global_data->vrrp_ipset_address_iface6[len-1] == '6')
			global_data->vrrp_ipset_address_iface6[--len] = '\0';
		if (len < sizeof(global_data->vrrp_ipset_address_iface6) - 5)
			strcat(global_data->vrrp_ipset_address6, "_if6");
		else
			strcpy(global_data->vrrp_ipset_address6 + sizeof(global_data->vrrp_ipset_address6) - 5, "_if6");
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
	global_data->enable_snmp_rfc = true;
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
	install_keyword("router_id", &routerid_handler, true);
	install_keyword("notification_email_from", &emailfrom_handler, true);
	install_keyword("smtp_server", &smtpserver_handler, true);
	install_keyword("smtp_connect_timeout", &smtpto_handler, true);
	install_keyword("notification_email", &email_handler, true);
	install_keyword("vrrp_mcast_group4", &vrrp_mcast_group4_handler, true);
	install_keyword("vrrp_mcast_group6", &vrrp_mcast_group6_handler, true);
	install_keyword("vrrp_garp_master_delay", &vrrp_garp_delay_handler, true);
	install_keyword("vrrp_garp_master_repeat", &vrrp_garp_rep_handler, true);
	install_keyword("vrrp_garp_master_refresh", &vrrp_garp_refresh_handler, true);
	install_keyword("vrrp_garp_master_refresh_repeat", &vrrp_garp_refresh_rep_handler, true);
	install_keyword("vrrp_version", &vrrp_version_handler, true);
	install_keyword("vrrp_iptables", &vrrp_iptables_handler, true);
#ifdef _HAVE_LIBIPSET_
	install_keyword("vrrp_ipsets", &vrrp_ipsets_handler, true);
#endif
	install_keyword("vrrp_check_unicast_src", &vrrp_check_unicast_src_handler, true);
	install_keyword("vrrp_skip_check_adv_addr", &vrrp_check_adv_addr_handler, true);
	install_keyword("vrrp_strict", &vrrp_strict_handler, true);
#ifdef _WITH_SNMP_
	install_keyword("snmp_socket", &snmp_socket_handler, true);
	install_keyword("enable_traps", &trap_handler, true);
#ifdef _WITH_SNMP_KEEPALIVED_
	install_keyword("enable_snmp_keepalived", &snmp_keepalived_handler, true);
#endif
#ifdef _WITH_SNMP_RFC_
	install_keyword("enable_snmp_rfc", &snmp_rfc_handler, true);
#endif
#ifdef _WITH_SNMP_CHECKER_
	install_keyword("enable_snmp_checker", &snmp_checker_handler, true);
#endif
#endif
}
