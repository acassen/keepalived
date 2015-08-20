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
plugin_handler(vector_t *strvec)
{
	global_data->plugin_dir = set_value(strvec);
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
	vector_t *email_vec = read_value_block();
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
#ifdef _WITH_SNMP_
static void
trap_handler(vector_t *strvec)
{
	global_data->enable_traps = 1;
}
#endif

void
global_init_keywords(void)
{
	/* global definitions mapping */
	install_keyword_root("linkbeat_use_polling", use_polling_handler);
	install_keyword_root("global_defs", NULL);
	install_keyword("router_id", &routerid_handler);
	install_keyword("plugin_dir", &plugin_handler);
	install_keyword("notification_email_from", &emailfrom_handler);
	install_keyword("smtp_server", &smtpserver_handler);
	install_keyword("smtp_connect_timeout", &smtpto_handler);
	install_keyword("notification_email", &email_handler);
	install_keyword("vrrp_mcast_group4", &vrrp_mcast_group4_handler);
	install_keyword("vrrp_mcast_group6", &vrrp_mcast_group6_handler);
#ifdef _WITH_SNMP_
	install_keyword("enable_traps", &trap_handler);
#endif
}
