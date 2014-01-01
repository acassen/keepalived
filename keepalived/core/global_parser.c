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
#include "logger.h"
#include "utils.h"

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
smtpip_handler(vector_t *strvec)
{
	inet_stosockaddr(vector_slot(strvec, 1), SMTP_PORT_STR, &global_data->smtp_server);
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
mcast_group4(vector_t *strvec)
{
	char *str = vector_slot(strvec, 1);
	struct in_addr tmp;
	if (inet_pton(AF_INET, str, &tmp) <= 0)
		log_message(LOG_ERR, "can not parse 'AF_INET:%s' to binary", str);
	else
		global_data->mcast_group4 = tmp;
}
static void
mcast_group6(vector_t *strvec)
{
	char *str = vector_slot(strvec, 1);
	struct in6_addr tmp;
	if (inet_pton(AF_INET6, str, &tmp) <= 0)
		log_message(LOG_ERR, "can not parse 'AF_INET6:%s' to binary", str);
	else
		global_data->mcast_group6 = tmp;
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
	install_keyword("smtp_server", &smtpip_handler);
	install_keyword("smtp_connect_timeout", &smtpto_handler);
	install_keyword("notification_email", &email_handler);
	install_keyword("mcast_group4", &mcast_group4);
	install_keyword("mcast_group6", &mcast_group6);
#ifdef _WITH_SNMP_
	install_keyword("enable_traps", &trap_handler);
#endif
}
