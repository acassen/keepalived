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
	FREE_PTR(data->plugin_dir);
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
	if (data->plugin_dir)
		log_message(LOG_INFO, " Plugin dir = %s", data->plugin_dir);
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
#ifdef _WITH_SNMP_
	if (data->enable_traps)
		log_message(LOG_INFO, " SNMP Trap enabled");
	else
		log_message(LOG_INFO, " SNMP Trap disabled");
#endif
}
