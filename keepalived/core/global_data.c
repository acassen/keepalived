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
 * Copyright (C) 2001-2009 Alexandre Cassen, <acassen@freebox.fr>
 */

#include <syslog.h>
#include <unistd.h>
#include <pwd.h>
#include "global_data.h"
#include "memory.h"
#include "list.h"
#include "logger.h"
#include "utils.h"

/* global vars */
conf_data *data = NULL;

/* Default settings */
static void
set_default_router_id(conf_data * conf_data_obj)
{
	char *new_id = NULL;
	int len = 0;

	new_id = get_local_name();
	if (!new_id || !new_id[0])
		return;

	len = strlen(new_id);
	conf_data_obj->router_id = MALLOC(len + 1);
	if (!conf_data_obj->router_id)
		return;

	memcpy(conf_data_obj->router_id, new_id, len);
}

static void
set_default_email_from(conf_data * conf_data_obj)
{
	struct passwd *pwd = NULL;
	char *hostname = NULL;
	int len = 0;

	hostname = get_local_name();
	if (!hostname || !hostname[0])
		return;

	pwd = getpwuid(getuid());
	if (!pwd)
		return;

	len = strlen(hostname) + strlen(pwd->pw_name) + 2;
	conf_data_obj->email_from = MALLOC(len);
	if (!conf_data_obj->email_from)
		return;

	snprintf(conf_data_obj->email_from, len, "%s@%s", pwd->pw_name, hostname);
}

static void
set_default_smtp_server(conf_data * conf_data_obj)
{
	conf_data_obj->smtp_server = htonl(DEFAULT_SMTP_SERVER);
}

static void
set_default_smtp_connection_timeout(conf_data * conf_data_obj)
{
	conf_data_obj->smtp_connection_to = DEFAULT_SMTP_CONNECTION_TIMEOUT;
}

static void
set_default_values(conf_data * conf_data_obj)
{
	/* No global data so don't default */
	if (!conf_data_obj)
		return;
	set_default_router_id(conf_data_obj);
	set_default_smtp_server(conf_data_obj);
	set_default_smtp_connection_timeout(conf_data_obj);
	set_default_email_from(conf_data_obj);
}

/* email facility functions */
static void
free_email(void *data_obj)
{
	FREE(data_obj);
}
static void
dump_email(void *data_obj)
{
	char *addr = data_obj;
	log_message(LOG_INFO, " Email notification = %s", addr);
}

void
alloc_email(char *addr)
{
	int size = strlen(addr);
	char *new;

	new = (char *) MALLOC(size + 1);
	memcpy(new, addr, size + 1);

	list_add(data->email, new);
}

/* data facility functions */
conf_data *
alloc_global_data(void)
{
	conf_data *new;

	new = (conf_data *) MALLOC(sizeof (conf_data));
	new->email = alloc_list(free_email, dump_email);

	set_default_values(new);
	return new;
}

void
free_global_data(conf_data * global_data)
{
	free_list(data->email);
	FREE_PTR(data->router_id);
	FREE_PTR(data->plugin_dir);
	FREE_PTR(data->email_from);
	FREE(data);
}

void
dump_global_data(conf_data * global_data)
{
	if (!data)
		return;

	if (data->router_id ||
	    data->smtp_server || data->smtp_connection_to || data->email_from) {
		log_message(LOG_INFO, "------< Global definitions >------");
	}
	if (data->router_id)
		log_message(LOG_INFO, " Router ID = %s", data->router_id);
	if (data->plugin_dir)
		log_message(LOG_INFO, " Plugin dir = %s", data->plugin_dir);
	if (data->smtp_server)
		log_message(LOG_INFO, " Smtp server = %s",
		       inet_ntop2(data->smtp_server));
	if (data->smtp_connection_to)
		log_message(LOG_INFO, " Smtp server connection timeout = %lu",
		       data->smtp_connection_to / TIMER_HZ);
	if (data->email_from) {
		log_message(LOG_INFO, " Email notification from = %s",
		       data->email_from);
		dump_list(data->email);
	}
}
