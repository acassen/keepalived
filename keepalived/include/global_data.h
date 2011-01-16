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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

#ifndef _GLOBAL_DATA_H
#define _GLOBAL_DATA_H

/* system includes */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* local includes */
#include "list.h"
#include "timer.h"

/* constants */
#define DEFAULT_SMTP_SERVER 0x7f000001
#define DEFAULT_SMTP_CONNECTION_TIMEOUT (30 * TIMER_HZ)
#define DEFAULT_PLUGIN_DIR "/etc/keepalived/plugins"

/* email link list */
typedef struct _email {
	char *addr;
} email;

/* Configuration data root */
typedef struct _conf_data {
	int linkbeat_use_polling;
	char *router_id;
	char *plugin_dir;
	char *email_from;
	struct sockaddr_storage smtp_server;
	long smtp_connection_to;
	list email;
} conf_data_t;

/* Global vars exported */
extern conf_data_t *data;	/* Global configuration data */

/* Prototypes */
extern void alloc_email(char *);
extern conf_data_t *alloc_global_data(void);
extern void free_global_data(conf_data_t *);
extern void dump_global_data(conf_data_t *);

#endif
