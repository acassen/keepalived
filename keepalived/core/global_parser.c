/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        Configuration file parser/reader. Place into the dynamic
 *              data structure representation the conf file representing
 *              the loadbalanced server pool.
 *  
 * Version:     $Id: global_parser.c,v 1.1.0 2003/07/20 23:41:34 acassen Exp $
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
 */

#include "global_parser.h"
#include "global_data.h"
#include "parser.h"
#include "memory.h"
#include "utils.h"

/* External vars */
extern conf_data *data;

/* data handlers */
/* Global def handlers */
static void
lvsid_handler(vector strvec)
{
	data->lvs_id = set_value(strvec);
}
static void
emailfrom_handler(vector strvec)
{
	data->email_from = set_value(strvec);
}
static void
smtpto_handler(vector strvec)
{
	data->smtp_connection_to = atoi(VECTOR_SLOT(strvec, 1));
}
static void
smtpip_handler(vector strvec)
{
	inet_ston(VECTOR_SLOT(strvec, 1), &data->smtp_server);
}
static void
email_handler(vector strvec)
{
	vector email = read_value_block();
	int i;
	char *str;

	for (i = 0; i < VECTOR_SIZE(email); i++) {
		str = VECTOR_SLOT(email, i);
		alloc_email(str);
	}

	free_strvec(email);
}

void
global_init_keywords(void)
{
	/* global definitions mapping */
	install_keyword_root("global_defs", NULL);
	install_keyword("lvs_id", &lvsid_handler);
	install_keyword("notification_email_from", &emailfrom_handler);
	install_keyword("smtp_server", &smtpip_handler);
	install_keyword("smtp_connect_timeout", &smtpto_handler);
	install_keyword("notification_email", &email_handler);
}
