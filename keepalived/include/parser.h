/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        cfreader.c include file.
 *  
 * Version:     $Id: parser.h,v 0.6.9 2002/07/31 01:33:12 acassen Exp $
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

#ifndef _PARSER_H
#define _PARSER_H

/* system includes */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>
#include <ctype.h>

/* local includes */
#include "data.h"
#include "vector.h"

/* Global definitions */
#define CONF "/etc/keepalived/keepalived.conf"
#define EOB  "}"
#define MAXBUF	1024

/* ketword definition */
struct keyword {
	char *string;
	void (*handler) (vector);
	vector sub;
};

/* Prototypes */
extern void init_data(char *conf_file);
extern void install_keyword(char *string, void (*handler) (vector));
extern void install_sublevel(void);
extern void install_sublevel_end(void);
extern void *set_value(vector strvec);

#endif
