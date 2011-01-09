/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        logging facility.
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

#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>

/* Boolean flag - send messages to console as well as syslog */
static int log_console = 0;

void
enable_console_log(void) {
	log_console = 1;
}

void
log_message(const int facility, const char *format, ...)
{
	va_list args;

	va_start(args,format);

	if (log_console) {
		vfprintf(stderr, format, args);
		fprintf(stderr,"\n");
	}

	vsyslog(facility, format, args);
}
