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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include "config.h"

#include <stdio.h>
#include <stdbool.h>
#include <time.h>

#include "logger.h"

/* Boolean flag - send messages to console as well as syslog */
static bool log_console = false;

void
enable_console_log(void)
{
	log_console = true;
}

void
vlog_message(const int facility, const char* format, va_list args)
{
	char buf[MAX_LOG_MSG+1];

	vsnprintf(buf, sizeof(buf), format, args);

	if (log_console) {
		/* timestamp setup */
		time_t t = time(NULL);
		struct tm tm;
		localtime_r(&t, &tm);
		char timestamp[64];
		strftime(timestamp, sizeof(timestamp), "%c", &tm);

		fprintf(stderr, "%s: %s\n", timestamp, buf);
	}

	syslog(facility, "%s", buf);
}

void
log_message(const int facility, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vlog_message(facility, format, args);
	va_end(args);
}
