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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _LOGGER_H
#define _LOGGER_H

#include <stdarg.h>
#include <syslog.h>
#include <stdio.h>
#ifdef ENABLE_LOG_TO_FILE
#include <sys/stat.h>
#endif

#define	MAX_LOG_MSG	255

#ifdef ENABLE_LOG_TO_FILE
extern const char *log_file_name;
#endif

extern void enable_console_log(void);
#ifdef ENABLE_LOG_TO_FILE
extern void set_flush_log_file(void);
extern void close_log_file(void);
extern void open_log_file(const char *, const char *, const char *, const char *);
extern void flush_log_file(void);
extern void update_log_file_perms(mode_t);
#endif
extern void vlog_message(const int facility, const char* format, va_list args)
	__attribute__ ((format (printf, 2, 0)));
extern void log_message(int priority, const char* format, ...)
	__attribute__ ((format (printf, 2, 3)));
extern void conf_write(FILE *fp, const char *format, ...)
	__attribute__ ((format (printf, 2, 3)));

#endif
