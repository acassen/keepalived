/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        A safe version of snprintf.
 *
 * Author:      Quentin Armitage, <quentin@armitage.org.uk>
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
 * Copyright (C) 2026-2026 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <stdio.h>

#include "safe_snprintf.h"
#include "memory.h"
#include "logger.h"

/* Note: if safe_snprintf is called with buf = NULL, buf_size = 0,
 * then it is guaranteed that a buffer will be malloc'd.
 * This is similar to make_message() in the printf man page.
 */
char * __attribute__ ((format (printf, 3, 4)))
safe_snprintf(char *buf, size_t buf_size, const char *format, ...)
{
	char *obuf = buf;
	size_t required_buf_size;
	va_list args;

	va_start(args, format);

	do {
		required_buf_size = vsnprintf(obuf, buf_size, format, args);
		if (required_buf_size < buf_size)
			break;

		log_message(LOG_DEBUG, "safe_snprintf buf[%zu] too small - needs to be [%zu]", buf_size, required_buf_size + 1);

		if (obuf != buf)	// This should never happen
			FREE(obuf);
		obuf = MALLOC(buf_size = required_buf_size + 1);
	} while (true);

	va_end(args);

	return obuf;
}
