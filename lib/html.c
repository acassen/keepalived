/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        HTML stream parser utility functions.
 *
 * Authors:     Alexandre Cassen, <acassen@linux-vs.org>
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

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "html.h"
#include "memory.h"

/* HTTP header tag */
#define CONTENT_LENGTH	"Content-Length:"

/* Return the http header content length */
size_t extract_content_length(const char *buffer, size_t size)
{
	char *clen = strstr(buffer, CONTENT_LENGTH);
	size_t len;
	char *end;

	/* Pattern not found */
	if (!clen || clen > buffer + size)
		return SIZE_MAX;

	/* Content-Length extraction */
	len = strtoul(clen + strlen(CONTENT_LENGTH), &end, 10);
	if (*end)
		return SIZE_MAX;

	return len;
}

/*
 * Return the http header error code. According
 * to rfc2616.6.1 status code is between HTTP_Version
 * and Reason_Phrase, separated by space caracter.
 */
#include "logger.h"
int extract_status_code(const char *buffer, size_t size)
{
	const char *buf_end = buffer + size;
	char *end;
	unsigned long code;

	/* Status-Code extraction */
	while (buffer < buf_end && *buffer != ' ' && *buffer != '\r')
		buffer++;
	if (*buffer != ' ')
		return 0;
	buffer++;
	if (buffer + 3 >= buf_end || *buffer == ' ' || buffer[3] != ' ')
		return 0;
	code = strtoul(buffer, &end, 10);	// This line causes a strict-overflow=4 warning with gcc 5.4.0
	if (buffer + 3 != end)
		return 0;
	return code;
}

/* simple function returning a pointer to the html buffer begin */
const char * __attribute__ ((pure))
extract_html(const char *buffer, size_t size_buffer)
{
	const char *end = buffer + size_buffer;
	const char *cur;

	for (cur = buffer; cur + 3 < end; cur++)
		if (*cur == '\r' && *(cur+1) == '\n'
		    && *(cur+2) == '\r' && *(cur+3) == '\n')
			return cur + 4;
	return NULL;
}
