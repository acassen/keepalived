/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        http.c include file.
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

#ifndef _HTTP_H
#define _HTTP_H

/* system includes */
#include <stdio.h>
#include <openssl/ssl.h>

/* local includes */
#include "scheduler.h"
#include "sock.h"

/* global defs */
#define GET_BUFFER_LENGTH 2048
#define MAX_BUFFER_LENGTH 4096
#define HTTP_CNX_TIMEOUT 5
#define PROTO_HTTP	0x01
#define PROTO_SSL	0x02

typedef enum {
	HTTP_PROTOCOL_1_0,
	HTTP_PROTOCOL_1_0C,
	HTTP_PROTOCOL_1_0K,
	HTTP_PROTOCOL_1_1,
	HTTP_PROTOCOL_1_1K,
} http_protocol_t;

/* Globals exported */
extern const hash_t hashes[];

/* Define prototypes */
extern int epilog(thread_ref_t);
extern int finalize(thread_ref_t);
extern int http_process_stream(SOCK *, int);
extern int http_request_thread(thread_ref_t);

#endif
