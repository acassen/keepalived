/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        ssl.c include file.
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

#ifndef _SSL_H
#define _SSL_H

/* global includes */
#include <openssl/ssl.h>
#include <stdbool.h>

#include "scheduler.h"

/* Prototypes */
extern void init_ssl(void);
extern bool ssl_connect(thread_ref_t);
extern int ssl_send_request(SSL *, const char *, int);
extern int ssl_read_thread(thread_ref_t);

#endif
