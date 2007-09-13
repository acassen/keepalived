/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        http.c include file.
 *
 * Version:     $Id: http.h,v 1.0.0 2002/11/20 21:34:18 acassen Exp $
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
 * Copyright (C) 2001-2007 Alexandre Cassen, <acassen@freebox.fr>
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
#define HTTP_CNX_TIMEOUT (5 * TIMER_HZ)
#define PROTO_HTTP	0x01
#define PROTO_SSL	0x02

/* GET processing command */
#define REQUEST_TEMPLATE "GET %s HTTP/1.0\r\n" \
			 "User-Agent: GenHash (Linux powered)\r\n" \
			 "Host: %s:%d\r\n\r\n"

/* Output delimiters */
#define DELIM_BEGIN "-----------------------["
#define DELIM_END   "]-----------------------\n"
#define HTTP_HEADER_HEXA  DELIM_BEGIN"    HTTP Header Buffer    "DELIM_END
#define HTTP_HEADER_ASCII DELIM_BEGIN" HTTP Header Ascii Buffer "DELIM_END
#define HTML_HEADER_HEXA  DELIM_BEGIN"       HTML Buffer        "DELIM_END
#define HTML_MD5          DELIM_BEGIN"    HTML MD5 resulting    "DELIM_END
#define HTML_MD5_FINAL    DELIM_BEGIN" HTML MD5 final resulting "DELIM_END

/* Define prototypes */
extern int epilog(thread * thread_obj);
extern int finalize(thread * thread_obj);
extern int http_process_stream(SOCK * sock_obj, int r);
extern int http_request_thread(thread * thread_obj);

#endif
