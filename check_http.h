/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_http.c include file.
 *
 * Version:     $Id: check_http.h,v 0.4.9 2001/12/10 10:52:33 acassen Exp $
 *
 * Authors:     Alexandre Cassen, <acassen@linux-vs.org>
 *              Jan Holmberg, <jan@artech.net>
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

#ifndef _HTTP_H
#define _HTTP_H

/* local includes */
#include "cfreader.h"
#include "ipwrapper.h"
#include "scheduler.h"
#include "layer4.h"

/* global defs */
#define MD5_BUFFER_LENGTH 32
#define GET_REQUEST_BUFFER_LENGTH 128
#define GET_BUFFER_LENGTH 2048
#define MAX_BUFFER_LENGTH 4096

/* http get processing command */
#define REQUEST_TEMPLATE "GET %s HTTP/1.0\r\n" \
                         "User-Agent:KeepAliveClient\r\n" \
                         "Host: %s:%d\r\n\r\n"

/* Define prototypes */
extern int epilog(thread *thread, int metod, int t, int c);
extern int timeout_epilog(thread *thread, char *smtp_msg, char *debug_msg);
extern char *extract_html(char *buffer, int size_buffer);
extern urls *fetch_next_url(thread_arg *thread_arg);
extern int http_handle_response(thread *thread
                                , unsigned char digest[16]
                                , int empty_buffer);

extern void smtp_alert(thread_master *
                       , configuration_data *
                       , realserver *
                       , const char *
                       , const char *);

#endif
