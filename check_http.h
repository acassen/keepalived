/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_http.c include file.
 *
 * Version:     $Id: check_http.h,v 0.5.7 2002/05/02 22:18:07 acassen Exp $
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

/* system includes */
#include <stdio.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>

/* local includes */
#include "data.h"
#include "ipwrapper.h"
#include "scheduler.h"
#include "layer4.h"
#include "list.h"

/* Checker argument structure  */
/* ssl specific thread arguments defs */
typedef struct {
  char  *buffer;
  char  *extracted;
  int   error;
  int   len;
  SSL   *ssl;
  BIO   *bio;
  MD5_CTX context;
} REQ;

/* http specific thread arguments defs */
typedef struct _http_arg {
  int retry_it;         /* current number of get retry */
  int url_it;           /* current url checked index */
  REQ *req;             /* GET buffer and SSL args */
} http_arg;

typedef struct _url {
  char *path;
  char *digest;
} url;
typedef struct _http_get_checker {
  int      proto;
  int      connection_to;
  int      nb_get_retry;
  int      delay_before_retry;
  list     url;
  http_arg *arg;
} http_get_checker;

/* global defs */
#define MD5_BUFFER_LENGTH 32
#define GET_REQUEST_BUFFER_LENGTH 128
#define GET_BUFFER_LENGTH 2048
#define MAX_BUFFER_LENGTH 4096
#define PROTO_HTTP	0x01
#define PROTO_SSL	0x02

/* GET processing command */
#define REQUEST_TEMPLATE "GET %s HTTP/1.0\r\n" \
                         "User-Agent:KeepAliveClient\r\n" \
                         "Host: %s:%d\r\n\r\n"

/* macro utility */
#define HTTP_ARG(X) ((X)->arg)
#define HTTP_REQ(X) ((X)->req)

/* Define prototypes */
extern void install_http_check_keyword(void);
extern int epilog(thread *thread, int metod, int t, int c);
extern int timeout_epilog(thread *thread, char *smtp_msg, char *debug_msg);
extern char *extract_html(char *buffer, int size_buffer);
extern url *fetch_next_url(http_get_checker *http_get_check);
extern int http_handle_response(thread *thread
                                , unsigned char digest[16]
                                , int empty_buffer);
#endif
