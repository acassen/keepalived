/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_http.c include file.
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
 *
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

#ifndef _CHECK_HTTP_H
#define _CHECK_HTTP_H

/* system includes */
#include <stdio.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>

/* local includes */
#include "check_data.h"
#include "ipwrapper.h"
#include "scheduler.h"
#include "layer4.h"
#include "list.h"

/* Checker argument structure  */
/* ssl specific thread arguments defs */
typedef struct _request {
	char *buffer;
	char *extracted;
	int error;
	int status_code;
	int len;
	SSL *ssl;
	BIO *bio;
	MD5_CTX context;
} request_t;

/* http specific thread arguments defs */
typedef struct _http_arg {
	int retry_it;		/* current number of get retry */
	int url_it;		/* current url checked index */
	request_t *req;		/* GET buffer and SSL args */
} http_arg_t ;

typedef struct _url {
	char *path;
	char *digest;
	int status_code;
} url_t;

typedef struct _http_checker {
	int proto;
	struct sockaddr_storage dst;
	struct sockaddr_storage bindto;
	long connection_to;
	int nb_get_retry;
	long delay_before_retry;
	list url;
	http_arg_t *arg;
} http_checker_t;

/* global defs */
#define MD5_BUFFER_LENGTH 32
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
extern int epilog(thread_t *, int, int, int);
extern int timeout_epilog(thread_t *, char *, char *);
extern url_t *fetch_next_url(http_checker_t *);
extern int http_process_response(request_t *, int);
extern int http_handle_response(thread_t *, unsigned char digest[16]
				, int);
#endif
