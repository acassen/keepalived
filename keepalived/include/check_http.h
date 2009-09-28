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
 * Copyright (C) 2001-2009 Alexandre Cassen, <acassen@freebox.fr>
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
typedef struct {
	char *buffer;
	char *extracted;
	int error;
	int status_code;
	int len;
	SSL *ssl;
	BIO *bio;
	MD5_CTX context;
} REQ;

/* http specific thread arguments defs */
typedef struct _http_arg {
	int retry_it;		/* current number of get retry */
	int url_it;		/* current url checked index */
	REQ *req;		/* GET buffer and SSL args */
} http_arg;

typedef struct _url {
	char *path;
	char *digest;
	int status_code;
} url;
typedef struct _http_get_checker {
	int proto;
	uint16_t connection_port;
	uint32_t bindto;
	long connection_to;
	int nb_get_retry;
	long delay_before_retry;
	list url;
	http_arg *arg;
} http_get_checker;

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
extern int epilog(thread * thread_obj, int metod, int t, int c);
extern int timeout_epilog(thread * thread_obj, char *smtp_msg, char *debug_msg);
extern url *fetch_next_url(http_get_checker * http_get_check);
extern int http_process_response(REQ * req, int r);
extern int http_handle_response(thread * thread_obj, unsigned char digest[16]
				, int empty_buffer);
#endif
