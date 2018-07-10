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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _CHECK_HTTP_H
#define _CHECK_HTTP_H

/* system includes */
#include <sys/types.h>
#include <stdbool.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>

/* local includes */
#include "scheduler.h"
#include "list.h"

/* Checker argument structure  */
/* ssl specific thread arguments defs */
typedef struct _request {
	char				*buffer;
	char				*extracted;
	int				error;
	int				status_code;
	size_t				len;
	SSL				*ssl;
	BIO				*bio;
	MD5_CTX				context;
	size_t				content_len;
	size_t				rx_bytes;
} request_t;

typedef struct _url {
	char				*path;
	uint8_t				*digest;
	int				status_code;
	char				*virtualhost;
	ssize_t				len_mismatch;
} url_t;

typedef struct _http_checker {
	unsigned			proto;
	unsigned			url_it;		/* current url checked index */
	request_t			*req;		/* GET buffer and SSL args */
	list				url;
	char				*virtualhost;
#ifdef _HAVE_SSL_SET_TLSEXT_HOST_NAME_
	bool				enable_sni;
#endif
} http_checker_t;

/* global defs */
#define GET_BUFFER_LENGTH 2048U
#define MAX_BUFFER_LENGTH 4096U
#define PROTO_HTTP	0x01
#define PROTO_SSL	0x02

/* GET processing command */
#define REQUEST_TEMPLATE "GET %s HTTP/1.0\r\n" \
			 "User-Agent: KeepAliveClient\r\n" \
			 "Host: %s%s\r\n\r\n"

#define REQUEST_TEMPLATE_IPV6 "GET %s HTTP/1.0\r\n" \
			 "User-Agent: KeepAliveClient\r\n" \
			 "Host: [%s]%s\r\n\r\n"

/* macro utility */
#define FMT_HTTP_RS(C) FMT_CHK(C)

/* Define prototypes */
extern void install_http_check_keyword(void);
extern int timeout_epilog(thread_t *, const char *);
extern void http_process_response(request_t *, size_t, bool);
extern int http_handle_response(thread_t *, unsigned char digest[16], bool);
#endif
