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
#ifdef _WITH_REGEX_CHECK_
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#ifdef _WITH_REGEX_TIMERS_
#include <time.h>
#endif
#endif
#include <stdbool.h>

/* local includes */
#include "scheduler.h"
#include "list.h"

typedef enum {
        HTTP_PROTOCOL_1_0,
        HTTP_PROTOCOL_1_0C,
        HTTP_PROTOCOL_1_1,
} http_protocol_t;

#define HTTP_STATUS_CODE_MIN		100
#define HTTP_STATUS_CODE_MAX		599
#define HTTP_DEFAULT_STATUS_CODE_MIN	200
#define HTTP_DEFAULT_STATUS_CODE_MAX	299

/* Checker argument structure  */
/* ssl specific thread arguments defs */
typedef struct _request {
	char				*buffer;
	const char			*extracted;
	int				error;
	int				status_code;
	size_t				len;
	SSL				*ssl;
	BIO				*bio;
	MD5_CTX				context;
	size_t				content_len;
	size_t				rx_bytes;
#ifdef _WITH_REGEX_CHECK_
	bool				regex_matched;
	size_t				start_offset;	/* Offset into buffer to match from */
	size_t				regex_subject_offset;	/* Offset into web page of start of buffer */
#ifdef _WITH_REGEX_TIMERS_
	struct timespec			req_time;
	unsigned			num_match_calls;
#endif
#endif
} request_t;

#ifdef _WITH_REGEX_CHECK_
typedef struct _regex {
	const unsigned char		*pattern;
	int				pcre2_options;
	pcre2_code			*pcre2_reCompiled;
	pcre2_match_data		*pcre2_match_data;
	uint32_t			pcre2_max_lookbehind;
	unsigned			use_count;
#ifdef _WITH_REGEX_TIMERS_
	struct timespec			regex_time;
	unsigned			num_match_calls;
	unsigned			num_regex_urls;
#endif
} regex_t;
#endif

typedef struct _url {
	const char			*path;
	const uint8_t			*digest;
	unsigned long			status_code[(HTTP_STATUS_CODE_MAX - HTTP_STATUS_CODE_MIN + 1 - 1) / (sizeof(unsigned long) * CHAR_BIT) + 1];
	const char			*virtualhost;
	ssize_t				len_mismatch;
#ifdef _WITH_REGEX_CHECK_
	bool				regex_no_match;
	regex_t				*regex;
	size_t				regex_min_offset;
	size_t				regex_max_offset;	/* One beyond max offset */
#ifndef PCRE2_DONT_USE_JIT
	bool				regex_use_stack;
#endif
#endif
} url_t;

typedef struct _http_checker {
	unsigned			proto;
	element				url_it;		/* current url checked list element */
	url_t				*failed_url;	/* the url that is currently failing, if any */
	request_t			*req;		/* GET buffer and SSL args */
	list				url;
	http_protocol_t			http_protocol;
	const char			*virtualhost;
#ifdef _HAVE_SSL_SET_TLSEXT_HOST_NAME_
	bool				enable_sni;
#endif
	bool				fast_recovery;
} http_checker_t;

/* global defs */
#define GET_BUFFER_LENGTH 2048U
#define MAX_BUFFER_LENGTH 4096U
#define PROTO_HTTP	0x01
#define PROTO_SSL	0x02

#ifdef _REGEX_DEBUG_
extern bool do_regex_debug;
#endif
#ifdef _WITH_REGEX_TIMERS_
extern bool do_regex_timers;
#endif

/* Define prototypes */
extern void install_http_check_keyword(void);
extern int timeout_epilog(thread_ref_t, const char *);
extern void http_process_response(request_t *, size_t, url_t *);
extern int http_handle_response(thread_ref_t, unsigned char digest[16], bool);
#ifdef THREAD_DUMP
extern void register_check_http_addresses(void);
#endif

#endif
