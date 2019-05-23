/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        main.c include file.
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

#ifndef _MAIN_H
#define _MAIN_H

/* global includes */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <openssl/ssl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/* local includes */
#include "memory.h"
#include "timer.h"
#include "http.h"
#include "ssl.h"
#include "list.h"
#include "sock.h"

/* Build version */
#define PROG    "genhash"

/* HTTP/HTTPS request structure */
typedef struct {
	struct		addrinfo *dst;
	char		ipaddress[INET6_ADDRSTRLEN];
	uint16_t	addr_port;
	const char	*url;
	const char	*vhost;
	int		verbose;
	int		ssl;
	http_protocol_t http_protocol;
	unsigned	timeout;
#ifdef _HAVE_SSL_SET_TLSEXT_HOST_NAME_
	int		sni;
#endif
	SSL_CTX		*ctx;
	const SSL_METHOD *meth;
	enum		feat_hashes hash;
	unsigned long	ref_time;
	unsigned long	response_time;
#ifdef _WITH_SO_MARK_
	unsigned int	mark;
#endif
} REQ;

/* Global variables */
extern REQ *req;		/* Cmd line arguments */
extern int exit_code;

/* Data buffer length description */
#define BUFSIZE		1024

/* Command line error handling */
#define CMD_LINE_ERROR   0
#define CMD_LINE_SUCCESS 1

#endif
