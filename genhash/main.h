/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        main.c include file.
 *
 * Version:     $Id: main.h,v 1.1.16 2009/02/14 03:25:07 acassen Exp $
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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

#ifndef _MAIN_H
#define _MAIN_H

/* global includes */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <popt.h>
#include <openssl/ssl.h>

/* local includes */
#include "memory.h"
#include "timer.h"
#include "http.h"
#include "ssl.h"
#include "list.h"

/* Build version */
#define PROG    "genhash"

#define VERSION_CODE 0x010000
#define DATE_CODE    0x120b02

#define GETMETER_VERSION(version)	\
        (version >> 16) & 0xFF,		\
        (version >> 8) & 0xFF,		\
        version & 0xFF

#define VERSION_STRING PROG" v%d.%d.%d (%.2d/%.2d, 20%.2d)\n",	\
                GETMETER_VERSION(VERSION_CODE),			\
                GETMETER_VERSION(DATE_CODE)

/* HTTP/HTTPS request structure */
typedef struct {
	uint32_t addr_ip;
	uint16_t addr_port;
	char *url;
	char *vhost;
	int verbose;
	int ssl;
	SSL_CTX *ctx;
	SSL_METHOD *meth;
	unsigned long ref_time;
	unsigned long response_time;
} REQ;

/* Global variables */
extern thread_master_t *master;
extern REQ *req;		/* Cmd line arguments */

/* Data buffer length description */
#define BUFSIZE             1024

/* Command line error handling */
#define CMD_LINE_ERROR   0
#define CMD_LINE_SUCCESS 1

#endif
