/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Checkers arguments structures definitions.
 *
 * Version:     $Id: check.h,v 0.4.9 2001/12/10 10:52:33 acassen Exp $
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
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

#ifndef _CHECK_H
#define _CHECK_H

/* system includes */
#include <openssl/md5.h>
#include <openssl/ssl.h>

/* ssl specific thread arguments defs */
typedef struct {
  char *buffer;
  char *extracted;
  int   error;
  int   len;
  SSL   *ssl;
  BIO   *bio;
  MD5_CTX context;
} REQ;

/* http specific thread arguments defs */
typedef struct _http_thread_arg {
  int retry_it;                /* current number of get retry */
  int url_it;                  /* current url checked index */
  REQ *req;                    /* GET buffer and SSL args */
} http_thread_arg;

/* global thread arguments defs */
typedef struct _thread_arg {
  configuration_data *root;    /* pointer to the configuration root data */
  virtualserver *vs;           /* pointer to the checker thread virtualserver */
  realserver *svr;             /* pointer to the checker thread realserver */
  void *checker_arg;           /* pointer to the specific checker arg */
} thread_arg;

#endif
