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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _CHECK_SSL_H
#define _CHECK_SSL_H

/* local includes */
#include "check_http.h"

/* Prototypes */
extern void install_ssl_check_keyword(bool);
extern int init_ssl_ctx(void);
extern void clear_ssl(ssl_data_t *);
extern int ssl_connect(thread_t *, int);
extern int ssl_printerr(int);
extern int ssl_send_request(SSL *, char *, int);
extern int ssl_read_thread(thread_t *);

#endif
