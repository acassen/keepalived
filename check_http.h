/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_http.c include file.
 *
 * Version:     $Id: check_http.h,v 0.4.1 2001/09/14 00:37:56 acassen Exp $
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

#ifndef _HTTP_H
#define _HTTP_H

/* local includes */
#include "cfreader.h"
#include "ipwrapper.h"
#include "scheduler.h"
#include "layer4.h"
#include "md5.h"

/* global defs */
#define SOCKET_ERROR   0
#define SOCKET_SUCCESS 1

#define MD5_BUFFER_LENGTH 32
#define GET_REQUEST_BUFFER_LENGTH 128
#define GET_BUFFER_LENGTH 2048
#define MAX_BUFFER_LENGTH 4096
#define LOGBUFFER_LENGTH 100

/* http get processing command */
#define GETCMD "GET %s HTTP/1.0\r\n\r\n"

/* Prototypes defs */
extern int http_connect_thread(struct thread *thread);

extern void smtp_alert(struct thread_master *master,
                       configuration_data *root,
                       realserver *rserver,
                       const char *subject,
                       const char *body);

#endif
