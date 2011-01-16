/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_smtp.c include file.
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *              Jeremy Rumpf, <jrumpf@heavyload.net>
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

#ifndef _CHECK_SMTP_H
#define _CHECK_SMTP_H

/* system includes */
#include <stdlib.h>

/* local includes */
#include "check_data.h"
#include "scheduler.h"
#include "list.h"

#define SMTP_BUFF_MAX		512

#define SMTP_START		1
#define SMTP_HAVE_BANNER	2
#define SMTP_SENT_HELO		3
#define SMTP_RECV_HELO		4
#define SMTP_SENT_QUIT		5
#define SMTP_RECV_QUIT		6

#define SMTP_DEFAULT_HELO	"smtpchecker.keepalived.org"
#define SMTP_DEFAULT_PORT	25

/* Per host configuration structure  */
typedef struct _smtp_host {
	struct sockaddr_storage dst;
	struct sockaddr_storage bindto;
} smtp_host_t;

/* Checker argument structure  */
typedef struct _smtp_checker {
	/* non per host config data goes here */
	char *helo_name;
	long timeout;
	long db_retry;
	int retry;
	int attempts;
	int  host_ctr;
	smtp_host_t *host_ptr;

	/* data buffer */
	char buff[SMTP_BUFF_MAX];
	int buff_ctr;
	int (*buff_cb) (thread_t *);

	int state;

	/* list holding the host config data */
	list host;
} smtp_checker_t;

/* Prototypes defs */
extern void install_smtp_check_keyword(void);

#endif
