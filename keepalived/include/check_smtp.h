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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _CHECK_SMTP_H
#define _CHECK_SMTP_H

/* system includes */
#include <sys/types.h>

/* local includes */
#include "scheduler.h"
#include "list.h"
#include "check_api.h"

#define SMTP_BUFF_MAX		512U

typedef enum {
	SMTP_START,
	SMTP_HAVE_BANNER,
	SMTP_SENT_HELO,
	SMTP_RECV_HELO,
	SMTP_SENT_QUIT,
	SMTP_RECV_QUIT
} smtp_state_t;

#define SMTP_DEFAULT_HELO	"smtpchecker.keepalived.org"

/* Checker argument structure  */
typedef struct _smtp_checker {
	/* non per host config data goes here */
	const char			*helo_name;

	/* data buffer */
	char				buff[SMTP_BUFF_MAX];
	size_t				buff_ctr;

	smtp_state_t			state;
} smtp_checker_t;

/* macro utility */
#define FMT_SMTP_RS(H) (inet_sockaddrtopair (&(H)->dst))

/* Prototypes defs */
extern void install_smtp_check_keyword(void);
#ifdef THREAD_DUMP
extern void register_check_smtp_addresses(void);
#endif

#endif
