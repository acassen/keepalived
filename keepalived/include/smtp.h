/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        smtp.c include file.
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
 *
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _SMTP_H
#define _SMTP_H

/* globales includes */
#include <netdb.h>

/* local includes */
#include "check_data.h"
#include "vrrp_data.h"
#include "scheduler.h"
#include "layer4.h"
#include "vrrp.h"

/* global defs */
#define SMTP_PORT_STR		"25"
#define SMTP_BUFFER_LENGTH	512
#define SMTP_BUFFER_MAX		1024
#define SMTP_MAX_FSM_STATE	10

/* SMTP command stage */
#define HELO	4
#define MAIL	5
#define RCPT	6
#define DATA	7
#define BODY	8
#define QUIT	9
#define END	10
#define ERROR	11

/* SMTP thread argument structure */
#define MAX_HEADERS_LENGTH 256
#define MAX_BODY_LENGTH    512

/* SMTP FSM Macro */
#define SMTP_FSM_SEND(S, T)	\
do {				\
  if ((*(SMTP_FSM[S].send)))	\
    (*(SMTP_FSM[S].send)) (T);	\
} while (0)

#define SMTP_FSM_READ(S, T, N)		\
do {					\
  if ((*(SMTP_FSM[S].read)))		\
    (*(SMTP_FSM[S].read)) (T, N);	\
} while (0)

/* SMTP thread arguments */
typedef struct _smtp {
	int		fd;
	int		stage;
	int		email_it;
	char		*subject;
	char		*body;
	char		*buffer;
	char		*email_to;
	long		buflen;
} smtp_t;

/* SMTP command string processing */
#define SMTP_HELO_CMD    "HELO %s\r\n"
#define SMTP_MAIL_CMD    "MAIL FROM:<%s>\r\n"
#define SMTP_RCPT_CMD    "RCPT TO:<%s>\r\n"
#define SMTP_DATA_CMD    "DATA\r\n"
#define SMTP_HEADERS_CMD "Date: %s\r\nFrom: %s\r\nSubject: %s\r\n" \
			 "X-Mailer: Keepalived\r\nTo: %s\r\n\r\n"
#define SMTP_BODY_CMD    "%s\r\n"
#define SMTP_SEND_CMD    "\r\n.\r\n"
#define SMTP_QUIT_CMD    "QUIT\r\n"

#define FMT_SMTP_HOST()	inet_sockaddrtopair(&global_data->smtp_server)

/* Prototypes defs */
extern void smtp_alert(real_server_t *, vrrp_t *, vrrp_sgroup_t *,
		       const char *, const char *);
#endif
