/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        smtp.c include file.
 *
 * Version:     $Id: smtp.h,v 0.6.5 2002/07/01 23:41:28 acassen Exp $
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

#ifndef _SMTP_H
#define _SMTP_H

/* globales includes */
#include <netdb.h>
#include <sys/param.h>
#include <sys/utsname.h>

/* local includes */
#include "data.h"
#include "scheduler.h"
#include "layer4.h"
#include "vrrp.h"

/* global defs */
#define SMTP_PORT          25
#define SMTP_BUFFER_LENGTH 128
#define SMTP_BUFFER_MAX    256

/* command stage */
enum smtp_cmd {
	CONNECTION,
	HELO,
	MAIL,
	RCPT,
	DATA,
	BODY,
	QUIT,
	ERROR
};

/* SMTP thread argument structure */
#define MAX_HEADERS_LENGTH 256
#define MAX_BODY_LENGTH    512

typedef struct _smtp_thread_arg {
	enum smtp_cmd stage;
	int email_it;
	char *subject;
	char *body;
	char *buffer;
	long buflen;
} smtp_thread_arg;

/* Smtp command string processing */
#define SMTP_HELO_CMD    "HELO %s\r\n"
#define SMTP_MAIL_CMD    "MAIL FROM:<%s>\r\n"
#define SMTP_RCPT_CMD    "RCPT TO:<%s>\r\n"
#define SMTP_DATA_CMD    "DATA\r\n"
#define SMTP_HEADERS_CMD "From: %s\r\nSubject: %s\r\nX-Mailer: Keepalived\r\n\r\n"
#define SMTP_BODY_CMD    "\r\n\r\n%s\r\n\r\n"
#define SMTP_SEND_CMD    "\r\n.\r\n"
#define SMTP_QUIT_CMD    "QUIT\r\n"

/* Prototypes defs */
extern void smtp_alert(thread_master *, real_server *, vrrp_rt *, const char *,
		       const char *);
#endif
