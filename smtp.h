/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        smtp.c include file.
 *
 * Version:     $Id: smtp.h,v 0.5.3 2002/02/24 23:50:11 acassen Exp $
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
} smtp_thread_arg;

/* Smtp error code */
#define SMTP_CONNECT   "220"
#define SMTP_HELO      "250"
#define SMTP_MAIL_FROM "250"
#define SMTP_RCPT_TO   "250"
#define SMTP_DATA      "354"
#define SMTP_DOT       "250"

/* Smtp command string processing */
#define SMTP_HELO_CMD    "HELO %s\n"
#define SMTP_MAIL_CMD    "MAIL FROM:<%s>\n"
#define SMTP_RCPT_CMD    "RCPT TO:<%s>\n"
#define SMTP_DATA_CMD    "DATA\n"
#define SMTP_HEADERS_CMD "From: %s\nSubject: %s\nX-Mailer: Keepalived\n\n"
#define SMTP_BODY_CMD    "\n\n%s\n\n"
#define SMTP_SEND_CMD    "\n.\n"
#define SMTP_QUIT_CMD    "QUIT\n"

/* Prototypes defs */
extern void smtp_alert(thread_master *
                       , real_server *
                       , const char *
                       , const char *);
#endif
