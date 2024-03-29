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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _SMTP_H
#define _SMTP_H

/* globales includes */
#include <sys/types.h>
#include <stdbool.h>

/* local includes */
#include "global_data.h"
#include "layer4.h"
#ifdef _WITH_LVS_
#include "check_data.h"
#include "check_api.h"
#endif
#ifdef _WITH_VRRP_
#include "vrrp.h"
#endif

/* global defs */
#define SMTP_PORT_STR		"25"

/* SMTP command stage. These values are used along with the enum connect_result
 * values in the SMTP FSM, and so need to follow them. */
enum smtp_cmd_state {
	HELO = connect_result_next,
	MAIL,
	RCPT,
	DATA,
	BODY,
	QUIT,
	END
};
#define SMTP_MAX_FSM_STATE	END

/* SMTP mesage type format */
typedef enum {
#ifdef _WITH_LVS_
	SMTP_MSG_RS,
	SMTP_MSG_VS,
	SMTP_MSG_RS_SHUT,
#endif
#ifdef _WITH_VRRP_
	SMTP_MSG_VGROUP,
	SMTP_MSG_VRRP,
#endif
} smtp_msg_t;

/* SMTP thread argument structure */
#define MAX_HEADERS_LENGTH 256
#define MAX_BODY_LENGTH    512

/* SMTP FSM Macro */
#define SMTP_FSM_SEND(S, T)	\
do {				\
  if ((*(SMTP_FSM[S].send)))	\
    (*(SMTP_FSM[S].send)) (T);	\
} while (0)

#define SMTP_FSM_READ(S, T)		\
do {					\
  if ((*(SMTP_FSM[S].read)))		\
    (*(SMTP_FSM[S].read)) (T);	\
} while (0)

/* SMTP thread arguments */
typedef struct _smtp {
	int		stage;
	email_t		*next_email_element;
	char		*subject;
	char		*body;
	char		*buffer;
	size_t		buflen;
} smtp_t;

#define FMT_SMTP_HOST()	inet_sockaddrtopair(&global_data->smtp_server)

#ifdef _WITH_LVS_
typedef struct _smtp_rs {
	real_server_t *rs;
	virtual_server_t *vs;
} smtp_rs;
#else
typedef void real_server_t;
#endif

#ifdef _SMTP_ALERT_DEBUG_
extern bool do_smtp_alert_debug;
#endif
#ifdef _SMTP_CONNECT_DEBUG_
extern bool do_smtp_connect_debug;
#endif

/* Prototypes defs */
extern void smtp_alert(smtp_msg_t, void *data, const char *, const char *);
#ifdef THREAD_DUMP
extern void register_smtp_addresses(void);
#endif

#endif
