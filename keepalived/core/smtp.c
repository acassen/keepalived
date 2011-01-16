/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        SMTP WRAPPER connect to a specified smtp server and send mail
 *              using the smtp protocol according to the RFC 821. A non blocking
 *              timeouted connection is used to handle smtp protocol.
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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include <time.h>

#include "smtp.h"
#include "global_data.h"
#include "check_data.h"
#include "scheduler.h"
#include "memory.h"
#include "list.h"
#include "logger.h"
#include "utils.h"

/* SMTP FSM definition */
static int connection_error(thread_t *);
static int connection_in_progress(thread_t *);
static int connection_timeout(thread_t *);
static int connection_success(thread_t *);
static int helo_cmd(thread_t *);
static int mail_cmd(thread_t *);
static int rcpt_cmd(thread_t *);
static int data_cmd(thread_t *);
static int body_cmd(thread_t *);
static int quit_cmd(thread_t *);

static int connection_code(thread_t *, int);
static int helo_code(thread_t *, int);
static int mail_code(thread_t *, int);
static int rcpt_code(thread_t *, int);
static int data_code(thread_t *, int);
static int body_code(thread_t *, int);
static int quit_code(thread_t *, int);

static int smtp_read_thread(thread_t *);
static int smtp_send_thread(thread_t *);

struct {
	int (*send) (thread_t *);
	int (*read) (thread_t *, int);
} SMTP_FSM[SMTP_MAX_FSM_STATE] = {
/*      Stream Write Handlers    |   Stream Read handlers   *
 *-------------------------------+--------------------------*/
	{connection_error,		NULL},			/* connect_error */
	{connection_in_progress,	NULL},			/* connect_in_progress */
	{connection_timeout,		NULL},			/* connect_timeout */
	{connection_success,		connection_code},	/* connect_success */
	{helo_cmd,			helo_code},		/* HELO */
	{mail_cmd,			mail_code},		/* MAIL */
	{rcpt_cmd,			rcpt_code},		/* RCPT */
	{data_cmd,			data_code},		/* DATA */
	{body_cmd,			body_code},		/* BODY */
	{quit_cmd,			quit_code}		/* QUIT */
};

static void
free_smtp_all(smtp_thread_arg * smtp_arg)
{
	FREE(smtp_arg->buffer);
	FREE(smtp_arg->subject);
	FREE(smtp_arg->body);
	FREE(smtp_arg);
}

static char *
fetch_next_email(smtp_thread_arg * smtp_arg)
{
	return list_element(data->email, smtp_arg->email_it);
}

/* layer4 connection handlers */
static int
connection_error(thread_t * thread)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);

	log_message(LOG_INFO, "SMTP connection ERROR to [%s:%d]."
			    , inet_sockaddrtos(&data->smtp_server), SMTP_PORT);
	free_smtp_all(smtp_arg);
	return 0;
}
static int
connection_timeout(thread_t * thread)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);

	log_message(LOG_INFO, "Timeout connecting SMTP server [%s:%d]."
			    , inet_sockaddrtos(&data->smtp_server), SMTP_PORT);
	free_smtp_all(smtp_arg);
	return 0;
}
static int
connection_in_progress(thread_t * thread)
{
	int status;

	DBG("SMTP connection to [%s:%d] now IN_PROGRESS.",
	    inet_sockaddrtos(&data->smtp_server), SMTP_PORT);

	/*
	 * Here we use the propriety of a union structure,
	 * each element of the structure have the same value.
	 */
	status = tcp_socket_state(thread->u.fd, thread, connection_in_progress);

	if (status != connect_in_progress)
		SMTP_FSM_SEND(status, thread);

	return 0;
}
static int
connection_success(thread_t * thread)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);

	log_message(LOG_INFO, "Remote SMTP server [%s:%d] connected."
			    , inet_sockaddrtos(&data->smtp_server), SMTP_PORT);

	smtp_arg->stage = connect_success;
	thread_add_read(thread->master, smtp_read_thread, smtp_arg,
			smtp_arg->fd, data->smtp_connection_to);
	return 0;
}

/* SMTP protocol handlers */
static int
smtp_read_thread(thread_t * thread)
{
	smtp_thread_arg *smtp_arg;
	char *buffer;
	char *reply;
	int rcv_buffer_size = 0;
	int status = -1;

	smtp_arg = THREAD_ARG(thread);

	if (thread->type == THREAD_READ_TIMEOUT) {
		log_message(LOG_INFO, "Timeout reading data to remote SMTP server [%s:%d]."
				    , inet_sockaddrtos(&data->smtp_server), SMTP_PORT);
		SMTP_FSM_READ(QUIT, thread, 0);
		return -1;
	}

	buffer = smtp_arg->buffer;

	rcv_buffer_size = read(thread->u.fd, buffer + smtp_arg->buflen,
			       SMTP_BUFFER_LENGTH - smtp_arg->buflen);

	if (rcv_buffer_size == -1) {
		if (errno == EAGAIN)
			goto end;
		log_message(LOG_INFO, "Error reading data from remote SMTP server [%s:%d]."
				    , inet_sockaddrtos(&data->smtp_server), SMTP_PORT);
		SMTP_FSM_READ(QUIT, thread, 0);
		return 0;
	}

	/* received data overflow buffer size ? */
	if (smtp_arg->buflen >= SMTP_BUFFER_MAX) {
		log_message(LOG_INFO, "Received buffer from remote SMTP server [%s:%d]"
				      " overflow our get read buffer length."
				    , inet_sockaddrtos(&data->smtp_server), SMTP_PORT);
		SMTP_FSM_READ(QUIT, thread, 0);
		return 0;
	} else {
		smtp_arg->buflen += rcv_buffer_size;
		buffer[smtp_arg->buflen] = 0;	/* NULL terminate */
	}

      end:

	/* parse the buffer, finding the last line of the response for the code */
	reply = buffer;
	while (reply < buffer + smtp_arg->buflen) {
		char *p;

		p = strstr(reply, "\r\n");
		if (!p) {
			memmove(buffer, reply,
				smtp_arg->buflen - (reply - buffer));
			smtp_arg->buflen -= (reply - buffer);
			buffer[smtp_arg->buflen] = 0;

			thread_add_read(thread->master, smtp_read_thread,
					smtp_arg, thread->u.fd,
					data->smtp_connection_to);
			return 0;
		}

		if (reply[3] == '-') {
			/* Skip over the \r\n */
			reply = p + 2;
			continue;
		}

		status = ((reply[0] - '0') * 100) + ((reply[1] - '0') * 10) + (reply[2] - '0');

		reply = p + 2;
		break;
	}

	memmove(buffer, reply, smtp_arg->buflen - (reply - buffer));
	smtp_arg->buflen -= (reply - buffer);
	buffer[smtp_arg->buflen] = 0;

	if (status == -1) {
		thread_add_read(thread->master, smtp_read_thread, smtp_arg,
				thread->u.fd, data->smtp_connection_to);
		return 0;
	}

	SMTP_FSM_READ(smtp_arg->stage, thread, status);

	/* Registering next smtp command processing thread */
	if (smtp_arg->stage != ERROR) {
		thread_add_write(thread->master, smtp_send_thread, smtp_arg,
				 smtp_arg->fd, data->smtp_connection_to);
	} else {
		log_message(LOG_INFO, "Can not read data from remote SMTP server [%s:%d]."
				    , inet_sockaddrtos(&data->smtp_server), SMTP_PORT);
		SMTP_FSM_READ(QUIT, thread, 0);
	}

	return 0;
}

static int
smtp_send_thread(thread_t * thread)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);

	if (thread->type == THREAD_WRITE_TIMEOUT) {
		log_message(LOG_INFO, "Timeout sending data to remote SMTP server [%s:%d]."
				    , inet_sockaddrtos(&data->smtp_server), SMTP_PORT);
		SMTP_FSM_READ(QUIT, thread, 0);
		return 0;
	}

	SMTP_FSM_SEND(smtp_arg->stage, thread);

	/* Handle END command */
	if (smtp_arg->stage == END) {
		SMTP_FSM_READ(QUIT, thread, 0);
		return 0;
	}

	/* Registering next smtp command processing thread */
	if (smtp_arg->stage != ERROR) {
		thread_add_read(thread->master, smtp_read_thread, smtp_arg,
				thread->u.fd, data->smtp_connection_to);
	} else {
		log_message(LOG_INFO,
		       "Can not send data to remote SMTP server [%s:%d].",
		       inet_sockaddrtos(&data->smtp_server), SMTP_PORT);
		SMTP_FSM_READ(QUIT, thread, 0);
	}

	return 0;
}

static int
connection_code(thread_t * thread, int status)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);

	if (status == 220) {
		smtp_arg->stage++;
	} else {
		log_message(LOG_INFO, "Error connecting SMTP server[%s:%d]."
		       " SMTP status code = %d", inet_sockaddrtos(&data->smtp_server),
		       SMTP_PORT, status);
		smtp_arg->stage = ERROR;
	}

	return 0;
}

/* HELO command processing */
static int
helo_cmd(thread_t * thread)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);
	char *buffer;

	buffer = (char *) MALLOC(SMTP_BUFFER_MAX);
	snprintf(buffer, SMTP_BUFFER_MAX, SMTP_HELO_CMD, get_local_name());
	if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
		smtp_arg->stage = ERROR;
	FREE(buffer);

	return 0;
}
static int
helo_code(thread_t * thread, int status)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);

	if (status == 250) {
		smtp_arg->stage++;
	} else {
		log_message(LOG_INFO,
		       "Error processing HELO cmd on SMTP server [%s:%d]."
		       " SMTP status code = %d", inet_sockaddrtos(&data->smtp_server),
		       SMTP_PORT, status);
		smtp_arg->stage = ERROR;
	}

	return 0;
}

/* MAIL command processing */
static int
mail_cmd(thread_t * thread)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);
	char *buffer;

	buffer = (char *) MALLOC(SMTP_BUFFER_MAX);
	snprintf(buffer, SMTP_BUFFER_MAX, SMTP_MAIL_CMD, data->email_from);
	if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
		smtp_arg->stage = ERROR;
	FREE(buffer);

	return 0;
}
static int
mail_code(thread_t * thread, int status)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);

	if (status == 250) {
		smtp_arg->stage++;
	} else {
		log_message(LOG_INFO,
		       "Error processing MAIL cmd on SMTP server [%s:%d]."
		       " SMTP status code = %d", inet_sockaddrtos(&data->smtp_server),
		       SMTP_PORT, status);
		smtp_arg->stage = ERROR;
	}

	return 0;
}

/* RCPT command processing */
static int
rcpt_cmd(thread_t * thread)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);
	char *buffer;
	char *fetched_email;

	buffer = (char *) MALLOC(SMTP_BUFFER_MAX);
	/* We send RCPT TO command multiple time to add all our email receivers.
	 * --rfc821.3.1
	 */
	fetched_email = fetch_next_email(smtp_arg);

	snprintf(buffer, SMTP_BUFFER_MAX, SMTP_RCPT_CMD, fetched_email);
	if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
		smtp_arg->stage = ERROR;
	FREE(buffer);

	return 0;
}
static int
rcpt_code(thread_t * thread, int status)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);
	char *fetched_email;

	if (status == 250) {
		smtp_arg->email_it++;

		fetched_email = fetch_next_email(smtp_arg);

		if (!fetched_email)
			smtp_arg->stage++;
	} else {
		log_message(LOG_INFO,
		       "Error processing RCPT cmd on SMTP server [%s:%d]."
		       " SMTP status code = %d", inet_sockaddrtos(&data->smtp_server),
		       SMTP_PORT, status);
		smtp_arg->stage = ERROR;
	}

	return 0;
}

/* DATA command processing */
static int
data_cmd(thread_t * thread)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);

	if (send(thread->u.fd, SMTP_DATA_CMD, strlen(SMTP_DATA_CMD), 0) == -1)
		smtp_arg->stage = ERROR;
	return 0;
}
static int
data_code(thread_t * thread, int status)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);

	if (status == 354) {
		smtp_arg->stage++;
	} else {
		log_message(LOG_INFO,
		       "Error processing DATA cmd on SMTP server [%s:%d]."
		       " SMTP status code = %d", inet_sockaddrtos(&data->smtp_server),
		       SMTP_PORT, status);
		smtp_arg->stage = ERROR;
	}

	return 0;
}

/* BODY command processing.
 * Do we need to use mutli-thread for multi-part body
 * handling ? Don t really think :)
 */
static int
body_cmd(thread_t * thread)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);
	char *buffer;
	char rfc822[80];
	time_t tm;

	buffer = (char *) MALLOC(SMTP_BUFFER_MAX);

	time(&tm);
	strftime(rfc822, sizeof(rfc822), "%a, %d %b %Y %H:%M:%S %z", gmtime(&tm));

	snprintf(buffer, SMTP_BUFFER_MAX, SMTP_HEADERS_CMD,
		 rfc822, data->email_from, smtp_arg->subject);

	/* send the subject field */
	if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
		smtp_arg->stage = ERROR;

	memset(buffer, 0, SMTP_BUFFER_MAX);
	snprintf(buffer, SMTP_BUFFER_MAX, SMTP_BODY_CMD, smtp_arg->body);

	/* send the the body field */
	if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
		smtp_arg->stage = ERROR;

	/* send the sending dot */
	if (send(thread->u.fd, SMTP_SEND_CMD, strlen(SMTP_SEND_CMD), 0)
	    == -1)
		smtp_arg->stage = ERROR;

	FREE(buffer);
	return 0;
}
static int
body_code(thread_t * thread, int status)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);

	if (status == 250) {
		log_message(LOG_INFO, "SMTP alert successfully sent.");
		smtp_arg->stage++;
	} else {
		log_message(LOG_INFO,
		       "Error processing DOT cmd on SMTP server [%s:%d]."
		       " SMTP status code = %d", inet_sockaddrtos(&data->smtp_server),
		       SMTP_PORT, status);
		smtp_arg->stage = ERROR;
	}

	return 0;
}

/* QUIT command processing */
static int
quit_cmd(thread_t * thread)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);

	if (send(thread->u.fd, SMTP_QUIT_CMD, strlen(SMTP_QUIT_CMD), 0) == -1)
		smtp_arg->stage = ERROR;
	else
		smtp_arg->stage++;
	return 0;
}
static int
quit_code(thread_t * thread, int status)
{
	smtp_thread_arg *smtp_arg = THREAD_ARG(thread);

	/* final state, we are disconnected from the remote host */
	free_smtp_all(smtp_arg);
	close(thread->u.fd);
	return 0;
}

/* connect remote SMTP server */
static void
smtp_connect(smtp_thread_arg * smtp_arg)
{
	enum connect_result status;

	if ((smtp_arg->fd = socket(data->smtp_server.ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		DBG("SMTP connect fail to create socket.");
		free_smtp_all(smtp_arg);
		return;
	}

	status = tcp_connect(smtp_arg->fd, &data->smtp_server);

	/* Handle connection status code */
	thread_add_event(master, SMTP_FSM[status].send, smtp_arg, smtp_arg->fd);
}

/* Main entry point */
void
smtp_alert(real_server * rs, vrrp_rt * vrrp,
	   vrrp_sgroup * vgroup, const char *subject, const char *body)
{
	smtp_thread_arg *smtp_arg;

	/* Only send mail if email specified */
	if (!LIST_ISEMPTY(data->email) && data->smtp_server.ss_family != 0) {
		/* allocate & initialize smtp argument data structure */
		smtp_arg = (smtp_thread_arg *) MALLOC(sizeof (smtp_thread_arg));
		smtp_arg->subject = (char *) MALLOC(MAX_HEADERS_LENGTH);
		smtp_arg->body = (char *) MALLOC(MAX_BODY_LENGTH);
		smtp_arg->buffer = (char *) MALLOC(SMTP_BUFFER_MAX);

		/* format subject if rserver is specified */
		if (rs) {
			snprintf(smtp_arg->subject, MAX_HEADERS_LENGTH, "[%s] Realserver %s:%d - %s"
				 , data->router_id, inet_sockaddrtos(&rs->addr)
				 , ntohs(inet_sockaddrport(&rs->addr))
				 , subject);
		} else if (vrrp)
			snprintf(smtp_arg->subject, MAX_HEADERS_LENGTH,
				 "[%s] VRRP Instance %s - %s",
				 data->router_id, vrrp->iname, subject);
		else if (vgroup)
			snprintf(smtp_arg->subject, MAX_HEADERS_LENGTH,
				 "[%s] VRRP Group %s - %s",
				 data->router_id, vgroup->gname, subject);
		else if (data->router_id)
			snprintf(smtp_arg->subject, MAX_HEADERS_LENGTH,
				 "[%s] %s", data->router_id, subject);
		else
			snprintf(smtp_arg->subject, MAX_HEADERS_LENGTH, "%s",
				 subject);

		strncpy(smtp_arg->body, body, MAX_BODY_LENGTH);

		smtp_connect(smtp_arg);
	}
}
