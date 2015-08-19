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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
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
free_smtp_all(smtp_t * smtp)
{
	FREE(smtp->buffer);
	FREE(smtp->subject);
	FREE(smtp->body);
	FREE(smtp->email_to);
	FREE(smtp);
}

static char *
fetch_next_email(smtp_t * smtp)
{
	return list_element(global_data->email, smtp->email_it);
}

/* layer4 connection handlers */
static int
connection_error(thread_t * thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	log_message(LOG_INFO, "SMTP connection ERROR to %s."
			    , FMT_SMTP_HOST());
	free_smtp_all(smtp);
	return 0;
}
static int
connection_timeout(thread_t * thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	log_message(LOG_INFO, "Timeout connecting SMTP server %s."
			    , FMT_SMTP_HOST());
	free_smtp_all(smtp);
	return 0;
}
static int
connection_in_progress(thread_t * thread)
{
	int status;

	DBG("SMTP connection to %s now IN_PROGRESS.",
	    FMT_SMTP_HOST());

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
	smtp_t *smtp = THREAD_ARG(thread);

	log_message(LOG_INFO, "Remote SMTP server %s connected."
			    , FMT_SMTP_HOST());

	smtp->stage = connect_success;
	thread_add_read(thread->master, smtp_read_thread, smtp,
			smtp->fd, global_data->smtp_connection_to);
	return 0;
}

/* SMTP protocol handlers */
static int
smtp_read_thread(thread_t * thread)
{
	smtp_t *smtp;
	char *buffer;
	char *reply;
	int rcv_buffer_size = 0;
	int status = -1;

	smtp = THREAD_ARG(thread);

	if (thread->type == THREAD_READ_TIMEOUT) {
		log_message(LOG_INFO, "Timeout reading data to remote SMTP server %s."
				    , FMT_SMTP_HOST());
		SMTP_FSM_READ(QUIT, thread, 0);
		return -1;
	}

	buffer = smtp->buffer;

	rcv_buffer_size = read(thread->u.fd, buffer + smtp->buflen,
			       SMTP_BUFFER_LENGTH - smtp->buflen);

	if (rcv_buffer_size == -1) {
		if (errno == EAGAIN)
			goto end;
		log_message(LOG_INFO, "Error reading data from remote SMTP server %s."
				    , FMT_SMTP_HOST());
		SMTP_FSM_READ(QUIT, thread, 0);
		return 0;
	} else if (rcv_buffer_size == 0) {
		log_message(LOG_INFO, "Remote SMTP server %s has closed the connection."
				    , FMT_SMTP_HOST());
		SMTP_FSM_READ(QUIT, thread, 0);
		return 0;
	}

	/* received data overflow buffer size ? */
	if (smtp->buflen >= SMTP_BUFFER_MAX) {
		log_message(LOG_INFO, "Received buffer from remote SMTP server %s"
				      " overflow our get read buffer length."
				    , FMT_SMTP_HOST());
		SMTP_FSM_READ(QUIT, thread, 0);
		return 0;
	} else {
		smtp->buflen += rcv_buffer_size;
		buffer[smtp->buflen] = 0;	/* NULL terminate */
	}

      end:

	/* parse the buffer, finding the last line of the response for the code */
	reply = buffer;
	while (reply < buffer + smtp->buflen) {
		char *p;

		p = strstr(reply, "\r\n");
		if (!p) {
			memmove(buffer, reply,
				smtp->buflen - (reply - buffer));
			smtp->buflen -= (reply - buffer);
			buffer[smtp->buflen] = 0;

			thread_add_read(thread->master, smtp_read_thread,
					smtp, thread->u.fd,
					global_data->smtp_connection_to);
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

	memmove(buffer, reply, smtp->buflen - (reply - buffer));
	smtp->buflen -= (reply - buffer);
	buffer[smtp->buflen] = 0;

	if (status == -1) {
		thread_add_read(thread->master, smtp_read_thread, smtp,
				thread->u.fd, global_data->smtp_connection_to);
		return 0;
	}

	SMTP_FSM_READ(smtp->stage, thread, status);

	/* Registering next smtp command processing thread */
	if (smtp->stage != ERROR) {
		thread_add_write(thread->master, smtp_send_thread, smtp,
				 smtp->fd, global_data->smtp_connection_to);
	} else {
		log_message(LOG_INFO, "Can not read data from remote SMTP server %s."
				    , FMT_SMTP_HOST());
		SMTP_FSM_READ(QUIT, thread, 0);
	}

	return 0;
}

static int
smtp_send_thread(thread_t * thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	if (thread->type == THREAD_WRITE_TIMEOUT) {
		log_message(LOG_INFO, "Timeout sending data to remote SMTP server %s."
				    , FMT_SMTP_HOST());
		SMTP_FSM_READ(QUIT, thread, 0);
		return 0;
	}

	SMTP_FSM_SEND(smtp->stage, thread);

	/* Handle END command */
	if (smtp->stage == END) {
		SMTP_FSM_READ(QUIT, thread, 0);
		return 0;
	}

	/* Registering next smtp command processing thread */
	if (smtp->stage != ERROR) {
		thread_add_read(thread->master, smtp_read_thread, smtp,
				thread->u.fd, global_data->smtp_connection_to);
	} else {
		log_message(LOG_INFO, "Can not send data to remote SMTP server %s."
				    , FMT_SMTP_HOST());
		SMTP_FSM_READ(QUIT, thread, 0);
	}

	return 0;
}

static int
connection_code(thread_t * thread, int status)
{
	smtp_t *smtp = THREAD_ARG(thread);

	if (status == 220) {
		smtp->stage++;
	} else {
		log_message(LOG_INFO, "Error connecting SMTP server %s."
				      " SMTP status code = %d"
				    , FMT_SMTP_HOST()
				    , status);
		smtp->stage = ERROR;
	}

	return 0;
}

/* HELO command processing */
static int
helo_cmd(thread_t * thread)
{
	smtp_t *smtp = THREAD_ARG(thread);
	char *name;
	char *buffer;

	buffer = (char *) MALLOC(SMTP_BUFFER_MAX);
	name = get_local_name();
	snprintf(buffer, SMTP_BUFFER_MAX, SMTP_HELO_CMD, (name) ? name : "localhost");
	if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
		smtp->stage = ERROR;
	FREE(buffer);
	FREE_PTR(name);

	return 0;
}
static int
helo_code(thread_t * thread, int status)
{
	smtp_t *smtp = THREAD_ARG(thread);

	if (status == 250) {
		smtp->stage++;
	} else {
		log_message(LOG_INFO, "Error processing HELO cmd on SMTP server %s."
				      " SMTP status code = %d"
				    , FMT_SMTP_HOST()
				    , status);
		smtp->stage = ERROR;
	}

	return 0;
}

/* MAIL command processing */
static int
mail_cmd(thread_t * thread)
{
	smtp_t *smtp = THREAD_ARG(thread);
	char *buffer;

	buffer = (char *) MALLOC(SMTP_BUFFER_MAX);
	snprintf(buffer, SMTP_BUFFER_MAX, SMTP_MAIL_CMD, global_data->email_from);
	if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
		smtp->stage = ERROR;
	FREE(buffer);

	return 0;
}
static int
mail_code(thread_t * thread, int status)
{
	smtp_t *smtp = THREAD_ARG(thread);

	if (status == 250) {
		smtp->stage++;
	} else {
		log_message(LOG_INFO, "Error processing MAIL cmd on SMTP server %s."
				      " SMTP status code = %d"
				    , FMT_SMTP_HOST()
				    , status);
		smtp->stage = ERROR;
	}

	return 0;
}

/* RCPT command processing */
static int
rcpt_cmd(thread_t * thread)
{
	smtp_t *smtp = THREAD_ARG(thread);
	char *buffer;
	char *fetched_email;

	buffer = (char *) MALLOC(SMTP_BUFFER_MAX);
	/* We send RCPT TO command multiple time to add all our email receivers.
	 * --rfc821.3.1
	 */
	fetched_email = fetch_next_email(smtp);

	snprintf(buffer, SMTP_BUFFER_MAX, SMTP_RCPT_CMD, fetched_email);
	if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
		smtp->stage = ERROR;
	FREE(buffer);

	return 0;
}
static int
rcpt_code(thread_t * thread, int status)
{
	smtp_t *smtp = THREAD_ARG(thread);
	char *fetched_email;

	if (status == 250) {
		smtp->email_it++;

		fetched_email = fetch_next_email(smtp);

		if (!fetched_email)
			smtp->stage++;
	} else {
		log_message(LOG_INFO, "Error processing RCPT cmd on SMTP server %s."
				      " SMTP status code = %d"
				    , FMT_SMTP_HOST()
				    , status);
		smtp->stage = ERROR;
	}

	return 0;
}

/* DATA command processing */
static int
data_cmd(thread_t * thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	if (send(thread->u.fd, SMTP_DATA_CMD, strlen(SMTP_DATA_CMD), 0) == -1)
		smtp->stage = ERROR;
	return 0;
}
static int
data_code(thread_t * thread, int status)
{
	smtp_t *smtp = THREAD_ARG(thread);

	if (status == 354) {
		smtp->stage++;
	} else {
		log_message(LOG_INFO, "Error processing DATA cmd on SMTP server %s."
				      " SMTP status code = %d"
				    , FMT_SMTP_HOST()
				    , status);
		smtp->stage = ERROR;
	}

	return 0;
}

/* 
 * Build a comma separated string of smtp recipient email addresses
 * for the email message To-header.
 */
void
build_to_header_rcpt_addrs(smtp_t *smtp)
{
	char *fetched_email;
	char *email_to_addrs;
	int bytes_available = SMTP_BUFFER_MAX - 1;
	int bytes_not_written, bytes_to_write;

	if (smtp == NULL)
		return;

	email_to_addrs = smtp->email_to;
	smtp->email_it = 0;

	while (1) {
		fetched_email = fetch_next_email(smtp);
		if (fetched_email == NULL)
			break;

		bytes_not_written = 0;
		bytes_to_write = strlen(fetched_email);
		if (smtp->email_it == 0) {
			if (bytes_available < bytes_to_write)
				break;
		} else {
			if (bytes_available < 2 + bytes_to_write)
				break;

			/* Prepend with a comma and space to all non-first email addresses */
			*email_to_addrs++ = ',';
			*email_to_addrs++ = ' ';
			bytes_available -= 2;
		}

		bytes_not_written = snprintf(email_to_addrs, bytes_to_write + 1, "%s", fetched_email) - bytes_to_write;;
		if (bytes_not_written > 0) {
			/* Inconsistent state, no choice but to break here and do nothing */
			break;
		}

		email_to_addrs += bytes_to_write;
		bytes_available -= bytes_to_write;
		smtp->email_it++;
	}

	smtp->email_it = 0;
}

/* BODY command processing.
 * Do we need to use mutli-thread for multi-part body
 * handling ? Don t really think :)
 */
static int
body_cmd(thread_t * thread)
{
	smtp_t *smtp = THREAD_ARG(thread);
	char *buffer;
	char rfc822[80];
	time_t tm;
	struct tm *t;

	buffer = (char *) MALLOC(SMTP_BUFFER_MAX);

	time(&tm);
	t = localtime(&tm);
	strftime(rfc822, sizeof(rfc822), "%a, %d %b %Y %H:%M:%S %z", t);

	snprintf(buffer, SMTP_BUFFER_MAX, SMTP_HEADERS_CMD,
		 rfc822, global_data->email_from, smtp->subject, smtp->email_to);

	/* send the subject field */
	if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
		smtp->stage = ERROR;

	memset(buffer, 0, SMTP_BUFFER_MAX);
	snprintf(buffer, SMTP_BUFFER_MAX, SMTP_BODY_CMD, smtp->body);

	/* send the the body field */
	if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
		smtp->stage = ERROR;

	/* send the sending dot */
	if (send(thread->u.fd, SMTP_SEND_CMD, strlen(SMTP_SEND_CMD), 0) == -1)
		smtp->stage = ERROR;

	FREE(buffer);
	return 0;
}
static int
body_code(thread_t * thread, int status)
{
	smtp_t *smtp = THREAD_ARG(thread);

	if (status == 250) {
		log_message(LOG_INFO, "SMTP alert successfully sent.");
		smtp->stage++;
	} else {
		log_message(LOG_INFO, "Error processing DOT cmd on SMTP server %s."
				      " SMTP status code = %d"
				    , FMT_SMTP_HOST()
				    , status);
		smtp->stage = ERROR;
	}

	return 0;
}

/* QUIT command processing */
static int
quit_cmd(thread_t * thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	if (send(thread->u.fd, SMTP_QUIT_CMD, strlen(SMTP_QUIT_CMD), 0) == -1)
		smtp->stage = ERROR;
	else
		smtp->stage++;
	return 0;
}
static int
quit_code(thread_t * thread, int status)
{
	smtp_t *smtp = THREAD_ARG(thread);

	/* final state, we are disconnected from the remote host */
	free_smtp_all(smtp);
	close(thread->u.fd);
	return 0;
}

/* connect remote SMTP server */
static void
smtp_connect(smtp_t * smtp)
{
	enum connect_result status;

	if ((smtp->fd = socket(global_data->smtp_server.ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		DBG("SMTP connect fail to create socket.");
		free_smtp_all(smtp);
		return;
	}

	status = tcp_connect(smtp->fd, &global_data->smtp_server);

	/* Handle connection status code */
	thread_add_event(master, SMTP_FSM[status].send, smtp, smtp->fd);
}

/* Main entry point */
void
smtp_alert(real_server_t * rs, vrrp_t * vrrp,
	   vrrp_sgroup_t * vgroup, const char *subject, const char *body)
{
	smtp_t *smtp;

	/* Only send mail if email specified */
	if (!LIST_ISEMPTY(global_data->email) && global_data->smtp_server.ss_family != 0) {
		/* allocate & initialize smtp argument data structure */
		smtp = (smtp_t *) MALLOC(sizeof(smtp_t));
		smtp->subject = (char *) MALLOC(MAX_HEADERS_LENGTH);
		smtp->body = (char *) MALLOC(MAX_BODY_LENGTH);
		smtp->buffer = (char *) MALLOC(SMTP_BUFFER_MAX);
		smtp->email_to = (char *) MALLOC(SMTP_BUFFER_MAX);

		/* format subject if rserver is specified */
		if (rs) {
			snprintf(smtp->subject, MAX_HEADERS_LENGTH, "[%s] Realserver %s - %s"
					      , global_data->router_id
					      , FMT_RS(rs)
					      , subject);
		} else if (vrrp)
			snprintf(smtp->subject, MAX_HEADERS_LENGTH, "[%s] VRRP Instance %s - %s"
					      , global_data->router_id
					      , vrrp->iname
					      , subject);
		else if (vgroup)
			snprintf(smtp->subject, MAX_HEADERS_LENGTH, "[%s] VRRP Group %s - %s"
					      , global_data->router_id
					      , vgroup->gname
					      , subject);
		else if (global_data->router_id)
			snprintf(smtp->subject, MAX_HEADERS_LENGTH, "[%s] %s"
					      , global_data->router_id
					      , subject);
		else
			snprintf(smtp->subject, MAX_HEADERS_LENGTH, "%s", subject);

		strncpy(smtp->body, body, MAX_BODY_LENGTH);
		build_to_header_rcpt_addrs(smtp);

		smtp_connect(smtp);
	}
}
