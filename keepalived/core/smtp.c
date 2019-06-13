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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <errno.h>
#include <unistd.h>
#include <time.h>

#include "smtp.h"
#include "memory.h"
#include "layer4.h"
#include "logger.h"
#include "utils.h"
#if !HAVE_DECL_SOCK_CLOEXEC
#include "old_socket.h"
#endif
#ifdef _WITH_LVS_
#include "check_api.h"
#endif
#ifdef THREAD_DUMP
#include "scheduler.h"
#endif
#ifdef _SMTP_ALERT_DEBUG_
bool do_smtp_alert_debug;
#endif

/* SMTP FSM definition */
static int connection_error(thread_ref_t);
static int connection_in_progress(thread_ref_t);
static int connection_timeout(thread_ref_t);
static int connection_success(thread_ref_t);
static int helo_cmd(thread_ref_t);
static int mail_cmd(thread_ref_t);
static int rcpt_cmd(thread_ref_t);
static int data_cmd(thread_ref_t);
static int body_cmd(thread_ref_t);
static int quit_cmd(thread_ref_t);

static int connection_code(thread_ref_t , int);
static int helo_code(thread_ref_t , int);
static int mail_code(thread_ref_t , int);
static int rcpt_code(thread_ref_t , int);
static int data_code(thread_ref_t , int);
static int body_code(thread_ref_t , int);
static int quit_code(thread_ref_t , int);

static int smtp_read_thread(thread_ref_t);
static int smtp_send_thread(thread_ref_t);

struct {
	int (*send) (thread_ref_t);
	int (*read) (thread_ref_t, int);
} SMTP_FSM[SMTP_MAX_FSM_STATE] = {
/*       Code			  Stream Write Handlers		Stream Read handlers *
 *------------------------------+----------------------------------------------------*/
	[connect_error]		= {connection_error,		NULL},
	[connect_in_progress]	= {connection_in_progress,	NULL},
	[connect_timeout]	= {connection_timeout,		NULL},
	[connect_fail]		= {connection_error,		NULL},
	[connect_success]	= {connection_success,		connection_code},
	[HELO]			= {helo_cmd,			helo_code},
	[MAIL]			= {mail_cmd,			mail_code},
	[RCPT]			= {rcpt_cmd,			rcpt_code},
	[DATA]			= {data_cmd,			data_code},
	[BODY]			= {body_cmd,			body_code},
	[QUIT]			= {quit_cmd,			quit_code}
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

/* layer4 connection handlers */
static int
connection_error(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	log_message(LOG_INFO, "SMTP connection ERROR to %s."
			    , FMT_SMTP_HOST());
	free_smtp_all(smtp);
	return 0;
}
static int
connection_timeout(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	log_message(LOG_INFO, "Timeout connecting SMTP server %s."
			    , FMT_SMTP_HOST());
	free_smtp_all(smtp);
	return 0;
}
static int
connection_in_progress(thread_ref_t thread)
{
	int status;

	DBG("SMTP connection to %s now IN_PROGRESS.",
	    FMT_SMTP_HOST());

	/*
	 * Here we use the propriety of a union structure,
	 * each element of the structure have the same value.
	 */
	status = tcp_socket_state(thread, connection_in_progress);

	if (status != connect_in_progress)
		SMTP_FSM_SEND(status, thread);

	return 0;
}
static int
connection_success(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	log_message(LOG_INFO, "Remote SMTP server %s connected."
			    , FMT_SMTP_HOST());

	smtp->stage = connect_success;
	thread_add_read(thread->master, smtp_read_thread, smtp,
			smtp->fd, global_data->smtp_connection_to, true);
	return 0;
}

/* SMTP protocol handlers */
static int
smtp_read_thread(thread_ref_t thread)
{
	smtp_t *smtp;
	char *buffer;
	char *reply;
	ssize_t rcv_buffer_size;
	int status = -1;

	smtp = THREAD_ARG(thread);

	if (thread->type == THREAD_READ_TIMEOUT) {
		log_message(LOG_INFO, "Timeout reading data to remote SMTP server %s."
				    , FMT_SMTP_HOST());
		SMTP_FSM_READ(QUIT, thread, 0);
		return -1;
	}

	buffer = smtp->buffer;

	rcv_buffer_size = read(thread->u.f.fd, buffer + smtp->buflen,
			       SMTP_BUFFER_LENGTH - 1 - smtp->buflen);

	if (rcv_buffer_size == -1) {
		if (check_EAGAIN(errno)) {
			thread_add_read(thread->master, smtp_read_thread, smtp,
					thread->u.f.fd, global_data->smtp_connection_to, true);
			return 0;
		}

		log_message(LOG_INFO, "Error reading data from remote SMTP server %s."
				    , FMT_SMTP_HOST());
		SMTP_FSM_READ(QUIT, thread, 0);
		return 0;
	}

	if (rcv_buffer_size == 0) {
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
	}

	smtp->buflen += (size_t)rcv_buffer_size;
	buffer[smtp->buflen] = 0;	/* NULL terminate */

	/* parse the buffer, finding the last line of the response for the code */
	reply = buffer;
	while (reply < buffer + smtp->buflen) {		// This line causes a strict-overflow=4 warning with gcc 5.4.0
		char *p;

		p = strstr(reply, "\r\n");
		if (!p) {
			memmove(buffer, reply,
				smtp->buflen - (size_t)(reply - buffer));
			smtp->buflen -= (size_t)(reply - buffer);
			buffer[smtp->buflen] = 0;

			thread_add_read(thread->master, smtp_read_thread,
					smtp, thread->u.f.fd,
					global_data->smtp_connection_to, true);
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

	memmove(buffer, reply, smtp->buflen - (size_t)(reply - buffer));
	smtp->buflen -= (size_t)(reply - buffer);
	buffer[smtp->buflen] = 0;

	if (status == -1) {
		thread_add_read(thread->master, smtp_read_thread, smtp,
				thread->u.f.fd, global_data->smtp_connection_to, true);
		return 0;
	}

	SMTP_FSM_READ(smtp->stage, thread, status);

	/* Registering next smtp command processing thread */
	if (smtp->stage != ERROR) {
		thread_add_write(thread->master, smtp_send_thread, smtp,
				 smtp->fd, global_data->smtp_connection_to, true);
	} else {
		log_message(LOG_INFO, "Can not read data from remote SMTP server %s."
				    , FMT_SMTP_HOST());
		SMTP_FSM_READ(QUIT, thread, 0);
	}

	return 0;
}

static int
smtp_send_thread(thread_ref_t thread)
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
				thread->u.f.fd, global_data->smtp_connection_to, true);
		thread_del_write(thread);
	} else {
		log_message(LOG_INFO, "Can not send data to remote SMTP server %s."
				    , FMT_SMTP_HOST());
		SMTP_FSM_READ(QUIT, thread, 0);
	}

	return 0;
}

static int
connection_code(thread_ref_t thread, int status)
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
helo_cmd(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);
	char *buffer;

	buffer = (char *) MALLOC(SMTP_BUFFER_MAX);
	snprintf(buffer, SMTP_BUFFER_MAX, SMTP_HELO_CMD, (global_data->smtp_helo_name) ? global_data->smtp_helo_name : "localhost");
	if (send(thread->u.f.fd, buffer, strlen(buffer), 0) == -1)
		smtp->stage = ERROR;
	FREE(buffer);

	return 0;
}
static int
helo_code(thread_ref_t thread, int status)
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
mail_cmd(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);
	char *buffer;

	buffer = (char *) MALLOC(SMTP_BUFFER_MAX);
	snprintf(buffer, SMTP_BUFFER_MAX, SMTP_MAIL_CMD, global_data->email_from);
	if (send(thread->u.f.fd, buffer, strlen(buffer), 0) == -1)
		smtp->stage = ERROR;
	FREE(buffer);

	return 0;
}
static int
mail_code(thread_ref_t thread, int status)
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
rcpt_cmd(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);
	char *buffer;
	char *fetched_email;

	buffer = (char *) MALLOC(SMTP_BUFFER_MAX);
	/* We send RCPT TO command multiple time to add all our email receivers.
	 * --rfc821.3.1
	 */
	fetched_email = ELEMENT_DATA(smtp->next_email_element);
	ELEMENT_NEXT(smtp->next_email_element);

	snprintf(buffer, SMTP_BUFFER_MAX, SMTP_RCPT_CMD, fetched_email);
	if (send(thread->u.f.fd, buffer, strlen(buffer), 0) == -1)
		smtp->stage = ERROR;
	FREE(buffer);

	return 0;
}
static int
rcpt_code(thread_ref_t thread, int status)
{
	smtp_t *smtp = THREAD_ARG(thread);

	if (status == 250) {
		if (!smtp->next_email_element)
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
data_cmd(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	if (send(thread->u.f.fd, SMTP_DATA_CMD, strlen(SMTP_DATA_CMD), 0) == -1)
		smtp->stage = ERROR;
	return 0;
}
static int
data_code(thread_ref_t thread, int status)
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

/* BODY command processing.
 * Do we need to use mutli-thread for multi-part body
 * handling ? Don t really think :)
 */
static int
body_cmd(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);
	char *buffer;
	char rfc822[80];
	time_t now;
	struct tm *t;

	buffer = (char *) MALLOC(SMTP_BUFFER_MAX);

	time(&now);
	t = localtime(&now);
	strftime(rfc822, sizeof(rfc822), "%a, %d %b %Y %H:%M:%S %z", t);

	snprintf(buffer, SMTP_BUFFER_MAX, SMTP_HEADERS_CMD,
		 rfc822, global_data->email_from, smtp->subject, smtp->email_to);

	/* send the subject field */
	if (send(thread->u.f.fd, buffer, strlen(buffer), 0) == -1)
		smtp->stage = ERROR;

	memset(buffer, 0, SMTP_BUFFER_MAX);
	snprintf(buffer, SMTP_BUFFER_MAX, SMTP_BODY_CMD, smtp->body);

	/* send the the body field */
	if (send(thread->u.f.fd, buffer, strlen(buffer), 0) == -1)
		smtp->stage = ERROR;

	/* send the sending dot */
	if (send(thread->u.f.fd, SMTP_SEND_CMD, strlen(SMTP_SEND_CMD), 0) == -1)
		smtp->stage = ERROR;

	FREE(buffer);
	return 0;
}
static int
body_code(thread_ref_t thread, int status)
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
quit_cmd(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	if (send(thread->u.f.fd, SMTP_QUIT_CMD, strlen(SMTP_QUIT_CMD), 0) == -1)
		smtp->stage = ERROR;
	else
		smtp->stage++;
	return 0;
}

static int
quit_code(thread_ref_t thread, __attribute__((unused)) int status)
{
	smtp_t *smtp = THREAD_ARG(thread);

	/* final state, we are disconnected from the remote host */
	free_smtp_all(smtp);
	thread_close_fd(thread);
	return 0;
}

/* connect remote SMTP server */
static void
smtp_connect(smtp_t *smtp)
{
	enum connect_result status;

	smtp->next_email_element = LIST_HEAD(global_data->email);

	if ((smtp->fd = socket(global_data->smtp_server.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP)) == -1) {
		DBG("SMTP connect fail to create socket.");
		free_smtp_all(smtp);
		return;
	}

#if !HAVE_DECL_SOCK_NONBLOCK
	if (set_sock_flags(smtp->fd, F_SETFL, O_NONBLOCK))
		log_message(LOG_INFO, "Unable to set NONBLOCK on smtp_connect socket - %s (%d)", strerror(errno), errno);
#endif

#if !HAVE_DECL_SOCK_CLOEXEC
	if (set_sock_flags(smtp->fd, F_SETFD, FD_CLOEXEC))
		log_message(LOG_INFO, "Unable to set CLOEXEC on smtp_connect socket - %s (%d)", strerror(errno), errno);
#endif

	status = tcp_connect(smtp->fd, &global_data->smtp_server);

	/* Handle connection status code */
	thread_add_event(master, SMTP_FSM[status].send, smtp, smtp->fd);
}

#ifdef _SMTP_ALERT_DEBUG_
static void
smtp_log_to_file(smtp_t *smtp)
{
	FILE *fp = fopen_safe("/tmp/smtp-alert.log", "a");
	time_t now;
	struct tm tm;
	char time_buf[25];
	int time_buf_len;

	time(&now);
	localtime_r(&now, &tm);
	time_buf_len = strftime(time_buf, sizeof time_buf, "%a %b %e %X %Y", &tm);

	fprintf(fp, "%s: %s -> %s\n"
		    "%*sSubject: %s\n"
		    "%*sBody:    %s\n\n",
		    time_buf, global_data->email_from, smtp->email_to,
		    time_buf_len - 7, "", smtp->subject,
		    time_buf_len - 7, "", smtp->body);

	fclose(fp);

	free_smtp_all(smtp);
}
#endif

/*
 * Build a comma separated string of smtp recipient email addresses
 * for the email message To-header.
 */
static void
build_to_header_rcpt_addrs(smtp_t *smtp)
{
	const char *fetched_email;
	char *email_to_addrs;
	size_t bytes_available = SMTP_BUFFER_MAX - 1;
	size_t bytes_to_write;
	bool done_addr = false;
	element e;

	if (smtp == NULL)
		return;

	email_to_addrs = smtp->email_to;

	LIST_FOREACH(global_data->email, fetched_email, e) {
		bytes_to_write = strlen(fetched_email);
		if (done_addr) {
			if (bytes_available < 2)
				break;

			/* Prepend with a comma and space to all non-first email addresses */
			*email_to_addrs++ = ',';
			*email_to_addrs++ = ' ';
			bytes_available -= 2;
		}
		else
			done_addr = true;

		if (bytes_available < bytes_to_write)
			break;

		strcpy(email_to_addrs, fetched_email);

		email_to_addrs += bytes_to_write;
		bytes_available -= bytes_to_write;
	}
}

/* Main entry point */
void
smtp_alert(smtp_msg_t msg_type, void* data, const char *subject, const char *body)
{
	smtp_t *smtp;
#ifdef _WITH_VRRP_
	vrrp_t *vrrp;
	vrrp_sgroup_t *vgroup;
#endif
#ifdef _WITH_LVS_
	checker_t *checker;
	virtual_server_t *vs;
	smtp_rs *rs_info;
#endif

	/* Only send mail if email specified */
	if (LIST_ISEMPTY(global_data->email) || !global_data->smtp_server.ss_family)
		return;

	/* allocate & initialize smtp argument data structure */
	smtp = (smtp_t *) MALLOC(sizeof(smtp_t));
	smtp->subject = (char *) MALLOC(MAX_HEADERS_LENGTH);
	smtp->body = (char *) MALLOC(MAX_BODY_LENGTH);
	smtp->buffer = (char *) MALLOC(SMTP_BUFFER_MAX);
	smtp->email_to = (char *) MALLOC(SMTP_BUFFER_MAX);

	/* format subject if rserver is specified */
#ifdef _WITH_LVS_
	if (msg_type == SMTP_MSG_RS) {
		checker = (checker_t *)data;
		snprintf(smtp->subject, MAX_HEADERS_LENGTH, "[%s] Realserver %s of virtual server %s - %s",
					global_data->router_id,
					FMT_RS(checker->rs, checker->vs),
					FMT_VS(checker->vs),
					checker->rs->alive ? "UP" : "DOWN");
	}
	else if (msg_type == SMTP_MSG_VS) {
		vs = (virtual_server_t *)data;
		snprintf(smtp->subject, MAX_HEADERS_LENGTH, "[%s] Virtualserver %s - %s",
					global_data->router_id,
					FMT_VS(vs),
					subject);
	}
	else if (msg_type == SMTP_MSG_RS_SHUT) {
		rs_info = (smtp_rs *)data;
		snprintf(smtp->subject, MAX_HEADERS_LENGTH, "[%s] Realserver %s of virtual server %s - %s",
					global_data->router_id,
					FMT_RS(rs_info->rs, rs_info->vs),
					FMT_VS(rs_info->vs),
					subject);
	}
	else
#endif
#ifdef _WITH_VRRP_
	if (msg_type == SMTP_MSG_VRRP) {
		vrrp = (vrrp_t *)data;
		snprintf(smtp->subject, MAX_HEADERS_LENGTH, "[%s] VRRP Instance %s - %s",
					global_data->router_id,
					vrrp->iname,
					subject);
	} else if (msg_type == SMTP_MSG_VGROUP) {
		vgroup = (vrrp_sgroup_t *)data;
		snprintf(smtp->subject, MAX_HEADERS_LENGTH, "[%s] VRRP Group %s - %s",
					global_data->router_id,
					vgroup->gname,
					subject);
	}
	else
#endif
	if (global_data->router_id)
		snprintf(smtp->subject, MAX_HEADERS_LENGTH, "[%s] %s"
				      , global_data->router_id
				      , subject);
	else
		snprintf(smtp->subject, MAX_HEADERS_LENGTH, "%s", subject);

	strncpy(smtp->body, body, MAX_BODY_LENGTH - 1);
	smtp->body[MAX_BODY_LENGTH - 1]= '\0';

	build_to_header_rcpt_addrs(smtp);

#ifdef _SMTP_ALERT_DEBUG_
	if (do_smtp_alert_debug)
		smtp_log_to_file(smtp);
	else
#endif
	smtp_connect(smtp);
}

#ifdef THREAD_DUMP
void
register_smtp_addresses(void)
{
	register_thread_address("body_cmd", body_cmd);
	register_thread_address("connection_error", connection_error);
	register_thread_address("connection_in_progress", connection_in_progress);
	register_thread_address("connection_success", connection_success);
	register_thread_address("connection_timeout", connection_timeout);
	register_thread_address("data_cmd", data_cmd);
	register_thread_address("helo_cmd", helo_cmd);
	register_thread_address("mail_cmd", mail_cmd);
	register_thread_address("quit_cmd", quit_cmd);
	register_thread_address("rcpt_cmd", rcpt_cmd);
	register_thread_address("smtp_read_thread", smtp_read_thread);
	register_thread_address("smtp_send_thread", smtp_send_thread);
}
#endif
