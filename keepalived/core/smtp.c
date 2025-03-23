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
 * Copyright (C) 2001-2021 Alexandre Cassen, <acassen@gmail.com>
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
#ifdef _WITH_LVS_
#include "check_api.h"
#endif
#ifdef THREAD_DUMP
#include "scheduler.h"
#endif

/* If it suspected that one of subject, body or buffer
 * is overflowing in the smtp_t structure, defining SMTP_MSG_ALLOC_DEBUG
 * when using --enable-mem-check should help identity the issue
 */
//#define SMTP_MSG_ALLOC_DEBUG

#define SMTP_BUFFER_MAX         1024U

#ifdef _SMTP_ALERT_DEBUG_
bool do_smtp_alert_debug;
#endif
#ifdef _SMTP_CONNECT_DEBUG_
bool do_smtp_connect_debug;
#endif

static char smtp_send_buffer[SMTP_BUFFER_MAX];

/* SMTP FSM definition */
static void connection_error(thread_ref_t);
static void connection_in_progress(thread_ref_t);
static void connection_timeout(thread_ref_t);
static void connection_success(thread_ref_t);
static void helo_cmd(thread_ref_t);
static void mail_cmd(thread_ref_t);
static void rcpt_cmd(thread_ref_t);
static void data_cmd(thread_ref_t);
static void body_cmd(thread_ref_t);
static void quit_cmd(thread_ref_t);

static void rcpt_code(thread_ref_t);
static void body_code(thread_ref_t);
static void quit_code(thread_ref_t);

static void smtp_read_thread(thread_ref_t);

struct {
	void (*send) (thread_ref_t);
	void (*read) (thread_ref_t);
	int expected_code;
	const char *cmd_name;
} SMTP_FSM[SMTP_MAX_FSM_STATE] = {
/*       Code			  Stream Write Handlers		Stream Read handlers *
 *------------------------------+----------------------------------------------------*/
	[connect_error]		= {connection_error,		NULL,		  -1, NULL},
	[connect_in_progress]	= {connection_in_progress,	NULL,		  -1, NULL},
	[connect_timeout]	= {connection_timeout,		NULL,		  -1, NULL},
	[connect_fail]		= {connection_error,		NULL,		  -1, NULL},
	[connect_success]	= {connection_success,		NULL,		 220, "(E)SMTP"},
	[HELO]			= {helo_cmd,			NULL,		 250, "HELO"},
	[MAIL]			= {mail_cmd,			NULL,		 250, "MAIL"},
	[RCPT]			= {rcpt_cmd,			rcpt_code,	 250, "RCPT"},
	[DATA]			= {data_cmd,			NULL,		 354, "DATA"},
	[BODY]			= {body_cmd,			body_code,	 250, "BODY"},
	[QUIT]			= {quit_cmd,			quit_code,	 221, "QUIT"}
};

static inline void
free_smtp_msg_data(smtp_t * smtp)
{
#ifdef SMTP_MSG_ALLOC_DEBUG
	FREE(smtp->buffer);
	FREE(smtp->subject);
	FREE(smtp->body);
#endif
	FREE(smtp);
}

static smtp_t *
alloc_smtp_msg_data(void)
{
	smtp_t *smtp;

	/* allocate & initialize smtp argument data structure */
#ifdef SMTP_MSG_ALLOC_DEBUG
	PMALLOC(smtp);
	smtp->subject = (char *)MALLOC(MAX_HEADERS_LENGTH);
	smtp->body = (char *)MALLOC(MAX_BODY_LENGTH);
	smtp->buffer = (char *)MALLOC(SMTP_BUFFER_MAX);
#else
	smtp = MALLOC(sizeof(smtp_t) + MAX_HEADERS_LENGTH + MAX_BODY_LENGTH + SMTP_BUFFER_MAX + SMTP_BUFFER_MAX);
	smtp->subject = (char *)smtp + sizeof(smtp_t);
	smtp->body = smtp->subject + MAX_HEADERS_LENGTH;
	smtp->buffer = smtp->body + MAX_BODY_LENGTH;
#endif

	return smtp;
}

static void
smtp_send(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	smtp_send_buffer[0] = '\0';
	SMTP_FSM_SEND(smtp->stage, thread);

	if (!smtp_send_buffer[0]) {
		/* Nothing in send buffer means connection failed */
		thread_close_fd(thread);
		free_smtp_msg_data(smtp);
		return;
	}

	if (send(thread->u.f.fd, smtp_send_buffer, strlen(smtp_send_buffer), 0) == -1) {
		log_message(LOG_INFO, "Cannot send data to remote SMTP server %s."
				    , FMT_SMTP_HOST());
		thread_close_fd(thread);
		free_smtp_msg_data(smtp);
		return;
	}

	/* Registering next smtp command processing thread */
	thread_add_read(thread->master, smtp_read_thread, smtp,
			thread->u.f.fd, global_data->smtp_connection_to, THREAD_DESTROY_CLOSE_FD | THREAD_DESTROY_FREE_ARG);
}

/* layer4 connection handlers */
static void
connection_error(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	log_message(LOG_INFO, "SMTP connection ERROR to %s."
			    , FMT_SMTP_HOST());
	free_smtp_msg_data(smtp);
}
static void
connection_timeout(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	log_message(LOG_INFO, "Timeout connecting SMTP server %s."
			    , FMT_SMTP_HOST());
	free_smtp_msg_data(smtp);
}
static void
connection_in_progress(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

#ifdef _SMTP_CONNECT_DEBUG_
	if (do_smtp_connect_debug)
		log_message(LOG_DEBUG, "SMTP connection to %s now IN_PROGRESS.", FMT_SMTP_HOST());
#endif

	if (thread->type == THREAD_WRITE_TIMEOUT) {
		log_message(LOG_INFO, "Timeout opening connection to remote SMTP server %s."
				    , FMT_SMTP_HOST());

		thread_close_fd(thread);
		free_smtp_msg_data(smtp);
		return;
	} else if (thread->type == THREAD_WRITE_ERROR) {
		log_message(LOG_INFO, "smtp fd %d returned write error", thread->u.f.fd);
		thread_close_fd(thread);
		free_smtp_msg_data(smtp);
		return;
	}

	/*
	 * Here we use the propriety of a union structure,
	 * each element of the structure have the same value.
	 */
	smtp->stage = tcp_socket_state(thread, connection_in_progress, THREAD_DESTROY_FREE_ARG);

	if (smtp->stage != connect_in_progress) {
		thread_del_write(thread);
		SMTP_FSM_SEND(smtp->stage, thread);
	}
}
static void
connection_success(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "Remote SMTP server %s connected."
				    , FMT_SMTP_HOST());

	smtp->stage = connect_success;
	thread_add_read(thread->master, smtp_read_thread, smtp,
			thread->u.f.fd, global_data->smtp_connection_to, THREAD_DESTROY_CLOSE_FD | THREAD_DESTROY_FREE_ARG);
}

/* SMTP protocol handlers */
static void
smtp_read_thread(thread_ref_t thread)
{
	smtp_t *smtp;
	char *reply;
	ssize_t rcv_buffer_size;
	int status = -1;

	smtp = THREAD_ARG(thread);

	if (thread->type == THREAD_READ_TIMEOUT) {
		log_message(LOG_INFO, "Timeout reading data to remote SMTP server %s."
				    , FMT_SMTP_HOST());

		if (smtp->stage == QUIT) {
			/* We have already sent a quit, so just terminate */
			thread_close_fd(thread);
			free_smtp_msg_data(smtp);
		} else {
			smtp->stage = QUIT;
			smtp_send(thread);
		}

		return;
	} else if (thread->type == THREAD_READ_ERROR) {
		log_message(LOG_INFO, "smtp fd %d returned read error", thread->u.f.fd);
		thread_close_fd(thread);
		free_smtp_msg_data(smtp);
		return;
	}

	rcv_buffer_size = read(thread->u.f.fd, smtp->buffer + smtp->buflen,
			       SMTP_BUFFER_MAX - smtp->buflen);

	if (rcv_buffer_size == -1) {
		if (check_EAGAIN(errno)) {
			thread_add_read(thread->master, smtp_read_thread, smtp,
					thread->u.f.fd, global_data->smtp_connection_to, THREAD_DESTROY_CLOSE_FD | THREAD_DESTROY_FREE_ARG);
			return;
		}

		log_message(LOG_INFO, "Error reading data from remote SMTP server %s."
				    , FMT_SMTP_HOST());
		smtp->stage = QUIT;
		smtp_send(thread);

		return;
	}

	if (rcv_buffer_size == 0) {
		log_message(LOG_INFO, "Remote SMTP server %s has closed the connection."
				    , FMT_SMTP_HOST());
		thread_close_fd(thread);
		free_smtp_msg_data(smtp);

		return;
	}

	/* received data overflow buffer size ? */
	if (smtp->buflen + rcv_buffer_size >= SMTP_BUFFER_MAX) {
		log_message(LOG_INFO, "Received buffer from remote SMTP server %s"
				      " overflow our get read buffer length."
				    , FMT_SMTP_HOST());
		smtp->buflen = 0;
		smtp->stage = QUIT;
		smtp_send(thread);

		return;
	}

	smtp->buflen += (size_t)rcv_buffer_size;
	smtp->buffer[smtp->buflen] = 0;	/* NULL terminate */

	/* parse the buffer, finding the last line of the response for the code */
	reply = smtp->buffer;
	while (reply < smtp->buffer + smtp->buflen) {		// This line causes a strict-overflow=4 warning with gcc 5.4.0
		char *p;

		p = strstr(reply, "\r\n");
		if (!p) {
			if (reply != smtp->buffer) {
				memmove(smtp->buffer, reply,
					smtp->buflen - (size_t)(reply - smtp->buffer) + 1);	/* Include terminating NUL byte */
				smtp->buflen -= (size_t)(reply - smtp->buffer);
			}

			thread_add_read(thread->master, smtp_read_thread,
					smtp, thread->u.f.fd,
					global_data->smtp_connection_to, THREAD_DESTROY_CLOSE_FD | THREAD_DESTROY_FREE_ARG);
			return;
		}

		/* Is it a multi-line reply? */
		if (reply[3] == '-') {
			/* Skip over the \r\n */
			reply = p + 2;
			continue;
		}

		status = ((reply[0] - '0') * 100) + ((reply[1] - '0') * 10) + (reply[2] - '0');

		reply = p + 2;
		break;
	}

	if (reply >= smtp->buffer + smtp->buflen)
		smtp->buflen = 0;
	else {
		memmove(smtp->buffer, reply, smtp->buflen - (size_t)(reply - smtp->buffer) + 1);
		smtp->buflen -= (size_t)(reply - smtp->buffer);
	}

	if (status == -1) {
		thread_add_read(thread->master, smtp_read_thread, smtp,
				thread->u.f.fd, global_data->smtp_connection_to, THREAD_DESTROY_CLOSE_FD | THREAD_DESTROY_FREE_ARG);
		return;
	}


	if (status == SMTP_FSM[smtp->stage].expected_code) {
		if (SMTP_FSM[smtp->stage].read)
			SMTP_FSM_READ(smtp->stage, thread);
		else
			smtp->stage++;
	} else {
		/* Incorrect code returned */
		if (SMTP_FSM[smtp->stage].cmd_name)
			log_message(LOG_INFO, "Error processing %s cmd on SMTP server %s."
					      " SMTP status code = %d"
					    , SMTP_FSM[smtp->stage].cmd_name
					    , FMT_SMTP_HOST()
					    , status);
		smtp->stage = QUIT;
	}

	if (smtp->stage == END) {
		/* We have finished */
		thread_close_fd(thread);
		free_smtp_msg_data(smtp);
		return;
	}

	/* Send next packet */
	smtp_send(thread);
}

/* HELO command processing */
static void
helo_cmd(__attribute__((unused)) thread_ref_t thread)
{
	snprintf(smtp_send_buffer, sizeof(smtp_send_buffer), "HELO %s\r\n", (global_data->smtp_helo_name) ? global_data->smtp_helo_name : "localhost");
}

/* MAIL command processing */
static void
mail_cmd(__attribute__((unused)) thread_ref_t thread)
{
	size_t len;
	const char *start;

	len = strlen(global_data->email_from);
	if (global_data->email_from[len - 1] == '>' && (start = strrchr(global_data->email_from, '<')))
		snprintf(smtp_send_buffer, sizeof(smtp_send_buffer), "MAIL FROM:%s\r\n", start);
	else
		snprintf(smtp_send_buffer, sizeof(smtp_send_buffer), "MAIL FROM:<%s>\r\n", global_data->email_from);
}

/* RCPT command processing */
static void
rcpt_cmd(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);
	email_t *email = smtp->next_email_element;
	size_t len;
	const char *start;

	/* We send RCPT TO command multiple time to add all our email receivers.
	 * --rfc821.3.1
	 */
	if (list_is_last(&smtp->next_email_element->e_list, &global_data->email))
		smtp->next_email_element = NULL;
	else
		smtp->next_email_element = list_entry(email->e_list.next, email_t, e_list);

	len = strlen(email->addr);
	if (email->addr[len - 1] == '>' && (start = strrchr(email->addr, '<')))
		snprintf(smtp_send_buffer, sizeof(smtp_send_buffer), "RCPT TO:%s\r\n", start);
	else
		snprintf(smtp_send_buffer, sizeof(smtp_send_buffer), "RCPT TO:<%s>\r\n", email->addr);
}
static void
rcpt_code(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	if (!smtp->next_email_element)
		smtp->stage++;
}

/* DATA command processing */
static void
data_cmd(__attribute__((unused)) thread_ref_t thread)
{
	strncpy(smtp_send_buffer, "DATA\r\n", sizeof(smtp_send_buffer));
}

/* BODY command processing.
 * Do we need to use multi-thread for multi-part body
 * handling? Don't really think so :)
 */
static void
body_cmd(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);
	char rfc822[80];	/* Mon, 01 Mar 2021 09:44:08 +0000 */
	time_t now;
	struct tm t;
	size_t offs = 0;
	email_t *email;

	time(&now);
	localtime_r(&now, &t);
	strftime(rfc822, sizeof(rfc822), "%a, %d %b %Y %H:%M:%S %z", &t);

	/* send the DATA fields */
	offs = snprintf(smtp_send_buffer, sizeof(smtp_send_buffer),
		"Date: %s\r\n"
		"From: %s\r\n"
		"Subject: %s\r\n"
                "X-Mailer: Keepalived\r\n"
		"To:",
		 rfc822, global_data->email_from, smtp->subject);

	/* Add the recipients */
	list_for_each_entry(email, &global_data->email, e_list) {
		offs += snprintf(smtp_send_buffer + offs, sizeof(smtp_send_buffer) - offs,
				"%s %s",
				list_is_first(&email->e_list, &global_data->email) ? "" : ",\r\n",
				email->addr);
	}

	/* Now the message body */
	snprintf(smtp_send_buffer + offs, sizeof(smtp_send_buffer) - offs,
		"\r\n\r\n"
		"%s\r\n"
		"\r\n.\r\n",
		smtp->body);
}
static void
body_code(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "SMTP alert successfully sent.");

	smtp->stage++;
}

/* QUIT command processing */
static void
quit_cmd(__attribute__((unused)) thread_ref_t thread)
{
	strncpy(smtp_send_buffer, "QUIT\r\n", sizeof(smtp_send_buffer));
}

static void
quit_code(thread_ref_t thread)
{
	smtp_t *smtp = THREAD_ARG(thread);

	smtp->stage = END;
}

/* connect remote SMTP server */
static void
smtp_connect(smtp_t *smtp)
{
	enum connect_result status;
	int fd;

	smtp->next_email_element = list_first_entry(&global_data->email, email_t, e_list);

	if ((fd = socket(global_data->smtp_server.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP)) == -1) {
#ifdef _SMTP_CONNECT_DEBUG_
		if (do_smtp_connect_debug)
			log_message(LOG_DEBUG, "SMTP connect fail to create socket.");
#endif
		free_smtp_msg_data(smtp);
		return;
	}

	status = tcp_connect(fd, &global_data->smtp_server);

	/* Handle connection status code */
	if (status == connect_in_progress) {
		thread_add_write(master, connection_in_progress, smtp,
				 fd, global_data->smtp_connection_to, THREAD_DESTROY_CLOSE_FD | THREAD_DESTROY_FREE_ARG);
		return;
	}
 
	if (status == connect_success) {
		thread_t thread = { .u.f.fd = fd, .master = master, .arg = smtp };
		connection_success(&thread);
		return;
	}
 
	/* connect_fail, connect_error */
	close(fd);
	free_smtp_msg_data(smtp);
}

#ifdef _SMTP_ALERT_DEBUG_
static void
smtp_log_to_file(smtp_t *smtp)
{
	FILE *fp;
	time_t now;
	struct tm tm;
	char time_buf[25];
	int time_buf_len;
	const char *file_name;
	email_t *email;

	file_name = make_tmp_filename("smtp-alert.log");
	fp = fopen_safe(file_name, "a");
	FREE_CONST(file_name);

	if (fp) {
		time(&now);
		localtime_r(&now, &tm);
		time_buf_len = strftime(time_buf, sizeof time_buf, "%a %b %e %X %Y", &tm);

		fprintf(fp, "%s: %s ->", time_buf, global_data->email_from);
		list_for_each_entry(email, &global_data->email, e_list)
			fprintf(fp, "%s %s",
				list_is_first(&email->e_list, &global_data->email) ? "" : ",",
				email->addr);

		fprintf(fp, "\n"
			    "%*sSubject: %s\n"
			    "%*sBody:    %s\n\n",
			    time_buf_len - 7, "", smtp->subject,
			    time_buf_len - 7, "", smtp->body);

		fclose(fp);
	}

	free_smtp_msg_data(smtp);
}
#endif

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
	if (list_empty(&global_data->email) || !global_data->smtp_server.ss_family)
		return;

	/* allocate & initialize smtp argument data structure */
	smtp = alloc_smtp_msg_data();

	/* format subject if rserver is specified */
#ifdef _WITH_LVS_
	if (msg_type == SMTP_MSG_RS) {
		checker = PTR_CAST(checker_t, data);
		snprintf(smtp->subject, MAX_HEADERS_LENGTH, "[%s] Realserver %s of virtual server %s - %s",
					global_data->router_id,
					FMT_RS(checker->rs, checker->vs),
					FMT_VS(checker->vs),
					checker->rs->alive ? "UP" : "DOWN");
	}
	else if (msg_type == SMTP_MSG_VS) {
		vs = PTR_CAST(virtual_server_t, data);
		snprintf(smtp->subject, MAX_HEADERS_LENGTH, "[%s] Virtualserver %s - %s",
					global_data->router_id,
					FMT_VS(vs),
					subject);
	}
	else if (msg_type == SMTP_MSG_RS_SHUT) {
		rs_info = PTR_CAST(smtp_rs, data);
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
		vrrp = PTR_CAST(vrrp_t, data);
		snprintf(smtp->subject, MAX_HEADERS_LENGTH, "[%s] VRRP Instance %s - %s",
					global_data->router_id,
					vrrp->iname,
					subject);
	} else if (msg_type == SMTP_MSG_VGROUP) {
		vgroup = PTR_CAST(vrrp_sgroup_t, data);
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
}
#endif
