/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        DNS checker
 *
 * Author:      Masanobu Yasui, <yasui-m@klab.com>
 *              Masaya Yamamoto, <yamamoto-ma@klab.com>
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
 * Copyright (C) 2016 KLab Inc.
 * Copyright (C) 2016-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>

#include "check_dns.h"
#include "check_api.h"
#include "memory.h"
#include "global_data.h"
#include "ipwrapper.h"
#include "logger.h"
#include "smtp.h"
#include "utils.h"
#include "parser.h"
#include "layer4.h"
#include "scheduler.h"

const dns_type_t DNS_TYPE[] = {
	{DNS_TYPE_A, "A"},
	{DNS_TYPE_NS, "NS"},
	{DNS_TYPE_CNAME, "CNAME"},
	{DNS_TYPE_SOA, "SOA"},
	{DNS_TYPE_MX, "MX"},
	{DNS_TYPE_TXT, "TXT"},
	{DNS_TYPE_AAAA, "AAAA"},
	{DNS_TYPE_RRSIG, "RRSIG"},
	{DNS_TYPE_DNSKEY, "DNSKEY"},
	{0, NULL}
};

static void dns_connect_thread(thread_ref_t);
static void dns_send_thread(thread_ref_t);

static uint16_t __attribute__ ((pure))
dns_type_lookup(const char *label)
{
	const dns_type_t *t;

	for (t = DNS_TYPE; t->type; t++) {
		if (!strcasecmp(label, t->label)) {
			return t->type;
		}
	}
	return 0;
}

static const char * __attribute__ ((pure))
dns_type_name(uint16_t type)
{
	const dns_type_t *t;

	for (t = DNS_TYPE; t->type; t++) {
		if (type == t->type) {
			return t->label;
		}
	}
	return "(unknown)";
}

static void __attribute__ ((format (printf, 3, 4)))
dns_log_message(thread_ref_t thread, int level, const char *fmt, ...)
{
	char buf[MAX_LOG_MSG];
	va_list args;

	checker_t *checker = THREAD_ARG(thread);

	va_start(args, fmt);
	vsnprintf(buf, sizeof (buf), fmt, args);
	va_end(args);

	log_message(level, "DNS_CHECK (%s) %s", FMT_CHK(checker), buf);
}

static int __attribute__ ((format (printf, 3, 4)))
dns_final(thread_ref_t thread, bool error, const char *fmt, ...)
{
	char buf[MAX_LOG_MSG];
	va_list args;
	int len;
	bool checker_was_up;
	bool rs_was_alive;

	checker_t *checker = THREAD_ARG(thread);

#ifdef _CHECKER_DEBUG_
	if (do_checker_debug)
		dns_log_message(thread, LOG_DEBUG, "final error=%d attempts=%u retry=%u", error,
				checker->retry_it, checker->retry);
#endif

	if (thread->type != THREAD_READY_TIMER)
		thread_close_fd(thread);

	if (error) {
		if (checker->is_up || !checker->has_run) {
			if (fmt &&
			    (global_data->checker_log_all_failures ||
			     checker->log_all_failures ||
			     checker->retry_it >= checker->retry)) {
				va_start(args, fmt);
				len = vsnprintf(buf, sizeof (buf), fmt, args);
				va_end(args);
				if (checker->has_run && checker->retry_it >= checker->retry )
					snprintf(buf + len, sizeof(buf) - len, " after %u retries", checker->retry);
				dns_log_message(thread, LOG_INFO, "%s", buf);
			}
			if (checker->retry_it < checker->retry) {
				checker->retry_it++;
				checker->has_run = true;
				thread_add_timer(thread->master,
						 dns_connect_thread, checker,
						 checker->delay_before_retry);
				return 0;
			}
			checker_was_up = checker->is_up;
			rs_was_alive = checker->rs->alive;
			update_svr_checker_state(DOWN, checker);
			if (checker_was_up && checker->rs->smtp_alert &&
			    (rs_was_alive != checker->rs->alive || !global_data->no_checker_emails))
				smtp_alert(SMTP_MSG_RS, checker, NULL,
					   "=> DNS_CHECK: failed on service <=");
		}
	} else {
		if (!checker->is_up || !checker->has_run) {
			checker_was_up = checker->is_up;
			rs_was_alive = checker->rs->alive;
			update_svr_checker_state(UP, checker);
			if (!checker_was_up && checker->rs->smtp_alert &&
			    (rs_was_alive != checker->rs->alive || !global_data->no_checker_emails))
				smtp_alert(SMTP_MSG_RS, checker, NULL,
					   "=> DNS_CHECK: succeed on service <=");
		}
	}

	checker->retry_it = 0;
	thread_add_timer(thread->master, dns_connect_thread, checker,
			 checker->delay_loop);

	return 0;
}

static void
dns_recv_thread(thread_ref_t thread)
{
	unsigned long timeout;
	ssize_t ret;
	char rbuf[DNS_BUFFER_SIZE] __attribute__((aligned(__alignof__(dns_header_t))));
	dns_header_t *s_header, *r_header;
	int flags, rcode;

	checker_t *checker = THREAD_ARG(thread);
	dns_check_t *dns_check = CHECKER_ARG(checker);

	if (thread->type == THREAD_READ_TIMEOUT) {
		dns_final(thread, true, "read timeout from socket");
		return;
	}

	timeout = timer_long(thread->sands) - timer_long(time_now);

	ret = recv(thread->u.f.fd, rbuf, sizeof (rbuf), 0);
	if (ret == -1) {
		if (check_EAGAIN(errno) || check_EINTR(errno)) {
			thread_add_read(thread->master, dns_recv_thread,
					checker, thread->u.f.fd, timeout, THREAD_DESTROY_CLOSE_FD);
			return;
		}
		dns_final(thread, true, "failed to read socket; errno %d (%s)", errno, strerror(errno));
		return;
	}

	if (ret < (ssize_t) sizeof (r_header)) {
#ifdef _CHECKER_DEBUG_
		if (do_checker_debug)
			dns_log_message(thread, LOG_DEBUG, "too small message. (%zd bytes)", ret);
#endif
		thread_add_read(thread->master, dns_recv_thread, checker,
				thread->u.f.fd, timeout, THREAD_DESTROY_CLOSE_FD);
		return;
	}

	s_header = PTR_CAST(dns_header_t , dns_check->sbuf);
	r_header = PTR_CAST(dns_header_t , rbuf);

	if (s_header->id != r_header->id) {
#ifdef _CHECKER_DEBUG_
		if (do_checker_debug)
			dns_log_message(thread, LOG_DEBUG, "ID does not match. (%04x != %04x)",
					ntohs(s_header->id), ntohs(r_header->id));
#endif
		thread_add_read(thread->master, dns_recv_thread, checker,
				thread->u.f.fd, timeout, THREAD_DESTROY_CLOSE_FD);
		return;
	}

	flags = ntohs(r_header->flags);

	if (!DNS_QR(flags)) {
#ifdef _CHECKER_DEBUG_
		if (do_checker_debug)
			dns_log_message(thread, LOG_DEBUG, "receive query message?");
#endif
		thread_add_read(thread->master, dns_recv_thread, checker,
				thread->u.f.fd, timeout, THREAD_DESTROY_CLOSE_FD);
		return;
	}

	if ((rcode = DNS_RC(flags)) != 0) {
		dns_final(thread, true, "read error occurred. (rcode = %d)", rcode);
		return;
	}

	/* success */
	dns_final(thread, false, NULL);
}

#define APPEND16(x, y) do { \
		*PTR_CAST(uint16_t, (x)) = htons(y); \
		(x) = (uint8_t *) (x) + 2; \
	} while(0)

static void
dns_make_query(thread_ref_t thread)
{
	uint16_t flags = 0;
	uint8_t *p;
	const char *s, *e;
	size_t n;
	checker_t *checker = THREAD_ARG(thread);
	dns_check_t *dns_check = CHECKER_ARG(checker);
	dns_header_t *header = PTR_CAST(dns_header_t, dns_check->sbuf);

	DNS_SET_RD(flags, 1);	/* Recursion Desired */

	/* coverity[dont_call] */
	header->id = random();
	header->flags = htons(flags);
	header->qdcount = htons(1);
	header->ancount = htons(0);
	header->nscount = htons(0);
	header->arcount = htons(0);

	p = PTR_CAST(uint8_t, header + 1);

	/* QNAME */
	for (s = dns_check->name; *s; s = *e ? ++e : e) {
		if (!(e = strchr(s, '.'))) {
			e = s + strlen(s);
		}
		n = (size_t)(e - s);
		*(p++) = (uint8_t)n;
		memcpy(p, s, n);
		p += n;
	}
	
	if (dns_check->name[0] != '.' || dns_check->name[1] != '\0')
		*(p++) = 0;

	APPEND16(p, dns_check->type);
	APPEND16(p, 1);		/* IN */

	dns_check->slen = (size_t)(p - PTR_CAST(uint8_t, header));
}

static void
dns_send(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	dns_check_t *dns_check = CHECKER_ARG(checker);
	unsigned long timeout;
	ssize_t ret;

	timeout = timer_long(thread->sands) - timer_long(time_now);

	/* Handle time_now > thread->sands (check for underflow) */
	if (timeout > checker->co->connection_to)
		timeout = 0;

	ret = send(thread->u.f.fd, dns_check->sbuf, dns_check->slen, 0);
	if (ret == -1) {
		if (check_EAGAIN(errno) || check_EINTR(errno)) {
			thread_add_write(thread->master, dns_send_thread,
					 checker, thread->u.f.fd, timeout, THREAD_DESTROY_CLOSE_FD);
			return;
		}
		dns_final(thread, true, "failed to write socket.");
		return;
	}

	if (ret != (ssize_t) dns_check->slen) {
		dns_final(thread, true, "failed to write all of the datagram.");
		return;
	}

	thread_add_read(thread->master, dns_recv_thread, checker, thread->u.f.fd, timeout, THREAD_DESTROY_CLOSE_FD);

	return;
}

static void
dns_send_thread(thread_ref_t thread)
{
	if (thread->type == THREAD_WRITE_TIMEOUT) {
		dns_final(thread, true, "write timeout to socket.");
		return;
	}

	dns_send(thread);
}

static void
dns_check_thread(thread_ref_t thread)
{
	int status;

	if (thread->type == THREAD_WRITE_TIMEOUT) {
		dns_final(thread, true, "write timeout to socket.");
		return;
	}

	status = socket_state(thread, dns_check_thread, 0);

	/* If status = connect_in_progress, next thread is already registered.
	 * If it is connect_success, the fd is still open.
	 * Otherwise we have a real connection error or connection timeout.
	 */
	switch (status) {
	case connect_error:
		dns_final(thread, true, "connection error.");
		break;
	case connect_timeout:
		dns_final(thread, true, "connection timeout.");
		break;
	case connect_fail:
		dns_final(thread, true, "connection failure.");
		break;
	case connect_success:
		dns_make_query(thread);
		dns_send(thread);

		/* Cancel the write after the read is added to avoid the
		 * file descriptor being removed */
		thread_del_write(thread);
		break;
	}
}

static void
dns_connect_thread(thread_ref_t thread)
{
	int fd, status;
	thread_t thread_fd;

	checker_t *checker = THREAD_ARG(thread);
	conn_opts_t *co = checker->co;

	if (!checker->enabled) {
		thread_add_timer(thread->master, dns_connect_thread, checker,
				 checker->delay_loop);
		return;
	}

	if ((fd = socket(co->dst.ss_family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP)) == -1) {
		dns_log_message(thread, LOG_INFO,
				"failed to create socket. Rescheduling.");
		thread_add_timer(thread->master, dns_connect_thread, checker,
				 checker->delay_loop);
		return;
	}

	status = socket_bind_connect(fd, co);

	if (status == connect_success) {
		thread_fd = *thread;
		thread_fd.u.f.fd = fd;
		thread_fd.sands = timer_add_long(time_now, co->connection_to);
		dns_make_query(&thread_fd);
		dns_send(&thread_fd);

		return;
	}

	if (status == connect_fail) {
		close(fd);
		dns_final(thread, true, "network unreachable for %s", inet_sockaddrtopair(&co->dst));

		return;
	}

	/* handle connection status & register check worker thread */
	if (socket_connection_state(fd, status, thread, dns_check_thread, co->connection_to, 0)) {
		close(fd);
		dns_log_message(thread, LOG_INFO,
				"UDP socket bind failed. Rescheduling.");
		thread_add_timer(thread->master, dns_connect_thread, checker,
				 checker->delay_loop);
	}
}

static void
free_dns_check(checker_t *checker)
{
	dns_check_t *dns_check = checker->data;

	FREE_CONST(dns_check->name);
	FREE(checker->co);
	FREE(checker->data);
	FREE(checker);
}

static void
dump_dns_check(FILE *fp, const checker_t *checker)
{
	const dns_check_t *dns_check = checker->data;

	conf_write(fp, "   Keepalive method = DNS_CHECK");
	conf_write(fp, "   Type = %s", dns_type_name(dns_check->type));
	conf_write(fp, "   Name = %s", dns_check->name);
}

static bool
compare_dns_check(const checker_t *old_c, checker_t *new_c)
{
	const dns_check_t *old = old_c->data;
	const dns_check_t *new = new_c->data;

	if (!compare_conn_opts(old_c->co, new_c->co))
		return false;
	if (old->type != new->type)
		return false;
	if (strcmp(old->name, new->name) != 0)
		return false;

	return true;
}

static const checker_funcs_t dns_checker_funcs = { CHECKER_DNS, free_dns_check, dump_dns_check, compare_dns_check, NULL };

static void
dns_check_handler(__attribute__((unused)) const vector_t *strvec)
{
	checker_t *checker;
	dns_check_t *dns_check;

	PMALLOC(dns_check);
	dns_check->type = DNS_DEFAULT_TYPE;
	checker = queue_checker(&dns_checker_funcs, dns_connect_thread,
				dns_check, CHECKER_NEW_CO(), true);

	/* Set the non-standard retry time */
	checker->default_retry = DNS_DEFAULT_RETRY;
	checker->default_delay_before_retry = 0;	/* This will default to delay_loop */
}

static void
dns_type_handler(const vector_t *strvec)
{
	uint16_t dns_type;
	dns_check_t *dns_check = CHECKER_GET();

	dns_type = dns_type_lookup(strvec_slot(strvec, 1));
	if (!dns_type)
		report_config_error(CONFIG_GENERAL_ERROR, "Unknown DNS check type %s - ignoring",
				    strvec_slot(strvec, 1));
	else
		dns_check->type = dns_type;
}

static void
dns_name_handler(const vector_t *strvec)
{
	dns_check_t *dns_check = CHECKER_GET();
	const char *name;
	bool name_invalid = false;
	const char *p;

	if (dns_check->name) {
		report_config_error(CONFIG_GENERAL_ERROR, "DNS_CHECK name already specified - ignoring");
		return;
	}

	/* Check name does not have an empty label */
	name = strvec_slot(strvec, 1);
	if (name[0] == '.' && name[1] != '\0')
		name_invalid = true;
	else {
		for (p = name; p; p = strchr(p + 1, '.')) {
			if (p[1] == '.') {
				name_invalid = true;
				break;
			}
		}
	}

	if (name_invalid) {
		report_config_error(CONFIG_GENERAL_ERROR, "DNS_CHECK name '%s' has empty label - ignoring", name);
		return;
	}

	dns_check->name = STRDUP(name);
}

static void
dns_check_end(void)
{
	dns_check_t *dns_check;

	if (!check_conn_opts(CHECKER_GET_CO())) {
		dequeue_new_checker();
		return;
	}

	dns_check = CHECKER_GET();
	if (!dns_check->name)
		dns_check->name = STRDUP(DNS_DEFAULT_NAME);
}

void
install_dns_check_keyword(void)
{
	install_keyword("DNS_CHECK", &dns_check_handler);
	install_sublevel();
	install_checker_common_keywords(true);
	install_keyword("type", &dns_type_handler);
	install_keyword("name", &dns_name_handler);
	install_sublevel_end_handler(dns_check_end);
	install_sublevel_end();
}

#ifdef THREAD_DUMP
void
register_check_dns_addresses(void)
{
	register_thread_address("dns_check_thread", dns_check_thread);
	register_thread_address("dns_connect_thread", dns_connect_thread);
	register_thread_address("dns_recv_thread", dns_recv_thread);
	register_thread_address("dns_send_thread", dns_send_thread);
}
#endif
