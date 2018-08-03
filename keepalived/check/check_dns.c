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
#include "ipwrapper.h"
#include "logger.h"
#include "smtp.h"
#include "utils.h"
#include "parser.h"
#if !HAVE_DECL_SOCK_CLOEXEC
#include "old_socket.h"
#endif
#include "layer4.h"

#ifdef _DEBUG_
#define DNS_DBG(args...) dns_log_message(thread, LOG_DEBUG, ## args)
#else
#define DNS_DBG(args...)
#endif

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

static int dns_connect_thread(thread_t *);

static uint16_t
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

static const char *
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

static void
dns_log_message(thread_t * thread, int level, const char *fmt, ...)
{
	char buf[MAX_LOG_MSG];
	va_list args;

	checker_t *checker = THREAD_ARG(thread);

	va_start(args, fmt);
	vsnprintf(buf, sizeof (buf), fmt, args);
	va_end(args);

	log_message(level, "DNS_CHECK (%s) %s", FMT_DNS_RS(checker), buf);
}

static int
dns_final(thread_t * thread, int error, const char *fmt, ...)
{
	char buf[MAX_LOG_MSG];
	va_list args;
	int len;
	bool checker_was_up;
	bool rs_was_alive;

	checker_t *checker = THREAD_ARG(thread);

	DNS_DBG("final error=%d attempts=%d retry=%d", error,
		checker->retry_it, checker->retry);

	close(thread->u.fd);

	if (error) {
		if (checker->is_up || !checker->has_run) {
			if (checker->retry_it < checker->retry) {
				checker->retry_it++;
				thread_add_timer(thread->master,
						 dns_connect_thread, checker,
						 checker->delay_before_retry);
				return 0;
			}
			if (fmt) {
				va_start(args, fmt);
				len = vsnprintf(buf, sizeof (buf), fmt, args);
				va_end(args);
				if (checker->has_run && checker->retry)
					snprintf(buf + len, sizeof(buf) - len, " after %d retries", checker->retry);
				dns_log_message(thread, LOG_INFO, buf);
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

static int
dns_recv_thread(thread_t * thread)
{
	unsigned long timeout;
	ssize_t ret;
	char rbuf[DNS_BUFFER_SIZE];
	dns_header_t *s_header, *r_header;
	int flags, rcode;

	checker_t *checker = THREAD_ARG(thread);
	dns_check_t *dns_check = CHECKER_ARG(checker);

	if (thread->type == THREAD_READ_TIMEOUT) {
		dns_final(thread, 1, "read timeout from socket");
		return 0;
	}

	timeout = timer_long(thread->sands) - timer_long(time_now);

	ret = recv(thread->u.fd, rbuf, sizeof (rbuf), 0);
	if (ret == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			thread_add_read(thread->master, dns_recv_thread,
					checker, thread->u.fd, timeout);
			return 0;
		}
		dns_final(thread, 1, "failed to read socket. %s", strerror(errno));
		return 0;
	}

	if (ret < (ssize_t) sizeof (r_header)) {
		DNS_DBG("too small message. (%d bytes)", ret);
		thread_add_read(thread->master, dns_recv_thread, checker,
				thread->u.fd, timeout);
		return 0;
	}

	s_header = (dns_header_t *) dns_check->sbuf;
	r_header = (dns_header_t *) rbuf;

	if (s_header->id != r_header->id) {
		DNS_DBG("ID does not match. (%04x != %04x)",
			ntohs(s_header->id), ntohs(r_header->id));
		thread_add_read(thread->master, dns_recv_thread, checker,
				thread->u.fd, timeout);
		return 0;
	}

	flags = ntohs(r_header->flags);

	if (!DNS_QR(flags)) {
		DNS_DBG("receive query message?");
		thread_add_read(thread->master, dns_recv_thread, checker,
				thread->u.fd, timeout);
		return 0;
	}

	if ((rcode = DNS_RC(flags)) != 0) {
		dns_final(thread, 1, "read error occurred. (rcode = %d)", rcode);
		return 0;
	}

	/* success */
	dns_final(thread, 0, NULL);

	return 0;
}

#define APPEND16(x, y) do { \
		*(uint16_t *) (x) = htons(y); \
		(x) = (uint8_t *) (x) + 2; \
	} while(0)

static int
dns_make_query(thread_t * thread)
{
	uint16_t flags = 0;
	uint8_t *p;
	char *s, *e;
	size_t n;
	checker_t *checker = THREAD_ARG(thread);
	dns_check_t *dns_check = CHECKER_ARG(checker);
	dns_header_t *header = (dns_header_t *) dns_check->sbuf;

	DNS_SET_RD(flags, 1);	/* Recursion Desired */

	header->id = htons(random());
	header->flags = htons(flags);
	header->qdcount = htons(1);
	header->ancount = htons(0);
	header->nscount = htons(0);
	header->arcount = htons(0);

	p = (uint8_t *) (header + 1);

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
	n = strlen(dns_check->name);
	if (n && dns_check->name[--n] != '.') {
		*(p++) = 0;
	}

	APPEND16(p, dns_check->type);
	APPEND16(p, 1);		/* IN */

	dns_check->slen = (size_t)(p - (uint8_t *)header);

	return 0;
}

static int
dns_send_thread(thread_t * thread)
{
	unsigned long timeout;
	ssize_t ret;

	checker_t *checker = THREAD_ARG(thread);
	dns_check_t *dns_check = CHECKER_ARG(checker);

	if (thread->type == THREAD_WRITE_TIMEOUT) {
		dns_final(thread, 1, "write timeout to socket.");
		return 0;
	}

	timeout = timer_long(thread->sands) - timer_long(time_now);

	ret = send(thread->u.fd, dns_check->sbuf, dns_check->slen, 0);
	if (ret == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			thread_add_write(thread->master, dns_send_thread,
					 checker, thread->u.fd, timeout);
			return 0;
		}
		dns_final(thread, 1, "failed to write socket.");
		return 0;
	}

	if (ret != (ssize_t) dns_check->slen) {
		dns_final(thread, 1, "failed to write all of the datagram.");
		return 0;
	}

	thread_add_read(thread->master, dns_recv_thread, checker, thread->u.fd,
			timeout);

	return 0;
}

static int
dns_check_thread(thread_t * thread)
{
	int status;
	unsigned long timeout;

	checker_t *checker = THREAD_ARG(thread);

	status = socket_state(thread, dns_check_thread);

	/* If status = connect_in_progress, next thread is already registered.
	 * If it is connect_success, the fd is still open.
	 * Otherwise we have a real connection error or connection timeout.
	 */
	switch (status) {
	case connect_error:
		dns_final(thread, 1, "connection error.");
		break;
	case connect_timeout:
		dns_final(thread, 1, "connection failure.");
		break;
	case connect_success:
		dns_make_query(thread);
		timeout = timer_long(thread->sands) - timer_long(time_now);
		thread_add_write(thread->master, dns_send_thread, checker,
				 thread->u.fd, timeout);
		break;
	}

	return 0;
}

static int
dns_connect_thread(thread_t * thread)
{
	int fd, status;

	checker_t *checker = THREAD_ARG(thread);
	conn_opts_t *co = checker->co;

	if (!checker->enabled) {
		thread_add_timer(thread->master, dns_connect_thread, checker,
				 checker->delay_loop);
		return 0;
	}

	if ((fd = socket(co->dst.ss_family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP)) == -1) {
		dns_log_message(thread, LOG_INFO,
				"failed to create socket. Rescheduling.");
		thread_add_timer(thread->master, dns_connect_thread, checker,
				 checker->delay_loop);
		return 0;
	}

#if !HAVE_DECL_SOCK_NONBLOCK
	if (set_sock_flags(fd, F_SETFL, O_NONBLOCK))
		dns_log_message(thread, LOG_INFO,
				"unable to set NONBLOCK on socket - %s (%d)",
				strerror(errno), errno);
#endif

#if !HAVE_DECL_SOCK_CLOEXEC
	if (set_sock_flags(fd, F_SETFD, FD_CLOEXEC))
		dns_log_message(thread, LOG_INFO,
				"unable to set CLOEXEC on socket - %s (%d)",
				strerror(errno), errno);
#endif

	status = socket_bind_connect(fd, co);

	/* handle connection status & register check worker thread */
	if (socket_connection_state(fd, status, thread, dns_check_thread, co->connection_to)) {
		close(fd);
		dns_log_message(thread, LOG_INFO,
				"UDP socket bind failed. Rescheduling.");
		thread_add_timer(thread->master, dns_connect_thread, checker,
				 checker->delay_loop);
	}

	return 0;
}

static void
dns_free(void *data)
{
	FREE(CHECKER_CO(data));
	FREE(CHECKER_DATA(data));
	FREE(data);
}

static void
dns_dump(FILE *fp, void *data)
{
	checker_t *checker = data;
	dns_check_t *dns_check = checker->data;

	conf_write(fp, "   Keepalive method = DNS_CHECK");
	dump_checker_opts(fp, checker);
	conf_write(fp, "   Type = %s", dns_type_name(dns_check->type));
	conf_write(fp, "   Name = %s", dns_check->name);
}

static bool
dns_check_compare(void *a, void *b)
{
	dns_check_t *old = CHECKER_DATA(a);
	dns_check_t *new = CHECKER_DATA(b);

	if (!compare_conn_opts(CHECKER_CO(a), CHECKER_CO(b)))
		return false;
	if (old->type != new->type)
		return false;
	if (strcmp(old->name, new->name) != 0)
		return false;

	return true;
}

static void
dns_check_handler(__attribute__((unused)) vector_t * strvec)
{
	checker_t *checker;

	dns_check_t *dns_check = (dns_check_t *) MALLOC(sizeof (dns_check_t));
	dns_check->type = DNS_DEFAULT_TYPE;
	dns_check->name = DNS_DEFAULT_NAME;
	checker = queue_checker(dns_free, dns_dump, dns_connect_thread,
				dns_check_compare, dns_check, CHECKER_NEW_CO());

	/* Set the non-standard retry time */
	checker->default_retry = DNS_DEFAULT_RETRY;
	checker->default_delay_before_retry = 0;	/* This will default to delay_loop */
}

static void
dns_type_handler(vector_t * strvec)
{
	uint16_t dns_type;
	dns_check_t *dns_check = CHECKER_GET();

	dns_type = dns_type_lookup(CHECKER_VALUE_STRING(strvec));
	if (!dns_type)
		report_config_error(CONFIG_GENERAL_ERROR, "Unknown DNS check type %s - defaulting to SOA", vector_size(strvec) < 2 ? "[blank]" : FMT_STR_VSLOT(strvec, 1));
	else
		dns_check->type = dns_type;
}

static void
dns_name_handler(vector_t * strvec)
{
	dns_check_t *dns_check = CHECKER_GET();
	dns_check->name = CHECKER_VALUE_STRING(strvec);
}

static void
dns_check_end(void)
{
	if (!check_conn_opts(CHECKER_GET_CO())) {
		dequeue_new_checker();
	}
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

#ifdef _TIMER_DEBUG_
void
print_check_dns_addresses(void)
{
	log_message(LOG_INFO, "Address of dns_check_thread() is 0x%p", dns_check_thread);
	log_message(LOG_INFO, "Address of dns_connect_thread() is 0x%p", dns_connect_thread);
	log_message(LOG_INFO, "Address of dns_dump() is 0x%p", dns_dump);
	log_message(LOG_INFO, "Address of dns_recv_thread() is 0x%p", dns_recv_thread);
	log_message(LOG_INFO, "Address of dns_send_thread() is 0x%p", dns_send_thread);
}
#endif
