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
 */

#include "config.h"

#include <strings.h>
#include "check_dns.h"
#include "check_api.h"
#include "memory.h"
#include "ipwrapper.h"
#include "logger.h"
#include "smtp.h"
#include "utils.h"
#include "parser.h"
#include "timer.h"
#if !HAVE_DECL_SOCK_CLOEXEC
#include "old_socket.h"
#include "string.h"
#endif

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

	checker_t *checker = THREAD_ARG(thread);
	dns_check_t *dns_check = CHECKER_ARG(checker);

	DNS_DBG("final error=%d attempts=%d retry=%d", error,
		dns_check->attempts, dns_check->retry);

	close(thread->u.fd);

	if (error) {
		if (svr_checker_up(checker->id, checker->rs)) {
			if (fmt) {
				va_start(args, fmt);
				vsnprintf(buf, sizeof (buf), fmt, args);
				dns_log_message(thread, LOG_INFO, buf);
				va_end(args);
			}
			if (dns_check->attempts < dns_check->retry) {
				dns_check->attempts++;
				thread_add_timer(thread->master,
						 dns_connect_thread, checker,
						 checker->vs->delay_loop);
				return 0;
			}
			update_svr_checker_state(DOWN, checker->id, checker->vs,
						 checker->rs);
			smtp_alert(checker->rs, NULL, NULL, "DOWN",
				   "=> DNS_CHECK: failed on service <=");
		}
	} else {
		if (!svr_checker_up(checker->id, checker->rs)) {
			smtp_alert(checker->rs, NULL, NULL, "UP",
				   "=> DNS_CHECK: succeed on service <=");
			update_svr_checker_state(UP, checker->id, checker->vs,
						 checker->rs);
		}
	}

	dns_check->attempts = 0;
	thread_add_timer(thread->master, dns_connect_thread, checker,
			 checker->vs->delay_loop);

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
		dns_final(thread, 1, "read timeout from socket.");
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
		dns_final(thread, 1, "failed to read socket. %s.", strerror(errno));
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
		DNS_DBG("recieve query message?");
		thread_add_read(thread->master, dns_recv_thread, checker,
				thread->u.fd, timeout);
		return 0;
	}

	if ((rcode = DNS_RC(flags)) != 0) {
		dns_final(thread, 1, "error occurread. (rcode = %d)", rcode);
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

	APPEND16(p, dns_type_lookup(dns_check->type));
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
		fcntl(thread->u.fd, F_SETFL,
		      fcntl(thread->u.fd, F_GETFL, 0) | O_NONBLOCK);
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

	if (!CHECKER_ENABLED(checker)) {
		thread_add_timer(thread->master, dns_connect_thread, checker,
				 checker->vs->delay_loop);
		return 0;
	}

	if ((fd = socket(co->dst.ss_family, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP)) == -1) {
		dns_log_message(thread, LOG_INFO,
				"failed to create socket. Rescheduling.");
		thread_add_timer(thread->master, dns_connect_thread, checker,
				 checker->vs->delay_loop);
		return 0;
	}
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
				 checker->vs->delay_loop);
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
dns_dump(void *data)
{
	dns_check_t *dns_check = CHECKER_DATA(data);
	log_message(LOG_INFO, "   Keepalive method = DNS_CHECK");
	dump_conn_opts(CHECKER_CO(data));
	log_message(LOG_INFO, "   Retry = %d", dns_check->retry);
	log_message(LOG_INFO, "   Type = %s", dns_check->type);
	log_message(LOG_INFO, "   Name = %s", dns_check->name);
}

static void
dns_check_handler(__attribute__((unused)) vector_t * strvec)
{
	dns_check_t *dns_check = (dns_check_t *) MALLOC(sizeof (dns_check_t));
	dns_check->retry = DNS_DEFAULT_RETRY;
	dns_check->attempts = 0;
	dns_check->type = DNS_DEFAULT_TYPE;
	dns_check->name = DNS_DEFAULT_NAME;
	queue_checker(dns_free, dns_dump, dns_connect_thread, dns_check,
		      CHECKER_NEW_CO());
}

static void
dns_retry_handler(vector_t * strvec)
{
	dns_check_t *dns_check = CHECKER_GET();
	dns_check->retry = CHECKER_VALUE_INT(strvec);
}

static void
dns_type_handler(vector_t * strvec)
{
	dns_check_t *dns_check = CHECKER_GET();
	dns_check->type = CHECKER_VALUE_STRING(strvec);
}

static void
dns_name_handler(vector_t * strvec)
{
	dns_check_t *dns_check = CHECKER_GET();
	dns_check->name = CHECKER_VALUE_STRING(strvec);
}

void
install_dns_check_keyword(void)
{
	install_keyword("DNS_CHECK", &dns_check_handler);
	install_sublevel();
	install_connect_keywords();
	install_keyword("retry", &dns_retry_handler);
	install_keyword("type", &dns_type_handler);
	install_keyword("name", &dns_name_handler);
	install_sublevel_end();
}
