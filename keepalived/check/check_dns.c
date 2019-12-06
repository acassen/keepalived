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
#include "scheduler.h"
#include "bitops.h"

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

static int
dns_epilog(thread_ref_t thread, bool is_success)
{
	checker_t *checker = THREAD_ARG(thread);

#ifdef _CHECKER_DEBUG
	if (do_checker_debug)
		log_message(LOG_DEBUG, "DNS_CHECK (%s) final error=%d attempts=%u retry=%u",
				FMT_CHECKER(checker), error, checker->retry_it, checker->retry);
#endif

	if (thread->type != THREAD_TIMER)
		thread_close_fd(thread);

	check_update_svr_checker_state(is_success, checker, thread, "DNS", dns_connect_thread);

	return 0;
}

static void
dns_recv_thread(thread_ref_t thread)
{
	unsigned long timeout;
	ssize_t ret;
	char rbuf[DNS_BUFFER_SIZE];
	dns_header_t *s_header, *r_header;
	int flags, rcode;

	checker_t *checker = THREAD_ARG(thread);
	dns_check_t *dns_check = CHECKER_ARG(checker);

	if (thread->type == THREAD_READ_TIMEOUT) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "read timeout from socket");

		dns_epilog(thread, false);
		return;
	}

	timeout = timer_long(thread->sands) - timer_long(time_now);

	ret = recv(thread->u.f.fd, rbuf, sizeof (rbuf), 0);
	if (ret == -1) {
		if (check_EAGAIN(errno) || check_EINTR(errno)) {
			thread_add_read(thread->master, dns_recv_thread,
					checker, thread->u.f.fd, timeout, true);
			return;
		}
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "failed to read socket. %s", strerror(errno));

		dns_epilog(thread, false);
		return;
	}

	if (ret < (ssize_t) sizeof (r_header)) {
#ifdef _CHECKER_DEBUG
		if (do_checker_debug)
			log_message(LOG_DEBUG, "DNS_CHECK (%s) too small message. (%ld bytes)", FMT_CHECKER(checker), ret);
#endif
		thread_add_read(thread->master, dns_recv_thread, checker,
				thread->u.f.fd, timeout, true);
		return;
	}

	s_header = (dns_header_t *) dns_check->sbuf;
	r_header = (dns_header_t *) rbuf;

	if (s_header->id != r_header->id) {
#ifdef _CHECKER_DEBUG
		if (do_checker_debug)
			log_message(LOG_DEBUG, "DNS_CHECK (%s) ID does not match. (%04x != %04x)",
					FMT_CHECKER(checker), ntohs(s_header->id), ntohs(r_header->id));
#endif
		thread_add_read(thread->master, dns_recv_thread, checker,
				thread->u.f.fd, timeout, true);
		return;
	}

	flags = ntohs(r_header->flags);

	if (!DNS_QR(flags)) {
#ifdef _CHECKER_DEBUG
		if (do_checker_debug)
			log_message(thread, LOG_DEBUG, "DNS_CHECK (%s) receive query message?", FMT_CHECKER(checker));
#endif
		thread_add_read(thread->master, dns_recv_thread, checker,
				thread->u.f.fd, timeout, true);
		return;
	}

	if ((rcode = DNS_RC(flags)) != 0) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "read error occurred. (rcode = %d)", rcode);

		dns_epilog(thread, false);
		return;
	}

	/* success */
	dns_epilog(thread, true);
}

#define APPEND16(x, y) do { \
		*(uint16_t *) (x) = htons(y); \
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
	dns_header_t *header = (dns_header_t *) dns_check->sbuf;

	DNS_SET_RD(flags, 1);	/* Recursion Desired */

	/* coverity[dont_call] */
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
	*(p++) = 0;	/* Terminate the name */

	APPEND16(p, dns_check->type);
	APPEND16(p, 1);		/* IN */

	dns_check->slen = (size_t)(p - (uint8_t *)header);
}

static void
dns_send(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	dns_check_t *dns_check = CHECKER_ARG(checker);
	unsigned long timeout;
	ssize_t ret;

	timeout = timer_long(thread->sands) - timer_long(time_now);

	ret = send(thread->u.f.fd, dns_check->sbuf, dns_check->slen, 0);
	if (ret == -1) {
		if (check_EAGAIN(errno) || check_EINTR(errno)) {
			thread_add_write(thread->master, dns_send_thread,
					 checker, thread->u.f.fd, timeout, true);
			return;
		}
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "failed to write socket.");

		dns_epilog(thread, false);
		return;
	}

	if (ret != (ssize_t) dns_check->slen) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "failed to write all of the datagram.");

		dns_epilog(thread, false);
		return;
	}

	thread_add_read(thread->master, dns_recv_thread, checker, thread->u.f.fd, timeout, true);

	return;
}

static void
dns_send_thread(thread_ref_t thread)
{
	if (thread->type == THREAD_WRITE_TIMEOUT) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "write timeout to socket.");

		dns_epilog(thread, false);
		return;
	}

	dns_send(thread);
}

static void
dns_check_thread(thread_ref_t thread)
{
	int status;

	if (thread->type == THREAD_WRITE_TIMEOUT) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "write timeout to socket.");

		dns_epilog(thread, false);
		return;
	}

	status = socket_state(thread, dns_check_thread);

	/* If status = connect_in_progress, next thread is already registered.
	 * If it is connect_success, the fd is still open.
	 * Otherwise we have a real connection error or connection timeout.
	 */
	switch (status) {
	case connect_error:
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "connection error.");

		dns_epilog(thread, false);
		break;
	case connect_timeout:
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "connection timeout.");

		dns_epilog(thread, false);
		break;
	case connect_fail:
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "connection failure.");

		dns_epilog(thread, false);
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
		log_message(LOG_INFO, "DNS_CHECK (%s) failed to create socket. Rescheduling.", FMT_CHK(checker));
		thread_add_timer(thread->master, dns_connect_thread, checker,
				 checker->delay_loop);
		return;
	}

#if !HAVE_DECL_SOCK_NONBLOCK
	if (set_sock_flags(fd, F_SETFL, O_NONBLOCK))
		log_message(LOG_INFO, "DNS_CHECK (%s) unable to set NONBLOCK on socket - %s (%d)",
				FMT_CHK(checker), strerror(errno), errno);
#endif

#if !HAVE_DECL_SOCK_CLOEXEC
	if (set_sock_flags(fd, F_SETFD, FD_CLOEXEC))
		log_message(LOG_INFO, "DNS_CHECK (%s) unable to set CLOEXEC on socket - %s (%d)",
				FMT_CHK(checker),strerror(errno), errno);
#endif

	status = socket_bind_connect(fd, co);

	if (status == connect_success) {
		thread_fd = *thread;
		thread_fd.u.f.fd = fd;
		dns_make_query(&thread_fd);
		dns_send(&thread_fd);

		return;
	}

	if (status == connect_fail) {
		close(fd);
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "network unreachable for %s", inet_sockaddrtopair(&co->dst));

		dns_epilog(thread, false);

		return;
	}

	/* handle connection status & register check worker thread */
	if (socket_connection_state(fd, status, thread, dns_check_thread, co->connection_to)) {
		close(fd);
		log_message(LOG_INFO, "DNS_CHECK (%s) UDP socket bind failed. Rescheduling.", FMT_CHK(checker));
		thread_add_timer(thread->master, dns_connect_thread, checker,
				 checker->delay_loop);
	}
}

static void
dns_free(checker_t *checker)
{
	dns_check_t *dns_check = checker->data;

	FREE_CONST(dns_check->name);
}

static void
dns_dump(FILE *fp, const checker_t *checker)
{
	const dns_check_t *dns_check = checker->data;

	conf_write(fp, "   Keepalive method = DNS_CHECK");
	dump_checker_opts(fp, checker);
	conf_write(fp, "   Type = %s", dns_type_name(dns_check->type));
	conf_write(fp, "   Name = %s", dns_check->name);
}

static bool
dns_check_compare(const checker_t *old_c, const checker_t *new_c)
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

static void
dns_check_handler(__attribute__((unused)) const vector_t *strvec)
{
	checker_t *checker;

	dns_check_t *dns_check = (dns_check_t *) MALLOC(sizeof (dns_check_t));
	dns_check->type = DNS_DEFAULT_TYPE;
	dns_check->name = DNS_DEFAULT_NAME;
	checker = queue_checker(dns_free, dns_dump, dns_connect_thread,
				dns_check_compare, dns_check, CHECKER_NEW_CO(), true);

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
	dns_check->name = set_value(strvec);
}

static void
dns_check_end(void)
{
	if (!check_conn_opts(CHECKER_GET_CO())) {
		dequeue_new_checker();
	}
// Is name needed?
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
