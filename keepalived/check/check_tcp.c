/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        TCP checker.
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

#include "config.h"

#include <unistd.h>

#include "check_tcp.h"
#include "check_api.h"
#include "memory.h"
#include "ipwrapper.h"
#include "layer4.h"
#include "logger.h"
#include "smtp.h"
#include "utils.h"
#include "parser.h"
#if !HAVE_DECL_SOCK_CLOEXEC
#include "old_socket.h"
#endif

static int tcp_connect_thread(thread_t *);

/* Configuration stream handling */
static void
free_tcp_check(void *data)
{
	FREE(CHECKER_CO(data));
	FREE(CHECKER_DATA(data));
	FREE(data);
}

static void
dump_tcp_check(void *data)
{
	checker_t *checker = data;

	log_message(LOG_INFO, "   Keepalive method = TCP_CHECK");
	dump_checker_opts(checker);
}

static bool
tcp_check_compare(void *a, void *b)
{
	return compare_conn_opts(CHECKER_CO(a), CHECKER_CO(b));
}

static void
tcp_check_handler(__attribute__((unused)) vector_t *strvec)
{
	/* queue new checker */
	queue_checker(free_tcp_check, dump_tcp_check, tcp_connect_thread,
		      tcp_check_compare, NULL, CHECKER_NEW_CO());
}

static void
tcp_check_end_handler(void)
{
	if (!check_conn_opts(CHECKER_GET_CO())) {
		dequeue_new_checker();
	}
}

void
install_tcp_check_keyword(void)
{
	install_keyword("TCP_CHECK", &tcp_check_handler);
	install_sublevel();
	install_checker_common_keywords(true);
	install_sublevel_end_handler(tcp_check_end_handler);
	install_sublevel_end();
}

static void
tcp_epilog(thread_t * thread, bool is_success)
{
	checker_t *checker;
	unsigned long delay;

	checker = THREAD_ARG(thread);

	if (is_success || checker->retry_it >= checker->retry) {
		delay = checker->delay_loop;
		checker->retry_it = 0;

		if (is_success && !checker->is_up) {
			log_message(LOG_INFO, "TCP connection to %s success."
					, FMT_TCP_RS(checker));
			smtp_alert(checker, NULL, NULL,
				   "UP",
				   "=> TCP CHECK succeed on service <=");
			update_svr_checker_state(UP, checker);
		} else if (!is_success
			   && checker->is_up) {
			if (checker->retry)
				log_message(LOG_INFO
				    , "Check on service %s failed after %d retry."
				    , FMT_TCP_RS(checker)
				    , checker->retry);
			smtp_alert(checker, NULL, NULL,
				   "DOWN",
				   "=> TCP CHECK failed on service <=");
			update_svr_checker_state(DOWN, checker);
		}
	} else {
		delay = checker->delay_before_retry;
		++checker->retry_it;
	}

	/* Register next timer checker */
	thread_add_timer(thread->master, tcp_connect_thread, checker, delay);
}

static int
tcp_check_thread(thread_t * thread)
{
	checker_t *checker;
	int status;

	checker = THREAD_ARG(thread);
	status = tcp_socket_state(thread, tcp_check_thread);

	/* If status = connect_in_progress, next thread is already registered.
	 * If it is connect_success, the fd is still open.
	 * Otherwise we have a real connection error or connection timeout.
	 */
	switch(status) {
	case connect_in_progress:
		break;
	case connect_success:
		close(thread->u.fd);
		tcp_epilog(thread, true);
		break;
	case connect_timeout:
		if (checker->is_up)
			log_message(LOG_INFO, "TCP connection to %s timeout."
					, FMT_TCP_RS(checker));
		tcp_epilog(thread, false);
		break;
	default:
		if (checker->is_up)
			log_message(LOG_INFO, "TCP connection to %s failed."
					, FMT_TCP_RS(checker));
		tcp_epilog(thread, false);
	}

	return 0;
}

static int
tcp_connect_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	conn_opts_t *co = checker->co;
	int fd;
	int status;

	/*
	 * Register a new checker thread & return
	 * if checker is disabled
	 */
	if (!checker->enabled) {
		thread_add_timer(thread->master, tcp_connect_thread, checker,
				 checker->delay_loop);
		return 0;
	}

	if ((fd = socket(co->dst.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP)) == -1) {
		log_message(LOG_INFO, "TCP connect fail to create socket. Rescheduling.");
		thread_add_timer(thread->master, tcp_connect_thread, checker,
				checker->delay_loop);

		return 0;
	}

#if !HAVE_DECL_SOCK_NONBLOCK
	if (set_sock_flags(fd, F_SETFL, O_NONBLOCK))
		log_message(LOG_INFO, "Unable to set NONBLOCK on tcp_connect socket - %s (%d)", strerror(errno), errno);
#endif

#if !HAVE_DECL_SOCK_CLOEXEC
	if (set_sock_flags(fd, F_SETFD, FD_CLOEXEC))
		log_message(LOG_INFO, "Unable to set CLOEXEC on tcp_connect socket - %s (%d)", strerror(errno), errno);
#endif

	status = tcp_bind_connect(fd, co);

	/* handle tcp connection status & register check worker thread */
	if(tcp_connection_state(fd, status, thread, tcp_check_thread,
			co->connection_to)) {
		close(fd);
		log_message(LOG_INFO, "TCP socket bind failed. Rescheduling.");
		thread_add_timer(thread->master, tcp_connect_thread, checker,
				checker->delay_loop);
	}

	return 0;
}

#ifdef _TIMER_DEBUG_
void
print_check_tcp_addresses(void)
{
	log_message(LOG_INFO, "Address of dump_tcp_check() is 0x%p", dump_tcp_check);
	log_message(LOG_INFO, "Address of tcp_check_thread() is 0x%p", tcp_check_thread);
	log_message(LOG_INFO, "Address of tcp_connect_thread() is 0x%p", tcp_connect_thread);
}
#endif
