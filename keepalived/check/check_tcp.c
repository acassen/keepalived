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

#include "check_tcp.h"
#include "check_api.h"
#include "memory.h"
#include "ipwrapper.h"
#include "layer4.h"
#include "logger.h"
#include "smtp.h"
#include "utils.h"
#include "parser.h"

int tcp_connect_thread(thread_t *);

/* Configuration stream handling */
void
free_tcp_check(void *data)
{
	FREE(CHECKER_CO(data));
	FREE(CHECKER_DATA(data));
	FREE(data);
}

void
dump_tcp_check(void *data)
{
	tcp_check_t *tcp_check = CHECKER_DATA(data);

	log_message(LOG_INFO, "   Keepalive method = TCP_CHECK");
	dump_conn_opts (CHECKER_CO(data));
	if (tcp_check->n_retry) {
		log_message(LOG_INFO, "     Retry count = %d"
			    , tcp_check->n_retry);
		log_message(LOG_INFO, "     Retry delay = %ld"
			    , tcp_check->delay_before_retry / TIMER_HZ);
	}
}

void
tcp_check_handler(vector_t *strvec)
{
	tcp_check_t *tcp_check;

	tcp_check = MALLOC(sizeof (tcp_check_t));
	tcp_check->n_retry = 1;
	tcp_check->delay_before_retry = 1 * TIMER_HZ;

	/* queue new checker */
	queue_checker(free_tcp_check, dump_tcp_check, tcp_connect_thread
		      ,tcp_check, CHECKER_NEW_CO());
}

void
tcp_retry_handler(vector_t *strvec)
{
	tcp_check_t *tcp_check = CHECKER_GET();
	tcp_check->n_retry = CHECKER_VALUE_INT(strvec);
}

void
tcp_delay_before_retry_handler(vector_t *strvec)
{
	tcp_check_t *tcp_check = CHECKER_GET();
	tcp_check->delay_before_retry =
		(long)CHECKER_VALUE_INT(strvec) * TIMER_HZ;
}

void
install_tcp_check_keyword(void)
{
	install_keyword("TCP_CHECK", &tcp_check_handler);
	install_sublevel();
	install_keyword("retry", &tcp_retry_handler);
	install_keyword("delay_before_retry", &tcp_delay_before_retry_handler);
	install_connect_keywords();
	install_keyword("warmup", &warmup_handler);
	install_sublevel_end();
}

void
tcp_eplilog(thread_t * thread, int is_success)
{
	checker_t *checker;
	tcp_check_t *tcp_check;
	long delay;

	checker = THREAD_ARG(thread);
	tcp_check = CHECKER_ARG(checker);

	if (is_success || tcp_check->retry_it > tcp_check->n_retry - 1) {
		delay = checker->vs->delay_loop;
		tcp_check->retry_it = 0;

		if (is_success && !svr_checker_up(checker->id, checker->rs)) {
			log_message(LOG_INFO, "TCP connection to %s success."
					, FMT_TCP_RS(checker));
			smtp_alert(checker->rs, NULL, NULL,
				   "UP",
				   "=> TCP CHECK succeed on service <=");
			update_svr_checker_state(UP, checker->id
						   , checker->vs
						   , checker->rs);
		} else if (! is_success
			   && svr_checker_up(checker->id, checker->rs)) {
			if (tcp_check->n_retry)
				log_message(LOG_INFO
				    , "Check on service %s failed after %d retry."
				    , FMT_TCP_RS(checker)
				    , tcp_check->n_retry);
			smtp_alert(checker->rs, NULL, NULL,
				   "DOWN",
				   "=> TCP CHECK failed on service <=");
			update_svr_checker_state(DOWN, checker->id
						     , checker->vs
						     , checker->rs);
		}
	} else {
		delay = tcp_check->delay_before_retry;
		++tcp_check->retry_it;
	}

	/* Register next timer checker */
	thread_add_timer(thread->master, tcp_connect_thread, checker, delay);
}

int
tcp_check_thread(thread_t * thread)
{
	checker_t *checker;
	int status;

	checker = THREAD_ARG(thread);
	status = tcp_socket_state(thread->u.fd, thread, tcp_check_thread);

	/* If status = connect_in_progress, next thread is already registered.
	 * If it is connect_success, the fd is still open.
	 * Otherwise we have a real connection error or connection timeout.
	 */
	switch(status) {
	case connect_in_progress:
		break;
	case connect_success:
		close(thread->u.fd);
		tcp_eplilog(thread, 1);
		break;
	case connect_timeout:
		if (svr_checker_up(checker->id, checker->rs))
			log_message(LOG_INFO, "TCP connection to %s timeout."
					, FMT_TCP_RS(checker));
		tcp_eplilog(thread, 0);
		break;
	default:
		if (svr_checker_up(checker->id, checker->rs))
			log_message(LOG_INFO, "TCP connection to %s failed."
					, FMT_TCP_RS(checker));
		tcp_eplilog(thread, 0);
	}

	return 0;
}

int
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
	if (!CHECKER_ENABLED(checker)) {
		thread_add_timer(thread->master, tcp_connect_thread, checker,
				 checker->vs->delay_loop);
		return 0;
	}

	if ((fd = socket(co->dst.ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		log_message(LOG_INFO, "TCP connect fail to create socket. Rescheduling.");
		thread_add_timer(thread->master, tcp_connect_thread, checker,
				checker->vs->delay_loop);

		return 0;
	}

	status = tcp_bind_connect(fd, co);

	/* handle tcp connection status & register check worker thread */
	if(tcp_connection_state(fd, status, thread, tcp_check_thread,
			co->connection_to)) {
		close(fd);
		log_message(LOG_INFO, "TCP socket bind failed. Rescheduling.");
		thread_add_timer(thread->master, tcp_connect_thread, checker,
				checker->vs->delay_loop);
	}

	return 0;
}
