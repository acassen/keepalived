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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <unistd.h>
#include <stdio.h>

#include "check_tcp.h"
#include "check_api.h"
#include "memory.h"
#include "ipwrapper.h"
#include "layer4.h"
#include "logger.h"
#include "smtp.h"
#include "utils.h"
#include "parser.h"
#ifdef THREAD_DUMP
#include "scheduler.h"
#endif
#include "check_parser.h"


static void tcp_connect_thread(thread_ref_t);

/* Configuration stream handling */
static void
free_tcp_check(checker_t *checker)
{
	FREE(checker->co);
	FREE(checker);
}

static void
dump_tcp_check(FILE *fp, __attribute__((unused)) const checker_t *checker)
{
	conf_write(fp, "   Keepalive method = TCP_CHECK");
}

static bool
compare_tcp_check(const checker_t *old_c, checker_t *new_c)
{
	return compare_conn_opts(old_c->co, new_c->co);
}

static const checker_funcs_t tcp_checker_funcs = { CHECKER_TCP, free_tcp_check, dump_tcp_check, compare_tcp_check, NULL };

static void
tcp_check_handler(__attribute__((unused)) const vector_t *strvec)
{
	/* queue new checker */
	queue_checker(&tcp_checker_funcs, tcp_connect_thread, NULL, CHECKER_NEW_CO(), true);
}

static void
tcp_check_end_handler(void)
{
	if (!check_conn_opts(current_checker->co)) {
		dequeue_new_checker();
		return;
	}
}

void
install_tcp_check_keyword(void)
{
	vpp_t check_ptr;

	install_keyword("TCP_CHECK", &tcp_check_handler);
	check_ptr = install_sublevel(VPP &current_checker);
	install_checker_common_keywords(true);
	install_level_end_handler(tcp_check_end_handler);
	install_sublevel_end(check_ptr);
}

static void
tcp_epilog(thread_ref_t thread, bool is_success)
{
	checker_t *checker;
	unsigned long delay;
	bool checker_was_up;
	bool rs_was_alive;

	checker = THREAD_ARG(thread);

	delay = checker->delay_loop;
	if (is_success || ((checker->is_up || !checker->has_run) && checker->retry_it >= checker->retry)) {
		checker->retry_it = 0;

		if (is_success && (!checker->is_up || !checker->has_run)) {
			log_message(LOG_INFO, "TCP connection to %s success."
					, FMT_CHK(checker));
			checker_was_up = checker->is_up;
			rs_was_alive = checker->rs->alive;
			update_svr_checker_state(UP, checker);
			if (checker->rs->smtp_alert && !checker_was_up &&
			    (rs_was_alive != checker->rs->alive || !global_data->no_checker_emails))
				smtp_alert(SMTP_MSG_RS, checker, NULL,
					   "=> TCP CHECK succeed on service <=");
		} else if (!is_success &&
			   (checker->is_up || !checker->has_run)) {
			if (checker->retry && checker->has_run)
				log_message(LOG_INFO
				    , "TCP_CHECK on service %s failed after %u retries."
				    , FMT_CHK(checker)
				    , checker->retry);
			else
				log_message(LOG_INFO
				    , "TCP_CHECK on service %s failed."
				    , FMT_CHK(checker));
			checker_was_up = checker->is_up;
			rs_was_alive = checker->rs->alive;
			update_svr_checker_state(DOWN, checker);
			if (checker->rs->smtp_alert && checker_was_up &&
			    (rs_was_alive != checker->rs->alive || !global_data->no_checker_emails))
				smtp_alert(SMTP_MSG_RS, checker, NULL,
					   "=> TCP CHECK failed on service <=");
		}
	} else if (checker->is_up) {
		delay = checker->delay_before_retry;
		++checker->retry_it;
	}

	checker->has_run = true;

	/* Register next timer checker */
	thread_add_timer(thread->master, tcp_connect_thread, checker, delay);
}

static void
tcp_check_thread(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	int status;

	status = tcp_socket_state(thread, tcp_check_thread, 0);

	/* If status = connect_in_progress, next thread is already registered.
	 * If it is connect_success, the fd is still open.
	 * Otherwise we have a real connection error or connection timeout.
	 */
	switch(status) {
	case connect_in_progress:
		break;
	case connect_success:
		thread_close_fd(thread);
		tcp_epilog(thread, true);
		break;
	case connect_timeout:
		if (checker->is_up &&
		    (global_data->checker_log_all_failures || checker->log_all_failures))
			log_message(LOG_INFO, "TCP connection to %s timeout."
					, FMT_CHK(checker));
		tcp_epilog(thread, false);
		break;
	default:
		if (checker->is_up &&
		    (global_data->checker_log_all_failures || checker->log_all_failures))
			log_message(LOG_INFO, "TCP connection to %s failed."
					, FMT_CHK(checker));
		tcp_epilog(thread, false);
	}
}

static void
tcp_connect_thread(thread_ref_t thread)
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
		return;
	}

	if ((fd = socket(co->dst.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP)) == -1) {
		log_message(LOG_INFO, "TCP connect fail to create socket. Rescheduling.");
		thread_add_timer(thread->master, tcp_connect_thread, checker,
				checker->delay_loop);

		return;
	}

	status = tcp_bind_connect(fd, co);

	/* handle tcp connection status & register check worker thread */
	if(tcp_connection_state(fd, status, thread, tcp_check_thread,
			co->connection_to, 0)) {
		close(fd);

		if (status == connect_fail) {
			tcp_epilog(thread, false);
		} else {
			log_message(LOG_INFO, "TCP socket bind failed. Rescheduling.");
			thread_add_timer(thread->master, tcp_connect_thread, checker,
					checker->delay_loop);
		}
	}
}

#ifdef THREAD_DUMP
void
register_check_tcp_addresses(void)
{
	register_thread_address("tcp_check_thread", tcp_check_thread);
	register_thread_address("tcp_connect_thread", tcp_connect_thread);
}
#endif
