/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        UDP checker.
 *
 * Author:      Jie Liu, <liujie165@huawei.com>
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
 * Copyright (C) 2019-2019 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

/* system includes */
#include <stdio.h>
#include <unistd.h>

/* local includes */
#include "scheduler.h"
#include "check_udp.h"
#include "check_api.h"
#include "memory.h"
#include "ipwrapper.h"
#include "layer4.h"
#include "logger.h"
#include "global_data.h"
#include "smtp.h"
#include "utils.h"
#include "parser.h"
#if !HAVE_DECL_SOCK_CLOEXEC
#include "old_socket.h"
#endif

static void udp_connect_thread(thread_ref_t);

/* Configuration stream handling */
static void
free_udp_check(checker_t *checker)
{
	FREE(checker->co);
	FREE(checker->data);
	FREE(checker);
}

static void
dump_udp_check(FILE *fp, const checker_t *checker)
{
	udp_check_t *udp_check = CHECKER_ARG(checker);

	conf_write(fp, "   Keepalive method = UDP_CHECK");
	dump_checker_opts(fp, checker);
	conf_write(fp, "   Require reply = %s", udp_check->require_reply ? "yes" : "no");
}

static bool
udp_check_compare(const checker_t *a, checker_t *b)
{
	return compare_conn_opts(a->co, b->co);
}

static void
udp_check_handler(__attribute__((unused)) const vector_t *strvec)
{
	udp_check_t *udp_check = MALLOC(sizeof (udp_check_t));

	/* queue new checker */
	queue_checker(free_udp_check, dump_udp_check, udp_connect_thread,
		      udp_check_compare, udp_check, CHECKER_NEW_CO(), true);
}
static void
require_reply_handler(__attribute__((unused)) const vector_t *strvec)
{
	udp_check_t *udp_check = CHECKER_GET();

	udp_check->require_reply = true;
}

static void
udp_check_end_handler(void)
{
	if (!check_conn_opts(CHECKER_GET_CO()))
		dequeue_new_checker();
}

void
install_udp_check_keyword(void)
{
	/* We don't want some common keywords */
	install_keyword("UDP_CHECK", &udp_check_handler);
	install_sublevel();
	install_checker_common_keywords(true);
	install_keyword("require_reply", &require_reply_handler);
	install_sublevel_end_handler(udp_check_end_handler);
	install_sublevel_end();
}

static void
udp_epilog(thread_ref_t thread, bool is_success)
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
			log_message(LOG_INFO, "UDP connection to %s success."
					, FMT_CHK(checker));
			checker_was_up = checker->is_up;
			rs_was_alive = checker->rs->alive;
			update_svr_checker_state(UP, checker);
			if (checker->rs->smtp_alert && !checker_was_up &&
			    (rs_was_alive != checker->rs->alive || !global_data->no_checker_emails))
				smtp_alert(SMTP_MSG_RS, checker, NULL,
					   "=> UDP CHECK succeed on service <=");
		} else if (!is_success &&
			   (checker->is_up || !checker->has_run)) {
			if (checker->retry && checker->has_run)
				log_message(LOG_INFO
				    , "UDP_CHECK on service %s failed after %u retries."
				    , FMT_CHK(checker)
				    , checker->retry);
			else
				log_message(LOG_INFO
				    , "UDP_CHECK on service %s failed."
				    , FMT_CHK(checker));
			checker_was_up = checker->is_up;
			rs_was_alive = checker->rs->alive;
			update_svr_checker_state(DOWN, checker);
			if (checker->rs->smtp_alert && checker_was_up &&
			    (rs_was_alive != checker->rs->alive || !global_data->no_checker_emails))
				smtp_alert(SMTP_MSG_RS, checker, NULL,
					   "=> UDP CHECK failed on service <=");
		}
	} else if (checker->is_up) {
		delay = checker->delay_before_retry;
		++checker->retry_it;
	}

	checker->has_run = true;

	thread_add_timer(thread->master, udp_connect_thread, checker, delay);
}

static void
udp_check_thread(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	udp_check_t *udp_check = CHECKER_ARG(checker);
	int status;

	status = udp_socket_state(thread->u.f.fd, thread, udp_check->require_reply);

	thread_close_fd(thread);

	if (status == connect_success)
		udp_epilog(thread, true);
	else {
		if (checker->is_up &&
		    (global_data->checker_log_all_failures || checker->log_all_failures))
			log_message(LOG_INFO, "UDP connection to %s failed."
					, FMT_CHK(checker));
		udp_epilog(thread, false);
	}

	return;
}

static void
udp_connect_thread(thread_ref_t thread)
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
		thread_add_timer(thread->master, udp_connect_thread, checker,
				 checker->delay_loop);
		return;
	}

	if ((fd = socket(co->dst.ss_family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP)) == -1) {
		log_message(LOG_INFO, "UDP connect fail to create socket. Rescheduling.");
		thread_add_timer(thread->master, udp_connect_thread, checker,
				checker->delay_loop);

		return;
	}
#if !HAVE_DECL_SOCK_NONBLOCK
	if (set_sock_flags(fd, F_SETFL, O_NONBLOCK))
		log_message(LOG_INFO, "Unable to set NONBLOCK on icmp_connect socket - %s (%d)", strerror(errno), errno);
#endif

#if !HAVE_DECL_SOCK_CLOEXEC
	if (set_sock_flags(fd, F_SETFD, FD_CLOEXEC))
		log_message(LOG_INFO, "Unable to set CLOEXEC on icmp_connect socket - %s (%d)", strerror(errno), errno);
#endif

	status = udp_bind_connect(fd, co);

	/* handle udp connection status & register check worker thread */
	if (udp_icmp_check_state(fd, status, thread, udp_check_thread, co->connection_to))
		udp_epilog(thread, false);

	return;
}

#ifdef THREAD_DUMP
void
register_check_udp_addresses(void)
{
	register_thread_address("udp_check_thread", udp_check_thread);
	register_thread_address("udp_connect_thread", udp_connect_thread);
}
#endif
