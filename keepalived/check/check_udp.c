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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <unistd.h>
#include <stdio.h>

#include "check_udp.h"
#include "check_api.h"
#include "memory.h"
#include "ipwrapper.h"
#include "layer4.h"
#include "logger.h"
#include "smtp.h"
#include "utils.h"
#include "parser.h"
#include "check_ping.h"
#if !HAVE_DECL_SOCK_CLOEXEC
#include "old_socket.h"
#endif
#ifdef THREAD_DUMP
#include "scheduler.h"
#endif

static int udp_connect_thread(thread_t *);
static int icmp_connect_thread(thread_t * thread);
static int choose_mode_thread(thread_t * thread);

/* Configuration stream handling */
static void
free_udp_check(void *data)
{
	FREE(CHECKER_CO(data));
	FREE(CHECKER_DATA(data));
	FREE(data);
}

static void
dump_udp_check(FILE *fp, void *data)
{
	checker_t *checker = data;
	conf_write(fp, "   Keepalive method = TCP_CHECK");
	dump_checker_opts(fp, checker);
}

static bool
udp_check_compare(void *a, void *b)
{
	return compare_conn_opts(CHECKER_CO(a), CHECKER_CO(b));
}

static void
udp_check_handler(__attribute__((unused)) vector_t *strvec)
{
	udp_check_t *udp_check;
	udp_check = MALLOC(sizeof (udp_check_t));
        udp_check->ping_check = 1;

	/* queue new checker */
	queue_checker(free_udp_check, dump_udp_check, choose_mode_thread,
		      udp_check_compare, udp_check, CHECKER_NEW_CO());
}

static void
udp_ping_check_off_handler(__attribute__((unused)) vector_t *strvec)
{
	udp_check_t *udp_check = CHECKER_GET();
	udp_check->ping_check = 0;
}

static void
udp_check_end_handler(void)
{
	if (!check_conn_opts(CHECKER_GET_CO())) {
		dequeue_new_checker();
	}
}

void
install_udp_check_keyword(void)
{
	install_keyword("UDP_CHECK", &udp_check_handler);
	install_sublevel();
	install_keyword("ping_check_off", &udp_ping_check_off_handler);
	install_checker_common_keywords(true);
	install_sublevel_end_handler(udp_check_end_handler);
	install_sublevel_end();
}

static void
udp_epilog(thread_t * thread, bool is_success)
{
	checker_t *checker;
	udp_check_t *udp_check;
	unsigned long delay;
	bool checker_was_up;
	bool rs_was_alive;

	checker = THREAD_ARG(thread);
	udp_check = CHECKER_ARG(checker);

	if (is_success || checker->retry_it >= checker->retry) {
		delay = checker->delay_loop;
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
				    , "UDP_CHECK on service %s failed after %d retries."
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
					   "=> TCP CHECK failed on service <=");
		}
		if(udp_check->ping_check)
			thread_add_timer(thread->master, icmp_connect_thread, checker, delay);
		else
			thread_add_timer(thread->master, udp_connect_thread, checker, delay);
	} else {
		delay = checker->delay_before_retry;
		++checker->retry_it;
		thread_add_timer(thread->master, udp_connect_thread, checker, delay);
	}

	checker->has_run = true;
}

static int
udp_check_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	int status;

	status = udp_socket_state(thread->u.f.fd, thread);

	close(thread->u.f.fd);

	switch(status) {
	case connect_success:
		udp_epilog(thread, true);
		break;
	default:
		if (checker->is_up &&
		    (global_data->checker_log_all_failures || checker->log_all_failures))
			log_message(LOG_INFO, "UDP connection to %s failed."
					, FMT_CHK(checker));
		udp_epilog(thread, false);
	}

	return 0;
}

static int
udp_connect_thread(thread_t * thread)
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
		return 0;
	}

	if ((fd = socket(co->dst.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		log_message(LOG_INFO, "UDP connect fail to create socket. Rescheduling.");
		thread_add_timer(thread->master, udp_connect_thread, checker,
				checker->delay_loop);

		return 0;
	}

	status = udp_bind_connect(fd, co);

	/* handle udp connection status & register check worker thread */
	if(udp_connection_state(fd, status, thread, udp_check_thread,
			co->connection_to)) {
		close(fd);
		log_message(LOG_INFO, "TCP socket bind failed. Maybe port used up. Rescheduling.");
		thread_add_timer(thread->master, udp_connect_thread, checker,
					checker->delay_loop);
	}

	return 0;
}

static void
icmp_epilog(thread_t * thread, bool is_success)
{
	checker_t *checker;
	unsigned long delay;
	bool checker_was_up;
	bool rs_was_alive;

	checker = THREAD_ARG(thread);

	if (is_success || checker->retry_it >= checker->retry) {
		delay = checker->delay_loop;
		checker->retry_it = 0;

		if (!is_success && 
			   (checker->is_up || !checker->has_run)) {
			if (checker->retry && checker->has_run)
				log_message(LOG_INFO
				    , "ICMP CHECK on service %s of %s failed after %d retries."
				    , FMT_CHK(checker), FMT_VS(checker->vs)
				    , checker->retry);
			else
				log_message(LOG_INFO
				    , "ICMP CHECK on service %s failed."
				    , FMT_CHK(checker));
			checker_was_up = checker->is_up;
			rs_was_alive = checker->rs->alive;
			update_svr_checker_state(DOWN, checker);
			if (checker->rs->smtp_alert && checker_was_up &&
			    (rs_was_alive != checker->rs->alive || !global_data->no_checker_emails))
				smtp_alert(SMTP_MSG_RS, checker, NULL,
					   "=> ICMP CHECK failed on service <=");
		}
	} else {
		delay = checker->delay_before_retry;
		++checker->retry_it;
	}
	if(is_success)
		thread_add_timer(thread->master, udp_connect_thread, checker, 0);
	else
		thread_add_timer(thread->master, icmp_connect_thread, checker, delay);
}

static int
icmp_check_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	int status;

	if (thread->type == THREAD_READ_TIMEOUT) {
		if (checker->is_up)
			log_message(LOG_INFO, "ICMP connection to address %s Timeout.", FMT_CHK(checker));
		status = connect_error;
	} else {
		status = checker->co->dst.ss_family == AF_INET ?
			recv_it(thread->u.f.fd):recv6_it(thread->u.f.fd);
	}
	/*
	 * If status = connect_success, then we start udp check with the record of icmp failed times.
	 * Otherwise we will do the icmp connect again until it reaches the unhealthy threshold.
	 * we handle fd uniform.
	 */
	close(thread->u.f.fd);
	switch(status) {
	case connect_success:
		icmp_epilog(thread, 1);
		break;
	case connect_error:
		if (checker->is_up)
			log_message(LOG_INFO, "ICMP connection to %s of %s failed."
				,FMT_CHK(checker), FMT_VS(checker->vs));
		icmp_epilog(thread, 0);
		break;
	default:
		break;
	}
	return 0;
}

int
icmp_connect_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	conn_opts_t *co = checker->co;
	int fd;
	int status;
	struct protoent* protocol = NULL;
	int size = SOCK_RECV_BUFF;

	if (!checker->enabled) {
		thread_add_timer(thread->master, icmp_connect_thread, checker,
				checker->delay_loop);
		return 0;
	}

	protocol = co->dst.ss_family == AF_INET ? getprotobyname("icmp"):getprotobyname("ipv6-icmp");

	if (!protocol) {
		log_message(LOG_INFO, "%s connect fail to getprotobyname. Rescheduling.",
			(co->dst.ss_family == AF_INET)?"ICMP":"ICMPv6");
		thread_add_timer(thread->master, icmp_connect_thread, checker,
				checker->delay_loop);
		return 0;
	}

	if ((fd = socket(co->dst.ss_family, SOCK_DGRAM, protocol->p_proto)) == -1) {
		log_message(LOG_INFO, "%s connect fail to create socket. Rescheduling.",
			(co->dst.ss_family == AF_INET)?"ICMP":"ICMPv6");
		thread_add_timer(thread->master, icmp_connect_thread, checker,
				checker->delay_loop);
		return 0;
	}

	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	/*
	 * OK if setsockopt fails
	 * Prevent users from pinging broadcast or multicast addresses
	 */
	if (co->dst.ss_family == AF_INET)
		status = ping_it(fd, co);
	else
		status = ping6_it(fd, co);

	/* handle icmp send status & register check worker thread */
	if(icmp_send_state(fd, status, thread, icmp_check_thread,
		co->connection_to)) {
		close(fd);
		log_message(LOG_INFO, "ICMP socket send failed. Rescheduling.");
		thread_add_timer(thread->master, icmp_connect_thread, checker,
			checker->delay_loop);
	}
	return 0;
}

int
choose_mode_thread(thread_t * thread){
	checker_t *checker = THREAD_ARG(thread);
	udp_check_t *udp_check = CHECKER_ARG(checker);
	if(udp_check->ping_check)
		thread_add_timer(thread->master, icmp_connect_thread, checker, 0);
	else
		thread_add_timer(thread->master, udp_connect_thread, checker, 0);
	return 0;
}


#ifdef THREAD_DUMP
void
register_check_udp_addresses(void)
{
	register_thread_address("icmp_check_thread", icmp_check_thread);
	register_thread_address("icmp_connect_thread", icmp_connect_thread);
	register_thread_address("udp_check_thread", udp_check_thread);
	register_thread_address("udp_connect_thread", udp_connect_thread);
}
#endif
