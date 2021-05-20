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

static void udp_connect_thread(thread_ref_t);

/* Configuration stream handling */
static void
free_udp_check(checker_t *checker)
{
	udp_check_t *udp_check = CHECKER_ARG(checker);

	FREE_PTR(udp_check->payload);
	FREE_PTR(udp_check->reply_data);
	FREE_PTR(udp_check->reply_mask);
	FREE(checker->co);
	FREE(checker->data);
	FREE(checker);
}

static void
dump_udp_check(FILE *fp, const checker_t *checker)
{
	udp_check_t *udp_check = CHECKER_ARG(checker);

	conf_write(fp, "   Keepalive method = UDP_CHECK");

	if (udp_check->payload)
		conf_write(fp, "   Payload len = %u", udp_check->payload_len);
	else
		conf_write(fp, "   Payload specified = no");

	conf_write(fp, "   Require reply = %s", udp_check->require_reply ? "yes" : "no");
	if (udp_check->require_reply) {
		conf_write(fp, "     Min reply length = %u", udp_check->min_reply_len);
		conf_write(fp, "     Max reply length = %u", udp_check->max_reply_len);
		conf_write(fp, "     Reply data len = %u", udp_check->reply_len);
		if (udp_check->reply_data)
			conf_write(fp, "     Reply data mask = %s", udp_check->reply_mask ? "yes" : "no");
	}
}

static bool
compare_udp_check(const checker_t *a, checker_t *b)
{
	return compare_conn_opts(a->co, b->co);
}

static const checker_funcs_t udp_checker_funcs = { CHECKER_UDP, free_udp_check, dump_udp_check, compare_udp_check, NULL };

static void
udp_check_handler(__attribute__((unused)) const vector_t *strvec)
{
	udp_check_t *udp_check = MALLOC(sizeof (udp_check_t));

	udp_check->min_reply_len = 0;
	udp_check->max_reply_len = UINT8_MAX;

	/* queue new checker */
	queue_checker(&udp_checker_funcs, udp_connect_thread, udp_check, CHECKER_NEW_CO(), true);
}

static void
payload_handler(const vector_t *strvec)
{
	udp_check_t *udp_check = CHECKER_GET();
	char *hex_str;

	if (vector_size(strvec) == 1) {
		report_config_error(CONFIG_GENERAL_ERROR, "UDP_CHECK payload requires a payload");
		return;
	}

	hex_str = make_strvec_str(strvec, 1);

	udp_check->payload_len = read_hex_str(hex_str, &udp_check->payload, NULL);
	if (!udp_check->payload_len)
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid hex string for UDP_CHECK payload");

	FREE_ONLY(hex_str);
}

static void
require_reply_handler(const vector_t *strvec)
{
	udp_check_t *udp_check = CHECKER_GET();
	char *hex_str;

	udp_check->require_reply = true;

	if (vector_size(strvec) == 1)
		return;

	hex_str = make_strvec_str(strvec, 1);

	udp_check->reply_len = read_hex_str(hex_str, &udp_check->reply_data, &udp_check->reply_mask);
	if (!udp_check->reply_len)
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid hex string for UDP_CHECK reply");

	FREE_ONLY(hex_str);
}

static void
min_length_handler(const vector_t *strvec)
{
	udp_check_t *udp_check = CHECKER_GET();
	unsigned len;

	if (!read_unsigned_strvec(strvec, 1, &len, 0, UINT16_MAX, false)) {
		report_config_error(CONFIG_GENERAL_ERROR, "UDP_CHECK min length %s not valid - must be between 0 & %d", strvec_slot(strvec, 1), UINT16_MAX);
                return;
        }

	udp_check->min_reply_len = len;
}

static void
max_length_handler(const vector_t *strvec)
{
	udp_check_t *udp_check = CHECKER_GET();
	unsigned len;

	if (!read_unsigned_strvec(strvec, 1, &len, 0, UINT16_MAX, false)) {
		report_config_error(CONFIG_GENERAL_ERROR, "UDP_CHECK max length %s not valid - must be between 0 & %d", strvec_slot(strvec, 1), UINT16_MAX);
                return;
        }

	udp_check->max_reply_len = len;
}

static void
udp_check_end_handler(void)
{
	udp_check_t *udp_check = CHECKER_GET();

	if (!check_conn_opts(CHECKER_GET_CO())) {
		dequeue_new_checker();
		return;
	}

	if (udp_check->min_reply_len > udp_check->max_reply_len)
		report_config_error(CONFIG_GENERAL_ERROR, "UDP_CHECK min_reply length %d > max_reply_length %d - will always fail",
				    udp_check->min_reply_len, udp_check->max_reply_len);
}

void
install_udp_check_keyword(void)
{
	/* We don't want some common keywords */
	install_keyword("UDP_CHECK", &udp_check_handler);
	install_sublevel();
	install_checker_common_keywords(true);
	install_keyword("payload", &payload_handler);
	install_keyword("require_reply", &require_reply_handler);
	install_keyword("min_reply_length", &min_length_handler);
	install_keyword("max_reply_length", &max_length_handler);
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

static bool
check_udp_reply(const uint8_t *recv_data, size_t len, const udp_check_t *udp_check)
{
	unsigned i;
	unsigned check_len;

	if (len < udp_check->min_reply_len ||
	    len > udp_check->max_reply_len)
		return true;

	/* We only checker lesser of len and udp_check->reply_len octets */
	check_len = udp_check->reply_len;
	if (len < check_len)
		check_len = len;

	/* Check the received data matches */
	for (i = 0; i < check_len; i++) {
		if ((recv_data[i] ^ udp_check->reply_data[i]) & (udp_check->reply_mask ? ~udp_check->reply_mask[i] : ~0))
			return true;
	}

	/* Success */
	return false;
}

static void
udp_check_thread(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	udp_check_t *udp_check = CHECKER_ARG(checker);
	int status;
	uint8_t *recv_buf;
	size_t len = udp_check->max_reply_len + 1;

	recv_buf = udp_check->require_reply ?
			MALLOC(udp_check->max_reply_len + 1) :
			NULL;

	status = udp_socket_state(thread->u.f.fd, thread, recv_buf, &len);

	thread_close_fd(thread);

	if (status == connect_success) {
		/* coverity[var_deref_model] - udp_check->reply_data is only set if udp_check->require_reply is set */
		if (udp_check->reply_data && check_udp_reply(recv_buf, len, udp_check)) {
			if (checker->is_up &&
			    (global_data->checker_log_all_failures || checker->log_all_failures))
				log_message(LOG_INFO, "UDP check to %s reply data mismatch."
						, FMT_CHK(checker));
			udp_epilog(thread, false);
		} else
			udp_epilog(thread, true);
	} else {
		if (checker->is_up &&
		    (global_data->checker_log_all_failures || checker->log_all_failures))
			log_message(LOG_INFO, "UDP connection to %s failed."
					, FMT_CHK(checker));
		udp_epilog(thread, false);
	}

	if (recv_buf)
		FREE(recv_buf);

	return;
}

static void
udp_connect_thread(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	udp_check_t *udp_check = CHECKER_ARG(checker);
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

	status = udp_bind_connect(fd, co, udp_check->payload, udp_check->payload_len);

	/* handle udp connection status & register check worker thread */
	if (udp_icmp_check_state(fd, status, thread, udp_check_thread, co->connection_to)) {
		close(fd);
		udp_epilog(thread, false);
	}

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
