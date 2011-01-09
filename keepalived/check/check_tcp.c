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
 * Copyright (C) 2001-2010 Alexandre Cassen, <acassen@freebox.fr>
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

int tcp_connect_thread(thread *);

/* Configuration stream handling */
void
free_tcp_check(void *data)
{
	tcp_checker *tcp_chk = CHECKER_DATA(data);

	FREE(tcp_chk);
	FREE(data);
}

void
dump_tcp_check(void *data)
{
	tcp_checker *tcp_chk = CHECKER_DATA(data);

	log_message(LOG_INFO, "   Keepalive method = TCP_CHECK");
	log_message(LOG_INFO, "   Connection port = %d", ntohs(inet_sockaddrport(&tcp_chk->dst)));
	if (tcp_chk->bindto.ss_family)
		log_message(LOG_INFO, "   Bind to = %s", inet_sockaddrtos(&tcp_chk->bindto));
	log_message(LOG_INFO, "   Connection timeout = %d", tcp_chk->connection_to/TIMER_HZ);
}

void
tcp_check_handler(vector strvec)
{
	tcp_checker *tcp_chk = (tcp_checker *) MALLOC(sizeof (tcp_checker));

	/* queue new checker */
	checker_set_dst(&tcp_chk->dst);
	queue_checker(free_tcp_check, dump_tcp_check, tcp_connect_thread, tcp_chk);
}

void
connect_port_handler(vector strvec)
{
	tcp_checker *tcp_chk = CHECKER_GET();

	checker_set_dst_port(&tcp_chk->dst, htons(CHECKER_VALUE_INT(strvec)));
}

void
bind_handler(vector strvec)
{
	tcp_checker *tcp_chk = CHECKER_GET();
	inet_stosockaddr(VECTOR_SLOT(strvec, 1), 0, &tcp_chk->bindto);
}

void
connect_timeout_handler(vector strvec)
{
	tcp_checker *tcp_chk = CHECKER_GET();
	tcp_chk->connection_to = CHECKER_VALUE_INT(strvec) * TIMER_HZ;
}

void
install_tcp_check_keyword(void)
{
	install_keyword("TCP_CHECK", &tcp_check_handler);
	install_sublevel();
	install_keyword("connect_port", &connect_port_handler);
	install_keyword("bindto", &bind_handler);
	install_keyword("connect_timeout", &connect_timeout_handler);
	install_sublevel_end();
}

int
tcp_check_thread(thread * thread_obj)
{
	checker *checker_obj;
	tcp_checker *tcp_check;
	int status;

	checker_obj = THREAD_ARG(thread_obj);
	tcp_check = CHECKER_ARG(checker_obj);

	status = tcp_socket_state(thread_obj->u.fd, thread_obj, tcp_check_thread);

	/* If status = connect_success, TCP connection to remote host is established.
	 * Otherwise we have a real connection error or connection timeout.
	 */
	if (status == connect_success) {
		close(thread_obj->u.fd);

		if (!svr_checker_up(checker_obj->id, checker_obj->rs)) {
			log_message(LOG_INFO, "TCP connection to [%s:%d] success."
					    , inet_sockaddrtos(&tcp_check->dst)
					    , ntohs(inet_sockaddrport(&tcp_check->dst)));
			smtp_alert(checker_obj->rs, NULL, NULL,
				   "UP",
				   "=> TCP CHECK succeed on service <=");
			update_svr_checker_state(UP, checker_obj->id
						   , checker_obj->vs
						   , checker_obj->rs);
		}

	} else {

		if (svr_checker_up(checker_obj->id, checker_obj->rs)) {
			log_message(LOG_INFO, "TCP connection to [%s:%d] failed !!!"
					    , inet_sockaddrtos(&tcp_check->dst)
					    , ntohs(inet_sockaddrport(&tcp_check->dst)));
			smtp_alert(checker_obj->rs, NULL, NULL,
				   "DOWN",
				   "=> TCP CHECK failed on service <=");
			update_svr_checker_state(DOWN, checker_obj->id
						     , checker_obj->vs
						     , checker_obj->rs);
		}

	}

	/* Register next timer checker */
	if (status != connect_in_progress)
		thread_add_timer(thread_obj->master, tcp_connect_thread, checker_obj,
				 checker_obj->vs->delay_loop);
	return 0;
}

int
tcp_connect_thread(thread * thread_obj)
{
	checker *checker_obj = THREAD_ARG(thread_obj);
	tcp_checker *tcp_check = CHECKER_ARG(checker_obj);
	int fd;
	int status;

	/*
	 * Register a new checker thread & return
	 * if checker is disabled
	 */
	if (!CHECKER_ENABLED(checker_obj)) {
		thread_add_timer(thread_obj->master, tcp_connect_thread, checker_obj,
				 checker_obj->vs->delay_loop);
		return 0;
	}

	if ((fd = socket(tcp_check->dst.ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		DBG("TCP connect fail to create socket.");
		return 0;
	}

	status = tcp_bind_connect(fd, &tcp_check->dst, &tcp_check->bindto);
	if (status == connect_error) {
		thread_add_timer(thread_obj->master, tcp_connect_thread, checker_obj,
				 checker_obj->vs->delay_loop);
		return 0;
	}

	/* handle tcp connection status & register check worker thread */
	tcp_connection_state(fd, status, thread_obj, tcp_check_thread,
			     tcp_check->connection_to);
	return 0;
}
