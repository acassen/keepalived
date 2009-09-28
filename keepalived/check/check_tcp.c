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
 * Copyright (C) 2001-2009 Alexandre Cassen, <acassen@freebox.fr>
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
	if (tcp_chk->connection_port)
		log_message(LOG_INFO, "   Connection port = %d",
		       ntohs(tcp_chk->connection_port));
	if (tcp_chk->bindto)
		log_message(LOG_INFO, "   Bind to = %s", inet_ntop2(tcp_chk->bindto));
	log_message(LOG_INFO, "   Connection timeout = %d", tcp_chk->connection_to/TIMER_HZ);
}

void
tcp_check_handler(vector strvec)
{
	tcp_checker *tcp_chk = (tcp_checker *) MALLOC(sizeof (tcp_checker));

	/* queue new checker */
	queue_checker(free_tcp_check, dump_tcp_check, tcp_connect_thread,
		      tcp_chk);
}

void
connect_port_handler(vector strvec)
{
	tcp_checker *tcp_chk = CHECKER_GET();
	tcp_chk->connection_port = htons(CHECKER_VALUE_INT(strvec));
}

void
bind_handler(vector strvec)
{
	tcp_checker *tcp_chk = CHECKER_GET();
	inet_ston(VECTOR_SLOT(strvec, 1), &tcp_chk->bindto);
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
	uint16_t addr_port;
	int status;

	checker_obj = THREAD_ARG(thread_obj);
	tcp_check = CHECKER_ARG(checker_obj);

	addr_port = CHECKER_RPORT(checker_obj);
	if (tcp_check->connection_port)
		addr_port = tcp_check->connection_port;
	status = tcp_socket_state(thread_obj->u.fd, thread_obj, CHECKER_RIP(checker_obj)
				  , addr_port, tcp_check_thread);

	/* If status = connect_success, TCP connection to remote host is established.
	 * Otherwise we have a real connection error or connection timeout.
	 */
	if (status == connect_success) {
		close(thread_obj->u.fd);

		if (!svr_checker_up(checker_obj->id, checker_obj->rs)) {
			log_message(LOG_INFO, "TCP connection to [%s:%d] success.",
			       inet_ntop2(CHECKER_RIP(checker_obj))
			       , ntohs(addr_port));
			smtp_alert(checker_obj->rs, NULL, NULL,
				   "UP",
				   "=> TCP CHECK succeed on service <=");
			update_svr_checker_state(UP, checker_obj->id
						   , checker_obj->vs
						   , checker_obj->rs);
		}

	} else {

		if (svr_checker_up(checker_obj->id, checker_obj->rs)) {
			log_message(LOG_INFO, "TCP connection to [%s:%d] failed !!!",
			       inet_ntop2(CHECKER_RIP(checker_obj))
			       , ntohs(addr_port));
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
	uint16_t addr_port;
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

	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		DBG("TCP connect fail to create socket.");
		return 0;
	}

	addr_port = CHECKER_RPORT(checker_obj);
	if (tcp_check->connection_port)
		addr_port = tcp_check->connection_port;
	status = tcp_bind_connect(fd, CHECKER_RIP(checker_obj), addr_port
				  , tcp_check->bindto);

	/* handle tcp connection status & register check worker thread */
	tcp_connection_state(fd, status, thread_obj, tcp_check_thread,
			     tcp_check->connection_to);
	return 0;
}
