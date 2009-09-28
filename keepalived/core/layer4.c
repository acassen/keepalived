/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Layer4 checkers handling. Register worker threads &
 *              upper layer checkers.
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

#include "layer4.h"
#include "check_api.h"
#include "utils.h"

enum connect_result
tcp_bind_connect(int fd, uint32_t addr_ip, uint16_t addr_port, uint32_t bind_ip)
{
	struct linger li = { 0 };
	int long_inet;
	struct sockaddr_in sa_in;
	int ret;
	int val;

	/* free the tcp port after closing the socket descriptor */
	li.l_onoff = 1;
	li.l_linger = 0;
	setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &li,
		   sizeof (struct linger));

	/* Make socket non-block. */
	val = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, val | O_NONBLOCK);

	/* Bind socket */
	long_inet = sizeof (struct sockaddr_in);
	memset(&sa_in, 0, long_inet);

	if (bind_ip) {
		sa_in.sin_family = AF_INET;
		sa_in.sin_addr.s_addr = bind_ip;
		if (bind(fd, (struct sockaddr *) &sa_in, sizeof (sa_in)) != 0)
			return connect_error;
	}

	/* Set remote IP and connect */
	memset(&sa_in, 0, long_inet);
	sa_in.sin_family = AF_INET;
	sa_in.sin_port = addr_port;
	sa_in.sin_addr.s_addr = addr_ip;

	ret = connect(fd, (struct sockaddr *) &sa_in, long_inet);

	/* Immediate success */
	if (ret == 0) {
		fcntl(fd, F_SETFL, val);
		return connect_success;
	}

	/* If connect is in progress then return 1 else it's real error. */
	if (ret < 0) {
		if (errno != EINPROGRESS)
			return connect_error;
	}

	/* restore previous fd args */
	fcntl(fd, F_SETFL, val);
	return connect_in_progress;
}

enum connect_result
tcp_connect(int fd, uint32_t addr_ip, uint16_t addr_port)
{
	return tcp_bind_connect(fd, addr_ip, addr_port, 0);
}

enum connect_result
tcp_socket_state(int fd, thread * thread_obj, uint32_t addr_ip, uint16_t addr_port,
		 int (*func) (struct _thread *))
{
	int status;
	socklen_t slen;
	int ret = 0;
	TIMEVAL timer_min;

	/* Handle connection timeout */
	if (thread_obj->type == THREAD_WRITE_TIMEOUT) {
		DBG("TCP connection timeout to [%s:%d].",
		    inet_ntop2(addr_ip), ntohs(addr_port));
		close(thread_obj->u.fd);
		return connect_timeout;
	}

	/* Check file descriptor */
	slen = sizeof (status);
	if (getsockopt
	    (thread_obj->u.fd, SOL_SOCKET, SO_ERROR, (void *) &status, &slen) < 0)
		ret = errno;

	/* Connection failed !!! */
	if (ret) {
		DBG("TCP connection failed to [%s:%d].",
		    inet_ntop2(addr_ip), ntohs(addr_port));
		close(thread_obj->u.fd);
		return connect_error;
	}

	/* If status = 0, TCP connection to remote host is established.
	 * Otherwise register checker thread to handle connection in progress,
	 * and other error code until connection is established.
	 * Recompute the write timeout (or pending connection).
	 */
	if (status == EINPROGRESS) {
		DBG("TCP connection to [%s:%d] still IN_PROGRESS.",
		    inet_ntop2(addr_ip), ntohs(addr_port));

		timer_min = timer_sub_now(thread_obj->sands);
		thread_add_write(thread_obj->master, func, THREAD_ARG(thread_obj)
				 , thread_obj->u.fd, TIMER_LONG(timer_min));
		return connect_in_progress;
	} else if (status != 0) {
		close(thread_obj->u.fd);
		return connect_error;
	}

	return connect_success;
}

void
tcp_connection_state(int fd, enum connect_result status, thread * thread_obj,
		     int (*func) (struct _thread *)
		     , long timeout)
{
	checker *checker_obj;

	checker_obj = THREAD_ARG(thread_obj);

	switch (status) {
	case connect_error:
		DBG("TCP connection ERROR to [%s:%d].",
		    inet_ntop2(SVR_IP(checker_obj->rs)),
		    ntohs(SVR_PORT(checker_obj->rs)));
		close(fd);
		break;

	case connect_success:
		DBG("TCP connection SUCCESS to [%s:%d].",
		    inet_ntop2(SVR_IP(checker_obj->rs)),
		    ntohs(SVR_PORT(checker_obj->rs)));
		thread_add_write(thread_obj->master, func, checker_obj, fd, timeout);
		break;

		/* Checking non-blocking connect, we wait until socket is writable */
	case connect_in_progress:
		DBG("TCP connection to [%s:%d] now IN_PROGRESS.",
		    inet_ntop2(SVR_IP(checker_obj->rs)),
		    ntohs(SVR_PORT(checker_obj->rs)));
		thread_add_write(thread_obj->master, func, checker_obj, fd, timeout);
		break;

	default:
		break;
	}
}
