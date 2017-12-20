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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <errno.h>
#include <unistd.h>

#include "layer4.h"
#include "logger.h"

#ifndef _WITH_LVS_
static
#endif
enum connect_result
socket_bind_connect(int fd, conn_opts_t *co)
{
	int opt;
	socklen_t optlen;
	struct linger li;
	socklen_t addrlen;
	int ret;
	struct sockaddr_storage *addr = &co->dst;
	struct sockaddr_storage *bind_addr = &co->bindto;

	optlen = sizeof(opt);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, (void *) &opt, &optlen) < 0) {
		log_message(LOG_ERR, "Can't get socket type: %s", strerror(errno));
		return connect_error;
	}
	if (opt == SOCK_STREAM) {
		/* free the tcp port after closing the socket descriptor */
		li.l_onoff = 1;
		li.l_linger = 0;
		setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &li, sizeof (struct linger));
	}

#ifdef _WITH_SO_MARK_
	if (co->fwmark) {
		if (setsockopt (fd, SOL_SOCKET, SO_MARK, &co->fwmark, sizeof (co->fwmark)) < 0) {
			log_message(LOG_ERR, "Error setting fwmark %d to socket: %s", co->fwmark, strerror(errno));
			return connect_error;
		}
	}
#endif

	if (co->bind_if[0]) {
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, co->bind_if, (unsigned)strlen(co->bind_if) + 1) < 0) {
			log_message(LOG_INFO, "Checker can't bind to device %s: %s", co->bind_if, strerror(errno));
			return connect_error;
		}
	}

	/* Bind socket */
	if (((struct sockaddr *) bind_addr)->sa_family != AF_UNSPEC) {
		addrlen = sizeof(*bind_addr);
		if (bind(fd, (struct sockaddr *) bind_addr, addrlen) != 0) {
			log_message(LOG_INFO, "Checker bind failed: %s", strerror(errno));
			return connect_error;
		}
	}

	/* Set remote IP and connect */
	addrlen = sizeof(*addr);
	ret = connect(fd, (struct sockaddr *) addr, addrlen);

	/* Immediate success */
	if (ret == 0)
		return connect_success;

	/* If connect is in progress then return 1 else it's real error. */
	if (ret < 0) {
		if (errno != EINPROGRESS)
			return connect_error;
	}

	return connect_in_progress;
}

enum connect_result
socket_connect(int fd, struct sockaddr_storage *addr)
{
	conn_opts_t co;
	memset(&co, 0, sizeof(co));
	co.dst = *addr;
	return socket_bind_connect(fd, &co);
}

enum connect_result
socket_state(thread_t * thread, int (*func) (thread_t *))
{
	int status;
	socklen_t addrlen;
	int ret = 0;
	timeval_t timer_min;

	/* Handle connection timeout */
	if (thread->type == THREAD_WRITE_TIMEOUT) {
		close(thread->u.fd);
		return connect_timeout;
	}

	/* Check file descriptor */
	addrlen = sizeof(status);
	if (getsockopt(thread->u.fd, SOL_SOCKET, SO_ERROR, (void *) &status, &addrlen) < 0)
		ret = errno;

	/* Connection failed !!! */
	if (ret) {
		close(thread->u.fd);
		return connect_error;
	}

	/* If status = 0, TCP connection to remote host is established.
	 * Otherwise register checker thread to handle connection in progress,
	 * and other error code until connection is established.
	 * Recompute the write timeout (or pending connection).
	 */
	if (status == EINPROGRESS) {
		timer_min = timer_sub_now(thread->sands);
		thread_add_write(thread->master, func, THREAD_ARG(thread),
				 thread->u.fd, -timer_long(timer_min));
		return connect_in_progress;
	} else if (status != 0) {
		close(thread->u.fd);
		return connect_error;
	}

	return connect_success;
}

#ifdef _WITH_LVS_
bool
socket_connection_state(int fd, enum connect_result status, thread_t * thread,
		     int (*func) (thread_t *), unsigned long timeout)
{
	void *checker;

	checker = THREAD_ARG(thread);

	if (status == connect_success ||
	    status == connect_in_progress) {
		thread_add_write(thread->master, func, checker, fd, timeout);
		return false;
	}

	return true;
}
#endif
