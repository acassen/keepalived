/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        Layer4 asynchronous primitives.
 *
 * Authors:     Alexandre Cassen, <acassen@linux-vs.org>
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

#include <fcntl.h>

/* keepalived include */
#include "utils.h"

/* genhash includes */
#include "include/layer4.h"

static enum connect_result
tcp_connect(int fd, REQ * req_obj)
{
	struct linger li;
	socklen_t long_inet;
	struct sockaddr_in adr_serv;
	struct sockaddr_in6 adr_serv6;
	int ret;

	/* free the tcp port after closing the socket descriptor, but allow
	 * time for a proper shutdown. */
	li.l_onoff = 1;
	li.l_linger = 5;
	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &li, sizeof (struct linger)))
		fprintf(stderr, "Error setting SO_LINGER on socket %d\n", fd);

#ifdef _WITH_SO_MARK_
	if (req->mark) {
		if (setsockopt (fd, SOL_SOCKET, SO_MARK, &req->mark, sizeof req->mark)) {
			fprintf(stderr, "Error setting fwmark %u to socket: %s\n",
					req->mark, strerror(errno));
			return connect_error;
		}
	}
#endif

	if(req_obj->dst && req_obj->dst->ai_family == AF_INET6) {
		long_inet = sizeof (struct sockaddr_in6);
		memset(&adr_serv6, 0, long_inet);
		adr_serv6.sin6_family = AF_INET6;
		adr_serv6.sin6_port = req_obj->addr_port;
		inet_pton(AF_INET6, req_obj->ipaddress, &adr_serv6.sin6_addr);

		/* Call connect function. */
		ret = connect(fd, (struct sockaddr *) &adr_serv6, long_inet);
	} else {
		long_inet = sizeof (struct sockaddr_in);
		memset(&adr_serv, 0, long_inet);
		adr_serv.sin_family = AF_INET;
		adr_serv.sin_port = req_obj->addr_port;
		inet_pton(AF_INET, req_obj->ipaddress, &adr_serv.sin_addr);

		/* Call connect function. */
		ret = connect(fd, (struct sockaddr *) &adr_serv, long_inet);
	}

	/* Immediate success */
	if (ret == 0)
		return connect_success;

	/* If connect is in progress then return connect_in_progress else it's real error. */
	if (errno != EINPROGRESS)
		return connect_error;

	/* restore previous fd args */
	return connect_in_progress;
}

static enum connect_result
tcp_socket_state(thread_ref_t thread, thread_func_t func)
{
	int status;
	socklen_t slen;
	int ret = 0;
	timeval_t timer_min;

	/* Handle connection timeout */
	if (thread->type == THREAD_WRITE_TIMEOUT) {
		DBG("TCP connection timeout to [%s]:%d.\n",
		    req->ipaddress, ntohs(req->addr_port));
		thread_close_fd(thread);
		return connect_timeout;
	}

	/* Check file descriptor */
	slen = sizeof (status);
	if (getsockopt
	    (thread->u.f.fd, SOL_SOCKET, SO_ERROR, (void *) &status, &slen) < 0)
		ret = errno;

	/* Connection failed !!! */
	if (ret) {
		DBG("TCP getsockopt() failed to [%s]:%d.\n",
		    req->ipaddress, ntohs(req->addr_port));
		thread_close_fd(thread);
		return connect_error;
	}

	/* If status = 0, TCP connection to remote host is established.
	 * Otherwise register checker thread to handle connection in progress,
	 * and other error code until connection is established.
	 * Recompute the write timeout (or pending connection).
	 */
	if (status == EINPROGRESS) {
		DBG("TCP connection to [%s]:%d still IN_PROGRESS.\n",
		    req->ipaddress, ntohs(req->addr_port));

		timer_min = timer_sub_now(thread->sands);
		thread_add_write(thread->master, func, THREAD_ARG(thread)
				 , thread->u.f.fd, timer_long(timer_min), true);
		return connect_in_progress;
	} else if (status) {
		DBG("TCP connection failed to [%s]:%d.\n",
		    req->ipaddress, ntohs(req->addr_port));
		thread_close_fd(thread);
		return connect_error;
	}

	return connect_success;
}

static void
tcp_connection_state(int fd, enum connect_result status, thread_ref_t thread
		     , thread_func_t func
		     , unsigned long timeout)
{
	switch (status) {
	case connect_error:
		close(fd);
		thread_add_terminate_event(thread->master);
		break;

	case connect_success:
		thread_add_write(thread->master, func, THREAD_ARG(thread),
				 fd, timeout, true);
		break;

		/* Checking non-blocking connect, we wait until socket is writable */
	case connect_in_progress:
		thread_add_write(thread->master, func, THREAD_ARG(thread),
				 fd, timeout, true);
		break;

	default:
		break;
	}
}

static int
tcp_check_thread(thread_ref_t thread)
{
	SOCK *sock_obj = THREAD_ARG(thread);
	int ret = 1;

	sock_obj->status = tcp_socket_state(thread, tcp_check_thread);
	switch (sock_obj->status) {
	case connect_error:
		DBG("Error connecting server [%s]:%d.\n",
		    req->ipaddress, ntohs(req->addr_port));
		thread_add_terminate_event(thread->master);
		return -1;
		break;

	case connect_timeout:
		DBG("Timeout connecting server [%s]:%d.\n",
		    req->ipaddress, ntohs(req->addr_port));
		thread_add_terminate_event(thread->master);
		return -1;
		break;

	case connect_success:{
			if (req->ssl)
				ret = ssl_connect(thread);

			if (ret) {
				/* SSL connections manage their own threads for SSL_connect */
				if (req->ssl)
					return 1;

				/* Remote WEB server is connected.
				 * Unlock eventual locked socket.
				 */
				sock_obj->lock = 0;
				thread_add_event(thread->master,
						 http_request_thread, sock_obj, 0);
				thread_del_write(thread);
			} else {
				DBG("Connection trouble to: [%s]:%d.\n",
				    req->ipaddress,
				    ntohs(req->addr_port));
				sock_obj->status = connect_error;
				thread_add_terminate_event(thread->master);
				return -1;
			}
		}
		break;
	}

	return 1;
}

int
tcp_connect_thread(thread_ref_t thread)
{
	SOCK *sock_obj = THREAD_ARG(thread);

	if ((sock_obj->fd = socket((req->dst && req->dst->ai_family == AF_INET6) ? AF_INET6 : AF_INET,
				   SOCK_STREAM | SOCK_NONBLOCK
#ifdef SOCK_CLOEXEC
					       | SOCK_CLOEXEC
#endif
							     , IPPROTO_TCP)) == -1) {
		DBG("WEB connection fail to create socket.\n");
		return 0;
	}

#if !HAVE_DECL_SOCK_NONBLOCK
	if (fcntl(sock_obj->fd, F_SETFL, fcntl(sock_obj->fd, F_GETFL) | O_NONBLOCK))
		fprintf(stderr, "Unable to set socket non blocking\n");
#endif

	sock->status = tcp_connect(sock_obj->fd, req);

	/* handle tcp connection status & register check worker thread */
	tcp_connection_state(sock_obj->fd, sock_obj->status, thread, tcp_check_thread,
			     req->timeout);
	return 0;
}
