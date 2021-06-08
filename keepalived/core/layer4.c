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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#ifdef ERRQUEUE_NEEDS_SYS_TIME
#include <sys/time.h>
#endif
#include <linux/errqueue.h>

#include "layer4.h"
#include "logger.h"
#include "scheduler.h"
#ifdef _WITH_LVS_
#include "check_api.h"
#endif
#include "bitops.h"
#include "utils.h"
#include "align.h"

// #define ICMP_DEBUG	1

#ifdef _WITH_LVS_
#define UDP_BUFSIZE	32
#endif

#ifdef _WITH_LVS_
void
set_buf(char *buf, size_t buf_len)
{
	const char *str = "keepalived check - ";
	size_t str_len = strlen(str);
	char *p = buf;

	/* We need to overwrite the send buffer to avoid leaking
	 * stack content. */

	while (buf_len >= str_len) {
		memcpy(p, str, str_len);
		p += str_len;
		buf_len -= str_len;
	}

	if (buf_len)
		memcpy(p, str, buf_len);
}
#endif

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
	const struct sockaddr_storage *addr = &co->dst;
	const struct sockaddr_storage *bind_addr = &co->bindto;

	optlen = sizeof(opt);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, (void *)&opt, &optlen) < 0) {
		log_message(LOG_ERR, "Can't get socket type: %s", strerror(errno));
		return connect_error;
	}
	if (opt == SOCK_STREAM) {
		/* free the tcp port after closing the socket descriptor, but
		 * allow time for a proper shutdown. */
		li.l_onoff = 1;
		li.l_linger = 5;
		if (setsockopt(fd, SOL_SOCKET, SO_LINGER, PTR_CAST(char, &li), sizeof (struct linger)))
			log_message(LOG_INFO, "Failed to set SO_LINGER for socket %d - errno %d (%m)", fd, errno);
	}

#ifdef _WITH_SO_MARK_
	if (co->fwmark) {
		if (setsockopt (fd, SOL_SOCKET, SO_MARK, &co->fwmark, sizeof (co->fwmark)) < 0) {
			log_message(LOG_ERR, "Error setting fwmark %u to socket: %s", co->fwmark, strerror(errno));
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
	if (PTR_CAST_CONST(struct sockaddr, bind_addr)->sa_family != AF_UNSPEC) {
		addrlen = sizeof(*bind_addr);
		if (bind(fd, PTR_CAST_CONST(struct sockaddr, bind_addr), addrlen) != 0) {
			log_message(LOG_INFO, "Checker bind failed: %s", strerror(errno));
			return connect_error;
		}
	}

	/* Set remote IP and connect */
	addrlen = sizeof(*addr);
	ret = connect(fd, PTR_CAST_CONST(struct sockaddr, addr), addrlen);

	/* Immediate success */
	if (ret == 0)
		return connect_success;

	/* If connect is in progress then return 1 else it's real error. */
	if (errno == EINPROGRESS)
		return connect_in_progress;

	/* ENETUNREACH can be returned here. I'm not sure
	 * about any of the others, but play safe. These
	 * should all be considered to be a failure to connect
	 * rather than a failure to run the check. */
	if (errno == ENETUNREACH || errno == EHOSTUNREACH ||
	    errno == ECONNREFUSED || errno == EHOSTDOWN ||
	    errno == ENETDOWN || errno == ECONNRESET ||
	    errno == ECONNABORTED || errno == ETIMEDOUT)
		return connect_fail;

	/* We want to know about the error, but not repeatedly */
	if (errno != co->last_errno) {
		co->last_errno = errno;
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "socket connect error %d - %m", errno);
	}

	return connect_error;
}

enum connect_result
socket_connect(int fd, const struct sockaddr_storage *addr)
{
	conn_opts_t co = { .dst = *addr };

	return socket_bind_connect(fd, &co);
}

enum connect_result
socket_state(thread_ref_t thread, thread_func_t func, unsigned extra_flags)
{
	int status;
	socklen_t addrlen;
	timeval_t timer_min;

	/* Handle connection timeout */
	if (thread->type == THREAD_WRITE_TIMEOUT) {
		thread_close_fd(thread);
		return connect_timeout;
	}

	/* Check file descriptor */
	addrlen = sizeof(status);
	if (getsockopt(thread->u.f.fd, SOL_SOCKET, SO_ERROR, (void *) &status, &addrlen) < 0) {
		/* getsockopt failed !!! */
		thread_close_fd(thread);
		return connect_error;
	}

	/* If status = 0, TCP connection to remote host is established.
	 * Otherwise register checker thread to handle connection in progress,
	 * and other error code until connection is established.
	 * Recompute the write timeout (or pending connection).
	 */
	if (status == 0)
		return connect_success;

	if (status == EINPROGRESS) {
		timer_min = timer_sub_now(thread->sands);
		thread_add_write(thread->master, func, THREAD_ARG(thread),
				 thread->u.f.fd, -timer_long(timer_min), THREAD_DESTROY_CLOSE_FD | extra_flags);
		return connect_in_progress;
	}

	thread_close_fd(thread);

	if (status == ETIMEDOUT)
		return connect_timeout;

	/* Since the connect() call succeeded, treat this as a
	 * failure to establish a connection. */
	return connect_fail;
}

#ifdef _WITH_LVS_
bool
socket_connection_state(int fd, enum connect_result status, thread_ref_t thread,
			thread_func_t func, unsigned long timeout, unsigned extra_flags)
{
	if (status == connect_success ||
	    status == connect_in_progress) {
		thread_add_write(thread->master, func, THREAD_ARG(thread), fd, timeout, THREAD_DESTROY_CLOSE_FD | extra_flags);
		return false;
	}

	return true;
}

enum connect_result
udp_bind_connect(int fd, conn_opts_t *co, uint8_t *payload, uint16_t payload_len)
{
	socklen_t addrlen;
	ssize_t ret;
	const struct sockaddr_storage *addr = &co->dst;
	const struct sockaddr_storage *bind_addr = &co->bindto;
	char buf[UDP_BUFSIZE];
	int on = 1;
	int err;

	/* Ensure we don't leak our stack */
	if (!payload) {
		set_buf(buf, sizeof(buf));
		payload = PTR_CAST(uint8_t, buf);
		payload_len = sizeof(buf);
	}

	/* We want to be able to receive ICMP error responses */
	if (co->dst.ss_family == AF_INET)
		err = setsockopt(fd, SOL_IP, IP_RECVERR, PTR_CAST(char, &on), sizeof(on));
	else
		err = setsockopt(fd, SOL_IPV6, IPV6_RECVERR, PTR_CAST(char, &on), sizeof(on));
	if (err)
		log_message(LOG_INFO, "Error %d setting IP%s_RECVERR for socket %d - %m", errno, co->dst.ss_family == AF_INET ? "" : "V6", fd);

#ifdef _WITH_SO_MARK_
	if (co->fwmark) {
		if (setsockopt (fd, SOL_SOCKET, SO_MARK, &co->fwmark, sizeof (co->fwmark)) < 0) {
			log_message(LOG_ERR, "Error setting fwmark %u to socket: %s", co->fwmark, strerror(errno));
			return connect_error;
		}
	}
#endif

	/* Bind socket */
	if (PTR_CAST_CONST(struct sockaddr, bind_addr)->sa_family != AF_UNSPEC) {
		addrlen = sizeof(*bind_addr);
		if (bind(fd, PTR_CAST_CONST(struct sockaddr, bind_addr), addrlen) != 0) {
			log_message(LOG_INFO, "bind failed. errno: %d, error: %s", errno, strerror(errno));
			return connect_error;
		}
	}

	/* Set remote IP and connect */
	addrlen = sizeof(*addr);
	ret = connect(fd, PTR_CAST_CONST(struct sockaddr, addr), addrlen);

	if (ret < 0) {
		/* We want to know about the error, but not repeatedly */
		if (errno != co->last_errno) {
			co->last_errno = errno;
			if (__test_bit(LOG_DETAIL_BIT, &debug))
				log_message(LOG_INFO, "UDP connect error %d - %m", errno);
		}

		return connect_error;
	}

	/* Send udp packet */
	ret = send(fd, payload, payload_len, 0);

	if (ret == payload_len)
		return connect_success;

	if (ret == -1) {
		/* We want to know about the error, but not repeatedly */
		if (errno != co->last_errno) {
			co->last_errno = errno;
			if (__test_bit(LOG_DETAIL_BIT, &debug))
				log_message(LOG_INFO, "UDP send error %d - %m", errno);
		}
	}
	else if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "udp_bind_connect send - sent %zd bytes instead of %zu", ret, sizeof(buf));

	return connect_error;
}

static enum connect_result
udp_socket_error(int fd)
{
	struct msghdr msg;
	char name_buf[128];
	struct iovec iov;
	char control[2560] __attribute__((aligned(__alignof__(struct cmsghdr))));
	struct icmphdr icmph;
	struct cmsghdr *cmsg;                   /* Control related data */
	struct sock_extended_err *sock_err;
	ssize_t n;

	iov.iov_base = &icmph;
	iov.iov_len = sizeof icmph;
	msg.msg_name = name_buf;
	msg.msg_namelen = sizeof(name_buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof control;
	msg.msg_flags = 0;

	n = recvmsg(fd, &msg, MSG_ERRQUEUE);

	if (n == -1) {
		log_message(LOG_INFO, "udp_socket_error recvmsg failed - errno %d", errno);
		return connect_success;
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		sock_err = PTR_CAST(struct sock_extended_err, CMSG_DATA(cmsg));
		if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) {
			if (sock_err) {
				/* We are interested in ICMP errors */
				if (sock_err->ee_origin == SO_EE_ORIGIN_ICMP && sock_err->ee_type == ICMP_DEST_UNREACH) {
#ifdef ICMP_DEBUG
					/* Handle ICMP errors types */
					switch (sock_err->ee_code)
					{
					case ICMP_NET_UNREACH:
						/* Handle this error */
						log_message(LOG_INFO, "Network Unreachable Error");
						break;
					case ICMP_HOST_UNREACH:
						/* Handle this error */
						log_message(LOG_INFO, "Host Unreachable Error");
						break;
					case ICMP_PORT_UNREACH:
						/* Handle this error */
						log_message(LOG_INFO, "Port Unreachable Error");
						break;
					default:
						log_message(LOG_INFO, "Unreach code %d", sock_err->ee_code);
					}
#endif
					return connect_error;
#ifndef ICMP_DEBUG
				}
			}
		}
#else
				} else
					log_message(LOG_INFO, "ee_origin %d, ee_type %d", sock_err->ee_origin, sock_err->ee_type);
			} else
				log_message(LOG_INFO, "No CMSG_DATA");
		}
#endif
		else if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVERR) {
			if (sock_err) {
				/* We are interested in ICMP errors */
				if (sock_err->ee_origin == SO_EE_ORIGIN_ICMP6 && sock_err->ee_type == ICMPV6_DEST_UNREACH) {
#ifdef ICMP_DEBUG
					/* Handle ICMP errors types */
					switch (sock_err->ee_code)
					{
					case ICMPV6_NOROUTE:
						/* Handle this error */
						log_message(LOG_INFO, "No Route Error");
						break;
					case ICMPV6_ADDR_UNREACH:
						/* Handle this error */
						log_message(LOG_INFO, "Address Unreachable Error");
						break;
					case ICMPV6_PORT_UNREACH:
						/* Handle this error */
						log_message(LOG_INFO, "Port Unreachable Error");
						break;
					default:
						log_message(LOG_INFO, "Unreach code %d", sock_err->ee_code);
					}
#endif
					return connect_error;
#ifndef ICMP_DEBUG
				}
			}
		}
#else
				} else
					log_message(LOG_INFO, "ee_origin %d, ee_type %d", sock_err->ee_origin, sock_err->ee_type);
			} else
				log_message(LOG_INFO, "No CMSG_DATA");
		}
		else
			log_message(LOG_INFO, "cmsg_level %d, cmsg->type %d", cmsg->cmsg_level, cmsg->cmsg_type);
#endif
	}

	return connect_success;
}

enum connect_result
udp_socket_state(int fd, thread_ref_t thread, uint8_t *recv_buf, size_t *len)
{
	int ret;
	char local_recv_buf;

	/* Handle Read timeout, we consider it success unless require_reply is set */
	if (thread->type == THREAD_READ_TIMEOUT)
		return recv_buf ? connect_error : connect_success;

	if (thread->type == THREAD_READ_ERROR)
		return udp_socket_error(fd);

	if (recv_buf) {
		ret = recv(fd, recv_buf, *len, 0);
		*len = ret;
	} else {
		ret = recv(fd, &local_recv_buf, sizeof(local_recv_buf), 0);
	}

	/* Ret less than 0 means the port is unreachable.
	 * Otherwise, we consider it success.
	 */

	if (ret < 0)
		return connect_error;

	return connect_success;
}

bool
udp_icmp_check_state(int fd, enum connect_result status, thread_ref_t thread,
					thread_func_t func, unsigned long timeout)
{
	checker_t *checker;

	checker = THREAD_ARG(thread);

	if (status == connect_success) {
		thread_add_read(thread->master, func, checker, fd, timeout, THREAD_DESTROY_CLOSE_FD);
		return false;
	}

	return true;
}
#endif
