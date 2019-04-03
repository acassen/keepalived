/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        ICMP checker.
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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */
#include "config.h"
#include "check_ping.h"
#include "logger.h"
#include "layer4.h"
#include <error.h>
#include <stdio.h>

enum connect_result ping_it(int fd, conn_opts_t* co)
{
	struct icmphdr icmp_hdr;
	struct sockaddr_storage *dest = &co->dst;
	int size = 0;
	int seq = 1;
	socklen_t addrlen;
	char send_buf[ICMP_BUFSIZE];

	memset(&icmp_hdr, 0, sizeof icmp_hdr);
	icmp_hdr.type = ICMP_ECHO;
	icmp_hdr.un.echo.id = fd;//arbitrary id
	icmp_hdr.un.echo.sequence = seq++;
	addrlen = sizeof(*dest);
	memcpy(send_buf, &icmp_hdr, sizeof(icmp_hdr));
	size = sendto(fd, send_buf, sizeof(send_buf), 0, (struct sockaddr*)dest, addrlen);

	if(size < 0)
	{
		log_message(LOG_INFO, "send icmp packet fail!");
		return connect_error;
	}
	return connect_success;
}

enum connect_result recv_it(int fd)
{
	char recv_buf[ICMP_BUFSIZE];
	int size = 0;
	int ret = connect_error;
	struct icmphdr rcv_hdr;

	memset(recv_buf, 0, sizeof(recv_buf));
	size = recv(fd, recv_buf, sizeof(recv_buf), 0);

	if(size < 0) {
		log_message(LOG_INFO, "recv icmp packet error!");
		return ret;
	} else if ((unsigned int)size < sizeof(rcv_hdr)) {
		log_message(LOG_INFO, "Error, got short ICMP packet, %d bytes", size);
		return ret;
	}
	memcpy(&rcv_hdr, recv_buf, sizeof(rcv_hdr));
	if (rcv_hdr.type == ICMP_ECHOREPLY)
		ret = connect_success;
	else {
		log_message(LOG_INFO, "Got ICMP packet with type 0x%x ?!?", rcv_hdr.type);
	}
	return ret;
}

enum connect_result ping6_it(int fd, conn_opts_t* co)
{
	struct icmp6_hdr* send_hdr;
	struct sockaddr_storage *dest = &co->dst;
	struct sockaddr_in6* dest_in6 = (struct sockaddr_in6*)dest;
	int size = 0;
	int seq = 1;
	char send_buf[ICMP_BUFSIZE];
	send_hdr = (struct icmp6_hdr*)&send_buf;

	memset(send_hdr, 0, sizeof(struct icmp6_hdr));
	send_hdr->icmp6_type = ICMP6_ECHO_REQUEST;
	send_hdr->icmp6_id = fd;
	send_hdr->icmp6_seq = seq;

	size = sendto(fd, send_buf, ICMP_BUFSIZE, 0,dest_in6, sizeof(*dest_in6));
	if(size < 0)
	{
		log_message(LOG_INFO, "send icmpv6 packet fail!");
		return connect_error;
	}
	return connect_success;
}

enum connect_result recv6_it(int fd)
{
	char recv_buf[ICMP_BUFSIZE];
	int size = 0;
	int ret = connect_error;
	struct icmp6_hdr* rcv_hdr;

	size = recv(fd, recv_buf, sizeof(recv_buf), 0);

	if (size < 0) {
		log_message(LOG_INFO, "recv icmpv6 packet error!");
		return ret;
	} else if ((unsigned int)size < sizeof(rcv_hdr)) {
		log_message(LOG_INFO, "Error, got short ICMPV6 packet, %d bytes", size);
		return ret;
	}
	rcv_hdr = (struct icmp6_hdr*)&recv_buf;

	if (rcv_hdr->icmp6_type == ICMP6_ECHO_REPLY)
		ret = connect_success;
	else
		log_message(LOG_INFO, "Got ICMP packet with type 0x%x ?!?", rcv_hdr->icmp6_type);

	return ret;
}


