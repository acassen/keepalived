/*
 * Soft:        Genhash compute MD5 digest from a HTTP get result. This
 *              program is use to compute hash value that you will add
 *              into the /etc/keepalived/keepalived.conf for HTTP_GET
 *              & SSL_GET keepalive method.
 *
 * Part:        client.c include file.
 *
 * Version:     $Id: client.h,v 0.4.9 2001/11/28 11:50:23 acassen Exp $
 *
 * Authors:     Alexandre Cassen, <acassen@linux-vs.org>
 *              Jan Holmberg, <jan@artech.se>
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
 */

#ifndef _CLIENT_H
#define _CLIENT_H

/* System includes */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

/* Socket timeout */
#define SOCKET_TIMEOUT_READ    3
#define SOCKET_TIMEOUT_WRITE   3

/* Return codes */
/* systems predefined ret codes */
#define OUT_OF_MEMORY		(1 << 0)

/* TCP predefined ret codes */
#define TCP_BIND_ERROR		(1 << 1)
#define TCP_RESOLV_ERROR	(1 << 2)
#define TCP_CONNECT_ERROR	(1 << 3)
#define TCP_CONNECT_SUCCESS	(1 << 4)
#define TCP_WRITE_TIMEOUT	(1 << 5)
#define TCP_SELECT_ERROR	(1 << 6)
#define TCP_CONNECT_FAILED	(1 << 7)
#define TCP_SEND_ERROR		(1 << 8)
#define TCP_READ_TIMEOUT	(1 << 9)

/* Upper Layer - HTTP predefined ret codes */
#define HTTP_GET_SUCCESS	(1 << 10)

/* Upper Layer - SSL predefined ret codes */
#define SSL_WRITE_ERROR		(1 << 11)
#define SSL_INCOMPLETE_WRITE	(1 << 12)
#define SSL_READ_ERROR		(1 << 13)
#define SSL_SHUTDOWN_FAILED	(1 << 14)
#define SSL_GET_SUCCESS		(1 << 15)

/* Prototypes */
extern int tcp_connect(int fd, char *host, int port);
extern int tcp_send(int fd, char *request, int len);
extern int tcp_read_to(int fd);
extern int tcp_sock(void);

#endif

