/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        Socket pool utility functions.
 *
 * Version:     $Id: sock.c,v 1.1.16 2009/02/14 03:25:07 acassen Exp $
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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

/* system includes */
#include <string.h>

/* keepalived includes */
#include "memory.h"
#include "utils.h"
#include "list.h"

/* genhash includes */
#include "include/sock.h"
#include "include/layer4.h"
#include "include/ssl.h"
#include "include/main.h"

/* global var */
SOCK *sock = NULL;

/* Close the descriptor */
static void
close_sock(SOCK * sock_obj)
{
	if (sock_obj->ssl) {
		SSL_shutdown(sock_obj->ssl);
		SSL_free(sock_obj->ssl);
	}
	close(sock_obj->fd);
}

/* Destroy the socket handler */
void
free_sock(SOCK * sock_obj)
{
	DBG("Freeing fd:%d\n", sock_obj->fd);

	close_sock(sock_obj);
	FREE(sock_obj);
}

/* Init socket handler */
void
init_sock(void)
{
	sock = (SOCK *) MALLOC(sizeof (SOCK));
	memset(sock, 0, sizeof (SOCK));
	thread_add_event(master, tcp_connect_thread, sock, 0);
}
