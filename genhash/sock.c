/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        Socket pool utility functions.
 *
 * Version:     $Id: sock.c,v 1.0.0 2002/11/20 21:34:18 acassen Exp $
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
 */

#include <string.h>
#include "memory.h"
#include "utils.h"
#include "list.h"
#include "sock.h"
#include "layer4.h"
#include "ssl.h"
#include "main.h"

/* extern var */
extern thread_master *master;
extern SOCK *sock;

/* Close the descriptor */
static void close_sock(SOCK *sock)
{
	if (sock->ssl) {
		SSL_shutdown(sock->ssl);
		SSL_free(sock->ssl);
	}
	close(sock->fd);
}

/* Destroy the socket handler */
void free_sock(SOCK *sock)
{
	DBG("Freeing fd:%d\n", sock->fd);

	close_sock(sock);
	FREE(sock);
}

/* Init socket handler */
void init_sock(void)
{
	sock = (SOCK *)MALLOC(sizeof(SOCK));
	memset(sock, 0, sizeof(SOCK));
	thread_add_event(master, tcp_connect_thread,
			 sock, 0);
}
