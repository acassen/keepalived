/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        HTTP asynchronous engine.
 *
 * Version:     $Id: http.c,v 1.0.0 2002/11/20 21:34:18 acassen Exp $
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

#include <errno.h>
#include <openssl/err.h>
#include "memory.h"
#include "http.h"
#include "layer4.h"
#include "main.h"
#include "utils.h"
#include "html.h"
#include "timer.h"

/* extern variables */
extern REQ *req;

/* 
 * The global design of this checker is the following :
 * 
 * - All the actions are done asynchronously.
 * - All the actions handle timeout connection.
 * - All the actions handle error from low layer to upper
 *   layers.
 * 
 * The global synopsis of the inter-thread-call is :
 *     
 *     http_request_thread (send SSL GET request)
 *            v
 *     http_response_thread (initialize read stream step)
 *         /             \
 *        /               \
 *       v                 v
 *  http_read_thread   ssl_read_thread (perform HTTP|SSL stream)
 *       v              v
 *  ------------------------------
 *   finalize    /     epilog
 */

/* free allocated pieces */
static void free_all(thread * thread)
{
	SOCK *sock = THREAD_ARG(thread);

	DBG("Total read size read = %d Bytes, fd:%d\n",
	    sock->total_size, sock->fd);

	if (sock->buffer)
		FREE(sock->buffer);

	/*
	 * Decrement the current global get number.
	 * => free the reserved thread
	 */
	req->response_time = timer_tol(timer_now());
	thread_add_terminate_event(thread->master);
}

/* Simple epilog functions. */
int
epilog(thread * thread)
{
	DBG("Timeout on URL : [%s]\n", req->url);
	free_all(thread);
	return 0;
}

/* Simple finalization function */
int
finalize(thread *thread)
{
	SOCK *sock = THREAD_ARG(thread);
	unsigned char digest[16];
	int i;

	printf("\n");
	/* Compute final MD5 digest */
	MD5_Final(digest, &sock->context);
	printf(HTML_MD5);
	print_buffer(16, digest);

	printf(HTML_MD5_FINAL);
	for (i = 0; i < 16; i++)
		printf("%02x", digest[i]);
	printf("\n\n");

	DBG("Finalize : [%s]\n", req->url);
	free_all(thread);
	return 0;
}

/* Process incoming stream */
int http_process_stream(SOCK *sock, int r)
{
	sock->size += r;
	sock->total_size += r;

	if (!sock->extracted) {
		printf(HTTP_HEADER_HEXA);
		if ((sock->extracted =
		    extract_html(sock->buffer, sock->size))) {
			print_buffer(sock->extracted - sock->buffer, sock->buffer);
			printf(HTTP_HEADER_ASCII);
			for (r = 0; r < sock->extracted - sock->buffer; r++)
				printf("%c", sock->buffer[r]);
			printf("\n");

			printf(HTML_HEADER_HEXA);
			r = sock->size - (sock->extracted - sock->buffer);
			if (r) {
				print_buffer(r, sock->extracted);
				memcpy(sock->buffer, sock->extracted, r);
				MD5_Update(&sock->context, sock->buffer,
					   r);
				r = 0;
			}
			sock->size = r;
		} else {
			/* minimize buffer using no 2*CR/LF found yet */
			if (sock->size > 3) {
				memcpy(sock->buffer,
				       sock->buffer + sock->size - 3, 3);
				sock->size = 3;
			}
		}
	} else if (sock->size) {
		print_buffer(r, sock->buffer);
		MD5_Update(&sock->context, sock->buffer,
			   sock->size);
		sock->size = 0;
	}

	return 0;
}

/* Asynchronous HTTP stream reader */
int
http_read_thread(thread * thread)
{
	SOCK *sock = THREAD_ARG(thread);
	int r = 0;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT)
		return epilog(thread);

	/* read the HTTP stream */
	memset(sock->buffer, 0, MAX_BUFFER_LENGTH);
	r = read(thread->u.fd, sock->buffer, MAX_BUFFER_LENGTH);

	DBG(" [l:%d,fd:%d]\n", r, sock->fd);

	if (r == -1 || r == 0) {	/* -1:error , 0:EOF */
		if (r == -1) {
			/* We have encourred a real read error */
			DBG("Read error with server [%s:%d]: %s\n",
			    inet_ntop2(req->addr_ip), ntohs(req->addr_port),
			    strerror(errno));
			return epilog(thread);
		}

		/* All the HTTP stream has been parsed */
		finalize(thread);
	} else {
		/* Handle the response stream */
		http_process_stream(sock, r);

		/*
		 * Register next http stream reader.
		 * Register itself to not perturbe global I/O multiplexer.
		 */
		thread_add_read(thread->master, http_read_thread, sock,
				thread->u.fd, HTTP_CNX_TIMEOUT);
	}

	return 0;
}

/*
 * Read get result from the remote web server.
 * Apply trigger check to this result.
 */
int
http_response_thread(thread * thread)
{
	SOCK *sock = THREAD_ARG(thread);

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT)
		return epilog(thread);

	/* Allocate & clean the get buffer */
	sock->buffer = (char *) MALLOC(MAX_BUFFER_LENGTH);

	/* Initalize the MD5 context */
	MD5_Init(&sock->context);

	/* Register asynchronous http/ssl read thread */
	if (req->ssl)
		thread_add_read(thread->master, ssl_read_thread, sock,
				thread->u.fd, HTTP_CNX_TIMEOUT);
	else
		thread_add_read(thread->master, http_read_thread, sock,
				thread->u.fd, HTTP_CNX_TIMEOUT);
	return 0;
}

/* remote Web server is connected, send it the get url query.  */
int
http_request_thread(thread * thread)
{
	SOCK *sock = THREAD_ARG(thread);
	char *str_request;
	int ret = 0;

	/* Handle read timeout */
	if (thread->type == THREAD_WRITE_TIMEOUT)
		return epilog(thread);

	/* Allocate & clean the GET string */
	str_request = (char *) MALLOC(GET_BUFFER_LENGTH);
	memset(str_request, 0, GET_BUFFER_LENGTH);

	snprintf(str_request, GET_BUFFER_LENGTH, REQUEST_TEMPLATE,
		 req->url,
		 (req->vhost) ? req->vhost : inet_ntop2(req->addr_ip)
		 , ntohs(req->addr_port));

	/* Send the GET request to remote Web server */
	DBG("Sending GET request [%s] on fd:%d\n",
	    req->url, sock->fd);
	if (req->ssl)
		ret =
		    ssl_send_request(sock->ssl, str_request,
				     strlen(str_request));
	else
		ret =
		    (send(sock->fd, str_request, strlen(str_request), 0) !=
		     -1) ? 1 : 0;

	FREE(str_request);

	if (!ret) {
		fprintf(stderr, "Cannot send get request to [%s:%d].\n",
		    inet_ntop2(req->addr_ip)
		    , ntohs(req->addr_port));
		return epilog(thread);
	}

	/* Register read timeouted thread */
	thread_add_read(thread->master, http_response_thread, sock,
			sock->fd, HTTP_CNX_TIMEOUT);
	return 1;
}
