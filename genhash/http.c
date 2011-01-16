/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        HTTP asynchronous engine.
 *
 * Version:     $Id: http.c,v 1.1.16 2009/02/14 03:25:07 acassen Exp $
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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
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
static void
free_all(thread_t * thread)
{
	SOCK *sock_obj = THREAD_ARG(thread);

	DBG("Total read size read = %d Bytes, fd:%d\n",
	    sock_obj->total_size, sock_obj->fd);

	if (sock_obj->buffer)
		FREE(sock_obj->buffer);

	/*
	 * Decrement the current global get number.
	 * => free the reserved thread
	 */
	req->response_time = timer_tol(timer_now());
	thread_add_terminate_event(thread->master);
}

/* Simple epilog functions. */
int
epilog(thread_t * thread)
{
	DBG("Timeout on URL : [%s]\n", req->url);
	free_all(thread);
	return 0;
}

/* Simple finalization function */
int
finalize(thread_t * thread)
{
	SOCK *sock_obj = THREAD_ARG(thread);
	unsigned char digest[16];
	int i;

	/* Compute final MD5 digest */
	MD5_Final(digest, &sock_obj->context);
	if (req->verbose) {
		printf("\n");
		printf(HTML_MD5);
		dump_buffer((char *) digest, 16);

		printf(HTML_MD5_FINAL);
	}
	printf("MD5SUM = ");
	for (i = 0; i < 16; i++)
		printf("%02x", digest[i]);
	printf("\n\n");

	DBG("Finalize : [%s]\n", req->url);
	free_all(thread);
	return 0;
}

/* Dump HTTP header */
static void
http_dump_header(char *buffer, int size)
{
	int r;

	dump_buffer(buffer, size);
	printf(HTTP_HEADER_ASCII);
	for (r = 0; r < size; r++)
		printf("%c", buffer[r]);
	printf("\n");
}

/* Process incoming stream */
int
http_process_stream(SOCK * sock_obj, int r)
{
	sock_obj->size += r;
	sock_obj->total_size += r;

	if (!sock_obj->extracted) {
		if (req->verbose)
			printf(HTTP_HEADER_HEXA);
		if ((sock_obj->extracted = extract_html(sock_obj->buffer, sock_obj->size))) {
			if (req->verbose)
				http_dump_header(sock_obj->buffer,
						 sock_obj->extracted - sock_obj->buffer);
			r = sock_obj->size - (sock_obj->extracted - sock_obj->buffer);
			if (r) {
				if (req->verbose) {
					printf(HTML_HEADER_HEXA);
					dump_buffer(sock_obj->extracted, r);
				}
				memmove(sock_obj->buffer, sock_obj->extracted, r);
				MD5_Update(&sock_obj->context, sock_obj->buffer, r);
				r = 0;
			}
			sock_obj->size = r;
		} else {
			if (req->verbose)
				http_dump_header(sock_obj->buffer, sock_obj->size);

			/* minimize buffer using no 2*CR/LF found yet */
			if (sock_obj->size > 4) {
				memmove(sock_obj->buffer,
					sock_obj->buffer + sock_obj->size - 4, 4);
				sock_obj->size = 4;
			}
		}
	} else if (sock_obj->size) {
		if (req->verbose)
			dump_buffer(sock_obj->buffer, r);
		MD5_Update(&sock_obj->context, sock_obj->buffer, sock_obj->size);
		sock_obj->size = 0;
	}

	return 0;
}

/* Asynchronous HTTP stream reader */
int
http_read_thread(thread_t * thread)
{
	SOCK *sock_obj = THREAD_ARG(thread);
	int r = 0;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT)
		return epilog(thread);

	/* read the HTTP stream */
	memset(sock_obj->buffer, 0, MAX_BUFFER_LENGTH);
	r = read(thread->u.fd, sock_obj->buffer + sock_obj->size,
		 MAX_BUFFER_LENGTH - sock_obj->size);

	DBG(" [l:%d,fd:%d]\n", r, sock_obj->fd);

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
		http_process_stream(sock_obj, r);

		/*
		 * Register next http stream reader.
		 * Register itself to not perturbe global I/O multiplexer.
		 */
		thread_add_read(thread->master, http_read_thread, sock_obj,
				thread->u.fd, HTTP_CNX_TIMEOUT);
	}

	return 0;
}

/*
 * Read get result from the remote web server.
 * Apply trigger check to this result.
 */
int
http_response_thread(thread_t * thread)
{
	SOCK *sock_obj = THREAD_ARG(thread);

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT)
		return epilog(thread);

	/* Allocate & clean the get buffer */
	sock_obj->buffer = (char *) MALLOC(MAX_BUFFER_LENGTH);

	/* Initalize the MD5 context */
	MD5_Init(&sock_obj->context);

	/* Register asynchronous http/ssl read thread */
	if (req->ssl)
		thread_add_read(thread->master, ssl_read_thread, sock_obj,
				thread->u.fd, HTTP_CNX_TIMEOUT);
	else
		thread_add_read(thread->master, http_read_thread, sock_obj,
				thread->u.fd, HTTP_CNX_TIMEOUT);
	return 0;
}

/* remote Web server is connected, send it the get url query.  */
int
http_request_thread(thread_t * thread)
{
	SOCK *sock_obj = THREAD_ARG(thread);
	char *str_request;
	int ret = 0;

	/* Handle read timeout */
	if (thread->type == THREAD_WRITE_TIMEOUT)
		return epilog(thread);

	/* Allocate & clean the GET string */
	str_request = (char *) MALLOC(GET_BUFFER_LENGTH);
	memset(str_request, 0, GET_BUFFER_LENGTH);

	snprintf(str_request, GET_BUFFER_LENGTH, REQUEST_TEMPLATE,
		 req->url, (req->vhost) ? req->vhost : inet_ntop2(req->addr_ip)
		 , ntohs(req->addr_port));

	/* Send the GET request to remote Web server */
	DBG("Sending GET request [%s] on fd:%d\n", req->url, sock_obj->fd);
	if (req->ssl)
		ret =
		    ssl_send_request(sock_obj->ssl, str_request,
				     strlen(str_request));
	else
		ret =
		    (send(sock_obj->fd, str_request, strlen(str_request), 0) !=
		     -1) ? 1 : 0;

	FREE(str_request);

	if (!ret) {
		fprintf(stderr, "Cannot send get request to [%s:%d].\n",
			inet_ntop2(req->addr_ip)
			, ntohs(req->addr_port));
		return epilog(thread);
	}

	/* Register read timeouted thread */
	thread_add_read(thread->master, http_response_thread, sock_obj,
			sock_obj->fd, HTTP_CNX_TIMEOUT);
	return 1;
}
