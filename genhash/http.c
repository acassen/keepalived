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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

/* system includes */
#include <errno.h>
#include <openssl/err.h>

/* keepalived includes */
#include "memory.h"
#include "utils.h"
#include "html.h"
#include "timer.h"

/* genhash includes */
#include "include/http.h"
#include "include/layer4.h"
#include "include/main.h"

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

const hash_t hashes[hash_guard] = {
	[hash_md5] = {
		(hash_init_f) MD5_Init,
		(hash_update_f) MD5_Update,
		(hash_final_f) MD5_Final,
		MD5_DIGEST_LENGTH,
		"MD5",
		"MD5SUM",
	},
#ifdef FEAT_SHA1
	[hash_sha1] = {
		(hash_init_f) SHA1_Init,
		(hash_update_f) SHA1_Update,
		(hash_final_f) SHA1_Final,
		SHA_DIGEST_LENGTH,
		"SHA1",
		"SHA1SUM",
	}
#endif
};

#define HASH_LENGTH(sock)	((sock)->hash->length)
#define HASH_LABEL(sock)	((sock)->hash->label)
#define HASH_INIT(sock)		((sock)->hash->init(&(sock)->context))
#define HASH_UPDATE(sock, buf, len) \
	((sock)->hash->update(&(sock)->context, (buf), (len)))
#define HASH_FINAL(sock, digest) \
	((sock)->hash->final((digest), &(sock)->context))

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

	unsigned char digest_length = HASH_LENGTH(sock_obj);
	unsigned char digest[digest_length];
	int i;

	/* Compute final hash digest */
	HASH_FINAL(sock_obj, digest);
	if (req->verbose) {
		printf("\n");
		printf(HTML_HASH);
		dump_buffer((char *) digest, digest_length);

		printf(HTML_HASH_FINAL);
	}
	printf("%s = ", HASH_LABEL(sock_obj));
	for (i = 0; i < digest_length; i++)
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
				http_dump_header(sock_obj->buffer + (sock_obj->size - r),
						 (sock_obj->extracted - sock_obj->buffer)
						 - (sock_obj->size - r));
			r = sock_obj->size - (sock_obj->extracted - sock_obj->buffer);
			if (r) {
				if (req->verbose) {
					printf(HTML_HEADER_HEXA);
					dump_buffer(sock_obj->extracted, r);
				}
				memmove(sock_obj->buffer, sock_obj->extracted, r);
				HASH_UPDATE(sock_obj, sock_obj->buffer, r);
				r = 0;
			}
			sock_obj->size = r;
		} else {
			if (req->verbose)
				http_dump_header(sock_obj->buffer + (sock_obj->size - r),
						 r);

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
		HASH_UPDATE(sock_obj, sock_obj->buffer, sock_obj->size);
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
	r = MAX_BUFFER_LENGTH - sock_obj->size;
	if (r <= 0) {
		/* defensive check, should not occur */
		fprintf(stderr, "HTTP socket buffer overflow (not consumed)\n");
		r = MAX_BUFFER_LENGTH;
	}
	memset(sock_obj->buffer + sock_obj->size, 0, r);
	r = read(thread->u.fd, sock_obj->buffer + sock_obj->size, r);

	DBG(" [l:%d,fd:%d]\n", r, sock_obj->fd);

	if (r == -1 || r == 0) {	/* -1:error , 0:EOF */
		if (r == -1) {
			/* We have encourred a real read error */
			DBG("Read error with server [%s]:%d: %s\n",
			    req->ipaddress, ntohs(req->addr_port),
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

	/* Initalize the hash context */
	sock_obj->hash = &hashes[req->hash];
	HASH_INIT(sock_obj);

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
	char *request_host;
	char *request_host_port;
	int ret = 0;

	/* Handle read timeout */
	if (thread->type == THREAD_WRITE_TIMEOUT)
		return epilog(thread);

	/* Allocate & clean the GET string */
	str_request = (char *) MALLOC(GET_BUFFER_LENGTH);
	memset(str_request, 0, GET_BUFFER_LENGTH);

	if (req->vhost) {
		/* If vhost was defined we don't need to override it's port */
		request_host = req->vhost;
		request_host_port = (char*) MALLOC(1);
		*request_host_port = 0;
	} else {
		request_host = req->ipaddress;
	
		/* Allocate a buffer for the port string ( ":" [0-9][0-9][0-9][0-9][0-9] "\0" ) */
		request_host_port = (char*) MALLOC(7);
		snprintf(request_host_port, 7, ":%d",
		 ntohs(req->addr_port));
	}
	
	if(req->dst){
		if(req->dst->ai_family == AF_INET6 && !req->vhost) {
			snprintf(str_request, GET_BUFFER_LENGTH, REQUEST_TEMPLATE_IPV6,
				req->url, request_host, request_host_port);
		} else {
			snprintf(str_request, GET_BUFFER_LENGTH, REQUEST_TEMPLATE,
				req->url, request_host, request_host_port);
		}
	} else {
		snprintf(str_request, GET_BUFFER_LENGTH, REQUEST_TEMPLATE,
			req->url, request_host, request_host_port);
	}
	
	FREE(request_host_port);

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
		fprintf(stderr, "Cannot send get request to [%s]:%d.\n",
			req->ipaddress,
			ntohs(req->addr_port));
		return epilog(thread);
	}

	/* Register read timeouted thread */
	thread_add_read(thread->master, http_response_thread, sock_obj,
			sock_obj->fd, HTTP_CNX_TIMEOUT);
	return 1;
}
