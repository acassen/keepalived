/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        HTTP asynchronous engine.
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

/* system includes */
#include <openssl/err.h>

/* keepalived includes */
#include "utils.h"
#include "html.h"

/* genhash includes */
#include "include/http.h"
#include "include/layer4.h"

/* GET processing command */
static const char *request_template =
			"GET %s HTTP/1.%d\r\n"
			"User-Agent: KeepAlive GenHash Client\r\n"
			"%s"
			"Host: %s%s\r\n\r\n";

static const char *request_template_ipv6 =
			"GET %s HTTP/1.%d\r\n"
			"User-Agent: KeepAlive GenHash Client\r\n"
			"%s"
			"Host: [%s]%s\r\n\r\n";

/* Output delimiters */
#define DELIM_BEGIN		"-----------------------["
#define DELIM_END		"]-----------------------\n"
#define HTTP_HEADER_HEXA	DELIM_BEGIN"    HTTP Header Buffer    "DELIM_END
#define HTTP_HEADER_ASCII	DELIM_BEGIN" HTTP Header Ascii Buffer "DELIM_END
#define HTML_HEADER_HEXA	DELIM_BEGIN"        HTML Buffer        "DELIM_END
#define HTML_HASH		DELIM_BEGIN"    HTML hash resulting    "DELIM_END
#define HTML_HASH_FINAL		DELIM_BEGIN" HTML hash final resulting "DELIM_END

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
 *                v
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
#ifdef _WITH_SHA1_
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
	if ((sock)->content_len == -1 || (sock)->rx_bytes < (sock)->content_len) \
		((sock)->hash->update(&(sock)->context, (buf), (sock)->content_len == -1 || (sock)->content_len - (sock)->rx_bytes >= len ? len : (sock)->content_len - (sock)->rx_bytes))
#define HASH_FINAL(sock, digest) \
	((sock)->hash->final((digest), &(sock)->context))

/* free allocated pieces */
static void
free_all(thread_ref_t thread)
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
	req->response_time = timer_long(timer_now());
	thread_add_terminate_event(thread->master);
}

/* Simple epilog functions. */
int
epilog(thread_ref_t thread)
{
	DBG("Timeout on URL : [%s]\n", req->url);
	free_all(thread);
	return 0;
}

/* Simple finalization function */
int
finalize(thread_ref_t thread)
{
	SOCK *sock_obj = THREAD_ARG(thread);
	unsigned char digest_length = HASH_LENGTH(sock_obj);
	unsigned char *digest = MALLOC(digest_length);
	int i;

	/* Compute final hash digest */
	HASH_FINAL(sock_obj, digest);
	if (req->verbose) {
		printf("\n");
		printf(HTML_HASH);
		dump_buffer((char *) digest, digest_length, stdout, 0);

		printf(HTML_HASH_FINAL);
	}
	printf("%s = ", HASH_LABEL(sock_obj));
	for (i = 0; i < digest_length; i++)
		printf("%02x", digest[i]);
	if (sock_obj->content_len != -1 && sock_obj->content_len != sock_obj->rx_bytes)
		printf ("\nWARNING - Content-Length (%zd) does not match received bytes (%zd).", sock_obj->content_len, sock_obj->rx_bytes);
	printf("\n\n");

	DBG("Finalize : [%s]\n", req->url);
	free_all(thread);
	FREE(digest);
	return 0;
}

/* Dump HTTP header */
static void
http_dump_header(char *buffer, size_t size)
{
	dump_buffer(buffer, size, stdout, 0);
	printf(HTTP_HEADER_ASCII);
	printf("%*s\n", (int)size, buffer);
}

static ssize_t
find_content_len(char *buffer, size_t size)
{
	const char *content_len_str = "Content-Length:";
	unsigned long content_len;
	bool valid_len = false;
	char sav_char = buffer[size];
	char *p;
	char *end;

	buffer[size] = '\0';
	p = strstr(buffer, content_len_str);
	if (p &&
	    (p == buffer || p[-1] == '\r' || p[-1] == '\n')) {
		p += strlen(content_len_str);
		content_len = strtoul(p, &end, 10);

		/* Make sure we have read to the end of the line */
		if (!*end || *end == '\r' || *end == '\n')
			valid_len = true;
	}
	buffer[size] = sav_char;

	if (valid_len)
		return (ssize_t)content_len;

	return -1;
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
		if ((sock_obj->extracted = extract_html(sock_obj->buffer, (size_t)sock_obj->size))) {
			sock_obj->content_len =
				find_content_len(sock_obj->buffer + (sock_obj->size - r),
					 (size_t)((sock_obj->extracted - sock_obj->buffer) - (sock_obj->size - r)));
			if (req->verbose)
				http_dump_header(sock_obj->buffer + (sock_obj->size - r),
						 (size_t)((sock_obj->extracted - sock_obj->buffer) - (sock_obj->size - r)));
			r = sock_obj->size - (int)(sock_obj->extracted - sock_obj->buffer);
			if (r) {
				if (req->verbose) {
					printf(HTML_HEADER_HEXA);
					dump_buffer(sock_obj->extracted, (size_t)r, stdout, 0);
				}
				memmove(sock_obj->buffer, sock_obj->extracted, (size_t)r);
				HASH_UPDATE(sock_obj, sock_obj->buffer, r);
				sock_obj->rx_bytes += r;
				r = 0;
			}
			sock_obj->size = r;
		} else {
			sock_obj->content_len = find_content_len(sock_obj->buffer + (sock_obj->size - r), (size_t)r);
			if (req->verbose)
				http_dump_header(sock_obj->buffer + (sock_obj->size - r), (size_t)r);

			/* minimize buffer using no 2*CR/LF found yet */
			if (sock_obj->size > 4) {
				memmove(sock_obj->buffer,
					sock_obj->buffer + sock_obj->size - 4, 4);
				sock_obj->size = 4;
			}
		}
	} else if (sock_obj->size) {
		if (req->verbose)
			dump_buffer(sock_obj->buffer, (size_t)r, stdout, 0);
		HASH_UPDATE(sock_obj, sock_obj->buffer, sock_obj->size);
		sock_obj->rx_bytes += sock_obj->size;
		sock_obj->size = 0;
	}

	return 0;
}

/* Asynchronous HTTP stream reader */
static int
http_read_thread(thread_ref_t thread)
{
	SOCK *sock_obj = THREAD_ARG(thread);
	ssize_t r = 0;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT) {
		exit_code = 1;
		return epilog(thread);
	}

	/* read the HTTP stream */
	r = MAX_BUFFER_LENGTH - sock_obj->size;
	if (r <= 0) {
		/* defensive check, should not occur */
		fprintf(stderr, "HTTP socket buffer overflow (not consumed)\n");
		r = MAX_BUFFER_LENGTH;
	}
	memset(sock_obj->buffer + sock_obj->size, 0, (size_t)r);
	r = read(thread->u.f.fd, sock_obj->buffer + sock_obj->size, (size_t)r);

	DBG(" [l:%zd,fd:%d]\n", r, sock_obj->fd);

	if (r == 0) {		/* EOF */
		/* All the HTTP stream has been parsed */
		finalize(thread);
	} else if (r == -1) {	/* error */
		/* We have encountered a real read error */
		DBG("Read error with server [%s]:%d: %s\n",
		    req->ipaddress, ntohs(req->addr_port),
		    strerror(errno));
		exit_code = 1;
		return epilog(thread);
	} else {
		/* Handle the response stream */
		http_process_stream(sock_obj, (int)r);

		/*
		 * Register next http stream reader.
		 * Register itself to not perturbe global I/O multiplexer.
		 */
		thread_add_read(thread->master, http_read_thread, sock_obj,
				thread->u.f.fd, req->timeout, true);
	}

	return 0;
}

/* remote Web server is connected, send it the get url query.  */
int
http_request_thread(thread_ref_t thread)
{
	SOCK *sock_obj = THREAD_ARG(thread);
	char *str_request;
	const char *request_host;
	const char *request_host_port;
	int ret = 0;
	char *str;

	/* Handle read timeout */
	if (thread->type == THREAD_WRITE_TIMEOUT) {
		exit_code = 1;
		return epilog(thread);
	}

	/* Allocate & clean the GET string */
	str_request = (char *) MALLOC(GET_BUFFER_LENGTH);

	if (req->vhost) {
		/* If vhost was defined we don't need to override it's port */
		request_host = req->vhost;
		str = (char*) MALLOC(1);
		*str = '\0';
		request_host_port = str;
	} else {
		request_host = req->ipaddress;

		/* Allocate a buffer for the port string ( ":" [0-9][0-9][0-9][0-9][0-9] "\0" ) */
		str = (char*) MALLOC(7);
		snprintf(str, 7, ":%d", ntohs(req->addr_port));
		request_host_port = str;
	}

	snprintf(str_request, GET_BUFFER_LENGTH,
		 (req->dst && req->dst->ai_family == AF_INET6 && !req->vhost) ? request_template_ipv6 : request_template,
		  req->url,
		  req->http_protocol == HTTP_PROTOCOL_1_1 || req->http_protocol == HTTP_PROTOCOL_1_1K ? 1 : 0,
		  req->http_protocol == HTTP_PROTOCOL_1_0C || req->http_protocol == HTTP_PROTOCOL_1_1 ? "Connection: close\r\n" :
		    req->http_protocol == HTTP_PROTOCOL_1_0K || req->http_protocol == HTTP_PROTOCOL_1_1K ? "Connection: keep-alive\r\n" : "",
		  request_host, request_host_port);

	FREE_CONST(request_host_port);

	/* Send the GET request to remote Web server */
	DBG("Sending GET request [%s] on fd:%d\n", req->url, sock_obj->fd);
	if (req->ssl)
		ret = ssl_send_request(sock_obj->ssl, str_request, (int)strlen(str_request));
	else
		ret = (send(sock_obj->fd, str_request, strlen(str_request), 0) != -1) ? 1 : 0;

	FREE(str_request);

	if (!ret) {
		fprintf(stderr, "Cannot send get request to [%s]:%d.\n",
			req->ipaddress,
			ntohs(req->addr_port));
		exit_code = 1;
		return epilog(thread);
	}

	/* Allocate & clean the get buffer */
	sock_obj->buffer = (char *) MALLOC(MAX_BUFFER_LENGTH);

	/* Initalize the hash context */
	sock_obj->hash = &hashes[req->hash];
	HASH_INIT(sock_obj);

	sock_obj->rx_bytes = 0;

	/* Register asynchronous http/ssl read thread */
	if (req->ssl)
		thread_add_read(thread->master, ssl_read_thread, sock_obj,
				sock_obj->fd, req->timeout, true);
	else
		thread_add_read(thread->master, http_read_thread, sock_obj,
				sock_obj->fd, req->timeout, true);

	return 1;
}
