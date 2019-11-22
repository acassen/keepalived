/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        SSL engine. 'Semi' asyncrhonous stream handling.
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
#include <stdbool.h>

/* keepalived includes */
#include "utils.h"

/* genhash includes */
#include "include/ssl.h"
#include "include/main.h"
#include "include/layer4.h"

/*
 * Initialize the SSL context, with or without specific
 * configuration files.
 */
void
init_ssl(void)
{
	/* Library initialization */
#ifdef HAVE_OPENSSL_INIT_CRYPTO
#ifndef HAVE_OPENSSL_INIT_NO_LOAD_CONFIG_BUG
	/* In OpenSSL v1.1.1 if the following is called, SSL_CTX_new() below fails.
	 * It works in v1.1.0h and v1.1.1b.
	 * It transpires that it works without setting NO_LOAD_CONFIG, but it is
	 * presumably more efficient not to load it. */
	if (!OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL))
		fprintf(stderr, "OPENSSL_init_crypto failed\n");
#endif
#else
	SSL_library_init();
	SSL_load_error_strings();
#endif

	/* Initialize SSL context */
#ifdef HAVE_TLS_METHOD
	req->meth = TLS_method();
#else
	req->meth = SSLv23_method();
#endif
	if (!(req->ctx = SSL_CTX_new(req->meth))) {
		fprintf(stderr, "SSL_CTX_new() failed\n");
		exit(1);
	}

#if HAVE_SSL_CTX_SET_VERIFY_DEPTH
	SSL_CTX_set_verify_depth(req->ctx, 1);
#endif
}

/* Display SSL error to readable string */
static int
ssl_printerr(int err)
{
	switch (err) {
	case SSL_ERROR_ZERO_RETURN:
		fprintf(stderr, "  SSL error: (zero return)\n");
		break;
	case SSL_ERROR_WANT_READ:
		fprintf(stderr, "  SSL error: (read error)\n");
		break;
	case SSL_ERROR_WANT_WRITE:
		fprintf(stderr, "  SSL error: (write error)\n");
		break;
	case SSL_ERROR_WANT_CONNECT:
		fprintf(stderr, "  SSL error: (connect error)\n");
		break;
	case SSL_ERROR_WANT_X509_LOOKUP:
		fprintf(stderr, "  SSL error: (X509 lookup error)\n");
		break;
	case SSL_ERROR_SYSCALL:
		fprintf(stderr, "  SSL error: (syscall error)\n");
		break;
	case SSL_ERROR_SSL:
		fprintf(stderr, "  SSL error: (%s)\n", ERR_error_string(ERR_get_error(), NULL));
		break;
	}
	return 0;
}

static void
ssl_connection_done(thread_ref_t thread)
{
	SOCK *sock_obj = THREAD_ARG(thread);

	sock_obj->lock = 0;
	thread_add_event(thread->master,
			 http_request_thread, sock_obj, 0);
	thread_del_write(thread);
}

static int
ssl_connect_complete_thread(thread_ref_t thread)
{
	SOCK *sock_obj = THREAD_ARG(thread);
	int ret;
	int error;

	if (thread->type == THREAD_READ_TIMEOUT ||
	    thread->type == THREAD_WRITE_TIMEOUT) {
		exit_code = 1;
		return epilog(thread);
	}

	ret = SSL_connect(sock_obj->ssl);
	if (ret > 0) {
		ssl_connection_done(thread);
		return 0;
	}

	error = SSL_get_error(sock_obj->ssl, ret);
	if (ret == -1 && error == SSL_ERROR_WANT_READ) {
		thread_add_read(thread->master, ssl_connect_complete_thread, sock_obj,
				sock_obj->fd, req->timeout, true);
	}
	else if (ret == -1 && error == SSL_ERROR_WANT_WRITE) {
		thread_add_write(thread->master, ssl_connect_complete_thread, sock_obj,
				sock_obj->fd, req->timeout, true);
	} else {
		DBG("  SSL_connect return code = %d on fd:%d\n", ret, thread->u.f.fd);
		ssl_printerr(error);
		sock_obj->status = connect_error;
		thread_add_terminate_event(thread->master);
	}

	return 0;
}

bool
ssl_connect(thread_ref_t thread)
{
	SOCK *sock_obj = THREAD_ARG(thread);
	int ret;
	int error;

	sock_obj->ssl = SSL_new(req->ctx);
	if (!sock_obj->ssl) {
		fprintf(stderr, "SSL_new() failed\n");
		return false;
	}

	sock_obj->bio = BIO_new_socket(sock_obj->fd, BIO_NOCLOSE);
	if (!sock_obj->bio) {
		fprintf(stderr, "BIO_new_socket failed\n");
		return false;
	}

	BIO_set_nbio(sock_obj->bio, 1);	/* Set the Non-Blocking flag */
#ifdef HAVE_SSL_SET0_RBIO
	BIO_up_ref(sock_obj->bio);
	SSL_set0_rbio(sock_obj->ssl, sock_obj->bio);
	SSL_set0_wbio(sock_obj->ssl, sock_obj->bio);
#else
	SSL_set_bio(sock_obj->ssl, sock_obj->bio, sock_obj->bio);
#endif
#ifdef _HAVE_SSL_SET_TLSEXT_HOST_NAME_
	if (req->vhost != NULL && req->sni) {
		SSL_set_tlsext_host_name(sock_obj->ssl, req->vhost);
	}
#endif

	ret = SSL_connect(sock_obj->ssl);
	if (ret > 0) {
		ssl_connection_done(thread);
		return 1;
	}

	error = SSL_get_error(sock_obj->ssl, ret);
	if (ret == -1 && error == SSL_ERROR_WANT_READ) {
		thread_add_read(thread->master, ssl_connect_complete_thread, sock_obj,
				sock_obj->fd, req->timeout, true);
		return 1;
	}
	else if (ret == -1 && error == SSL_ERROR_WANT_WRITE) {
		thread_add_write(thread->master, ssl_connect_complete_thread, sock_obj,
				sock_obj->fd, req->timeout, true);
		return 1;
	}

	DBG("  SSL_connect return code = %d on fd:%d\n", ret, thread->u.f.fd);
	ssl_printerr(error);

	return (ret > 0);
}

int
ssl_send_request(SSL *ssl, const char *str_request, int request_len)
{
	int err, r = 0;

	while (1) {
		err = 1;
		r = SSL_write(ssl, str_request, request_len);
		if (SSL_ERROR_NONE != SSL_get_error(ssl, r))
			break;
		err++;
		if (request_len != r)
			break;
		err++;
		break;
	}

	return (err == 3) ? 1 : 0;
}

/* Asynchronous SSL stream reader */
int
ssl_read_thread(thread_ref_t thread)
{
	SOCK *sock_obj = THREAD_ARG(thread);
	int r = 0;
	int error;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT) {
		exit_code = 1;
		return epilog(thread);
	}

	/*
	 * The design implemented here is a workaround for use
	 * with OpenSSL. This goto loop is a 'read until not
	 * end of stream'. But this break a little our global
	 * I/O multiplexer thread framework because it enter
	 * a synchronous read process for each GET reply.
	 * Sound a little nasty !.
	 *
	 * Why OpenSSL doesn t handle underlying fd. This
	 * break the I/O (select()) approach !...
	 * If you read this and know the answer, please reply
	 * I am probably missing something... :)
	 * My test show that sometime it return from select,
	 * and sometime not...
	 */

	do {
		/* read the SSL stream */
		r = MAX_BUFFER_LENGTH - sock_obj->size;
		if (r <= 0) {
			/* defensive check, should not occur */
			fprintf(stderr, "SSL socket buffer overflow (not consumed)\n");
			r = MAX_BUFFER_LENGTH;
		}
		memset(sock_obj->buffer + sock_obj->size, 0, (size_t)r);
		r = SSL_read(sock_obj->ssl, sock_obj->buffer + sock_obj->size, r);
		error = SSL_get_error(sock_obj->ssl, r);
		if (r == -1 && error == SSL_ERROR_WANT_READ) {
			thread_add_read(thread->master, ssl_read_thread, sock_obj,
					sock_obj->fd, req->timeout, true);

			return 0;
		} else if (r == -1 && error == SSL_ERROR_WANT_WRITE) {
			thread_add_write(thread->master, ssl_read_thread, sock_obj,
					sock_obj->fd, req->timeout, true);

			return 0;
		}
		DBG(" [l:%d,fd:%d]\n", r, sock_obj->fd);

		if (error != SSL_ERROR_NONE) {
			/* All the SSL stream has been parsed */
			/* Handle response stream */
			return finalize(thread);
		} else if (r <= 0)
			return 0;

		/* Handle the response stream */
		http_process_stream(sock_obj, r);
	} while (true);

	/* Unreachable */
	return 0;
}
