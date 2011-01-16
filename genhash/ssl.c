/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        SSL engine. 'Semi' asyncrhonous stream handling.
 *
 * Version:     $Id: ssl.c,v 1.1.16 2009/02/14 03:25:07 acassen Exp $
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

#include <openssl/err.h>
#include "main.h"
#include "sock.h"
#include "http.h"
#include "ssl.h"
#include "utils.h"
#include "html.h"

/* extern variables */
extern REQ *req;

/*
 * Initialize the SSL context, with or without specific
 * configuration files.
 */
static BIO *bio_err = 0;
void
init_ssl(void)
{
	/* Library initialization */
	SSL_library_init();

	SSL_load_error_strings();
	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	/* Initialize SSL context for SSL v2/3 */
	req->meth = SSLv23_method();
	req->ctx = SSL_CTX_new(req->meth);

#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
	SSL_CTX_set_verify_depth(req->ctx, 1);
#endif
}

/* Display SSL error to readable string */
int
ssl_printerr(int err)
{
	unsigned long extended_error = 0;
	char *ssl_strerr;

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
	case SSL_ERROR_SSL:{
			ssl_strerr = (char *) MALLOC(500);

			extended_error = ERR_get_error();
			ERR_error_string(extended_error, ssl_strerr);
			fprintf(stderr, "  SSL error: (%s)\n", ssl_strerr);
			FREE(ssl_strerr);
			break;
		}
	}
	return 0;
}

int
ssl_connect(thread_t * thread)
{
	SOCK *sock_obj = THREAD_ARG(thread);
	int ret;

	sock_obj->ssl = SSL_new(req->ctx);
	sock_obj->bio = BIO_new_socket(sock_obj->fd, BIO_NOCLOSE);
	BIO_set_nbio(sock_obj->bio, 1);	/* Set the Non-Blocking flag */
	SSL_set_bio(sock_obj->ssl, sock_obj->bio, sock_obj->bio);
	ret = SSL_connect(sock_obj->ssl);

	DBG("  SSL_connect return code = %d on fd:%d\n", ret, thread->u.fd);
	ssl_printerr(SSL_get_error(sock_obj->ssl, ret));

	return (ret > 0) ? 1 : 0;
}

int
ssl_send_request(SSL * ssl, char *str_request, int request_len)
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
ssl_read_thread(thread_t * thread)
{
	SOCK *sock_obj = THREAD_ARG(thread);
	int r = 0;
	int error;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT)
		return epilog(thread);

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

      read_stream:

	/* read the SSL stream */
	memset(sock_obj->buffer, 0, MAX_BUFFER_LENGTH);
	r = SSL_read(sock_obj->ssl, sock_obj->buffer, MAX_BUFFER_LENGTH);
	error = SSL_get_error(sock_obj->ssl, r);

	DBG(" [l:%d,fd:%d]\n", r, sock_obj->fd);

	if (error) {
		/* All the SSL streal has been parsed */
		/* Handle response stream */
		if (error != SSL_ERROR_NONE)
			return finalize(thread);
	} else if (r > 0 && error == 0) {

		/* Handle the response stream */
		http_process_stream(sock_obj, r);

		/*
		 * Register next ssl stream reader.
		 * Register itself to not perturbe global I/O multiplexer.
		 */
		goto read_stream;
	}

	return 0;
}
