/* 
 * Soft:        Genhash compute MD5 digest from a HTTP get result. This
 *              program is use to compute hash value that you will add
 *              into the /etc/keepalived/keepalived.conf for HTTP_GET
 *              & SSL_GET keepalive method.
 * 
 * Part:        Main part performing get request and MD5SUM over content.
 *
 * Version:     $Id: main.c,v 0.4.9 2001/11/28 11:50:23 acassen Exp $
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

#include "main.h"
#include "common.h"
#include "client.h"

/* Dump a buffer (ASCII or Binary) */
static void
print_buffer(int count, char *buff)
{
	int i, j, c;
	int printnext = 1;

	if (count % 16)
		c = count + (16 - count % 16);
	else
		c = count;

	for (i = 0; i < c; i++) {
		if (printnext) {
			printnext--;
			printf("%.4x ", i & 0xffff);
		}
		if (i < count)
			printf("%3.2x", buff[i] & 0xff);
		else
			printf("   ");
		if (!((i + 1) % 8)) {
			if ((i + 1) % 16)
				printf(" -");
			else {
				printf("   ");
				for (j = i - 15; j <= i; j++)
					if (j < count) {
						if ((buff[j] & 0xff) >= 0x20
						    && (buff[j] & 0xff) <= 0x7e)
							printf("%c",
							       buff[j] & 0xff);
						else
							printf(".");
					} else
						printf(" ");
				printf("\n");
				printnext = 1;
			}
		}
	}
}

/* Allocate & clean a buffer */
static char *
xmalloc(const int size)
{
	char *buffer;

	buffer = (char *) malloc(size);
	if (!buffer)
		return NULL;
	memset(buffer, 0, size);

	return buffer;
}

/* Return the html header from a global HTTP buffer */
static char *
extract_html(char *buffer, int size_buffer)
{
	char *end = buffer + size_buffer;

	while (buffer < end && !(*buffer++ == '\n' &&
				 (*buffer == '\n'
				  || (*buffer++ == '\r' && *buffer == '\n')))) ;

	if (*buffer == '\n')
		return buffer + 1;
	return NULL;
}

/* Build the GET request */
static char *
build_request(REQ * req)
{
	char *request;
	char *vhost;
	int request_len = 0;

	request_len = strlen(REQUEST_TEMPLATE) + strlen(req->host) + strlen(req->url) + 5 +	/* characters for port */
	    1;			/* null terminator     */
	request = xmalloc(request_len);
	if (!request)
		return NULL;

	vhost = req->host;
	if (req->virtualhost)
		vhost = req->virtualhost;
	snprintf(request, request_len, REQUEST_TEMPLATE, req->url, vhost,
		 req->port);
	return request;
}

static int
https_request(SSL * ssl, REQ * req)
{
	char *request = NULL;
	int r, i, e = 0;
	int request_len;
	char *extracted;
	unsigned char digest[16];
	MD5_CTX context;

	/* Build the SSL request */
	request = build_request(req);
	if (!request)
		return OUT_OF_MEMORY;
	request_len = strlen(request);

	/* Send the SSL request */
	r = SSL_write(ssl, request, request_len);
	if (SSL_ERROR_NONE != SSL_get_error(ssl, r)) {
		free(request);
		return SSL_WRITE_ERROR;
	}

	/* Test for eventual imcomplete SSL write */
	if (request_len != r) {
		free(request);
		return SSL_INCOMPLETE_WRITE;
	}

	/* Init MD5 context */
	MD5_Init(&context);
	extracted = NULL;
	req->len = 0;
	e = 0;

	/* 
	 * Now read the server's response, assuming
	 * that it's terminated by a close.
	 *
	 * FIXME: Create a function to read data from remote
	 *        server instead of code duplication.
	 */
	printf(HTTP_HEADER_HEXA);

	while (!e) {
		r = SSL_read(ssl, req->buffer + req->len, req->max - req->len);
		e = SSL_get_error(ssl, r);
		if (e != SSL_ERROR_NONE)
			break;
		if (r > 0 && e == 0) {
			req->len += r;
			/* Only header yet ? */
			if (!extracted) {
				/* Found something more than header ? */
				if ((extracted =
				     extract_html(req->buffer, req->len))) {
					r = req->len - (extracted -
							req->buffer);
					if (r) {
						print_buffer(r, req->buffer);
						printf(HTTP_HEADER_ASCII);
						for (i = 0;
						     i <
						     extracted - req->buffer;
						     i++)
							printf("%c",
							       req->buffer[i]);
						printf("\n");
						printf(HTML_HEADER_HEXA);
						memcpy(req->buffer, extracted,
						       r);
						MD5_Update(&context,
							   req->buffer, r);
						r = 0;
					}
					req->len = r;
				} else {
					if (req->len > 3) {
						print_buffer(req->len - 3,
							     req->buffer);
						printf(HTTP_HEADER_ASCII);
						for (i = 0; i < req->len - 3;
						     i++)
							printf("%c",
							       req->buffer[i]);
						printf("\n");
						printf(HTML_HEADER_HEXA);
						memcpy(req->buffer,
						       req->buffer + req->len -
						       3, 3);
						req->len = 3;
					}
				}
			} else {
				if (req->len) {
					print_buffer(req->len, req->buffer);
					MD5_Update(&context, req->buffer,
						   req->len);
					req->len = 0;
				}
			}
		}
	}

	/* Error handling */
	if (e != SSL_ERROR_ZERO_RETURN && e != SSL_ERROR_SYSCALL) {
		free(request);
		return SSL_READ_ERROR;
	}

	if (e == SSL_ERROR_ZERO_RETURN)
		if (SSL_shutdown(ssl) != 1) {
			free(request);
			return SSL_SHUTDOWN_FAILED;
		}

	if (e != SSL_ERROR_SYSCALL)
		SSL_free(ssl);

	MD5_Final(digest, &context);
	printf(HTML_MD5);
	print_buffer(16, digest);

	printf(HTML_MD5_FINAL);
	for (r = 0; r < 16; r++)
		printf("%02x", digest[r]);
	printf("\n\n");

	free(request);
	return SSL_GET_SUCCESS;
}

/*
 * Connect a remote SSL server and generate a MD5SUM
 * Upon the remote HTML content returned.
 */
static int
genhash_ssl(REQ * req)
{
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *sbio;
	int retcode = 0;

	/* SSL context initialization */
	ctx = initialize_ctx(req->keyfile, req->password, req->cafile);

	/* TCP socket creation */
	req->fd = tcp_sock();
	if (req->fd == -1) {
		destroy_ctx(ctx);
		return TCP_BIND_ERROR;
	}

	/* TCP connect remote host */
	retcode = tcp_connect(req->fd, req->host, req->port);
	if (retcode != TCP_CONNECT_SUCCESS)
		goto end;

	/* Create the SSL context */
	ssl = SSL_new(ctx);
	sbio = BIO_new_socket(req->fd, BIO_NOCLOSE);
	SSL_set_bio(ssl, sbio, sbio);

	/* Connect remote SSL server */
	if (SSL_connect(ssl) <= 0)
		return -2;

	/* Proceed the SSL server reply */
	retcode = https_request(ssl, req);

      end:
	/* Shutdown the socket */
	destroy_ctx(ctx);
	close(req->fd);
	return (retcode);
}

/*
 * Connect a remote HTTP server and generate a MD5SUM
 * Upon the remote HTML content returned.
 */
static int
genhash_http(REQ * req)
{
	int request_len = 0;
	char *request = NULL;
	char *buffertmp = NULL;
	int retcode = 0;
	int r;
	char *extracted;
	unsigned char digest[16];
	MD5_CTX context;

	/* Temporary get buffer allocation */
	buffertmp = xmalloc(RCV_BUFFER_LENGTH);
	if (!buffertmp) {
		free(request);
		return OUT_OF_MEMORY;
	}

	/* Build the HTTP request */
	request = build_request(req);
	if (!request) {
		free(buffertmp);
		return OUT_OF_MEMORY;
	}
	request_len = strlen(request);

	/* TCP socket creation */
	req->fd = tcp_sock();
	if (req->fd == -1) {
		free(request);
		free(buffertmp);
		return TCP_BIND_ERROR;
	}

	/* TCP connect remote host */
	retcode = tcp_connect(req->fd, req->host, req->port);
	if (retcode != TCP_CONNECT_SUCCESS)
		goto error;

	/* Send the HTTP request */
	retcode = tcp_send(req->fd, request, request_len);
	if (retcode == TCP_SEND_ERROR)
		goto error;

	/* Proceed the HTTP server reply */
	retcode = tcp_read_to(req->fd);
	if (retcode == TCP_READ_TIMEOUT)
		goto error;

	MD5_Init(&context);
	extracted = NULL;
	req->len = 0;

	/* 
	 * Now read the server's response.
	 *
	 * FIXME: Create a function to read data from remote
	 *        server instead of code duplication.
	 */
	printf(HTTP_HEADER_HEXA);
	while (1) {
		r = read(req->fd, buffertmp, RCV_BUFFER_LENGTH);
		if (r == -1 || r == 0)
			break;
		memcpy(req->buffer + req->len, buffertmp, r);
		req->len += r;
		if (!extracted &&
		    (extracted = extract_html(req->buffer, req->len))) {
			print_buffer(extracted - req->buffer, req->buffer);
			printf(HTTP_HEADER_ASCII);
			for (r = 0; r < extracted - req->buffer; r++)
				printf("%c", req->buffer[r]);
			printf("\n");

			printf(HTML_HEADER_HEXA);
			r = req->len - (extracted - req->buffer);
			if (r)
				memcpy(req->buffer, extracted, r);
			req->len = r;
		}

		if (extracted && req->len) {
			print_buffer(req->len, req->buffer);
			MD5_Update(&context, req->buffer, req->len);
			req->len = 0;
		}
	}

	MD5_Final(digest, &context);
	printf(HTML_MD5);
	print_buffer(16, digest);

	printf(HTML_MD5_FINAL);
	for (r = 0; r < 16; r++)
		printf("%02x", digest[r]);
	printf("\n\n");

	/* All is fine just return a success code */
	retcode = HTTP_GET_SUCCESS;

      error:
	close(req->fd);
	free(request);
	free(buffertmp);
	return (retcode);
}

/* Error return function */
static void
print_error(int err)
{
	switch (err) {
		/* System errors */
	case OUT_OF_MEMORY:
		err_exit("Out Of Memery");
		break;

		/* TCP errors */
	case TCP_BIND_ERROR:
		err_exit("TCP Bind error");
		break;
	case TCP_RESOLV_ERROR:
		err_exit("TCP Resolv error");
		break;
	case TCP_CONNECT_ERROR:
		err_exit("TCP Connect error");
		break;
	case TCP_WRITE_TIMEOUT:
		err_exit("TCP Write TimeOut");
		break;
	case TCP_READ_TIMEOUT:
		err_exit("TCP Read error");
		break;
	case TCP_SELECT_ERROR:
		err_exit("TCP Select error");
		break;
	case TCP_CONNECT_FAILED:
		err_exit("TCP Connectin failed");
		break;
	case TCP_SEND_ERROR:
		err_exit("TCP Send error");
		break;

		/* SSL errors */
	case SSL_WRITE_ERROR:
		err_exit("SSL Write error");
		break;
	case SSL_INCOMPLETE_WRITE:
		err_exit("SSL Incomplete write");
		break;
	case SSL_READ_ERROR:
		err_exit("SSL Read error");
		break;
	case SSL_SHUTDOWN_FAILED:
		err_exit("SSL Shutdown failed");
		break;
	}
}

/* Usage function */
static void
usage(const char *prog)
{
	fprintf(stderr, "%s Version %s\n", PROG, VERSION);
	fprintf(stderr,
		"Usage:\n"
		"  %s -s server-address -p port -u url\n"
		"  %s -S -K priv-key-file -P pem-password -s server-address -p port -u url\n"
		"  %s -S -K priv-key-file -P pem-password -C cert-file -s server-address -p port -u url\n"
		"  %s -h\n" "  %s -v\n\n", prog, prog, prog, prog, prog);
	fprintf(stderr,
		"Commands:\n"
		"Either long or short options are allowed.\n"
		"  %s --use-ssl         -S       Use SSL connection to remote server.\n"
		"  %s --server          -s       Use the specified remote server address.\n"
		"  %s --port            -p       Use the specified remote server port.\n"
		"  %s --url             -u       Use the specified remote server url.\n"
		"  %s --use-private-key -K       Use the specified SSL private key.\n"
		"  %s --use-password    -P       Use the specified SSL private key password.\n"
		"  %s --use-virtualhost -V       Use the specified VirtualHost GET query.\n"
		"  %s --use-certificate -C       Use the specified SSL Certificate file.\n"
		"  %s --help            -h       Display this short inlined help screen.\n"
		"  %s --version         -v       Display the version number\n",
		prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

/* Command line parser */
static int
parse_cmdline(int argc, char **argv, REQ * req)
{
	poptContext context;
	char *optarg = NULL;
	int c;

	struct poptOption options_table[] = {
		{"version", 'v', POPT_ARG_NONE, NULL, 'v'},
		{"help", 'h', POPT_ARG_NONE, NULL, 'h'},
		{"use-ssl", 'S', POPT_ARG_NONE, NULL, 'S'},
		{"server", 's', POPT_ARG_STRING, &optarg, 's'},
		{"port", 'p', POPT_ARG_STRING, &optarg, 'p'},
		{"url", 'u', POPT_ARG_STRING, &optarg, 'u'},
		{"use-private-key", 'K', POPT_ARG_STRING, &optarg, 'K'},
		{"use-virtualhost", 'V', POPT_ARG_STRING, &optarg, 'V'},
		{"use-password", 'P', POPT_ARG_STRING, &optarg, 'P'},
		{"use-certificate", 'C', POPT_ARG_STRING, &optarg, 'C'},
		{NULL, 0, 0, NULL, 0}
	};

	context =
	    poptGetContext(PROG, argc, (const char **) argv, options_table, 0);
	if ((c = poptGetNextOpt(context)) < 0) {
		usage(argv[0]);
		return CMD_LINE_ERROR;
	}

	/* The first option car */
	switch (c) {
	case 'v':
		fprintf(stderr, "%s Version %s\n", PROG, VERSION);
		break;
	case 'h':
		usage(argv[0]);
		break;
	case 'S':
		req->ssl = 1;
		break;
	case 's':
		req->host = optarg;
		break;
	default:
		usage(argv[0]);
		return CMD_LINE_ERROR;
	}

	/* the others */
	while ((c = poptGetNextOpt(context)) >= 0) {
		switch (c) {
		case 's':
			req->host = optarg;
			break;
		case 'p':
			req->port = atoi(optarg);
			break;
		case 'u':
			req->url = optarg;
			break;
		case 'K':
			req->keyfile = optarg;
			break;
		case 'P':
			req->password = optarg;
			break;
		case 'V':
			req->virtualhost = optarg;
			break;
		case 'C':
			req->cafile = optarg;
			break;
		default:
			usage(argv[0]);
			return CMD_LINE_ERROR;
		}
	}

	/* check unexpected arguments */
	if ((optarg = (char *) poptGetArg(context))) {
		fprintf(stderr, "unexpected argument %s", optarg);
		return CMD_LINE_ERROR;
	}

	/* free the allocated context */
	poptFreeContext(context);

	return CMD_LINE_SUCCESS;
}

int
main(int argc, char **argv)
{
	REQ *req;
	char *buffer;
	int err = 0;

	/* Allocate the room */
	req = (REQ *) xmalloc(sizeof (REQ));
	buffer = (char *) xmalloc(RCV_BUFFER_LENGTH);

	/* Command line parser */
	if (!parse_cmdline(argc, argv, req))
		exit(0);

	/* Check minimum configuration need */
	if (!req->host && !req->port && !req->url) {
		exit(0);
	}

	/* finalize req initialisation  */
	req->buffer = buffer;
	req->max = RCV_BUFFER_LENGTH;

	/* Now make our HTTP/SSL request */
	err = req->ssl ? genhash_ssl(req) : genhash_http(req);
	print_error(err);

	free(req);
	return (1);
}
