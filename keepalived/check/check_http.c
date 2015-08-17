/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        WEB CHECK. Common HTTP/SSL checker primitives.
 *
 * Authors:     Alexandre Cassen, <acassen@linux-vs.org>
 *              Jan Holmberg, <jan@artech.net>
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

#include <openssl/err.h>
#include "check_http.h"
#include "check_ssl.h"
#include "check_api.h"
#include "logger.h"
#include "memory.h"
#include "parser.h"
#include "utils.h"
#include "html.h"

int http_connect_thread(thread_t *);

/* Configuration stream handling */
void
free_url(void *data)
{
	url_t *url = data;
	FREE(url->path);
	FREE(url->digest);
	FREE(url);
}

void
dump_url(void *data)
{
	url_t *url = data;
	log_message(LOG_INFO, "   Checked url = %s", url->path);
	if (url->digest)
		log_message(LOG_INFO, "           digest = %s",
		       url->digest);
	if (url->status_code)
		log_message(LOG_INFO, "           HTTP Status Code = %d",
		       url->status_code);
}

void
free_http_get_check(void *data)
{
	http_checker_t *http_get_chk = CHECKER_DATA(data);

	free_list(http_get_chk->url);
	FREE(http_get_chk->arg);
	FREE(http_get_chk);
	FREE(CHECKER_CO(data));
	FREE(data);
}

void
dump_http_get_check(void *data)
{
	http_checker_t *http_get_chk = CHECKER_DATA(data);

	if (http_get_chk->proto == PROTO_HTTP)
		log_message(LOG_INFO, "   Keepalive method = HTTP_GET");
	else
		log_message(LOG_INFO, "   Keepalive method = SSL_GET");
	dump_conn_opts (CHECKER_GET_CO());
	log_message(LOG_INFO, "   Nb get retry = %d", http_get_chk->nb_get_retry);
	log_message(LOG_INFO, "   Delay before retry = %lu",
	       http_get_chk->delay_before_retry/TIMER_HZ);
	dump_list(http_get_chk->url);
}
static http_checker_t *
alloc_http_get(char *proto)
{
	http_checker_t *http_get_chk;

	http_get_chk = (http_checker_t *) MALLOC(sizeof (http_checker_t));
	http_get_chk->arg = (http_t *) MALLOC(sizeof (http_t));
	http_get_chk->proto =
	    (!strcmp(proto, "HTTP_GET")) ? PROTO_HTTP : PROTO_SSL;
	http_get_chk->url = alloc_list(free_url, dump_url);
	http_get_chk->nb_get_retry = 1;
	http_get_chk->delay_before_retry = 3 * TIMER_HZ;

	return http_get_chk;
}

void
http_get_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk;
	char *str = vector_slot(strvec, 0);

	/* queue new checker */
	http_get_chk = alloc_http_get(str);
	queue_checker(free_http_get_check, dump_http_get_check,
		      http_connect_thread, http_get_chk, CHECKER_NEW_CO());
}

void
nb_get_retry_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	http_get_chk->nb_get_retry = CHECKER_VALUE_INT(strvec);
}

void
delay_before_retry_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	http_get_chk->delay_before_retry = CHECKER_VALUE_INT(strvec) * TIMER_HZ;
}

void
url_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *new;

	/* allocate the new URL */
	new = (url_t *) MALLOC(sizeof (url_t));

	list_add(http_get_chk->url, new);
}

void
path_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = LIST_TAIL_DATA(http_get_chk->url);

	url->path = CHECKER_VALUE_STRING(strvec);
}

void
digest_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = LIST_TAIL_DATA(http_get_chk->url);

	url->digest = CHECKER_VALUE_STRING(strvec);
}

void
status_code_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = LIST_TAIL_DATA(http_get_chk->url);

	url->status_code = CHECKER_VALUE_INT(strvec);
}

void
install_http_check_keyword(void)
{
	install_keyword("HTTP_GET", &http_get_handler);
	install_sublevel();
	install_connect_keywords();
	install_keyword("warmup", &warmup_handler);
	install_keyword("nb_get_retry", &nb_get_retry_handler);
	install_keyword("delay_before_retry", &delay_before_retry_handler);
	install_keyword("url", &url_handler);
	install_sublevel();
	install_keyword("path", &path_handler);
	install_keyword("digest", &digest_handler);
	install_keyword("status_code", &status_code_handler);
	install_sublevel_end();
	install_sublevel_end();
}

/* a little code duplication :/ */
void
install_ssl_check_keyword(void)
{
	install_keyword("SSL_GET", &http_get_handler);
	install_sublevel();
	install_connect_keywords();
	install_keyword("warmup", &warmup_handler);
	install_keyword("nb_get_retry", &nb_get_retry_handler);
	install_keyword("delay_before_retry", &delay_before_retry_handler);
	install_keyword("url", &url_handler);
	install_sublevel();
	install_keyword("path", &path_handler);
	install_keyword("digest", &digest_handler);
	install_keyword("status_code", &status_code_handler);
	install_sublevel_end();
	install_sublevel_end();
}

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
 *     http_connect_thread (handle layer4 connect)
 *            v
 *     http_check_thread (handle SSL connect)
 *            v
 *     http_request_thread (send SSL GET request)
 *            v
 *     http_response_thread (initialize read stream step)
 *         /             \
 *        /               \
 *       v                 v
 *  http_read_thread   ssl_read_thread (perform HTTP|SSL stream)
 *       v              v
 *     http_handle_response (next checker thread registration)
 */

/*
 * Simple epilog functions. Handling event timeout.
 * Finish the checker with memory managment or url rety check.
 *
 * c == 0 => reset to 0 retry_it counter
 * t == 0 => reset to 0 url_it counter
 * method == 1 => register a new checker thread
 * method == 2 => register a retry on url checker thread
 */
int
epilog(thread_t * thread, int method, int t, int c)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	http_t *http = HTTP_ARG(http_get_check);
	request_t *req = HTTP_REQ(http);
	long delay = 0;

	if (method) {
		http->url_it += t ? t : -http->url_it;
		http->retry_it += c ? c : -http->retry_it;
	}

	if (method == 1 && http->url_it >= LIST_SIZE(http_get_check->url)) {
		/* All the url have been successfully checked.
		 * Check completed.
		 * check if server is currently alive.
		 */
		if (!svr_checker_up(checker->id, checker->rs)) {
			log_message(LOG_INFO, "Remote Web server %s succeed on service."
					    , FMT_HTTP_RS(checker));
			smtp_alert(checker->rs, NULL, NULL, "UP",
				   "=> CHECK succeed on service <=");
			update_svr_checker_state(UP, checker->id
						   , checker->vs
						   , checker->rs);
		}

		/* Reset it counters */
		http->url_it = 0;
		http->retry_it = 0;
	}
	/*
	 * The get retry implementation mean that we retry performing
	 * a GET on the same url until the remote web server return 
	 * html buffer. This is sometime needed with some applications
	 * servers.
	 */
	else if (method == 2 && http->retry_it > http_get_check->nb_get_retry) {
		if (svr_checker_up(checker->id, checker->rs)) {
			if (http_get_check->nb_get_retry)
				log_message(LOG_INFO
				   , "Check on service %s failed after %d retry."
				   , FMT_HTTP_RS(checker)
				   , http->retry_it - 1);
			smtp_alert(checker->rs, NULL, NULL,
				   "DOWN",
				   "=> CHECK failed on service"
				   " : HTTP request failed <=");
			update_svr_checker_state(DOWN, checker->id
						     , checker->vs
						     , checker->rs);
		}

		/* Reset it counters */
		http->url_it = 0;
		http->retry_it = 0;
	}

	/* register next timer thread */
	switch (method) {
	case 1:
		delay = checker->vs->delay_loop;
		break;
	case 2:
		if (http->url_it == 0 && http->retry_it == 0)
			delay = checker->vs->delay_loop;
		else
			delay = http_get_check->delay_before_retry;
		break;
	}

	/* If req == NULL, fd is not created */
	if (req) {
		if (req->ssl)
			SSL_free(req->ssl);
		if (req->buffer)
			FREE(req->buffer);
		FREE(req);
		http->req = NULL;
		close(thread->u.fd);
	}

	/* Register next checker thread */
	thread_add_timer(thread->master, http_connect_thread, checker, delay);
	return 0;
}

int
timeout_epilog(thread_t * thread, char *debug_msg)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	http_t *http = HTTP_ARG(http_get_check);

	/* check if server is currently alive */
	if (svr_checker_up(checker->id, checker->rs)) {
		log_message(LOG_INFO, "%s server %s."
				    , debug_msg
				    , FMT_HTTP_RS(checker));
		return epilog(thread, 2, 0, 1);
	}

	/* do not retry if server is already known as dead */
	return epilog(thread, 1, 0, 0);
}

/* return the url pointer of the current url iterator  */
url_t *
fetch_next_url(http_checker_t * http_get_check)
{
	http_t *http = HTTP_ARG(http_get_check);

	return list_element(http_get_check->url, http->url_it);
}

/* Handle response */
int
http_handle_response(thread_t * thread, unsigned char digest[16]
		     , int empty_buffer)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	http_t *http = HTTP_ARG(http_get_check);
	request_t *req = HTTP_REQ(http);
	int r, di = 0;
	char *digest_tmp;
	url_t *fetched_url = fetch_next_url(http_get_check);
	enum {
		none,
		on_status,
		on_digest
	} last_success = none; /* the source of last considered success */

	/* First check if remote webserver returned data */
	if (empty_buffer)
		return timeout_epilog(thread, "Read, no data received from ");

	/* Next check the HTTP status code */
	if (fetched_url->status_code) {
		if (req->status_code != fetched_url->status_code) {
			return timeout_epilog(thread, "HTTP status code error to");
		} else {
			last_success = on_status;
		}
	}

	/* Continue with MD5SUM */
	if (fetched_url->digest) {
		/* Compute MD5SUM */
		digest_tmp = (char *) MALLOC(MD5_BUFFER_LENGTH + 1);
		for (di = 0; di < 16; di++)
			sprintf(digest_tmp + 2 * di, "%02x", digest[di]);

		r = strcmp(fetched_url->digest, digest_tmp);

		if (r) {
			FREE(digest_tmp);
			return timeout_epilog(thread, "MD5 digest error to");
		} else {
			last_success = on_digest;
			FREE(digest_tmp);
		}
	}

	if (!svr_checker_up(checker->id, checker->rs)) {
		switch (last_success) {
			case none:
				break;
			case on_status:
				log_message(LOG_INFO,
				       "HTTP status code success to %s url(%d)."
				       , FMT_HTTP_RS(checker)
				       , http->url_it + 1);
				return epilog(thread, 1, 1, 0) + 1;
			case on_digest:
				log_message(LOG_INFO,
					"MD5 digest success to %s url(%d)."
					, FMT_HTTP_RS(checker)
					, http->url_it + 1);
				return epilog(thread, 1, 1, 0) + 1;
		}
	}

	return epilog(thread, 1, 0, 0) + 1;
}

/* Handle response stream performing MD5 updates */
int
http_process_response(request_t *req, int r, int do_md5)
{
	req->len += r;
	if (!req->extracted) {
		if ((req->extracted =
		     extract_html(req->buffer, req->len))) {
			req->status_code = extract_status_code(req->buffer, req->len);
			r = req->len - (req->extracted - req->buffer);
			if (r && do_md5)
				MD5_Update(&req->context, req->extracted, r);
			req->len = 0;
		}
	} else if (req->len) {
		MD5_Update(&req->context, req->buffer,
			   req->len);
		req->len = 0;
	}

	return 0;
}

/* Asynchronous HTTP stream reader */
int
http_read_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	http_t *http = HTTP_ARG(http_get_check);
	request_t *req = HTTP_REQ(http);
	url_t *url = list_element(http_get_check->url, http->url_it);
	unsigned timeout = checker->co->connection_to;
	unsigned char digest[16];
	int r = 0;
	int val;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT)
		return timeout_epilog(thread, "Timeout HTTP read");

	/* Set descriptor non blocking */
	val = fcntl(thread->u.fd, F_GETFL, 0);
	fcntl(thread->u.fd, F_SETFL, val | O_NONBLOCK);

	/* read the HTTP stream */
	r = read(thread->u.fd, req->buffer + req->len,
		 MAX_BUFFER_LENGTH - req->len);

	/* restore descriptor flags */
	fcntl(thread->u.fd, F_SETFL, val);

	/* Test if data are ready */
	if (r == -1 && (errno == EAGAIN || errno == EINTR)) {
		log_message(LOG_INFO, "Read error with server %s: %s"
				    , FMT_HTTP_RS(checker)
				    , strerror(errno));
		thread_add_read(thread->master, http_read_thread, checker,
				thread->u.fd, timeout);
		return 0;
	}

	if (r == -1 || r == 0) {	/* -1:error , 0:EOF */

		/* All the HTTP stream has been parsed */
		if (url->digest)
			MD5_Final(digest, &req->context);

		if (r == -1) {
			/* We have encourred a real read error */
			return timeout_epilog(thread, "Read error with");
		}

		/* Handle response stream */
		http_handle_response(thread, digest, (!req->extracted) ? 1 : 0);

	} else {

		/* Handle response stream */
		http_process_response(req, r, (url->digest != NULL));

		/*
		 * Register next http stream reader.
		 * Register itself to not perturbe global I/O multiplexer.
		 */
		thread_add_read(thread->master, http_read_thread, checker,
				thread->u.fd, timeout);
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
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	http_t *http = HTTP_ARG(http_get_check);
	request_t *req = HTTP_REQ(http);
	url_t *url = list_element(http_get_check->url, http->url_it);
	unsigned timeout = checker->co->connection_to;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT)
		return timeout_epilog(thread, "Timeout WEB read");

	/* Allocate & clean the get buffer */
	req->buffer = (char *) MALLOC(MAX_BUFFER_LENGTH);
	req->extracted = NULL;
	req->len = 0;
	req->error = 0;
	if (url->digest)
		MD5_Init(&req->context);

	/* Register asynchronous http/ssl read thread */
	if (http_get_check->proto == PROTO_SSL)
		thread_add_read(thread->master, ssl_read_thread, checker,
				thread->u.fd, timeout);
	else
		thread_add_read(thread->master, http_read_thread, checker,
				thread->u.fd, timeout);
	return 0;
}

/* remote Web server is connected, send it the get url query.  */
int
http_request_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	http_t *http = HTTP_ARG(http_get_check);
	request_t *req = HTTP_REQ(http);
	struct sockaddr_storage *addr = &checker->co->dst;
	unsigned timeout = checker->co->connection_to;
	char *vhost = CHECKER_VHOST(checker);
	char *request_host = 0;
	char *request_host_port = 0;
	char *str_request;
	url_t *fetched_url;
	int ret = 0;
	int val;

	/* Handle read timeout */
	if (thread->type == THREAD_WRITE_TIMEOUT)
		return timeout_epilog(thread, "Timeout WEB read");

	/* Allocate & clean the GET string */
	str_request = (char *) MALLOC(GET_BUFFER_LENGTH);

	fetched_url = fetch_next_url(http_get_check);

	if (vhost) {
		/* If vhost was defined we don't need to override it's port */
		request_host = vhost;
		request_host_port = (char*) MALLOC(1);
		*request_host_port = 0;
	} else {
		request_host = inet_sockaddrtos(addr);

		/* Allocate a buffer for the port string ( ":" [0-9][0-9][0-9][0-9][0-9] "\0" ) */
		request_host_port = (char*) MALLOC(7);
		snprintf(request_host_port, 7, ":%d", 
			 ntohs(inet_sockaddrport(addr)));
	}

	if(addr->ss_family == AF_INET6 && !vhost){
		/* if literal ipv6 address, use ipv6 template, see RFC 2732 */
		snprintf(str_request, GET_BUFFER_LENGTH, REQUEST_TEMPLATE_IPV6,
			fetched_url->path, request_host, request_host_port);
	} else {
		snprintf(str_request, GET_BUFFER_LENGTH, REQUEST_TEMPLATE,
			fetched_url->path, request_host, request_host_port);
	}

	FREE(request_host_port);

	DBG("Processing url(%d) of %s.",
	    http->url_it + 1
	    , FMT_HTTP_RS(checker));

	/* Set descriptor non blocking */
	val = fcntl(thread->u.fd, F_GETFL, 0);
	fcntl(thread->u.fd, F_SETFL, val | O_NONBLOCK);

	/* Send the GET request to remote Web server */
	if (http_get_check->proto == PROTO_SSL) {
		ret = ssl_send_request(req->ssl, str_request,
				       strlen(str_request));
	} else {
		ret = (send(thread->u.fd, str_request, strlen(str_request), 0) !=
		       -1) ? 1 : 0;
	}

	/* restore descriptor flags */
	fcntl(thread->u.fd, F_SETFL, val);

	FREE(str_request);

	if (!ret) {
		return timeout_epilog(thread, "Cannot send get request to");
	}

	/* Register read timeouted thread */
	thread_add_read(thread->master, http_response_thread, checker,
			thread->u.fd, timeout);
	return 1;
}

/* WEB checkers threads */
int
http_check_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	http_t *http = HTTP_ARG(http_get_check);
#ifdef _DEBUG_
	request_t *req = HTTP_REQ(http);
#endif
	int ret = 1;
	int status;
	long timeout = 0;
	int ssl_err = 0;
	int new_req = 0;

	status = tcp_socket_state(thread->u.fd, thread, http_check_thread);
	switch (status) {
	case connect_error:
		return timeout_epilog(thread, "Error connecting");
		break;

	case connect_timeout:
		return timeout_epilog(thread, "Timeout connecting");
		break;

	case connect_success:{
			if (!http->req) {
				http->req = (request_t *) MALLOC(sizeof (request_t));
				new_req = 1;
			} else
				new_req = 0;

			if (http_get_check->proto == PROTO_SSL) {
				timeout = timer_long(thread->sands) - timer_long(time_now);
				if (thread->type != THREAD_WRITE_TIMEOUT &&
				    thread->type != THREAD_READ_TIMEOUT)
					ret = ssl_connect(thread, new_req);
				else {
					return timeout_epilog(thread, "Timeout connecting");
				}

				if (ret == -1) {
					switch ((ssl_err = SSL_get_error(http->req->ssl,
									 ret))) {
					case SSL_ERROR_WANT_READ:
						thread_add_read(thread->master,
								http_check_thread,
								THREAD_ARG(thread),
								thread->u.fd, timeout);
						break;
					case SSL_ERROR_WANT_WRITE:
						thread_add_write(thread->master,
								 http_check_thread,
								 THREAD_ARG(thread),
								 thread->u.fd, timeout);
						break;
					default:
						ret = 0;
						break;
					}
					if (ret == -1)
						break;
				} else if (ret != 1)
					ret = 0;
			}

			if (ret) {
				/* Remote WEB server is connected.
				 * Register the next step thread ssl_request_thread.
				 */
				DBG("Remote Web server %s connected.", FMT_HTTP_RS(checker));
				thread_add_write(thread->master,
						 http_request_thread, checker,
						 thread->u.fd,
						 checker->co->connection_to);
			} else {
				DBG("Connection trouble to: %s."
						 , FMT_HTTP_RS(checker));
#ifdef _DEBUG_
				if (http_get_check->proto == PROTO_SSL)
					ssl_printerr(SSL_get_error
						     (req->ssl, ret));
#endif
				return timeout_epilog(thread, "SSL handshake/communication error"
							 " connecting to");
			}
		}
		break;
	}

	return 0;
}

int
http_connect_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	conn_opts_t *co = checker->co;
	url_t *fetched_url;
	enum connect_result status;
	int fd;

	/*
	 * Register a new checker thread & return
	 * if checker is disabled
	 */
	if (!CHECKER_ENABLED(checker)) {
		thread_add_timer(thread->master, http_connect_thread, checker,
				 checker->vs->delay_loop);
		return 0;
	}

	/* if there are no URLs in list, enable server w/o checking */
	fetched_url = fetch_next_url(http_get_check);
	if (!fetched_url)
		return epilog(thread, 1, 1, 0) + 1;

	/* Create the socket */
	if ((fd = socket(co->dst.ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		log_message(LOG_INFO, "WEB connection fail to create socket. Rescheduling.");
		thread_add_timer(thread->master, http_connect_thread, checker,
				checker->vs->delay_loop);

		return 0;
	}

	status = tcp_bind_connect(fd, co);

	/* handle tcp connection status & register check worker thread */
	if(tcp_connection_state(fd, status, thread, http_check_thread,
			co->connection_to)) {
		close(fd);
		log_message(LOG_INFO, "WEB socket bind failed. Rescheduling");
		thread_add_timer(thread->master, http_connect_thread, checker,
				checker->vs->delay_loop);
	}

	return 0;
}
