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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <openssl/err.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>

#include "check_http.h"
#include "check_api.h"
#include "check_ssl.h"
#include "logger.h"
#include "parser.h"
#include "utils.h"
#include "html.h"
#if !HAVE_DECL_SOCK_CLOEXEC
#include "old_socket.h"
#include "string.h"
#endif
#include "layer4.h"
#include "ipwrapper.h"
#include "smtp.h"

#define	REGISTER_CHECKER_NEW	1
#define	REGISTER_CHECKER_RETRY	2

static int http_connect_thread(thread_t *);

/* Configuration stream handling */
static void
free_url(void *data)
{
	url_t *url = data;
	FREE_PTR(url->path);
	FREE_PTR(url->digest);
	FREE_PTR(url->virtualhost);
	FREE(url);
}

static void
dump_url(FILE *fp, void *data)
{
	url_t *url = data;
	conf_write(fp, "   Checked url = %s", url->path);
	if (url->digest)
		conf_write(fp, "     digest = %s", url->digest);
	if (url->status_code)
		conf_write(fp, "     HTTP Status Code = %d", url->status_code);
	if (url->virtualhost)
		conf_write(fp, "     Virtual host = %s", url->virtualhost);
}

static void
free_http_request(request_t *req)
{
	if(!req)
		return;
	if (req->ssl)
		SSL_free(req->ssl);
	if (req->buffer)
		FREE(req->buffer);
	FREE(req);
}

static void
free_http_get_check(void *data)
{
	http_checker_t *http_get_chk = CHECKER_DATA(data);
	request_t *req = http_get_chk->req;

	free_list(&http_get_chk->url);
	free_http_request(req);
	FREE_PTR(http_get_chk->virtualhost);
	FREE_PTR(http_get_chk);
	FREE_PTR(CHECKER_CO(data));
	FREE(data);
}

static void
dump_http_get_check(FILE *fp, void *data)
{
	checker_t *checker = data;
	http_checker_t *http_get_chk = checker->data;

	conf_write(fp, "   Keepalive method = %s_GET",
			http_get_chk->proto == PROTO_HTTP ? "HTTP" : "SSL");
	dump_checker_opts(fp, checker);
	if (http_get_chk->virtualhost)
		conf_write(fp, "   Virtualhost = %s", http_get_chk->virtualhost);
	dump_list(fp, http_get_chk->url);
}
static http_checker_t *
alloc_http_get(char *proto)
{
	http_checker_t *http_get_chk;

	http_get_chk = (http_checker_t *) MALLOC(sizeof (http_checker_t));
	http_get_chk->proto =
	    (!strcmp(proto, "HTTP_GET")) ? PROTO_HTTP : PROTO_SSL;
	http_get_chk->url = alloc_list(free_url, dump_url);
	http_get_chk->virtualhost = NULL;

	if (http_get_chk->proto == PROTO_SSL)
		check_data->ssl_required = true;

	return http_get_chk;
}

static bool
http_get_check_compare(void *a, void *b)
{
	http_checker_t *old = CHECKER_DATA(a);
	http_checker_t *new = CHECKER_DATA(b);
	size_t n;
	url_t *u1, *u2;

	if (!compare_conn_opts(CHECKER_CO(a), CHECKER_CO(b)))
		return false;
	if (LIST_SIZE(old->url) != LIST_SIZE(new->url))
		return false;
	if (!old->virtualhost != !new->virtualhost)
		return false;
	if (old->virtualhost && strcmp(old->virtualhost, new->virtualhost))
		return false;
	for (n = 0; n < LIST_SIZE(new->url); n++) {
		u1 = (url_t *)list_element(old->url, n);
		u2 = (url_t *)list_element(new->url, n);
		if (strcmp(u1->path, u2->path))
			return false;
		if (!u1->digest != !u2->digest)
			return false;
		if (u1->digest && strcmp(u1->digest, u2->digest))
			return false;
		if (u1->status_code != u2->status_code)
			return false;
		if (!u1->virtualhost != !u2->virtualhost)
			return false;
		if (u1->virtualhost && strcmp(u1->virtualhost, u2->virtualhost))
			return false;
	}

	return true;
}

static void
http_get_handler(vector_t *strvec)
{
	checker_t *checker;
	http_checker_t *http_get_chk;
	char *str = strvec_slot(strvec, 0);

	/* queue new checker */
	http_get_chk = alloc_http_get(str);
	checker = queue_checker(free_http_get_check, dump_http_get_check,
		      http_connect_thread, http_get_check_compare,
		      http_get_chk, CHECKER_NEW_CO());
	checker->default_delay_before_retry = 3 * TIMER_HZ;
}

static void
http_get_retry_handler(vector_t *strvec)
{
	checker_t *checker = LIST_TAIL_DATA(checkers_queue);
	checker->retry = CHECKER_VALUE_UINT(strvec);
}

static void
virtualhost_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();

	http_get_chk->virtualhost = CHECKER_VALUE_STRING(strvec);
}

static void
http_get_check(void)
{
	http_checker_t *http_get_chk = CHECKER_GET();

	if (LIST_ISEMPTY(http_get_chk->url)) {
		log_message(LOG_INFO, "HTTP/SSL_GET checker has no urls specified - ignoring");
		dequeue_new_checker();
	}

	if (!check_conn_opts(CHECKER_GET_CO())) {
		dequeue_new_checker();
	}
}

static void
url_handler(__attribute__((unused)) vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *new;

	/* allocate the new URL */
	new = (url_t *) MALLOC(sizeof (url_t));

	list_add(http_get_chk->url, new);
}

static void
path_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = LIST_TAIL_DATA(http_get_chk->url);

	url->path = CHECKER_VALUE_STRING(strvec);
}

static void
digest_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = LIST_TAIL_DATA(http_get_chk->url);

	url->digest = CHECKER_VALUE_STRING(strvec);
}

static void
status_code_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = LIST_TAIL_DATA(http_get_chk->url);

	url->status_code = CHECKER_VALUE_INT(strvec);
}

static void
url_virtualhost_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = LIST_TAIL_DATA(http_get_chk->url);

	url->virtualhost = CHECKER_VALUE_STRING(strvec);
}

#ifdef _HAVE_SSL_SET_TLSEXT_HOST_NAME_
static void
enable_sni_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res == -1) {
			log_message(LOG_INFO, "Invalid enable_sni parameter %s", FMT_STR_VSLOT(strvec, 1));
			return;
		}
	}
	http_get_chk->enable_sni = res;
}
#endif

static void
url_check(void)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = LIST_TAIL_DATA(http_get_chk->url);

	if (!url->path) {
		log_message(LOG_INFO, "HTTP/SSL_GET checker url has no path - ignoring");
		free_list_element(http_get_chk->url, http_get_chk->url->tail);
	}
}
static void
install_http_ssl_check_keyword(const char *keyword)
{
	install_keyword(keyword, &http_get_handler);
	install_sublevel();
	install_checker_common_keywords(true);
	install_keyword("nb_get_retry", &http_get_retry_handler);	/* Deprecated */
	install_keyword("virtualhost", &virtualhost_handler);
#ifdef _HAVE_SSL_SET_TLSEXT_HOST_NAME_
	install_keyword("enable_sni", &enable_sni_handler);
#endif
	install_keyword("url", &url_handler);
	install_sublevel();
	install_keyword("path", &path_handler);
	install_keyword("digest", &digest_handler);
	install_keyword("status_code", &status_code_handler);
	install_keyword("virtualhost", &url_virtualhost_handler);
	install_sublevel_end_handler(url_check);
	install_sublevel_end();
	install_sublevel_end_handler(http_get_check);
	install_sublevel_end();
}

void
install_http_check_keyword(void)
{
	install_http_ssl_check_keyword("HTTP_GET");
}

void
install_ssl_check_keyword(void)
{
	install_http_ssl_check_keyword("SSL_GET");
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
static int
epilog(thread_t * thread, int method, unsigned t, unsigned c)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	request_t *req = http_get_check->req;
	unsigned long delay = 0;
	bool checker_was_up;
	bool rs_was_alive;

	http_get_check->url_it += t ? t : -http_get_check->url_it;
	checker->retry_it += c ? c : -checker->retry_it;

	if (method == REGISTER_CHECKER_NEW && http_get_check->url_it >= LIST_SIZE(http_get_check->url)) {
		/* All the url have been successfully checked.
		 * Check completed.
		 * check if server is currently alive.
		 */
		if (!checker->is_up || !checker->has_run) {
			log_message(LOG_INFO, "Remote Web server %s succeed on service."
					    , FMT_HTTP_RS(checker));
			checker_was_up = checker->is_up;
			rs_was_alive = checker->rs->alive;
			update_svr_checker_state(UP, checker);
			if (!checker_was_up && checker->rs->smtp_alert &&
			    (rs_was_alive != checker->rs->alive || !global_data->no_checker_emails))
				smtp_alert(SMTP_MSG_RS, checker, NULL,
					   "=> CHECK succeed on service <=");
		}

		/* Reset it counters */
		http_get_check->url_it = 0;
		checker->retry_it = 0;
	}
	/*
	 * The get retry implementation mean that we retry performing
	 * a GET on the same url until the remote web server return
	 * html buffer. This is sometime needed with some applications
	 * servers.
	 */
	else if (method == REGISTER_CHECKER_RETRY && checker->retry_it > checker->retry) {
		if (checker->is_up || !checker->has_run) {
			if (checker->has_run && checker->retry)
				log_message(LOG_INFO
				   , "Check on service %s failed after %u retry."
				   , FMT_HTTP_RS(checker)
				   , checker->retry_it - 1);
			else
				log_message(LOG_INFO
				   , "Check on service %s failed."
				   , FMT_HTTP_RS(checker));
			checker_was_up = checker->is_up;
			rs_was_alive = checker->rs->alive;
			update_svr_checker_state(DOWN, checker);
			if (checker_was_up && checker->rs->smtp_alert &&
			    (rs_was_alive != checker->rs->alive || !global_data->no_checker_emails))
				smtp_alert(SMTP_MSG_RS, checker, NULL,
					   "=> CHECK failed on service"
					   " : HTTP request failed <=");
		}

		/* Reset it counters */
		http_get_check->url_it = 0;
		checker->retry_it = 0;
	}

	/* register next timer thread */
	switch (method) {
	case REGISTER_CHECKER_NEW:
		delay = checker->delay_loop;
		break;
	case REGISTER_CHECKER_RETRY:
		if (http_get_check->url_it == 0 && checker->retry_it == 0)
			delay = checker->delay_loop;
		else
			delay = checker->delay_before_retry;
		break;
	}

	/* If req == NULL, fd is not created */
	if (req) {
		free_http_request(req);
		http_get_check->req = NULL;
		close(thread->u.fd);
	}

	/* Register next checker thread */
	thread_add_timer(thread->master, http_connect_thread, checker, delay);
	return 0;
}

int
timeout_epilog(thread_t * thread, const char *debug_msg)
{
	checker_t *checker = THREAD_ARG(thread);

	/* check if server is currently alive */
	if (checker->is_up) {
		log_message(LOG_INFO, "%s server %s."
				    , debug_msg
				    , FMT_HTTP_RS(checker));
		return epilog(thread, REGISTER_CHECKER_RETRY, 0, 1);
	}

	/* do not retry if server is already known as dead */
	return epilog(thread, REGISTER_CHECKER_NEW, 0, 0);
}

/* return the url pointer of the current url iterator  */
static url_t *
fetch_next_url(http_checker_t * http_get_check)
{
	return list_element(http_get_check->url, http_get_check->url_it);
}

/* Handle response */
int
http_handle_response(thread_t * thread, unsigned char digest[16]
		     , bool empty_buffer)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	request_t *req = http_get_check->req;
	url_t *url;
	int r, di = 0;
	char *digest_tmp;
	url_t *fetched_url = fetch_next_url(http_get_check);
	enum {
		NONE,
		ON_SUCCESS,
		ON_STATUS,
		ON_DIGEST
	} last_success = NONE; /* the source of last considered success */

	/* First check if remote webserver returned data */
	if (empty_buffer)
		return timeout_epilog(thread, "Read, no data received from ");

	/* Next check the HTTP status code */
	if (fetched_url->status_code) {
		if (req->status_code != fetched_url->status_code)
			return timeout_epilog(thread, "HTTP status code error to");

		last_success = ON_STATUS;
	}
	else if (req->status_code >= 200 && req->status_code <= 299)
		last_success = ON_SUCCESS;

	/* Report a length mismatch the first time we get the specific difference */
	url = list_element(http_get_check->url, http_get_check->url_it);
	if (req->content_len != SIZE_MAX && req->content_len != req->rx_bytes) {
		if (url->len_mismatch != (ssize_t)req->content_len - (ssize_t)req->rx_bytes) {
			log_message(LOG_INFO, "http_check for RS %s VS %s url %s%s: content_length (%lu) does not match received bytes (%lu)",
				    FMT_RS(checker->rs, checker->vs), FMT_VS(checker->vs), url->virtualhost ? url->virtualhost : "",
				    url->path, req->content_len, req->rx_bytes);
			url->len_mismatch = (ssize_t)req->content_len - (ssize_t)req->rx_bytes;
		}
	}
	else
		url->len_mismatch = 0;

	/* Continue with MD5SUM */
	if (fetched_url->digest) {
		/* Compute MD5SUM */
		digest_tmp = (char *) MALLOC(MD5_BUFFER_LENGTH + 1);
		for (di = 0; di < 16; di++)
			sprintf(digest_tmp + 2 * di, "%02x", digest[di]);

		r = strcmp(fetched_url->digest, digest_tmp);
		FREE(digest_tmp);

		if (r)
			return timeout_epilog(thread, "MD5 digest error to");
		last_success = ON_DIGEST;
	}

	if (!checker->is_up) {
		switch (last_success) {
			case NONE:
				break;
			case ON_SUCCESS:
				log_message(LOG_INFO,
				       "HTTP success to %s url(%u)."
				       , FMT_HTTP_RS(checker)
				       , http_get_check->url_it + 1);
				return epilog(thread, REGISTER_CHECKER_NEW, 1, 0) + 1;
			case ON_STATUS:
				log_message(LOG_INFO,
				       "HTTP status code success to %s url(%u)."
				       , FMT_HTTP_RS(checker)
				       , http_get_check->url_it + 1);
				return epilog(thread, REGISTER_CHECKER_NEW, 1, 0) + 1;
			case ON_DIGEST:
				log_message(LOG_INFO,
					"MD5 digest success to %s url(%u)."
					, FMT_HTTP_RS(checker)
					, http_get_check->url_it + 1);
				return epilog(thread, REGISTER_CHECKER_NEW, 1, 0) + 1;
		}
	}

	return epilog(thread, REGISTER_CHECKER_NEW, 0, 0) + 1;
}

/* Handle response stream performing MD5 updates */
void
http_process_response(request_t *req, size_t r, bool do_md5)
{
	req->len += r;
	if (!req->extracted) {
		if ((req->extracted = extract_html(req->buffer, req->len))) {
			req->status_code = extract_status_code(req->buffer, req->len);
			req->content_len = extract_content_length(req->buffer, req->len);
			r = req->len - (size_t)(req->extracted - req->buffer);
			if (r && do_md5) {
				if (req->content_len == SIZE_MAX || req->content_len > req->rx_bytes)
					MD5_Update(&req->context, req->extracted,
						   req->content_len == SIZE_MAX || req->content_len >= req->rx_bytes + r ? r : req->content_len - req->rx_bytes);
			}
			req->rx_bytes = r;
			req->len = 0;
		}
	} else if (req->len) {
		if (req->content_len == SIZE_MAX || req->content_len > req->rx_bytes) {
			MD5_Update(&req->context, req->buffer,
				   req->content_len == SIZE_MAX || req->content_len >= req->rx_bytes + req->len ? req->len : req->content_len - req->rx_bytes);
		}
		req->rx_bytes += req->len;
		req->len = 0;
	}
}

/* Asynchronous HTTP stream reader */
static int
http_read_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	request_t *req = http_get_check->req;
	url_t *url = list_element(http_get_check->url, http_get_check->url_it);
	unsigned timeout = checker->co->connection_to;
	unsigned char digest[16];
	ssize_t r = 0;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT)
		return timeout_epilog(thread, "Timeout HTTP read");

	/* read the HTTP stream */
	r = read(thread->u.fd, req->buffer + req->len,
		 MAX_BUFFER_LENGTH - req->len);

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
			/* We have encountered a real read error */
			return timeout_epilog(thread, "Read error with");
		}

		/* Handle response stream */
		http_handle_response(thread, digest, !req->extracted);

	} else {

		/* Handle response stream */
		http_process_response(req, (size_t)r, (url->digest != NULL));

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
static int
http_response_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	request_t *req = http_get_check->req;
	url_t *url = list_element(http_get_check->url, http_get_check->url_it);
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
static int
http_request_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	request_t *req = http_get_check->req;
	struct sockaddr_storage *addr = &checker->co->dst;
	unsigned timeout = checker->co->connection_to;
	char *vhost;
	char *request_host;
	char request_host_port[7];	/* ":" [0-9][0-9][0-9][0-9][0-9] "\0" */
	char *str_request;
	url_t *fetched_url;
	int ret = 0;

	/* Handle write timeout */
	if (thread->type == THREAD_WRITE_TIMEOUT)
		return timeout_epilog(thread, "Timeout WEB write");

	/* Allocate & clean the GET string */
	str_request = (char *) MALLOC(GET_BUFFER_LENGTH);

	fetched_url = fetch_next_url(http_get_check);

	if (fetched_url->virtualhost)
		vhost = fetched_url->virtualhost;
	else if (http_get_check->virtualhost)
		vhost = http_get_check->virtualhost;
	else if (checker->rs->virtualhost)
		vhost = checker->rs->virtualhost;
	else if (checker->vs->virtualhost)
		vhost = checker->vs->virtualhost;
	else
		vhost = NULL;

	if (vhost) {
		/* If vhost was defined we don't need to override it's port */
		request_host = vhost;
		request_host_port[0] = '\0';
	} else {
		request_host = inet_sockaddrtos(addr);

		snprintf(request_host_port, sizeof(request_host_port), ":%d",
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

	DBG("Processing url(%u) of %s.", http_get_check->url_it + 1 , FMT_HTTP_RS(checker));

	/* Send the GET request to remote Web server */
	if (http_get_check->proto == PROTO_SSL)
		ret = ssl_send_request(req->ssl, str_request, (int)strlen(str_request));
	else
		ret = (send(thread->u.fd, str_request, strlen(str_request), 0) != -1);

	FREE(str_request);

	if (!ret)
		return timeout_epilog(thread, "Cannot send get request to");

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
#ifdef _DEBUG_
	request_t *req = http_get_check->req;
#endif
	int ret = 1;
	int status;
	unsigned long timeout = 0;
	int ssl_err = 0;
	bool new_req = false;

	status = tcp_socket_state(thread, http_check_thread);
	switch (status) {
	case connect_error:
		return timeout_epilog(thread, "Error connecting");
		break;

	case connect_timeout:
		return timeout_epilog(thread, "Timeout connecting");
		break;

	case connect_success:
		if (!http_get_check->req) {
			http_get_check->req = (request_t *) MALLOC(sizeof (request_t));
			new_req = true;
		} else
			new_req = false;

		if (http_get_check->proto == PROTO_SSL) {
			timeout = timer_long(thread->sands) - timer_long(time_now);
			if (thread->type != THREAD_WRITE_TIMEOUT &&
			    thread->type != THREAD_READ_TIMEOUT)
				ret = ssl_connect(thread, new_req);
			else
				return timeout_epilog(thread, "Timeout connecting");

			if (ret == -1) {
				switch ((ssl_err = SSL_get_error(http_get_check->req->ssl,
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
		break;
	}

	return 0;
}

static int
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
	if (!checker->enabled) {
		thread_add_timer(thread->master, http_connect_thread, checker,
				 checker->delay_loop);
		return 0;
	}

	/* if there are no URLs in list, enable server w/o checking */
	fetched_url = fetch_next_url(http_get_check);
	if (!fetched_url)
		return epilog(thread, REGISTER_CHECKER_NEW, 1, 0) + 1;

	/* Create the socket */
	if ((fd = socket(co->dst.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP)) == -1) {
		log_message(LOG_INFO, "WEB connection fail to create socket. Rescheduling.");
		thread_add_timer(thread->master, http_connect_thread, checker,
				checker->delay_loop);

		return 0;
	}

#if !HAVE_DECL_SOCK_NONBLOCK
	if (set_sock_flags(fd, F_SETFL, O_NONBLOCK))
		log_message(LOG_INFO, "Unable to set NONBLOCK on http_connect socket - %s (%d)", strerror(errno), errno);
#endif

#if !HAVE_DECL_SOCK_CLOEXEC
	if (set_sock_flags(fd, F_SETFD, FD_CLOEXEC))
		log_message(LOG_INFO, "Unable to set CLOEXEC on http_connect socket - %s (%d)", strerror(errno), errno);
#endif

	status = tcp_bind_connect(fd, co);

	/* handle tcp connection status & register check worker thread */
	if(tcp_connection_state(fd, status, thread, http_check_thread,
			co->connection_to)) {
		close(fd);
		log_message(LOG_INFO, "WEB socket bind failed. Rescheduling");
		thread_add_timer(thread->master, http_connect_thread, checker,
				checker->delay_loop);
	}

	return 0;
}

#ifdef _TIMER_DEBUG_
void
print_check_http_addresses(void)
{
	log_message(LOG_INFO, "Address of dump_http_get_check() is 0x%p", dump_http_get_check);
	log_message(LOG_INFO, "Address of http_check_thread() is 0x%p", http_check_thread);
	log_message(LOG_INFO, "Address of http_connect_thread() is 0x%p", http_connect_thread);
	log_message(LOG_INFO, "Address of http_read_thread() is 0x%p", http_read_thread);
	log_message(LOG_INFO, "Address of http_request_thread() is 0x%p", http_request_thread);
	log_message(LOG_INFO, "Address of http_response_thread() is 0x%p", http_response_thread);
}
#endif
