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
 * Copyright (C) 2001-2009 Alexandre Cassen, <acassen@freebox.fr>
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

int http_connect_thread(thread *);

/* Configuration stream handling */
void
free_url(void *data)
{
	url *url_obj = data;
	FREE(url_obj->path);
	FREE(url_obj->digest);
	FREE(url_obj);
}

void
dump_url(void *data)
{
	url *url_obj = data;
	log_message(LOG_INFO, "   Checked url = %s", url_obj->path);
	if (url_obj->digest)
		log_message(LOG_INFO, "           digest = %s",
		       url_obj->digest);
	if (url_obj->status_code)
		log_message(LOG_INFO, "           HTTP Status Code = %d",
		       url_obj->status_code);
}

void
free_http_get_check(void *data)
{
	http_get_checker *http_get_chk = CHECKER_DATA(data);

	free_list(http_get_chk->url);
	FREE(http_get_chk->arg);
	FREE(http_get_chk);
	FREE(data);
}

void
dump_http_get_check(void *data)
{
	http_get_checker *http_get_chk = CHECKER_DATA(data);

	if (http_get_chk->proto == PROTO_HTTP)
		log_message(LOG_INFO, "   Keepalive method = HTTP_GET");
	else
		log_message(LOG_INFO, "   Keepalive method = SSL_GET");
	if (http_get_chk->connection_port)
		log_message(LOG_INFO, "   Connection port = %d",
		       ntohs(http_get_chk->connection_port));
	if (http_get_chk->bindto)
		log_message(LOG_INFO, "   Bind to = %s",
		       inet_ntop2(http_get_chk->bindto));
	log_message(LOG_INFO, "   Connection timeout = %lu",
	       http_get_chk->connection_to/TIMER_HZ);
	log_message(LOG_INFO, "   Nb get retry = %d", http_get_chk->nb_get_retry);
	log_message(LOG_INFO, "   Delay before retry = %lu",
	       http_get_chk->delay_before_retry/TIMER_HZ);
	dump_list(http_get_chk->url);
}
static http_get_checker *
alloc_http_get(char *proto)
{
	http_get_checker *http_get_chk;

	http_get_chk = (http_get_checker *) MALLOC(sizeof (http_get_checker));
	http_get_chk->arg = (http_arg *) MALLOC(sizeof (http_arg));
	http_get_chk->proto =
	    (!strcmp(proto, "HTTP_GET")) ? PROTO_HTTP : PROTO_SSL;
	http_get_chk->url = alloc_list(free_url, dump_url);
	http_get_chk->nb_get_retry = 1;

	return http_get_chk;
}

void
http_get_handler(vector strvec)
{
	http_get_checker *http_get_chk;
	char *str = VECTOR_SLOT(strvec, 0);

	/* queue new checker */
	http_get_chk = alloc_http_get(str);
	queue_checker(free_http_get_check, dump_http_get_check,
		      http_connect_thread, http_get_chk);
}

void
connect_p_handler(vector strvec)
{
	http_get_checker *http_get_chk = CHECKER_GET();
	http_get_chk->connection_port = htons(CHECKER_VALUE_INT(strvec));
}

void
bindto_handler(vector strvec)
{
	http_get_checker *http_get_chk = CHECKER_GET();
	inet_ston(VECTOR_SLOT(strvec, 1), &http_get_chk->bindto);
}

void
connect_to_handler(vector strvec)
{
	http_get_checker *http_get_chk = CHECKER_GET();
	http_get_chk->connection_to = CHECKER_VALUE_INT(strvec) * TIMER_HZ;
}

void
nb_get_retry_handler(vector strvec)
{
	http_get_checker *http_get_chk = CHECKER_GET();
	http_get_chk->nb_get_retry = CHECKER_VALUE_INT(strvec);
}

void
delay_before_retry_handler(vector strvec)
{
	http_get_checker *http_get_chk = CHECKER_GET();
	http_get_chk->delay_before_retry = CHECKER_VALUE_INT(strvec) * TIMER_HZ;
}

void
url_handler(vector strvec)
{
	http_get_checker *http_get_chk = CHECKER_GET();
	url *new;

	/* allocate the new URL */
	new = (url *) MALLOC(sizeof (url));

	list_add(http_get_chk->url, new);
}

void
path_handler(vector strvec)
{
	http_get_checker *http_get_chk = CHECKER_GET();
	url *url_obj = LIST_TAIL_DATA(http_get_chk->url);

	url_obj->path = CHECKER_VALUE_STRING(strvec);
}

void
digest_handler(vector strvec)
{
	http_get_checker *http_get_chk = CHECKER_GET();
	url *url_obj = LIST_TAIL_DATA(http_get_chk->url);

	url_obj->digest = CHECKER_VALUE_STRING(strvec);
}

void
status_code_handler(vector strvec)
{
	http_get_checker *http_get_chk = CHECKER_GET();
	url *url_obj = LIST_TAIL_DATA(http_get_chk->url);

	url_obj->status_code = CHECKER_VALUE_INT(strvec);
}

void
install_http_check_keyword(void)
{
	install_keyword("HTTP_GET", &http_get_handler);
	install_sublevel();
	install_keyword("connect_port", &connect_p_handler);
	install_keyword("bindto", &bindto_handler);
	install_keyword("connect_timeout", &connect_to_handler);
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
	install_keyword("connect_port", &connect_p_handler);
	install_keyword("bindto", &bindto_handler);
	install_keyword("connect_timeout", &connect_to_handler);
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

uint16_t
get_service_port(checker * checker_obj)
{
	http_get_checker *http_get_check = CHECKER_ARG(checker_obj);
	uint16_t addr_port;

	/*
	 *  Set the remote connection port.
	 *  If a specific checker port is specified, we used this.
	 *  If we are balancing all services (host rather than service),
	 *  then assume we want to use default ports for HTTP or HTTPS.
	 *  Known as 'Layer3 stickyness'.
	 */
	addr_port = CHECKER_RPORT(checker_obj);
	if (!addr_port)
		addr_port =
		    htons((http_get_check->proto == PROTO_SSL) ? 443 : 80);
	if (http_get_check->connection_port)
		addr_port = http_get_check->connection_port;
	return addr_port;
}

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
epilog(thread * thread_obj, int method, int t, int c)
{
	checker *checker_obj = THREAD_ARG(thread_obj);
	http_get_checker *http_get_check = CHECKER_ARG(checker_obj);
	http_arg *http_arg_obj = HTTP_ARG(http_get_check);
	REQ *req = HTTP_REQ(http_arg_obj);
	uint16_t addr_port = get_service_port(checker_obj);
	long delay = 0;

	if (method) {
		http_arg_obj->url_it += t ? t : -http_arg_obj->url_it;
		http_arg_obj->retry_it += c ? c : -http_arg_obj->retry_it;
	}

	/*
	 * The get retry implementation mean that we retry performing
	 * a GET on the same url until the remote web server return 
	 * html buffer. This is sometime needed with some applications
	 * servers.
	 */
	if (http_arg_obj->retry_it > http_get_check->nb_get_retry-1) {
		if (svr_checker_up(checker_obj->id, checker_obj->rs)) {
			log_message(LOG_INFO, "Check on service [%s:%d] failed after %d retry."
			       , inet_ntop2(CHECKER_RIP(checker_obj))
			       , ntohs(addr_port), http_arg_obj->retry_it);
			smtp_alert(checker_obj->rs, NULL, NULL,
				   "DOWN",
				   "=> CHECK failed on service"
				   " : MD5 digest mismatch <=");
			update_svr_checker_state(DOWN, checker_obj->id
						     , checker_obj->vs
						     , checker_obj->rs);
		}

		/* Reset it counters */
		http_arg_obj->url_it = 0;
		http_arg_obj->retry_it = 0;
	}

	/* register next timer thread */
	switch (method) {
	case 1:
		if (req)
			delay = checker_obj->vs->delay_loop;
		else
			delay =
			    http_get_check->delay_before_retry;
		break;
	case 2:
		if (http_arg_obj->url_it == 0 && http_arg_obj->retry_it == 0)
			delay = checker_obj->vs->delay_loop;
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
		http_arg_obj->req = NULL;
		close(thread_obj->u.fd);
	}

	/* Register next checker thread */
	thread_add_timer(thread_obj->master, http_connect_thread, checker_obj, delay);
	return 0;
}

int
timeout_epilog(thread * thread_obj, char *smtp_msg, char *debug_msg)
{
	checker *checker_obj = THREAD_ARG(thread_obj);
	uint16_t addr_port = get_service_port(checker_obj);

	log_message(LOG_INFO, "Timeout %s server [%s:%d].",
	       debug_msg
	       , inet_ntop2(CHECKER_RIP(checker_obj))
	       , ntohs(addr_port));

	/* check if server is currently alive */
	if (svr_checker_up(checker_obj->id, checker_obj->rs)) {
		smtp_alert(checker_obj->rs, NULL, NULL,
			   "DOWN", smtp_msg);
		update_svr_checker_state(DOWN, checker_obj->id
					     , checker_obj->vs
					     , checker_obj->rs);
	}

	return epilog(thread_obj, 1, 0, 0);
}

/* return the url pointer of the current url iterator  */
url *
fetch_next_url(http_get_checker * http_get_check)
{
	http_arg *http_arg_obj = HTTP_ARG(http_get_check);

	return list_element(http_get_check->url, http_arg_obj->url_it);
}

/* Handle response */
int
http_handle_response(thread * thread_obj, unsigned char digest[16]
		     , int empty_buffer)
{
	checker *checker_obj = THREAD_ARG(thread_obj);
	http_get_checker *http_get_check = CHECKER_ARG(checker_obj);
	http_arg *http_arg_obj = HTTP_ARG(http_get_check);
	REQ *req = HTTP_REQ(http_arg_obj);
	uint16_t addr_port = get_service_port(checker_obj);
	int r, di = 0;
	char *digest_tmp;
	url *fetched_url = fetch_next_url(http_get_check);

	/* First check if remote webserver returned data */
	if (empty_buffer)
		return timeout_epilog(thread_obj, "=> CHECK failed on service"
				      " : empty buffer received <=\n\n",
				      "Read, no data received from ");

	/* Next check the HTTP status code */
	if (fetched_url->status_code) {
		if (req->status_code != fetched_url->status_code) {
			/* check if server is currently alive */
			if (svr_checker_up(checker_obj->id, checker_obj->rs)) {
				log_message(LOG_INFO,
				       "HTTP status code error to [%s:%d] url(%s)"
				       ", status_code [%d].",
				       inet_ntop2(CHECKER_RIP(checker_obj)),
				       ntohs(addr_port), fetched_url->path,
				       req->status_code);
				smtp_alert(checker_obj->rs, NULL, NULL,
					   "DOWN",
					   "=> CHECK failed on service"
					   " : HTTP status code mismatch <=");
				update_svr_checker_state(DOWN, checker_obj->id
							     , checker_obj->vs
							     , checker_obj->rs);
			} else {
				DBG("HTTP Status_code to [%s:%d] url(%d) = [%d].",
				    inet_ntop2(CHECKER_RIP(checker_obj))
				    , ntohs(addr_port)
				    , http_arg_obj->url_it + 1
				    , req->status_code);
				/*
				 * We set retry iterator to max value to not retry
				 * when service is already know as die.
				 */
				http_arg_obj->retry_it = http_get_check->nb_get_retry;
			}
			return epilog(thread_obj, 2, 0, 1);
		} else {
			if (!svr_checker_up(checker_obj->id, checker_obj->rs))
				log_message(LOG_INFO,
				       "HTTP status code success to [%s:%d] url(%d).",
				       inet_ntop2(CHECKER_RIP(checker_obj))
				       , ntohs(addr_port)
				       , http_arg_obj->url_it + 1);
			return epilog(thread_obj, 1, 1, 0) + 1;
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
			/* check if server is currently alive */
			if (svr_checker_up(checker_obj->id, checker_obj->rs)) {
				log_message(LOG_INFO,
				       "MD5 digest error to [%s:%d] url[%s]"
				       ", MD5SUM [%s].",
				       inet_ntop2(CHECKER_RIP(checker_obj)),
				       ntohs(addr_port), fetched_url->path,
				       digest_tmp);
				smtp_alert(checker_obj->rs, NULL, NULL,
					   "DOWN",
					   "=> CHECK failed on service"
					   " : HTTP MD5SUM mismatch <=");
				update_svr_checker_state(DOWN, checker_obj->id
							     , checker_obj->vs
							     , checker_obj->rs);
			} else {
				DBG("MD5SUM to [%s:%d] url(%d) = [%s].",
				    inet_ntop2(CHECKER_RIP(checker_obj))
				    , ntohs(addr_port)
				    , http_arg_obj->url_it + 1
				    , digest_tmp);
				/*
				 * We set retry iterator to max value to not retry
				 * when service is already know as die.
				 */
				http_arg_obj->retry_it = http_get_check->nb_get_retry;
			}
			FREE(digest_tmp);
			return epilog(thread_obj, 2, 0, 1);
		} else {
			if (!svr_checker_up(checker_obj->id, checker_obj->rs))
				log_message(LOG_INFO, "MD5 digest success to [%s:%d] url(%d).",
				       inet_ntop2(CHECKER_RIP(checker_obj))
				       , ntohs(addr_port)
				       , http_arg_obj->url_it + 1);
			FREE(digest_tmp);
			return epilog(thread_obj, 1, 1, 0) + 1;
		}
	}

	return epilog(thread_obj, 1, 0, 0) + 1;
}

/* Handle response stream performing MD5 updates */
int
http_process_response(REQ *req, int r)
{
	req->len += r;
	if (!req->extracted) {
		if ((req->extracted =
		     extract_html(req->buffer, req->len))) {
			req->status_code = extract_status_code(req->buffer, req->len);
			r = req->len - (req->extracted - req->buffer);
			if (r) {
				memmove(req->buffer, req->extracted, r);
				MD5_Update(&req->context, req->buffer, r);
				r = 0;
			}
			req->len = r;
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
http_read_thread(thread * thread_obj)
{
	checker *checker_obj = THREAD_ARG(thread_obj);
	http_get_checker *http_get_check = CHECKER_ARG(checker_obj);
	http_arg *http_arg_obj = HTTP_ARG(http_get_check);
	REQ *req = HTTP_REQ(http_arg_obj);
	uint16_t addr_port = get_service_port(checker_obj);
	unsigned char digest[16];
	int r = 0;
	int val;

	/* Handle read timeout */
	if (thread_obj->type == THREAD_READ_TIMEOUT)
		return timeout_epilog(thread_obj, "=> HTTP CHECK failed on service"
				      " : recevice data <=\n\n", "HTTP read");

	/* Set descriptor non blocking */
	val = fcntl(thread_obj->u.fd, F_GETFL, 0);
	fcntl(thread_obj->u.fd, F_SETFL, val | O_NONBLOCK);

	/* read the HTTP stream */
	r = read(thread_obj->u.fd, req->buffer + req->len,
		 MAX_BUFFER_LENGTH - req->len);

	/* restore descriptor flags */
	fcntl(thread_obj->u.fd, F_SETFL, val);

	/* Test if data are ready */
	if (r == -1 && (errno == EAGAIN || errno == EINTR)) {
		log_message(LOG_INFO, "Read error with server [%s:%d]: %s",
		       inet_ntop2(CHECKER_RIP(checker_obj))
		       , ntohs(addr_port)
		       , strerror(errno));
		thread_add_read(thread_obj->master, http_read_thread, checker_obj,
				thread_obj->u.fd, http_get_check->connection_to);
		return 0;
	}

	if (r == -1 || r == 0) {	/* -1:error , 0:EOF */

		/* All the HTTP stream has been parsed */
		MD5_Final(digest, &req->context);

		if (r == -1) {
			/* We have encourred a real read error */
			if (svr_checker_up(checker_obj->id, checker_obj->rs)) {
				log_message(LOG_INFO, "Read error with server [%s:%d]: %s",
				       inet_ntop2(CHECKER_RIP(checker_obj))
				       , ntohs(addr_port)
				       , strerror(errno));
				smtp_alert(checker_obj->rs, NULL, NULL,
					   "DOWN",
					   "=> HTTP CHECK failed on service"
					   " : cannot receive data <=");
				update_svr_checker_state(DOWN, checker_obj->id
							     , checker_obj->vs
							     , checker_obj->rs);
			}
			return epilog(thread_obj, 1, 0, 0);
		}

		/* Handle response stream */
		http_handle_response(thread_obj, digest, (!req->extracted) ? 1 : 0);

	} else {

		/* Handle response stream */
		http_process_response(req, r);

		/*
		 * Register next http stream reader.
		 * Register itself to not perturbe global I/O multiplexer.
		 */
		thread_add_read(thread_obj->master, http_read_thread, checker_obj,
				thread_obj->u.fd, http_get_check->connection_to);
	}

	return 0;
}

/*
 * Read get result from the remote web server.
 * Apply trigger check to this result.
 */
int
http_response_thread(thread * thread_obj)
{
	checker *checker_obj = THREAD_ARG(thread_obj);
	http_get_checker *http_get_check = CHECKER_ARG(checker_obj);
	http_arg *http_arg_obj = HTTP_ARG(http_get_check);
	REQ *req = HTTP_REQ(http_arg_obj);

	/* Handle read timeout */
	if (thread_obj->type == THREAD_READ_TIMEOUT)
		return timeout_epilog(thread_obj, "=> CHECK failed on service"
				      " : recevice data <=\n\n", "WEB read");

	/* Allocate & clean the get buffer */
	req->buffer = (char *) MALLOC(MAX_BUFFER_LENGTH);
	req->extracted = NULL;
	req->len = 0;
	req->error = 0;
	MD5_Init(&req->context);

	/* Register asynchronous http/ssl read thread */
	if (http_get_check->proto == PROTO_SSL)
		thread_add_read(thread_obj->master, ssl_read_thread, checker_obj,
				thread_obj->u.fd, http_get_check->connection_to);
	else
		thread_add_read(thread_obj->master, http_read_thread, checker_obj,
				thread_obj->u.fd, http_get_check->connection_to);
	return 0;
}

/* remote Web server is connected, send it the get url query.  */
int
http_request_thread(thread * thread_obj)
{
	checker *checker_obj = THREAD_ARG(thread_obj);
	http_get_checker *http_get_check = CHECKER_ARG(checker_obj);
	http_arg *http_arg_obj = HTTP_ARG(http_get_check);
	REQ *req = HTTP_REQ(http_arg_obj);
	uint16_t addr_port = get_service_port(checker_obj);
	char *vhost = CHECKER_VHOST(checker_obj);
	char *str_request;
	url *fetched_url;
	int ret = 0;
	int val;

	/* Handle read timeout */
	if (thread_obj->type == THREAD_WRITE_TIMEOUT)
		return timeout_epilog(thread_obj, "=> CHECK failed on service"
				      " : read timeout <=\n\n",
				      "Web read, timeout");

	/* Allocate & clean the GET string */
	str_request = (char *) MALLOC(GET_BUFFER_LENGTH);

	fetched_url = fetch_next_url(http_get_check);
	snprintf(str_request, GET_BUFFER_LENGTH, REQUEST_TEMPLATE,
		 fetched_url->path,
		 (vhost) ? vhost : inet_ntop2(CHECKER_RIP(checker_obj))
		 , ntohs(addr_port));
	DBG("Processing url(%d) of [%s:%d].",
	    http_arg_obj->url_it + 1
	    , inet_ntop2(CHECKER_RIP(checker_obj))
	    , ntohs(addr_port));

	/* Set descriptor non blocking */
	val = fcntl(thread_obj->u.fd, F_GETFL, 0);
	fcntl(thread_obj->u.fd, F_SETFL, val | O_NONBLOCK);

	/* Send the GET request to remote Web server */
	if (http_get_check->proto == PROTO_SSL) {
		ret = ssl_send_request(req->ssl, str_request,
				       strlen(str_request));
	} else {
		ret = (send(thread_obj->u.fd, str_request, strlen(str_request), 0) !=
		       -1) ? 1 : 0;
	}

	/* restore descriptor flags */
	fcntl(thread_obj->u.fd, F_SETFL, val);

	FREE(str_request);

	if (!ret) {
		log_message(LOG_INFO, "Cannot send get request to [%s:%d].",
		       inet_ntop2(CHECKER_RIP(checker_obj))
		       , ntohs(addr_port));

		/* check if server is currently alive */
		if (svr_checker_up(checker_obj->id, checker_obj->rs)) {
			smtp_alert(checker_obj->rs, NULL, NULL,
				   "DOWN",
				   "=> CHECK failed on service"
				   " : cannot send data <=");
			update_svr_checker_state(DOWN, checker_obj->id
						     , checker_obj->vs
						     , checker_obj->rs);
		}
		return epilog(thread_obj, 1, 0, 0);
	}

	/* Register read timeouted thread */
	thread_add_read(thread_obj->master, http_response_thread, checker_obj,
			thread_obj->u.fd, http_get_check->connection_to);
	return 1;
}

/* WEB checkers threads */
int
http_check_thread(thread * thread_obj)
{
	checker *checker_obj = THREAD_ARG(thread_obj);
	http_get_checker *http_get_check = CHECKER_ARG(checker_obj);
	uint16_t addr_port = get_service_port(checker_obj);
	http_arg *http_arg_obj = HTTP_ARG(http_get_check);
#ifdef _DEBUG_
	REQ *req = HTTP_REQ(http_arg_obj);
#endif
	int ret = 1;
	int status;
	long timeout = 0;
	int ssl_err = 0;
	int new_req = 0;

	status = tcp_socket_state(thread_obj->u.fd, thread_obj, CHECKER_RIP(checker_obj)
				  , addr_port, http_check_thread);
	switch (status) {
	case connect_error:
		/* check if server is currently alive */
		if (svr_checker_up(checker_obj->id, checker_obj->rs)) {
			log_message(LOG_INFO, "Error connecting server [%s:%d].",
			       inet_ntop2(CHECKER_RIP(checker_obj))
			       , ntohs(addr_port));
			smtp_alert(checker_obj->rs, NULL, NULL,
				   "DOWN",
				   "=> CHECK failed on service"
				   " : connection error <=");
			update_svr_checker_state(DOWN, checker_obj->id
						 , checker_obj->vs
						 , checker_obj->rs);
		}
		return epilog(thread_obj, 1, 0, 0);
		break;

	case connect_timeout:
		return timeout_epilog(thread_obj, "==> CHECK failed on service"
				      " : connection timeout <=\n\n",
				      "connect, timeout");
		break;

	case connect_success:{
			if (!http_arg_obj->req) {
				http_arg_obj->req = (REQ *) MALLOC(sizeof (REQ));
				new_req = 1;
			} else
				new_req = 0;

			if (http_get_check->proto == PROTO_SSL) {
				timeout = TIMER_LONG(thread_obj->sands)-TIMER_LONG(time_now);
				if (thread_obj->type != THREAD_WRITE_TIMEOUT &&
				    thread_obj->type != THREAD_READ_TIMEOUT)
					ret = ssl_connect(thread_obj, new_req);
				else {
					return timeout_epilog(thread_obj, "==> CHECK failed on service"
							      " : connection timeout <=\n\n",
							      "connect, timeout");
				}

				if (ret == -1) {
					switch ((ssl_err = SSL_get_error(http_arg_obj->req->ssl,
									 ret))) {
					case SSL_ERROR_WANT_READ:
						thread_add_read(thread_obj->master,
								http_check_thread,
								THREAD_ARG(thread_obj),
								thread_obj->u.fd, timeout);
						break;
					case SSL_ERROR_WANT_WRITE:
						thread_add_write(thread_obj->master,
								 http_check_thread,
								 THREAD_ARG(thread_obj),
								 thread_obj->u.fd, timeout);
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
				DBG("Remote Web server [%s:%d] connected.",
				    inet_ntop2(CHECKER_RIP(checker_obj)),
				    ntohs(addr_port));
				thread_add_write(thread_obj->master,
						 http_request_thread, checker_obj,
						 thread_obj->u.fd,
						 http_get_check->connection_to);
			} else {
				DBG(LOG_INFO, "Connection trouble to: [%s:%d]."
				    , inet_ntop2(CHECKER_RIP(checker_obj))
				    , ntohs(addr_port));
#ifdef _DEBUG_
				if (http_get_check->proto == PROTO_SSL)
					ssl_printerr(SSL_get_error
						     (req->ssl, ret));
#endif
				if ((http_get_check->proto == PROTO_SSL) &&
				    (svr_checker_up(checker_obj->id, checker_obj->rs))) {
					log_message(LOG_INFO, "SSL handshake/communication error"
							 " connecting to server"
							 " (openssl errno: %d) [%s:%d]."
						       , SSL_get_error (http_arg_obj->req->ssl, ret)
						       , inet_ntop2(CHECKER_RIP(checker_obj))
						       , ntohs(addr_port));
					smtp_alert(checker_obj->rs, NULL, NULL,
						   "DOWN",
						   "=> CHECK failed on service"
						   " : SSL connection error <=");
					update_svr_checker_state(DOWN, checker_obj->id
								 , checker_obj->vs
								 , checker_obj->rs);
				}

				return epilog(thread_obj, 1, 0, 0);
			}
		}
		break;
	}

	return 0;
}

int
http_connect_thread(thread * thread_obj)
{
	checker *checker_obj = THREAD_ARG(thread_obj);
	http_get_checker *http_get_check = CHECKER_ARG(checker_obj);
	http_arg *http_arg_obj = HTTP_ARG(http_get_check);
	uint16_t addr_port = get_service_port(checker_obj);
	url *fetched_url;
	enum connect_result status;
	int fd;

	/*
	 * Register a new checker thread & return
	 * if checker is disabled
	 */
	if (!CHECKER_ENABLED(checker_obj)) {
		thread_add_timer(thread_obj->master, http_connect_thread, checker_obj,
				 checker_obj->vs->delay_loop);
		return 0;
	}

	/* Find eventual url end */
	fetched_url = fetch_next_url(http_get_check);

	if (!fetched_url) {
		/* All the url have been successfully checked.
		 * Check completed.
		 * check if server is currently alive.
		 */
		if (!svr_checker_up(checker_obj->id, checker_obj->rs)) {
			log_message(LOG_INFO, "Remote Web server [%s:%d] succeed on service.",
			       inet_ntop2(CHECKER_RIP(checker_obj))
			       , ntohs(addr_port));
			smtp_alert(checker_obj->rs, NULL, NULL, "UP",
				   "=> CHECK succeed on service <=");
			update_svr_checker_state(UP, checker_obj->id
						   , checker_obj->vs
						   , checker_obj->rs);
		}
		http_arg_obj->req = NULL;
		return epilog(thread_obj, 1, 0, 0) + 1;
	}

	/* Create the socket */
	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		DBG("WEB connection fail to create socket.");
		return 0;
	}

	status = tcp_bind_connect(fd, CHECKER_RIP(checker_obj), addr_port
				  , http_get_check->bindto);

	/* handle tcp connection status & register check worker thread */
	tcp_connection_state(fd, status, thread_obj, http_check_thread,
			     http_get_check->connection_to);
	return 0;
}
