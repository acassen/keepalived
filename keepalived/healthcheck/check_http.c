/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        WEB CHECK. Common HTTP/SSL checker primitives.
 *
 * Version:     $Id: check_http.c,v 0.6.9 2002/07/31 01:33:12 acassen Exp $
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
 */

#include <openssl/err.h>
#include "check_http.h"
#include "check_ssl.h"
#include "check_api.h"
#include "memory.h"
#include "parser.h"
#include "utils.h"

int http_connect_thread(thread *);

/* Configuration stream handling */
void
free_url(void *data)
{
	url *url = data;
	FREE(url->path);
	FREE(url->digest);
	FREE(url);
}

void
dump_url(void *data)
{
	url *url = data;
	syslog(LOG_INFO, "   Checked url = %s, digest = %s", url->path,
	       url->digest);
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
		syslog(LOG_INFO, "   Keepalive method = HTTP_GET");
	else
		syslog(LOG_INFO, "   Keepalive method = SSL_GET");
	if (http_get_chk->connection_port)
		syslog(LOG_INFO, "   Connection port = %d",
		       ntohs(http_get_chk->connection_port));
	syslog(LOG_INFO, "   Connection timeout = %d",
	       http_get_chk->connection_to);
	syslog(LOG_INFO, "   Nb get retry = %d", http_get_chk->nb_get_retry);
	syslog(LOG_INFO, "   Delay before retry = %d",
	       http_get_chk->delay_before_retry);
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
connect_to_handler(vector strvec)
{
	http_get_checker *http_get_chk = CHECKER_GET();
	http_get_chk->connection_to = CHECKER_VALUE_INT(strvec);
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
	http_get_chk->delay_before_retry = CHECKER_VALUE_INT(strvec);
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
	url *url = LIST_TAIL_DATA(http_get_chk->url);

	url->path = CHECKER_VALUE_STRING(strvec);
}

void
digest_handler(vector strvec)
{
	http_get_checker *http_get_chk = CHECKER_GET();
	url *url = LIST_TAIL_DATA(http_get_chk->url);

	url->digest = CHECKER_VALUE_STRING(strvec);
}

void
install_http_check_keyword(void)
{
	install_keyword("HTTP_GET", &http_get_handler);
	install_sublevel();
	install_keyword("connect_port", &connect_p_handler);
	install_keyword("connect_timeout", &connect_to_handler);
	install_keyword("nb_get_retry", &nb_get_retry_handler);
	install_keyword("delay_before_retry", &delay_before_retry_handler);
	install_keyword("url", &url_handler);
	install_sublevel();
	install_keyword("path", &path_handler);
	install_keyword("digest", &digest_handler);
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
	install_keyword("connect_timeout", &connect_to_handler);
	install_keyword("nb_get_retry", &nb_get_retry_handler);
	install_keyword("delay_before_retry", &delay_before_retry_handler);
	install_keyword("url", &url_handler);
	install_sublevel();
	install_keyword("path", &path_handler);
	install_keyword("digest", &digest_handler);
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
get_service_port(checker * checker)
{
	http_get_checker *http_get_check = CHECKER_ARG(checker);
	uint16_t addr_port;

	/*
	 *  Set the remote connection port.
	 *  If a specific checker port is specified, we used this.
	 *  If we are balancing all services (host rather than service),
	 *  then assume we want to use default ports for HTTP or HTTPS.
	 *  Known as 'Layer3 stickyness'.
	 */
	addr_port = CHECKER_RPORT(checker);
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
epilog(thread * thread, int method, int t, int c)
{
	checker *checker = THREAD_ARG(thread);
	http_get_checker *http_get_check = CHECKER_ARG(checker);
	http_arg *http_arg = HTTP_ARG(http_get_check);
	REQ *req = HTTP_REQ(http_arg);
	int delay = 0;

	if (method) {
		http_arg->url_it += t ? t : -http_arg->url_it;
		http_arg->retry_it += c ? c : -http_arg->retry_it;
	}

	/* register next timer thread */
	switch (method) {
	case 1:
		if (req)
			delay = checker->vs->delay_loop;
		else
			delay =
			    checker->vs->delay_loop -
			    http_get_check->delay_before_retry;
		break;
	case 2:
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
		close(thread->u.fd);
	}

	/* Register next checker thread */
	thread_add_timer(thread->master, http_connect_thread, checker, delay);
	return 0;
}

int
timeout_epilog(thread * thread, char *smtp_msg, char *debug_msg)
{
	checker *checker = THREAD_ARG(thread);
	http_get_checker *http_get_check = CHECKER_ARG(checker);
	http_arg *http_arg = HTTP_ARG(http_get_check);
#ifdef _DEBUG_
	uint16_t addr_port = get_service_port(checker);
#endif

	/*
	 * The get retry implementation mean that we retry performing
	 * a GET on the same url until the remote web server return 
	 * html buffer. This is sometime needed with some applications
	 * servers.
	 */
	if (++http_arg->retry_it <= http_get_check->nb_get_retry) {
		DBG("Retry %s server [%s:%d] after %d retry.",
		    debug_msg, inet_ntop2(CHECKER_RIP(checker)),
		    ntohs(addr_port), http_arg->retry_it - 1);
		return epilog(thread, 2, 0, 1);

	} else {
		if (checker->rs)
			DBG("Timeout %s server [%s:%d].",
			    debug_msg, inet_ntop2(CHECKER_RIP(checker)),
			    ntohs(addr_port));
		/* check if server is currently alive */
		if (ISALIVE(checker->rs)) {
			smtp_alert(thread->master, checker->rs, NULL, "DOWN",
				   smtp_msg);
			perform_svr_state(DOWN, checker->vs, checker->rs);
		}

		return epilog(thread, 1, 0, 0);
	}

	return 0;
}

/* HTML stream parser primitives */
/* simple function returning a pointer to the html buffer begin */
char *
extract_html(char *buffer, int size_buffer)
{
	char *end = buffer + size_buffer;

	while (buffer < end &&
	       !(*buffer++ == '\n' &&
		 (*buffer == '\n' || (*buffer++ == '\r' && *buffer == '\n')))) ;

	if (*buffer == '\n')
		return buffer + 1;
	return NULL;
}

/* return the url pointer of the current url iterator  */
url *
fetch_next_url(http_get_checker * http_get_check)
{
	http_arg *http_arg = HTTP_ARG(http_get_check);

	return list_element(http_get_check->url, http_arg->url_it);
}

/* Handle response */
int
http_handle_response(thread * thread, unsigned char digest[16]
		     , int empty_buffer)
{
	checker *checker = THREAD_ARG(thread);
	http_get_checker *http_get_check = CHECKER_ARG(checker);
#ifdef _DEBUG_
	uint16_t addr_port = get_service_port(checker);
	http_arg *http_arg = HTTP_ARG(http_get_check);
#endif
	int r, di = 0;
	unsigned char *digest_tmp;
	url *fetched_url;

	if (empty_buffer) {
		return timeout_epilog(thread, "=> CHECK failed on service"
				      " : empty buffer received <=\n\n",
				      "Read, no data received from ");
	} else {
		/* Compute MD5SUM */
		digest_tmp = (char *) MALLOC(MD5_BUFFER_LENGTH + 1);
		for (di = 0; di < 16; di++)
			sprintf(digest_tmp + 2 * di, "%02x", digest[di]);

		fetched_url = fetch_next_url(http_get_check);

		DBG("MD5SUM to [%s:%d] url(%d) = [%s].",
		    inet_ntop2(CHECKER_RIP(checker)), ntohs(addr_port),
		    http_arg->url_it + 1, digest_tmp);

		r = strcmp(fetched_url->digest, digest_tmp);
		FREE(digest_tmp);

		if (r) {
			DBG("MD5 digest error to [%s:%d] url(%d)"
			    ", expecting MD5SUM [%s].",
			    inet_ntop2(CHECKER_RIP(checker)),
			    ntohs(addr_port), http_arg->url_it + 1,
			    fetched_url->digest);

			/* check if server is currently alive */
			if (ISALIVE(checker->rs)) {
				smtp_alert(thread->master, checker->rs, NULL,
					   "DOWN",
					   "=> CHECK failed on service"
					   " : MD5 digest mismatch <=\n\n");
				perform_svr_state(DOWN, checker->vs,
						  checker->rs);
			}
			return epilog(thread, 1, 0, 0);
		} else {
			DBG("MD5 digest success to [%s:%d] url(%d).",
			    inet_ntop2(CHECKER_RIP(checker)), ntohs(addr_port),
			    http_arg->url_it + 1);
			return epilog(thread, 1, 1, 0) + 1;
		}
	}
	return epilog(thread, 0, 0, 0) + 1;
}

/* Asynchronous HTTP stream reader */
int
http_read_thread(thread * thread)
{
	checker *checker = THREAD_ARG(thread);
	http_get_checker *http_get_check = CHECKER_ARG(checker);
	http_arg *http_arg = HTTP_ARG(http_get_check);
	REQ *req = HTTP_REQ(http_arg);
#ifdef _DEBUG_
	uint16_t addr_port = get_service_port(checker);
#endif
	unsigned char digest[16];
	int r = 0;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT)
		return timeout_epilog(thread, "=> HTTP CHECK failed on service"
				      " : recevice data <=\n\n", "HTTP read");

	/* read the HTTP stream */
	r = read(thread->u.fd, req->buffer + req->len,
		 MAX_BUFFER_LENGTH - req->len);

	if (r == -1 || r == 0) {	/* -1:error , 0:EOF */

		/* All the HTTP stream has been parsed */
		MD5_Final(digest, &req->context);

		if (r == -1) {
			/* We have encourred a real read error */
			DBG("Read error with server [%s:%d]: %s",
			    inet_ntop2(CHECKER_RIP(checker)), ntohs(addr_port),
			    strerror(errno));
			if (ISALIVE(checker->rs)) {
				smtp_alert(thread->master, checker->rs, NULL,
					   "DOWN",
					   "=> HTTP CHECK failed on service"
					   " : cannot receive data <=\n\n");
				perform_svr_state(DOWN, checker->vs,
						  checker->rs);
			}
			return epilog(thread, 1, 0, 0);
		}

		/* Handle response stream */
		http_handle_response(thread, digest, (!req->extracted) ? 1 : 0);

	} else {

		req->len += r;
		if (!req->extracted) {
			if ((req->extracted =
			     extract_html(req->buffer, req->len))) {
				r = req->len - (req->extracted - req->buffer);
				if (r) {
					memcpy(req->buffer, req->extracted, r);
					MD5_Update(&req->context, req->buffer,
						   r);
					r = 0;
				}
				req->len = r;
			} else {
				/* minimize buffer using no 2*CR/LF found yet */
				if (req->len > 3) {
					memcpy(req->buffer,
					       req->buffer + req->len - 3, 3);
					req->len = 3;
				}
			}
		} else {
			if (req->len) {
				MD5_Update(&req->context, req->buffer,
					   req->len);
				req->len = 0;
			}
		}

		/*
		 * Register next http stream reader.
		 * Register itself to not perturbe global I/O multiplexer.
		 */
		thread_add_read(thread->master, http_read_thread, checker,
				thread->u.fd, http_get_check->connection_to);
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
	checker *checker = THREAD_ARG(thread);
	http_get_checker *http_get_check = CHECKER_ARG(checker);
	http_arg *http_arg = HTTP_ARG(http_get_check);
	REQ *req = HTTP_REQ(http_arg);

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT)
		return timeout_epilog(thread, "=> CHECK failed on service"
				      " : recevice data <=\n\n", "WEB read");

	/* Allocate & clean the get buffer */
	req->buffer = (char *) MALLOC(MAX_BUFFER_LENGTH);
	req->extracted = NULL;
	req->len = 0;
	req->error = 0;
	MD5_Init(&req->context);

	/* Register asynchronous http/ssl read thread */
	if (http_get_check->proto == PROTO_SSL)
		thread_add_read(thread->master, ssl_read_thread, checker,
				thread->u.fd, http_get_check->connection_to);
	else
		thread_add_read(thread->master, http_read_thread, checker,
				thread->u.fd, http_get_check->connection_to);
	return 0;
}

/* remote Web server is connected, send it the get url query.  */
int
http_request_thread(thread * thread)
{
	checker *checker = THREAD_ARG(thread);
	http_get_checker *http_get_check = CHECKER_ARG(checker);
	http_arg *http_arg = HTTP_ARG(http_get_check);
	REQ *req = HTTP_REQ(http_arg);
	uint16_t addr_port = get_service_port(checker);
	char *vhost = CHECKER_VHOST(checker);
	char *str_request;
	url *fetched_url;
	int ret = 0;

	/* Handle read timeout */
	if (thread->type == THREAD_WRITE_TIMEOUT)
		return timeout_epilog(thread, "=> CHECK failed on service"
				      " : read timeout <=\n\n",
				      "Web read, timeout");

	/* Allocate & clean the GET string */
	str_request = (char *) MALLOC(GET_REQUEST_BUFFER_LENGTH);

	fetched_url = fetch_next_url(http_get_check);
	snprintf(str_request, GET_REQUEST_BUFFER_LENGTH, REQUEST_TEMPLATE,
		 fetched_url->path,
		 (vhost) ? vhost : inet_ntop2(CHECKER_RIP(checker))
		 , ntohs(addr_port));
	DBG("Processing url(%d) of [%s:%d].",
	    http_arg->url_it + 1, inet_ntop2(CHECKER_RIP(checker)),
	    ntohs(addr_port));

	/* Send the GET request to remote Web server */
	if (http_get_check->proto == PROTO_SSL)
		ret =
		    ssl_send_request(req->ssl, str_request,
				     strlen(str_request));
	else
		ret =
		    (send(thread->u.fd, str_request, strlen(str_request), 0) !=
		     -1) ? 1 : 0;

	FREE(str_request);

	if (!ret) {
		syslog(LOG_INFO, "Cannot send get request to [%s:%d].",
		       inet_ntop2(CHECKER_RIP(checker))
		       , ntohs(addr_port));

		/* check if server is currently alive */
		if (ISALIVE(checker->rs)) {
			smtp_alert(thread->master, checker->rs, NULL, "DOWN",
				   "=> CHECK failed on service"
				   " : cannot send data <=\n\n");
			perform_svr_state(DOWN, checker->vs, checker->rs);
		}
		return epilog(thread, 1, 0, 0);
	}

	/* Register read timeouted thread */
	thread_add_read(thread->master, http_response_thread, checker,
			thread->u.fd, http_get_check->connection_to);
	return 1;
}

/* WEB checkers threads */
int
http_check_thread(thread * thread)
{
	checker *checker = THREAD_ARG(thread);
	http_get_checker *http_get_check = CHECKER_ARG(checker);
	uint16_t addr_port = get_service_port(checker);
#ifdef _DEBUG_
	http_arg *http_arg = HTTP_ARG(http_get_check);
	REQ *req = HTTP_REQ(http_arg);
#endif
	int ret = 1;
	int status;

	status = tcp_socket_state(thread->u.fd, thread, CHECKER_RIP(checker)
				  , addr_port, http_check_thread);
	switch (status) {
	case connect_error:
		DBG("Error connecting server [%s:%d].",
		    inet_ntop2(CHECKER_RIP(checker)), ntohs(addr_port));
		/* check if server is currently alive */
		if (ISALIVE(checker->rs)) {
			smtp_alert(thread->master, checker->rs, NULL, "DOWN",
				   "=> CHECK failed on service"
				   " : connection error <=\n\n");
			perform_svr_state(DOWN, checker->vs, checker->rs);
		}
		return epilog(thread, 1, 0, 0);
		break;

	case connect_timeout:
		return timeout_epilog(thread, "==> CHECK failed on service"
				      " : connection timeout <=\n\n",
				      "connect, timeout");
		break;

	case connect_success:{
			if (http_get_check->proto == PROTO_SSL)
				ret = ssl_connect(thread);

			if (ret) {
				/* Remote WEB server is connected.
				 * Register the next step thread ssl_request_thread.
				 */
				DBG("Remote Web server [%s:%d] connected.",
				    inet_ntop2(CHECKER_RIP(checker)),
				    ntohs(addr_port));
				thread_add_write(thread->master,
						 http_request_thread, checker,
						 thread->u.fd,
						 http_get_check->connection_to);
			} else {
				DBG("Connection trouble to: [%s:%d].",
				    inet_ntop2(CHECKER_RIP(checker)),
				    ntohs(addr_port));
#ifdef _DEBUG_
				if (http_get_check->proto == PROTO_SSL)
					ssl_printerr(SSL_get_error
						     (req->ssl, ret));
#endif
				return epilog(thread, 1, 0, 0);
			}
		}
		break;
	}

	return 0;
}

int
http_connect_thread(thread * thread)
{
	checker *checker = THREAD_ARG(thread);
	http_get_checker *http_get_check = CHECKER_ARG(checker);
	http_arg *http_arg = HTTP_ARG(http_get_check);
	uint16_t addr_port = get_service_port(checker);
	url *fetched_url;
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

	/* Find eventual url end */
	fetched_url = fetch_next_url(http_get_check);

	if (!fetched_url) {
		/* All the url have been successfully checked.
		 * Check completed.
		 * check if server is currently alive.
		 */
		if (!ISALIVE(checker->rs)) {
			smtp_alert(thread->master, checker->rs, NULL, "UP",
				   "=> CHECK succeed on service <=\n\n");
			perform_svr_state(UP, checker->vs, checker->rs);
			DBG("Remote Web server [%s:%d] succeed on service.",
			    inet_ntop2(CHECKER_RIP(checker)),
			    ntohs(addr_port));
		}
		http_arg->req = NULL;
		return epilog(thread, 1, 0, 0) + 1;
	}

	/* Allocate & clean request struct */
	http_arg->req = (REQ *) MALLOC(sizeof (REQ));

	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		DBG("WEB connection fail to create socket.");
		return 0;
	}

	status = tcp_connect(fd, CHECKER_RIP(checker), addr_port);

	/* handle tcp connection status & register check worker thread */
	tcp_connection_state(fd, status, thread, http_check_thread,
			     http_get_check->connection_to);
	return 0;
}
