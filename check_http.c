/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        WEB CHECK. Common HTTP/SSL checker primitives.
 *
 * Version:     $Id: check_http.c,v 0.4.9a 2001/12/20 17:14:25 acassen Exp $
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
#include "memory.h"

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
int epilog(thread *thread, int metod, int t, int c)
{
  thread_arg *thread_arg = THREAD_ARG(thread);
  http_thread_arg *checker_arg;
  int delay = 0;
  REQ *req;
 
  checker_arg = THREAD_ARG_CHECKER_ARG(thread_arg);
  req = checker_arg->req;
 
  if (metod) {
    checker_arg->url_it   += t ? t : -checker_arg->url_it;
    checker_arg->retry_it += c ? c : -checker_arg->retry_it;
  }

  /* register next timer thread */
  switch (metod) {
    case 1:
      if (req)
        delay = thread_arg->vs->delay_loop;
      else
        delay = thread_arg->vs->delay_loop -
                thread_arg->svr->method->u.http_get->delay_before_retry;
      thread_add_timer(thread->master, http_connect_thread, thread_arg, delay);
      break; 
    case 2:
      delay = thread_arg->svr->method->u.http_get->delay_before_retry;
      thread_add_timer(thread->master, http_connect_thread, thread_arg, delay);
      break;
  }

  /* If req == NULL, fd is not created */
  if (req != NULL) {
    if (req->ssl)
      SSL_free(req->ssl);
    if (req->buffer)
      FREE(req->buffer);
    FREE(req);
    close(thread->u.fd);
  }

  return 0;
}

int timeout_epilog(thread *thread, char *smtp_msg, char *debug_msg)
{
  thread_arg *thread_arg;
  http_thread_arg *checker_arg;

  thread_arg  = THREAD_ARG(thread);
  checker_arg = THREAD_ARG_CHECKER_ARG(thread_arg);

  /*
   * The get retry implementation mean that we retry performing
   * a GET on the same url until the remote web server return 
   * html buffer. This is sometime needed with some applications
   * servers.
   */
  if (++checker_arg->retry_it <=
      thread_arg->svr->method->u.http_get->nb_get_retry) {

#ifdef _DEBUG_
    syslog(LOG_DEBUG, "Retry %s server [%s:%d] after %d retry.", debug_msg,
                      inet_ntoa(thread_arg->svr->addr_ip),
                      ntohs(thread_arg->svr->addr_port),
                      checker_arg->retry_it - 1);
#endif
    return epilog(thread,2,0,1);
  } else {
#ifdef _DEBUG_
    if (thread_arg->svr)
      syslog(LOG_DEBUG, "Timeout %s server [%s:%d].", debug_msg,
                          inet_ntoa(thread_arg->svr->addr_ip),
                          ntohs(thread_arg->svr->addr_port));
#endif
    /* check if server is currently alive */
    if (thread_arg->svr->alive) {
      smtp_alert(thread->master, thread_arg->root, thread_arg->svr, "DOWN", smtp_msg);
      perform_svr_state(DOWN, thread_arg->vs, thread_arg->svr);
    }

    return epilog(thread,1,0,0);
  }

  return 0;
}

/* HTML stream parser primitives */
/* simple function returning a pointer to the html buffer begin */
char *extract_html(char *buffer, int size_buffer)
{
  char *end = buffer+size_buffer;

  while ( buffer < end &&
          !(*buffer++ == '\n' &&
            (*buffer == '\n' || (*buffer ++ == '\r' && *buffer =='\n'))));

  if (*buffer == '\n') return buffer+1;
  return NULL;
}

/* return the url pointer of the current url iterator  */
urls *fetch_next_url(thread_arg *thread_arg)
{
  http_thread_arg *checker_arg;
  int i = 0;

  checker_arg = THREAD_ARG_CHECKER_ARG(thread_arg);

  /* fetch the next url */
  for (i=0; i<checker_arg->url_it; i++)
    thread_arg->svr->method->u.http_get->check_urls=(urls *)thread_arg->svr->method->u.http_get->check_urls->next;

  if (thread_arg->svr->method->u.http_get->check_urls != NULL)
    return thread_arg->svr->method->u.http_get->check_urls;

  return NULL;
}

/* Handle response */
int http_handle_response(thread *thread, unsigned char digest[16], int empty_buffer)
{
  thread_arg *thread_arg;
  http_thread_arg *checker_arg;
  REQ *req;
  int r, di = 0;
  unsigned char *digest_tmp;
  urls *fetched_url;
  urls *pointerurls;

  thread_arg  = THREAD_ARG(thread);
  checker_arg = THREAD_ARG_CHECKER_ARG(thread_arg);
  req         = checker_arg->req;

  if (empty_buffer) {
    return timeout_epilog(thread,
      "=> CHECK failed on service : empty buffer received <=\n\n",
      "Read, no data received from ");
  } else {
    /* Compute MD5SUM */
    digest_tmp = (char *)MALLOC(MD5_BUFFER_LENGTH+1);
    for (di=0; di < 16; di++)
      sprintf(digest_tmp+2*di, "%02x", digest[di]);

    pointerurls = thread_arg->svr->method->u.http_get->check_urls;
    fetched_url = fetch_next_url(thread_arg);
    thread_arg->svr->method->u.http_get->check_urls = pointerurls;

#ifdef _DEBUG_
    syslog(LOG_DEBUG, "MD5SUM to [%s:%d] url(%d) = [%s].",
                      inet_ntoa(thread_arg->svr->addr_ip),
                      ntohs(thread_arg->svr->addr_port),
                      checker_arg->url_it+1, digest_tmp);
#endif

    r = strcmp(fetched_url->digest, digest_tmp);
    FREE(digest_tmp);

    if (r) {
#ifdef _DEBUG_
      syslog(LOG_DEBUG, "MD5 digest error to [%s:%d] url(%d), expecting MD5SUM [%s].",
                        inet_ntoa(thread_arg->svr->addr_ip),
                        ntohs(thread_arg->svr->addr_port),
                        checker_arg->url_it+1, fetched_url->digest);
#endif

      /* check if server is currently alive */
      if (thread_arg->svr->alive) {
        smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                   "DOWN", "=> CHECK failed on service : MD5 digest mismatch <=\n\n");
        perform_svr_state(DOWN, thread_arg->vs, thread_arg->svr);
      }
      return epilog(thread,1,0,0);
    } else {
#ifdef _DEBUG_
      syslog(LOG_DEBUG, "MD5 digest success to [%s:%d] url(%d).",
                        inet_ntoa(thread_arg->svr->addr_ip),
                        ntohs(thread_arg->svr->addr_port),
                        checker_arg->url_it+1);
#endif
      return epilog(thread,2,1,0)+1;
    }
  }
  return epilog(thread,0,0,0)+1;
}

/* Asynchronous HTTP stream reader */
int http_read_thread(thread *thread)
{
  thread_arg *thread_arg;
  http_thread_arg *checker_arg;
  unsigned char digest[16];
  REQ *req;
  int r = 0;

  thread_arg  = THREAD_ARG(thread);
  checker_arg = THREAD_ARG_CHECKER_ARG(thread_arg);
  req         = checker_arg->req;

  /* Handle read timeout */
  if (thread->type == THREAD_READ_TIMEOUT) {
    return timeout_epilog(thread,
      "=> HTTP CHECK failed on service : recevice data <=\n\n",
      "HTTP read");
  }

  /* read the HTTP stream */
  r = read(thread->u.fd, req->buffer+req->len, MAX_BUFFER_LENGTH-req->len);

  if (r == -1 || r == 0) { /* -1:error , 0:EOF */

    /* All the HTTP stream has been parsed */
    MD5_Final(digest, &req->context);

    if (r == -1) {
      /* We have encourred a real read error */
      if (thread_arg->svr->alive) {
        smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                   "DOWN", "=> HTTP CHECK failed on service : cannot receive data <=\n\n");
        perform_svr_state(DOWN, thread_arg->vs, thread_arg->svr);
      }
      return epilog(thread,1,0,0);
    }

    /* Handle response stream */
    http_handle_response(thread, digest, (!req->extracted)?1:0);

  } else {

    req->len += r;
    if (!req->extracted) {
      if ((req->extracted = extract_html(req->buffer, req->len))) {
        r = req->len - (req->extracted-req->buffer);
        if (r) {
          memcpy(req->buffer, req->extracted, r);
          MD5_Update(&req->context, req->buffer, r);
          r=0;
        }
        req->len = r;
      } else {
        /* minimize buffer using no 2*CR/LF found yet */
        if (req->len > 3) {
          memcpy(req->buffer, req->buffer + req->len - 3, 3);
          req->len = 3;
        }
      }
    } else {
      if (req->len) {
        MD5_Update(&req->context, req->buffer, req->len);
        req->len = 0;
      }
    }

    /*
     * Register next http stream reader.
     * Register itself to not perturbe global I/O multiplexer.
     */
    thread_add_read(thread->master, http_read_thread, thread_arg, thread->u.fd,
                    thread_arg->svr->method->connection_to);
  }

  return 0;
}

/*
 * Read get result from the remote web server.
 * Apply trigger check to this result.
 */
int http_response_thread(thread *thread)
{
  thread_arg *thread_arg;
  http_thread_arg *checker_arg;
  REQ *req;

  thread_arg  = THREAD_ARG(thread);
  checker_arg = THREAD_ARG_CHECKER_ARG(thread_arg);
  req         = checker_arg->req;

  /* Handle read timeout */
  if (thread->type == THREAD_READ_TIMEOUT) {
    return timeout_epilog(thread,
      "=> CHECK failed on service : recevice data <=\n\n",
      "WEB read");
  }

  /* Allocate & clean the get buffer */
  req->buffer    = (char *)MALLOC(MAX_BUFFER_LENGTH);
  req->extracted = NULL;
  req->len       = 0;
  req->error     = 0;
  MD5_Init(&req->context);

  /* Register asynchronous http/ssl read thread */
  if (thread_arg->svr->method->type == SSL_GET_ID)
    thread_add_read(thread->master, ssl_read_thread, thread_arg, thread->u.fd,
                    thread_arg->svr->method->connection_to);
  else
    thread_add_read(thread->master, http_read_thread, thread_arg, thread->u.fd,
                    thread_arg->svr->method->connection_to);
  return 0;
}

/* remote Web server is connected, send it the get url query.  */
int http_request_thread(thread *thread)
{
  thread_arg *thread_arg;
  http_thread_arg *checker_arg;
  char    *str_request;
  urls    *fetched_url;
  urls    *pointerurls;
  REQ     *req;
  int ret = 0;

  thread_arg  = THREAD_ARG(thread);
  checker_arg = THREAD_ARG_CHECKER_ARG(thread_arg);
  req         = checker_arg->req;

  /* Handle read timeout */
  if(thread->type == THREAD_WRITE_TIMEOUT) {
    return timeout_epilog(thread,
      "=> CHECK failed on service : read timeout <=\n\n",
      "Web read, timeout");
  }

  /* Allocate & clean the GET string */
  str_request = (char *)MALLOC(GET_REQUEST_BUFFER_LENGTH);

  pointerurls = thread_arg->svr->method->u.http_get->check_urls;
  fetched_url = fetch_next_url(thread_arg);
  thread_arg->svr->method->u.http_get->check_urls = pointerurls;

  snprintf(str_request, GET_REQUEST_BUFFER_LENGTH
                      , REQUEST_TEMPLATE, fetched_url->url
                      , inet_ntoa(thread_arg->svr->addr_ip)
                      , ntohs(thread_arg->svr->addr_port));

#ifdef _DEBUG_
  syslog(LOG_DEBUG, "Processing url(%d) of [%s:%d].",
                    checker_arg->url_it+1,
                    inet_ntoa(thread_arg->svr->addr_ip),
                    ntohs(thread_arg->svr->addr_port));
#endif

  /* Send the GET request to remote Web server */
  if (thread_arg->svr->method->type == SSL_GET_ID)
    ret = ssl_send_request(req->ssl, str_request, strlen(str_request));
  else
    ret = (send(thread->u.fd, str_request, strlen(str_request), 0) != -1)?1:0;

  FREE(str_request);

  if (!ret) {
    syslog(LOG_WARNING, "Cannot send get request to [%s:%d].",
                        inet_ntoa(thread_arg->svr->addr_ip),
                        ntohs(thread_arg->svr->addr_port));

    /* check if server is currently alive */
    if (thread_arg->svr->alive) {
      smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                 "DOWN", "=> CHECK failed on service : cannot send data <=\n\n");
      perform_svr_state(DOWN, thread_arg->vs, thread_arg->svr);
    }
    return epilog(thread,1,0,0);
  }

  /* Register read timeouted thread */
  thread_add_read(thread->master, http_response_thread, thread_arg, thread->u.fd,
                  thread_arg->svr->method->connection_to);
  return 1;
}

/* WEB checkers threads */
int http_check_thread(thread *thread)
{
  thread_arg *thread_arg;
  http_thread_arg *checker_arg;
  REQ *req;
  int ret = 1;

  int status;

  thread_arg  = THREAD_ARG(thread);
  checker_arg = THREAD_ARG_CHECKER_ARG(thread_arg);
  req         = checker_arg->req;

  status = tcp_socket_state(thread->u.fd, thread, http_check_thread);

  switch (status) {
    case connect_error:
#ifdef _DEBUG_
      syslog(LOG_DEBUG,"Error connecting server [%s:%d].",
                       inet_ntoa(thread_arg->svr->addr_ip),
                       ntohs(thread_arg->svr->addr_port));
#endif
      /* check if server is currently alive */
      if (thread_arg->svr->alive) {
        smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                   "DOWN", "=> CHECK failed on service : connection error <=\n\n");
        perform_svr_state(DOWN, thread_arg->vs, thread_arg->svr);
      }
      return epilog(thread,1,0,0);
      break;

    case connect_timeout:
      return timeout_epilog(thread,
        "==> CHECK failed on service : connection timeout <=\n\n",
        "connect, timeout");
      break;

    case connect_success: {
      if (thread_arg->svr->method->type == SSL_GET_ID)
        ret = ssl_connect(thread);
        
      if (ret) {
        /* Remote WEB server is connected.
         * Register the next step thread ssl_request_thread.
         */
#ifdef _DEBUG_
        syslog(LOG_DEBUG, "Remote Web server [%s:%d] connected.",
                          inet_ntoa(thread_arg->svr->addr_ip),
                          ntohs(thread_arg->svr->addr_port));
#endif
        thread_add_write(thread->master, http_request_thread, thread_arg, thread->u.fd,
                         thread_arg->svr->method->connection_to);
      } else {
#ifdef _DEBUG_
        syslog(LOG_DEBUG, "Connection problem host: [%s:%d].",
                          inet_ntoa(thread_arg->svr->addr_ip),
                          ntohs(thread_arg->svr->addr_port));
        if (thread_arg->svr->method->type == SSL_GET_ID)
          ssl_printerr(SSL_get_error(req->ssl, ret));
#endif
        return epilog(thread,1,0,0);
      }
    }
    break;
  }

  return 0;
}

int http_connect_thread(thread *thread)
{
  thread_arg *thread_arg;
  http_thread_arg *checker_arg;
  urls *fetched_url;
  urls *pointerurls;
  enum connect_result status;
  int fd;

  thread_arg  = THREAD_ARG(thread);
  checker_arg = THREAD_ARG_CHECKER_ARG(thread_arg);

  /* Find eventual url end */
  pointerurls = thread_arg->svr->method->u.http_get->check_urls;
  fetched_url = fetch_next_url(thread_arg);
  thread_arg->svr->method->u.http_get->check_urls = pointerurls;
  if (fetched_url == NULL) {
    /* All the url have been successfully checked.
     * Check completed.
     * check if server is currently alive.
     */
    if (!thread_arg->svr->alive) {
      smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                 "UP", "=> CHECK succeed on service <=\n\n");
      perform_svr_state(UP, thread_arg->vs, thread_arg->svr);
#ifdef _DEBUG_
      syslog(LOG_DEBUG, "Remote Web server [%s:%d] succeed on service."
                      , inet_ntoa(thread_arg->svr->addr_ip)
                      , ntohs(thread_arg->svr->addr_port));
#endif
    }
    checker_arg->req = NULL;
    return epilog(thread,1,0,0)+1;
  }

  /* Allocate & clean request struct */
  checker_arg->req = (REQ *)MALLOC(sizeof(REQ));

  if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
#ifdef _DEBUG_
    syslog(LOG_DEBUG, "WEB connection fail to create socket.");
#endif
    return 0;
  }

  status = tcp_connect(fd, thread_arg->svr->addr_ip.s_addr, thread_arg->svr->addr_port);

  /* handle tcp connection status & register check worker thread */
  tcp_connection_state(fd, status, thread, http_check_thread);

  return 0;
}
