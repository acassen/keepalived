/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        HTTP GET CHECK. Perform an http get query to a specified
 *              url, compute a MD5 over this result and match it to the
 *              expected value.
 *
 * Version:     $Id: check_http.c,v 0.3.8 2001/11/04 21:41:32 acassen Exp $
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
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

#include "check_http.h"

/* simple function returning a pointer to the html buffer begin */
char *extract_html(char *buffer, int size_buffer)
{
  char *end=buffer+size_buffer;

  while ( buffer < end &&
          !(*buffer++ == '\n' &&
            (*buffer == '\n' || (*buffer ++ == '\r' && *buffer =='\n'))));

  if (*buffer == '\n') return buffer+1;
  return NULL;
}

/* return the url pointer of the current url iterator  */
urls *fetch_next_url(struct thread_arg *thread_arg)
{
  struct http_thread_arg *checker_arg;
  int i = 0;

  checker_arg = THREAD_ARG_CHECKER_ARG(thread_arg);

  /* fetch the next url */
  for (i=0; i<checker_arg->url_it; i++)
    thread_arg->svr->method->http_get->check_urls=(urls *) thread_arg->svr->method->http_get->check_urls->next;

  if (thread_arg->svr->method->http_get->check_urls != NULL)
    return thread_arg->svr->method->http_get->check_urls;

  return NULL;
}

/* read http get result from the remote http server. Apply trigger check to this result */
int http_response_thread(struct thread *thread)
{
  struct thread_arg *thread_arg;
  struct http_thread_arg *checker_arg;
  long total_length = 0;
  int rcv_buffer_size = 0;
  int di = 0;
  MD5_CTX context;
  unsigned char digest[16];
  char *buffer;
  char *digest_tmp;
  char *buffer_html;
  char *buffer_tmp;
  urls *fetched_url;
  urls *pointerurls;

  thread_arg = THREAD_ARG(thread);
  checker_arg = THREAD_ARG_CHECKER_ARG(thread_arg);

  /* Handle read timeout */
  if(thread->type == THREAD_READ_TIMEOUT) {
#ifdef DEBUG
    if (thread_arg->svr)
      syslog(LOG_DEBUG, "HTTP read timeout to [%s:%d].",
                          inet_ntoa(thread_arg->svr->addr_ip),
                          ntohs(thread_arg->svr->addr_port));
#endif
    /* check if server is currently alive */
    if (thread_arg->svr->alive) {
      smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                 "DOWN", "=> HTTP CHECK failed on service : cannot receive data <=\n\n");
      perform_svr_state(DOWN, thread_arg->vs, thread_arg->svr);
    }

    /* reset iterator counters */
    memset(thread_arg->checker_arg, 0, sizeof(struct http_thread_arg));

    /* register next timer thread */
    thread_add_timer(thread->master, http_connect_thread, thread_arg, 
                     thread_arg->vs->delay_loop);

    close(thread->u.fd);
    return 0;
  }

  /* Allocate the get buffers */
  buffer = (char *)malloc(MAX_BUFFER_LENGTH);
  buffer_tmp = (char *)malloc(GET_BUFFER_LENGTH);

  /* Cleanup the room */
  memset(buffer, 0, MAX_BUFFER_LENGTH);
  memset(buffer_tmp, 0, GET_BUFFER_LENGTH);

  /* Read the fd until remote sever stop sending data.
     -> FIXME : need to register a new read thread while receiving data */
  while ((rcv_buffer_size = read(thread->u.fd, buffer_tmp, GET_BUFFER_LENGTH)) != 0) {
    if (rcv_buffer_size == -1) {
      if (errno == EAGAIN) goto end;
      free(buffer);
      free(buffer_tmp);
      close(thread->u.fd);

      /* check if server is currently alive */
      if (thread_arg->svr->alive) {
        smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                   "DOWN", "=> HTTP CHECK failed on service : cannot receive data <=\n\n");
        perform_svr_state(DOWN, thread_arg->vs, thread_arg->svr);
      }

      /* reset iterator counters */
      memset(thread_arg->checker_arg, 0, sizeof(struct http_thread_arg));

      /* register next timer thread */
      thread_add_timer(thread->master, http_connect_thread, thread_arg, 
                       thread_arg->vs->delay_loop);

      return 0;
    }

    /* received data overflow buffer size ? */
    if (total_length >= MAX_BUFFER_LENGTH) {
      syslog(LOG_INFO, "Received buffer from [%s:%d] overflow our get buffer size.",
                       inet_ntoa(thread_arg->svr->addr_ip),
                       ntohs(thread_arg->svr->addr_port));
      free(buffer);
      free(buffer_tmp);
      close(thread->u.fd);

      /* check if server is currently alive */
      if (thread_arg->svr->alive) {
        smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                   "DOWN", "=> HTTP CHECK failed on service : received data overflow <=\n\n");
        perform_svr_state(DOWN, thread_arg->vs, thread_arg->svr);
      }

      /* reset iterator counters */
      memset(thread_arg->checker_arg, 0, sizeof(struct http_thread_arg));

      /* register next timer thread */
      thread_add_timer(thread->master, http_connect_thread, thread_arg, 
                       thread_arg->vs->delay_loop);

      return 0;
    } else {
      memcpy(buffer+total_length, buffer_tmp, rcv_buffer_size);
      memset(buffer_tmp, 0, GET_BUFFER_LENGTH);
      total_length += rcv_buffer_size;
      if (rcv_buffer_size < GET_BUFFER_LENGTH) goto end;
    }
  }

end:

  buffer_html = extract_html(buffer, total_length);

//print_buffer(total_length - (buffer_html - buffer),buffer_html);

  if ((total_length == 0) || ((total_length-(buffer_html-buffer)) == 0)) {
#ifdef DEBUG
    syslog(LOG_DEBUG, "No html data received from remote server [%s:%d].",
                      inet_ntoa(thread_arg->svr->addr_ip),
                      ntohs(thread_arg->svr->addr_port));
#endif

    checker_arg->retry_it++;

    /* The get retry implementation mean that we retry performing
     * a GET on the same url until the remote web server return 
     * html buffer. This is sometime needed with some applications
     * servers.
     */
    if (checker_arg->retry_it > 
        thread_arg->svr->method->http_get->nb_get_retry) {

#ifdef DEBUG
      syslog(LOG_DEBUG, "Empty buffer returned from [%s:%d] after %d retry.",
                        inet_ntoa(thread_arg->svr->addr_ip),
                        ntohs(thread_arg->svr->addr_port),
                        --checker_arg->retry_it);
#endif

      /* check if server is currently alive */
      if (thread_arg->svr->alive) {
        smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                   "DOWN", "=> HTTP CHECK failed on service : empty buffer received <=\n\n");
        perform_svr_state(DOWN, thread_arg->vs, thread_arg->svr);
      }

      /* reset iterator counters */
      memset(thread_arg->checker_arg, 0, sizeof(struct http_thread_arg));

      /* register next timer thread */
      thread_add_timer(thread->master, http_connect_thread, thread_arg, 
                       thread_arg->vs->delay_loop);

    } else {
      thread_add_timer(thread->master, http_connect_thread, thread_arg, 
                       thread_arg->svr->method->http_get->delay_before_retry);
    }
  } else {

    /* Compute MD5SUM */
    digest_tmp = (char *)malloc(2*sizeof(digest));
    memset(digest_tmp, 0, 2*sizeof(digest));
    memset(digest, 0, sizeof(digest));
    MD5Init(&context);
    MD5Update(&context, buffer_html, total_length-(buffer_html-buffer));
    MD5Final(digest, &context);

    for (di=0; di < 16; ++di)
      sprintf(digest_tmp+2*di, "%02x", digest[di]);

    pointerurls = thread_arg->svr->method->http_get->check_urls;
    fetched_url = fetch_next_url(thread_arg);
    thread_arg->svr->method->http_get->check_urls = pointerurls;

#ifdef DEBUG
    syslog(LOG_DEBUG, "MD5SUM to [%s:%d] url(%d) = [%s].",
                      inet_ntoa(thread_arg->svr->addr_ip),
                      ntohs(thread_arg->svr->addr_port),
                      checker_arg->url_it+1, digest_tmp);
#endif

    if (strcmp(fetched_url->digest, digest_tmp) !=  0) {

#ifdef DEBUG
      syslog(LOG_DEBUG, "MD5 digest error to [%s:%d] url(%d), expecting MD5SUM [%s].",
                        inet_ntoa(thread_arg->svr->addr_ip),
                        ntohs(thread_arg->svr->addr_port),
                        checker_arg->url_it+1, fetched_url->digest);
#endif


      /* check if server is currently alive */
      if (thread_arg->svr->alive) {
        smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                   "DOWN", "=> HTTP CHECK failed on service : MD5 digest mismatch <=\n\n");
        perform_svr_state(DOWN, thread_arg->vs, thread_arg->svr);
      }

      /* reset iterator counters */
      memset(thread_arg->checker_arg, 0, sizeof(struct http_thread_arg));

      /* register next timer thread */
      thread_add_timer(thread->master, http_connect_thread, thread_arg, 
                       thread_arg->vs->delay_loop);

      /* free temporary buffer */
      free(digest_tmp);

    } else {

#ifdef DEBUG
      syslog(LOG_DEBUG, "MD5 digest success to [%s:%d] url(%d), expected MD5SUM [%s] match.",
                        inet_ntoa(thread_arg->svr->addr_ip),
                        ntohs(thread_arg->svr->addr_port),
                        checker_arg->url_it+1, fetched_url->digest);
#endif

      /* reset retry iterator and increment url iterator */
      checker_arg->retry_it = 0;
      checker_arg->url_it++;
      free(digest_tmp);

      thread_add_timer(thread->master, http_connect_thread, thread_arg, 
                       thread_arg->svr->method->http_get->delay_before_retry);
    }
  }

  free(buffer);
  free(buffer_tmp);
  close(thread->u.fd);

  return 1;
}

/* remote http server is connected, send it the get url query.  */
int http_request_thread(struct thread *thread)
{
  struct thread_arg *thread_arg;
  struct http_thread_arg *checker_arg;
  char *str_request;
  urls *fetched_url;
  urls *pointerurls;

  thread_arg = THREAD_ARG(thread);
  checker_arg = THREAD_ARG_CHECKER_ARG(thread_arg);

  /* Handle read timeout */
  if(thread->type == THREAD_WRITE_TIMEOUT) {
#ifdef DEBUG
    if (thread_arg->svr)
      syslog(LOG_DEBUG, "HTTP write timeout to [%s:%d].",
                          inet_ntoa(thread_arg->svr->addr_ip),
                          ntohs(thread_arg->svr->addr_port));
#endif
    /* check if server is currently alive */
    if (thread_arg->svr->alive) {
      smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                 "DOWN", "=> HTTP CHECK failed on service : cannot receive data <=\n\n");
      perform_svr_state(DOWN, thread_arg->vs, thread_arg->svr);
    }

    /* reset iterator counters */
    memset(thread_arg->checker_arg, 0, sizeof(struct http_thread_arg));

    /* register next timer thread */
    thread_add_timer(thread->master, http_connect_thread, thread_arg, 
                     thread_arg->vs->delay_loop);

    close(thread->u.fd);
    return 0;
  }

  str_request = (char *)malloc(GET_REQUEST_BUFFER_LENGTH);
  memset(str_request, 0, GET_REQUEST_BUFFER_LENGTH);

  pointerurls = thread_arg->svr->method->http_get->check_urls;
  fetched_url = fetch_next_url(thread_arg);
  thread_arg->svr->method->http_get->check_urls = pointerurls;

  if (fetched_url != NULL) {
    snprintf(str_request, GET_REQUEST_BUFFER_LENGTH, GETCMD, fetched_url->url);
  } else {
    /* All the url have been successfully checked.
     * Check completed.
     */
    close(thread->u.fd);
    free(str_request);

    /* check if server is currently alive */
    if (!thread_arg->svr->alive) {
      smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                 "UP", "=> HTTP CHECK succeed on service <=\n\n");
      perform_svr_state(UP, thread_arg->vs, thread_arg->svr);
    }

    /* reset iterator counters */
    memset(checker_arg, 0, sizeof(struct http_thread_arg));

    /* register next timer thread */
    thread_add_timer(thread->master, http_connect_thread, thread_arg,
                     thread_arg->vs->delay_loop);

    return 1;
  }

#ifdef DEBUG
  syslog(LOG_DEBUG,"Processing url(%d) of [%s:%d].",
                   checker_arg->url_it+1,
                   inet_ntoa(thread_arg->svr->addr_ip),
                   ntohs(thread_arg->svr->addr_port));
#endif

  if (send(thread->u.fd, str_request, strlen(str_request), 0) == -1) {
    syslog(LOG_WARNING, "Cannot send get request to [%s:%d].",
                        inet_ntoa(thread_arg->svr->addr_ip),
                        ntohs(thread_arg->svr->addr_port));

    /* check if server is currently alive */
    if (thread_arg->svr->alive) {
      smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                 "DOWN", "=> HTTP CHECK failed on service : cannot send data <=\n\n");
      perform_svr_state(DOWN, thread_arg->vs, thread_arg->svr);
    }

    /* reset iterator counters */
    memset(thread_arg->checker_arg, 0, sizeof(struct http_thread_arg));

    /* register next timer thread */
    thread_add_timer(thread->master, http_connect_thread, thread_arg, 
                     thread_arg->vs->delay_loop);

    close(thread->u.fd);
    free(str_request);
    return 0;
  }

  /* Register read timeouted thread */
  thread_add_read(thread->master, http_response_thread, thread_arg, thread->u.fd,
                  thread_arg->svr->method->connection_to);

  free(str_request);
  return 1;
}

/* HTTP checkers threads */
int
http_check_thread(struct thread *thread)
{
  struct thread_arg *thread_arg;
  int status;

  thread_arg = THREAD_ARG(thread);

  status = tcp_socket_state(thread->u.fd, thread, http_check_thread);

  switch (status) {
    case connect_error:
#ifdef DEBUG
      syslog(LOG_DEBUG,"Error connecting HTTP server [%s:%d].",
                       inet_ntoa(thread_arg->svr->addr_ip),
                       ntohs(thread_arg->svr->addr_port));
#endif

      /* check if server is currently alive */
      if (thread_arg->svr->alive) {
        smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                   "DOWN", "=> HTTP CHECK failed on service : connection error <=\n\n");
        perform_svr_state(DOWN, thread_arg->vs, thread_arg->svr);
      }

      /* reset iterator counters */
      memset(thread_arg->checker_arg, 0, sizeof(struct http_thread_arg));

      /* register next timer thread */
      thread_add_timer(thread->master, http_connect_thread, thread_arg, 
                       thread_arg->vs->delay_loop);

      break;

    case connect_timeout:
#ifdef DEBUG
      syslog(LOG_DEBUG, "Timeout connecting HTTP server [%s:%d].",
                        inet_ntoa(thread_arg->svr->addr_ip),
                        ntohs(thread_arg->svr->addr_port));
#endif

      /* check if server is currently alive */
      if (thread_arg->svr->alive) {
        smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                   "DOWN", "=> HTTP CHECK failed on service : connection timeout <=\n\n");
        perform_svr_state(DOWN, thread_arg->vs, thread_arg->svr);
      }

      /* reset iterator counters */
      memset(thread_arg->checker_arg, 0, sizeof(struct http_thread_arg));

      /* register next timer thread */
      thread_add_timer(thread->master, http_connect_thread, thread_arg, 
                       thread_arg->vs->delay_loop);

      break;

    case connect_success:
      /* Remote HTTP server is connected.
       * Register the next step thread http_request_thread.
       */
#ifdef DEBUG
      syslog(LOG_DEBUG, "Remote HTTP server [%s:%d] connected.",
                        inet_ntoa(thread_arg->svr->addr_ip),
                        ntohs(thread_arg->svr->addr_port));
#endif
      thread_add_write(thread->master, http_request_thread, thread_arg, thread->u.fd,
                       thread_arg->svr->method->connection_to);
      break;
  }

  return 0;
}

int
http_connect_thread(struct thread *thread)
{
  struct thread_arg *thread_arg;
  int fd;
  enum connect_result status;

  thread_arg = THREAD_ARG(thread);

  if ( (fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1 ) {
#ifdef DEBUG
    syslog(LOG_DEBUG,"HTTP connect fail to create socket.");
#endif
    return 0;
  }

  status = tcp_connect(fd, thread_arg->svr->addr_ip.s_addr, thread_arg->svr->addr_port);

  /* handle tcp connection status & register check worker thread */
  tcp_connection_state(fd, status, thread, http_check_thread);

  return 0;
}
