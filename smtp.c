/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        SMTP WRAPPER connect to a specified smtp server and send mail
 *              using the smtp protocol according to the RFC 821. A non blocking
 *              timeouted connection is used to handle smtp protocol.
 *
 * Version:     $Id: smtp.c,v 0.5.8 2002/05/21 16:09:46 acassen Exp $
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

#include "smtp.h"
#include "memory.h"
#include "list.h"
#include "utils.h"

extern data *conf_data;

/* static prototype */
static int smtp_send_cmd_thread(thread *);

static void free_smtp_all(smtp_thread_arg *smtp_arg)
{
  FREE(smtp_arg->subject);
  FREE(smtp_arg->body);
  FREE(smtp_arg);
}

static char *fetch_next_email(smtp_thread_arg *smtp_arg)
{
  return list_element(conf_data->email, smtp_arg->email_it);
}

static int smtp_read_cmd_thread(thread *thread)
{
  smtp_thread_arg *smtp_arg;
  char *fetched_email;
  long total_length = 0;
  int rcv_buffer_size = 0;
  char *buffer;
  char *buffer_tmp;

  smtp_arg = THREAD_ARG(thread);

  if (thread->type == THREAD_READ_TIMEOUT) {
#ifdef _DEBUG_
    syslog(LOG_DEBUG, "Timeout reading data to remote SMTP server [%s:%d].",
                      ip_ntoa(conf_data->smtp_server),
                      SMTP_PORT);
#endif
    free_smtp_all(smtp_arg);
    close(thread->u.fd);
    return 0;
  }

  /* Allocate the get buffers */
  buffer     = (char *)MALLOC(SMTP_BUFFER_MAX);
  buffer_tmp = (char *)MALLOC(SMTP_BUFFER_LENGTH);

  /* Cleanup the room */
  memset(buffer, 0, SMTP_BUFFER_MAX);
  memset(buffer_tmp, 0, SMTP_BUFFER_LENGTH);

  while ((rcv_buffer_size = read(thread->u.fd, buffer_tmp, SMTP_BUFFER_LENGTH)) != 0) {
    if (rcv_buffer_size == -1) {
      if (errno == EAGAIN) goto end;
#ifdef _DEBUG_
      syslog(LOG_DEBUG, "Error reading data to remote SMTP server [%s:%d]."
                      , ip_ntoa(conf_data->smtp_server)
                      , SMTP_PORT);
#endif
      free_smtp_all(smtp_arg);
      close(thread->u.fd);
      FREE(buffer);
      FREE(buffer_tmp);
      return 0;
    }

    /* received data overflow buffer size ? */
    if (total_length >= SMTP_BUFFER_MAX) {
#ifdef _DEBUG_
      syslog(LOG_DEBUG, "Received buffer from remote SMTP server [%s:%d]"
                        " overflow our get read buffer length."
                      , ip_ntoa(conf_data->smtp_server)
                      , SMTP_PORT);
#endif
      free_smtp_all(smtp_arg);
      close(thread->u.fd);
      FREE(buffer);
      FREE(buffer_tmp);
      return 0;
    } else {
      memcpy(buffer+total_length, buffer_tmp, rcv_buffer_size);
      memset(buffer_tmp, 0, SMTP_BUFFER_LENGTH);
      total_length += rcv_buffer_size;
      if (rcv_buffer_size < SMTP_BUFFER_LENGTH) goto end;
    }
  }

end:

// printf("Received : %s", buffer);

  /* setting the next stage */
  switch (smtp_arg->stage) {
    case CONNECTION:
      if (memcmp(buffer, SMTP_CONNECT, 3) == 0) {
        smtp_arg->stage = HELO;
      } else {
        syslog(LOG_DEBUG, "Error connecting smtp server : [%s]", buffer);
        smtp_arg->stage = ERROR;
      }
      break;

    case HELO:
      if (memcmp(buffer, SMTP_HELO, 3) == 0) {
        smtp_arg->stage = MAIL;
      } else {
        syslog(LOG_DEBUG, "Error processing HELO cmd : [%s]", buffer);
        smtp_arg->stage = ERROR;
      }
      break;

    case MAIL:
      if (memcmp(buffer, SMTP_MAIL_FROM, 3) == 0) {
        smtp_arg->stage = RCPT;
      } else {
        syslog(LOG_DEBUG, "Error processing MAIL FROM cmd : [%s]", buffer);
        smtp_arg->stage = ERROR;
      }
      break;

    case RCPT:
      if (memcmp(buffer, SMTP_RCPT_TO, 3) == 0) {
        smtp_arg->email_it++;

        fetched_email = fetch_next_email(smtp_arg);

        if (!fetched_email)
          smtp_arg->stage = DATA;
      } else {
        syslog(LOG_DEBUG, "Error processing RCPT TO cmd : [%s]", buffer);
        smtp_arg->stage = ERROR;
      }
      break;

    case DATA:
      if (memcmp(buffer, SMTP_DATA, 3) == 0) {
        smtp_arg->stage = BODY;
      } else {
        syslog(LOG_DEBUG, "Error processing DATA cmd : [%s]", buffer);
        smtp_arg->stage = ERROR;
      }
      break;

    case BODY:
      if (memcmp(buffer, SMTP_DOT, 3) == 0) {
        smtp_arg->stage = QUIT;
        syslog(LOG_INFO, "SMTP alert successfully sent.");
      } else {
        syslog(LOG_DEBUG, "Error processing DOT cmd : [%s]", buffer);
        smtp_arg->stage = ERROR;
      }
      break;

    case QUIT:
      /* final state, we are disconnected from the remote host */
      free_smtp_all(smtp_arg);
      close(thread->u.fd);
      FREE(buffer);
      FREE(buffer_tmp);
      return 0;
      break;

    case ERROR:
      break;
  }

  /* Registering next smtp command processing thread */
  thread_add_write(thread->master, smtp_send_cmd_thread
                                 , smtp_arg
                                 , thread->u.fd
                                 , conf_data->smtp_connection_to);

  FREE(buffer);
  FREE(buffer_tmp);
  return 0;
}

/* Getting localhost official canonical name */
static char *get_local_name(void)
{
  struct hostent *host;
  struct utsname name;

  if (uname(&name) < 0)
    return NULL;

  if (!(host = gethostbyname(name.nodename)))
    return NULL;

  return host->h_name;
}

static int smtp_send_cmd_thread(thread *thread)
{
  smtp_thread_arg *smtp_arg;
  char *fetched_email;
  char *buffer;

  smtp_arg = THREAD_ARG(thread);

  if (thread->type == THREAD_WRITE_TIMEOUT) {
#ifdef _DEBUG_
    syslog(LOG_DEBUG, "Timeout sending data to remote SMTP server [%s:%d]."
                    , ip_ntoa(conf_data->smtp_server)
                    , SMTP_PORT);
#endif
    free_smtp_all(smtp_arg);
    close(thread->u.fd);
    return 0;
  }

  /* allocate temporary command buffer */
  buffer = (char *)MALLOC(SMTP_BUFFER_MAX);

  switch (smtp_arg->stage) {
    case CONNECTION:
      break;

    case HELO:
      snprintf(buffer, SMTP_BUFFER_MAX, SMTP_HELO_CMD, get_local_name());
      if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
        smtp_arg->stage = ERROR;
      break;

    case MAIL:
      snprintf(buffer, SMTP_BUFFER_MAX, SMTP_MAIL_CMD, conf_data->email_from);
      if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
        smtp_arg->stage = ERROR;
      break;

    case RCPT:
      /* We send RCPT TO command multiple time to add all our email receivers.
       * --rfc821.3.1
       */
      fetched_email = fetch_next_email(smtp_arg);

      snprintf(buffer, SMTP_BUFFER_MAX, SMTP_RCPT_CMD, fetched_email);
      if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
        smtp_arg->stage = ERROR;
      break;

    case DATA:
      if (send(thread->u.fd, SMTP_DATA_CMD, strlen(SMTP_DATA_CMD), 0) == -1)
        smtp_arg->stage = ERROR;
      break;

    case BODY:
      snprintf(buffer, SMTP_BUFFER_MAX, SMTP_HEADERS_CMD
                     , conf_data->email_from
                     , smtp_arg->subject);
      /* send the subject field */
      if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
        smtp_arg->stage = ERROR;

      memset(buffer, 0, SMTP_BUFFER_MAX);
      snprintf(buffer, SMTP_BUFFER_MAX, SMTP_BODY_CMD, smtp_arg->body);
      /* send the the body field */
      if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
        smtp_arg->stage = ERROR;

      /* send the sending dot */
      if (send(thread->u.fd, SMTP_SEND_CMD, strlen(SMTP_SEND_CMD), 0) == -1)
        smtp_arg->stage = ERROR;
      break;

    case QUIT:
      if (send(thread->u.fd, SMTP_QUIT_CMD, strlen(SMTP_QUIT_CMD), 0) == -1)
        smtp_arg->stage = ERROR;
      break;

    case ERROR:
#ifdef _DEBUG_
      syslog(LOG_DEBUG, "Can not send data to remote SMTP server [%s:%d]."
                      , ip_ntoa(conf_data->smtp_server)
                      , SMTP_PORT);
#endif
      /* we just cleanup the room */
      free_smtp_all(smtp_arg);
      close(thread->u.fd);
      FREE(buffer);
      return 0;
      break;
  }

//printf("Sending : %s", buffer);

  /* Registering next smtp command processing thread */
  thread_add_read(thread->master, smtp_read_cmd_thread
                                , smtp_arg
                                , thread->u.fd
                                , conf_data->smtp_connection_to);

  FREE(buffer);
  return 0;
}

/* SMTP checkers threads */
static int smtp_check_thread(thread *thread)
{
  smtp_thread_arg *smtp_arg;
  int status;

  smtp_arg = THREAD_ARG(thread);

  status = tcp_socket_state(thread->u.fd, thread
                                        , conf_data->smtp_server
                                        , htons(SMTP_PORT)
                                        , smtp_check_thread);

  switch (status) {
    case connect_error:
#ifdef _DEBUG_
      syslog(LOG_DEBUG, "Error connecting SMTP server [%s:%d]."
                      , ip_ntoa(conf_data->smtp_server)
                      , SMTP_PORT);
#endif
      free_smtp_all(smtp_arg);
      break;

    case connect_timeout:
#ifdef _DEBUG_
      syslog(LOG_DEBUG, "Timeout writing data to SMTP server [%s:%d]."
                      , ip_ntoa(conf_data->smtp_server)
                      , SMTP_PORT);
#endif
      free_smtp_all(smtp_arg);
      break;

    case connect_success:
      /* Remote SMTP server is connected.
       * Register the next step thread smtp_cmd_thread.
       */
#ifdef _DEBUG_
      syslog(LOG_DEBUG, "Remote SMTP server [%s:%d] connected."
                      , ip_ntoa(conf_data->smtp_server)
                      , SMTP_PORT);
#endif
      thread_add_write(thread->master, smtp_send_cmd_thread
                                     , smtp_arg
                                     , thread->u.fd
                                     , conf_data->smtp_connection_to);
      break;
  }

  return 0;
}

static int smtp_connect_thread(thread *thread)
{
  smtp_thread_arg *smtp_arg;
  enum connect_result status;
  int fd;

  smtp_arg = THREAD_ARG(thread);

  /* Return if no smtp server is defined */
  if (conf_data->smtp_server == 0) {
    free_smtp_all(smtp_arg);
    return 0;
  }

  if ( (fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1 ) {
#ifdef _DEBUG_
    syslog(LOG_DEBUG, "SMTP connect fail to create socket.");
#endif
    return 0;
  }

  status = tcp_connect(fd, conf_data->smtp_server, htons(SMTP_PORT));

  switch (status) {
    case connect_error:
#ifdef _DEBUG_
      syslog(LOG_DEBUG, "SMTP connection ERROR to [%s:%d]."
                      , ip_ntoa(conf_data->smtp_server)
                      , SMTP_PORT);
#endif
      free_smtp_all(smtp_arg);
      close(fd);
      return 0;
      break;

    case connect_timeout:
#ifdef _DEBUG_
      syslog(LOG_DEBUG, "Timeout connecting SMTP server [%s:%d]."
                      , ip_ntoa(conf_data->smtp_server)
                      , SMTP_PORT);
#endif
      free_smtp_all(smtp_arg);
      close(fd);
      return 0;
      break;

    case connect_success:
#ifdef _DEBUG_
      syslog(LOG_DEBUG, "SMTP connection SUCCESS to [%s:%d]."
                      , ip_ntoa(conf_data->smtp_server)
                      , SMTP_PORT);
#endif
      break;

    /* Checking non-blocking connect, we wait until socket is writable */
    case connect_in_progress:
#ifdef _DEBUG_
      syslog(LOG_DEBUG, "SMTP connection to [%s:%d] now IN_PROGRESS."
                      , ip_ntoa(conf_data->smtp_server)
                      , SMTP_PORT);
#endif
      break;
  }

  /* connection have succeeded or still in progress */
  thread_add_write(thread->master, smtp_check_thread
                                 , smtp_arg
                                 , fd
                                 , conf_data->smtp_connection_to);
  return 1;
}

void smtp_alert(thread_master *master
                , real_server *rs
                , vrrp_rt *vrrp
                , const char *subject
                , const char *body)
{
  smtp_thread_arg *smtp_arg;

  /* Only send mail if email specified */
  if (!LIST_ISEMPTY(conf_data->email)) {
    /* allocate & initialize smtp argument data structure */
    smtp_arg          = (smtp_thread_arg *)MALLOC(sizeof(smtp_thread_arg));
    smtp_arg->subject = (char *)MALLOC(MAX_HEADERS_LENGTH);
    smtp_arg->body    = (char *)MALLOC(MAX_BODY_LENGTH);

    smtp_arg->stage = CONNECTION; /* first smtp command set to HELO */

    /* format subject if rserver is specified */
    if (rs)
      snprintf(smtp_arg->subject, MAX_HEADERS_LENGTH
                                , "[%s] Realserver %s:%d - %s"
                                , conf_data->lvs_id
                                , ip_ntoa(SVR_IP(rs))
                                , ntohs(SVR_PORT(rs))
                                , subject);
    else if (vrrp)
      snprintf(smtp_arg->subject, MAX_HEADERS_LENGTH
                                , "[%s] VRRP Instance %s - %s"
                                , conf_data->lvs_id
                                , vrrp->iname
                                , subject);
    else if (conf_data->lvs_id)
      snprintf(smtp_arg->subject, MAX_HEADERS_LENGTH, "[%s] %s"
                                , conf_data->lvs_id
                                , subject);
    else
      snprintf(smtp_arg->subject, MAX_HEADERS_LENGTH, "%s"
                                , subject);

    strncpy(smtp_arg->body, body, MAX_BODY_LENGTH);

    thread_add_event(master, smtp_connect_thread, smtp_arg, 0);
  }
}
