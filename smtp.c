/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        SMTP WRAPPER connect to a specified smtp server and send mail
 *              using the smtp protocol according to the RFC 821. A non blocking
 *              timeouted connection is used to handle smtp protocol.
 *
 * Version:     $Id: smtp.c,v 0.4.0 2001/08/24 00:35:19 acassen Exp $
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *
 * Changes:     Alexandre Cassen : 2001/07/15 : Initial release
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

/* static prototype */
static int smtp_send_cmd_thread(struct thread *thread);

static void free_smtp_arg(struct smtp_thread_arg *smtp_arg)
{
  free(smtp_arg->subject);
  free(smtp_arg->body);
  free(smtp_arg);
}

static char *fetch_next_email(struct thread_arg *thread_arg)
{
  struct smtp_thread_arg *smtp_arg;
  int i = 0;

  smtp_arg = THREAD_ARG_CHECKER_ARG(thread_arg);

  for (i=0; i<smtp_arg->email_it; i++)
    thread_arg->root->email = (notification_email *)thread_arg->root->email->next;

  if (thread_arg->root->email)
    return thread_arg->root->email->addr;

  return NULL;
}

static int smtp_read_cmd_thread(struct thread *thread)
{
  struct thread_arg *thread_arg;
  struct smtp_thread_arg *smtp_arg;
  notification_email *pointeremail;
  char *fetched_email;
  long total_length = 0;
  int rcv_buffer_size = 0;
  char *buffer;
  char *buffer_tmp;

  thread_arg = THREAD_ARG(thread);
  smtp_arg = THREAD_ARG_CHECKER_ARG(thread_arg);

  if (thread->type == THREAD_READ_TIMEOUT) {
#ifdef DEBUG
    syslog(LOG_DEBUG, "Timeout reading data to remote SMTP server [%s:%d].",
                      inet_ntoa(thread_arg->root->smtp_server),
                      SMTP_PORT);
#endif
    free_smtp_arg(smtp_arg);
    thread_arg->checker_arg = NULL;
    close(thread->u.fd);
    return 0;
  }

  /* Allocate the get buffers */
  buffer = (char *)malloc(SMTP_BUFFER_MAX);
  buffer_tmp = (char *)malloc(SMTP_BUFFER_LENGTH);

  /* Cleanup the room */
  memset(buffer, 0, SMTP_BUFFER_MAX);
  memset(buffer_tmp, 0, SMTP_BUFFER_LENGTH);

  while ((rcv_buffer_size = read(thread->u.fd, buffer_tmp, SMTP_BUFFER_LENGTH)) != 0) {
    if (rcv_buffer_size == -1) {
      if (errno == EAGAIN) goto end;
#ifdef DEBUG
      syslog(LOG_DEBUG, "Error reading data to remote SMTP server [%s:%d].",
                        inet_ntoa(thread_arg->root->smtp_server),
                        SMTP_PORT);
#endif
      free_smtp_arg(smtp_arg);
      thread_arg->checker_arg = NULL;
      close(thread->u.fd);
      free(buffer);
      free(buffer_tmp);
      return 0;
    }

    /* received data overflow buffer size ? */
    if (total_length >= SMTP_BUFFER_MAX) {
#ifdef DEBUG
      syslog(LOG_DEBUG, "Received buffer from remote SMTP server [%s:%d]"
                        " overflow our get read buffer length.",
                        inet_ntoa(thread_arg->root->smtp_server),
                        SMTP_PORT);
#endif
      free_smtp_arg(smtp_arg);
      thread_arg->checker_arg = NULL;
      close(thread->u.fd);
      free(buffer);
      free(buffer_tmp);
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
    case connection:
      if (memcmp(buffer, SMTP_CONNECT, 3) == 0) {
        smtp_arg->stage = helo;
      } else {
        syslog(LOG_DEBUG, "Error connecting smtp server : [%s]", buffer);
        smtp_arg->stage = error;
      }
      break;

    case helo:
      if (memcmp(buffer, SMTP_HELO, 3) == 0) {
        smtp_arg->stage = mail;
      } else {
        syslog(LOG_DEBUG, "Error processing HELO cmd : [%s]", buffer);
        smtp_arg->stage = error;
      }
      break;

    case mail:
      if (memcmp(buffer, SMTP_MAIL_FROM, 3) == 0) {
        smtp_arg->stage = rcpt;
      } else {
        syslog(LOG_DEBUG, "Error processing MAIL FROM cmd : [%s]", buffer);
        smtp_arg->stage = error;
      }
      break;

    case rcpt:
      if (memcmp(buffer, SMTP_RCPT_TO, 3) == 0) {
        smtp_arg->email_it++;

        pointeremail = thread_arg->root->email;
        fetched_email = fetch_next_email(thread_arg);
        thread_arg->root->email = pointeremail;

        if (!fetched_email)
          smtp_arg->stage = data;
      } else {
        syslog(LOG_DEBUG, "Error processing RCPT TO cmd : [%s]", buffer);
        smtp_arg->stage = error;
      }
      break;

    case data:
      if (memcmp(buffer, SMTP_DATA, 3) == 0) {
        smtp_arg->stage = body;
      } else {
        syslog(LOG_DEBUG, "Error processing DATA cmd : [%s]", buffer);
        smtp_arg->stage = error;
      }
      break;

    case body:
      if (memcmp(buffer, SMTP_DOT, 3) == 0) {
        smtp_arg->stage = quit;
        syslog(LOG_INFO, "SMTP alert successfully sent.");
      } else {
        syslog(LOG_DEBUG, "Error processing DOT cmd : [%s]", buffer);
        smtp_arg->stage = error;
      }
      break;

    case quit:
      /* final state, we are disconnected from the remote host */
      free_smtp_arg(smtp_arg);
      thread_arg->checker_arg = NULL;
      close(thread->u.fd);
      free(buffer);
      free(buffer_tmp);
      return 0;
      break;

    case error:
      break;
  }

  /* Registering next smtp command processing thread */
  thread_add_write(thread->master, smtp_send_cmd_thread, thread_arg, thread->u.fd,
                   thread_arg->root->smtp_connection_to);

  free(buffer);
  free(buffer_tmp);
  return 0;
}

/* Getting localhost official canonical name */
static char *get_local_name()
{
  struct hostent *host;
  struct utsname name;

  if (uname(&name) < 0)
    return NULL;

  if (!(host = gethostbyname(name.nodename)))
    return NULL;

  return host->h_name;
}

static int smtp_send_cmd_thread(struct thread *thread)
{
  struct thread_arg *thread_arg;
  struct smtp_thread_arg *smtp_arg;
  notification_email *pointeremail;
  char *fetched_email;
  char *buffer;

  thread_arg = THREAD_ARG(thread);
  smtp_arg = THREAD_ARG_CHECKER_ARG(thread_arg);

  if (thread->type == THREAD_WRITE_TIMEOUT) {
#ifdef DEBUG
    syslog(LOG_DEBUG, "Timeout sending data to remote SMTP server [%s:%d].",
                      inet_ntoa(thread_arg->root->smtp_server),
                      SMTP_PORT);
#endif
    free_smtp_arg(smtp_arg);
    thread_arg->checker_arg = NULL;
    close(thread->u.fd);
    return 0;
  }

  /* allocate temporary command buffer */
  buffer = (char *)malloc(SMTP_BUFFER_MAX);
  memset(buffer, 0, SMTP_BUFFER_MAX);

  switch (smtp_arg->stage) {
    case connection:
      break;

    case helo:
      snprintf(buffer, TEMP_BUFFER_LENGTH, SMTP_HELO_CMD, get_local_name());
      if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
        smtp_arg->stage = error;
      break;

    case mail:
      snprintf(buffer, TEMP_BUFFER_LENGTH, SMTP_MAIL_CMD, thread_arg->root->email_from);
      if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
        smtp_arg->stage = error;
      break;

    case rcpt:
      /* We send RCPT TO command multiple time to add all our email receivers.
       * --rfc821.3.1
       */
      pointeremail = thread_arg->root->email;
      fetched_email = fetch_next_email(thread_arg);
      thread_arg->root->email = pointeremail;

      snprintf(buffer, TEMP_BUFFER_LENGTH, SMTP_RCPT_CMD, fetched_email);
      if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
        smtp_arg->stage = error;
      break;

    case data:
      if (send(thread->u.fd, SMTP_DATA_CMD, strlen(SMTP_DATA_CMD), 0) == -1)
        smtp_arg->stage = error;
      break;

    case body:
      snprintf(buffer, TEMP_BUFFER_LENGTH, SMTP_SUBJECT_CMD, smtp_arg->subject);
      /* send the subject field */
      if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
        smtp_arg->stage = error;

      memset(buffer, 0, SMTP_BUFFER_MAX);
      snprintf(buffer, TEMP_BUFFER_LENGTH, SMTP_BODY_CMD, smtp_arg->body);
      /* send the the body field */
      if (send(thread->u.fd, buffer, strlen(buffer), 0) == -1)
        smtp_arg->stage = error;

      /* send the sending dot */
      if (send(thread->u.fd, SMTP_SEND_CMD, strlen(SMTP_SEND_CMD), 0) == -1)
        smtp_arg->stage = error;
      break;

    case quit:
      if (send(thread->u.fd, SMTP_QUIT_CMD, strlen(SMTP_QUIT_CMD), 0) == -1)
        smtp_arg->stage = error;
      break;

    case error:
#ifdef DEBUG
      syslog(LOG_DEBUG, "Can not send data to remote SMTP server [%s:%d].",
                        inet_ntoa(thread_arg->root->smtp_server),
                        SMTP_PORT);
#endif
      /* we just cleanup the room */
      free_smtp_arg(smtp_arg);
      thread_arg->checker_arg = NULL;
      close(thread->u.fd);
      free(buffer);
      return 0;
      break;
  }

//printf("Sending : %s", buffer);

  /* Registering next smtp command processing thread */
  thread_add_read(thread->master, smtp_read_cmd_thread, thread_arg, thread->u.fd,
                  thread_arg->root->smtp_connection_to);

  free(buffer);
  return 0;
}

/* SMTP checkers threads */
static int smtp_check_thread(struct thread *thread)
{
  struct thread_arg *thread_arg;
  struct smtp_thread_arg *smtp_arg;
  int status;

  thread_arg = THREAD_ARG(thread);
  smtp_arg = THREAD_ARG_CHECKER_ARG(thread_arg);

  status = tcp_socket_state(thread->u.fd, thread, smtp_check_thread);

  switch (status) {
    case connect_error:
#ifdef DEBUG
      syslog(LOG_DEBUG, "Error connecting SMTP server [%s:%d].",
                        inet_ntoa(thread_arg->root->smtp_server),
                        SMTP_PORT);
#endif
      free_smtp_arg(smtp_arg);
      thread_arg->checker_arg = NULL;
      break;

    case connect_timeout:
#ifdef DEBUG
      syslog(LOG_DEBUG, "Timeout writing data to SMTP server [%s:%d].",
                        inet_ntoa(thread_arg->root->smtp_server),
                        SMTP_PORT);
#endif
      free_smtp_arg(smtp_arg);
      thread_arg->checker_arg = NULL;
      break;

    case connect_success:
      /* Remote SMTP server is connected.
       * Register the next step thread smtp_cmd_thread.
       */
#ifdef DEBUG
      syslog(LOG_DEBUG, "Remote SMTP server [%s:%d] connected.",
                        inet_ntoa(thread_arg->root->smtp_server),
                        SMTP_PORT);
#endif

      thread_add_write(thread->master, smtp_send_cmd_thread, thread_arg, thread->u.fd,
                       thread_arg->root->smtp_connection_to);
      break;
  }

  return 0;
}

static int smtp_connect_thread(struct thread *thread)
{
  struct thread_arg *thread_arg;
  struct smtp_thread_arg *smtp_arg;
  enum connect_result status;
  int fd;

  thread_arg = THREAD_ARG(thread);
  smtp_arg = THREAD_ARG_CHECKER_ARG(thread_arg);

  if ( (fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1 ) {
#ifdef DEBUG
    syslog(LOG_DEBUG, "SMTP connect fail to create socket.");
#endif
    return 0;
  }

  status = tcp_connect(fd, thread_arg->root->smtp_server.s_addr, htons(SMTP_PORT));

  switch (status) {
    case connect_error:
#ifdef DEBUG
      syslog(LOG_DEBUG, "SMTP connection ERROR to [%s:%d].",
                        inet_ntoa(thread_arg->root->smtp_server),
                        SMTP_PORT);
#endif
      free_smtp_arg(smtp_arg);
      thread_arg->checker_arg = NULL;
      close(fd);
      return 0;
      break;

    case connect_timeout:
#ifdef DEBUG
      syslog(LOG_DEBUG, "Timeout connecting SMTP server [%s:%d].",
                        inet_ntoa(thread_arg->root->smtp_server),
                        SMTP_PORT);
#endif
      free_smtp_arg(smtp_arg);
      thread_arg->checker_arg = NULL;
      close(fd);
      return 0;
      break;

    case connect_success:
#ifdef DEBUG
      syslog(LOG_DEBUG, "SMTP connection SUCCESS to [%s:%d].",
                        inet_ntoa(thread_arg->root->smtp_server),
                        SMTP_PORT);
#endif
      break;

    /* Checking non-blocking connect, we wait until socket is writable */
    case connect_in_progress:
#ifdef DEBUG
      syslog(LOG_DEBUG, "SMTP connection to [%s:%d] now IN_PROGRESS.",
                        inet_ntoa(thread_arg->root->smtp_server),
                        SMTP_PORT);
#endif
      break;
  }

  /* connection have succeeded or still in progress */
  thread_add_write(thread->master, smtp_check_thread, thread_arg, fd,
                   thread_arg->root->smtp_connection_to);

  return 1;
}

void smtp_alert(struct thread_master *master,
                configuration_data *root,
                realserver *rserver,
                const char *subject,
                const char *body)
{
  struct thread_arg *thread_arg;
  struct smtp_thread_arg *smtp_arg;

  /* allocate a new thread_arg */
  thread_arg = thread_arg_new(root, NULL, NULL);

  /* allocate & initialize smtp argument data structure */
  smtp_arg = (struct smtp_thread_arg *)malloc(sizeof(struct smtp_thread_arg));
  memset(smtp_arg, 0, sizeof(struct smtp_thread_arg));

  smtp_arg->subject = (char *)malloc(MAX_SUBJECT_LENGTH);
  smtp_arg->body = (char *)malloc(MAX_BODY_LENGTH);
  memset(smtp_arg->subject, 0, MAX_SUBJECT_LENGTH);
  memset(smtp_arg->body, 0, MAX_BODY_LENGTH);

  smtp_arg->stage = connection; /* first smtp command set to HELO */

  /* format subject if rserver is specified */
  if (rserver)
    snprintf(smtp_arg->subject, MAX_SUBJECT_LENGTH, "[%s] %s:%d - %s",
             root->lvs_id, inet_ntoa(rserver->addr_ip), ntohs(rserver->addr_port), subject);
  else
    snprintf(smtp_arg->subject, MAX_SUBJECT_LENGTH, "[%s] %s", root->lvs_id, subject);

  strncpy(smtp_arg->body, body, MAX_BODY_LENGTH);

  thread_arg->checker_arg = smtp_arg;

  thread_add_event(master, smtp_connect_thread, thread_arg, 0);
}
