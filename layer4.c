/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Layer4 checkers handling. Register worker threads &
 *              upper layer checkers.
 *
 * Version:     $Id: layer4.c,v 0.4.9 2001/12/10 10:52:33 acassen Exp $
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

#include "layer4.h"

enum connect_result
tcp_connect (int fd, uint32_t IP_DST, uint16_t PORT_DST)
{
  struct linger li = { 0 };
  int long_inet;
  struct sockaddr_in adr_serv;
  int ret;
  int val;

  /* free the tcp port after closing the socket descriptor */
  li.l_onoff=1;
  li.l_linger=0;
  setsockopt(fd,SOL_SOCKET,SO_LINGER,(char *)&li,sizeof(struct linger));

  long_inet = sizeof(struct sockaddr_in);
  memset(&adr_serv,0,long_inet);
  adr_serv.sin_family = AF_INET;
  adr_serv.sin_port = PORT_DST;
  adr_serv.sin_addr.s_addr = IP_DST;

  /* Make socket non-block. */
  val = fcntl (fd, F_GETFL, 0);
  fcntl (fd, F_SETFL, val|O_NONBLOCK);

  /* Call connect function. */
  ret = connect (fd, (struct sockaddr *)&adr_serv, long_inet);

  /* Immediate success */
  if (ret == 0) {
    fcntl (fd, F_SETFL, val);
    return connect_success;
  }

  /* If connect is in progress then return 1 else it's real error. */
  if (ret < 0) {
    if (errno != EINPROGRESS)
      return connect_error;
  }

  /* restore previous fd args */
  fcntl (fd, F_SETFL, val);
  return connect_in_progress;
}

enum connect_result tcp_socket_state(int fd, thread *thread
				     , int (*func) (struct _thread *))
{
  thread_arg *thread_arg;
  int status;
  int slen;
  int ret = 0;
  TIMEVAL timer_now;
  TIMEVAL timer_min;

  thread_arg = THREAD_ARG(thread);

  /* Handle connection timeout */
  if(thread->type == THREAD_WRITE_TIMEOUT) {
#ifdef _DEBUG_
    if (thread_arg->svr)
      syslog(LOG_DEBUG, "TCP connection timeout to [%s:%d].",
                          inet_ntoa(thread_arg->svr->addr_ip),
                          ntohs(thread_arg->svr->addr_port));
#endif
    close(thread->u.fd);
    return connect_timeout;
  }

  /* Check file descriptor */
  slen = sizeof(status);
  if (getsockopt(thread->u.fd, SOL_SOCKET, SO_ERROR, (void *)&status, &slen) < 0)
    ret = errno;

  /* Connection failed !!! */
  if (ret) {
#ifdef _DEBUG_
    if (thread_arg->svr)
      syslog(LOG_DEBUG, "TCP connection failed to [%s:%d].",
                          inet_ntoa(thread_arg->svr->addr_ip), 
                          ntohs(thread_arg->svr->addr_port));
#endif
    close(thread->u.fd);
    return connect_error;
  }

  /* If status = 0, TCP connection to remote host is established.
   * Otherwise register checker thread to handle connection in progress,
   * and other error code until connection is established.
   * Recompute the write timeout (or pending connection).
   */
  if (status != 0) {
#ifdef _DEBUG_
    if (thread_arg->svr)
      syslog(LOG_DEBUG, "TCP connection to [%s:%d] still IN_PROGRESS.",
                        inet_ntoa(thread_arg->svr->addr_ip),
                        ntohs(thread_arg->svr->addr_port));
#endif

    gettimeofday(&timer_now,NULL);
    timer_min = thread_timer_sub(thread->sands,timer_now);

    if (timer_min.tv_sec <= 0)
      thread_add_write(thread->master, func,
                       thread_arg, thread->u.fd, 0);
    else
      thread_add_write(thread->master, func,
                       thread_arg, thread->u.fd, timer_min.tv_sec);

    return connect_in_progress;
  }

  return connect_success;
}

void tcp_connection_state(int fd, enum connect_result status
			  , thread *thread
			  , int (*func) (struct _thread *))
{
  thread_arg *thread_arg;

  thread_arg = THREAD_ARG(thread);

  switch (status) {
    case connect_error:
#ifdef _DEBUG_
      syslog(LOG_DEBUG,"TCP connection ERROR to [%s:%d].",
                       inet_ntoa(thread_arg->svr->addr_ip),
                       ntohs(thread_arg->svr->addr_port));
#endif
      close(fd);
      break;

    case connect_success:
#ifdef _DEBUG_
      syslog(LOG_DEBUG,"TCP connection SUCCESS to [%s:%d].",
                       inet_ntoa(thread_arg->svr->addr_ip),
                       ntohs(thread_arg->svr->addr_port));
#endif
      thread_add_write(thread->master, func, thread_arg, fd,
                       thread_arg->svr->method->connection_to);
      break;

    /* Checking non-blocking connect, we wait until socket is writable */
    case connect_in_progress:
#ifdef _DEBUG_
      syslog(LOG_DEBUG,"TCP connection to [%s:%d] now IN_PROGRESS.",
                       inet_ntoa(thread_arg->svr->addr_ip),
                       ntohs(thread_arg->svr->addr_port));
#endif
      thread_add_write(thread->master, func, thread_arg, fd,
                       thread_arg->svr->method->connection_to);
      break;

    default:
      break;
  }
}
