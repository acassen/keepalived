/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        TCP checker.
 *
 * Version:     $Id: check_tcp.c,v 0.4.9a 2001/12/20 17:14:25 acassen Exp $
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

#include "check_tcp.h"

int tcp_check_thread(thread *thread)
{
  thread_arg *thread_arg;
  int status;

  thread_arg = THREAD_ARG(thread);

  status = tcp_socket_state(thread->u.fd, thread, tcp_check_thread);

  /* If status = connect_success, TCP connection to remote host is established.
   * Otherwise we have a real connection error or connection timeout.
   */
  if (status == connect_success) {

#ifdef _DEBUG_
    syslog(LOG_DEBUG, "TCP connection to [%s:%d] success.",
                      inet_ntoa(thread_arg->svr->addr_ip),
                      ntohs(thread_arg->svr->addr_port));
#endif
    close(thread->u.fd);

    if (!thread_arg->svr->alive) {
      smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                 "UP", "=> TCP CHECK succeed on service <=\n\n");
      perform_svr_state(UP, thread_arg->vs, thread_arg->svr);
    }

  } else {
#ifdef _DEBUG_
    syslog(LOG_DEBUG, "TCP connection to [%s:%d] failed !!!",
                      inet_ntoa(thread_arg->svr->addr_ip),
                      ntohs(thread_arg->svr->addr_port));
#endif

    if (thread_arg->svr->alive) {
      smtp_alert(thread->master, thread_arg->root, thread_arg->svr,
                 "DOWN", "=> TCP CHECK failed on service <=\n\n");
      perform_svr_state(DOWN, thread_arg->vs, thread_arg->svr);
    }

  }

  /* Register next timer checker */
  if (status != connect_in_progress)
    thread_add_timer(thread->master, tcp_connect_thread, thread_arg,
                     thread_arg->vs->delay_loop);

  return 0;
}

int tcp_connect_thread(thread *thread)
{
  thread_arg *thread_arg;
  int fd;
  int status;

  thread_arg = THREAD_ARG(thread);

  if ( (fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1 ) {
#ifdef _DEBUG_
    syslog(LOG_DEBUG, "TCP connect fail to create socket.");
#endif
    return 0;
  }

  status = tcp_connect(fd, thread_arg->svr->addr_ip.s_addr, thread_arg->svr->addr_port);

  /* handle tcp connection status & register check worker thread */
  tcp_connection_state(fd, status, thread, tcp_check_thread);

  return 0;
}
