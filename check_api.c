/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Checkers registration.
 *
 * Version:     $Id: check_api.c,v 0.5.7 2002/05/02 22:18:07 acassen Exp $
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

#include "check_api.h"
#include "parser.h"
#include "memory.h"
#include "utils.h"
#include "check_misc.h"
#include "check_tcp.h"
#include "check_http.h"
#include "check_ssl.h"

extern thread_master *master;
extern data *conf_data;

/* free checker data */
static void free_checker(void *data)
{
  checker *checker = data;
  (*checker->free) (checker);
}

/* dump checker data */
static void dump_checker(void *data)
{
  checker *checker = data;
  syslog(LOG_INFO, " %s:%d"
                 , ip_ntoa(CHECKER_RIP(checker))
                 , ntohs(CHECKER_RPORT(checker)));
  (*checker->dump) (checker);
}

/* init the global checkers queue */
void init_checkers_queue(void)
{
  checkers_queue = alloc_list(free_checker, dump_checker);
}

/* Queue a checker to the checkers_queue */
void queue_checker(void (*free) (void *), void (*dump) (void *)
                                        , int (*launch) (struct _thread *)
                                        , void *data)
{
  virtual_server *vs = LIST_TAIL_DATA(conf_data->vs);
  real_server *rs    = LIST_TAIL_DATA(vs->rs);
  checker *chk       = (checker *)MALLOC(sizeof(checker));

  chk->free   = free;
  chk->dump   = dump;
  chk->launch = launch;
  chk->vs     = vs;
  chk->rs     = rs;
  chk->data   = data;

  /* queue the checker */
  list_add(checkers_queue, chk);
}

/* dump the checkers_queue */
void dump_checkers_queue(void)
{
  if (!LIST_ISEMPTY(checkers_queue)) {
    syslog(LOG_INFO, "------< Health checkers >------");
    dump_list(checkers_queue);
  }
}

/* release the checkers_queue */
void free_checkers_queue(void)
{
  free_list(checkers_queue);
}

/* register the checker to the global I/O scheduler */
void register_checkers_thread(void)
{
  checker *checker;
  element e;

  for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
    checker = ELEMENT_DATA(e);
    thread_add_timer(master, checker->launch
                           , checker
                           , BOOTSTRAP_DELAY);
  }
}

/* Install checkers keywords */
void install_checkers_keyword(void)
{
  install_misc_check_keyword();
  install_tcp_check_keyword();
  install_http_check_keyword();
  install_ssl_check_keyword();
}
