/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Checkers registration.
 *
 * Version:     $Id: check_api.c,v 0.6.8 2002/07/16 02:41:25 acassen Exp $
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
#ifdef _WITH_CI_LINUX_
#include "check_ci.h"
#endif

extern thread_master *master;
extern data *conf_data;

/* free checker data */
static void
free_checker(void *data)
{
	checker *checker = data;
	(*checker->free) (checker);
}

/* dump checker data */
static void
dump_checker(void *data)
{
	checker *checker = data;
	syslog(LOG_INFO, " %s:%d", inet_ntop2(CHECKER_RIP(checker))
	       , ntohs(CHECKER_RPORT(checker)));
	(*checker->dump) (checker);
}

/* init the global checkers queue */
void
init_checkers_queue(void)
{
	checkers_queue = alloc_list(free_checker, dump_checker);
}

/* Queue a checker to the checkers_queue */
void
queue_checker(void (*free) (void *), void (*dump) (void *)
	      , int (*launch) (struct _thread *)
	      , void *data)
{
	virtual_server *vs = LIST_TAIL_DATA(conf_data->vs);
	real_server *rs = LIST_TAIL_DATA(vs->rs);
	checker *chk = (checker *) MALLOC(sizeof (checker));

	chk->free = free;
	chk->dump = dump;
	chk->launch = launch;
	chk->vs = vs;
	chk->rs = rs;
	chk->data = data;
	chk->enabled = (vs->vfwmark) ? 1 : 0;

	/* queue the checker */
	list_add(checkers_queue, chk);
}

/* dump the checkers_queue */
void
dump_checkers_queue(void)
{
	if (!LIST_ISEMPTY(checkers_queue)) {
		syslog(LOG_INFO, "------< Health checkers >------");
		dump_list(checkers_queue);
	}
}

/* release the checkers_queue */
void
free_checkers_queue(void)
{
	free_list(checkers_queue);
}

/* register the checker to the global I/O scheduler */
void
register_checkers_thread(void)
{
	checker *checker;
	element e;

	for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
		checker = ELEMENT_DATA(e);
		thread_add_timer(master, checker->launch, checker,
				 BOOTSTRAP_DELAY);
	}
}

/* Sync checkers activity with netlink kernel reflection */
void
update_checker_activity(uint32_t address, int enable)
{
	checker *checker;
	element e;

	/* Processing Healthcheckers queue */
	if (!LIST_ISEMPTY(checkers_queue))
		for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
			checker = ELEMENT_DATA(e);
			if (CHECKER_VIP(checker) == address) {
				if (!CHECKER_ENABLED(checker) && enable) {
					syslog(LOG_INFO,
					       "Netlink reflector reports IP %s added",
					       inet_ntop2(address));
					syslog(LOG_INFO,
					       "Activating healtchecker for VIP %s",
					       inet_ntop2(address));
				}
				if (CHECKER_ENABLED(checker) && !enable) {
					syslog(LOG_INFO,
					       "Netlink reflector reports IP %s removed",
					       inet_ntop2(address));
					syslog(LOG_INFO,
					       "Suspending healtchecker for VIP %s",
					       inet_ntop2(address));
				}
				checker->enabled = enable;
			}
		}
}

/* Install checkers keywords */
void
install_checkers_keyword(void)
{
	install_misc_check_keyword();
	install_tcp_check_keyword();
	install_http_check_keyword();
	install_ssl_check_keyword();
#ifdef _WITH_CI_LINUX_
	install_ci_check_keyword();
#endif
}
