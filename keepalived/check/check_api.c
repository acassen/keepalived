/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Checkers registration.
 *
 * Version:     $Id: check_api.c,v 1.1.9 2005/02/07 03:18:31 acassen Exp $
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
 *
 * Copyright (C) 2001-2005 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include <dirent.h>
#include <dlfcn.h>
#include "check_api.h"
#include "main.h"
#include "parser.h"
#include "memory.h"
#include "utils.h"
#include "global_data.h"
#include "check_misc.h"
#include "check_smtp.h"
#include "check_tcp.h"
#include "check_http.h"
#include "check_ssl.h"

/* Global vars */
static checker_id_t ncheckers = 0;
list checkers_queue;

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

/* Queue a checker into the checkers_queue */
void
queue_checker(void (*free) (void *), void (*dump) (void *)
	      , int (*launch) (struct _thread *)
	      , void *data)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	real_server *rs = LIST_TAIL_DATA(vs->rs);
	checker *chk = (checker *) MALLOC(sizeof (checker));

	chk->free = free;
	chk->dump = dump;
	chk->launch = launch;
	chk->vs = vs;
	chk->rs = rs;
	chk->data = data;
	chk->id = ncheckers++;
	chk->enabled = (vs->vfwmark) ? 1 : 0;
#ifdef _WITHOUT_VRRP_
	chk->enabled = 1;
#endif

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

/* init the global checkers queue */
void
init_checkers_queue(void)
{
	checkers_queue = alloc_list(free_checker, dump_checker);
}

/* release the checkers_queue */
void
free_checkers_queue(void)
{
	free_list(checkers_queue);
	ncheckers = 0;
}

/* register checkers to the global I/O scheduler */
void
register_checkers_thread(void)
{
	checker *checker;
	element e;

	for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
		checker = ELEMENT_DATA(e);
		syslog(LOG_INFO,
		       "Activating healtchecker for service [%s:%d]",
		       inet_ntop2(CHECKER_RIP(checker)),
		       ntohs(CHECKER_RPORT(checker)));
		CHECKER_ENABLE(checker);
		if (checker->launch)
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

	/* Display netlink operation */
	if (debug & 32)
		syslog(LOG_INFO, "Netlink reflector reports IP %s %s",
		       inet_ntop2(address), (enable) ? "added" : "removed");

	/* Processing Healthcheckers queue */
	if (!LIST_ISEMPTY(checkers_queue))
		for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
			checker = ELEMENT_DATA(e);
			if (CHECKER_VIP(checker) == address && CHECKER_HA_SUSPEND(checker)) {
				if (!CHECKER_ENABLED(checker) && enable)
					syslog(LOG_INFO,
					       "Activating healtchecker for service [%s:%d]",
					       inet_ntop2(CHECKER_RIP(checker)),
					       ntohs(CHECKER_RPORT(checker)));
				if (CHECKER_ENABLED(checker) && !enable)
					syslog(LOG_INFO,
					       "Suspending healtchecker for service [%s:%d]",
					       inet_ntop2(CHECKER_RIP(checker)),
					       ntohs(CHECKER_RPORT(checker)));
				checker->enabled = enable;
			}
		}
}

/* Install checkers keywords */
void
install_checkers_keyword(void)
{
	install_misc_check_keyword();
	install_smtp_check_keyword();
	install_tcp_check_keyword();
	install_http_check_keyword();
	install_ssl_check_keyword();
}
