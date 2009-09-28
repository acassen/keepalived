/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Checkers registration.
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
 * Copyright (C) 2001-2009 Alexandre Cassen, <acassen@freebox.fr>
 */

#include <dirent.h>
#include <dlfcn.h>
#include "check_api.h"
#include "main.h"
#include "parser.h"
#include "memory.h"
#include "utils.h"
#include "logger.h"
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
free_checker(void *chk_data_obj)
{
	checker *checker_obj = chk_data_obj;
	(*checker_obj->free_func) (checker_obj);
}

/* dump checker data */
static void
dump_checker(void *data_obj)
{
	checker *checker_obj = data_obj;
	log_message(LOG_INFO, " %s:%d", inet_ntop2(CHECKER_RIP(checker_obj))
	       , ntohs(CHECKER_RPORT(checker_obj)));
	(*checker_obj->dump_func) (checker_obj);
}

/* Queue a checker into the checkers_queue */
void
queue_checker(void (*free_func) (void *), void (*dump_func) (void *)
	      , int (*launch) (struct _thread *)
	      , void *data_obj)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	real_server *rs = LIST_TAIL_DATA(vs->rs);
	checker *check_obj = (checker *) MALLOC(sizeof (checker));

	check_obj->free_func = free_func;
	check_obj->dump_func = dump_func;
	check_obj->launch = launch;
	check_obj->vs = vs;
	check_obj->rs = rs;
	check_obj->data = data_obj;
	check_obj->id = ncheckers++;
	check_obj->enabled = (vs->vfwmark) ? 1 : 0;
#ifdef _WITHOUT_VRRP_
	check_obj->enabled = 1;
#endif

	/* queue the checker */
	list_add(checkers_queue, check_obj);

	/* In Alpha mode also mark the check as failed. */
	if (vs->alpha) {
		list fc = rs->failed_checkers;
		checker_id_t *id = (checker_id_t *) MALLOC(sizeof(checker_id_t));
		*id = check_obj->id;
		list_add (fc, id);
	}
}

/* dump the checkers_queue */
void
dump_checkers_queue(void)
{
	if (!LIST_ISEMPTY(checkers_queue)) {
		log_message(LOG_INFO, "------< Health checkers >------");
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
	checkers_queue = NULL;
	ncheckers = 0;
}

/* register checkers to the global I/O scheduler */
void
register_checkers_thread(void)
{
	checker *checker_obj;
	element e;

	for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
		checker_obj = ELEMENT_DATA(e);
		log_message(LOG_INFO,
		       "Activating healtchecker for service [%s:%d]",
		       inet_ntop2(CHECKER_RIP(checker_obj)),
		       ntohs(CHECKER_RPORT(checker_obj)));
		CHECKER_ENABLE(checker_obj);
		if (checker_obj->launch)
			thread_add_timer(master, checker_obj->launch, checker_obj,
					 BOOTSTRAP_DELAY);
	}
}

/* Sync checkers activity with netlink kernel reflection */
void
update_checker_activity(uint32_t address, int enable)
{
	checker *checker_obj;
	element e;

	/* Display netlink operation */
	if (debug & 32)
		log_message(LOG_INFO, "Netlink reflector reports IP %s %s",
		       inet_ntop2(address), (enable) ? "added" : "removed");

	/* Processing Healthcheckers queue */
	if (!LIST_ISEMPTY(checkers_queue))
		for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
			checker_obj = ELEMENT_DATA(e);
			if (CHECKER_VIP(checker_obj) == address && CHECKER_HA_SUSPEND(checker_obj)) {
				if (!CHECKER_ENABLED(checker_obj) && enable)
					log_message(LOG_INFO,
					       "Activating healtchecker for service [%s:%d]",
					       inet_ntop2(CHECKER_RIP(checker_obj)),
					       ntohs(CHECKER_RPORT(checker_obj)));
				if (CHECKER_ENABLED(checker_obj) && !enable)
					log_message(LOG_INFO,
					       "Suspending healtchecker for service [%s:%d]",
					       inet_ntop2(CHECKER_RIP(checker_obj)),
					       ntohs(CHECKER_RPORT(checker_obj)));
				checker_obj->enabled = enable;
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
