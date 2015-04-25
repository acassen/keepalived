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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#include <dirent.h>
#include <dlfcn.h>
#include "check_api.h"
#include "main.h"
#include "parser.h"
#include "memory.h"
#include "utils.h"
#include "logger.h"
#include "bitops.h"
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
	checker_t *checker= data;
	(*checker->free_func) (checker);
}

/* dump checker data */
static void
dump_checker(void *data)
{
	checker_t *checker = data;
	log_message(LOG_INFO, " %s", FMT_CHK(checker));
	(*checker->dump_func) (checker);
}

void
dump_conn_opts (conn_opts_t *conn)
{
	log_message(LOG_INFO, "   Connection dest = %s", inet_sockaddrtopair(&conn->dst));
	if (conn->bindto.ss_family)
		log_message(LOG_INFO, "   Bind to = %s", inet_sockaddrtopair(&conn->bindto));
#ifdef _WITH_SO_MARK_
	if (conn->fwmark != 0)
		log_message(LOG_INFO, "   Connection mark = %u", conn->fwmark);
#endif
	log_message(LOG_INFO, "   Connection timeout = %d", conn->connection_to/TIMER_HZ);
}

/* Queue a checker into the checkers_queue */
void
queue_checker(void (*free_func) (void *), void (*dump_func) (void *)
	      , int (*launch) (thread_t *)
	      , void *data
	      , conn_opts_t *co)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	checker_t *checker = (checker_t *) MALLOC(sizeof (checker_t));

	/* Set default dst = RS, timeout = 5 */
	if (co) {
		co->dst = rs->addr;
		co->connection_to = 5 * TIMER_HZ;
	}

	checker->free_func = free_func;
	checker->dump_func = dump_func;
	checker->launch = launch;
	checker->vs = vs;
	checker->rs = rs;
	checker->data = data;
	checker->co = co;
	checker->id = ncheckers++;
	checker->enabled = (vs->vfwmark) ? 1 : 0;
	checker->warmup = vs->delay_loop;
#ifdef _WITHOUT_VRRP_
	checker->enabled = 1;
#endif

	/* queue the checker */
	list_add(checkers_queue, checker);

	/* In Alpha mode also mark the check as failed. */
	if (vs->alpha) {
		list fc = rs->failed_checkers;
		checker_id_t *id = (checker_id_t *) MALLOC(sizeof(checker_id_t));
		*id = checker->id;
		list_add (fc, id);
	}
}

/* Set dst */
void
checker_set_dst(struct sockaddr_storage *dst)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);

	*dst = rs->addr;
}

void
checker_set_dst_port(struct sockaddr_storage *dst, uint16_t port)
{
	if (dst->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) dst;
		addr6->sin6_port = port;
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) dst;
		addr4->sin_port = port;
	}
}

/* "connect_ip" keyword */
static void
co_ip_handler(vector_t *strvec)
{
	conn_opts_t *co = CHECKER_GET_CO();
	inet_stosockaddr(vector_slot(strvec, 1), 0, &co->dst);
}

/* "connect_port" keyword */
static void
co_port_handler(vector_t *strvec)
{
	conn_opts_t *co = CHECKER_GET_CO();
	checker_set_dst_port(&co->dst, htons(CHECKER_VALUE_INT(strvec)));
}

/* "bindto" keyword */
static void
co_srcip_handler(vector_t *strvec)
{
	conn_opts_t *co = CHECKER_GET_CO();
	inet_stosockaddr(vector_slot(strvec, 1), 0, &co->bindto);
}

/* "bind_port" keyword */
static void
co_srcport_handler(vector_t *strvec)
{
	conn_opts_t *co = CHECKER_GET_CO();
	checker_set_dst_port(&co->bindto, htons(CHECKER_VALUE_INT(strvec)));
}

/* "connect_timeout" keyword */
static void
co_timeout_handler(vector_t *strvec)
{
	conn_opts_t *co = CHECKER_GET_CO();
	co->connection_to = CHECKER_VALUE_INT(strvec) * TIMER_HZ;

	/* do not allow 0 timeout */
	if (! co->connection_to)
		co->connection_to = TIMER_HZ;
}

#ifdef _WITH_SO_MARK_
/* "fwmark" keyword */
static void
co_fwmark_handler(vector_t *strvec)
{
	conn_opts_t *co = CHECKER_GET_CO();
	co->fwmark = CHECKER_VALUE_INT(strvec);
}
#endif

void
install_connect_keywords(void)
{
	install_keyword("connect_ip", &co_ip_handler);
	install_keyword("connect_port", &co_port_handler);
	install_keyword("bindto", &co_srcip_handler);
	install_keyword("bind_port", &co_srcport_handler);
	install_keyword("connect_timeout", &co_timeout_handler);
#ifdef _WITH_SO_MARK_
	install_keyword("fwmark", &co_fwmark_handler);
#endif
}

/* "warmup" keyword */
void warmup_handler(vector_t *strvec)
{
	checker_t *checker = CHECKER_GET_CURRENT();
	checker->warmup = (long)CHECKER_VALUE_INT (strvec) * TIMER_HZ;
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
	checker_t *checker;
	element e;
	long warmup;

	for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
		checker = ELEMENT_DATA(e);
		log_message(LOG_INFO, "Activating healthchecker for service %s"
				    , FMT_CHK(checker));
		CHECKER_ENABLE(checker);
		if (checker->launch)
		{
			/* wait for a random timeout to begin checker thread.
			   It helps avoiding multiple simultaneous checks to
			   the same RS.
			*/
			warmup = checker->warmup;
			if (warmup)
				warmup = warmup * rand() / RAND_MAX;
			thread_add_timer(master, checker->launch, checker,
					 BOOTSTRAP_DELAY + warmup);
		}
	}
}

/* Sync checkers activity with netlink kernel reflection */
void
update_checker_activity(sa_family_t family, void *address, int enable)
{
	checker_t *checker;
	sa_family_t vip_family;
	element e;
	char addr_str[INET6_ADDRSTRLEN];
	void *addr;

	/* Display netlink operation */
	if (__test_bit(LOG_DETAIL_BIT, &debug)) {
		inet_ntop(family, address, addr_str, sizeof(addr_str));
		log_message(LOG_INFO, "Netlink reflector reports IP %s %s"
				    , addr_str, (enable) ? "added" : "removed");
	}

	/* Processing Healthcheckers queue */
	if (!LIST_ISEMPTY(checkers_queue)) {
		for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
			checker = ELEMENT_DATA(e);
			vip_family = checker->vs->addr.ss_family;

			if (vip_family != family)
				continue;

			if (family == AF_INET6) {
				addr = (void *) &((struct sockaddr_in6 *)&checker->vs->addr)->sin6_addr;
			} else {
				addr = (void *) &((struct sockaddr_in *)&checker->vs->addr)->sin_addr;
			}

			if (inaddr_equal(family, addr, address) &&
			    CHECKER_HA_SUSPEND(checker)) {
				if (!CHECKER_ENABLED(checker) && enable)
					log_message(LOG_INFO, "Activating healthchecker for service %s"
							    , FMT_CHK(checker));
				if (CHECKER_ENABLED(checker) && !enable)
					log_message(LOG_INFO, "Suspending healthchecker for service %s"
							    , FMT_CHK(checker));
				checker->enabled = enable;
			}
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
