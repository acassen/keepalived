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

#include "config.h"

#include <dirent.h>
#include <dlfcn.h>
#include <stdint.h>

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
#include "check_dns.h"

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
dump_conn_opts(void *data)
{
	conn_opts_t *conn = data;
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
	/* Enable the checker if the virtual server is not configured with ha_suspend */
	checker->enabled = !vs->ha_suspend;
	checker->warmup = vs->delay_loop;

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

static void
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
	inet_stosockaddr(strvec_slot(strvec, 1), 0, &co->dst);
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
	inet_stosockaddr(strvec_slot(strvec, 1), 0, &co->bindto);
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
	co->connection_to = CHECKER_VALUE_UINT(strvec) * TIMER_HZ;

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
	co->fwmark = CHECKER_VALUE_UINT(strvec);
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
	checker->warmup = CHECKER_VALUE_UINT(strvec) * TIMER_HZ;
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
	free_list(&checkers_queue);
	ncheckers = 0;
}

/* register checkers to the global I/O scheduler */
void
register_checkers_thread(void)
{
	checker_t *checker;
	element e;
	unsigned long warmup;

	for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
		checker = ELEMENT_DATA(e);
		log_message(LOG_INFO, "%sctivating healthchecker for service %s"
				    , checker->enabled ? "A" : "Dea", FMT_VS(checker->vs));
		if (checker->launch)
		{
			/* wait for a random timeout to begin checker thread.
			   It helps avoiding multiple simultaneous checks to
			   the same RS.
			*/
			warmup = checker->warmup;
			if (warmup)
				warmup = warmup * (unsigned)rand() / RAND_MAX;
			thread_add_timer(master, checker->launch, checker,
					 BOOTSTRAP_DELAY + warmup);
		}
	}
}

/* Sync checkers activity with netlink kernel reflection */
static bool
addr_matches(const virtual_server_t *vs, void *address)
{
	void *addr;
        virtual_server_group_entry_t *vsg_entry;

	if (vs->addr.ss_family != AF_UNSPEC) {
		if (vs->addr.ss_family == AF_INET6)
			addr = (void *) &((struct sockaddr_in6 *)&vs->addr)->sin6_addr;
		else
			addr = (void *) &((struct sockaddr_in *)&vs->addr)->sin_addr;

		return inaddr_equal(vs->addr.ss_family, addr, address);
	}

	if (!vs->vsg)
		return false;

	if (vs->vsg->addr_ip) {
		element e;
		for (e = LIST_HEAD(vs->vsg->addr_ip); e; ELEMENT_NEXT(e)) {
			vsg_entry = ELEMENT_DATA(e);

			if (vsg_entry->addr.ss_family == AF_INET6)
				addr = (void *) &((struct sockaddr_in6 *)&vsg_entry->addr)->sin6_addr;
			else
				addr = (void *) &((struct sockaddr_in *)&vsg_entry->addr)->sin_addr;

			if (inaddr_equal(vsg_entry->addr.ss_family, addr, address))
				return true;
		}
	}

	if (vs->vsg->range) {
		element e;
		struct in_addr mask_addr = {0};
		struct in6_addr mask_addr6 = {{{0}}};
		unsigned addr_base;

		if (vs->af == AF_INET) {
			mask_addr = *(struct in_addr*)address;
			addr_base = htonl(mask_addr.s_addr & htonl(0xFF));
			mask_addr.s_addr &= htonl(0xFFFFFF00);
		}
		else {
			mask_addr6 = *(struct in6_addr*)address;
			addr_base = htons(mask_addr6.s6_addr16[7]);
			mask_addr6.s6_addr16[7] = 0;
		}

		for (e = LIST_HEAD(vs->vsg->range); e; ELEMENT_NEXT(e)) {
			vsg_entry = ELEMENT_DATA(e);
			struct sockaddr_storage range_addr = vsg_entry->addr;
			uint32_t ra_base;

			if (range_addr.ss_family == AF_INET) {
				struct in_addr ra;

				ra = ((struct sockaddr_in *)&range_addr)->sin_addr;
				ra_base = htonl(ra.s_addr & htonl(0xFF));

				if (addr_base < ra_base || addr_base > vsg_entry->range)
					continue;

				ra.s_addr &= htonl(0xFFFFFF00);
				if (ra.s_addr != mask_addr.s_addr)
					continue;
			}
			else
			{
				struct in6_addr ra = ((struct sockaddr_in6 *)&range_addr)->sin6_addr;
				ra_base = htons(ra.s6_addr16[7]);

				if (addr_base < ra_base || addr_base > htons(vsg_entry->range))
					continue;

				ra.s6_addr16[7] = 0;
				if (!inaddr_equal(AF_INET6, &ra, &mask_addr6))
					continue;
			}

			return true;
		}
	}

	return false;
}

void
update_checker_activity(sa_family_t family, void *address, bool enable)
{
	checker_t *checker;
	element e;
	char addr_str[INET6_ADDRSTRLEN];
	bool address_logged = false;

	/* Display netlink operation */
	if (__test_bit(LOG_ADDRESS_CHANGES, &debug)) {
		inet_ntop(family, address, addr_str, sizeof(addr_str));
		log_message(LOG_INFO, "Netlink reflector reports IP %s %s"
				    , addr_str, (enable) ? "added" : "removed");

		address_logged = true;
	}

	if (!using_ha_suspend)
		return;

	/* Processing Healthcheckers queue */
	if (!LIST_ISEMPTY(checkers_queue)) {
		for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
			checker = ELEMENT_DATA(e);

			if (!CHECKER_HA_SUSPEND(checker))
				continue;

			/* If there is no address configured, the family will be AF_UNSPEC */
			if (checker->vs->af != family)
				continue;

			/* If we have that same address (IPv6 link local) on multiple interfaces,
			 * we want to count them multiple times so that we only suspend the checkers
			 * if they are all deleted */
			if (addr_matches(checker->vs, address)) {
				if (!address_logged &&
				    __test_bit(LOG_DETAIL_BIT, &debug)) {
					inet_ntop(family, address, addr_str, sizeof(addr_str));
					log_message(LOG_INFO, "Netlink reflector reports IP %s %s"
							    , addr_str, (enable) ? "added" : "removed");
				}
				address_logged = true;

				if (enable)
					checker->vs->ha_suspend_addr_count++;
				else
					checker->vs->ha_suspend_addr_count--;
			}

			if ((!(checker->vs->ha_suspend_addr_count)) == checker->enabled) {
				log_message(LOG_INFO, "%sing healthchecker for service %s",
							!checker->enabled ? "Activat" : "Suspend",
							FMT_VS(checker->vs));
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
	install_dns_check_keyword();
}
