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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "check_api.h"
#include "main.h"
#include "parser.h"
#include "utils.h"
#include "logger.h"
#include "bitops.h"
#include "global_data.h"
#include "keepalived_netlink.h"
#include "check_misc.h"
#include "check_smtp.h"
#include "check_tcp.h"
#include "check_http.h"
#include "check_ssl.h"
#include "check_dns.h"
#include "ipwrapper.h"
#include "check_daemon.h"
#ifdef _WITH_BFD_
#include "check_bfd.h"
#include "bfd_event.h"
#include "bfd_daemon.h"
#endif

/* Global vars */
list checkers_queue;

/* free checker data */
static void
free_checker(void *data)
{
	checker_t *checker = data;
	(*checker->free_func) (checker);
}

/* dump checker data */
static void
dump_checker(FILE *fp, void *data)
{
	checker_t *checker = data;
	conf_write(fp, " %s", FMT_CHK(checker));
	(*checker->dump_func) (fp, checker);
}

void
dump_connection_opts(FILE *fp, void *data)
{
	conn_opts_t *conn = data;

	conf_write(fp, "     Dest = %s", inet_sockaddrtopair(&conn->dst));
	if (conn->bindto.ss_family)
		conf_write(fp, "     Bind to = %s", inet_sockaddrtopair(&conn->bindto));
	if (conn->bind_if[0])
		conf_write(fp, "     Bind i/f = %s", conn->bind_if);
#ifdef _WITH_SO_MARK_
	if (conn->fwmark != 0)
		conf_write(fp, "     Mark = %u", conn->fwmark);
#endif
	conf_write(fp, "     Timeout = %d", conn->connection_to/TIMER_HZ);
}

void
dump_checker_opts(FILE *fp, void *data)
{
	checker_t *checker = data;
	conn_opts_t *conn = checker->co;

	if (conn) {
		conf_write(fp, "   Connection");
		dump_connection_opts(fp, conn);
	}

	conf_write(fp, "   Alpha is %s", checker->alpha ? "ON" : "OFF");
	conf_write(fp, "   Delay loop = %lu" , checker->delay_loop / TIMER_HZ);
	if (checker->retry) {
		conf_write(fp, "   Retry count = %u" , checker->retry);
		conf_write(fp, "   Retry delay = %lu" , checker->delay_before_retry / TIMER_HZ);
	}
	conf_write(fp, "   Warmup = %lu", checker->warmup / TIMER_HZ);
}

/* Queue a checker into the checkers_queue */
checker_t *
queue_checker(void (*free_func) (void *), void (*dump_func) (FILE *, void *)
	      , int (*launch) (thread_t *)
	      , bool (*compare) (void *, void *)
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
	checker->compare = compare;
	checker->vs = vs;
	checker->rs = rs;
	checker->data = data;
	checker->co = co;
	checker->enabled = true;
	checker->alpha = -1;
	checker->delay_loop = ULONG_MAX;
	checker->warmup = ULONG_MAX;
	checker->retry = UINT_MAX;
	checker->delay_before_retry = ULONG_MAX;
	checker->retry_it = 0;
	checker->is_up = true;
	checker->default_delay_before_retry = 1 * TIMER_HZ;
	checker->default_retry = 1 ;

	/* queue the checker */
	list_add(checkers_queue, checker);

	return checker;
}

void
dequeue_new_checker(void)
{
	checker_t *checker = ELEMENT_DATA(checkers_queue->tail);

	if (!checker->is_up)
		set_checker_state(checker, true);

	free_list_element(checkers_queue, checkers_queue->tail);
}

bool
check_conn_opts(conn_opts_t *co)
{
	if (co->dst.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6*)&co->dst)->sin6_addr) &&
	    !co->bind_if[0]) {
		log_message(LOG_INFO, "Checker link local address %s requires a bind_if", inet_sockaddrtos(&co->dst));
		return false;
	}

	return true;
}

bool
compare_conn_opts(conn_opts_t *a, conn_opts_t *b)
{
	if (a == b)
		return true;

	if (!a || !b)
		return false;
	if (!sockstorage_equal(&a->dst, &b->dst))
		return false;
	if (!sockstorage_equal(&a->bindto, &b->bindto))
		return false;
	if (strcmp(a->bind_if, b->bind_if))
		return false;
	if (a->connection_to != b->connection_to)
		return false;
#ifdef _WITH_SO_MARK_
	if (a->fwmark != b->fwmark)
		return false;
#endif

	return true;
}

void
checker_set_dst_port(struct sockaddr_storage *dst, uint16_t port)
{
	/* NOTE: we are relying on the offset of sin_port and sin6_port being
	 * the same if an IPv6 address is specified after the port */
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

	if (inet_stosockaddr(strvec_slot(strvec, 1), 0, &co->dst))
		log_message(LOG_INFO, "Invalid connect_ip address %s - ignoring", FMT_STR_VSLOT(strvec, 1));
	else if (co->bindto.ss_family != AF_UNSPEC &&
		 co->bindto.ss_family != co->dst.ss_family) {
		log_message(LOG_INFO, "connect_ip address %s does not match address family of bindto - skipping", FMT_STR_VSLOT(strvec, 1));
		co->dst.ss_family = AF_UNSPEC;
	}
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
	if (inet_stosockaddr(strvec_slot(strvec, 1), 0, &co->bindto))
		log_message(LOG_INFO, "Invalid bindto address %s - ignoring", FMT_STR_VSLOT(strvec, 1));
	else if (co->dst.ss_family != AF_UNSPEC &&
		 co->dst.ss_family != co->bindto.ss_family) {
		log_message(LOG_INFO, "bindto address %s does not match address family of connect_ip - skipping", FMT_STR_VSLOT(strvec, 1));
		co->bindto.ss_family = AF_UNSPEC;
	}
}

/* "bind_port" keyword */
static void
co_srcport_handler(vector_t *strvec)
{
	conn_opts_t *co = CHECKER_GET_CO();
	checker_set_dst_port(&co->bindto, htons(CHECKER_VALUE_INT(strvec)));
}

/* "bind_if" keyword */
static void
co_srcif_handler(vector_t *strvec)
{
	// This is needed for link local IPv6 bindto address
	conn_opts_t *co = CHECKER_GET_CO();

	if (strlen(strvec_slot(strvec, 1)) > sizeof(co->bind_if) - 1) {
		log_message(LOG_INFO, "Interface name %s is too long - ignoring", FMT_STR_VSLOT(strvec, 1));
		return;
	}
	strcpy(co->bind_if, strvec_slot(strvec, 1));
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

static void
retry_handler(vector_t *strvec)
{
	checker_t *checker = CHECKER_GET_CURRENT();
	checker->retry = CHECKER_VALUE_UINT(strvec);
}

static void
delay_before_retry_handler(vector_t *strvec)
{
	checker_t *checker = CHECKER_GET_CURRENT();
	checker->delay_before_retry = CHECKER_VALUE_UINT(strvec) * TIMER_HZ;
}

/* "warmup" keyword */
static void
warmup_handler(vector_t *strvec)
{
	checker_t *checker = CHECKER_GET_CURRENT();
	checker->warmup = CHECKER_VALUE_UINT(strvec) * TIMER_HZ;
}

static void
delay_handler(vector_t *strvec)
{
	checker_t *checker = CHECKER_GET_CURRENT();
	checker->delay_loop = read_timer(strvec);
}

static void
alpha_handler(vector_t *strvec)
{
	checker_t *checker = CHECKER_GET_CURRENT();
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res == -1) {
			log_message(LOG_INFO, "Invalid alpha parameter %s", FMT_STR_VSLOT(strvec, 1));
			return;
		}
	}
	checker->alpha = res;
}
void
install_checker_common_keywords(bool connection_keywords)
{
	if (connection_keywords) {
		install_keyword("connect_ip", &co_ip_handler);
		install_keyword("connect_port", &co_port_handler);
		install_keyword("bindto", &co_srcip_handler);
		install_keyword("bind_port", &co_srcport_handler);
		install_keyword("bind_if", &co_srcif_handler);
		install_keyword("connect_timeout", &co_timeout_handler);
#ifdef _WITH_SO_MARK_
		install_keyword("fwmark", &co_fwmark_handler);
#endif
	}
	install_keyword("retry", &retry_handler);
	install_keyword("delay_before_retry", &delay_before_retry_handler);
	install_keyword("warmup", &warmup_handler);
	install_keyword("delay_loop", &delay_handler);
	install_keyword("alpha", &alpha_handler);
}

/* dump the checkers_queue */
void
dump_checkers_queue(FILE *fp)
{
	if (!LIST_ISEMPTY(checkers_queue)) {
		conf_write(fp, "------< Health checkers >------");
		dump_list(fp, checkers_queue);
	}
}

/* init the global checkers queue */
void
init_checkers_queue(void)
{
	checkers_queue = alloc_list(free_checker, dump_checker);
}

/* release the checkers for a virtual server */
void
free_vs_checkers(virtual_server_t *vs)
{
	element e;
	element next;
	checker_t *checker;

	if (LIST_ISEMPTY(checkers_queue))
		return;

	for (e = LIST_HEAD(checkers_queue); e; e = next) {
		next = e->next;

		checker = ELEMENT_DATA(e);
		if (checker->vs != vs)
			continue;

		free_list_element(checkers_queue, e);
	}
}

/* release the checkers_queue */
void
free_checkers_queue(void)
{
	if (!checkers_queue)
		return;

	free_list(&checkers_queue);
}

/* register checkers to the global I/O scheduler */
void
register_checkers_thread(void)
{
	checker_t *checker;
	element e;
	unsigned long warmup;

	LIST_FOREACH(checkers_queue, checker, e) {
		if (checker->launch)
		{
			if (checker->vs->ha_suspend && !checker->vs->ha_suspend_addr_count)
				checker->enabled = false;

			log_message(LOG_INFO, "%sctivating healthchecker for service %s for VS %s"
					    , checker->enabled ? "A" : "Dea", FMT_RS(checker->rs, checker->vs), FMT_VS(checker->vs));

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

#ifdef _WITH_BFD_
	log_message(LOG_INFO, "Activating BFD healthchecker");

	/* We need to always enable this, since the bfd process may write to the pipe, and we
	 * need to ensure that messages are stripped out. */
	start_bfd_monitoring(master);
#endif
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

	if (vs->vsg->addr_range) {
		element e;
		struct in_addr mask_addr = {0};
		struct in6_addr mask_addr6 = {{{0}}};
		unsigned addr_base;

		if (vs->af == AF_INET) {
			mask_addr = *(struct in_addr*)address;
			addr_base = ntohl(mask_addr.s_addr) & 0xFF;
			mask_addr.s_addr &= htonl(0xFFFFFF00);
		}
		else {
			mask_addr6 = *(struct in6_addr*)address;
			addr_base = ntohs(mask_addr6.s6_addr16[7]);
			mask_addr6.s6_addr16[7] = 0;
		}

		for (e = LIST_HEAD(vs->vsg->addr_range); e; ELEMENT_NEXT(e)) {
			vsg_entry = ELEMENT_DATA(e);
			struct sockaddr_storage range_addr = vsg_entry->addr;
			uint32_t ra_base;

			if (!vsg_entry->range) {
				if (vsg_entry->addr.ss_family == AF_INET6)
					addr = (void *) &((struct sockaddr_in6 *)&vsg_entry->addr)->sin6_addr;
				else
					addr = (void *) &((struct sockaddr_in *)&vsg_entry->addr)->sin_addr;

				if (inaddr_equal(vsg_entry->addr.ss_family, addr, address))
					return true;
			}
			else {
				if (range_addr.ss_family == AF_INET) {
					struct in_addr ra;

					ra = ((struct sockaddr_in *)&range_addr)->sin_addr;
					ra_base = ntohl(ra.s_addr) & 0xFF;

					if (addr_base < ra_base || addr_base > ra_base + vsg_entry->range)
						continue;

					ra.s_addr &= htonl(0xFFFFFF00);
					if (ra.s_addr != mask_addr.s_addr)
						continue;
				}
				else
				{
					struct in6_addr ra = ((struct sockaddr_in6 *)&range_addr)->sin6_addr;
					ra_base = ntohs(ra.s6_addr16[7]);

					if (addr_base < ra_base || addr_base > ra_base + vsg_entry->range)
						continue;

					ra.s6_addr16[7] = 0;
					if (!inaddr_equal(AF_INET6, &ra, &mask_addr6))
						continue;
				}

				return true;
			}
		}
	}

	return false;
}

void
update_checker_activity(sa_family_t family, void *address, bool enable)
{
	checker_t *checker;
	virtual_server_t *vs;
	element e, e1;
	char addr_str[INET6_ADDRSTRLEN];
	bool address_logged = false;

	if (__test_bit(LOG_ADDRESS_CHANGES, &debug)) {
		inet_ntop(family, address, addr_str, sizeof(addr_str));
		log_message(LOG_INFO, "Netlink reflector reports IP %s %s"
				    , addr_str, (enable) ? "added" : "removed");
		address_logged = true;
	}

	if (!using_ha_suspend)
		return;

	if (LIST_ISEMPTY(checkers_queue))
		return;

	/* Check if any of the virtual servers are using this address, and have ha_suspend */
	LIST_FOREACH(check_data->vs, vs, e) {
		if (!vs->ha_suspend)
			continue;

		/* If there is no address configured, the family will be AF_UNSPEC */
		if (vs->af != family)
			continue;

		if (!addr_matches(vs, address))
			continue;

		if (!address_logged &&
		    __test_bit(LOG_DETAIL_BIT, &debug)) {
			inet_ntop(family, address, addr_str, sizeof(addr_str));
			log_message(LOG_INFO, "Netlink reflector reports IP %s %s"
					    , addr_str, (enable) ? "added" : "removed");
		}
		address_logged = true;

		/* If we have that same address (IPv6 link local) on multiple interfaces,
		 * we want to count them multiple times so that we only suspend the checkers
		 * if they are all deleted */
		if (enable)
			vs->ha_suspend_addr_count++;
		else
			vs->ha_suspend_addr_count--;

		/* Processing Healthcheckers queue for this vs */
		LIST_FOREACH(checkers_queue, checker, e1) {
			if (checker->vs != vs)
				continue;

			if (enable != checker->enabled &&
			    (enable || vs->ha_suspend_addr_count == 0)) {
				log_message(LOG_INFO, "%sing healthchecker for service %s for VS %s",
							!checker->enabled ? "Activat" : "Suspend",
							FMT_RS(checker->rs, checker->vs), FMT_VS(checker->vs));
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
#ifdef _WITH_BFD_
	install_bfd_check_keyword();
#endif
}
