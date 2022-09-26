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
#include "check_ping.h"
#include "check_udp.h"
#include "check_file.h"
#include "ipwrapper.h"
#include "check_daemon.h"
#ifdef _WITH_BFD_
#include "check_bfd.h"
#include "bfd_event.h"
#include "bfd_daemon.h"
#endif
#include "track_file.h"
#include "check_parser.h"


/* Global vars */
LIST_HEAD_INITIALIZE(checkers_queue);
#ifdef _CHECKER_DEBUG_
bool do_checker_debug;
#endif
checker_t *current_checker;

/* free checker data */
void
free_checker(checker_t *checker)
{
	list_del_init(&checker->e_list);
	(*checker->checker_funcs->free_func) (checker);
}
void
free_checker_list(list_head_t *l)
{
	checker_t *checker, *checker_tmp;

	list_for_each_entry_safe(checker, checker_tmp, l, e_list)
		free_checker(checker);
}

/* dump checker data */
static void
dump_checker(FILE *fp, const checker_t *checker)
{
	conf_write(fp, " %s -> %s", FMT_VS(checker->vs), FMT_CHK(checker));
	conf_write(fp, "   Enabled = %s", checker->enabled ? "yes" : "no");
	conf_write(fp, "   Up = %s", checker->is_up ? "yes" : "no");
	conf_write(fp, "   Has run = %s", checker->has_run ? "yes" : "no");
	conf_write(fp, "   Current weight = %d", checker->cur_weight);
	if (checker->checker_funcs->type != CHECKER_FILE) {
		conf_write(fp, "   Alpha = %s", checker->alpha ? "yes" : "no");
		conf_write(fp, "   Delay loop = %lu us", checker->delay_loop);
		conf_write(fp, "   Warmup = %lu us", checker->warmup);
		conf_write(fp, "   Retries = %u", checker->retry);
		if (checker->retry) {
			conf_write(fp, "   Delay before retry = %lu us", checker->delay_before_retry);
			conf_write(fp, "   Retries iterations = %u", checker->retry_it);
		}
		conf_write(fp, "   Default delay before retry = %lu us", checker->default_delay_before_retry);
	}
	conf_write(fp, "   Log all failures = %s", checker->log_all_failures ? "yes" : "no");

	if (checker->co) {
		conf_write(fp, "   Connection");
		dump_connection_opts(fp, checker->co);
	}

	(*checker->checker_funcs->dump_func) (fp, checker);
}
static void
dump_checker_list(FILE *fp, const list_head_t *l)
{
	checker_t *checker;

	list_for_each_entry(checker, l, e_list)
		dump_checker(fp, checker);
}

void
dump_connection_opts(FILE *fp, const void *data)
{
	const conn_opts_t *conn = data;

	conf_write(fp, "     Dest = %s", inet_sockaddrtopair(&conn->dst));
	if (conn->bindto.ss_family)
		conf_write(fp, "     Bind to = %s", inet_sockaddrtopair(&conn->bindto));
	if (conn->bind_if[0])
		conf_write(fp, "     Bind i/f = %s", conn->bind_if);
#ifdef _WITH_SO_MARK_
	if (conn->fwmark != 0)
		conf_write(fp, "     Mark = %u", conn->fwmark);
#endif
	conf_write(fp, "     Timeout = %f", (double)conn->connection_to / TIMER_HZ);
	if (conn->last_errno)
		conf_write(fp, "     Last errno = %d", conn->last_errno);
}

/* Queue a checker into the checkers_queue */
void
queue_checker(const checker_funcs_t *funcs
	      , thread_func_t launch
	      , void *data
	      , conn_opts_t *co
	      , bool fd_required)
{
	checker_t *checker;

	/* Set default dst = RS, timeout = default */
	if (co) {
		co->dst = current_rs->addr;
		co->connection_to = UINT_MAX;
	}

	PMALLOC(checker);
	INIT_LIST_HEAD(&checker->e_list);
	checker->checker_funcs = funcs;
	checker->launch = launch;
	checker->vs = current_vs;
	checker->rs = current_rs;
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

	if (fd_required)
		check_data->num_checker_fd_required++;

	current_checker = checker;
}

void
dequeue_new_checker(void)
{
// TODO - queue checker at end, not at start
	if (!current_checker->is_up)
		set_checker_state(current_checker, true);

	free_checker(current_checker);

	current_checker = NULL;
}

bool
check_conn_opts(conn_opts_t *co)
{
	if (co->dst.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_LINKLOCAL(&PTR_CAST(struct sockaddr_in6, &co->dst)->sin6_addr) &&
	    !co->bind_if[0]) {
		report_config_error(CONFIG_GENERAL_ERROR, "Checker link local address %s requires a bind_if", inet_sockaddrtos(&co->dst));
		return false;
	}

	return true;
}

bool __attribute__ ((pure))
compare_conn_opts(const conn_opts_t *a, const conn_opts_t *b)
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
checker_set_dst_port(sockaddr_t *dst, uint16_t port)
{
	/* NOTE: we are relying on the offset of sin_port and sin6_port being
	 * the same if an IPv6 address is specified after the port */
	if (dst->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = PTR_CAST(struct sockaddr_in6, dst);
		addr6->sin6_port = port;
	} else if (dst->ss_family == AF_UNSPEC &&
		   offsetof(struct sockaddr_in6, sin6_port) != offsetof(struct sockaddr_in, sin_port)) {
		log_message(LOG_INFO, "BUG: checker_set_dst_port() in/in6 port offsets differ");
	} else {
		struct sockaddr_in *addr4 = PTR_CAST(struct sockaddr_in, dst);
		addr4->sin_port = port;
	}
}

/* "connect_ip" keyword */
static void
co_ip_handler(const vector_t *strvec)
{
	conn_opts_t *co = current_checker->co;

	if (inet_stosockaddr(strvec_slot(strvec, 1), NULL, &co->dst))
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid connect_ip address %s - ignoring", strvec_slot(strvec, 1));
	else if (co->bindto.ss_family != AF_UNSPEC &&
		 co->bindto.ss_family != co->dst.ss_family) {
		report_config_error(CONFIG_GENERAL_ERROR, "connect_ip address %s does not match address family of bindto - skipping", strvec_slot(strvec, 1));
		co->dst.ss_family = AF_UNSPEC;
	}
}

/* "connect_port" keyword */
static void
co_port_handler(const vector_t *strvec)
{
	conn_opts_t *co = current_checker->co;
	unsigned port;

	if (!read_unsigned_strvec(strvec, 1, &port, 1, 65535, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid checker connect_port '%s'", strvec_slot(strvec, 1));
		return;
	}

	checker_set_dst_port(&co->dst, htons(port));
}

/* "bindto" keyword */
static void
co_srcip_handler(const vector_t *strvec)
{
	conn_opts_t *co = current_checker->co;

	if (inet_stosockaddr(strvec_slot(strvec, 1), NULL, &co->bindto))
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid bindto address %s - ignoring", strvec_slot(strvec, 1));
	else if (co->dst.ss_family != AF_UNSPEC &&
		 co->dst.ss_family != co->bindto.ss_family) {
		report_config_error(CONFIG_GENERAL_ERROR, "bindto address %s does not match address family of connect_ip - skipping", strvec_slot(strvec, 1));
		co->bindto.ss_family = AF_UNSPEC;
	}
}

/* "bind_port" keyword */
static void
co_srcport_handler(const vector_t *strvec)
{
	conn_opts_t *co = current_checker->co;
	unsigned port;

	if (!read_unsigned_strvec(strvec, 1, &port, 1, 65535, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid checker bind_port '%s'", strvec_slot(strvec, 1));
		return;
	}

	checker_set_dst_port(&co->bindto, htons(port));
}

/* "bind_if" keyword */
static void
co_srcif_handler(const vector_t *strvec)
{
	// This is needed for link local IPv6 bindto address
	conn_opts_t *co = current_checker->co;

	if (strlen(strvec_slot(strvec, 1)) > sizeof(co->bind_if) - 1) {
		report_config_error(CONFIG_GENERAL_ERROR, "Interface name %s is too long - ignoring", strvec_slot(strvec, 1));
		return;
	}
	strcpy(co->bind_if, strvec_slot(strvec, 1));
}

/* "connect_timeout" keyword */
static void
co_timeout_handler(const vector_t *strvec)
{
	conn_opts_t *co = current_checker->co;
	unsigned long timer;

	if (!read_timer(strvec, 1, &timer, 1, UINT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "connect_timeout %s invalid - ignoring", strvec_slot(strvec, 1));
		return;
	}
	co->connection_to = timer;
}

#ifdef _WITH_SO_MARK_
/* "fwmark" keyword */
static void
co_fwmark_handler(const vector_t *strvec)
{
	conn_opts_t *co = current_checker->co;
	unsigned fwmark;

	if (!read_unsigned_strvec(strvec, 1, &fwmark, 0, UINT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid fwmark connection value '%s'", strvec_slot(strvec, 1));
		return;
	}
	co->fwmark = fwmark;
}
#endif

static void
retry_handler(const vector_t *strvec)
{
	checker_t *checker = current_checker;
	unsigned retry;

	if (!read_unsigned_strvec(strvec, 1, &retry, 0, UINT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid retry connection value '%s'", strvec_slot(strvec, 1));
		return;
	}

	checker->retry = retry;
}

static void
delay_before_retry_handler(const vector_t *strvec)
{
	checker_t *checker = current_checker;
	unsigned long delay;

	if (!read_timer(strvec, 1, &delay, 0, 0, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid delay_before_retry connection value '%s'", strvec_slot(strvec, 1));
		return;
	}

	checker->delay_before_retry = delay;
}

/* "warmup" keyword */
static void
warmup_handler(const vector_t *strvec)
{
	checker_t *checker = current_checker;
	unsigned long warmup;

	if (!read_timer(strvec, 1, &warmup, 0, 0, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid warmup connection value '%s'", strvec_slot(strvec, 1));
		return;
	}

	checker->warmup = warmup;
}

static void
delay_handler(const vector_t *strvec)
{
	checker_t *checker = current_checker;
	unsigned long delay_loop;

	if (!read_timer(strvec, 1, &delay_loop, 1, 0, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "delay_loop '%s' is invalid - ignoring", strvec_slot(strvec, 1));
		return;
	}

	checker->delay_loop = delay_loop;
}

static void
alpha_handler(const vector_t *strvec)
{
	checker_t *checker = current_checker;
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res == -1) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid alpha parameter %s", strvec_slot(strvec, 1));
			return;
		}
	}
	checker->alpha = res;
}
static void
log_all_failures_handler(const vector_t *strvec)
{
	checker_t *checker = current_checker;
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res == -1) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid log_all_failures parameter %s", strvec_slot(strvec, 1));
			return;
		}
	}
	checker->log_all_failures = res;
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
	install_keyword("log_all_failures", &log_all_failures_handler);
}

/* dump the checkers_queue */
void
dump_checkers_queue(FILE *fp)
{
	if (!list_empty(&checkers_queue)) {
		conf_write(fp, "------< Health checkers >------");
		dump_checker_list(fp, &checkers_queue);
	}
}

/* init the global checkers queue */
void
init_checkers_queue(void)
{
	INIT_LIST_HEAD(&checkers_queue);
}

/* release the checkers for a virtual server */
void
free_vs_checkers(const virtual_server_t *vs)
{
	checker_t *checker, *checker_tmp;

	list_for_each_entry_safe(checker, checker_tmp, &checkers_queue, e_list) {
		if (checker->vs != vs)
			continue;

		free_checker(checker);
	}
}

/* release the checkers for a virtual server */
void
free_rs_checkers(const real_server_t *rs)
{
	checker_t *checker, *checker_tmp;

	list_for_each_entry_safe(checker, checker_tmp, &checkers_queue, e_list) {
		if (checker->rs != rs)
			continue;

		free_checker(checker);
	}
}

/* release the checkers_queue */
void
free_checkers_queue(void)
{
	free_checker_list(&checkers_queue);
}

/* register checkers to the global I/O scheduler */
void
register_checkers_thread(void)
{
	checker_t *checker;
	unsigned long warmup;

	list_for_each_entry(checker, &checkers_queue, e_list) {
		if (checker->launch) {
			if (checker->vs->ha_suspend && !checker->vs->ha_suspend_addr_count)
				checker->enabled = false;

			log_message(LOG_INFO, "%sctivating healthchecker for service %s for VS %s"
					    , checker->enabled ? "A" : "Dea"
					    , FMT_RS(checker->rs, checker->vs)
					    , FMT_VS(checker->vs));

			/* wait for a random timeout to begin checker thread.
			   It helps avoiding multiple simultaneous checks to
			   the same RS.
			*/
			warmup = checker->warmup;
			if (warmup) {
				/* coverity[dont_call] */
				warmup = warmup * (unsigned)random() / RAND_MAX;
			}
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
static bool __attribute__ ((pure))
addr_matches(const virtual_server_t *vs, void *address)
{
	virtual_server_group_entry_t *vsg_entry;
	struct in_addr mask_addr = {0};
	struct in6_addr mask_addr6 = {{{0}}};
	unsigned addr_base;
	const void *addr;

	if (vs->vsg)
		return false;

	if (vs->addr.ss_family != AF_UNSPEC) {
		if (vs->addr.ss_family == AF_INET6)
			addr = (const void *)&PTR_CAST_CONST(struct sockaddr_in6, &vs->addr)->sin6_addr;
		else
			addr = (const void *)&PTR_CAST_CONST(struct sockaddr_in, &vs->addr)->sin_addr;

		return inaddr_equal(vs->addr.ss_family, addr, address);
	}

	if (!vs->vsg || list_empty(&vs->vsg->addr_range))
		return false;

	if (vs->af == AF_INET) {
		mask_addr = *PTR_CAST(struct in_addr, address);
		addr_base = ntohl(mask_addr.s_addr) & 0xFF;
		mask_addr.s_addr &= htonl(0xFFFFFF00);
	} else {
		mask_addr6 = *PTR_CAST(struct in6_addr, address);
		addr_base = ntohs(mask_addr6.s6_addr16[7]);
		mask_addr6.s6_addr16[7] = 0;
	}

	list_for_each_entry(vsg_entry, &vs->vsg->addr_range, e_list) {
		uint32_t ra_base, ra_end;

		if (!inet_sockaddrcmp(&vsg_entry->addr, &vsg_entry->addr_end)) {
			if (vsg_entry->addr.ss_family == AF_INET6)
				addr = (void *)&PTR_CAST(struct sockaddr_in6, &vsg_entry->addr)->sin6_addr;
			else
				addr = (void *)&PTR_CAST(struct sockaddr_in, &vsg_entry->addr)->sin_addr;

			if (inaddr_equal(vsg_entry->addr.ss_family, addr, address))
				return true;

			continue;
		}

		if (vsg_entry->addr.ss_family == AF_INET) {
			struct in_addr ra;

			ra_base = ntohl(PTR_CAST(struct sockaddr_in, &vsg_entry->addr)->sin_addr.s_addr) & 0xFF;
			ra_end = ntohl(PTR_CAST(struct sockaddr_in, &vsg_entry->addr_end)->sin_addr.s_addr) & 0xFF;

			if (addr_base < ra_base || addr_base > ra_end)
				continue;

			ra = PTR_CAST(struct sockaddr_in, &vsg_entry->addr)->sin_addr;
			ra.s_addr &= htonl(0xFFFFFF00);
			if (ra.s_addr != mask_addr.s_addr)
				continue;
		} else {
			struct in6_addr ra;

			ra_base = ntohs(PTR_CAST(struct sockaddr_in6, &vsg_entry->addr)->sin6_addr.s6_addr16[7]);
			ra_end = ntohs(PTR_CAST(struct sockaddr_in6, &vsg_entry->addr_end)->sin6_addr.s6_addr16[7]);

			if (addr_base < ra_base || addr_base > ra_end)
				continue;

			ra = PTR_CAST(struct sockaddr_in6, &vsg_entry->addr)->sin6_addr;
			ra.s6_addr16[7] = 0;
			if (!inaddr_equal(AF_INET6, &ra, &mask_addr6))
				continue;
		}

		return true;
	}

	return false;
}

void
update_checker_activity(sa_family_t family, void *address, bool enable)
{
	checker_t *checker;
	virtual_server_t *vs;
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

	if (list_empty(&checkers_queue))
		return;

	/* Check if any of the virtual servers are using this address, and have ha_suspend */
	list_for_each_entry(vs, &check_data->vs, e_list) {
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
		list_for_each_entry(checker, &checkers_queue, e_list) {
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
	install_ping_check_keyword();
	install_udp_check_keyword();
	install_http_check_keyword();
	install_ssl_check_keyword();
	install_dns_check_keyword();
	install_file_check_keyword();
#ifdef _WITH_BFD_
	install_bfd_check_keyword();
#endif
}
