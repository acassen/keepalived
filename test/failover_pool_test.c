/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Test of the virtual server failover pool state machine.
 *
 *              The test is linked with the same libraries as keepalived,
 *              so it builds with whatever configure options and optional
 *              libraries keepalived is built with. Only the IPVS kernel
 *              interface (libipvs) and the running of notify scripts are
 *              replaced, using the linker's --wrap option. The replacement
 *              keeps a model of the IPVS destination table, so that both
 *              the commands issued and the resulting table can be checked.
 *
 *              It is run by "make check". Set FAILOVER_POOL_TEST_VERBOSE
 *              in the environment to see keepalived's log messages.
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
 * Copyright (C) 2026 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "check_data.h"
#include "check_api.h"
#include "ipwrapper.h"
#include "ipvswrapper.h"
#include "libipvs.h"
#include "global_data.h"
#include "check_daemon.h"
#include "main.h"
#include "logger.h"
#include "notify.h"
#include "utils.h"
#include "bitops.h"

/* The replacements for the wrapped functions */
int __wrap_ipvs_add_service(ipvs_service_t *);
int __wrap_ipvs_update_service(ipvs_service_t *);
int __wrap_ipvs_del_service(ipvs_service_t *);
int __wrap_ipvs_add_dest(ipvs_service_t *, ipvs_dest_t *);
int __wrap_ipvs_update_dest(ipvs_service_t *, ipvs_dest_t *);
int __wrap_ipvs_del_dest(ipvs_service_t *, ipvs_dest_t *);
int __wrap_notify_exec(const notify_script_t *);

static unsigned fails;
static unsigned passes;

/*
 * Names of the real servers, by address, and of the notify scripts
 */
#define MAX_NAMES	64

static struct {
	uint32_t	addr;
	const char	*name;
} rs_names[MAX_NAMES];
static unsigned num_rs_names;

static struct {
	const notify_script_t	*script;
	const char		*name;
} script_names[MAX_NAMES];
static unsigned num_script_names;

static void
name_addr(uint32_t addr, const char *name)
{
	unsigned i;

	for (i = 0; i < num_rs_names; i++) {
		if (rs_names[i].addr == addr) {
			rs_names[i].name = name;
			return;
		}
	}

	if (num_rs_names >= MAX_NAMES) {
		fprintf(stderr, "too many real server names\n");
		exit(EXIT_FAILURE);
	}

	rs_names[num_rs_names].addr = addr;
	rs_names[num_rs_names++].name = name;
}

static const char *
addr_name(uint32_t addr)
{
	unsigned i;

	for (i = 0; i < num_rs_names; i++) {
		if (rs_names[i].addr == addr)
			return rs_names[i].name;
	}

	return "?";
}

static void
name_script(const notify_script_t *script, const char *name)
{
	if (num_script_names >= MAX_NAMES) {
		fprintf(stderr, "too many script names\n");
		exit(EXIT_FAILURE);
	}

	script_names[num_script_names].script = script;
	script_names[num_script_names++].name = name;
}

/*
 * The log of IPVS commands and scripts run
 */
#define MAX_OPS		64
#define OP_LEN		32

static char op_log[MAX_OPS][OP_LEN];
static unsigned num_ops;

static void __attribute__((format (printf, 1, 2)))
log_op(const char *format, ...)
{
	va_list args;

	if (num_ops < MAX_OPS) {
		va_start(args, format);
		vsnprintf(op_log[num_ops], OP_LEN, format, args);
		va_end(args);
	}
	num_ops++;
}

static void
clear_ops(void)
{
	num_ops = 0;
}

static void
pass_fail(const char *what, bool ok)
{
	printf("%s %s\n", ok ? "PASS" : "FAIL", what);
	if (ok)
		passes++;
	else
		fails++;
}

static void
expect(const char *what, bool ok)
{
	pass_fail(what, ok);
}

/* Check the commands issued since the last check, as a comma separated
 * list. A weight is shown for an add if it is not 1, and always for an
 * edit. */
static void
expect_ops(const char *what, const char *expected)
{
	char got[MAX_OPS * (OP_LEN + 1)] = "";
	unsigned i;

	for (i = 0; i < num_ops && i < MAX_OPS; i++) {
		if (i)
			strcat(got, ",");
		strcat(got, op_log[i]);
	}

	pass_fail(what, !strcmp(got, expected));
	if (strcmp(got, expected))
		printf("    expected [%s]\n    got      [%s]\n", expected, got);

	clear_ops();
}

/*
 * The model of the IPVS destination table
 */
#define MAX_DESTS	32

static struct {
	uint32_t	addr;
	unsigned	weight;
} dests[MAX_DESTS];
static unsigned num_dests;
static unsigned num_services;

static int __attribute__ ((pure))
find_dest(const ipvs_dest_t *dest)
{
	unsigned i;

	for (i = 0; i < num_dests; i++) {
		if (dests[i].addr == dest->nf_addr.ip)
			return (int)i;
	}

	return -1;
}

static void
reset_table(void)
{
	num_dests = 0;
	num_services = 0;
}

static int
cmp_name(const void *a, const void *b)
{
	return strcmp(*(const char * const *)a, *(const char * const *)b);
}

/* Check the destinations in the table, sorted by name. A weight is shown
 * if it is not 1. */
static void
expect_table(const char *what, const char *expected)
{
	char entries[MAX_DESTS][OP_LEN];
	const char *sorted[MAX_DESTS];
	char got[MAX_DESTS * (OP_LEN + 1)] = "";
	unsigned i;

	for (i = 0; i < num_dests; i++) {
		if (dests[i].weight == 1)
			snprintf(entries[i], OP_LEN, "%s", addr_name(dests[i].addr));
		else
			snprintf(entries[i], OP_LEN, "%s:%u", addr_name(dests[i].addr), dests[i].weight);
		sorted[i] = entries[i];
	}
	qsort(sorted, num_dests, sizeof(sorted[0]), cmp_name);

	for (i = 0; i < num_dests; i++) {
		if (i)
			strcat(got, ",");
		strcat(got, sorted[i]);
	}

	pass_fail(what, !strcmp(got, expected));
	if (strcmp(got, expected))
		printf("    expected table [%s]\n    got table      [%s]\n", expected, got);
}

int
__wrap_ipvs_add_service(__attribute__((unused)) ipvs_service_t *svc)
{
	log_op("SVC_ADD");
	num_services++;

	return 0;
}

int
__wrap_ipvs_update_service(__attribute__((unused)) ipvs_service_t *svc)
{
	log_op("SVC_EDIT");

	return 0;
}

int
__wrap_ipvs_del_service(__attribute__((unused)) ipvs_service_t *svc)
{
	log_op("SVC_DEL");
	num_services--;
	num_dests = 0;

	return 0;
}

int
__wrap_ipvs_add_dest(__attribute__((unused)) ipvs_service_t *svc, ipvs_dest_t *dest)
{
	const char *name = addr_name(dest->nf_addr.ip);

	if (find_dest(dest) >= 0) {
		log_op("ADD %s EEXIST", name);
		errno = EEXIST;
		return -1;
	}

	if (dest->user.weight == 1)
		log_op("ADD %s", name);
	else
		log_op("ADD %s:%d", name, dest->user.weight);

	dests[num_dests].addr = dest->nf_addr.ip;
	dests[num_dests++].weight = (unsigned)dest->user.weight;

	return 0;
}

int
__wrap_ipvs_update_dest(__attribute__((unused)) ipvs_service_t *svc, ipvs_dest_t *dest)
{
	const char *name = addr_name(dest->nf_addr.ip);
	int i = find_dest(dest);

	if (i < 0) {
		log_op("EDIT %s ENOENT", name);
		errno = ENOENT;
		return -1;
	}

	log_op("EDIT %s:%d", name, dest->user.weight);
	dests[i].weight = (unsigned)dest->user.weight;

	return 0;
}

int
__wrap_ipvs_del_dest(__attribute__((unused)) ipvs_service_t *svc, ipvs_dest_t *dest)
{
	const char *name = addr_name(dest->nf_addr.ip);
	int i = find_dest(dest);

	if (i < 0) {
		log_op("DEL %s ENOENT", name);
		errno = ENOENT;
		return -1;
	}

	log_op("DEL %s", name);
	dests[i] = dests[--num_dests];

	return 0;
}

int
__wrap_notify_exec(const notify_script_t *script)
{
	unsigned i;

	for (i = 0; i < num_script_names; i++) {
		if (script_names[i].script == script) {
			log_op("SCRIPT %s", script_names[i].name);
			return 0;
		}
	}

	log_op("SCRIPT ?");

	return 0;
}

/*
 * The configuration being tested
 */
#define MAX_POOLS	3
#define MAX_POOL_RS	4
#define MAX_RS		((1 + MAX_POOLS) * MAX_POOL_RS)

typedef struct {
	unsigned	priority;			/* Failover pools only */
	unsigned	num_rs;
	unsigned	quorum;				/* 0 for the default of 1 */
	unsigned	hysteresis;
	unsigned	weights[MAX_POOL_RS];		/* 0 for the default of 1 */
} pool_spec_t;

typedef struct {
	pool_spec_t	primary;
	pool_spec_t	failover[MAX_POOLS];		/* In priority order, num_rs 0 if unused */
	bool		sorry;
	bool		alpha;
	bool		inhibit;
	bool		scripts;
} world_spec_t;

typedef struct {
	check_data_t		cdata;
	virtual_server_t	vs;
	failover_pool_t		pools[MAX_POOLS];
	real_server_t		rs[MAX_RS];
	checker_t		ck[MAX_RS];
	char			rs_name[MAX_RS][8];
	unsigned		num_rs;
	real_server_t		sorry;
	notify_script_t		vs_up, vs_down;
	notify_script_t		pool_up[MAX_POOLS], pool_down[MAX_POOLS];
	char			script_name[2 * MAX_POOLS][16];
} world_t;

static const checker_funcs_t test_checker_funcs = { CHECKER_TCP, NULL, NULL, NULL, NULL };

static void
add_rs(world_t *w, failover_pool_t *pool, unsigned pool_index, unsigned rs_index, const world_spec_t *spec, unsigned weight)
{
	real_server_t *rs = &w->rs[w->num_rs];
	checker_t *ck = &w->ck[w->num_rs];
	char *name = w->rs_name[w->num_rs];
	char addr[16];

	/* The primary pool real servers are p1, p2..., those of the
	 * failover pools a1, a2..., b1, b2... */
	snprintf(name, sizeof(w->rs_name[0]), "%c%u", pool_index ? 'a' + (int)pool_index - 1 : 'p', rs_index + 1);
	snprintf(addr, sizeof(addr), "192.168.%u.%u", pool_index + 1, rs_index + 1);

	INIT_LIST_HEAD(&rs->e_list);
	INIT_LIST_HEAD(&rs->track_files);
#ifdef _WITH_BFD_
	INIT_LIST_HEAD(&rs->tracked_bfds);
#endif
	INIT_LIST_HEAD(&rs->checkers_list);
	inet_stosockaddr(addr, "80", &rs->addr);
	rs->forwarding_method = IP_VS_CONN_F_MASQ;
	rs->iweight = weight ? (int)weight : 1;
	rs->effective_weight = rs->iweight;
	rs->peffective_weight = rs->iweight;
	rs->inhibit = spec->inhibit;
	rs->alpha = spec->alpha;
	rs->pool = pool;
	rs->num_failed_checkers = spec->alpha ? 1 : 0;
	list_add_tail(&rs->e_list, &w->vs.rs);

	INIT_LIST_HEAD(&ck->rs_list);
	ck->checker_funcs = &test_checker_funcs;
	ck->vs = &w->vs;
	ck->rs = rs;
	ck->enabled = true;
	ck->alpha = spec->alpha;
	ck->is_up = !spec->alpha;
	ck->has_run = !spec->alpha;
	list_add_tail(&ck->rs_list, &rs->checkers_list);

	name_addr(inet_sockaddrip4(&rs->addr), name);

	w->num_rs++;
}

static void
set_script(world_t *w, notify_script_t *script, unsigned n, const char *name)
{
	snprintf(w->script_name[n], sizeof(w->script_name[0]), "%s", name);
	name_script(script, w->script_name[n]);
}

/* Build the configuration, as it is after it has been read */
static void
build_world(world_t *w, const world_spec_t *spec)
{
	failover_pool_t *pool;
	const pool_spec_t *ps;
	unsigned i, j;
	char name[16];

	memset(w, 0, sizeof(*w));

	INIT_LIST_HEAD(&w->cdata.vs_group);
	INIT_LIST_HEAD(&w->cdata.vs);
	INIT_LIST_HEAD(&w->cdata.track_files);
#ifdef _WITH_BFD_
	INIT_LIST_HEAD(&w->cdata.track_bfds);
#endif

	INIT_LIST_HEAD(&w->vs.e_list);
	INIT_LIST_HEAD(&w->vs.rs);
	INIT_LIST_HEAD(&w->vs.failover_pools);
	inet_stosockaddr("10.0.0.1", "80", &w->vs.addr);
	w->vs.af = AF_INET;
	w->vs.service_type = IPPROTO_TCP;
	strcpy(w->vs.sched, "rr");
	w->vs.weight = 1;
	w->vs.forwarding_method = IP_VS_CONN_F_MASQ;
	w->vs.persistence_granularity = 0xffffffff;
	w->vs.alpha = spec->alpha;
	w->vs.inhibit = spec->inhibit;
	w->vs.quorum = spec->primary.quorum ? spec->primary.quorum : 1;
	w->vs.hysteresis = spec->primary.hysteresis;
	w->vs.quorum_state_up = true;
	list_add_tail(&w->vs.e_list, &w->cdata.vs);

	if (spec->scripts) {
		w->vs.notify_quorum_up = &w->vs_up;
		w->vs.notify_quorum_down = &w->vs_down;
		name_script(&w->vs_up, "vs-up");
		name_script(&w->vs_down, "vs-down");
	}

	for (j = 0; j < spec->primary.num_rs; j++)
		add_rs(w, NULL, 0, j, spec, spec->primary.weights[j]);

	for (i = 0; i < MAX_POOLS && spec->failover[i].num_rs; i++) {
		ps = &spec->failover[i];
		pool = &w->pools[i];
		INIT_LIST_HEAD(&pool->e_list);
		pool->priority = ps->priority ? ps->priority : i + 1;
		pool->quorum = ps->quorum ? ps->quorum : 1;
		pool->hysteresis = ps->hysteresis;
		list_add_tail(&pool->e_list, &w->vs.failover_pools);

		if (spec->scripts) {
			pool->notify_quorum_up = &w->pool_up[i];
			pool->notify_quorum_down = &w->pool_down[i];
			snprintf(name, sizeof(name), "pool%u-up", pool->priority);
			set_script(w, &w->pool_up[i], 2 * i, name);
			snprintf(name, sizeof(name), "pool%u-down", pool->priority);
			set_script(w, &w->pool_down[i], 2 * i + 1, name);
		}

		for (j = 0; j < ps->num_rs; j++)
			add_rs(w, pool, i + 1, j, spec, ps->weights[j]);
	}

	if (spec->sorry) {
		inet_stosockaddr("192.168.200.1", "80", &w->sorry.addr);
		w->sorry.forwarding_method = IP_VS_CONN_F_MASQ;
		w->sorry.iweight = 1;
		w->sorry.effective_weight = 1;
		w->vs.s_svr = &w->sorry;
		name_addr(inet_sockaddrip4(&w->sorry.addr), "sorry");
	}
}

/* Start keepalived's checker process with the configuration */
static void
start_world(world_t *w, const world_spec_t *spec)
{
	reset_table();
	build_world(w, spec);

	check_data = &w->cdata;
	old_check_data = NULL;
	reload = false;

	set_quorum_states();
	clear_ops();
	init_services();
}

static unsigned
rs_index(const world_t *w, const char *name)
{
	unsigned i;

	for (i = 0; i < w->num_rs; i++) {
		if (!strcmp(w->rs_name[i], name))
			return i;
	}

	fprintf(stderr, "unknown real server %s\n", name);
	exit(EXIT_FAILURE);
}

static real_server_t *
rs_named(world_t *w, const char *name)
{
	return &w->rs[rs_index(w, name)];
}

static void
fail(world_t *w, const char *name)
{
	update_svr_checker_state(false, &w->ck[rs_index(w, name)]);
}

static void
recover(world_t *w, const char *name)
{
	update_svr_checker_state(true, &w->ck[rs_index(w, name)]);
}

/* Start a reload to the new configuration, up to the point where the
 * IPVS rules for the new configuration are set. The state of the checkers
 * is carried over as migrate_checkers() would. */
static void
reload_diff(world_t *old, world_t *new, const world_spec_t *spec)
{
	unsigned i, j;

	if (new->num_rs == 0)
		build_world(new, spec);

	for (i = 0; i < new->num_rs; i++) {
		for (j = 0; j < old->num_rs; j++) {
			if (!strcmp(new->rs_name[i], old->rs_name[j]))
				break;
		}

		if (j == old->num_rs)
			continue;

		new->ck[i].has_run = old->ck[j].has_run;
		new->ck[i].is_up = old->ck[j].is_up;
	}

	check_data = &new->cdata;
	old_check_data = &old->cdata;
	reload = true;

	set_quorum_states();
	clear_ops();
	clear_diff_services();
}

static void
reload_init(void)
{
	check_new_rs_state();
	init_services();
	reload = false;
}

/*
 * The tests
 */

/* Without failover pools, the sorry server behaves as it always has */
static void
test_no_pools_sorry_server(void)
{
	static world_t w;
	static const world_spec_t spec = {
		.primary = { .num_rs = 2 },
		.sorry = true,
	};

	start_world(&w, &spec);
	expect_ops("no pools: init", "SVC_ADD,ADD p1,ADD p2");
	fail(&w, "p1");
	expect_ops("no pools: one real server fails", "DEL p1");
	fail(&w, "p2");
	expect_ops("no pools: quorum lost, sorry server added", "DEL p2,ADD sorry");
	recover(&w, "p1");
	expect_ops("no pools: quorum regained, sorry server removed", "DEL sorry,ADD p1");
	expect_table("no pools: table", "p1");
}

/* Without a sorry server, losing quorum leaves the alive real servers */
static void
test_no_pools_no_sorry_server(void)
{
	static world_t w;
	static const world_spec_t spec = {
		.primary = { .num_rs = 3, .quorum = 2 },
	};

	start_world(&w, &spec);
	expect_ops("no sorry server: init", "SVC_ADD,ADD p1,ADD p2,ADD p3");
	fail(&w, "p1");
	fail(&w, "p2");
	expect_ops("no sorry server: quorum lost, alive real server stays", "DEL p1,DEL p2");
	expect("no sorry server: quorum down", !w.vs.quorum_state_up);
	recover(&w, "p1");
	expect_ops("no sorry server: quorum regained", "ADD p1");
	expect_table("no sorry server: table", "p1,p3");
}

/* The failover pool is used when the primary pool loses quorum, and the
 * primary pool is used again when it regains quorum */
static void
test_switch_and_revert(void)
{
	static world_t w;
	static const world_spec_t spec = {
		.primary = { .num_rs = 3, .quorum = 2 },
		.failover = { { .num_rs = 2 } },
	};

	start_world(&w, &spec);
	expect_ops("switch: init adds only the primary pool", "SVC_ADD,ADD p1,ADD p2,ADD p3");
	expect("switch: failover pool real servers alive but not set",
	       rs_named(&w, "a1")->alive && !rs_named(&w, "a1")->set &&
	       rs_named(&w, "a2")->alive && !rs_named(&w, "a2")->set);
	expect("switch: failover pool has quorum", w.pools[0].quorum_state_up);

	fail(&w, "p1");
	expect_ops("switch: primary pool still has quorum", "DEL p1");
	fail(&w, "p2");
	expect_ops("switch: primary pool loses quorum, failover pool added before primary removed",
		   "DEL p2,ADD a1,ADD a2,DEL p3");
	expect("switch: failover pool active", w.vs.active_pool == &w.pools[0]);
	expect_table("switch: table", "a1,a2");

	fail(&w, "p3");
	expect_ops("switch: primary real server failing while unused", "");
	recover(&w, "p3");
	expect_ops("switch: primary real server recovering below quorum", "");

	fail(&w, "a1");
	expect_ops("switch: failover pool real server fails", "DEL a1");
	recover(&w, "a1");
	expect_ops("switch: failover pool real server recovers", "ADD a1");

	recover(&w, "p1");
	expect_ops("switch: primary pool regains quorum", "ADD p1,ADD p3,DEL a1,DEL a2");
	expect("switch: primary pool active", !w.vs.active_pool);
	expect_table("switch: table after revert", "p1,p3");
}

/* Each pool is used while it has quorum, in priority order */
static void
test_priority_order(void)
{
	static world_t w;
	static const world_spec_t spec = {
		.primary = { .num_rs = 2, .quorum = 2 },
		.failover = { { .priority = 10, .num_rs = 2, .quorum = 2 },
			      { .priority = 20, .num_rs = 1 } },
	};

	start_world(&w, &spec);
	clear_ops();

	fail(&w, "p1");
	expect_ops("priority: primary loses quorum, pool 10 used", "DEL p1,ADD a1,ADD a2,DEL p2");
	fail(&w, "a1");
	expect_ops("priority: pool 10 loses quorum, pool 20 used", "DEL a1,ADD b1,DEL a2");
	expect("priority: pool 20 active", w.vs.active_pool == &w.pools[1]);
	recover(&w, "a1");
	expect_ops("priority: pool 10 regains quorum and is used", "ADD a1,ADD a2,DEL b1");
	recover(&w, "p1");
	expect_ops("priority: primary regains quorum and is used", "ADD p1,ADD p2,DEL a1,DEL a2");
	expect_table("priority: table", "p1,p2");
}

/* The sorry server is the last resort, after all the failover pools */
static void
test_sorry_server_last(void)
{
	static world_t w;
	static const world_spec_t spec = {
		.primary = { .num_rs = 1 },
		.failover = { { .num_rs = 1 } },
		.sorry = true,
	};

	start_world(&w, &spec);
	expect_ops("sorry last: init", "SVC_ADD,ADD p1");
	fail(&w, "p1");
	expect_ops("sorry last: failover pool used before the sorry server", "DEL p1,ADD a1");
	fail(&w, "a1");
	expect_ops("sorry last: failover pool exhausted, sorry server used", "DEL a1,ADD sorry");
	expect_table("sorry last: table", "sorry");
	recover(&w, "a1");
	expect_ops("sorry last: failover pool recovers, sorry server removed", "DEL sorry,ADD a1");
	recover(&w, "p1");
	expect_ops("sorry last: primary pool recovers", "ADD p1,DEL a1");
	expect_table("sorry last: table after recovery", "p1");
}

/* A pool's quorum is measured by weight; the weight defaults to 1, so
 * without weights it is the number of alive real servers */
static void
test_weights(void)
{
	static world_t w;
	static const world_spec_t spec = {
		.primary = { .num_rs = 1 },
		.failover = { { .num_rs = 2, .quorum = 3, .weights = { 3, 1 } },
			      { .num_rs = 2, .quorum = 2 } },
	};

	start_world(&w, &spec);
	clear_ops();

	fail(&w, "p1");
	expect_ops("weights: pool 1 has quorum by weight", "DEL p1,ADD a1:3,ADD a2");
	fail(&w, "a2");
	expect_ops("weights: pool 1 keeps quorum with weight 3", "DEL a2");
	recover(&w, "a2");
	fail(&w, "a1");
	expect_ops("weights: pool 1 loses quorum with weight 1, pool 2 used",
		   "ADD a2,DEL a1,ADD b1,ADD b2,DEL a2");
	fail(&w, "b1");
	expect_ops("weights: pool 2 counts real servers, loses quorum, degraded use of pool 1",
		   "DEL b1,ADD a2,DEL b2");
	expect_table("weights: table", "a2");
}

/* Hysteresis applies to a failover pool's quorum as to the primary pool's */
static void
test_pool_hysteresis(void)
{
	static world_t w;
	static const world_spec_t spec = {
		.primary = { .num_rs = 1 },
		.failover = { { .num_rs = 3, .quorum = 2, .hysteresis = 1 } },
	};

	start_world(&w, &spec);
	clear_ops();

	fail(&w, "p1");
	expect_ops("hysteresis: pool used", "DEL p1,ADD a1,ADD a2,ADD a3");
	fail(&w, "a1");
	fail(&w, "a2");
	expect_ops("hysteresis: pool keeps quorum down to quorum - hysteresis", "DEL a1,DEL a2");
	expect("hysteresis: pool still has quorum", w.pools[0].quorum_state_up);
	fail(&w, "a3");
	expect_ops("hysteresis: pool loses quorum", "DEL a3");
	expect("hysteresis: pool quorum down", !w.pools[0].quorum_state_up);

	/* Nothing has quorum and there is no sorry server: the highest
	 * priority pool with alive real servers is used */
	recover(&w, "a1");
	expect_ops("hysteresis: degraded use of the only pool with alive real servers", "ADD a1");
	recover(&w, "a2");
	expect_ops("hysteresis: below quorum + hysteresis", "ADD a2");
	expect("hysteresis: pool quorum still down", !w.pools[0].quorum_state_up);
	recover(&w, "a3");
	expect_ops("hysteresis: pool regains quorum", "ADD a3");
	expect("hysteresis: pool quorum up", w.pools[0].quorum_state_up);
	recover(&w, "p1");
	expect_ops("hysteresis: primary used again", "ADD p1,DEL a1,DEL a2,DEL a3");
}

/* Starting in alpha mode, everything is down until it passes its checks */
static void
test_alpha(void)
{
	static world_t w;
	static const world_spec_t spec = {
		.primary = { .num_rs = 2 },
		.failover = { { .num_rs = 1 } },
		.sorry = true,
		.alpha = true,
	};

	start_world(&w, &spec);
	expect_ops("alpha: init uses the sorry server", "SVC_ADD,ADD sorry");
	recover(&w, "a1");
	expect_ops("alpha: failover pool passes its checks, replaces the sorry server", "DEL sorry,ADD a1");
	recover(&w, "p1");
	expect_ops("alpha: primary pool passes its checks, replaces the failover pool", "ADD p1,DEL a1");
	expect_table("alpha: table", "p1");
}

/* Inhibited real servers of a pool that is not in use are in the table
 * with weight 0, as for the primary pool while the sorry server is used */
static void
test_inhibit(void)
{
	static world_t w;
	static const world_spec_t spec = {
		.primary = { .num_rs = 2, .quorum = 2 },
		.failover = { { .num_rs = 2 } },
		.inhibit = true,
	};

	start_world(&w, &spec);
	expect_ops("inhibit: init adds the failover pool with weight 0", "SVC_ADD,ADD p1,ADD p2,ADD a1:0,ADD a2:0");
	fail(&w, "p1");
	expect_ops("inhibit: switch to failover pool", "EDIT p1:0,EDIT a1:1,EDIT a2:1,EDIT p2:0");
	expect_table("inhibit: table after switch", "a1,a2,p1:0,p2:0");
	fail(&w, "a1");
	expect_ops("inhibit: failover pool real server fails", "EDIT a1:0");
	recover(&w, "p1");
	expect_ops("inhibit: revert to primary pool", "EDIT p1:1,EDIT p2:1,EDIT a2:0");
	recover(&w, "a1");
	expect_ops("inhibit: failover pool real server recovers while unused", "");
	expect_table("inhibit: table after revert", "a1:0,a2:0,p1,p2");
}

/* The quorum_up and quorum_down scripts of the pools are run, once the
 * IPVS table has been updated */
static void
test_scripts(void)
{
	static world_t w;
	static const world_spec_t spec = {
		.primary = { .num_rs = 1 },
		.failover = { { .num_rs = 1 } },
		.scripts = true,
	};

	start_world(&w, &spec);
	expect_ops("scripts: init", "SVC_ADD,ADD p1,SCRIPT vs-up,SCRIPT pool1-up");
	fail(&w, "p1");
	expect_ops("scripts: primary loses quorum", "DEL p1,ADD a1,SCRIPT vs-down");
	fail(&w, "a1");
	expect_ops("scripts: failover pool loses quorum", "DEL a1,SCRIPT pool1-down");
	recover(&w, "a1");
	expect_ops("scripts: failover pool regains quorum", "ADD a1,SCRIPT pool1-up");
}

/* Reloading an unchanged configuration while a failover pool is in use
 * changes nothing */
static void
test_reload_unchanged(void)
{
	static world_t w_old, w_new;
	static const world_spec_t spec = {
		.primary = { .num_rs = 2, .quorum = 2 },
		.failover = { { .num_rs = 2 } },
	};

	start_world(&w_old, &spec);
	fail(&w_old, "p1");
	clear_ops();

	w_new.num_rs = 0;
	reload_diff(&w_old, &w_new, &spec);
	expect_ops("reload unchanged: no IPVS commands migrating state", "");
	expect("reload unchanged: failover pool still in use", w_new.vs.active_pool == &w_new.pools[0]);
	expect("reload unchanged: pool quorum carried over", w_new.pools[0].quorum_state_up && !w_new.vs.quorum_state_up);
	reload_init();
	expect_ops("reload unchanged: no IPVS commands setting rules", "");
	expect_table("reload unchanged: table", "a1,a2");
}

/* Removing the failover pool in use reinstates the primary pool */
static void
test_reload_remove_pool(void)
{
	static world_t w_old, w_new;
	static const world_spec_t spec = {
		.primary = { .num_rs = 2, .quorum = 2 },
		.failover = { { .num_rs = 2 } },
	};
	static const world_spec_t new_spec = {
		.primary = { .num_rs = 2, .quorum = 2 },
		.sorry = false,
	};

	start_world(&w_old, &spec);
	fail(&w_old, "p1");
	clear_ops();

	w_new.num_rs = 0;
	reload_diff(&w_old, &w_new, &new_spec);
	expect_ops("reload remove pool: pool removed, primary reinstated", "DEL a1,DEL a2,ADD p2");
	reload_init();
	expect_ops("reload remove pool: nothing more to do", "");
	expect_table("reload remove pool: table", "p2");
}

/* A real server brought up while the state is migrated must not cause
 * a pool change until all the state has been migrated */
static void
test_reload_up_during_diff(void)
{
	static world_t w_old, w_new;
	static const world_spec_t spec = {
		.primary = { .num_rs = 2, .quorum = 2 },
		.failover = { { .num_rs = 2 } },
	};

	start_world(&w_old, &spec);
	fail(&w_old, "p1");
	clear_ops();

	/* p1's failing checker is removed from the configuration */
	build_world(&w_new, &spec);
	list_del_init(&w_new.ck[rs_index(&w_new, "p1")].rs_list);
	rs_named(&w_new, "p1")->num_failed_checkers = 0;

	reload_diff(&w_old, &w_new, &spec);
	expect_ops("reload up during diff: no change while migrating", "");
	reload_init();
	expect_ops("reload up during diff: primary pool used once migrated", "ADD p1,ADD p2,DEL a1,DEL a2");
	expect_table("reload up during diff: table", "p1,p2");
}

/* A real server moved to a pool that is in use is added, and one moved
 * to a pool that is not in use is removed */
static void
test_reload_move_rs(void)
{
	static world_t w_old, w_new, w_new2;
	static const world_spec_t spec = {
		.primary = { .num_rs = 2 },
		.failover = { { .num_rs = 2 } },
	};

	start_world(&w_old, &spec);
	clear_ops();

	/* a1 is moved to the primary pool, which is in use */
	build_world(&w_new, &spec);
	rs_named(&w_new, "a1")->pool = NULL;
	reload_diff(&w_old, &w_new, &spec);
	expect_ops("reload move: moved to the pool in use is added", "ADD a1");
	reload_init();
	expect_ops("reload move: nothing more to do", "");

	/* and back again */
	build_world(&w_new2, &spec);
	reload_diff(&w_new, &w_new2, &spec);
	expect_ops("reload move: moved to a pool not in use is removed", "DEL a1");
	reload_init();
	expect_ops("reload move: nothing more to do again", "");
	expect_table("reload move: table", "p1,p2");
}

/* A failover pool added on reload replaces the sorry server */
static void
test_reload_add_pool(void)
{
	static world_t w_old, w_new;
	static const world_spec_t spec = {
		.primary = { .num_rs = 1 },
		.sorry = true,
	};
	static const world_spec_t new_spec = {
		.primary = { .num_rs = 1 },
		.failover = { { .num_rs = 1 } },
		.sorry = true,
	};

	start_world(&w_old, &spec);
	clear_ops();
	fail(&w_old, "p1");
	expect_ops("reload add pool: sorry server used", "DEL p1,ADD sorry");

	w_new.num_rs = 0;
	reload_diff(&w_old, &w_new, &new_spec);
	expect_ops("reload add pool: nothing while migrating", "");
	reload_init();
	expect_ops("reload add pool: new pool replaces the sorry server", "DEL sorry,ADD a1");
	expect_table("reload add pool: table", "a1");
}

int
main(void)
{
	/* Keep the results in order with the log messages */
	setvbuf(stdout, NULL, _IOLBF, 0);

	global_data = alloc_global_data();
	if (getenv("FAILOVER_POOL_TEST_VERBOSE")) {
		__set_bit(DONT_FORK_BIT, &debug);
		enable_console_log();
	}

	test_no_pools_sorry_server();
	test_no_pools_no_sorry_server();
	test_switch_and_revert();
	test_priority_order();
	test_sorry_server_last();
	test_weights();
	test_pool_hysteresis();
	test_alpha();
	test_inhibit();
	test_scripts();
	test_reload_unchanged();
	test_reload_remove_pool();
	test_reload_up_during_diff();
	test_reload_move_rs();
	test_reload_add_pool();

	printf("%u passed, %u failed\n", passes, fails);

	return fails ? EXIT_FAILURE : EXIT_SUCCESS;
}
