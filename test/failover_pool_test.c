/*
 * State machine regression test for the virtual server failover pool.
 *
 * ipwrapper.c is compiled directly into this test with the IPVS command
 * layer replaced by an op-logging stub, so every pool transition can be
 * asserted as the exact sequence of IPVS commands it would issue.
 * Build and run: make failover_pool_test && ./failover_pool_test
 *
 * Copyright (C) 2026 Alexandre Cassen, <acassen@gmail.com>
 */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "check_data.h"
#include "check_api.h"
#include "ipwrapper.h"
#include "ipvswrapper.h"
#include "global_data.h"
#include "check_daemon.h"
#include "main.h"
#include "smtp.h"
#include "utils.h"

static int fails;

/* ---------------- stubbed globals ---------------- */

check_data_t *check_data;
check_data_t *old_check_data;
static data_t gdata;
data_t *global_data = &gdata;
bool reload;
bool using_ha_suspend;

/* ---------------- op log ---------------- */

#define MAX_OPS		64
#define MAX_NAMES	32

static char op_log[MAX_OPS][40];
static unsigned op_cnt;

static struct {
	const real_server_t *rs;
	const char *name;
} name_tab[MAX_NAMES];
static unsigned name_cnt;

static void
name_rs(const real_server_t *rs, const char *name)
{
	name_tab[name_cnt].rs = rs;
	name_tab[name_cnt].name = name;
	name_cnt++;
}

static const char *
rs_name(const real_server_t *rs)
{
	unsigned i;

	for (i = 0; i < name_cnt; i++)
		if (name_tab[i].rs == rs)
			return name_tab[i].name;
	return "?";
}

static void
log_op(int cmd, const real_server_t *rs)
{
	const char *cmd_name;

	switch (cmd) {
	case IP_VS_SO_SET_ADD:      cmd_name = "SVC_ADD"; break;
	case IP_VS_SO_SET_DEL:      cmd_name = "SVC_DEL"; break;
	case IP_VS_SO_SET_EDIT:     cmd_name = "SVC_EDIT"; break;
	case IP_VS_SO_SET_ADDDEST:  cmd_name = "ADD"; break;
	case IP_VS_SO_SET_DELDEST:  cmd_name = "DEL"; break;
	case IP_VS_SO_SET_EDITDEST: cmd_name = "EDIT"; break;
	default:                    cmd_name = "???"; break;
	}

	if (op_cnt < MAX_OPS) {
		if (rs)
			snprintf(op_log[op_cnt], sizeof(op_log[0]), "%s %s", cmd_name, rs_name(rs));
		else
			snprintf(op_log[op_cnt], sizeof(op_log[0]), "%s", cmd_name);
	}
	op_cnt++;
}

static void
clear_ops(void)
{
	op_cnt = 0;
}

static void
expect_ops(const char *what, const char *expected)
{
	char joined[MAX_OPS * 40] = "";
	unsigned i;

	for (i = 0; i < op_cnt && i < MAX_OPS; i++) {
		if (i)
			strcat(joined, ",");
		strcat(joined, op_log[i]);
	}

	if (strcmp(joined, expected)) {
		printf("FAIL %s\n  expected [%s]\n  got      [%s]\n", what, expected, joined);
		fails++;
	} else
		printf("PASS %s\n", what);

	clear_ops();
}

static void
expect(const char *what, bool ok)
{
	printf("%s %s\n", ok ? "PASS" : "FAIL", what);
	if (!ok)
		fails++;
}

/* ---------------- IPVS layer stubs ---------------- */

int
ipvs_cmd(int cmd, __attribute__((unused)) virtual_server_t *vs, real_server_t *rs)
{
	/* Faithfully mirror the rs->set bookkeeping and inhibit command
	 * rewriting of the real ipvs_cmd() in ipvswrapper.c */
	if (rs) {
		if (cmd == IP_VS_SO_SET_DELDEST && rs->inhibit)
			cmd = IP_VS_SO_SET_EDITDEST;
		else if (cmd == IP_VS_SO_SET_ADDDEST && rs->inhibit && rs->set)
			cmd = IP_VS_SO_SET_EDITDEST;
		else if (cmd == IP_VS_SO_SET_ADDDEST && !rs->set)
			rs->set = true;
		else if (cmd == IP_VS_SO_SET_DELDEST && rs->set)
			rs->set = false;
	}

	log_op(cmd, rs);

	return 0;
}

void
ipvs_flush_cmd(void)
{
}

virtual_server_group_t *
ipvs_get_group_by_name(__attribute__((unused)) const char *gname, __attribute__((unused)) list_head_t *l)
{
	return NULL;
}

void
ipvs_group_sync_entry(__attribute__((unused)) virtual_server_t *vs, __attribute__((unused)) virtual_server_group_entry_t *vsge)
{
}

void
ipvs_group_remove_entry(__attribute__((unused)) virtual_server_t *vs, __attribute__((unused)) virtual_server_group_entry_t *vsge)
{
}

void
unset_vsge_alive(__attribute__((unused)) virtual_server_group_entry_t *vsge, __attribute__((unused)) const virtual_server_t *vs)
{
}

void
smtp_alert(__attribute__((unused)) smtp_msg_t msg_type, __attribute__((unused)) void *data,
	   __attribute__((unused)) const char *subject, __attribute__((unused)) const char *body)
{
}

const char *
format_vs(__attribute__((unused)) const virtual_server_t *vs)
{
	return "test-vs";
}

const char *
format_rs(const real_server_t *rs, __attribute__((unused)) const virtual_server_t *vs)
{
	return rs_name(rs);
}

void
free_vs(__attribute__((unused)) virtual_server_t *vs)
{
}

/* ---------------- test world ---------------- */

#define MAX_RS		8
#define MAX_BACKUP	4

typedef struct {
	check_data_t	cdata;
	virtual_server_t vs;
	real_server_t	rs[MAX_RS];
	real_server_t	backup[MAX_BACKUP];
	real_server_t	sorry;
	checker_t	rs_ck[MAX_RS];
	checker_t	backup_ck[MAX_BACKUP];
	unsigned	n_rs;
	unsigned	n_backup;
} world_t;

static const checker_funcs_t test_checker_funcs = { CHECKER_TCP, NULL, NULL, NULL, NULL };

static void
init_rs(world_t *w, real_server_t *rs, checker_t *ck, const char *ip, bool is_backup, bool alpha)
{
	memset(rs, 0, sizeof(*rs));
	INIT_LIST_HEAD(&rs->e_list);
	INIT_LIST_HEAD(&rs->track_files);
#ifdef _WITH_BFD_
	INIT_LIST_HEAD(&rs->tracked_bfds);
#endif
	INIT_LIST_HEAD(&rs->checkers_list);
	inet_stosockaddr(ip, "80", &rs->addr);
	rs->effective_weight = 1;
	rs->iweight = 1;
	rs->is_backup = is_backup;
	rs->alive = false;
	rs->num_failed_checkers = alpha ? 1 : 0;

	memset(ck, 0, sizeof(*ck));
	ck->checker_funcs = &test_checker_funcs;
	ck->vs = &w->vs;
	ck->rs = rs;
	ck->is_up = !alpha;
	ck->has_run = !alpha;
	ck->alpha = alpha;

	list_add_tail(&rs->e_list, is_backup ? &w->vs.backup_rs : &w->vs.rs);
}

static void
init_world(world_t *w, unsigned n_rs, unsigned n_backup, unsigned threshold, bool with_sorry, bool alpha)
{
	char ip[32];
	static const char *rs_names[MAX_RS] = { "rs1", "rs2", "rs3", "rs4", "rs5", "rs6", "rs7", "rs8" };
	static const char *backup_names[MAX_BACKUP] = { "b1", "b2", "b3", "b4" };
	unsigned i;

	memset(w, 0, sizeof(*w));
	name_cnt = 0;

	INIT_LIST_HEAD(&w->cdata.vs_group);
	INIT_LIST_HEAD(&w->cdata.vs);
	INIT_LIST_HEAD(&w->cdata.track_files);
#ifdef _WITH_BFD_
	INIT_LIST_HEAD(&w->cdata.track_bfds);
#endif

	INIT_LIST_HEAD(&w->vs.e_list);
	INIT_LIST_HEAD(&w->vs.rs);
	INIT_LIST_HEAD(&w->vs.backup_rs);
	w->vs.af = AF_INET;
	inet_stosockaddr("10.0.0.1", "80", &w->vs.addr);
	w->vs.service_type = IPPROTO_TCP;
	strcpy(w->vs.sched, "rr");
	w->vs.quorum = 1;
	w->vs.hysteresis = 0;
	w->vs.failover_threshold = threshold;
	w->vs.alpha = alpha;
	list_add_tail(&w->vs.e_list, &w->cdata.vs);

	w->n_rs = n_rs;
	for (i = 0; i < n_rs; i++) {
		snprintf(ip, sizeof(ip), "192.168.1.%u", i + 1);
		init_rs(w, &w->rs[i], &w->rs_ck[i], ip, false, alpha);
		name_rs(&w->rs[i], rs_names[i]);
	}

	w->n_backup = n_backup;
	for (i = 0; i < n_backup; i++) {
		snprintf(ip, sizeof(ip), "192.168.2.%u", i + 1);
		init_rs(w, &w->backup[i], &w->backup_ck[i], ip, true, alpha);
		name_rs(&w->backup[i], backup_names[i]);
	}

	if (with_sorry) {
		memset(&w->sorry, 0, sizeof(w->sorry));
		inet_stosockaddr("192.168.3.1", "80", &w->sorry.addr);
		w->sorry.effective_weight = 1;
		w->sorry.iweight = 1;
		w->vs.s_svr = &w->sorry;
		name_rs(&w->sorry, "sorry");
	}

	check_data = &w->cdata;
	old_check_data = NULL;
	reload = false;

	set_quorum_states();
	clear_ops();
	init_services();
}

static void
ck_fail(checker_t *ck)
{
	update_svr_checker_state(false, ck);
}

static void
ck_up(checker_t *ck)
{
	update_svr_checker_state(true, ck);
}

/* ---------------- tests ---------------- */

/* Default threshold (100%): only switch when every primary has failed */
static void
test_default_threshold(void)
{
	world_t w;

	init_world(&w, 3, 2, 100, false, false);
	expect_ops("init: primaries added, backups tracked but not added",
		   "SVC_ADD,ADD rs1,ADD rs2,ADD rs3");
	expect("init: backup members are alive but not set",
	       w.backup[0].alive && !w.backup[0].set && w.backup[1].alive && !w.backup[1].set);

	ck_fail(&w.rs_ck[0]);
	expect_ops("1 of 3 failed: no switch", "DEL rs1");
	ck_fail(&w.rs_ck[1]);
	expect_ops("2 of 3 failed: no switch", "DEL rs2");
	ck_fail(&w.rs_ck[2]);
	expect_ops("3 of 3 failed: switch to failover pool", "DEL rs3,ADD b1,ADD b2");
	expect("failover state is up", w.vs.failover_state_up);
}

/* 50% threshold with 3 servers: switch at 2 failed (implicit ceiling) */
static void
test_percent_rounding(void)
{
	world_t w;

	init_world(&w, 3, 2, 50, false, false);
	clear_ops();

	ck_fail(&w.rs_ck[0]);
	expect_ops("50% of 3: 1 failed (33%) no switch", "DEL rs1");
	ck_fail(&w.rs_ck[1]);
	expect_ops("50% of 3: 2 failed (66%) switches, remaining primary removed",
		   "DEL rs2,DEL rs3,ADD b1,ADD b2");

	/* 34% of 3 servers needs 2 failures (1 * 100 = 100 < 102) */
	init_world(&w, 3, 1, 34, false, false);
	clear_ops();
	ck_fail(&w.rs_ck[0]);
	expect_ops("34% of 3: 1 failed no switch", "DEL rs1");
	ck_fail(&w.rs_ck[1]);
	expect_ops("34% of 3: 2 failed switches", "DEL rs2,DEL rs3,ADD b1");

	/* 33% of 3 servers needs only 1 failure (1 * 100 = 100 >= 99) */
	init_world(&w, 3, 1, 33, false, false);
	clear_ops();
	ck_fail(&w.rs_ck[0]);
	expect_ops("33% of 3: 1 failed switches", "DEL rs1,DEL rs2,DEL rs3,ADD b1");
}

/* Exact boundary: 2 of 4 at 50% switches */
static void
test_exact_boundary(void)
{
	world_t w;

	init_world(&w, 4, 1, 50, false, false);
	clear_ops();

	ck_fail(&w.rs_ck[0]);
	expect_ops("50% of 4: 1 failed no switch", "DEL rs1");
	ck_fail(&w.rs_ck[1]);
	expect_ops("50% of 4: exactly 2 failed switches", "DEL rs2,DEL rs3,DEL rs4,ADD b1");
}

/* Primary recovery below the threshold reverts to the primary pool */
static void
test_recovery(void)
{
	world_t w;

	init_world(&w, 3, 2, 50, false, false);
	clear_ops();
	ck_fail(&w.rs_ck[0]);
	ck_fail(&w.rs_ck[1]);
	clear_ops();

	ck_up(&w.rs_ck[1]);
	expect_ops("recovery below threshold: backups removed, alive primaries re-added",
		   "DEL b1,DEL b2,ADD rs2,ADD rs3");
	expect("failover state is down", !w.vs.failover_state_up);
}

/* A backup member flapping while the failover pool is active only
 * touches that member */
static void
test_backup_flap(void)
{
	world_t w;

	init_world(&w, 2, 2, 100, false, false);
	clear_ops();
	ck_fail(&w.rs_ck[0]);
	ck_fail(&w.rs_ck[1]);
	clear_ops();

	ck_fail(&w.backup_ck[0]);
	expect_ops("backup member fails while active: single removal", "DEL b1");
	ck_up(&w.backup_ck[0]);
	expect_ops("backup member recovers while active: single addition", "ADD b1");
}

/* A primary flapping while the failover pool stays above the threshold
 * must not touch IPVS at all */
static void
test_primary_flap_while_backup_active(void)
{
	world_t w;

	init_world(&w, 3, 1, 50, false, false);
	clear_ops();
	ck_fail(&w.rs_ck[0]);
	ck_fail(&w.rs_ck[1]);
	ck_fail(&w.rs_ck[2]);
	clear_ops();

	ck_up(&w.rs_ck[0]);
	expect_ops("primary recovers, threshold still reached: no IPVS ops", "");
	ck_fail(&w.rs_ck[0]);
	expect_ops("primary fails again while backup active: no IPVS ops", "");
}

/* Layering: the sorry server takes over only when the failover pool is
 * exhausted, and yields as soon as a backup member recovers */
static void
test_sorry_layering(void)
{
	world_t w;

	init_world(&w, 3, 1, 100, true, false);
	clear_ops();
	ck_fail(&w.rs_ck[0]);
	ck_fail(&w.rs_ck[1]);
	clear_ops();

	ck_fail(&w.rs_ck[2]);
	expect_ops("all primaries dead: failover pool beats sorry server", "DEL rs3,ADD b1");

	ck_fail(&w.backup_ck[0]);
	expect_ops("failover pool exhausted: sorry server takes over", "DEL b1,ADD sorry");
	expect("failover state is down with sorry active", !w.vs.failover_state_up && w.sorry.alive);

	ck_up(&w.backup_ck[0]);
	expect_ops("backup recovers: sorry server yields to failover pool", "DEL sorry,ADD b1");
	expect("failover state is up again", w.vs.failover_state_up && !w.sorry.alive);
}

/* Without a failover pool the quorum / sorry server behaviour must be
 * exactly the historic one */
static void
test_legacy_regression(void)
{
	world_t w;

	init_world(&w, 2, 0, 100, true, false);
	expect_ops("legacy init", "SVC_ADD,ADD rs1,ADD rs2");

	ck_fail(&w.rs_ck[0]);
	expect_ops("legacy: one server fails", "DEL rs1");
	ck_fail(&w.rs_ck[1]);
	expect_ops("legacy: quorum lost, sorry server added", "DEL rs2,ADD sorry");
	ck_up(&w.rs_ck[0]);
	expect_ops("legacy: quorum regained, sorry removed", "DEL sorry,ADD rs1");
}

/* Reload: failover state and backup RS state must carry over without
 * spurious IPVS commands; a removed pool reinstates the primaries */
static void
test_reload(void)
{
	static world_t w_old, w_new;
	checker_t *ck;
	unsigned i;

	/* Old world: threshold 50, rs1 dead, rs2 alive, failover active */
	init_world(&w_old, 2, 2, 50, false, false);
	clear_ops();
	ck_fail(&w_old.rs_ck[0]);
	expect("reload setup: failover active", w_old.vs.failover_state_up);
	clear_ops();

	/* New world with the same configuration */
	memset(&w_new, 0, sizeof(w_new));
	init_world(&w_new, 2, 2, 50, false, false);
	/* init_world called init_services() for the new world; that is not
	 * the reload flow, so rebuild states as freshly parsed config */
	for (i = 0; i < 2; i++) {
		w_new.rs[i].alive = false;
		w_new.rs[i].set = false;
		w_new.backup[i].alive = false;
		w_new.backup[i].set = false;
		w_new.vs.alive = false;
	}
	/* Give every new RS a checker reflecting its old state, so
	 * migrate_checkers() computes the correct failed count */
	for (i = 0; i < 2; i++) {
		ck = &w_new.rs_ck[i];
		ck->has_run = true;
		ck->is_up = (i != 0);	/* rs1 down, rs2 up */
		list_add_tail(&ck->rs_list, &w_new.rs[i].checkers_list);
		ck = &w_new.backup_ck[i];
		ck->has_run = true;
		ck->is_up = true;
		list_add_tail(&ck->rs_list, &w_new.backup[i].checkers_list);
	}
	w_new.rs[0].num_failed_checkers = 1;

	check_data = &w_new.cdata;
	old_check_data = &w_old.cdata;
	reload = true;
	clear_ops();

	clear_diff_services();
	expect_ops("reload with unchanged config: no IPVS ops", "");
	expect("reload: failover state carried over", w_new.vs.failover_state_up);
	expect("reload: backup set flags carried over", w_new.backup[0].set && w_new.backup[1].set);
	expect("reload: primary state carried over", !w_new.rs[0].alive && w_new.rs[1].alive && !w_new.rs[1].set);

	/* Now reload again, removing the failover pool from the config */
	static world_t w_final;
	init_world(&w_final, 2, 0, 100, false, false);
	w_final.rs[0].alive = false;
	w_final.rs[0].set = false;
	w_final.rs[1].alive = false;
	w_final.rs[1].set = false;
	w_final.vs.alive = false;
	for (i = 0; i < 2; i++) {
		ck = &w_final.rs_ck[i];
		ck->has_run = true;
		ck->is_up = (i != 0);
		list_add_tail(&ck->rs_list, &w_final.rs[i].checkers_list);
	}
	w_final.rs[0].num_failed_checkers = 1;

	/* init_world() reset the name table - the old world's backups
	 * still appear in the diff and need names for the op log */
	name_rs(&w_new.backup[0], "b1");
	name_rs(&w_new.backup[1], "b2");

	check_data = &w_final.cdata;
	old_check_data = &w_new.cdata;
	reload = true;
	clear_ops();

	clear_diff_services();
	expect_ops("reload removing the pool: backups removed, alive primaries reinstated",
		   "DEL b1,DEL b2,ADD rs2");
	expect("reload: failover state cleared", !w_final.vs.failover_state_up);

	reload = false;
}

/* Reload while the failover pool is active, with a checker state
 * migration raising a primary up event mid-diff: the pool decision
 * must be deferred to init_services() so it runs against fully
 * migrated state, then converge with a clean revert */
static void
test_reload_migration_reentry(void)
{
	static world_t w_old, w_new;
	checker_t *ck;
	unsigned i;

	/* Old world: threshold 50 of 2, rs1 dead => failover active */
	init_world(&w_old, 2, 2, 50, false, false);
	clear_ops();
	ck_fail(&w_old.rs_ck[0]);
	expect("reentry setup: failover active", w_old.vs.failover_state_up);
	clear_ops();

	/* New world: rs1's failing checker has been removed from the
	 * configuration, so checker migration raises it up mid-diff */
	init_world(&w_new, 2, 2, 50, false, false);
	for (i = 0; i < 2; i++) {
		w_new.rs[i].alive = false;
		w_new.rs[i].set = false;
		w_new.backup[i].alive = false;
		w_new.backup[i].set = false;
	}
	w_new.vs.alive = false;
	ck = &w_new.rs_ck[1];		/* rs1 gets no checkers at all */
	ck->has_run = true;
	ck->is_up = true;
	list_add_tail(&ck->rs_list, &w_new.rs[1].checkers_list);
	for (i = 0; i < 2; i++) {
		ck = &w_new.backup_ck[i];
		ck->has_run = true;
		ck->is_up = true;
		list_add_tail(&ck->rs_list, &w_new.backup[i].checkers_list);
	}

	check_data = &w_new.cdata;
	old_check_data = &w_old.cdata;
	reload = true;
	clear_ops();

	clear_diff_services();
	expect_ops("reload with mid-diff up event: no IPVS ops during the diff", "");
	expect("mid-diff up event recorded but pool untouched",
	       w_new.rs[0].alive && !w_new.rs[0].set && w_new.vs.failover_state_up);

	init_services();
	expect_ops("init after reload converges: backups out, primaries in",
		   "DEL b1,DEL b2,ADD rs1,ADD rs2");
	expect("converged state is consistent",
	       !w_new.vs.failover_state_up &&
	       w_new.rs[0].set && w_new.rs[1].set &&
	       !w_new.backup[0].set && !w_new.backup[1].set);

	reload = false;
}

/* inhibit_on_failure on a backup member only applies while the pool is
 * active: reverting must remove its weight-0 entry from the table */
static void
test_inhibited_backup_revert(void)
{
	world_t w;

	init_world(&w, 2, 1, 50, false, false);
	w.backup[0].inhibit = true;
	clear_ops();

	ck_fail(&w.rs_ck[0]);
	expect_ops("switch with inhibited backup", "DEL rs1,DEL rs2,ADD b1");

	ck_fail(&w.backup_ck[0]);
	expect_ops("inhibited backup fails while active: disabled then removed on revert",
		   "EDIT b1,DEL b1,ADD rs2");
	expect("inhibited backup not left in the table", !w.backup[0].set);

	ck_up(&w.rs_ck[0]);
	expect_ops("primary recovers", "ADD rs1");

	ck_up(&w.backup_ck[0]);
	expect_ops("inhibited backup recovers while pool inactive: no IPVS ops", "");
	expect("inhibited backup stays out of the table while pool inactive",
	       !w.backup[0].set && w.backup[0].alive);
}

/* Alpha mode startup: sorry server first, failover pool once its
 * checkers succeed, primary once it recovers */
static void
test_alpha_init(void)
{
	world_t w;

	init_world(&w, 3, 1, 100, true, true);
	expect_ops("alpha init: only the sorry server is added", "SVC_ADD,ADD sorry");

	ck_up(&w.backup_ck[0]);
	expect_ops("alpha: backup passes checks, replaces sorry server", "DEL sorry,ADD b1");

	ck_up(&w.rs_ck[0]);
	expect_ops("alpha: primary passes checks, pool reverts to primary", "DEL b1,ADD rs1");
}

int
main(void)
{
	test_default_threshold();
	test_percent_rounding();
	test_exact_boundary();
	test_recovery();
	test_backup_flap();
	test_primary_flap_while_backup_active();
	test_sorry_layering();
	test_legacy_regression();
	test_reload();
	test_reload_migration_reentry();
	test_inhibited_backup_revert();
	test_alpha_init();

	printf("%s\n", fails ? "FAILURES" : "all tests passed");

	return fails;
}
