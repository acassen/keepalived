/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Manipulation functions for IPVS & IPFW wrappers.
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

#include <unistd.h>
#include <inttypes.h>

#include "ipwrapper.h"
#include "check_api.h"
#include "logger.h"
#include "utils.h"
#include "main.h"
#ifdef _WITH_SNMP_CHECKER_
  #include "check_snmp.h"
#endif
#include "global_data.h"
#include "smtp.h"
#include "check_daemon.h"
#include "track_file.h"
#include "decimal_chars.h"
#ifdef _WITH_NFTABLES_
#include "check_nftables.h"
#include "check_data.h"
#endif

static bool __attribute((pure))
vs_iseq(const virtual_server_t *vs_a, const virtual_server_t *vs_b)
{
	if (!vs_a->vsgname != !vs_b->vsgname)
		return false;

	if (vs_a->vsgname) {
		/* Should we check the vsg entries match? */
		if (inet_sockaddrport(&vs_a->addr) != inet_sockaddrport(&vs_b->addr))
			return false;

		return !strcmp(vs_a->vsgname, vs_b->vsgname);
	} else if (vs_a->af != vs_b->af)
		return false;
	else if (vs_a->vfwmark) {
		if (vs_a->vfwmark != vs_b->vfwmark)
			return false;
	} else {
		if (vs_a->service_type != vs_b->service_type ||
		    !sockstorage_equal(&vs_a->addr, &vs_b->addr))
			return false;
	}

	return true;
}

static bool __attribute((pure))
vsge_iseq(const virtual_server_group_entry_t *vsge_a, const virtual_server_group_entry_t *vsge_b)
{
	if (vsge_a->is_fwmark != vsge_b->is_fwmark)
		return false;

	if (vsge_a->is_fwmark)
		return vsge_a->vfwmark == vsge_b->vfwmark;

	if (!sockstorage_equal(&vsge_a->addr, &vsge_b->addr) ||
	    !sockstorage_equal(&vsge_a->addr_end, &vsge_b->addr_end))
		return false;

	return true;
}

/* Returns the sum of all alive RS weight in a pool of a virtual server.
 * The primary pool is NULL. Since the weight of a real server defaults
 * to 1, this is the number of alive real servers unless weights are
 * configured. */
static unsigned long __attribute__ ((pure))
weigh_live_realservers(virtual_server_t *vs, const failover_pool_t *pool)
{
	real_server_t *rs;
	long count = 0;

	list_for_each_entry(rs, &vs->rs, e_list) {
		if (rs->pool == pool && ISALIVE(rs))
			count += real_weight(rs->effective_weight);
	}
	return count;
}

static bool __attribute__ ((pure))
pool_has_alive_rs(virtual_server_t *vs, const failover_pool_t *pool)
{
	real_server_t *rs;

	list_for_each_entry(rs, &vs->rs, e_list) {
		if (rs->pool == pool && ISALIVE(rs))
			return true;
	}

	return false;
}

static unsigned __attribute__ ((pure))
pool_priority(const failover_pool_t *pool)
{
	return pool ? pool->priority : 0;
}

static failover_pool_t * __attribute__ ((pure))
find_failover_pool(virtual_server_t *vs, unsigned priority)
{
	failover_pool_t *pool;

	list_for_each_entry(pool, &vs->failover_pools, e_list) {
		if (pool->priority == priority)
			return pool;
	}

	return NULL;
}

/* Set while clear_diff_services() is migrating the state of the old
 * configuration to the new one. Migrating the checkers can bring real
 * servers up while the alive state of the other real servers has not
 * yet been copied, so quorum and pool changes are deferred until
 * init_services() runs update_quorum_state() on the migrated state. */
static bool migrating_diff;

static void
notify_fifo_vs(virtual_server_t *vs)
{
	const char *state = vs->quorum_state_up ? "UP" : "DOWN";
	size_t size;
	char *line;
	const char *vs_str;

	if (global_data->notify_fifo.fd == -1 &&
	    global_data->lvs_notify_fifo.fd == -1)
		return;

	vs_str = FMT_VS(vs);
	size = strlen(vs_str) + strlen(state) + 5 + 1;
	line = MALLOC(size);
	if (!line)
		return;

	snprintf(line, size, "VS %s %s\n", vs_str, state);

	if (global_data->notify_fifo.fd != -1)
		if (write(global_data->notify_fifo.fd, line, size) == -1) { /* empty */ }

	if (global_data->lvs_notify_fifo.fd != -1)
		if (write(global_data->lvs_notify_fifo.fd, line, size) == -1) { /* empty */ }

	FREE(line);
}

static void
notify_fifo_pool(virtual_server_t *vs, failover_pool_t *pool)
{
	const char *state = pool->quorum_state_up ? "UP" : "DOWN";
	size_t size;
	char *line;
	const char *vs_str;

	if (global_data->notify_fifo.fd == -1 &&
	    global_data->lvs_notify_fifo.fd == -1)
		return;

	vs_str = FMT_VS(vs);
	size = 5 + TYPE_MAX_CHRS(pool->priority) + 1 + strlen(vs_str) + 1 + strlen(state) + 1 + 1;
	line = MALLOC(size);
	if (!line)
		return;

	size = (size_t)snprintf(line, size, "POOL %u %s %s\n", pool->priority, vs_str, state);

	if (global_data->notify_fifo.fd != -1)
		if (write(global_data->notify_fifo.fd, line, size) == -1) { /* empty */ }

	if (global_data->lvs_notify_fifo.fd != -1)
		if (write(global_data->lvs_notify_fifo.fd, line, size) == -1) { /* empty */ }

	FREE(line);
}

static void
notify_fifo_rs(virtual_server_t* vs, real_server_t* rs)
{
	const char *state = rs->alive ? "UP" : "DOWN";
	size_t size;
	char *line;
	const char *rs_str;
	const char *vs_str;

	if (global_data->notify_fifo.fd == -1 &&
	    global_data->lvs_notify_fifo.fd == -1)
		return;

	rs_str = FMT_RS(rs, vs);
	vs_str = FMT_VS(vs);
	size = strlen(rs_str) + strlen(vs_str) + strlen(state) + 6 + 1;
	line = MALLOC(size);
	if (!line)
		return;

	snprintf(line, size, "RS %s %s %s\n", rs_str, vs_str, state);

	if (global_data->notify_fifo.fd != -1)
		if (write(global_data->notify_fifo.fd, line, size) == - 1) { /* empty */ }

	if (global_data->lvs_notify_fifo.fd != -1)
		if (write(global_data->lvs_notify_fifo.fd, line, size) == -1) { /* empty */ }

	FREE(line);
}

static void
do_vs_notifies(virtual_server_t* vs, bool init, long threshold, long weight_sum, bool stopping)
{
	notify_script_t *notify_script = vs->quorum_state_up ? vs->notify_quorum_up : vs->notify_quorum_down;
	char message[80];

#ifdef _WITH_SNMP_CHECKER_
	check_snmp_quorum_trap(vs, stopping);
#endif

	/* Only send non SNMP notifies when stopping if omega set */
	if (stopping && !vs->omega)
		return;

	if (notify_script) {
		if (stopping)
			system_call_script(master, child_killed_thread, NULL, TIMER_HZ, notify_script);
		else
			notify_exec(notify_script);
	}

	notify_fifo_vs(vs);

	if (vs->smtp_alert) {
		if (stopping)
			snprintf(message, sizeof(message), "=> Shutting down <=");
		else
			snprintf(message, sizeof(message), "=> %s %u+%u=%ld <= %ld <=",
				    vs->quorum_state_up ?
						   init ? "Starting with quorum up" :
							  "Gained quorum" :
						   init ? "Starting with quorum down" :
							  "Lost quorum",
				    vs->quorum,
				    vs->hysteresis,
				    threshold,
				    weight_sum);
		smtp_alert(SMTP_MSG_VS, vs, vs->quorum_state_up ? "UP" : "DOWN", message);
	}
}

static void
do_pool_notifies(virtual_server_t* vs, failover_pool_t *pool, bool init, long threshold, long weight_sum, bool stopping)
{
	notify_script_t *notify_script = pool->quorum_state_up ? pool->notify_quorum_up : pool->notify_quorum_down;
	char message[80];
	char subject[32];

	/* Only send notifies when stopping if omega set */
	if (stopping && !vs->omega)
		return;

	if (notify_script) {
		if (stopping)
			system_call_script(master, child_killed_thread, NULL, TIMER_HZ, notify_script);
		else
			notify_exec(notify_script);
	}

	notify_fifo_pool(vs, pool);

	if (vs->smtp_alert) {
		if (stopping)
			snprintf(message, sizeof(message), "=> Failover pool %u shutting down <=", pool->priority);
		else
			snprintf(message, sizeof(message), "=> Failover pool %u %s %u+%u=%ld <= %ld <=",
				    pool->priority,
				    pool->quorum_state_up ?
						   init ? "starting with quorum up" :
							  "gained quorum" :
						   init ? "starting with quorum down" :
							  "lost quorum",
				    pool->quorum,
				    pool->hysteresis,
				    threshold,
				    weight_sum);
		snprintf(subject, sizeof(subject), "POOL %u %s", pool->priority, pool->quorum_state_up ? "UP" : "DOWN");
		smtp_alert(SMTP_MSG_VS, vs, subject, message);
	}
}

static void
do_rs_notifies(virtual_server_t* vs, real_server_t* rs, bool stopping)
{
	notify_script_t *notify_script = rs->alive ? rs->notify_up : rs->notify_down;

	if (notify_script) {
		if (stopping)
			system_call_script(master, child_killed_thread, NULL, TIMER_HZ, notify_script);
		else
			notify_exec(notify_script);
	}

	notify_fifo_rs(vs, rs);

	/* The sending of smtp_alerts is handled by the individual checker
	 * so that the message can have context for the checker */

#ifdef _WITH_SNMP_CHECKER_
	check_snmp_rs_trap(rs, vs, stopping);
#endif
}

/* Remove a realserver IPVS rule */
static void
update_vs_notifies(virtual_server_t *vs, bool stopping)
{
	failover_pool_t *pool;
	long threshold = vs->quorum - vs->hysteresis;
	long weight_sum;

	/* Sooner or later VS will lose the quorum (if any). However,
	 * we don't push in a sorry server then, hence the regression
	 * is intended.
	 */
	weight_sum = weigh_live_realservers(vs, NULL);
	if (stopping ||
	    (vs->quorum_state_up &&
	     (!weight_sum || weight_sum < threshold))) {
		vs->quorum_state_up = false;
		do_vs_notifies(vs, false, threshold, weight_sum, stopping);
	}

	list_for_each_entry(pool, &vs->failover_pools, e_list) {
		threshold = pool->quorum - pool->hysteresis;
		weight_sum = weigh_live_realservers(vs, pool);
		if (pool->quorum_state_up &&
		    (stopping || !weight_sum || weight_sum < threshold)) {
			pool->quorum_state_up = false;
			do_pool_notifies(vs, pool, false, threshold, weight_sum, stopping);
		}
	}
}

static void
clear_service_rs(virtual_server_t *vs, real_server_t *rs, bool stopping)
{
	smtp_rs rs_info = { .vs = vs };
	bool sav_inhibit;

	if (rs->set || stopping)
		log_message(LOG_INFO, "%s %sservice %s from VS %s",
				stopping ? "Shutting down" : "Removing",
				rs->inhibit && !rs->alive ? "(inhibited) " : "",
				FMT_RS(rs, vs),
				FMT_VS(vs));

	if (!rs->set)
		return;

	/* Force removal of real servers with inhibit_on_failure set */
	sav_inhibit = rs->inhibit;
	rs->inhibit = false;

	ipvs_cmd(LVS_CMD_DEL_DEST, vs, rs);

	rs->inhibit = sav_inhibit;	/* Restore inhibit flag */

	if (!rs->alive)
		return;

	UNSET_ALIVE(rs);

	/* We always want to send SNMP messages on shutdown */
	if (!vs->omega && stopping) {
#ifdef _WITH_SNMP_CHECKER_
		check_snmp_rs_trap(rs, vs, true);
#endif
		return;
	}

	/* In Omega mode we call VS and RS down notifiers
	 * all the way down the exit, as necessary.
	 */
	do_rs_notifies(vs, rs, stopping);

	/* Send SMTP alert */
	if (rs->smtp_alert) {
		rs_info.rs = rs;
		smtp_alert(SMTP_MSG_RS_SHUT, &rs_info, "DOWN", stopping ? "=> Shutting down <=" : "=> Removing <=");
	}

}

static void
clear_service_rs_list(virtual_server_t *vs, list_head_t *l, bool stopping)
{
	real_server_t *rs;

	list_for_each_entry(rs, l, e_list)
		clear_service_rs(vs, rs, stopping);

	update_vs_notifies(vs, stopping);
}

static void
clear_vsg_rs_counts(virtual_server_t *vs)
{
	virtual_server_group_entry_t *vsg_entry;
	real_server_t *rs;

	/* Only the real servers in the IPVS table have been counted */
	list_for_each_entry(vsg_entry, &vs->vsg->addr_range, e_list) {
		list_for_each_entry(rs, &vs->rs, e_list) {
			if (rs->set)
				unset_vsge_alive(vsg_entry, vs);
		}
	}

	list_for_each_entry(vsg_entry, &vs->vsg->vfwmark, e_list) {
		list_for_each_entry(rs, &vs->rs, e_list) {
			if (rs->set)
				unset_vsge_alive(vsg_entry, vs);
		}
	}
}

/* Remove a virtualserver IPVS rule */
static void
clear_service_vs(virtual_server_t * vs, bool stopping)
{
	bool sav_inhibit;

	if (global_data->lvs_flush_on_stop == LVS_NO_FLUSH) {
		/* Processing real server queue */
		if (vs->s_svr && vs->s_svr->set) {
			if (vs->s_svr_duplicates_rs)
				vs->s_svr->set = false;
			else {
				/* Ensure removed if inhibit_on_failure set */
				sav_inhibit = vs->s_svr->inhibit;
				vs->s_svr->inhibit = false;

				ipvs_cmd(LVS_CMD_DEL_DEST, vs, vs->s_svr);

				vs->s_svr->inhibit = sav_inhibit;
			}

			UNSET_ALIVE(vs->s_svr);
		}

		/* Even if the sorry server was configured, if we are using
		 * inhibit_on_failure, then real servers may be configured. */
		clear_service_rs_list(vs, &vs->rs, stopping);
	} else {
		update_vs_notifies(vs, stopping);

		if (global_data->lvs_flush_on_stop == LVS_FLUSH_VS && vs->vsg)
			clear_vsg_rs_counts(vs);

		if (vs->s_svr && vs->s_svr->set)
			UNSET_ALIVE(vs->s_svr);
	}

	/* The above will handle Omega case for VS as well. */

#ifdef _WITH_NFTABLES_
	if (VS_USES_VSG_AUTO_FWMARK(vs))
		clear_vs_fwmark(vs);
#endif

	ipvs_cmd(LVS_CMD_DEL, vs, NULL);

	UNSET_ALIVE(vs);
}

/* IPVS cleaner processing */
void
clear_services(void)
{
	virtual_server_t *vs;

	if (!check_data || list_empty(&check_data->vs))
		return;

	if (global_data->lvs_flush_on_stop == LVS_FLUSH_FULL) {
		ipvs_flush_cmd();

		list_for_each_entry(vs, &check_data->vs, e_list)
			update_vs_notifies(vs, true);
	} else {
		list_for_each_entry(vs, &check_data->vs, e_list) {
			/* Remove the real servers, and clear the vs unless it is
			 * using a VS group and it is not the last vs of the same
			 * protocol or address family using the group. */
			clear_service_vs(vs, true);
		}
	}

#ifdef _WITH_NFTABLES_
	if (global_data->ipvs_nf_table_name)
		nft_ipvs_end();
#endif
}

/* Set a realserver IPVS rules */
static void
init_service_rs(virtual_server_t *vs)
{
	real_server_t *rs;
	tracked_file_monitor_t *tfm;
	int64_t new_weight;

	list_for_each_entry(rs, &vs->rs, e_list) {
		if (rs->reloaded) {
			if (rs->effective_weight != rs->peffective_weight) {
				/* We need to force a change from the previous weight */
				new_weight = rs->effective_weight;
				rs->effective_weight = rs->peffective_weight;
				update_svr_wgt(new_weight, vs, rs, false);
			}

			/* Do not re-add failed RS instantly on reload */
			continue;
		}

		/* On a reload with a new RS the num_failed_checkers is updated in set_track_file_checkers_down() */
		if (!reload) {
			list_for_each_entry(tfm, &rs->track_files, e_list) {
				if (tfm->weight) {
					if ((int64_t)tfm->file->last_status * tfm->weight * (tfm->weight_reverse ? -1 : 1) <= IPVS_WEIGHT_FAULT)
						rs->num_failed_checkers++;
				}
				else if (tfm->file->last_status)
					rs->num_failed_checkers++;
			}
		}

		/* In alpha mode, be pessimistic (or realistic?) and don't
		 * add real servers into the VS pool unless inhibit_on_failure.
		 * They will get there later upon healthchecks recovery (if ever).
		 * The real servers of a pool that is not in use are only added,
		 * with weight 0, if inhibit_on_failure is set.
		 */
		if ((!rs->num_failed_checkers && !ISALIVE(rs)) ||
		    (rs->inhibit && !rs->set)) {
			if (rs->num_failed_checkers || rs_pool_active(vs, rs))
				ipvs_cmd(LVS_CMD_ADD_DEST, vs, rs);
			else if (rs->inhibit && !rs->set) {
				/* ipvs_cmd() adds an inhibited real server with
				 * failed checkers with weight 0 */
				rs->num_failed_checkers = 1;
				ipvs_cmd(LVS_CMD_ADD_DEST, vs, rs);
				rs->num_failed_checkers = 0;
			}
			if (!rs->num_failed_checkers) {
				SET_ALIVE(rs);
				if (global_data->rs_init_notifies)
					do_rs_notifies(vs, rs, false);
			}
		}
	}
}

static void
sync_service_vsg_entry(virtual_server_t *vs, const list_head_t *l)
{
	virtual_server_group_entry_t *vsge;

	list_for_each_entry(vsge, l, e_list) {
		if (!vsge->reloaded) {
			if (vsge->is_fwmark)
				log_message(LOG_INFO, "VS [FWM %u] added into group %s"
						    , vsge->vfwmark
						    , vs->vsgname);
			else if (!inet_sockaddrcmp(&vsge->addr, &vsge->addr_end))
				log_message(LOG_INFO, "VS [%s] added into group %s"
						    , inet_sockaddrtotrio(&vsge->addr, vs->service_type)
						    , vs->vsgname);
			else
				log_message(LOG_INFO, "VS [%s-%s] added into group %s"
						    , inet_sockaddrtotrio(&vsge->addr, vs->service_type)
						    , inet_sockaddrtos(&vsge->addr_end)
						    , vs->vsgname);
			/* add all reloaded and alive/inhibit-set dests
			 * to the newly created vsg item */
			ipvs_group_sync_entry(vs, vsge);
		}
	}
}
static void
sync_service_vsg(virtual_server_t *vs)
{
	virtual_server_group_t *vsg = vs->vsg;

	sync_service_vsg_entry(vs, &vsg->addr_range);
	sync_service_vsg_entry(vs, &vsg->vfwmark);
}

/* add or remove the _alive_ real servers of a pool from a virtual server */
static void
perform_pool_state(virtual_server_t *vs, const failover_pool_t *pool, bool add)
{
	real_server_t *rs;

	if (pool)
		log_message(LOG_INFO, "%s failover pool %u %s VS %s"
				    , add?"Adding alive servers of":"Removing alive servers of"
				    , pool->priority
				    , add?"to":"from"
				    , FMT_VS(vs));
	else
		log_message(LOG_INFO, "%s the pool for VS %s"
				    , add?"Adding alive servers to":"Removing alive servers from"
				    , FMT_VS(vs));
	list_for_each_entry(rs, &vs->rs, e_list) {
		if (rs->pool != pool)
			continue;
		if (!ISALIVE(rs)) /* We only handle alive servers */
			continue;
		/* Nothing to do if already added (an inhibited server is
		 * updated to its weight) or removed */
		if (add ? rs->set && !rs->inhibit : !rs->set)
			continue;
		/* ipvs_cmd() uses the alive state to determine if the
		 * entries of a virtual server group need updating */
		if (add)
			rs->alive = false;
		ipvs_cmd(add?LVS_CMD_ADD_DEST:LVS_CMD_DEL_DEST, vs, rs);
		rs->alive = true;
	}
}

static void
activate_sorry_server(virtual_server_t *vs)
{
	log_message(LOG_INFO, "%s sorry server %s to VS %s"
			    , (vs->s_svr->inhibit ? "Enabling" : "Adding")
			    , FMT_RS(vs->s_svr, vs)
			    , FMT_VS(vs));

	/* the sorry server is now up in the pool, we flag it alive */
	ipvs_cmd(LVS_CMD_ADD_DEST, vs, vs->s_svr);
	vs->s_svr->alive = true;
}

static void
deactivate_sorry_server(virtual_server_t *vs)
{
	log_message(LOG_INFO, "%s sorry server %s from VS %s"
			    , (vs->s_svr->inhibit ? "Disabling" : "Removing")
			    , FMT_RS(vs->s_svr, vs)
			    , FMT_VS(vs));

	ipvs_cmd(LVS_CMD_DEL_DEST, vs, vs->s_svr);
	vs->s_svr->alive = false;
}

/* The pool to use is the highest priority pool that has quorum. If no
 * pool has quorum the sorry server is used, and returns NULL. If there
 * is no sorry server either, the highest priority pool with any alive
 * real servers is used; without failover pools that is always the
 * primary pool, which is the behaviour without failover pools. */
static bool
select_pool(virtual_server_t *vs, failover_pool_t **selected)
{
	failover_pool_t *pool;

	*selected = NULL;

	if (vs->quorum_state_up)
		return true;

	list_for_each_entry(pool, &vs->failover_pools, e_list) {
		if (pool->quorum_state_up) {
			*selected = pool;
			return true;
		}
	}

	if (vs->s_svr)
		return false;

	if (pool_has_alive_rs(vs, NULL))
		return true;

	list_for_each_entry(pool, &vs->failover_pools, e_list) {
		if (pool_has_alive_rs(vs, pool)) {
			*selected = pool;
			return true;
		}
	}

	return true;
}

static void
log_pool_switch(virtual_server_t *vs, const failover_pool_t *pool)
{
	if (pool)
		log_message(LOG_INFO, "Switching VS %s to failover pool %u", FMT_VS(vs), pool->priority);
	else
		log_message(LOG_INFO, "Switching VS %s to the primary pool", FMT_VS(vs));
}

/* Make the IPVS table use the selected pool, or the sorry server */
static void
update_active_pool(virtual_server_t *vs)
{
	failover_pool_t *pool;
	const failover_pool_t *old_pool = vs->active_pool;
	bool use_sorry_server = !select_pool(vs, &pool);

	if (vs->s_svr && ISALIVE(vs->s_svr)) {
		if (use_sorry_server)
			return;

		/* Removing sorry server since we don't need it anymore */
		deactivate_sorry_server(vs);

		/* Adding back alive real servers */
		vs->active_pool = pool;
		if (pool)
			log_pool_switch(vs, pool);
		perform_pool_state(vs, pool, true);

		return;
	}

	if (use_sorry_server) {
		/* Remove remaining alive real servers */
		perform_pool_state(vs, old_pool, false);
		vs->active_pool = NULL;

		activate_sorry_server(vs);

		return;
	}

	if (pool == old_pool)
		return;

	/* Add the alive real servers of the new pool before removing
	 * those of the old pool, so that there are always real servers
	 * in the IPVS table */
	log_pool_switch(vs, pool);
	vs->active_pool = pool;
	perform_pool_state(vs, pool, true);
	perform_pool_state(vs, old_pool, false);
}

void
set_quorum_states(void)
{
	virtual_server_t *vs;
	failover_pool_t *pool;

	list_for_each_entry(vs, &check_data->vs, e_list) {
		vs->quorum_state_up = (weigh_live_realservers(vs, NULL) >= vs->quorum + vs->hysteresis);

		list_for_each_entry(pool, &vs->failover_pools, e_list)
			pool->quorum_state_up = (weigh_live_realservers(vs, pool) >= pool->quorum + pool->hysteresis);
	}
}

/* set quorum state of a failover pool depending on current weight of its
 * real servers. Returns true if the quorum state has changed. */
static bool
update_pool_quorum_state(virtual_server_t *vs, failover_pool_t *pool)
{
	long weight_sum = weigh_live_realservers(vs, pool);
	long threshold;

	threshold = pool->quorum + (pool->quorum_state_up ? -1 : 1) * pool->hysteresis;

	if (!pool->quorum_state_up &&
	    weight_sum >= threshold) {
		pool->quorum_state_up = true;
		log_message(LOG_INFO, "Gained quorum %u+%u=%ld <= %ld for failover pool %u of VS %s"
				    , pool->quorum
				    , pool->hysteresis
				    , threshold
				    , weight_sum
				    , pool->priority
				    , FMT_VS(vs));
	} else if (pool->quorum_state_up &&
		   (!weight_sum || weight_sum < threshold)) {
		pool->quorum_state_up = false;
		log_message(LOG_INFO, "Lost quorum %u-%u=%ld > %ld for failover pool %u of VS %s"
				    , pool->quorum
				    , pool->hysteresis
				    , threshold
				    , weight_sum
				    , pool->priority
				    , FMT_VS(vs));
	} else
		return false;

	return true;
}

/* Notify the quorum state changes of the failover pools, once the IPVS
 * table has been updated */
static void
notify_pool_quorum_states(virtual_server_t *vs, const bool *changed, bool init)
{
	failover_pool_t *pool;
	long threshold;
	unsigned i = 0;

	list_for_each_entry(pool, &vs->failover_pools, e_list) {
		if (!changed[i++])
			continue;

		/* The threshold that was crossed */
		threshold = pool->quorum + (pool->quorum_state_up ? 1 : -1) * pool->hysteresis;
		do_pool_notifies(vs, pool, init, threshold, weigh_live_realservers(vs, pool), false);
	}
}

/* set quorum state depending on current weight of real servers, and
 * use the pool, or sorry server, that is then required */
static void
update_quorum_state(virtual_server_t * vs, bool init)
{
	long weight_sum = weigh_live_realservers(vs, NULL);
	long threshold;
	failover_pool_t *pool;
	bool pool_quorum_up = false;
	bool pool_changed[FAILOVER_POOL_PRIORITY_MAX];
	unsigned i = 0;

	list_for_each_entry(pool, &vs->failover_pools, e_list) {
		pool_changed[i++] = update_pool_quorum_state(vs, pool);
		if (pool->quorum_state_up)
			pool_quorum_up = true;
	}

	threshold = vs->quorum + (vs->quorum_state_up ? -1 : 1) * vs->hysteresis;

	/* If we have just gained quorum, it's time to consider notify_up. */
	if (!vs->quorum_state_up &&
	    weight_sum >= threshold) {
		vs->quorum_state_up = true;
		log_message(LOG_INFO, "Gained quorum %u+%u=%ld <= %ld for VS %s"
				    , vs->quorum
				    , vs->hysteresis
				    , threshold
				    , weight_sum
				    , FMT_VS(vs));

		/* Remove the sorry server or failover pool if in use */
		update_active_pool(vs);

		do_vs_notifies(vs, init, threshold, weight_sum, false);
	}
	else if ((vs->quorum_state_up &&
		  (!weight_sum || weight_sum < threshold)) ||
		 (init && !vs->quorum_state_up && !pool_quorum_up &&
		  vs->s_svr && !ISALIVE(vs->s_svr))) {
		/* We have just lost quorum for the VS, we need to consider
		 * VS notify_down, failover pool and sorry_server cases
		 *   or
		 * We are starting up and need to add the sorry server
		 */
		vs->quorum_state_up = false;
		log_message(LOG_INFO, "%s %u-%u=%ld > %ld for VS %s"
				    , init ? "Starting with quorum down" : "Lost quorum"
				    , vs->quorum
				    , vs->hysteresis
				    , threshold
				    , weight_sum
				    , FMT_VS(vs));

		/* Use a failover pool or the sorry server if there is one */
		update_active_pool(vs);

		do_vs_notifies(vs, init, threshold, weight_sum, false);
	}
	else {
		/* A failover pool may have gained or lost quorum */
		update_active_pool(vs);
	}

	notify_pool_quorum_states(vs, pool_changed, init);
}

/* manipulate add/remove rs according to alive state */
static bool
perform_svr_state(bool alive, checker_t *checker)
{
	/*
	 * | ISALIVE(rs) | alive | context
	 * | false       | false | first check failed under alpha mode, unreachable here
	 * | false       | true  | RS went up, add it to the pool
	 * | true        | false | RS went down, remove it from the pool
	 * | true        | true  | first check succeeded w/o alpha mode, unreachable here
	 */

	virtual_server_t * vs = checker->vs;
	real_server_t * rs = checker->rs;

	if (ISALIVE(rs) == alive)
		return true;

	log_message(LOG_INFO, "%sing service %s %s VS %s"
			    , alive ? (rs->inhibit) ? "Enabl" : "Add" :
				      (rs->inhibit) ? "Disabl" : "Remov"
			    , FMT_RS(rs, vs)
			    , (rs->inhibit) ? "of" : alive ? "to" : "from"
			    , FMT_VS(vs));

	/* Change only if the real server's pool is in use */
	if (rs_pool_active(vs, rs)) {
		if (ipvs_cmd(alive ? LVS_CMD_ADD_DEST : LVS_CMD_DEL_DEST, vs, rs))
			return false;
	}
	rs->alive = alive;
	do_rs_notifies(vs, rs, false);

	/* We may have changed quorum state. If the quorum wasn't up
	 * but is now up, this is where the rs is added. */
	if (!migrating_diff)
		update_quorum_state(vs, false);

	return true;
}

/* Set a virtualserver IPVS rules */
static bool
init_service_vs(virtual_server_t * vs)
{
	/* Init the VS root */
	if (!ISALIVE(vs) || vs->vsg) {
#ifdef _WITH_NFTABLES_
		if (ISALIVE(vs) &&
		    VS_USES_VSG_AUTO_FWMARK(vs))
			set_vs_fwmark(vs);
		else
#endif
		{
			ipvs_cmd(LVS_CMD_ADD, vs, NULL);
			SET_ALIVE(vs);
		}
	}

	/* Processing real server queue */
	init_service_rs(vs);

	if (vs->reloaded && vs->vsg
#ifdef _WITH_NFTABLES_
	    && !VS_USES_VSG_AUTO_FWMARK(vs)
#endif
				    ) {
		/* add reloaded dests into new vsg entries */
		sync_service_vsg(vs);
	}

	/* we may have got/lost quorum due to quorum setting changed */
	/* also update, in case we need the sorry server in alpha mode */
	update_quorum_state(vs, true);

	/* If we have a sorry server with inhibit, add it now */
	if (vs->s_svr && vs->s_svr->inhibit && !vs->s_svr->set) {
		if (vs->s_svr_duplicates_rs)
			vs->s_svr->set = true;
		else {
			/* Make sure the sorry server is configured with weight 0 */
			vs->s_svr->num_failed_checkers = 1;

			ipvs_cmd(LVS_CMD_ADD_DEST, vs, vs->s_svr);

			vs->s_svr->num_failed_checkers = 0;
		}
	}

	return true;
}

/* Set IPVS rules */
bool
init_services(void)
{
	virtual_server_t *vs;

	list_for_each_entry(vs, &check_data->vs, e_list) {
		if (!init_service_vs(vs))
			return false;
	}

	return true;
}

/* Store new weight in real_server struct and then update kernel. */
void
update_svr_wgt(int64_t weight, virtual_server_t * vs, real_server_t * rs
		, bool update_quorum)
{
	int old_weight, new_weight;


	new_weight = real_weight(weight);
	old_weight = real_weight(rs->effective_weight);

	rs->effective_weight = weight;

	if (new_weight != old_weight) {
		log_message(LOG_INFO, "Changing weight from %d to %d for %sactive service %s of VS %s"
				    , old_weight
				    , new_weight
				    , ISALIVE(rs) ? "" : "in"
				    , FMT_RS(rs, vs)
				    , FMT_VS(vs));
		/*
		 * Have weight change take effect now only if rs is in
		 * the pool and alive and its pool is in use. If not,
		 * it will take effect later when it becomes alive.
		 */
		if (rs->set && ISALIVE(rs) && rs_pool_active(vs, rs))
			ipvs_cmd(LVS_CMD_EDIT_DEST, vs, rs);
		if (update_quorum)
			update_quorum_state(vs, false);
	}
}

void
set_checker_state(checker_t *checker, bool up)
{
	if (checker->is_up == up)
		return;

	checker->is_up = up;

	if (!up)
		checker->rs->num_failed_checkers++;
	else if (checker->rs->num_failed_checkers)
		checker->rs->num_failed_checkers--;
}

/* Update checker's state */
void
update_svr_checker_state(bool alive, checker_t *checker)
{
	if (checker->is_up == alive) {
		if (!checker->has_run) {
			if (checker->alpha || !alive)
				do_rs_notifies(checker->vs, checker->rs, false);
			checker->has_run = true;
		}
		return;
	}

	checker->has_run = true;

	if (alive) {
		/* call the UP handler unless any more failed checks found */
		if (checker->rs->num_failed_checkers <= 1) {
			if (!perform_svr_state(true, checker))
				return;
		}
	}
	else {
		/* Handle not alive state */
		if (checker->rs->num_failed_checkers == 0) {
			if (!perform_svr_state(false, checker))
				return;
		}
	}

	set_checker_state(checker, alive);
}

/* Check if a vsg entry is in new data */
static virtual_server_group_entry_t * __attribute__ ((pure))
vsge_exist(virtual_server_group_entry_t *vsg_entry, list_head_t *l)
{
	virtual_server_group_entry_t *vsge;

	list_for_each_entry(vsge, l, e_list) {
		if (vsge_iseq(vsg_entry, vsge))
			return vsge;
	}

	return NULL;
}

/* Clear the diff vsge of old group */
static void
clear_diff_vsge(list_head_t *old, list_head_t *new, virtual_server_t *old_vs)
{
	virtual_server_group_entry_t *vsge, *new_vsge;

	list_for_each_entry(vsge, old, e_list) {
		new_vsge = vsge_exist(vsge, new);
		if (new_vsge) {
			new_vsge->reloaded = true;
			continue;
		}

		if (vsge->is_fwmark)
			log_message(LOG_INFO, "VS [%u] in group %s no longer exists",
					      vsge->vfwmark, old_vs->vsgname);
		else if (!inet_sockaddrcmp(&vsge->addr, &vsge->addr_end))
			log_message(LOG_INFO, "VS [%s] in group %s no longer exists"
					    , inet_sockaddrtotrio(&vsge->addr, old_vs->service_type)
					    , old_vs->vsgname);
		else
			log_message(LOG_INFO, "VS [%s-%s] in group %s no longer exists"
					    , inet_sockaddrtotrio(&vsge->addr, old_vs->service_type)
					    , inet_sockaddrtos(&vsge->addr_end)
					    , old_vs->vsgname);

		ipvs_group_remove_entry(old_vs, vsge);
	}
}

static void
update_alive_counts_vsge(list_head_t *old, list_head_t *new)
{
	virtual_server_group_entry_t *old_vsge, *new_vsge;

	list_for_each_entry(old_vsge, old, e_list) {
		new_vsge = vsge_exist(old_vsge, new);
		if (!new_vsge)
			continue;

		if (old_vsge->is_fwmark) {
			new_vsge->fwm4_alive = old_vsge->fwm4_alive;
			new_vsge->fwm6_alive = old_vsge->fwm6_alive;
		} else {
			new_vsge->tcp_alive = old_vsge->tcp_alive;
			new_vsge->udp_alive = old_vsge->udp_alive;
			new_vsge->sctp_alive = old_vsge->sctp_alive;
		}
	}

}
static void
update_alive_counts(virtual_server_t *old, virtual_server_t *new)
{
	if (!old->vsg || !new->vsg)
		return;

	update_alive_counts_vsge(&old->vsg->addr_range, &new->vsg->addr_range);
	update_alive_counts_vsge(&old->vsg->vfwmark, &new->vsg->vfwmark);
}

#ifdef _WITH_NFTABLES_
static void
handle_vsg(int family, virtual_server_t *vs)
{
	bool old_val;
	real_server_t *rs;

	if ((family == AF_INET && !vs->vsg->have_ipv4) ||
	    (family == AF_INET6 && !vs->vsg->have_ipv6))
		remove_fwmark_vs(vs, family);
	else {
		add_fwmark_vs(vs, family);

		/* Now add the RSs */
		if (family == AF_INET) {
			old_val = vs->vsg->have_ipv6;
			vs->vsg->have_ipv6 = false;
		} else {
			old_val = vs->vsg->have_ipv4;
			vs->vsg->have_ipv4 = false;
		}

		list_for_each_entry(rs, &vs->rs, e_list) {
			if ((!rs->num_failed_checkers || rs->inhibit) &&
			    rs_pool_active(vs, rs))
				ipvs_cmd(LVS_CMD_ADD_DEST, vs, rs);
		}

		if (family == AF_INET)
			vs->vsg->have_ipv6 = old_val;
		else
			vs->vsg->have_ipv4 = old_val;
	}
}
#endif

/* Clear the diff vsg of the old vs */
static void
clear_diff_vsg(virtual_server_t *old_vs, virtual_server_t *new_vs)
{
	virtual_server_group_t *old = old_vs->vsg;
	virtual_server_group_t *new = new_vs->vsg;
#ifdef _WITH_NFTABLES_
	bool vsg_already_done;
	proto_index_t proto_index;

	if (VS_USES_VSG_AUTO_FWMARK(old_vs)) {
		proto_index = protocol_to_index(new_vs->service_type);
		vsg_already_done = !!new_vs->vsg->auto_fwmark[proto_index];

		new_vs->vsg->auto_fwmark[proto_index] = old_vs->vsg->auto_fwmark[proto_index];

		if (new_vs->vsg->have_ipv4 != old_vs->vsg->have_ipv4)
			handle_vsg(AF_INET, new_vs);
		if (new_vs->vsg->have_ipv6 != old_vs->vsg->have_ipv6)
			handle_vsg(AF_INET6, new_vs);

		/* We have already updated this vsg */
		if (vsg_already_done)
			return;
	}
#endif

	/* Diff the group entries */
	clear_diff_vsge(&old->addr_range, &new->addr_range, old_vs);
	clear_diff_vsge(&old->vfwmark, &new->vfwmark, old_vs);
}

/* Check if a vs exist in new data and returns pointer to it */
static virtual_server_t* __attribute__ ((pure))
vs_exist(virtual_server_t * old_vs)
{
	virtual_server_t *vs;

	list_for_each_entry(vs, &check_data->vs, e_list) {
		if (vs_iseq(old_vs, vs))
			return vs;
	}

	return NULL;
}

/* Check if rs is in new vs data */
static real_server_t * __attribute__ ((pure))
rs_exist(real_server_t *old_rs, list_head_t *l)
{
	real_server_t *rs;

	list_for_each_entry(rs, l, e_list) {
		if (rs_iseq(rs, old_rs))
			return rs;
	}

	return NULL;
}

static void
migrate_checkers(virtual_server_t *vs, real_server_t *old_rs, real_server_t *new_rs)
{
	checker_t *old_c, *new_c;
	checker_t dummy_checker;
	bool a_checker_has_run = false;

	if (!list_empty(&old_rs->checkers_list)) {
		list_for_each_entry(new_c, &new_rs->checkers_list, rs_list) {
			if (!new_c->checker_funcs->compare)
				continue;
			list_for_each_entry(old_c, &old_rs->checkers_list, rs_list) {
				if (old_c->checker_funcs->type == new_c->checker_funcs->type && new_c->checker_funcs->compare(old_c, new_c)) {
					/* Update status if different */
					if (old_c->has_run && old_c->is_up != new_c->is_up)
						set_checker_state(new_c, old_c->is_up);

					/* Transfer some other state flags */
					new_c->has_run = old_c->has_run;

					/* If we have already had sufficient retries for the new retry value,
					 * we hadn't already failed, so just require one more failure to trigger
					 * failed state.
					 * If we no longer have any retries, one more failure should trigger
					 * failed state.
					 */
					if (!new_c->is_up)
						new_c->retry_it = new_c->retry + 1;
					else if (old_c->retry_it >= new_c->retry)
						new_c->retry_it = new_c->retry;
					else
						new_c->retry_it = old_c->retry_it;

					if (new_c->checker_funcs->migrate)
						new_c->checker_funcs->migrate(new_c, old_c);

					break;
				}
			}
		}
	}

	/* Find out how many checkers are really failed */
	new_rs->num_failed_checkers = 0;
	list_for_each_entry(new_c, &new_rs->checkers_list, rs_list) {
		if (new_c->has_run && !new_c->is_up)
			new_rs->num_failed_checkers++;
		if (new_c->has_run)
			a_checker_has_run = true;
	}

	/* If a checker has failed, set new alpha checkers to be down until
	 * they have run. */
	if (new_rs->num_failed_checkers || (!new_rs->alive && !a_checker_has_run)) {
		list_for_each_entry(new_c, &new_rs->checkers_list, rs_list) {
			if (!new_c->has_run) {
				if (new_c->alpha)
					set_checker_state(new_c, false);
				/* One failure is enough */
				new_c->retry_it = new_c->retry;
			}
		}
	}

	/* If there are no failed checkers, the RS needs to be up */
	if (!new_rs->num_failed_checkers && !new_rs->alive) {
		dummy_checker.vs = vs;
		dummy_checker.rs = new_rs;
		perform_svr_state(true, &dummy_checker);
	} else if (new_rs->num_failed_checkers && new_rs->set != new_rs->inhibit) {
		/* ipvs_cmd() checks for alive rather than set */
		new_rs->alive = new_rs->set;
		ipvs_cmd(new_rs->inhibit ? IP_VS_SO_SET_ADDDEST : IP_VS_SO_SET_DELDEST, vs, new_rs);
		new_rs->alive = false;
	}
}

/* Clear the diff rs of the old vs */
static void
clear_diff_rs(virtual_server_t *old_vs, virtual_server_t *new_vs)
{
	real_server_t *rs, *new_rs;

	/* If old vs didn't own rs then nothing return */
	if (list_empty(&old_vs->rs))
		return;

	/* remove RS from old vs which are not found in new vs */
	list_for_each_entry(rs, &old_vs->rs, e_list) {
		new_rs = rs_exist(rs, &new_vs->rs);
		if (!new_rs) {
			log_message(LOG_INFO, "service %s no longer exist"
					    , FMT_RS(rs, old_vs));

			clear_service_rs(old_vs, rs, false);
			continue;
		}

		/*
		 * We reflect the previous alive
		 * flag value to not try to set
		 * already set IPVS rule.
		 */
		new_rs->alive = rs->alive;
		new_rs->set = rs->set;
		new_rs->effective_weight = rs->effective_weight;
		new_rs->peffective_weight = rs->effective_weight;
		new_rs->reloaded = true;

		/* If the real server has moved to a different pool, and
		 * whether its pool is in use has changed, add it to or
		 * remove it from use. */
		if (rs->alive &&
		    pool_priority(rs->pool) != pool_priority(new_rs->pool) &&
		    rs_pool_active(old_vs, rs) != rs_pool_active(new_vs, new_rs)) {
			if (rs_pool_active(new_vs, new_rs)) {
				new_rs->alive = false;
				ipvs_cmd(LVS_CMD_ADD_DEST, new_vs, new_rs);
				new_rs->alive = true;
			} else
				ipvs_cmd(LVS_CMD_DEL_DEST, new_vs, new_rs);
		}

		/*
		 * We must migrate the state of the old checkers.
		 * If we do not, the new RS is in a state where it’s reported
		 * as down with no check failed. As a result, the server will never
		 * be put back up when it’s alive again in check_tcp.c#83 because
		 * of the check that put a rs up only if it was not previously up.
		 * For alpha mode checkers, if it was up, we don't need another
		 * success to say it is now up.
		 */
		migrate_checkers(new_vs, rs, new_rs);

		/* Do we need to update the RS configuration? */
		if ((new_rs->alive && new_rs->effective_weight != rs->effective_weight) ||
#ifdef _HAVE_IPVS_TUN_TYPE_
		    rs->tun_type != new_rs->tun_type ||
		    rs->tun_port != new_rs->tun_port ||
#ifdef _HAVE_IPVS_TUN_CSUM_
		    rs->tun_flags != new_rs->tun_flags ||
#endif
#endif
		    rs->forwarding_method != new_rs->forwarding_method)
			ipvs_cmd(LVS_CMD_EDIT_DEST, new_vs, new_rs);
	}

	update_vs_notifies(old_vs, false);
}

/* clear sorry server, but only if changed */
static void
clear_diff_s_srv(virtual_server_t *old_vs, virtual_server_t *new_vs)
{
	real_server_t *old_ss = old_vs->s_svr;
	real_server_t *new_ss = new_vs->s_svr;
	bool reinstate_alive_rs;

	if (!old_ss)
		return;

	if (new_ss && rs_iseq(old_ss, new_ss)) {
		/* which fields are really used on s_svr? */
		new_ss->alive = old_ss->alive;
		new_ss->set = old_ss->set;
		new_ss->effective_weight = new_ss->iweight;
		new_ss->reloaded = true;

		if (old_ss->inhibit == new_ss->inhibit ||
		    old_ss->alive)
			return;
	}

	/* With no sorry server configured, any alive real servers
	 * need to be reinstated. */
	reinstate_alive_rs = old_ss->alive && !new_ss;

	if (old_ss->inhibit && !ISALIVE(old_ss)) {
		/* Force removing the old SS */
		SET_ALIVE(old_ss);
		old_ss->inhibit = false;
	}

	if (ISALIVE(old_ss)) {
		log_message(LOG_INFO, "Removing sorry server %s from VS %s"
				    , FMT_RS(old_ss, old_vs)
				    , FMT_VS(old_vs));
		ipvs_cmd(LVS_CMD_DEL_DEST, old_vs, old_ss);
		if (new_ss)
			new_ss->set = false;

		if (reinstate_alive_rs)
			perform_pool_state(new_vs, new_vs->active_pool, true);
	}
}

/* Copy the failover pool states of the old vs, and identify the pool
 * that is in use. Returns true if the pool that was in use no longer
 * exists, in which case the primary pool is used, and its alive real
 * servers need to be added once they have been migrated. */
static bool
migrate_failover_pools(virtual_server_t *old_vs, virtual_server_t *new_vs)
{
	failover_pool_t *old_pool, *new_pool;

	list_for_each_entry(new_pool, &new_vs->failover_pools, e_list) {
		old_pool = find_failover_pool(old_vs, new_pool->priority);
		if (old_pool)
			new_pool->quorum_state_up = old_pool->quorum_state_up;
	}

	if (!old_vs->active_pool)
		return false;

	new_vs->active_pool = find_failover_pool(new_vs, old_vs->active_pool->priority);
	if (new_vs->active_pool)
		return false;

	log_message(LOG_INFO, "Failover pool %u of VS %s no longer exists"
			    , old_vs->active_pool->priority
			    , FMT_VS(old_vs));
	log_pool_switch(new_vs, NULL);

	return true;
}

/* When reloading configuration, remove negative diff entries
 * and copy status of existing entries to the new ones */
void
clear_diff_services(void)
{
	virtual_server_t *vs, *new_vs;
	bool reinstate_primary_rs;

	migrating_diff = true;

	/* Remove diff entries from previous IPVS rules */
	list_for_each_entry(vs, &old_check_data->vs, e_list) {
		/*
		 * Try to find this vs in the new conf data
		 * reloaded.
		 */
		new_vs = vs_exist(vs);
		if (!new_vs) {
			if (vs->vsgname)
				log_message(LOG_INFO, "Removing Virtual Server Group [%s]", vs->vsgname);
			else
				log_message(LOG_INFO, "Removing Virtual Server %s", FMT_VS(vs));

			/* Clear VS entry */
			clear_service_vs(vs, false);

			continue;
		}

		/* copy status fields from old VS */
		new_vs->alive = vs->alive;
		new_vs->quorum_state_up = vs->quorum_state_up;
		reinstate_primary_rs = migrate_failover_pools(vs, new_vs);
		new_vs->reloaded = true;
		if (using_ha_suspend)
			new_vs->ha_suspend_addr_count = vs->ha_suspend_addr_count;

		if (vs->vsgname)
			clear_diff_vsg(vs, new_vs);

		/* If vs exist, perform rs pool diff */
		/* omega = false must not prevent the notifiers from being called,
		   because the VS still exists in new configuration */
		if (strcmp(vs->sched, new_vs->sched) ||
		    vs->flags != new_vs->flags ||
		    strcmp(vs->pe_name, new_vs->pe_name) ||
		    vs->persistence_granularity != new_vs->persistence_granularity ||
		    vs->persistence_timeout != new_vs->persistence_timeout)
			ipvs_cmd(IP_VS_SO_SET_EDIT, new_vs, NULL);

		vs->omega = true;
		clear_diff_rs(vs, new_vs);
		if (reinstate_primary_rs)
			perform_pool_state(new_vs, NULL, true);
		clear_diff_s_srv(vs, new_vs);

		update_alive_counts(vs, new_vs);
	}

	migrating_diff = false;
}

/* This is only called during a reload. Any new real server with
 * alpha mode checkers should start in down state */
void
check_new_rs_state(void)
{
	virtual_server_t *vs;
	real_server_t *rs;
	checker_t *checker;

	list_for_each_entry(vs, &check_data->vs, e_list) {
		list_for_each_entry(rs, &vs->rs, e_list) {
			list_for_each_entry(checker, &rs->checkers_list, rs_list) {
				if (checker->rs->reloaded)
					continue;
				if (!checker->alpha)
					continue;
				set_checker_state(checker, false);
				UNSET_ALIVE(checker->rs);
			}
		}
	}
}

void
link_vsg_to_vs(void)
{
	virtual_server_t *vs, *vs_tmp;
	virtual_server_group_t *vsg;
	unsigned vsg_member_no;
	int vsg_af;

	if (list_empty(&check_data->vs))
		return;

	list_for_each_entry_safe(vs, vs_tmp, &check_data->vs, e_list) {
		if (!vs->vsgname)
			continue;

		vs->vsg = ipvs_get_group_by_name(vs->vsgname, &check_data->vs_group);
		if (!vs->vsg) {
			log_message(LOG_INFO, "Virtual server group %s specified but not configured"
					      " - ignoring virtual server %s"
					    , vs->vsgname, FMT_VS(vs));
			free_vs(vs);
			continue;
		}

		/* Check the vs and vsg address families match */
		if (vs->vsg->have_ipv4 == vs->vsg->have_ipv6)
			vsg_af = AF_UNSPEC;
		else if (vs->vsg->have_ipv4)
			vsg_af = AF_INET;
		else
			vsg_af = AF_INET6;

		/* We can have mixed IPv4 and IPv6 in a vsg only if all fwmarks have a family,
		 * and also all the real/sorry servers of the virtual server are tunnelled. */
		if (vs->vsg->have_ipv4 && vs->vsg->have_ipv6 && vs->af != AF_UNSPEC) {
			log_message(LOG_INFO, "%s: virtual server group with IPv4 & IPv6 doesn't"
					      " match virtual server %s - ignoring"
					    , vs->vsgname, FMT_VS(vs));
			free_vs(vs);
		} else if ((vs->vsg->have_ipv4 && vs->af == AF_INET6) ||
			   (vs->vsg->have_ipv6 && vs->af == AF_INET)) {
			log_message(LOG_INFO, "%s: address family doesn't match"
					      " virtual server %s - ignoring"
					    , vs->vsgname, FMT_VS(vs));
			free_vs(vs);
		} else if (vsg_af != AF_UNSPEC) {
			if (vs->af == AF_UNSPEC)
				vs->af = vsg_af;
			else if (vsg_af != vs->af) {
				log_message(LOG_INFO, "%s: address family doesn't"
						      " match virtual server %s - ignoring"
						    , vs->vsgname, FMT_VS(vs));
				free_vs(vs);
			}
		} else if (vs->af == AF_UNSPEC && vs->vsg && vs->vsg->fwmark_no_family) {
			log_message(LOG_INFO, "%s: Virtual server %s address family cannot be determined,"
					      " defaulting to IPv4"
					    , vs->vsgname, FMT_VS(vs));
		}
	}

	/* The virtual server port number is used to identify the sequence number of the virtual server in the group */
	list_for_each_entry(vsg, &check_data->vs_group, e_list) {
		vsg_member_no = 0;

		list_for_each_entry(vs, &check_data->vs, e_list) {
			if (!vs->vsgname)
				continue;

			if (!strcmp(vs->vsgname, vsg->gname)) {
				/* We use the IPv4 port since there is no address family */
				PTR_CAST(struct sockaddr_in, &vs->addr)->sin_port = htons(vsg_member_no);
				vsg_member_no++;
			}
		}
	}
}
