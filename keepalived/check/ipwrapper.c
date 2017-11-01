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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <unistd.h>

#include "ipwrapper.h"
#include "check_api.h"
#include "logger.h"
#include "utils.h"
#include "main.h"
#ifdef _WITH_SNMP_CHECKER_
  #include "check_snmp.h"
#endif
#include "global_data.h"

/* Returns the sum of all alive RS weight in a virtual server. */
static long
weigh_live_realservers(virtual_server_t * vs)
{
	element e;
	real_server_t *svr;
	long count = 0;

	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		svr = ELEMENT_DATA(e);
		if (ISALIVE(svr))
			count += svr->weight;
	}
	return count;
}

static void
notify_fifo_vs(virtual_server_t* vs, bool is_up)
{
	char *state = is_up ? "UP" : "DOWN";
	size_t size;
	char *line;
	char *vs_str;

	if (global_data->notify_fifo.fd == -1 &&
	    global_data->lvs_notify_fifo.fd == -1)
		return;

	vs_str = FMT_VS(vs);
	size = strlen(vs_str) + strlen(state) + 6;
	line = MALLOC(size);
	if (!line)
		return;

	snprintf(line, size, "VS %s %s\n", vs_str, state);

	if (global_data->notify_fifo.fd != -1) {
		if (write(global_data->notify_fifo.fd, line, size - 1) == -1) {}
	}
	if (global_data->lvs_notify_fifo.fd != -1) {
		if (write(global_data->lvs_notify_fifo.fd, line, size - 1) == -1) {}
	}

	FREE(line);
}

static void
notify_fifo_rs(virtual_server_t* vs, real_server_t* rs, bool is_up)
{
	char *state = is_up ? "UP" : "DOWN";
	size_t size;
	char *line;
	char *str;
	char *rs_str;
	char *vs_str;

	if (global_data->notify_fifo.fd == -1 &&
	    global_data->lvs_notify_fifo.fd == -1)
		return;

	str = FMT_RS(rs, vs);
	rs_str = MALLOC(strlen(str)+1);
	strcpy(rs_str, str);
	vs_str = FMT_VS(vs);
	size = strlen(rs_str) + strlen(vs_str) + strlen(state) + 7;
	line = MALLOC(size);
	if (!line)
		return;

	snprintf(line, size, "RS %s %s %s\n", rs_str, vs_str, state);
	FREE(rs_str);

	if (global_data->notify_fifo.fd != -1) {
		if (write(global_data->notify_fifo.fd, line, size - 1) == - 1) {}
	}
	if (global_data->lvs_notify_fifo.fd != -1) {
		if (write(global_data->lvs_notify_fifo.fd, line, size - 1) == -1) {}
	}

	FREE(line);
}

/* Remove a realserver IPVS rule */
static void
clear_service_rs(virtual_server_t * vs, list l)
{
	element e;
	real_server_t *rs;
	long weight_sum;
	long down_threshold = vs->quorum - vs->hysteresis;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
// ??? What about alpha mode. Use ->set
		if (!ISALIVE(rs))
			continue;

		log_message(LOG_INFO, "Removing service %s from VS %s"
					, FMT_RS(rs, vs)
					, FMT_VS(vs));
		ipvs_cmd(LVS_CMD_DEL_DEST, vs, rs);
		UNSET_ALIVE(rs);
		if (!vs->omega)
			continue;

		/* In Omega mode we call VS and RS down notifiers
		 * all the way down the exit, as necessary.
		 */
		if (rs->notify_down)
			notify_exec(rs->notify_down);
		notify_fifo_rs(vs, rs, false);
#ifdef _WITH_SNMP_CHECKER_
		check_snmp_rs_trap(rs, vs);
#endif

		/* Sooner or later VS will lose the quorum (if any). However,
		 * we don't push in a sorry server then, hence the regression
		 * is intended.
		 */
		weight_sum = weigh_live_realservers(vs);
		if (vs->quorum_state_up &&
		    (!weight_sum || weight_sum < down_threshold)) {
			vs->quorum_state_up = false;
			if (vs->notify_quorum_down)
				notify_exec(vs->notify_quorum_down);
			notify_fifo_vs(vs, false);
#ifdef _WITH_SNMP_CHECKER_
			check_snmp_quorum_trap(vs);
#endif
		}
	}
}

/* Remove a virtualserver IPVS rule */
static void
clear_service_vs(virtual_server_t * vs)
{
	/* Processing real server queue */
	if (vs->s_svr) {
		if (ISALIVE(vs->s_svr)) {
			ipvs_cmd(LVS_CMD_DEL_DEST, vs, vs->s_svr);
			UNSET_ALIVE(vs->s_svr);
		}
// ??? what about alpha mode ?
	} else
		clear_service_rs(vs, vs->rs);
	/* The above will handle Omega case for VS as well. */

	ipvs_cmd(LVS_CMD_DEL, vs, NULL);

	UNSET_ALIVE(vs);
}

/* IPVS cleaner processing */
void
clear_services(void)
{
	element e;
	virtual_server_t *vs;

	if (!check_data || !check_data->vs)
		return;

	for (e = LIST_HEAD(check_data->vs); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);

		/* If it is a virtual server group, only clear the vs if it is the last vs using the group
		 * of the same protocol or address family. */
		clear_service_vs(vs);
	}
}

/* Set a realserver IPVS rules */
static bool
init_service_rs(virtual_server_t * vs)
{
	element e;
	real_server_t *rs;

	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);

		if (rs->reloaded) {
			if (rs->iweight != rs->pweight)
				update_svr_wgt(rs->iweight, vs, rs, false);
			/* Do not re-add failed RS instantly on reload */
			continue;
		}

		/* In alpha mode, be pessimistic (or realistic?) and don't
		 * add real servers into the VS pool unless inhibit_on_failure.
		 * They will get there later upon healthchecks recovery (if ever).
		 */
		if ((!rs->num_failed_checkers && !ISALIVE(rs)) ||
		    (rs->inhibit && !rs->set)) {
			ipvs_cmd(LVS_CMD_ADD_DEST, vs, rs);
			if (!rs->num_failed_checkers)
				SET_ALIVE(rs);
		}
	}

	return true;
}

static void
sync_service_vsg(virtual_server_t * vs)
{
	virtual_server_group_t *vsg;
	virtual_server_group_entry_t *vsge;
	list *l;
	element e;

	vsg = vs->vsg;
	list ll[] = {
		vsg->addr_range,
		vsg->vfwmark,
		NULL,
	};

	for (l = ll; *l; l++)
		for (e = LIST_HEAD(*l); e; ELEMENT_NEXT(e)) {
			vsge = ELEMENT_DATA(e);
			if (vs->reloaded && !vsge->reloaded) {
				log_message(LOG_INFO, "VS [%s:%d:%u] added into group %s"
// Does this work with no address?
						    , inet_sockaddrtotrio(&vsge->addr, vs->service_type)
						    , vsge->range
						    , vsge->vfwmark
						    , vs->vsgname);
				/* add all reloaded and alive/inhibit-set dests
				 * to the newly created vsg item */
				ipvs_group_sync_entry(vs, vsge);
			}
		}
}

/* add or remove _alive_ real servers from a virtual server */
static void
perform_quorum_state(virtual_server_t *vs, bool add)
{
	element e;
	real_server_t *rs;

	log_message(LOG_INFO, "%s the pool for VS %s"
			    , add?"Adding alive servers to":"Removing alive servers from"
			    , FMT_VS(vs));
	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (!ISALIVE(rs)) /* We only handle alive servers */
			continue;
// ??? The following seems unnecessary
		if (add)
			rs->alive = false;
		ipvs_cmd(add?LVS_CMD_ADD_DEST:LVS_CMD_DEL_DEST, vs, rs);
		rs->alive = true;
	}
}

void
set_quorum_states(void)
{
	virtual_server_t *vs;
	element e;

	if (LIST_ISEMPTY(check_data->vs))
		return;

	for (e = LIST_HEAD(check_data->vs); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);

		vs->quorum_state_up = (weigh_live_realservers(vs) >= vs->quorum + vs->hysteresis);
	}
}

/* set quorum state depending on current weight of real servers */
static void
update_quorum_state(virtual_server_t * vs)
{
	long weight_sum = weigh_live_realservers(vs);
	long up_threshold = vs->quorum + vs->hysteresis;
	long down_threshold = vs->quorum - vs->hysteresis;

	/* If we have just gained quorum, it's time to consider notify_up. */
	if (!vs->quorum_state_up &&
	    weight_sum >= up_threshold) {
		vs->quorum_state_up = true;
		log_message(LOG_INFO, "Gained quorum %u+%u=%ld <= %ld for VS %s"
				    , vs->quorum
				    , vs->hysteresis
				    , up_threshold
				    , weight_sum
				    , FMT_VS(vs));
		if (vs->s_svr && ISALIVE(vs->s_svr)) {
			/* Adding back alive real servers */
			perform_quorum_state(vs, true);

			log_message(LOG_INFO, "%s sorry server %s from VS %s"
					    , (vs->s_svr->inhibit ? "Disabling" : "Removing")
					    , FMT_RS(vs->s_svr, vs)
					    , FMT_VS(vs));

			ipvs_cmd(LVS_CMD_DEL_DEST, vs, vs->s_svr);
			vs->s_svr->alive = false;
		}
		if (vs->notify_quorum_up)
			notify_exec(vs->notify_quorum_up);
		notify_fifo_vs(vs, true);
#ifdef _WITH_SNMP_CHECKER_
		check_snmp_quorum_trap(vs);
#endif
		return;
	}
	else if (vs->quorum_state_up &&
		 (!weight_sum || weight_sum < down_threshold)) {
		/* We have just lost quorum for the VS, we need to consider
		 * VS notify_down and sorry_server cases
		 */
		vs->quorum_state_up = false;
		log_message(LOG_INFO, "Lost quorum %u-%u=%ld > %ld for VS %s"
				    , vs->quorum
				    , vs->hysteresis
				    , down_threshold
				    , weight_sum
				    , FMT_VS(vs));

		if (vs->s_svr && !ISALIVE(vs->s_svr)) {
			log_message(LOG_INFO, "%s sorry server %s to VS %s"
					    , (vs->s_svr->inhibit ? "Enabling" : "Adding")
					    , FMT_RS(vs->s_svr, vs)
					    , FMT_VS(vs));

			/* the sorry server is now up in the pool, we flag it alive */
			ipvs_cmd(LVS_CMD_ADD_DEST, vs, vs->s_svr);
			vs->s_svr->alive = true;

			/* Remove remaining alive real servers */
			perform_quorum_state(vs, false);
		}

		if (vs->notify_quorum_down)
			notify_exec(vs->notify_quorum_down);
		notify_fifo_vs(vs, false);
#ifdef _WITH_SNMP_CHECKER_
		check_snmp_quorum_trap(vs);
#endif
	}
}

/* manipulate add/remove rs according to alive state */
static bool
perform_svr_state(bool alive, virtual_server_t * vs, real_server_t * rs)
{
	notify_script_t *notify_script;
	/*
	 * | ISALIVE(rs) | alive | context
	 * | false       | false | first check failed under alpha mode, unreachable here
	 * | false       | true  | RS went up, add it to the pool
	 * | true        | false | RS went down, remove it from the pool
	 * | true        | true  | first check succeeded w/o alpha mode, unreachable here
	 */

	if (ISALIVE(rs) == alive)
		return true;

	log_message(LOG_INFO, "%sing service %s to VS %s"
			    , alive ? (rs->inhibit) ? "Enabl" : "Add" :
				      (rs->inhibit) ? "Disabl" : "Remov"
			    , FMT_RS(rs, vs)
			    , FMT_VS(vs));

	/* Change only if we have quorum or no sorry server */
	if (vs->quorum_state_up || !vs->s_svr || !ISALIVE(vs->s_svr)) {
		if (ipvs_cmd(alive ? LVS_CMD_ADD_DEST : LVS_CMD_DEL_DEST, vs, rs))
			return false;
	}
	rs->alive = alive;
	notify_script = alive ? rs->notify_up : rs->notify_down;
	if (notify_script)
		notify_exec(notify_script);
	notify_fifo_rs(vs, rs, alive);
#ifdef _WITH_SNMP_CHECKER_
	check_snmp_rs_trap(rs, vs);
#endif

	/* We may have changed quorum state. If the quorum wasn't up
	 * but is now up, this is where the rs is added. */
	update_quorum_state(vs);

	return true;
}

/* Set a virtualserver IPVS rules */
static bool
init_service_vs(virtual_server_t * vs)
{
	/* Init the VS root */
	if (!ISALIVE(vs) || vs->vsgname) {
		ipvs_cmd(LVS_CMD_ADD, vs, NULL);
		SET_ALIVE(vs);
	}

	/* Processing real server queue */
	if (!init_service_rs(vs))
		return false;

	if (vs->reloaded && vs->vsgname) {
		/* add reloaded dests into new vsg entries */
		sync_service_vsg(vs);
	}

	/* we may have got/lost quorum due to quorum setting changed */
	/* also update, in case we need the sorry server in alpha mode */
	update_quorum_state(vs);

	return true;
}

/* Set IPVS rules */
bool
init_services(void)
{
	element e;
	list l = check_data->vs;
	virtual_server_t *vs;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);
		if (!init_service_vs(vs))
			return false;
	}
	return true;
}

/* Store new weight in real_server struct and then update kernel. */
void
update_svr_wgt(int weight, virtual_server_t * vs, real_server_t * rs
		, bool update_quorum)
{
	if (weight != rs->weight) {
		log_message(LOG_INFO, "Changing weight from %d to %d for %s service %s of VS %s"
				    , rs->weight
				    , weight
				    , ISALIVE(rs) ? "active" : "inactive"
				    , FMT_RS(rs, vs)
				    , FMT_VS(vs));
		rs->weight = weight;
		/*
		 * Have weight change take effect now only if rs is in
		 * the pool and alive and the quorum is met (or if
		 * there is no sorry server). If not, it will take
		 * effect later when it becomes alive.
		 */
		if (rs->set && ISALIVE(rs) &&
		    (vs->quorum_state_up || !vs->s_svr || !ISALIVE(vs->s_svr)))
			ipvs_cmd(LVS_CMD_EDIT_DEST, vs, rs);
		if (update_quorum)
			update_quorum_state(vs);
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
	if (checker->is_up == alive)
		return;

	if (alive) {
		/* call the UP handler unless any more failed checks found */
		if (checker->rs->num_failed_checkers <= 1) {
			if (!perform_svr_state(true, checker->vs, checker->rs))
				return;
		}
	}
	else {
		/* Handle not alive state */
		if (checker->rs->num_failed_checkers == 0) {
			if (!perform_svr_state(false, checker->vs, checker->rs))
				return;
		}
	}

	set_checker_state(checker, alive);
}

/* Check if a vsg entry is in new data */
static virtual_server_group_entry_t *
vsge_exist(virtual_server_group_entry_t *vsg_entry, list l)
{
	element e;
	virtual_server_group_entry_t *vsge;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsge = ELEMENT_DATA(e);
		if (VSGE_ISEQ(vsg_entry, vsge))
			return vsge;
	}

	return NULL;
}

/* Clear the diff vsge of old group */
static void
clear_diff_vsge(list old, list new, virtual_server_t * old_vs)
{
	virtual_server_group_entry_t *vsge, *new_vsge;
	element e;

	for (e = LIST_HEAD(old); e; ELEMENT_NEXT(e)) {
		vsge = ELEMENT_DATA(e);
		new_vsge = vsge_exist(vsge, new);
		if (new_vsge) {
			new_vsge->tcp_alive = vsge->tcp_alive;
			new_vsge->udp_alive = vsge->udp_alive;
			new_vsge->sctp_alive = vsge->sctp_alive;
			new_vsge->fwm4_alive = vsge->fwm4_alive;
			new_vsge->fwm6_alive = vsge->fwm6_alive;
			new_vsge->reloaded = true;
		}
		else {
			log_message(LOG_INFO, "VS [%s:%d:%u] in group %s no longer exists"
					    , inet_sockaddrtotrio(&vsge->addr, old_vs->service_type)
					    , vsge->range
					    , vsge->vfwmark
					    , old_vs->vsgname);

			ipvs_group_remove_entry(old_vs, vsge);
		}
	}
}

/* Clear the diff vsg of the old vs */
static void
clear_diff_vsg(virtual_server_t * old_vs, virtual_server_t * new_vs)
{
	virtual_server_group_t *old = old_vs->vsg;
	virtual_server_group_t *new = new_vs->vsg;

	/* Diff the group entries */
	clear_diff_vsge(old->addr_range, new->addr_range, old_vs);
	clear_diff_vsge(old->vfwmark, new->vfwmark, old_vs);
}

/* Check if a vs exist in new data and returns pointer to it */
static virtual_server_t*
vs_exist(virtual_server_t * old_vs)
{
	element e;
	list l = check_data->vs;
	virtual_server_t *vs;

	if (LIST_ISEMPTY(l))
		return NULL;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);
		if (VS_ISEQ(old_vs, vs))
			return vs;
	}

	return NULL;
}

/* Check if rs is in new vs data */
static real_server_t *
rs_exist(real_server_t * old_rs, list l)
{
	element e;
	real_server_t *rs;

	if (LIST_ISEMPTY(l))
		return NULL;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (RS_ISEQ(rs, old_rs))
			return rs;
	}

	return NULL;
}

static void
migrate_checkers(real_server_t *old_rs, real_server_t *new_rs, list old_checkers_queue)
{
	list l;
	element e, e1;
	checker_t *old_c, *new_c;

	l = alloc_list(NULL, NULL);
	for (e = LIST_HEAD(old_checkers_queue); e; ELEMENT_NEXT(e)) {
		old_c = ELEMENT_DATA(e);
		if (old_c->rs == old_rs) {
			list_add(l, old_c);
		}
	}

	if (!LIST_ISEMPTY(l)) {
		for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
			new_c = ELEMENT_DATA(e);
			if (new_c->rs != new_rs || !new_c->compare)
				continue;
			for (e1 = LIST_HEAD(l); e1; ELEMENT_NEXT(e1)) {
				old_c = ELEMENT_DATA(e1);
				if (old_c->compare == new_c->compare && new_c->compare(old_c, new_c)) {
					/* Update status if different */
					if (old_c->is_up != new_c->is_up)
						set_checker_state(new_c, old_c->is_up);
					break;
				}
			}
		}

		if (!new_rs->num_failed_checkers)
			SET_ALIVE(new_rs);
	}

	free_list(&l);
}

/* Clear the diff rs of the old vs */
static void
clear_diff_rs(virtual_server_t *old_vs, virtual_server_t *new_vs, list old_checkers_queue)
{
	element e;
	list l = old_vs->rs;
	real_server_t *rs, *new_rs;

	/* If old vs didn't own rs then nothing return */
	if (LIST_ISEMPTY(l))
		return;

	/* remove RS from old vs which are not found in new vs */
	list rs_to_remove = alloc_list (NULL, NULL);
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		new_rs = rs_exist(rs, new_vs->rs);
		if (!new_rs) {
			log_message(LOG_INFO, "service %s no longer exist"
					    , FMT_RS(rs, old_vs));

			/* Reset inhibit flag to delete inhibit entries */
			if (rs->inhibit) {
				if (!ISALIVE(rs) && rs->set)
					SET_ALIVE(rs);
				rs->inhibit = false;
			}
			list_add (rs_to_remove, rs);
		} else {
			/*
			 * We reflect the previous alive
			 * flag value to not try to set
			 * already set IPVS rule.
			 */
			if (new_rs->alive)
				new_rs->alive = rs->alive;
			new_rs->set = rs->set;
			new_rs->weight = rs->weight;
			new_rs->pweight = rs->iweight;
			new_rs->reloaded = true;

			/*
			 * We must migrate the state of the old checkers.
			 * If we do not, the new RS is in a state where it’s reported
			 * as down with no check failed. As a result, the server will never
			 * be put back up when it’s alive again in check_tcp.c#83 because
			 * of the check that put a rs up only if it was not previously up.
			 * For alpha mode checkers, if it was up, we don't need another
			 * success to say it is now up.
			 */
			migrate_checkers(rs, new_rs, old_checkers_queue);
		}
	}
	clear_service_rs(old_vs, rs_to_remove);
	free_list(&rs_to_remove);
}

/* clear sorry server, but only if changed */
static void
clear_diff_s_srv(virtual_server_t *old_vs, real_server_t *new_rs)
{
	real_server_t *old_rs = old_vs->s_svr;

	if (!old_rs)
		return;

	if (new_rs && RS_ISEQ(old_rs, new_rs)) {
		/* which fields are really used on s_svr? */
		new_rs->alive = old_rs->alive;
		new_rs->set = old_rs->set;
		new_rs->weight = old_rs->weight;
		new_rs->pweight = old_rs->iweight;
		new_rs->reloaded = true;
	}
	else {
		if (old_rs->inhibit) {
			if (!ISALIVE(old_rs) && old_rs->set)
				SET_ALIVE(old_rs);
			old_rs->inhibit = 0;
		}
		if (ISALIVE(old_rs)) {
			log_message(LOG_INFO, "Removing sorry server %s from VS %s"
					    , FMT_RS(old_rs, old_vs)
					    , FMT_VS(old_vs));
			ipvs_cmd(LVS_CMD_DEL_DEST, old_vs, old_rs);
		}
	}

}

/* When reloading configuration, remove negative diff entries
 * and copy status of existing entries to the new ones */
void
clear_diff_services(list old_checkers_queue)
{
	element e;
	list l = old_check_data->vs;
	virtual_server_t *vs, *new_vs;

	/* If old config didn't own vs then nothing return */
	if (LIST_ISEMPTY(l))
		return;

	/* Remove diff entries from previous IPVS rules */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);

		/*
		 * Try to find this vs into the new conf data
		 * reloaded.
		 */
		new_vs = vs_exist(vs);
		if (!new_vs) {
			if (vs->vsgname)
				log_message(LOG_INFO, "Removing Virtual Server Group [%s]", vs->vsgname);
			else
				log_message(LOG_INFO, "Removing Virtual Server %s", FMT_VS(vs));

			/* Clear VS entry */
			clear_service_vs(vs);
		} else {
			/* copy status fields from old VS */
			SET_ALIVE(new_vs);
			new_vs->quorum_state_up = vs->quorum_state_up;
			new_vs->reloaded = true;

			if (vs->vsgname)
				clear_diff_vsg(vs, new_vs);

			/* If vs exist, perform rs pool diff */
			/* omega = false must not prevent the notifiers from being called,
			   because the VS still exists in new configuration */
			vs->omega = true;
			clear_diff_rs(vs, new_vs, old_checkers_queue);
			clear_diff_s_srv(vs, new_vs->s_svr);
		}
	}
}

void
link_vsg_to_vs(void)
{
	element e, e1, next;
	virtual_server_t *vs;
	int vsg_af;
	virtual_server_group_t *vsg;
	virtual_server_group_entry_t *vsge;
	unsigned vsg_member_no;

	if (LIST_ISEMPTY(check_data->vs))
		return;

	for (e = LIST_HEAD(check_data->vs); e; e = next) {
		next = e->next;
		vs = ELEMENT_DATA(e);

		if (vs->vsgname) {
			vs->vsg = ipvs_get_group_by_name(vs->vsgname, check_data->vs_group);
			if (!vs->vsg) {
				log_message(LOG_INFO, "Virtual server group %s specified but not configured - ignoring virtual server %s", vs->vsgname, FMT_VS(vs));
				free_vs_checkers(vs);
				free_list_element(check_data->vs, e);
				continue;
			}

			/* Check the vsg has some configuration */
			if (LIST_ISEMPTY(vs->vsg->addr_range) &&
			    LIST_ISEMPTY(vs->vsg->vfwmark)) {
				log_message(LOG_INFO, "Virtual server group %s has no configuration - ignoring virtual server %s", vs->vsgname, FMT_VS(vs));
				free_vs_checkers(vs);
				free_list_element(check_data->vs, e);
				continue;
			}

			/* Check the vs and vsg address families match */
			if (!LIST_ISEMPTY(vs->vsg->addr_range)) {
				vsge = ELEMENT_DATA(LIST_HEAD(vs->vsg->addr_range));
				vsg_af = vsge->addr.ss_family;
			}
			else {
				/* fwmark only */
				vsg_af = AF_UNSPEC;
			}

			if (vsg_af != AF_UNSPEC && vsg_af != vs->af) {
				log_message(LOG_INFO, "Virtual server group %s address family doesn't match virtual server %s - ignoring", vs->vsgname, FMT_VS(vs));
				free_vs_checkers(vs);
				free_list_element(check_data->vs, e);
			}
		}
	}

	/* The virtual server port number is used to identify the sequence number of the virtual server in the group */
	if (LIST_ISEMPTY(check_data->vs_group))
		return;

	for (e = LIST_HEAD(check_data->vs_group); e; ELEMENT_NEXT(e)) {
		vsg_member_no = 0;
		vsg = ELEMENT_DATA(e);

		for (e1 = LIST_HEAD(check_data->vs); e1; ELEMENT_NEXT(e1)) {
			vs = ELEMENT_DATA(e1);

			if (!vs->vsgname)
				continue;

			if (!strcmp(vs->vsgname, vsg->gname)) {
				/* We use the IPv4 port since there is no address family */
				((struct sockaddr_in *)&vs->addr)->sin_port = htons(vsg_member_no);
				vsg_member_no++;
			}
		}
	}
}
