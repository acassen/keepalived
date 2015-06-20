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

#include "ipwrapper.h"
#include "ipvswrapper.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "notify.h"
#include "main.h"
#ifdef _WITH_SNMP_
  #include "check_snmp.h"
#endif

/* out-of-order functions declarations */
static void update_quorum_state(virtual_server_t * vs);

/* Returns the sum of all RS weight in a virtual server. */
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

/* Remove a realserver IPVS rule */
static int
clear_service_rs(virtual_server_t * vs, list l)
{
	element e;
	real_server_t *rs;
	long weight_sum;
	long down_threshold = vs->quorum - vs->hysteresis;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (ISALIVE(rs)) {
			log_message(LOG_INFO, "Removing service %s from VS %s"
						, FMT_RS(rs)
						, FMT_VS(vs));
			ipvs_cmd(LVS_CMD_DEL_DEST, vs, rs);
			UNSET_ALIVE(rs);
			if (!vs->omega)
				continue;

			/* In Omega mode we call VS and RS down notifiers
			 * all the way down the exit, as necessary.
			 */
			if (rs->notify_down) {
				log_message(LOG_INFO, "Executing [%s] for service %s in VS %s"
						    , rs->notify_down
						    , FMT_RS(rs)
						    , FMT_VS(vs));
				notify_exec(rs->notify_down);
			}
#ifdef _WITH_SNMP_
			check_snmp_rs_trap(rs, vs);
#endif

			/* Sooner or later VS will lose the quorum (if any). However,
			 * we don't push in a sorry server then, hence the regression
			 * is intended.
			 */
			weight_sum = weigh_live_realservers(vs);
			if (vs->quorum_state == UP && (
				!weight_sum ||
				weight_sum < down_threshold)
			) {
				vs->quorum_state = DOWN;
				if (vs->quorum_down) {
					log_message(LOG_INFO, "Executing [%s] for VS %s"
							    , vs->quorum_down
							    , FMT_VS(vs));
					notify_exec(vs->quorum_down);
				}
#ifdef _WITH_SNMP_
				check_snmp_quorum_trap(vs);
#endif
			}
		}
	}

	return 1;
}

/* Remove a virtualserver IPVS rule */
static int
clear_service_vs(virtual_server_t * vs)
{
	/* Processing real server queue */
	if (!LIST_ISEMPTY(vs->rs)) {
		if (vs->s_svr) {
			if (ISALIVE(vs->s_svr))
				ipvs_cmd(LVS_CMD_DEL_DEST, vs, vs->s_svr);
		} else if (!clear_service_rs(vs, vs->rs))
			return 0;
		/* The above will handle Omega case for VS as well. */
	}

	ipvs_cmd(LVS_CMD_DEL, vs, NULL);

	UNSET_ALIVE(vs);
	return 1;
}

/* IPVS cleaner processing */
int
clear_services(void)
{
	element e;
	list l = check_data->vs;
	virtual_server_t *vs;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);
		if (!clear_service_vs(vs))
			return 0;
	}
	return 1;
}

/* Set a realserver IPVS rules */
static int
init_service_rs(virtual_server_t * vs)
{
	element e;
	real_server_t *rs;

	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);

		if (rs->reloaded) {
			if (rs->iweight != rs->pweight)
				update_svr_wgt(rs->iweight, vs, rs, 0);
			/* Do not re-add failed RS instantly on reload */
			continue;
		}
		/* In alpha mode, be pessimistic (or realistic?) and don't
		 * add real servers into the VS pool. They will get there
		 * later upon healthchecks recovery (if ever).
		 */
		if (!vs->alpha && !ISALIVE(rs)) {
			ipvs_cmd(LVS_CMD_ADD_DEST, vs, rs);
			SET_ALIVE(rs);
		}
	}

	return 1;
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
		vsg->addr_ip,
		vsg->vfwmark,
		vsg->range,
		NULL,
	};

	for (l = ll; *l; l++)
		for (e = LIST_HEAD(*l); e; ELEMENT_NEXT(e)) {
			vsge = ELEMENT_DATA(e);
			if (vs->reloaded && !vsge->reloaded) {
				log_message(LOG_INFO, "VS [%s:%d:%u] added into group %s"
						    , inet_sockaddrtopair(&vsge->addr)
						    , vsge->range
						    , vsge->vfwmark
						    , vs->vsgname);
				/* add all reloaded and alive/inhibit-set dests
				 * to the newly created vsg item */
				ipvs_group_sync_entry(vs, vsge);
			}
		}
}

/* Set a virtualserver IPVS rules */
static int
init_service_vs(virtual_server_t * vs)
{
	/* Init the VS root */
	if (!ISALIVE(vs) || vs->vsgname) {
		ipvs_cmd(LVS_CMD_ADD, vs, NULL);
		SET_ALIVE(vs);
	}

	/* Processing real server queue */
	if (!init_service_rs(vs))
		return 0;

	if (vs->reloaded) {
		if (vs->vsgname)
			/* add reloaded dests into new vsg entries */
			sync_service_vsg(vs);

		/* we may have got/lost quorum due to quorum setting changed */
		update_quorum_state(vs);
	}

	return 1;
}

/* Set IPVS rules */
int
init_services(void)
{
	element e;
	list l = check_data->vs;
	virtual_server_t *vs;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);
		if (!init_service_vs(vs))
			return 0;
	}
	return 1;
}

/* add or remove _alive_ real servers from a virtual server */
void
perform_quorum_state(virtual_server_t *vs, int add)
{
	element e;
	real_server_t *rs;

	if (LIST_ISEMPTY(vs->rs))
		return;

	log_message(LOG_INFO, "%s the pool for VS %s"
			    , add?"Adding alive servers to":"Removing alive servers from"
			    , FMT_VS(vs));
	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (!ISALIVE(rs)) /* We only handle alive servers */
			continue;
		if (add)
			rs->alive = 0;
		ipvs_cmd(add?LVS_CMD_ADD_DEST:LVS_CMD_DEL_DEST, vs, rs);
		rs->alive = 1;
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
	if (vs->quorum_state == DOWN &&
	    weight_sum >= up_threshold) {
		vs->quorum_state = UP;
		log_message(LOG_INFO, "Gained quorum %lu+%lu=%li <= %li for VS %s"
				    , vs->quorum
				    , vs->hysteresis
				    , up_threshold
				    , weight_sum
				    , FMT_VS(vs));
		if (vs->s_svr && ISALIVE(vs->s_svr)) {
			log_message(LOG_INFO, "%s sorry server %s from VS %s"
					    , (vs->s_svr->inhibit ? "Disabling" : "Removing")
					    , FMT_RS(vs->s_svr)
					    , FMT_VS(vs));

			ipvs_cmd(LVS_CMD_DEL_DEST, vs, vs->s_svr);
			vs->s_svr->alive = 0;

			/* Adding back alive real servers */
			perform_quorum_state(vs, 1);
		}
		if (vs->quorum_up) {
			log_message(LOG_INFO, "Executing [%s] for VS %s"
					    , vs->quorum_up
					    , FMT_VS(vs));
			notify_exec(vs->quorum_up);
		}
#ifdef _WITH_SNMP_
               check_snmp_quorum_trap(vs);
#endif
		return;
	}

	/* If we have just lost quorum for the VS, we need to consider
	 * VS notify_down and sorry_server cases
	 */
	if (vs->quorum_state == UP &&
	    (!weight_sum || weight_sum < down_threshold)
	) {
		vs->quorum_state = DOWN;
		log_message(LOG_INFO, "Lost quorum %lu-%lu=%li > %li for VS %s"
				    , vs->quorum
				    , vs->hysteresis
				    , down_threshold
				    , weight_sum
				    , FMT_VS(vs));
		if (vs->quorum_down) {
			log_message(LOG_INFO, "Executing [%s] for VS %s"
					    , vs->quorum_down
					    , FMT_VS(vs));
			notify_exec(vs->quorum_down);
		}
		if (vs->s_svr) {
			log_message(LOG_INFO, "%s sorry server %s to VS %s"
					    , (vs->s_svr->inhibit ? "Enabling" : "Adding")
					    , FMT_RS(vs->s_svr)
					    , FMT_VS(vs));

			/* the sorry server is now up in the pool, we flag it alive */
			ipvs_cmd(LVS_CMD_ADD_DEST, vs, vs->s_svr);
			vs->s_svr->alive = 1;

			/* Remove remaining alive real servers */
			perform_quorum_state(vs, 0);
		}
#ifdef _WITH_SNMP_
		check_snmp_quorum_trap(vs);
#endif
		return;
	}
}

/* manipulate add/remove rs according to alive state */
int
perform_svr_state(int alive, virtual_server_t * vs, real_server_t * rs)
{
	/*
	 * | ISALIVE(rs) | alive | context
	 * | 0           | 0     | first check failed under alpha mode, unreachable here
	 * | 0           | 1     | RS went up, add it to the pool
	 * | 1           | 0     | RS went down, remove it from the pool
	 * | 1           | 1     | first check succeeded w/o alpha mode, unreachable here
	 */
	if (!ISALIVE(rs) && alive) {
		log_message(LOG_INFO, "%s service %s to VS %s"
				    , (rs->inhibit) ? "Enabling" : "Adding"
				    , FMT_RS(rs)
				    , FMT_VS(vs));
		/* Add only if we have quorum or no sorry server */
		if (vs->quorum_state == UP || !vs->s_svr || !ISALIVE(vs->s_svr)) {
			if (ipvs_cmd(LVS_CMD_ADD_DEST, vs, rs))
				return -1;
		}
		rs->alive = alive;
		if (rs->notify_up) {
			log_message(LOG_INFO, "Executing [%s] for service %s in VS %s"
					    , rs->notify_up
					    , FMT_RS(rs)
					    , FMT_VS(vs));
			notify_exec(rs->notify_up);
		}
#ifdef _WITH_SNMP_
		check_snmp_rs_trap(rs, vs);
#endif

		/* We may have gained quorum */
		update_quorum_state(vs);
	}

	if (ISALIVE(rs) && !alive) {
		log_message(LOG_INFO, "%s service %s from VS %s"
				    , (rs->inhibit) ? "Disabling" : "Removing"
				    , FMT_RS(rs)
				    , FMT_VS(vs));

		/* server is down, it is removed from the LVS realserver pool
		 * Remove only if we have quorum or no sorry server
		 */
		if (vs->quorum_state == UP || !vs->s_svr || !ISALIVE(vs->s_svr)) {
			if (ipvs_cmd(LVS_CMD_DEL_DEST, vs, rs))
				return -1;
		}
		rs->alive = alive;
		if (rs->notify_down) {
			log_message(LOG_INFO, "Executing [%s] for service %s in VS %s"
					    , rs->notify_down
					    , FMT_RS(rs)
					    , FMT_VS(vs));
			notify_exec(rs->notify_down);
		}
#ifdef _WITH_SNMP_
		check_snmp_rs_trap(rs, vs);
#endif

		/* We may have lost quorum */
		update_quorum_state(vs);
	}
	return 0;
}

/* Store new weight in real_server struct and then update kernel. */
void
update_svr_wgt(int weight, virtual_server_t * vs, real_server_t * rs
		, int update_quorum)
{
	if (weight != rs->weight) {
		log_message(LOG_INFO, "Changing weight from %d to %d for %s service %s of VS %s"
				    , rs->weight
				    , weight
				    , ISALIVE(rs) ? "active" : "inactive"
				    , FMT_RS(rs)
				    , FMT_VS(vs));
		rs->weight = weight;
		/*
		 * Have weight change take effect now only if rs is in
		 * the pool and alive and the quorum is met (or if
		 * there is no sorry server). If not, it will take
		 * effect later when it becomes alive.
		 */
		if (rs->set && ISALIVE(rs) &&
		    (vs->quorum_state == UP || !vs->s_svr || !ISALIVE(vs->s_svr)))
			ipvs_cmd(LVS_CMD_EDIT_DEST, vs, rs);
		if (update_quorum)
			update_quorum_state(vs);
	}
}

/* Test if realserver is marked UP for a specific checker */
int
svr_checker_up(checker_id_t cid, real_server_t *rs)
{
	element e;
	list l = rs->failed_checkers;
	checker_id_t *id;

	/*
	 * We assume there is not too much checker per
	 * real server, so we consider this lookup as
	 * o(1).
	 */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		id = ELEMENT_DATA(e);
		if (*id == cid)
			return 0;
	}

	return 1;
}

/* Update checker's state */
void
update_svr_checker_state(int alive, checker_id_t cid, virtual_server_t *vs, real_server_t *rs)
{
	element e;
	list l = rs->failed_checkers;
	checker_id_t *id;

	/* Handle alive state. Depopulate failed_checkers and call
	 * perform_svr_state() independently, letting the latter sort
	 * things out itself.
	 */
	if (alive) {
		for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
			id = ELEMENT_DATA(e);
			if (*id == cid)
				break;
		}

		/* call the UP handler unless any more failed checks found */
		if (LIST_SIZE(l) == 0 || (LIST_SIZE(l) == 1 && e)) {
			if (perform_svr_state(alive, vs, rs))
				return;
		}

		/* Remove the succeeded check from failed_checkers */
		if (e)
			free_list_element(l, e);
	}
	/* Handle not alive state */
	else {
		if (LIST_SIZE(l) == 0) {
			if (perform_svr_state(alive, vs, rs))
				return;
		} else {
			/* do not add failed check into list twice */
			for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
				id = ELEMENT_DATA(e);
				if (*id == cid)
					return;
			}
		}

		id = (checker_id_t *) MALLOC(sizeof(checker_id_t));
		*id = cid;
		list_add(l, id);
	}
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
static int
clear_diff_vsge(list old, list new, virtual_server_t * old_vs)
{
	virtual_server_group_entry_t *vsge, *new_vsge;
	element e;

	for (e = LIST_HEAD(old); e; ELEMENT_NEXT(e)) {
		vsge = ELEMENT_DATA(e);
		new_vsge = vsge_exist(vsge, new);
		if (new_vsge) {
			new_vsge->alive = vsge->alive;
			new_vsge->reloaded = 1;
		}
		else {
			log_message(LOG_INFO, "VS [%s:%d:%u] in group %s no longer exist"
					    , inet_sockaddrtopair(&vsge->addr)
					    , vsge->range
					    , vsge->vfwmark
					    , old_vs->vsgname);

			ipvs_group_remove_entry(old_vs, vsge);
		}
	}

	return 1;
}

/* Clear the diff vsg of the old vs */
static int
clear_diff_vsg(virtual_server_t * old_vs, virtual_server_t * new_vs)
{
	virtual_server_group_t *old = old_vs->vsg;
	virtual_server_group_t *new = new_vs->vsg;

	/* Diff the group entries */
	if (!clear_diff_vsge(old->addr_ip, new->addr_ip, old_vs))
		return 0;
	if (!clear_diff_vsge(old->range, new->range, old_vs))
		return 0;
	if (!clear_diff_vsge(old->vfwmark, new->vfwmark, old_vs))
		return 0;

	return 1;
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

/* Clear the diff rs of the old vs */
static int
clear_diff_rs(virtual_server_t * old_vs, list new_rs_list)
{
	element e;
	list l = old_vs->rs;
	real_server_t *rs, *new_rs;

	/* If old vs didn't own rs then nothing return */
	if (LIST_ISEMPTY(l))
		return 1;

	/* remove RS from old vs which are not found in new vs */
	list rs_to_remove = alloc_list (NULL, NULL);
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		new_rs = rs_exist(rs, new_rs_list);
		if (!new_rs) {
			/* Reset inhibit flag to delete inhibit entries */
			log_message(LOG_INFO, "service %s no longer exist"
					    , FMT_RS(rs));
			rs->inhibit = 0;
			list_add (rs_to_remove, rs);
		} else {
			/*
			 * We reflect the previous alive
			 * flag value to not try to set
			 * already set IPVS rule.
			 */
			new_rs->alive = rs->alive;
			new_rs->set = rs->set;
			new_rs->weight = rs->weight;
			new_rs->pweight = rs->iweight;
			new_rs->reloaded = 1;
			if (new_rs->alive) {
				/* clear failed_checkers list */
				free_list_elements(new_rs->failed_checkers);
			}
		}
	}
	int ret = clear_service_rs (old_vs, rs_to_remove);
	free_list (rs_to_remove);

	return ret;
}

/* When reloading configuration, remove negative diff entries
 * and copy status of existing entries to the new ones */
int
clear_diff_services(void)
{
	element e;
	list l = old_check_data->vs;
	virtual_server_t *vs, *new_vs;

	/* If old config didn't own vs then nothing return */
	if (LIST_ISEMPTY(l))
		return 1;

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
				log_message(LOG_INFO, "Removing Virtual Server Group [%s]"
						    , vs->vsgname);
			else
				log_message(LOG_INFO, "Removing Virtual Server %s"
						    , FMT_VS(vs));

			/* Clear VS entry */
			if (!clear_service_vs(vs))
				return 0;
		} else {
			/* copy status fields from old VS */
			SET_ALIVE(new_vs);
			new_vs->quorum_state = vs->quorum_state;
			new_vs->reloaded = 1;

			if (vs->vsgname)
				clear_diff_vsg(vs, new_vs);

			/* If vs exist, perform rs pool diff */
			/* omega = 0 must not prevent the notifiers from being called,
			   because the VS still exists in new configuration */
			vs->omega = 1;
			if (!clear_diff_rs(vs, new_vs->rs))
				return 0;
			if (vs->s_svr && ISALIVE(vs->s_svr))
				ipvs_cmd(LVS_CMD_DEL_DEST
					      , vs
					      , vs->s_svr);
		}
	}

	return 1;
}

void
link_vsg_to_vs(void)
{
	element e;
	virtual_server_t *vs;

	for (e = LIST_HEAD(check_data->vs); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);
		if (vs->vsgname)
			vs->vsg = ipvs_get_group_by_name(vs->vsgname, check_data->vs_group);
	}
}
