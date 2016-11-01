/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Interface tracking framework.
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

/* local include */
#include "vrrp_track.h"
#include "vrrp_if.h"
#include "vrrp_data.h"
#include "vrrp.h"
#include "vrrp_sync.h"
#include "logger.h"
#include "memory.h"
#include "vrrp_scheduler.h"

/* Track interface dump */
void
dump_track(void *track_data)
{
	tracked_if_t *tip = track_data;
	log_message(LOG_INFO, "     %s weight %d", IF_NAME(tip->ifp), tip->weight);
}

void
free_track(void *tip)
{
	FREE(tip);
}

void
alloc_track(list track_list, vector_t *strvec)
{
	interface_t *ifp = NULL;
	tracked_if_t *tip = NULL;
	int weight = 0;
	char *tracked = vector_slot(strvec, 0);

	ifp = if_get_by_ifname(tracked);

	/* Ignoring if no interface found */
	if (!ifp) {
		log_message(LOG_INFO, "     %s no match, ignoring...", tracked);
		return;
	}

	if (vector_size(strvec) >= 3 &&
	    !strcmp(vector_slot(strvec, 1), "weight")) {
		weight = atoi(vector_slot(strvec, 2));
		if (weight < -254 || weight > 254) {
			log_message(LOG_INFO, "     %s: weight must be between "
					 "[-254..254] inclusive. Ignoring...", tracked);
			weight = 0;
		}
	}

	tip	    = (tracked_if_t *) MALLOC(sizeof(tracked_if_t));
	tip->ifp    = ifp;
	tip->weight = weight;

	list_add(track_list, tip);
}

vrrp_script_t *
find_script_by_name(char *name)
{
	element e;
	vrrp_script_t *scr;

	if (LIST_ISEMPTY(vrrp_data->vrrp_script))
		return NULL;

	for (e = LIST_HEAD(vrrp_data->vrrp_script); e; ELEMENT_NEXT(e)) {
		scr = ELEMENT_DATA(e);
		if (!strcmp(scr->sname, name))
			return scr;
	}
	return NULL;
}

/* Track script dump */
void
dump_track_script(void *track_data)
{
	tracked_sc_t *tsc = track_data;
	log_message(LOG_INFO, "     %s weight %d", tsc->scr->sname, tsc->weight);
}

void
free_track_script(void *tsc)
{
	FREE(tsc);
}

void
alloc_track_script(vrrp_t *vrrp, vector_t *strvec)
{
	vrrp_script_t *vsc = NULL;
	tracked_sc_t *tsc = NULL;
	int weight = 0;
	char *tracked = vector_slot(strvec, 0);

	vsc = find_script_by_name(tracked);

	/* Ignoring if no script found */
	if (!vsc) {
		log_message(LOG_INFO, "     %s no match, ignoring...", tracked);
		return;
	}

	/* default weight */
	weight = vsc->weight;

	if (vector_size(strvec) >= 3 &&
	    !strcmp(vector_slot(strvec, 1), "weight")) {
		weight = atoi(vector_slot(strvec, 2));
		if (weight < -254 || weight > 254) {
			weight = vsc->weight;
			log_message(LOG_INFO, "     %s: weight must be between [-254..254]"
					 " inclusive, ignoring...",
			       tracked);
		}
	}

	tsc	    = (tracked_sc_t *) MALLOC(sizeof(tracked_sc_t));
	tsc->scr    = vsc;
	tsc->weight = weight;
	vsc->result = VRRP_SCRIPT_STATUS_INIT;
	list_add(vrrp->track_script, tsc);
}

/* Test if all tracked interfaces are either UP or weight-tracked */
bool
vrrp_tracked_up(list l)
{
	element e;
	tracked_if_t *tip;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		tip = ELEMENT_DATA(e);
		if (!tip->weight && !IF_ISUP(tip->ifp))
			return false;
	}

	return true;
}

/* Log tracked interface down */
void
vrrp_log_tracked_down(list l)
{
	element e;
	tracked_if_t *tip;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		tip = ELEMENT_DATA(e);
		if (!IF_ISUP(tip->ifp))
			log_message(LOG_INFO, "Kernel is reporting: interface %s DOWN",
			       IF_NAME(tip->ifp));
	}
}

/* Test if all tracked scripts are either OK or weight-tracked */
bool
vrrp_script_up(list l)
{
	element e;
	tracked_sc_t *tsc;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		tsc = ELEMENT_DATA(e);
		if (!tsc->weight && tsc->scr->result < tsc->scr->rise)
			return false;
	}

	return true;
}

void
down_instance(vrrp_t *vrrp)
{
	if (vrrp->num_script_if_fault++ == 0) {
		vrrp->wantstate = VRRP_STATE_GOTO_FAULT;
		if (vrrp->state == VRRP_STATE_MAST)
			vrrp_state_leave_master(vrrp);
		else
			vrrp_state_leave_fault(vrrp);
		timer_disable(vrrp->sands);

		if (vrrp->sync && vrrp->sync->num_member_fault++ == 0)
			vrrp_sync_fault(vrrp);
	}
}

void
update_script_priorities(vrrp_script_t *vscript, bool script_ok)
{
	element e, e1;
	vrrp_t *vrrp;
	tracked_sc_t *tsc;

	if (LIST_ISEMPTY(vscript->vrrp))
		return;

	for (e = LIST_HEAD(vscript->vrrp); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		/* Don't change effective priority if address owner */
		if (vrrp->base_priority == VRRP_PRIO_OWNER)
			continue;

		if (LIST_ISEMPTY(vrrp->track_script))
			continue;

		for (e1 = LIST_HEAD(vrrp->track_script); e1; ELEMENT_NEXT(e1)) {
			tsc = ELEMENT_DATA(e1);

			/* Skip if we haven't found the matching entry */
			if (tsc->scr != vscript)
				continue;

			if (!tsc->weight) {
				if (!script_ok) {
					/* The instance needs to go down */
					down_instance(vrrp);
				} else {
					/* The instance can come up */
					try_up_instance(vrrp);  // Set want_state = BACKUP/MASTER, and check i/fs and sync groups
				}
				break;
			}

			if (script_ok)
				vrrp->total_priority += abs(tsc->weight);
			else
				vrrp->total_priority -= abs(tsc->weight);

			vrrp_set_effective_priority(vrrp);
		}
	}
}

void
initialise_tracking_priorities(vrrp_t *vrrp)
{
	element e;
	tracked_if_t *tip;
	tracked_sc_t *tsc;

	if (!LIST_ISEMPTY(vrrp->track_ifp)) {
		for (e = LIST_HEAD(vrrp->track_ifp); e; ELEMENT_NEXT(e)) {
			tip = ELEMENT_DATA(e);

			if (!tip->weight) {
				if (!IF_ISUP(tip->ifp)) {
					/* The instance is down */
					vrrp->state = VRRP_STATE_FAULT;
				}
				continue;
			}

			/* Don't change effective priority if address owner, or if
			 * a member of a sync group without global tracking */
			if (vrrp->base_priority == VRRP_PRIO_OWNER ||
			    (vrrp->sync && !vrrp->sync->global_tracking))
				continue;

			if (IF_ISUP(tip->ifp)) {
				if (tip->weight > 0)
					vrrp->total_priority += tip->weight;
			}
			else {
				if (tip->weight < 0)
					vrrp->total_priority += tip->weight;
			}
		}
	}

	if (!LIST_ISEMPTY(vrrp->track_script)) {
		for (e = LIST_HEAD(vrrp->track_script); e; ELEMENT_NEXT(e)) {
			tsc = ELEMENT_DATA(e);

			if (!tsc->weight) {
				if (tsc->scr->result == VRRP_SCRIPT_STATUS_INIT ||
				    (tsc->scr->result >= 0 && tsc->scr->result < tsc->scr->rise)) {
					/* The script is in fault state */
					vrrp->num_script_if_fault++;
					if (tsc->scr->result >= 0)	/* Not INIT_STATE etc */
						vrrp->state = VRRP_STATE_FAULT;
				}
				continue;
			}

			/* Don't change effective priority if address owner, or if
			 * a member of a sync group with global tracking */
			if (vrrp->base_priority == VRRP_PRIO_OWNER ||
			    (vrrp->sync && !vrrp->sync->global_tracking))
				continue;

			if (tsc->scr->result >= tsc->scr->rise) {
				if (tsc->weight > 0)
					vrrp->total_priority += tsc->weight;
			} else {
				if (tsc->weight < 0)
					vrrp->total_priority += tsc->weight;
			}
		}
	}

	vrrp_set_effective_priority(vrrp);
}
