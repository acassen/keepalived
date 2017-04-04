/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        VRRP synchronization framework.
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

#include <stdbool.h>

#include "vrrp_sync.h"
#include "vrrp_track.h"
#include "vrrp_notify.h"
#include "vrrp_data.h"
#ifdef _WITH_SNMP_
  #include "vrrp_snmp.h"
#endif
#include "logger.h"
#include "smtp.h"

#include "vrrp_print.h"

/* Compute the new instance sands */
void
vrrp_init_instance_sands(vrrp_t * vrrp)
{
	set_time_now();

	if (vrrp->state == VRRP_STATE_MAST) {
		vrrp->sands = timer_add_long(time_now, vrrp->adver_int);
		return;
	}

	/*
	 * When in the BACKUP state the expiry timer should be updated to
	 * time_now plus the Master Down Timer, when a non-preemptable packet is
	 * received.
	 */
	if (vrrp->state == VRRP_STATE_BACK)
		vrrp->sands = timer_add_long(time_now, vrrp->ms_down_timer);
	else if (vrrp->state == VRRP_STATE_FAULT || vrrp->state == VRRP_STATE_INIT)
		vrrp->sands.tv_sec = TIMER_DISABLED;
}

/* Instance name lookup */
static vrrp_t *
vrrp_get_instance(char *iname)
{
	vrrp_t *vrrp;
	list l = vrrp_data->vrrp;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (strcmp(vrrp->iname, iname) == 0)
			return vrrp;
	}
	return NULL;
}

/* Set instances group pointer */
void
vrrp_sync_set_group(vrrp_sgroup_t *vgroup)
{
	vrrp_t *vrrp;
	char *str;
	unsigned int i;
	vrrp_t *vrrp_last = NULL;
	bool group_member_down = false;

	/* Can't handle no members of the group */
	if (!vgroup->iname)
		return;

	vgroup->index_list = alloc_list(NULL, NULL);

	for (i = 0; i < vector_size(vgroup->iname); i++) {
		str = vector_slot(vgroup->iname, i);
		vrrp = vrrp_get_instance(str);
		if (!vrrp) {
			log_message(LOG_INFO, "Virtual router %s specified in sync group %s doesn't exist - ignoring", str, vgroup->gname);
			continue;
		}

		if (vrrp->sync) {
			log_message(LOG_INFO, "Virtual router %s cannot exist in more than one sync group; ignoring %s", str, vgroup->gname);
			continue;
		}

		list_add(vgroup->index_list, vrrp);
		vrrp->sync = vgroup;
		vrrp_last = vrrp;

		/* set eventual sync group state. Unless all members are master and address owner,
		 * then we must be backup */
		if (vgroup->state == VRRP_STATE_MAST && vrrp->init_state == VRRP_STATE_BACK)
			log_message(LOG_INFO, "Sync group %s has some member(s) as address owner and some not as address owner. This won't work", vgroup->gname);
		if (vgroup->state != VRRP_STATE_BACK)
			vgroup->state = (vrrp->init_state == VRRP_STATE_MAST && vrrp->base_priority == VRRP_PRIO_OWNER) ? VRRP_STATE_MAST : VRRP_STATE_BACK;

// TODO - what about track scripts down?
		if (vrrp->state == VRRP_STATE_FAULT)
			group_member_down = true;
	}

	if (group_member_down)
		vgroup->state = VRRP_STATE_FAULT;

	if (LIST_SIZE(vgroup->index_list) <= 1) {
		/* The sync group will be removed by the calling function */
		log_message(LOG_INFO, "Sync group %s has only %d virtual router(s) - removing", vgroup->gname, LIST_SIZE(vgroup->index_list));

		/* If there is only one entry in the group, remove the group from the vrrp entry */
		if (vrrp_last)
			vrrp_last->sync = NULL;

		free_list(&vgroup->index_list);
	}

	/* The iname vector is only used for us to set up the sync groups, so delete it */
	free_strvec(vgroup->iname);
	vgroup->iname = NULL;
}

/* SMTP alert group notifier */
void
vrrp_sync_smtp_notifier(vrrp_sgroup_t *vgroup)
{
	if (vgroup->smtp_alert) {
		if (GROUP_STATE(vgroup) == VRRP_STATE_MAST)
			smtp_alert(NULL, NULL, vgroup,
				   "Entering MASTER state",
				   "=> All VRRP group instances are now in MASTER state <=");
		if (GROUP_STATE(vgroup) == VRRP_STATE_BACK)
			smtp_alert(NULL, NULL, vgroup,
				   "Entering BACKUP state",
				   "=> All VRRP group instances are now in BACKUP state <=");
	}
}

/* Check transition to master state */
bool
vrrp_sync_can_goto_master(vrrp_t * vrrp)
{
	vrrp_t *isync;
	vrrp_sgroup_t *vgroup = vrrp->sync;
	list l = vgroup->index_list;
	element e;

	if (GROUP_STATE(vgroup) == VRRP_STATE_MAST)
		return true;

	/* Only sync to master if everyone wants to
	 * i.e. prefer backup state to avoid thrashing */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		isync = ELEMENT_DATA(e);
		if (isync != vrrp && isync->wantstate != VRRP_STATE_MAST) {
			return false;
		}
	}
	return true;
}

void
vrrp_sync_backup(vrrp_t * vrrp)
{
	vrrp_t *isync;
	vrrp_sgroup_t *vgroup = vrrp->sync;
	list l = vgroup->index_list;
	element e;

	if (GROUP_STATE(vgroup) == VRRP_STATE_BACK)
		return;

	log_message(LOG_INFO, "VRRP_Group(%s) Syncing instances to BACKUP state",
	       GROUP_NAME(vgroup));

	/* Perform sync index */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		isync = ELEMENT_DATA(e);
		if (isync == vrrp || isync->state == VRRP_STATE_BACK)
			continue;

		isync->wantstate = VRRP_STATE_BACK;
// TODO - we may be leaving FAULT, so calling leave_master isn't right. I have
// had to add vrrp_state_leave_fault() for this
		if (isync->state == VRRP_STATE_FAULT) {
			vrrp_state_leave_fault(isync);
			thread_requeue_read(master, isync->sockets->fd_in, isync->ms_down_timer);
		}
		else
			vrrp_state_leave_master(isync);
		vrrp_init_instance_sands(isync);
	}
	vgroup->state = VRRP_STATE_BACK;
	vrrp_sync_smtp_notifier(vgroup);
	notify_group_exec(vgroup, VRRP_STATE_BACK);
#ifdef _WITH_SNMP_KEEPALIVED_
	vrrp_snmp_group_trap(vgroup);
#endif
}

void
vrrp_sync_master(vrrp_t * vrrp)
{
	vrrp_t *isync;
	vrrp_sgroup_t *vgroup = vrrp->sync;
	list l = vgroup->index_list;
	element e;

	if (GROUP_STATE(vgroup) == VRRP_STATE_MAST)
		return;
	if (!vrrp_sync_can_goto_master(vrrp))
		return;

	log_message(LOG_INFO, "VRRP_Group(%s) Syncing instances to MASTER state", GROUP_NAME(vgroup));

	/* Perform sync index */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		isync = ELEMENT_DATA(e);

// TODO		/* Send the higher priority advert on all synced instances */
		if (isync != vrrp && isync->state != VRRP_STATE_MAST) {
			isync->wantstate = VRRP_STATE_MAST;
// TODO 6 - transition straight to master if PRIO_OWNER
// TODO 7 - not here, but generally if init_state == MAST && !owner, ms_down_timer = adver_int + 1 skew and be backup
			vrrp_init_instance_sands(isync);
			if (vrrp->init_state == VRRP_STATE_MAST && vrrp->base_priority == VRRP_PRIO_OWNER) {
				/* ??? */
			} else {
				vrrp_state_goto_master(isync);
				thread_requeue_read(master, vrrp->sockets->fd_in, vrrp->ms_down_timer);
			}
		}
	}
	vgroup->state = VRRP_STATE_MAST;
	vrrp_sync_smtp_notifier(vgroup);
	notify_group_exec(vgroup, VRRP_STATE_MAST);
#ifdef _WITH_SNMP_KEEPALIVED_
	vrrp_snmp_group_trap(vgroup);
#endif
}

void
vrrp_sync_fault(vrrp_t * vrrp)
{
	vrrp_t *isync;
	vrrp_sgroup_t *vgroup = vrrp->sync;
	list l = vgroup->index_list;
	element e;

	if (GROUP_STATE(vgroup) == VRRP_STATE_FAULT)
		return;

	log_message(LOG_INFO, "VRRP_Group(%s) Syncing instances to FAULT state",
	       GROUP_NAME(vgroup));

	/* Perform sync index */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		isync = ELEMENT_DATA(e);

		/*
		 * We force sync instance to backup mode.
		 * This reduce instance takeover to less than ms_down_timer.
		 * => by default ms_down_timer is set to 3secs.
		 * => Takeover will be less than 3secs !
		 */
		if (isync != vrrp && isync->state != VRRP_STATE_FAULT) {
			isync->wantstate = VRRP_STATE_FAULT;
			if (isync->state == VRRP_STATE_MAST) {
				vrrp_state_leave_master(isync);
			}
			else if (isync->state == VRRP_STATE_BACK || isync->state == VRRP_STATE_INIT) {
				isync->state = VRRP_STATE_FAULT;	/* This is a bit of a bodge */
				vrrp_state_leave_fault(isync);
			}
		}
	}
	vgroup->state = VRRP_STATE_FAULT;
	notify_group_exec(vgroup, VRRP_STATE_FAULT);
#ifdef _WITH_SNMP_KEEPALIVED_
	vrrp_snmp_group_trap(vgroup);
#endif
}
