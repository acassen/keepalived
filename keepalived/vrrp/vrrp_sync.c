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

#include "vrrp_sync.h"
#include "vrrp_if.h"
#include "vrrp_notify.h"
#include "vrrp_data.h"
#ifdef _WITH_SNMP_
  #include "vrrp_snmp.h"
#endif
#include "logger.h"
#include "smtp.h"

/* Compute the new instance sands */
void
vrrp_init_instance_sands(vrrp_t * vrrp)
{
	set_time_now();

	if (vrrp->state == VRRP_STATE_MAST	  ||
	    vrrp->state == VRRP_STATE_GOTO_MASTER ||
	    vrrp->state == VRRP_STATE_GOTO_FAULT  ||
	    vrrp->wantstate == VRRP_STATE_GOTO_MASTER) {
		vrrp->sands = timer_add_long(time_now, vrrp->adver_int);
		return;
	}

	/*
	 * When in the BACKUP state the expiry timer should be updated to
	 * time_now plus the Master Down Timer, when a non-preemptable packet is
	 * received. (When a preemptable packet is received, the wantstate is
	 * moved to GOTO_MASTER and this condition is caught above).
	 */
	if (vrrp->state == VRRP_STATE_BACK || vrrp->state == VRRP_STATE_FAULT)
		vrrp->sands = timer_add_long(time_now, vrrp->ms_down_timer);
}

/* Instance name lookup */
vrrp_t *
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
	int i;

	for (i = 0; i < vector_size(vgroup->iname); i++) {
		str = vector_slot(vgroup->iname, i);
		vrrp = vrrp_get_instance(str);
		if (vrrp) {
			if (LIST_ISEMPTY(vgroup->index_list))
				vgroup->index_list = alloc_list(NULL, NULL);
			list_add(vgroup->index_list, vrrp);
			vrrp->sync = vgroup;
		}
	}
}

/* All interface are UP in the same group */
int
vrrp_sync_group_up(vrrp_sgroup_t * vgroup)
{
	vrrp_t *vrrp;
	element e;
	list l = vgroup->index_list;
	int is_up = 0;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (VRRP_ISUP(vrrp))
			is_up++;
	}

	if (is_up == LIST_SIZE(vgroup->index_list)) {
		log_message(LOG_INFO, "Kernel is reporting: Group(%s) UP"
			       , GROUP_NAME(vgroup));
		return 1;
	}
	return 0;
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

/* Leaving fault state */
int
vrrp_sync_leave_fault(vrrp_t * vrrp)
{
	vrrp_sgroup_t *vgroup = vrrp->sync;

	if (vrrp_sync_group_up(vgroup)) {
		log_message(LOG_INFO, "VRRP_Group(%s) Leaving FAULT state",
		       GROUP_NAME(vgroup));
		return 1;
	}
	return 0;
}

/* Check transition to master state */
int
vrrp_sync_goto_master(vrrp_t * vrrp)
{
	vrrp_t *isync;
	vrrp_sgroup_t *vgroup = vrrp->sync;
	list l = vgroup->index_list;
	element e;

	if (GROUP_STATE(vgroup) == VRRP_STATE_MAST)
		return 1;
	if (GROUP_STATE(vgroup) == VRRP_STATE_GOTO_MASTER)
		return 1;

        /* Only sync to master if everyone wants to 
	 * i.e. prefer backup state to avoid thrashing */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		isync = ELEMENT_DATA(e);
		if (isync != vrrp && (isync->wantstate != VRRP_STATE_GOTO_MASTER && 
		                      isync->wantstate != VRRP_STATE_MAST)) {
			return 0;	
		}
	}
	return 1;
}

void
vrrp_sync_master_election(vrrp_t * vrrp)
{
	vrrp_t *isync;
	vrrp_sgroup_t *vgroup = vrrp->sync;
	list l = vgroup->index_list;
	element e;

	if (vrrp->wantstate != VRRP_STATE_GOTO_MASTER)
		return;
	if (GROUP_STATE(vgroup) == VRRP_STATE_FAULT)
		return;

	log_message(LOG_INFO, "VRRP_Group(%s) Transition to MASTER state",
	       GROUP_NAME(vgroup));

	/* Perform sync index */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		isync = ELEMENT_DATA(e);
		if (isync != vrrp && isync->wantstate != VRRP_STATE_GOTO_MASTER) {
			/* Force a new protocol master election */
			isync->wantstate = VRRP_STATE_GOTO_MASTER;
			log_message(LOG_INFO,
			       "VRRP_Instance(%s) forcing a new MASTER election",
			       isync->iname);
			vrrp_send_adv(isync, isync->effective_priority);
		}
	}
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
		if (isync != vrrp && isync->state != VRRP_STATE_BACK) {
			isync->wantstate = VRRP_STATE_BACK;
			vrrp_state_leave_master(isync);
			vrrp_init_instance_sands(isync);
		}
	}
	vgroup->state = VRRP_STATE_BACK;
	vrrp_sync_smtp_notifier(vgroup);
	notify_group_exec(vgroup, VRRP_STATE_BACK);
#ifdef _WITH_SNMP_
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
	if (!vrrp_sync_goto_master(vrrp))
		return;

	log_message(LOG_INFO, "VRRP_Group(%s) Syncing instances to MASTER state",
	       GROUP_NAME(vgroup));

	/* Perform sync index */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		isync = ELEMENT_DATA(e);

		/* Send the higher priority advert on all synced instances */
		if (isync != vrrp && isync->state != VRRP_STATE_MAST) {
			isync->wantstate = VRRP_STATE_MAST;
			vrrp_state_goto_master(isync);
			vrrp_init_instance_sands(isync);
		}
	}
	vgroup->state = VRRP_STATE_MAST;
	vrrp_sync_smtp_notifier(vgroup);
	notify_group_exec(vgroup, VRRP_STATE_MAST);
#ifdef _WITH_SNMP_
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
			if (isync->state == VRRP_STATE_MAST)
				isync->wantstate = VRRP_STATE_GOTO_FAULT;
			if (isync->state == VRRP_STATE_BACK)
				isync->state = VRRP_STATE_FAULT;
		}
	}
	vgroup->state = VRRP_STATE_FAULT;
	notify_group_exec(vgroup, VRRP_STATE_FAULT);
#ifdef _WITH_SNMP_
	vrrp_snmp_group_trap(vgroup);
#endif
}
