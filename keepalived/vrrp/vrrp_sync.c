/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        VRRP synchronization framework.
 *
 * Version:     $Id: vrrp_sync.c,v 0.7.6 2002/11/20 21:34:18 acassen Exp $
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
 */

#include "vrrp_sync.h"
#include "vrrp_if.h"
#include "vrrp_notify.h"
#include "data.h"

/* extern global vars */
extern data *conf_data;

/* Compute the new instance sands */
void
vrrp_init_instance_sands(vrrp_rt * vrrp)
{
	TIMEVAL timer;

	timer = timer_now();

	if (vrrp->state == VRRP_STATE_BACK || vrrp->state == VRRP_STATE_FAULT) {
		vrrp->sands.tv_sec = timer.tv_sec + vrrp->ms_down_timer / TIMER_HZ;
		vrrp->sands.tv_usec = timer.tv_usec + vrrp->ms_down_timer % TIMER_HZ;
	}
	if (vrrp->state == VRRP_STATE_GOTO_MASTER ||
	    vrrp->state == VRRP_STATE_MAST ||
	    vrrp->state == VRRP_STATE_GOTO_FAULT) {
		vrrp->sands.tv_sec = timer.tv_sec + vrrp->adver_int / TIMER_HZ;
 		vrrp->sands.tv_usec = timer.tv_usec;
	}
}

/* return the first group found for a specific instance */
vrrp_sgroup *
vrrp_get_sync_group(char *iname)
{
	int i;
	char *str;
	element e;
	vrrp_sgroup *vgroup;
	list l = conf_data->vrrp_sync_group;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vgroup = ELEMENT_DATA(e);
		if (vgroup->iname)
			for (i = 0; i < VECTOR_SIZE(vgroup->iname); i++) {
				str = VECTOR_SLOT(vgroup->iname, i);
				if (strcmp(str, iname) == 0)
					return vgroup;
			}
	}
	return NULL;
}

/* jointure between instance and group => iname */
vrrp_rt *
vrrp_get_instance(char *iname)
{
	vrrp_rt *vrrp;
	list l = conf_data->vrrp;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (strcmp(vrrp->iname, iname) == 0)
			return vrrp;
	}
	return NULL;
}

/* All interface are UP in the same group */
int
vrrp_sync_group_up(vrrp_sgroup * vgroup)
{
	vrrp_rt *isync;
	char *str;
	int is_up = 0;
	int i;

	for (i = 0; i < VECTOR_SIZE(vgroup->iname); i++) {
		str = VECTOR_SLOT(vgroup->iname, i);
		isync = vrrp_get_instance(str);
		if (IF_ISUP(isync->ifp))
			is_up++;
	}

	if (is_up == VECTOR_SIZE(vgroup->iname)) {
		syslog(LOG_INFO, "Kernel is reporting: Group(%s) UP"
			       , GROUP_NAME(vgroup));
		return 1;
	}
	return 0;
}

/* Leaving fault state */
int
vrrp_sync_leave_fault(vrrp_rt * vrrp)
{
	vrrp_sgroup *vgroup = vrrp->sync;

	if (vrrp_sync_group_up(vgroup)) {
		syslog(LOG_INFO, "VRRP_Group(%s) Leaving FAULT state",
		       GROUP_NAME(vgroup));
		vgroup->state = VRRP_STATE_MAST;
		notify_group_exec(vgroup, VRRP_STATE_MAST);
		return 1;
	}
	return 0;
}

void
vrrp_sync_master_election(vrrp_rt * vrrp)
{
	int i;
	char *str;
	vrrp_rt *isync;
	vrrp_sgroup *vgroup = vrrp->sync;

	if (vrrp->wantstate != VRRP_STATE_GOTO_MASTER)
		return;
	if (GROUP_STATE(vrrp->sync) == VRRP_STATE_FAULT)
		return;

	syslog(LOG_INFO, "VRRP_Group(%s) Transition to MASTER state",
	       GROUP_NAME(vrrp->sync));

	for (i = 0; i < VECTOR_SIZE(vgroup->iname); i++) {
		str = VECTOR_SLOT(vgroup->iname, i);
		isync = vrrp_get_instance(str);
		if (isync != vrrp)
			isync->wantstate = VRRP_STATE_GOTO_MASTER;

		/* Force a new protocol master election */
		syslog(LOG_INFO,
		       "VRRP_Instance(%s) forcing a new MASTER election",
		       isync->iname);
		vrrp_send_adv(isync, isync->priority);
	}
	vgroup->state = VRRP_STATE_MAST;
	notify_group_exec(vgroup, VRRP_STATE_MAST);
}

void
vrrp_sync_backup(vrrp_rt * vrrp)
{
	int i;
	char *str;
	vrrp_rt *isync;
	vrrp_sgroup *vgroup = vrrp->sync;

	syslog(LOG_INFO, "VRRP_Group(%s) Syncing instances to BACKUP state",
	       GROUP_NAME(vrrp->sync));

	for (i = 0; i < VECTOR_SIZE(vgroup->iname); i++) {
		str = VECTOR_SLOT(vgroup->iname, i);
		isync = vrrp_get_instance(str);
		if (isync != vrrp) {
			isync->wantstate = VRRP_STATE_BACK;
			vrrp_state_leave_master(isync);
			vrrp_init_instance_sands(isync);
		}
	}
	vgroup->state = VRRP_STATE_BACK;
	notify_group_exec(vgroup, VRRP_STATE_BACK);
}

void
vrrp_sync_master(vrrp_rt * vrrp)
{
	int i;
	char *str;
	vrrp_rt *isync;
	vrrp_sgroup *vgroup = vrrp->sync;

	syslog(LOG_INFO, "VRRP_Group(%s) Syncing instances to MASTER state",
	       GROUP_NAME(vrrp->sync));

	for (i = 0; i < VECTOR_SIZE(vgroup->iname); i++) {
		str = VECTOR_SLOT(vgroup->iname, i);
		isync = vrrp_get_instance(str);

		/* Send the higher priority advert on all synced instances */
		if (isync != vrrp) {
			isync->wantstate = VRRP_STATE_MAST;
			vrrp_state_goto_master(isync);
			vrrp_init_instance_sands(isync);
		}
	}
	vgroup->state = VRRP_STATE_MAST;
	notify_group_exec(vgroup, VRRP_STATE_MAST);
}

void
vrrp_sync_fault(vrrp_rt * vrrp)
{
	int i;
	char *str;
	vrrp_rt *isync;
	vrrp_sgroup *vgroup = vrrp->sync;

	if (GROUP_STATE(vrrp->sync) == VRRP_STATE_FAULT)
		return;

	syslog(LOG_INFO, "VRRP_Group(%s) Syncing instances to FAULT state",
	       GROUP_NAME(vrrp->sync));

	for (i = 0; i < VECTOR_SIZE(vgroup->iname); i++) {
		str = VECTOR_SLOT(vgroup->iname, i);
		isync = vrrp_get_instance(str);

		/*
		 * We force sync instance to backup mode.
		 * This reduce instance takeover to less than ms_down_timer.
		 * => by default ms_down_timer is set to 3secs.
		 * => Takeover will be less than 3secs !
		 */
		if (isync != vrrp) {
			if (isync->state == VRRP_STATE_MAST)
				isync->wantstate = VRRP_STATE_GOTO_FAULT;
			if (isync->state == VRRP_STATE_BACK)
				isync->state = VRRP_STATE_FAULT;
		}
	}
	vgroup->state = VRRP_STATE_FAULT;
	notify_group_exec(vgroup, VRRP_STATE_FAULT);
}
