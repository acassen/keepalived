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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <net/if.h>
#include <stdlib.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>

/* local include */
#include "vrrp_track.h"
#include "vrrp_data.h"
#include "vrrp.h"
#include "vrrp_sync.h"
#include "logger.h"
#include "memory.h"
#include "vrrp_scheduler.h"
#include "scheduler.h"
#include "parser.h"
#include "utils.h"
#include "vrrp_notify.h"
#include "bitops.h"
#include "track_file.h"
#ifdef _WITH_TRACK_PROCESS_
#include "track_process.h"
#endif


/* Track interface dump */
static void
dump_track_if(FILE *fp, const tracked_if_t *tip)
{
	conf_write(fp, "     %s weight %d%s", IF_NAME(tip->ifp), tip->weight, tip->weight_reverse ? " reverse" : "");
}
void
dump_track_if_list(FILE *fp, const list_head_t *l)
{
	tracked_if_t *tip;

	list_for_each_entry(tip, l, e_list)
		dump_track_if(fp, tip);
}

void
free_track_if(tracked_if_t *tip)
{
	list_del_init(&tip->e_list);
	FREE(tip);
}

void
free_track_if_list(list_head_t *l)
{
	tracked_if_t *tip, *tip_tmp;

	list_for_each_entry_safe(tip, tip_tmp, l, e_list)
		free_track_if(tip);
}

void
alloc_track_if(const char *name, list_head_t *l, const vector_t *strvec)
{
	interface_t *ifp;
	tracked_if_t *tip;
	int weight = 0;
	const char *tracked = strvec_slot(strvec, 0);
	bool reverse = false;

	ifp = if_get_by_ifname(tracked, IF_CREATE_IF_DYNAMIC);
	if (!ifp) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) tracked interface %s doesn't exist"
							, name, tracked);
		return;
	}

	/* Check this vrrp isn't already tracking the i/f */
	list_for_each_entry(tip, l, e_list) {
		if (tip->ifp == ifp) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) duplicate track_interface %s - ignoring"
								, name, tracked);
			return;
		}
	}

	if (vector_size(strvec) >= 2) {
		if (strcmp(strvec_slot(strvec, 1), "weight")) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track_interface %s"
								  " option %s - ignoring"
								, name, tracked, strvec_slot(strvec, 1));
			return;
		}

		if (vector_size(strvec) == 2) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight without value specified"
								  " for track_interface %s - ignoring"
								, name, tracked);
			return;
		}

		if (!read_int_strvec(strvec, 2, &weight, -254, 254, true)) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight %s for %s must be"
								  " between [-253..253] inclusive. Ignoring..."
								, name, strvec_slot(strvec, 2), tracked);
			weight = 0;
		}
		else if (weight == -254 || weight == 254) {
			/* This check can be removed once users have migrated away from +/-254 */
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight for %s cannot be +/-254."
								  " Setting to +/-253"
								, name, tracked);
			weight = weight == -254 ? -253 : 253;
		}

		if (vector_size(strvec) >= 4) {
			if (!strcmp(strvec_slot(strvec, 3), "reverse"))
				reverse = true;
			else
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track_interace %s"
									  " weight option %s - ignoring"
									, name, tracked, strvec_slot(strvec, 3));
		}
	}

	PMALLOC(tip);
	INIT_LIST_HEAD(&tip->e_list);
	tip->ifp    = ifp;
	tip->weight = weight;
	tip->weight_reverse = reverse;

	list_add_tail(&tip->e_list, l);
}

vrrp_script_t * __attribute__ ((pure))
find_script_by_name(const char *name)
{
	vrrp_script_t *scr;

	list_for_each_entry(scr, &vrrp_data->vrrp_script, e_list) {
		if (!strcmp(scr->sname, name))
			return scr;
	}

	return NULL;
}

/* Track script dump */
static void
dump_track_script(FILE *fp, const tracked_sc_t *tsc)
{
	conf_write(fp, "     %s weight %d%s", tsc->scr->sname, tsc->weight, tsc->weight_reverse ? " reverse" : "");
}
void
dump_track_script_list(FILE *fp, const list_head_t *l)
{
	tracked_sc_t *tsc;

	list_for_each_entry(tsc, l, e_list)
		dump_track_script(fp, tsc);
}
void
free_track_script(tracked_sc_t *tsc)
{
	list_del_init(&tsc->e_list);
	FREE(tsc);
}
void
free_track_script_list(list_head_t *l)
{
	tracked_sc_t *tsc, *tsc_tmp;

	list_for_each_entry_safe(tsc, tsc_tmp, l, e_list)
		free_track_script(tsc);
}

void
alloc_track_script(const char *name, list_head_t *l, const vector_t *strvec)
{
	vrrp_script_t *vsc;
	tracked_sc_t *tsc;
	int weight;
	const char *tracked = strvec_slot(strvec, 0);
	tracked_sc_t *etsc;
	bool reverse;

	vsc = find_script_by_name(tracked);

	/* Ignoring if no script found */
	if (!vsc) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) track script %s not found, ignoring..."
							, name, tracked);
		return;
	}

	/* Check this vrrp isn't already tracking the script */
	list_for_each_entry(etsc, l, e_list) {
		if (etsc->scr == vsc) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) duplicate track_script %s - ignoring"
								, name, tracked);
			return;
		}
	}

	/* default weight */
	weight = vsc->weight;
	reverse = vsc->weight_reverse;

	if (vector_size(strvec) >= 2) {
		if (strcmp(strvec_slot(strvec, 1), "weight")) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track script option %s - ignoring"
								, name, strvec_slot(strvec, 1));
			return;
		}

		if (vector_size(strvec) == 2) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight without value specified for"
								  " track script %s - ignoring"
								, name, tracked);
			return;
		}

		if (!read_int_strvec(strvec, 2, &weight, -254, 254, true)) {
			weight = vsc->weight;
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) track script %s: weight must be"
								  " between [-253..253] inclusive, ignoring..."
								, name, tracked);
		}
		else if (weight == -254 || weight == 254) {
			/* This check can be removed once users have migrated away from +/-254 */
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight for %s cannot be +/-254."
								  " Setting to +/-253"
								, name, tracked);
			weight = weight == -254 ? -253 : 253;
		}

		if (vector_size(strvec) >= 4) {
			if (!strcmp(strvec_slot(strvec, 3), "reverse"))
				reverse = true;
			else if (!strcmp(strvec_slot(strvec, 3), "noreverse"))
				reverse = false;
			else
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track_script %s"
									  " weight option %s - ignoring"
									, name, tracked, strvec_slot(strvec, 3));
		}
	}

	PMALLOC(tsc);
	INIT_LIST_HEAD(&tsc->e_list);
	tsc->scr    = vsc;
	tsc->weight = weight;
	tsc->weight_reverse = reverse;
	vsc->init_state = SCRIPT_INIT_STATE_INIT;
	list_add_tail(&tsc->e_list, l);
}

#ifdef _WITH_TRACK_PROCESS_
static vrrp_tracked_process_t * __attribute__ ((pure))
find_tracked_process_by_name(const char *name)
{
	vrrp_tracked_process_t *process;

	list_for_each_entry(process, &vrrp_data->vrrp_track_processes, e_list) {
		if (!strcmp(process->pname, name))
			return process;
	}
	return NULL;
}

/* Track process dump */
static void
dump_track_process(FILE *fp, const tracked_process_t *tprocess)
{
	conf_write(fp, "     %s, weight %d%s", tprocess->process->pname
					     , tprocess->weight, tprocess->weight_reverse ? " reverse" : "");
}
void
dump_track_process_list(FILE *fp, const list_head_t *l)
{
	tracked_process_t *tprocess;

	list_for_each_entry(tprocess, l, e_list)
		dump_track_process(fp, tprocess);
}

void
free_track_process_list(list_head_t *l)
{
	tracked_process_t *tprocess, *tprocess_tmp;

	list_for_each_entry_safe(tprocess, tprocess_tmp, l, e_list)
		FREE(tprocess);
}

void
alloc_track_process(const char *name, list_head_t *l, const vector_t *strvec)
{
	vrrp_tracked_process_t *vsp;
	const char *tracked = strvec_slot(strvec, 0);
	tracked_process_t *tprocess;
	int weight;
	bool reverse;

	vsp = find_tracked_process_by_name(tracked);

	/* Ignoring if no process found */
	if (!vsp) {
		if (proc_events_not_supported)
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) track process not supported by kernel"
								, name);
		else
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) track process %s not found, ignoring..."
								, name, tracked);
		return;
	}

	/* Check this vrrp isn't already tracking the process */
	list_for_each_entry(tprocess, l, e_list) {
		if (tprocess->process == vsp) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) duplicate track_process %s - ignoring"
								, name, tracked);
			return;
		}
	}

	weight = vsp->weight;
	reverse = vsp->weight_reverse;
	if (vector_size(strvec) >= 2) {
		if (strcmp(strvec_slot(strvec, 1), "weight")) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track process option %s - ignoring"
								, name, strvec_slot(strvec, 1));
			return;
		}

		if (vector_size(strvec) == 2) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight without value specified for"
								  " track process %s - ignoring"
								, name, tracked);
			return;
		}

		if (!read_int_strvec(strvec, 2, &weight, -254, 254, true)) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight for track process %s must be in "
								  "[-254..254] inclusive. Ignoring..."
								, name, tracked);
			weight = vsp->weight;
		}

		if (vector_size(strvec) >= 4) {
			if (!strcmp(strvec_slot(strvec, 3), "reverse"))
				reverse = true;
			else if (!strcmp(strvec_slot(strvec, 3), "noreverse"))
				reverse = false;
			else
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track_process %s weight"
									  " option %s - ignoring"
									, name, tracked, strvec_slot(strvec, 3));
		}
	}

	PMALLOC(tprocess);
	INIT_LIST_HEAD(&tprocess->e_list);
	tprocess->process = vsp;
	tprocess->weight = weight;
	tprocess->weight_reverse = reverse;
	list_add_tail(&tprocess->e_list, l);
}
#endif

#ifdef _WITH_BFD_
/* VRRP Track bfd related */
vrrp_tracked_bfd_t * __attribute__ ((pure))
find_vrrp_tracked_bfd_by_name(const char *name)
{
	vrrp_tracked_bfd_t *bfd;

	list_for_each_entry(bfd, &vrrp_data->vrrp_track_bfds, e_list) {
		if (!strcmp(bfd->bname, name))
			return bfd;
	}
	return NULL;
}

void
alloc_vrrp_tracked_bfd(const char *name, list_head_t *l)
{
	vrrp_tracked_bfd_t *tbfd;

	if (strlen(name) >= BFD_INAME_MAX) {
		report_config_error(CONFIG_GENERAL_ERROR, "BFD name %s too long", name);
		skip_block(true);
		return;
	}

	list_for_each_entry(tbfd, l, e_list) {
		if (!strcmp(name, tbfd->bname)) {
			report_config_error(CONFIG_GENERAL_ERROR, "BFD %s already specified", name);
			skip_block(true);
			return;
		}
	}

	PMALLOC(tbfd);
	INIT_LIST_HEAD(&tbfd->e_list);
	strncpy(tbfd->bname, name, BFD_INAME_MAX-1); /* Not really need, but... */
	tbfd->weight = 0;
	tbfd->weight_reverse = false;
	tbfd->bfd_up = false;
	INIT_LIST_HEAD(&tbfd->tracking_vrrp);
	list_add_tail(&tbfd->e_list, l);
}

/* Track bfd related */
static void
dump_tracked_bfd(FILE *fp, const tracked_bfd_t *tbfd)
{
	conf_write(fp, "     %s: weight %d%s", tbfd->bfd->bname, tbfd->weight, tbfd->weight_reverse ? " reverse" : "");
}
void
dump_tracked_bfd_list(FILE *fp, const list_head_t *l)
{
	tracked_bfd_t *tbfd;

	list_for_each_entry(tbfd, l, e_list)
		dump_tracked_bfd(fp, tbfd);
}

void
free_track_bfd(tracked_bfd_t *tbfd)
{
	list_del_init(&tbfd->e_list);
	FREE(tbfd);
}
void
free_track_bfd_list(list_head_t *l)
{
	tracked_bfd_t *tbfd, *tbfd_tmp;

	list_for_each_entry_safe(tbfd, tbfd_tmp, l, e_list)
		free_track_bfd(tbfd);
}

void
alloc_track_bfd(const char *name, list_head_t *l, const vector_t *strvec)
{
	vrrp_tracked_bfd_t *vtb;
	tracked_bfd_t *tbfd;
	const char *tracked = strvec_slot(strvec, 0);
	tracked_bfd_t *etbfd;
	int weight;
	bool reverse = false;

	vtb = find_vrrp_tracked_bfd_by_name(tracked);

	/* Ignoring if no bfd found */
	if (!vtb) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) track bfd %s not found, ignoring..."
							, name, tracked);
		return;
	}

	/* Check this vrrp isn't already tracking the bfd */
	list_for_each_entry(etbfd, l, e_list) {
		if (etbfd->bfd == vtb) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) duplicate track_bfd %s - ignoring"
								, name, tracked);
			return;
		}
	}

	weight = vtb->weight;
	reverse = vtb->weight_reverse;
	if (vector_size(strvec) >= 2) {
		if (strcmp(strvec_slot(strvec, 1), "weight")) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track bfd %s option %s - ignoring"
								, name, tracked, strvec_slot(strvec, 1));
			return;
		}

		if (vector_size(strvec) == 2) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight without value specified"
								  " for track bfd %s - ignoring"
								, name, tracked);
			return;
		}

		if (!read_int_strvec(strvec, 2, &weight, -253, 253, true)) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight for track bfd %s must be in "
								  "[-253..253] inclusive. Ignoring..."
								, name, tracked);
			weight = vtb->weight;
		}

		if (vector_size(strvec) >= 4) {
			if (!strcmp(strvec_slot(strvec, 3), "reverse"))
				reverse = true;
			else if (!strcmp(strvec_slot(strvec, 3), "noreverse"))
				reverse = false;
			else {
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track bfd %s weight"
									  " option %s - ignoring"
									, name, tracked, strvec_slot(strvec, 3));
				return;
			}
		}
	}

	PMALLOC(tbfd);
	INIT_LIST_HEAD(&tbfd->e_list);
	tbfd->bfd = vtb;
	tbfd->weight = weight;
	tbfd->weight_reverse = reverse;
	list_add_tail(&tbfd->e_list, l);
}
#endif

void
down_instance(vrrp_t *vrrp)
{
	if (vrrp->num_script_if_fault++ == 0 || vrrp->state == VRRP_STATE_INIT) {
		vrrp->wantstate = VRRP_STATE_FAULT;
		if (vrrp->state == VRRP_STATE_MAST)
			vrrp_state_leave_master(vrrp, true);
		else
			vrrp_state_leave_fault(vrrp);

		if (vrrp->sync && vrrp->sync->num_member_fault++ == 0)
			vrrp_sync_fault(vrrp);
	}
}

/* Set effective priorty, issue message on changes */
void
vrrp_set_effective_priority(vrrp_t *vrrp)
{
	uint8_t new_prio;
	uint32_t old_down_timer;

	/* Don't change priority if address owner */
	if (vrrp->base_priority == VRRP_PRIO_OWNER)
		return;

	if (vrrp->total_priority < 1)
		new_prio = 1;
	else if (vrrp->total_priority >= VRRP_PRIO_OWNER)
		new_prio = VRRP_PRIO_OWNER - 1;
	else
		new_prio = (uint8_t)vrrp->total_priority;

	if (vrrp->effective_priority == new_prio)
		return;

	log_message(LOG_INFO, "(%s) Changing effective priority from %d to %d",
		    vrrp->iname, vrrp->effective_priority, new_prio);

	vrrp->effective_priority = new_prio;
	old_down_timer = vrrp->ms_down_timer;
	vrrp->ms_down_timer = VRRP_MS_DOWN_TIMER(vrrp);

	if (vrrp->state == VRRP_STATE_BACK) {
		if (old_down_timer < vrrp->ms_down_timer)
			vrrp->sands = timer_add_long(vrrp->sands, vrrp->ms_down_timer - old_down_timer);
		else
			vrrp->sands = timer_sub_long(vrrp->sands, old_down_timer - vrrp->ms_down_timer);
		vrrp_thread_requeue_read(vrrp);
	}

	if (vrrp->notify_priority_changes)
		send_instance_priority_notifies(vrrp);
}

static void
process_script_update_priority(int weight, int multiplier, vrrp_script_t *vscript, bool script_ok, vrrp_t *vrrp)
{
	bool instance_left_init = false;

	if (!weight) {
		if (vscript->init_state == SCRIPT_INIT_STATE_INIT) {
			/* We need to adjust the number of scripts in init state */
			if (!--vrrp->num_script_init) {
				instance_left_init = true;
				if (vrrp->sync)
					vrrp->sync->num_member_init--;
			}
		}

		if (script_ok != (multiplier == 1)) {
			/* The instance needs to go down */
			down_instance(vrrp);
		} else if (!vrrp->num_script_init &&
			   (!vrrp->sync || !vrrp->sync->num_member_init)) {
			/* The instance can come up */
			try_up_instance(vrrp, instance_left_init);  // Set want_state = BACKUP/MASTER, and check i/fs and sync groups
		}
		return;
	}

	if (vscript->init_state == SCRIPT_INIT_STATE_INIT) {
		/* If the script hasn't previously exited, we need
		   to only adjust the priority if the state the script
		   is now in causes an adjustment to the priority */
		if (script_ok) {
			if (weight > 0)
				vrrp->total_priority += weight * multiplier;
		} else {
			if (weight < 0)
				vrrp->total_priority += weight * multiplier;
		}
	} else {
		if (script_ok)
			vrrp->total_priority += abs(weight) * multiplier;
		else
			vrrp->total_priority -= abs(weight) * multiplier;
	}

	vrrp_set_effective_priority(vrrp);
}

void
update_script_priorities(vrrp_script_t *vscript, bool script_ok)
{
	tracking_obj_t* top;
	vrrp_t *vrrp;

	/* First process the vrrp instances tracking the script */
	list_for_each_entry(top, &vscript->tracking_vrrp, e_list) {
		vrrp = top->obj.vrrp;
		process_script_update_priority(top->weight, top->weight_multiplier, vscript, script_ok, vrrp);
	}
}

static void
initialise_track_script_state(tracked_sc_t *tsc, vrrp_t *vrrp)
{
	if (!tsc->weight) {
		if (tsc->scr->init_state == SCRIPT_INIT_STATE_INIT)
			vrrp->num_script_init++;
		else if (tsc->scr->init_state == SCRIPT_INIT_STATE_FAILED ||
			 (tsc->scr->result >= 0 && tsc->scr->result < tsc->scr->rise)) {
			/* The script is in fault state */
			vrrp->num_script_if_fault++;
			log_message(LOG_INFO, "(%s): entering FAULT state due to script %s", vrrp->iname, tsc->scr->sname);
			vrrp->state = VRRP_STATE_FAULT;
		}
		return;
	}

	/* Don't change effective priority if address owner */
	if (vrrp->base_priority == VRRP_PRIO_OWNER)
		return;

	if (tsc->scr->init_state != SCRIPT_INIT_STATE_INIT)
	{
		if (tsc->scr->result >= tsc->scr->rise) {
			if (tsc->weight > 0)
				vrrp->total_priority += tsc->weight;
		} else {
			if (tsc->weight < 0)
				vrrp->total_priority += tsc->weight;
		}
	}
}

#ifdef _WITH_BFD_
static void
initialise_track_bfd_state(tracked_bfd_t *tbfd, vrrp_t *vrrp)
{
	int multiplier = tbfd->weight_reverse ? -1 : 1;

	if (tbfd->weight) {
		if (tbfd->bfd->bfd_up) {
			if (tbfd->weight > 0)
				vrrp->total_priority += tbfd->weight * multiplier;
		} else {
			if (tbfd->weight < 0)
				vrrp->total_priority += tbfd->weight * multiplier;
			else if (!tbfd->weight) {
				vrrp->num_script_if_fault++;
				vrrp->state = VRRP_STATE_FAULT;
			}
		}
	} else if (tbfd->bfd->bfd_up == tbfd->weight_reverse) {
		vrrp->num_script_if_fault++;
		vrrp->state = VRRP_STATE_FAULT;
	}
}
#endif

static void
initialise_interface_tracking_priorities(void)
{
	tracking_obj_t *top;
	vrrp_t *vrrp;
	interface_t *ifp;
	list_head_t *ifq;

	ifq = get_interface_queue();
	list_for_each_entry(ifp, ifq, e_list) {
		list_for_each_entry(top, &ifp->tracking_vrrp, e_list) {
			vrrp = top->obj.vrrp;
			if (top->weight == VRRP_NOT_TRACK_IF)
				continue;

			if (!top->weight) {
				if (IF_FLAGS_UP(ifp) != (top->weight_multiplier == 1)) {
					/* The instance is down */
					log_message(LOG_INFO, "(%s): entering FAULT state (interface %s down)", vrrp->iname, ifp->ifname);
					vrrp->state = VRRP_STATE_FAULT;
					vrrp->num_script_if_fault++;
				}
			} else if (IF_FLAGS_UP(ifp)) {
				if (top->weight > 0)
					vrrp->total_priority += top->weight * top->weight_multiplier;
			} else {
				if (top->weight < 0)
					vrrp->total_priority += top->weight * top->weight_multiplier;
			}
		}
	}
}

static void
initialise_vrrp_file_tracking_priorities(void)
{
	tracked_file_t *tfile;
	tracking_obj_t *top;
	vrrp_t *vrrp;
	int status;

	list_for_each_entry(tfile, &vrrp_data->vrrp_track_files, e_list) {
		list_for_each_entry(top, &tfile->tracking_obj, e_list) {
			vrrp = top->obj.vrrp;
			status = !top->weight ? (!!tfile->last_status == (top->weight_multiplier == 1) ? -254 : 0 ) : tfile->last_status * top->weight * top->weight_multiplier;

			if (status <= -254) {
				/* The instance is down */
				log_message(LOG_INFO, "(%s): entering FAULT state (tracked file %s has status %i)", vrrp->iname, tfile->fname, status);
				vrrp->state = VRRP_STATE_FAULT;
				vrrp->num_script_if_fault++;
			}
			else
				vrrp->total_priority += (status > 253 ? 253 : status);
		}
	}
}

#ifdef _WITH_TRACK_PROCESS_
static void
initialise_process_tracking_priorities(void)
{
	vrrp_tracked_process_t *tprocess;
	tracking_obj_t *top;
	vrrp_t *vrrp;

	list_for_each_entry(tprocess, &vrrp_data->vrrp_track_processes, e_list) {
		tprocess->have_quorum =
			(tprocess->num_cur_proc >= tprocess->quorum &&
			 tprocess->num_cur_proc <= tprocess->quorum_max);

		list_for_each_entry(top, &tprocess->tracking_vrrp, e_list) {
			vrrp = top->obj.vrrp;
			if (!top->weight) {
				if (tprocess->have_quorum != (top->weight_multiplier == 1)) {
					/* The instance is down */
					log_message(LOG_INFO, "(%s) entering FAULT state (tracked process %s"
							      " quorum not achieved)"
							    , vrrp->iname, tprocess->pname);
					vrrp->state = VRRP_STATE_FAULT;
					vrrp->num_script_if_fault++;
				}
			}
			else if (tprocess->have_quorum) {
				if (top->weight > 0)
					vrrp->total_priority += top->weight * top->weight_multiplier;
			}
			else {
				if (top->weight < 0)
					vrrp->total_priority += top->weight * top->weight_multiplier;
			}
		}
	}
}
#endif

static void
initialise_vrrp_tracking_priorities(vrrp_t *vrrp)
{
	tracked_sc_t *tsc;
#ifdef _WITH_BFD_
	tracked_bfd_t *tbfd;
#endif

	/* If no src address has been specified, and the interface doesn't have
	 * an appropriate address, put the interface into fault state */
	if (vrrp->saddr.ss_family == AF_UNSPEC) {
		/* The instance is down */
		log_message(LOG_INFO, "(%s) entering FAULT state (no IPv%d address for interface)"
				    , vrrp->iname, vrrp->family == AF_INET ? 4 : 6);
		vrrp->state = VRRP_STATE_FAULT;
		vrrp->num_script_if_fault++;
	}

	/* Initialise the vrrp instance's tracked scripts */
	list_for_each_entry(tsc, &vrrp->track_script, e_list)
		initialise_track_script_state(tsc, vrrp);

#ifdef _WITH_BFD_
	/* Initialise the vrrp instance's tracked scripts */
	list_for_each_entry(tbfd, &vrrp->track_bfd, e_list)
		initialise_track_bfd_state(tbfd, vrrp);
#endif

	/* If have a sync group, initialise it's tracked scripts and bfds */
	if (vrrp->sync) {
		list_for_each_entry(tsc, &vrrp->sync->track_script, e_list)
			initialise_track_script_state(tsc, vrrp);
#ifdef _WITH_BFD_
		list_for_each_entry(tbfd, &vrrp->sync->track_bfd, e_list)
			initialise_track_bfd_state(tbfd, vrrp);
#endif
	}

	vrrp_set_effective_priority(vrrp);
}

void
initialise_tracking_priorities(void)
{
	vrrp_t *vrrp;

	/* Check for instance down due to an interface */
	initialise_interface_tracking_priorities();

	initialise_vrrp_file_tracking_priorities();

#ifdef _WITH_TRACK_PROCESS_
	initialise_process_tracking_priorities();
#endif

	/* Now check for tracking scripts, files, bfd etc. */
	list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
		/* Set effective priority and fault state */
		initialise_vrrp_tracking_priorities(vrrp);

		if (vrrp->sync) {
			if (vrrp->state == VRRP_STATE_FAULT) {
				if (vrrp->sync->state != VRRP_STATE_FAULT) {
					vrrp->sync->state = VRRP_STATE_FAULT;
					log_message(LOG_INFO, "VRRP_Group(%s): Syncing %s to FAULT state"
							    , vrrp->sync->gname, vrrp->iname);
				}

				vrrp->sync->num_member_fault++;
			}
			if (vrrp->num_script_init) {
				/* Update init count on sync group if needed */
				vrrp->sync->num_member_init++;
				if (vrrp->sync->state != VRRP_STATE_FAULT)
					vrrp->sync->state = VRRP_STATE_INIT;
			}
		}
	}
}

#ifdef _WITH_TRACK_PROCESS_
void
process_update_track_process_status(vrrp_tracked_process_t *tprocess, bool now_up)
{
	tracking_obj_t *top;
	vrrp_t *vrrp;

	log_message(LOG_INFO, "Quorum %s for tracked process %s", now_up ? "gained" : "lost", tprocess->pname);

	list_for_each_entry(top, &tprocess->tracking_vrrp, e_list) {
		vrrp = top->obj.vrrp;
		if (!top->weight) {
			if (now_up == (top->weight_multiplier == 1))
				try_up_instance(vrrp, false);
			else
				down_instance(vrrp);
		}
		else if (vrrp->base_priority != VRRP_PRIO_OWNER) {
			if ((top->weight > 0) == now_up)
				vrrp->total_priority += top->weight * top->weight_multiplier;
			else
				vrrp->total_priority -= top->weight * top->weight_multiplier;
			vrrp_set_effective_priority(vrrp);
		}
	}
}
#endif
