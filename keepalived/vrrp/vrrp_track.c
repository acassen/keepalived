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
#include <sys/stat.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>

/* local include */
#include "vrrp_data.h"
#include "vrrp.h"
#include "vrrp_track.h"
#include "vrrp_sync.h"
#include "logger.h"
#include "memory.h"
#include "vrrp_scheduler.h"
#include "scheduler.h"
#include "parser.h"
#include "utils.h"
#include "vrrp_notify.h"
#include "bitops.h"
#ifdef _WITH_CN_PROC_
#include "track_process.h"
#endif

static int inotify_fd = -1;
static thread_ref_t inotify_thread;

/* Track interface dump */
void
dump_track_if(FILE *fp, const void *track_data)
{
	const tracked_if_t *tip = track_data;
	conf_write(fp, "     %s weight %d%s", IF_NAME(tip->ifp), tip->weight, tip->weight_reverse ? " reverse" : "");
}

void
free_track_if(void *tip)
{
	FREE(tip);
}

void
alloc_track_if(const char *name, list track_ifp, const vector_t *strvec)
{
	interface_t *ifp;
	tracked_if_t *tip;
	int weight = 0;
	const char *tracked = strvec_slot(strvec, 0);
	element e;
	bool reverse = false;

	ifp = if_get_by_ifname(tracked, IF_CREATE_IF_DYNAMIC);

	if (!ifp) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) tracked interface %s doesn't exist", name, tracked);
		return;
	}

	/* Check this vrrp isn't already tracking the i/f */
	LIST_FOREACH(track_ifp, tip, e) {
		if (tip->ifp == ifp) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) duplicate track_interface %s - ignoring", name, tracked);
			return;
		}
	}

	if (vector_size(strvec) >= 2) {
		if (strcmp(strvec_slot(strvec, 1), "weight")) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track_interface %s option %s - ignoring",
					 name, tracked, strvec_slot(strvec, 1));
			return;
		}

		if (vector_size(strvec) == 2) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight without value specified for track_interface %s - ignoring",
					name, tracked);
			return;
		}

		if (!read_int_strvec(strvec, 2, &weight, -254, 254, true)) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight %s for %s must be between "
					 "[-253..253] inclusive. Ignoring...", name, strvec_slot(strvec, 2), tracked);
			weight = 0;
		}
		else if (weight == -254 || weight == 254) {
			/* This check can be removed once users have migrated away from +/-254 */
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight for %s cannot be +/-254. Setting to +/-253", name, tracked);
			weight = weight == -254 ? -253 : 253;
		}

		if (vector_size(strvec) >= 4) {
			if (!strcmp(strvec_slot(strvec, 3), "reverse"))
				reverse = true;
			else
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track_interace %s weight option %s - ignoring",
						name, tracked, strvec_slot(strvec, 3));
		}
	}

	tip	    = (tracked_if_t *) MALLOC(sizeof(tracked_if_t));
	tip->ifp    = ifp;
	tip->weight = weight;
	tip->weight_reverse = reverse;

	list_add(track_ifp, tip);
}

vrrp_script_t * __attribute__ ((pure))
find_script_by_name(const char *name)
{
	element e;
	vrrp_script_t *scr;

	if (LIST_ISEMPTY(vrrp_data->vrrp_script))
		return NULL;

	LIST_FOREACH(vrrp_data->vrrp_script, scr, e) {
		if (!strcmp(scr->sname, name))
			return scr;
	}
	return NULL;
}

/* Track script dump */
void
dump_track_script(FILE *fp, const void *track_data)
{
	const tracked_sc_t *tsc = track_data;
	conf_write(fp, "     %s weight %d%s", tsc->scr->sname, tsc->weight, tsc->weight_reverse ? " reverse" : "");
}

void
free_track_script(void *tsc)
{
	FREE(tsc);
}

void
alloc_track_script(const char *name, list track_script, const vector_t *strvec)
{
	vrrp_script_t *vsc;
	tracked_sc_t *tsc;
	int weight;
	const char *tracked = strvec_slot(strvec, 0);
	tracked_sc_t *etsc;
	element e;
	bool reverse;

	vsc = find_script_by_name(tracked);

	/* Ignoring if no script found */
	if (!vsc) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) track script %s not found, ignoring...", name, tracked);
		return;
	}

	/* Check this vrrp isn't already tracking the script */
	LIST_FOREACH(track_script, etsc, e) {
		if (etsc->scr == vsc) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) duplicate track_script %s - ignoring", name, tracked);
			return;
		}
	}

	/* default weight */
	weight = vsc->weight;
	reverse = vsc->weight_reverse;

	if (vector_size(strvec) >= 2) {
		if (strcmp(strvec_slot(strvec, 1), "weight")) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track script option %s - ignoring",
					 name, strvec_slot(strvec, 1));
			return;
		}

		if (vector_size(strvec) == 2) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight without value specified for track script %s - ignoring",
					name, tracked);
			return;
		}

		if (!read_int_strvec(strvec, 2, &weight, -254, 254, true)) {
			weight = vsc->weight;
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) track script %s: weight must be between [-253..253]"
					 " inclusive, ignoring...", name, tracked);
		}
		else if (weight == -254 || weight == 254) {
			/* This check can be removed once users have migrated away from +/-254 */
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight for %s cannot be +/-254. Setting to +/-253", name, tracked);
			weight = weight == -254 ? -253 : 253;
		}

		if (vector_size(strvec) >= 4) {
			if (!strcmp(strvec_slot(strvec, 3), "reverse"))
				reverse = true;
			else if (!strcmp(strvec_slot(strvec, 3), "noreverse"))
				reverse = false;
			else
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track_script %s weight option %s - ignoring",
						name, tracked, strvec_slot(strvec, 3));
		}
	}

	tsc	    = (tracked_sc_t *) MALLOC(sizeof(tracked_sc_t));
	tsc->scr    = vsc;
	tsc->weight = weight;
	tsc->weight_reverse = reverse;
	vsc->init_state = SCRIPT_INIT_STATE_INIT;
	list_add(track_script, tsc);
}

static vrrp_tracked_file_t * __attribute__ ((pure))
find_tracked_file_by_name(const char *name)
{
	element e;
	vrrp_tracked_file_t *file;

	if (LIST_ISEMPTY(vrrp_data->vrrp_track_files))
		return NULL;

	for (e = LIST_HEAD(vrrp_data->vrrp_track_files); e; ELEMENT_NEXT(e)) {
		file = ELEMENT_DATA(e);
		if (!strcmp(file->fname, name))
			return file;
	}
	return NULL;
}

/* Track file dump */
void
dump_track_file(FILE *fp, const void *track_data)
{
	const tracked_file_t *tfile = track_data;
	conf_write(fp, "     %s, weight %d%s", tfile->file->fname, tfile->weight, tfile->weight_reverse ? " reverse" : "");
}

void
free_track_file(void *tsf)
{
	FREE(tsf);
}

void
alloc_track_file(const char *name, list track_file, const vector_t *strvec)
{
	vrrp_tracked_file_t *vsf;
	tracked_file_t *tfile;
	const char *tracked = strvec_slot(strvec, 0);
	tracked_file_t *etfile;
	element e;
	int weight;
	bool reverse;

	vsf = find_tracked_file_by_name(tracked);

	/* Ignoring if no file found */
	if (!vsf) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) track file %s not found, ignoring...", name, tracked);
		return;
	}

	if (!LIST_ISEMPTY(track_file)) {
		/* Check this vrrp isn't already tracking the script */
		LIST_FOREACH(track_file, etfile, e) {
			if (etfile->file == vsf) {
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) duplicate track_file %s - ignoring", name, tracked);
				return;
			}
		}
	}

	weight = vsf->weight;
	reverse = vsf->weight_reverse;
	if (vector_size(strvec) >= 2) {
		if (strcmp(strvec_slot(strvec, 1), "weight")) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track file option %s - ignoring",
					 name, strvec_slot(strvec, 1));
			return;
		}

		if (vector_size(strvec) == 2) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight without value specified for track file %s - ignoring",
					name, tracked);
			return;
		}

		if (!read_int_strvec(strvec, 2, &weight, -254, 254, true)) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight for track file %s must be in "
					 "[-254..254] inclusive. Ignoring...", name, tracked);
			weight = vsf->weight;
		}

		if (vector_size(strvec) >= 4) {
			if (!strcmp(strvec_slot(strvec, 3), "reverse"))
				reverse = true;
			else if (!strcmp(strvec_slot(strvec, 3), "noreverse"))
				reverse = false;
			else {
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track file %s weight option %s - ignoring",
						 name, tracked, strvec_slot(strvec, 3));
				return;
			}
		}
	}

	tfile = (tracked_file_t *) MALLOC(sizeof(tracked_file_t));
	tfile->file = vsf;
	tfile->weight = weight;
	tfile->weight_reverse = reverse;
	list_add(track_file, tfile);
}

#ifdef _WITH_CN_PROC_
static vrrp_tracked_process_t * __attribute__ ((pure))
find_tracked_process_by_name(const char *name)
{
	element e;
	vrrp_tracked_process_t *process;

	if (LIST_ISEMPTY(vrrp_data->vrrp_track_processes))
		return NULL;

	LIST_FOREACH(vrrp_data->vrrp_track_processes, process, e) {
		if (!strcmp(process->pname, name))
			return process;
	}
	return NULL;
}

/* Track process dump */
void
dump_track_process(FILE *fp, const void *track_data)
{
	const tracked_process_t *tprocess = track_data;
	conf_write(fp, "     %s, weight %d%s", tprocess->process->pname, tprocess->weight, tprocess->weight_reverse ? " reverse" : "");
}

void
free_track_process(void *tsf)
{
	FREE(tsf);
}

void
alloc_track_process(const char *name, list track_process, const vector_t *strvec)
{
	vrrp_tracked_process_t *vsp;
	tracked_process_t *tprocess;
	const char *tracked = strvec_slot(strvec, 0);
	tracked_process_t *etprocess;
	element e;
	int weight;
	bool reverse;

	vsp = find_tracked_process_by_name(tracked);

	/* Ignoring if no process found */
	if (!vsp) {
		if (proc_events_not_supported)
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) track process not supported by kernel", name);
		else
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) track process %s not found, ignoring...", name, tracked);
		return;
	}

	/* Check this vrrp isn't already tracking the process */
	LIST_FOREACH(track_process, etprocess, e) {
		if (etprocess->process == vsp) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) duplicate track_process %s - ignoring", name, tracked);
			return;
		}
	}

	weight = vsp->weight;
	reverse = vsp->weight_reverse;
	if (vector_size(strvec) >= 2) {
		if (strcmp(strvec_slot(strvec, 1), "weight")) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track process option %s - ignoring",
					 name, strvec_slot(strvec, 1));
			return;
		}

		if (vector_size(strvec) == 2) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight without value specified for track process %s - ignoring",
					name, tracked);
			return;
		}

		if (!read_int_strvec(strvec, 2, &weight, -254, 254, true)) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight for track process %s must be in "
					 "[-254..254] inclusive. Ignoring...", name, tracked);
			weight = vsp->weight;
		}

		if (vector_size(strvec) >= 4) {
			if (!strcmp(strvec_slot(strvec, 3), "reverse"))
				reverse = true;
			else if (!strcmp(strvec_slot(strvec, 3), "noreverse"))
				reverse = false;
			else
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track_process %s weight option %s - ignoring",
						name, tracked, strvec_slot(strvec, 3));
		}
	}

	tprocess = (tracked_process_t *) MALLOC(sizeof(tracked_process_t));
	tprocess->process = vsp;
	tprocess->weight = weight;
	tprocess->weight_reverse = reverse;
	list_add(track_process, tprocess);
}
#endif

#ifdef _WITH_BFD_
vrrp_tracked_bfd_t * __attribute__ ((pure))
find_vrrp_tracked_bfd_by_name(const char *name)
{
	element e;
	vrrp_tracked_bfd_t *bfd;

	LIST_FOREACH(vrrp_data->vrrp_track_bfds, bfd, e) {
		if (!strcmp(bfd->bname, name))
			return bfd;
	}
	return NULL;
}

/* Track bfd dump */
void
dump_vrrp_tracked_bfd(FILE *fp, const void *track_data)
{
	const tracked_bfd_t *tbfd = track_data;
	conf_write(fp, "     %s: weight %d%s", tbfd->bfd->bname, tbfd->weight, tbfd->weight_reverse ? " reverse" : "");
}

void
free_vrrp_tracked_bfd(void *bfd)
{
	FREE(bfd);
}

void
alloc_track_bfd(const char *name, list track_bfd, const vector_t *strvec)
{
	vrrp_tracked_bfd_t *vtb;
	tracked_bfd_t *tbfd;
	const char *tracked = strvec_slot(strvec, 0);
	tracked_bfd_t *etbfd;
	element e;
	int weight;
	bool reverse = false;

	vtb = find_vrrp_tracked_bfd_by_name(tracked);

	/* Ignoring if no bfd found */
	if (!vtb) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) track bfd %s not found, ignoring...", name, tracked);
		return;
	}

	/* Check this vrrp isn't already tracking the bfd */
	LIST_FOREACH(track_bfd, etbfd, e) {
		if (etbfd->bfd == vtb) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) duplicate track_bfd %s - ignoring", name, tracked);
			return;
		}
	}

	weight = vtb->weight;
	reverse = vtb->weight_reverse;
	if (vector_size(strvec) >= 2) {
		if (strcmp(strvec_slot(strvec, 1), "weight")) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track bfd %s option %s - ignoring",
					 name, tracked, strvec_slot(strvec, 1));
			return;
		}

		if (vector_size(strvec) == 2) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight without value specified for track bfd %s - ignoring",
					name, tracked);
			return;
		}

		if (!read_int_strvec(strvec, 2, &weight, -253, 253, true)) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight for track bfd %s must be in "
					 "[-253..253] inclusive. Ignoring...", name, tracked);
			weight = vtb->weight;
		}

		if (vector_size(strvec) >= 4) {
			if (!strcmp(strvec_slot(strvec, 3), "reverse"))
				reverse = true;
			else if (!strcmp(strvec_slot(strvec, 3), "noreverse"))
				reverse = false;
			else {
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track bfd %s weight option %s - ignoring",
						 name, tracked, strvec_slot(strvec, 3));
				return;
			}
		}
	}

	tbfd = (tracked_bfd_t *) MALLOC(sizeof(tracked_bfd_t));
	tbfd->bfd = vtb;
	tbfd->weight = weight;
	tbfd->weight_reverse = reverse;
	list_add(track_bfd, tbfd);
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
	vrrp->ms_down_timer = 3 * vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);

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
	element e;
	vrrp_t *vrrp;
	tracking_vrrp_t* tvp;

	/* First process the vrrp instances tracking the script */
	if (!LIST_ISEMPTY(vscript->tracking_vrrp)) {
		LIST_FOREACH(vscript->tracking_vrrp, tvp, e) {
			vrrp = tvp->vrrp;

			process_script_update_priority(tvp->weight, tvp->weight_multiplier, vscript, script_ok, vrrp);
		}
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
	tracking_vrrp_t *tvp;
	interface_t *ifp;
	element e, e1;

	LIST_FOREACH(get_if_list(), ifp, e) {
		LIST_FOREACH(ifp->tracking_vrrp, tvp, e1) {
			if (tvp->weight == VRRP_NOT_TRACK_IF)
				continue;

			if (!tvp->weight) {
				if (IF_FLAGS_UP(ifp) != (tvp->weight_multiplier == 1)) {
					/* The instance is down */
					log_message(LOG_INFO, "(%s): entering FAULT state (interface %s down)", tvp->vrrp->iname, ifp->ifname);
					tvp->vrrp->state = VRRP_STATE_FAULT;
					tvp->vrrp->num_script_if_fault++;
				}
			} else if (IF_FLAGS_UP(ifp)) {
				if (tvp->weight > 0)
					tvp->vrrp->total_priority += tvp->weight * tvp->weight_multiplier;
			} else {
				if (tvp->weight < 0)
					tvp->vrrp->total_priority += tvp->weight * tvp->weight_multiplier;
			}
		}
	}
}

static void
initialise_file_tracking_priorities(void)
{
	vrrp_tracked_file_t *tfile;
	tracking_vrrp_t *tvp;
	int status;
	element e, e1;

	LIST_FOREACH(vrrp_data->vrrp_track_files, tfile, e) {
		LIST_FOREACH(tfile->tracking_vrrp, tvp, e1) {
			status = !tvp->weight ? (!!tfile->last_status == (tvp->weight_multiplier == 1) ? -254 : 0 ) : tfile->last_status * tvp->weight * tvp->weight_multiplier;

			if (status <= -254) {
				/* The instance is down */
				log_message(LOG_INFO, "(%s): entering FAULT state (tracked file %s has status %i)", tvp->vrrp->iname, tfile->fname, status);
				tvp->vrrp->state = VRRP_STATE_FAULT;
				tvp->vrrp->num_script_if_fault++;
			}
			else
				tvp->vrrp->total_priority += (status > 253 ? 253 : status);
		}
	}
}

#ifdef _WITH_CN_PROC_
static void
initialise_process_tracking_priorities(void)
{
	vrrp_tracked_process_t *tprocess;
	tracking_vrrp_t *tvp;
	element e, e1;

	LIST_FOREACH(vrrp_data->vrrp_track_processes, tprocess, e) {
		tprocess->have_quorum =
			(tprocess->num_cur_proc >= tprocess->quorum &&
			 tprocess->num_cur_proc <= tprocess->quorum_max);

		LIST_FOREACH(tprocess->tracking_vrrp, tvp, e1) {
			if (!tvp->weight) {
				if (tprocess->have_quorum != (tvp->weight_multiplier == 1)) {
					/* The instance is down */
					log_message(LOG_INFO, "(%s) entering FAULT state (tracked process %s quorum not achieved)", tvp->vrrp->iname, tprocess->pname);
					tvp->vrrp->state = VRRP_STATE_FAULT;
					tvp->vrrp->num_script_if_fault++;
				}
			}
			else if (tprocess->have_quorum) {
				if (tvp->weight > 0)
					tvp->vrrp->total_priority += tvp->weight * tvp->weight_multiplier;
			}
			else {
				if (tvp->weight < 0)
					tvp->vrrp->total_priority += tvp->weight * tvp->weight_multiplier;
			}
		}
	}
}
#endif

static void
initialise_vrrp_tracking_priorities(vrrp_t *vrrp)
{
	element e;
	tracked_sc_t *tsc;
#ifdef _WITH_BFD_
	tracked_bfd_t *tbfd;
#endif

	/* If no src address has been specified, and the interface doesn't have
	 * an appropriate address, put the interface into fault state */
	if (vrrp->saddr.ss_family == AF_UNSPEC) {
		/* The instance is down */
		log_message(LOG_INFO, "(%s) entering FAULT state (no IPv%d address for interface)", vrrp->iname, vrrp->family == AF_INET ? 4 : 6);
		vrrp->state = VRRP_STATE_FAULT;
		vrrp->num_script_if_fault++;
	}

	/* Initialise the vrrp instance's tracked scripts */
	LIST_FOREACH(vrrp->track_script, tsc, e)
		initialise_track_script_state(tsc, vrrp);

#ifdef _WITH_BFD_
	/* Initialise the vrrp instance's tracked scripts */
	LIST_FOREACH(vrrp->track_bfd, tbfd, e)
		initialise_track_bfd_state(tbfd, vrrp);
#endif

	/* If have a sync group, initialise it's tracked scripts and bfds */
	if (vrrp->sync) {
		LIST_FOREACH(vrrp->sync->track_script, tsc, e)
			initialise_track_script_state(tsc, vrrp);
	}

	vrrp_set_effective_priority(vrrp);
}

void
initialise_tracking_priorities(void)
{
	vrrp_t *vrrp;
	element e;

	/* Check for instance down due to an interface */
	initialise_interface_tracking_priorities();

	initialise_file_tracking_priorities();

#ifdef _WITH_CN_PROC_
	initialise_process_tracking_priorities();
#endif

	/* Now check for tracking scripts, files, bfd etc. */
	LIST_FOREACH(vrrp_data->vrrp, vrrp, e) {
		/* Set effective priority and fault state */
		initialise_vrrp_tracking_priorities(vrrp);

		if (vrrp->sync) {
			if (vrrp->state == VRRP_STATE_FAULT) {
				if (vrrp->sync->state != VRRP_STATE_FAULT) {
					vrrp->sync->state = VRRP_STATE_FAULT;
					log_message(LOG_INFO, "VRRP_Group(%s): Syncing %s to FAULT state", vrrp->sync->gname, vrrp->iname);
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

static void
remove_track_file(list track_files, element e)
{
	vrrp_tracked_file_t *tfile = ELEMENT_DATA(e);
	element e1;
	element e2, next2;
	tracking_vrrp_t *tvp;
	tracked_file_t *tft;

	/* Search through the vrrp instances tracking this file */
	LIST_FOREACH(tfile->tracking_vrrp, tvp, e1) {
		/* Search for the matching track file */
		LIST_FOREACH_NEXT(tvp->vrrp->track_file, tft, e2, next2) {
			if (tft->file == tfile)
				free_list_element(tvp->vrrp->track_file, e2);
		}
	}

	free_list_element(track_files, e);
}

static void
process_update_track_file_status(vrrp_tracked_file_t *tfile, int new_status, tracking_vrrp_t *tvp)
{
	int previous_status;

	previous_status = !tvp->weight ? (!!tfile->last_status == (tvp->weight_multiplier == 1) ? -254 : 0 ) : tfile->last_status * tvp->weight * tvp->weight_multiplier;
	if (previous_status < -254)
		previous_status = -254;
	else if (previous_status > 253)
		previous_status = 253;

	if (previous_status == new_status)
		return;

	if (new_status == -254) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "(%s): tracked file %s now FAULT state", tvp->vrrp->iname, tfile->fname);
		down_instance(tvp->vrrp);
	} else if (previous_status == -254) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "(%s): tracked file %s leaving FAULT state", tvp->vrrp->iname, tfile->fname);
		try_up_instance(tvp->vrrp, false);
	} else if (tvp->vrrp->base_priority != VRRP_PRIO_OWNER) {
		tvp->vrrp->total_priority += new_status - previous_status;
		vrrp_set_effective_priority(tvp->vrrp);
	}
}

static void
update_track_file_status(vrrp_tracked_file_t* tfile, int new_status)
{
	element e;
	tracking_vrrp_t *tvp;
	int status;

	if (new_status == tfile->last_status)
		return;

	/* Process the VRRP instances tracking the file */
	LIST_FOREACH(tfile->tracking_vrrp, tvp, e) {
		/* If the tracking weight is 0, a non-zero value means
		 * failure, a 0 status means success */
		if (!tvp->weight)
			status = !!new_status == (tvp->weight_multiplier == 1) ? -254 : 0;
		else {
			status = new_status * tvp->weight * tvp->weight_multiplier;
			if (status < -254)
				status = -254;
			else if (status > 253)
				status = 253;
		}

		process_update_track_file_status(tfile, status, tvp);
	}
}

static void
process_track_file(vrrp_tracked_file_t *tfile, bool init)
{
	long new_status = 0;
	char buf[128];
	int fd;
	ssize_t len;

	if ((fd = open(tfile->file_path, O_RDONLY | O_NONBLOCK)) != -1) {
		if ((len = read(fd, buf, sizeof(buf) - 1)) > 0) {
			buf[len] = '\0';
			/* If there is an error, we want to use 0,
			 * so we don't really mind if there is an error */
			new_status = strtol(buf, NULL, 0);
		}
		close(fd);
	}

	if (new_status > 254)
		new_status = 254;
	else if (new_status < -254)
		new_status = -254;

	if (!init)
		update_track_file_status(tfile, (int)new_status);

	tfile->last_status = new_status;
}

static int
process_inotify(thread_ref_t thread)
{
	char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
	char *buf_ptr;
	ssize_t len;
	struct inotify_event* event;
	vrrp_tracked_file_t *tfile;
	element e;
	int fd = thread->u.f.fd;

	inotify_thread = thread_add_read(master, process_inotify, NULL, fd, TIMER_NEVER, false);

	while (true) {
		if ((len = read(fd, buf, sizeof(buf))) < (ssize_t)sizeof(struct inotify_event)) {
			if (len == -1) {
				if (check_EAGAIN(errno))
					return 0;

				if (check_EINTR(errno))
					continue;

				log_message(LOG_INFO, "inotify read() returned error %d - %m", errno);
				return 0;
			}

			log_message(LOG_INFO, "inotify read() returned short length %zd", len);
			return 0;
		}

		/* Try and keep coverity happy. It thinks event->name is not null
		 * terminated in the strcmp() below */
		buf[sizeof(buf) - 1] = 0;

		/* The following line causes a strict-overflow=4 warning on gcc 5.4.0 */
		for (buf_ptr = buf; buf_ptr < buf + len; buf_ptr += event->len + sizeof(struct inotify_event)) {
			event = (struct inotify_event*)buf_ptr;

			/* We are not interested in directories */
			if (event->mask & IN_ISDIR)
				continue;

			if (!(event->mask & (IN_DELETE | IN_CLOSE_WRITE | IN_MOVE))) {
				log_message(LOG_INFO, "Unknown inotify event 0x%x", event->mask);
				continue;
			}

			LIST_FOREACH(vrrp_data->vrrp_track_files, tfile, e) {
				/* Is this event for our file */
				if (tfile->wd != event->wd ||
				    strcmp(tfile->file_part, event->name))
					continue;

				if (event->mask & (IN_MOVED_FROM | IN_DELETE)) {
					/* The file has disappeared. Treat as though the value is 0 */
					update_track_file_status(tfile, 0);
				}
				else {	/* event->mask & (IN_MOVED_TO | IN_CLOSE_WRITE) */
					/* The file has been writted/moved in */
					process_track_file(tfile, false);
				}
			}
		}
	}

	/* NOT REACHED */
}

void
init_track_files(list track_files)
{
	vrrp_tracked_file_t *tfile;
	char *resolved_path;
	char *dir_end = NULL;
	char *new_path;
	struct stat stat_buf;
	element e, next;

	inotify_fd = -1;

	if (LIST_ISEMPTY(track_files))
		return;

#ifdef HAVE_INOTIFY_INIT1
	inotify_fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
#else
	inotify_fd = inotify_init();
	if (inotify_fd != -1) {
		fcntl(inotify_fd, F_SETFD, FD_CLOEXEC);
		fcntl(inotify_fd, F_SETFL, O_NONBLOCK);
	}
#endif

	if (inotify_fd == -1) {
		log_message(LOG_INFO, "Unable to monitor vrrp track files");
		return ;
	}

	LIST_FOREACH_NEXT(track_files, tfile, e, next) {
		if (LIST_ISEMPTY(tfile->tracking_vrrp)) {
			/* No vrrp instance is tracking this file, so forget it */
			report_config_error(CONFIG_GENERAL_ERROR, "Track file %s is not being used - removing", tfile->fname);
			remove_track_file(track_files, e);
			continue;
		}

		resolved_path = realpath(tfile->file_path, NULL);
		if (resolved_path) {
			if (strcmp(tfile->file_path, resolved_path)) {
				FREE_CONST(tfile->file_path);
				tfile->file_path = STRDUP(resolved_path);
			}

			/* The file exists, so read it now */
			process_track_file(tfile, true);
		}
		else if (errno == ENOENT) {
			/* Resolve the directory */
			if (!(dir_end = strrchr(tfile->file_path, '/')))
				resolved_path = realpath(".", NULL);
			else {
				*dir_end = '\0';
				resolved_path = realpath(tfile->file_path, NULL);

				/* Check it is a directory */
				if (resolved_path &&
				    (stat(resolved_path, &stat_buf) ||
				     !S_ISDIR(stat_buf.st_mode))) {
					free(resolved_path);
					resolved_path = NULL;
				}
			}

			if (!resolved_path) {
				report_config_error(CONFIG_GENERAL_ERROR, "Track file directory for %s does not exist - removing", tfile->fname);
				remove_track_file(track_files, e);

				continue;
			}

			if (strcmp(tfile->file_path, resolved_path)) {
				new_path = MALLOC(strlen(resolved_path) + strlen((!dir_end) ? tfile->file_path : dir_end + 1) + 2);
				strcpy(new_path, resolved_path);
				strcat(new_path, "/");
				strcat(new_path, dir_end ? dir_end + 1 : tfile->file_path);
				FREE_CONST(tfile->file_path);
				tfile->file_path = new_path;
			}
			else if (dir_end)
				*dir_end = '/';
		}
		else {
			report_config_error(CONFIG_GENERAL_ERROR, "track file %s is not accessible - ignoring", tfile->fname);
			remove_track_file(track_files, e);

			continue;
		}

		if (resolved_path)
			free(resolved_path);

		tfile->file_part = strrchr(tfile->file_path, '/') + 1;
		new_path = STRNDUP(tfile->file_path, tfile->file_part - tfile->file_path);
		tfile->wd = inotify_add_watch(inotify_fd, new_path, IN_CLOSE_WRITE | IN_DELETE | IN_MOVE);
		FREE(new_path);
	}

	inotify_thread = thread_add_read(master, process_inotify, NULL, inotify_fd, TIMER_NEVER, false);
}

void
stop_track_files(void)
{
	if (inotify_thread) {
		thread_cancel(inotify_thread);
		inotify_thread = NULL;
	}

	if (inotify_fd != -1) {
		close(inotify_fd);
		inotify_fd = -1;
	}
}

#ifdef _WITH_CN_PROC_
void
process_update_track_process_status(vrrp_tracked_process_t *tprocess, bool now_up)
{
	tracking_vrrp_t *tvp;
	element e;

	log_message(LOG_INFO, "Quorum %s for tracked process %s", now_up ? "gained" : "lost", tprocess->pname);

	LIST_FOREACH(tprocess->tracking_vrrp, tvp, e) {
		if (!tvp->weight) {
			if (now_up == (tvp->weight_multiplier == 1))
				try_up_instance(tvp->vrrp, false);
			else
				down_instance(tvp->vrrp);
		}
		else if (tvp->vrrp->base_priority != VRRP_PRIO_OWNER) {
			if ((tvp->weight > 0) == now_up)
				tvp->vrrp->total_priority += tvp->weight * tvp->weight_multiplier;
			else
				tvp->vrrp->total_priority -= tvp->weight * tvp->weight_multiplier;
			vrrp_set_effective_priority(tvp->vrrp);
		}
	}
}
#endif

#ifdef THREAD_DUMP
void
register_vrrp_inotify_addresses(void)
{
	register_thread_address("process_inotify", process_inotify);
}
#endif
