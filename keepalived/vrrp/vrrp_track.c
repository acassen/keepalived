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

#include <net/if.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>

/* local include */
#include "vrrp_track.h"
#include "vrrp_data.h"
#include "vrrp.h"
#include "vrrp_sync.h"
#include "logger.h"
#include "memory.h"
#include "vrrp_scheduler.h"
#include "scheduler.h"

/* Track interface dump */
void
dump_track_if(void *track_data)
{
	tracked_if_t *tip = track_data;
	log_message(LOG_INFO, "     %s weight %d", IF_NAME(tip->ifp), tip->weight);
}

void
free_track_if(void *tip)
{
	FREE(tip);
}

void
alloc_track_if(vrrp_t *vrrp, vector_t *strvec)
{
	interface_t *ifp = NULL;
	tracked_if_t *tip = NULL;
	int weight = 0;
	char *tracked = strvec_slot(strvec, 0);
	element e;

	ifp = if_get_by_ifname(tracked, IF_CREATE_IF_DYNAMIC);

	if (!ifp) {
		log_message(LOG_INFO, "(%s) tracked interface %s doesn't exist", vrrp->iname, tracked);
		return;
	}

	if (!LIST_ISEMPTY(vrrp->track_ifp)) {
		/* Check this vrrp isn't already tracking the i/f */
		for (e = LIST_HEAD(vrrp->track_ifp); e; ELEMENT_NEXT(e)) {
			tip = ELEMENT_DATA(e);
			if (tip->ifp == ifp) {
				log_message(LOG_INFO, "(%s) duplicate track_interface %s - ignoring", vrrp->iname, tracked);
				return;
			}
		}
	}

	if (vector_size(strvec) >= 3 &&
	    !strcmp(strvec_slot(strvec, 1), "weight")) {
		weight = atoi(strvec_slot(strvec, 2));
		if (weight == -254 || weight == 254) {
			/* This check can be removed once users have migrated away from +/-254 */
			log_message(LOG_INFO, "(%s) weight for %s cannot be +/-254. Setting to +/-253", vrrp->iname, tracked);
			weight = weight == -254 ? -253 : 253;
		}
		else if (weight < -253 || weight > 253) {
			log_message(LOG_INFO, "(%s) weight for %s must be between "
					 "[-253..253] inclusive. Ignoring...", vrrp->iname, tracked);
			weight = 0;
		}
	}

	tip	    = (tracked_if_t *) MALLOC(sizeof(tracked_if_t));
	tip->ifp    = ifp;
	tip->weight = weight;

	list_add(vrrp->track_ifp, tip);
}

void
alloc_group_track_if(vrrp_sgroup_t *sgroup, vector_t *strvec)
{
	interface_t *ifp;
	tracked_if_t *tip;
	int weight = 0;
	char *tracked = strvec_slot(strvec, 0);
	element e;

	ifp = if_get_by_ifname(tracked, IF_CREATE_IF_DYNAMIC);

	if (!ifp) {
		log_message(LOG_INFO, "(%s) tracked interface %s doesn't exist", sgroup->gname, tracked);
		return;
	}
	else if (!LIST_ISEMPTY(sgroup->track_ifp)) {
		/* Check this sgroup isn't already tracking the i/f */
		for (e = LIST_HEAD(sgroup->track_ifp); e; ELEMENT_NEXT(e)) {
			tip = ELEMENT_DATA(e);
			if (tip->ifp == ifp) {
				log_message(LOG_INFO, "(%s) duplicate track_interface %s - ignoring", sgroup->gname, tracked);
				return;
			}
		}
	}

	if (vector_size(strvec) >= 3 &&
	    !strcmp(strvec_slot(strvec, 1), "weight")) {
		weight = atoi(strvec_slot(strvec, 2));
		if (weight == -254 || weight == 254) {
			/* This check can be removed once users have migrated away from +/-254 */
			log_message(LOG_INFO, "(%s) weight for %s cannot be +/-254. Setting to +/-253", sgroup->gname, tracked);
			weight = weight == -254 ? -253 : 253;
		}
		else if (weight < -253 || weight > 253) {
			log_message(LOG_INFO, "(%s) weight for %s must be between "
					 "[-253..253] inclusive. Ignoring...", sgroup->gname, tracked);
			weight = 0;
		}
	}

	tip	    = (tracked_if_t *) MALLOC(sizeof(tracked_if_t));
	tip->ifp    = ifp;
	tip->weight = weight;

	list_add(sgroup->track_ifp, tip);
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
	vrrp_script_t *vsc;
	tracked_sc_t *tsc;
	int weight;
	char *tracked = strvec_slot(strvec, 0);
	element e;
	tracked_sc_t *etsc;

	vsc = find_script_by_name(tracked);

	/* Ignoring if no script found */
	if (!vsc) {
		log_message(LOG_INFO, "(%s) track script %s not found, ignoring...", vrrp->iname, tracked);
		return;
	}

	if (!LIST_ISEMPTY(vrrp->track_script)) {
		/* Check this vrrp isn't already tracking the script */
		for (e = LIST_HEAD(vrrp->track_script); e; ELEMENT_NEXT(e)) {
			etsc = ELEMENT_DATA(e);
			if (etsc->scr == vsc) {
				log_message(LOG_INFO, "(%s) duplicate track_script %s - ignoring", vrrp->iname, tracked);
				return;
			}
		}
	}

	/* default weight */
	weight = vsc->weight;

	if (vector_size(strvec) >= 3 &&
	    !strcmp(strvec_slot(strvec, 1), "weight")) {
		weight = atoi(strvec_slot(strvec, 2));
		if (weight == -254 || weight == 254) {
			/* This check can be removed once users have migrated away from +/-254 */
			log_message(LOG_INFO, "(%s) weight for %s cannot be +/-254. Setting to +/-253", vrrp->iname, tracked);
			weight = weight == -254 ? -253 : 253;
		}
		else if (weight < -253 || weight > 253) {
			weight = vsc->weight;
			log_message(LOG_INFO, "(%s) track script %s: weight must be between [-253..253]"
					 " inclusive, ignoring...",
			       vrrp->iname, tracked);
		}
	}

	tsc	    = (tracked_sc_t *) MALLOC(sizeof(tracked_sc_t));
	tsc->scr    = vsc;
	tsc->weight = weight;
	vsc->init_state = SCRIPT_INIT_STATE_INIT;
	list_add(vrrp->track_script, tsc);
}

void
alloc_group_track_script(vrrp_sgroup_t *sgroup, vector_t *strvec)
{
	vrrp_script_t *vsc = NULL;
	tracked_sc_t *tsc = NULL;
	int weight = 0;
	char *tracked = strvec_slot(strvec, 0);
	tracked_sc_t *etsc = NULL;
	element e;

	vsc = find_script_by_name(tracked);

	/* Ignoring if no script found */
	if (!vsc) {
		log_message(LOG_INFO, "(%s) track script %s not found, ignoring...", sgroup->gname, tracked);
		return;
	}

	if (!LIST_ISEMPTY(sgroup->track_script)) {
		/* Check this sync group isn't already tracking the script */
		for (e = LIST_HEAD(sgroup->track_script); e; ELEMENT_NEXT(e)) {
			etsc = ELEMENT_DATA(e);
			if (etsc->scr == vsc) {
				log_message(LOG_INFO, "(%s) duplicate track_script %s - ignoring", sgroup->gname, tracked);
				return;
			}
		}
	}

	/* default weight */
	weight = vsc->weight;

	if (vector_size(strvec) >= 3 &&
	    !strcmp(strvec_slot(strvec, 1), "weight")) {
		weight = atoi(strvec_slot(strvec, 2));
		if (weight == -254 || weight == 254) {
			/* This check can be removed once users have migrated away from +/-254 */
			log_message(LOG_INFO, "(%s) weight for %s cannot be +/-254. Setting to +/-253", sgroup->gname, tracked);
			weight = weight == -254 ? -253 : 253;
		}
		else if (weight < -253 || weight > 253) {
			weight = vsc->weight;
			log_message(LOG_INFO, "(%s) track script %s: weight must be between [-253..253]"
					 " inclusive, ignoring...",
			       sgroup->gname, tracked);
		}
	}

	tsc	    = (tracked_sc_t *) MALLOC(sizeof(tracked_sc_t));
	tsc->scr    = vsc;
	tsc->weight = weight;
	vsc->init_state = SCRIPT_INIT_STATE_INIT;
	list_add(sgroup->track_script, tsc);
}

vrrp_tracked_file_t *
find_tracked_file_by_name(char *name)
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
dump_track_file(void *track_data)
{
	tracked_file_t *tfile = track_data;
	log_message(LOG_INFO, "     %s", tfile->file->fname);
}

void
free_track_file(void *tsf)
{
	FREE(tsf);
}

void
alloc_track_file(vrrp_t *vrrp, vector_t *strvec)
{
	vrrp_tracked_file_t *vsf;
	tracked_file_t *tfile;
	char *tracked = strvec_slot(strvec, 0);
	tracked_file_t *etfile;
	element e;
	int weight;

	vsf = find_tracked_file_by_name(tracked);

	/* Ignoring if no file found */
	if (!vsf) {
		log_message(LOG_INFO, "(%s) track file %s not found, ignoring...", vrrp->iname, tracked);
		return;
	}

	if (!LIST_ISEMPTY(vrrp->track_file)) {
		/* Check this vrrp isn't already tracking the script */
		for (e = LIST_HEAD(vrrp->track_file); e; ELEMENT_NEXT(e)) {
			etfile = ELEMENT_DATA(e);
			if (etfile->file == vsf) {
				log_message(LOG_INFO, "(%s) duplicate track_file %s - ignoring", vrrp->iname, tracked);
				return;
			}
		}
	}

	weight = vsf->weight;
	if (vector_size(strvec) >= 2) {
		if (strcmp(strvec_slot(strvec, 1), "weight")) {
			log_message(LOG_INFO, "(%s) unknown track file option %s - ignoring",
					 vrrp->iname, FMT_STR_VSLOT(strvec, 1));
			return;
		}
		if (vector_size(strvec) >= 3) {
			weight = atoi(strvec_slot(strvec, 2));
			if (weight < -254 || weight > 254) {
				log_message(LOG_INFO, "(%s) weight for track file %s must be in "
						 "[-254..254] inclusive. Ignoring...", vrrp->iname, tracked);
				weight = vsf->weight;
			}
		} else {
			log_message(LOG_INFO, "(%s) weight without value specified for track file %s - ignoring",
					vrrp->iname, tracked);
			return;
		}
	}

	tfile = (tracked_file_t *) MALLOC(sizeof(tracked_file_t));
	tfile->file = vsf;
	tfile->weight = weight;
	list_add(vrrp->track_file, tfile);
}

void
alloc_group_track_file(vrrp_sgroup_t *sgroup, vector_t *strvec)
{
	vrrp_tracked_file_t *vsf;
	tracked_file_t *tfile;
	char *tracked = strvec_slot(strvec, 0);
	tracked_file_t *etfile;
	element e;
	int weight;

	vsf = find_tracked_file_by_name(tracked);

	/* Ignoring if no file found */
	if (!vsf) {
		log_message(LOG_INFO, "(%s) track file %s not found, ignoring...", sgroup->gname, tracked);
		return;
	}

	if (!LIST_ISEMPTY(sgroup->track_file)) {
		/* Check this vrrp isn't already tracking the script */
		for (e = LIST_HEAD(sgroup->track_file); e; ELEMENT_NEXT(e)) {
			etfile = ELEMENT_DATA(e);
			if (etfile->file == vsf) {
				log_message(LOG_INFO, "(%s) duplicate track_file %s - ignoring", sgroup->gname, tracked);
				return;
			}
		}
	}

	weight = vsf->weight;
	if (vector_size(strvec) >= 2) {
		if (strcmp(strvec_slot(strvec, 1), "weight")) {
			log_message(LOG_INFO, "(%s) unknown track file option %s - ignoring",
					 sgroup->gname, FMT_STR_VSLOT(strvec, 1));
			return;
		}
		if (vector_size(strvec) >= 3) {
			weight = atoi(strvec_slot(strvec, 2));
			if (weight < -254 || weight > 254) {
				log_message(LOG_INFO, "(%s) weight for track file %s must be in "
						 "[-254..254] inclusive. Ignoring...", sgroup->gname, tracked);
				weight = vsf->weight;
			}
		} else {
			log_message(LOG_INFO, "(%s) weight without value specified for track file %s - ignoring",
					sgroup->gname, tracked);
			return;
		}
	}

	tfile = (tracked_file_t *) MALLOC(sizeof(tracked_file_t));
	tfile->file = vsf;
	tfile->weight = weight;
	list_add(sgroup->track_file, tfile);
}

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
	bool increasing_priority;
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

	increasing_priority = (new_prio > vrrp->effective_priority);

	vrrp->effective_priority = new_prio;
	old_down_timer = vrrp->ms_down_timer;
	vrrp->ms_down_timer = 3 * vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);

	if (vrrp->state == VRRP_STATE_BACK && increasing_priority)
		vrrp_thread_requeue_read_relative(vrrp, old_down_timer - vrrp->ms_down_timer);
}

static void
process_script_update_priority(int weight, vrrp_script_t *vscript, bool script_ok, vrrp_t *vrrp)
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

		if (!script_ok) {
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
				vrrp->total_priority += weight;
		} else {
			if (weight < 0)
				vrrp->total_priority += weight;
		}
	} else {
		if (script_ok)
			vrrp->total_priority += abs(weight);
		else
			vrrp->total_priority -= abs(weight);
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
		for (e = LIST_HEAD(vscript->tracking_vrrp); e; ELEMENT_NEXT(e)) {
			tvp = ELEMENT_DATA(e);
			vrrp = tvp->vrrp;

			process_script_update_priority(tvp->weight, vscript, script_ok, vrrp);
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
			vrrp->state = VRRP_STATE_FAULT;
		}
		return;
	}

	/* Don't change effective priority if address owner */
	if (vrrp->base_priority == VRRP_PRIO_OWNER)
		return;

//	if (tsc->scr->last_status != VRRP_SCRIPT_STATUS_NOT_SET)
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

void
initialise_tracking_priorities(vrrp_t *vrrp)
{
	element e;
	tracked_if_t *tip;
	tracked_sc_t *tsc;

	/* If no src address has been specified, and the interface doesn't have
	 * an appropriate address, put the interface into fault state */
	if (vrrp->saddr.ss_family == AF_UNSPEC) {
		vrrp->num_script_if_fault++;
		vrrp->state = VRRP_STATE_FAULT;
	}

	if (!LIST_ISEMPTY(vrrp->track_ifp)) {
		for (e = LIST_HEAD(vrrp->track_ifp); e; ELEMENT_NEXT(e)) {
			tip = ELEMENT_DATA(e);

			if (tip->weight == VRRP_NOT_TRACK_IF)
				continue;

			if (!tip->weight) {
				if (!IF_ISUP(tip->ifp)) {
					/* The instance is down */
					vrrp->state = VRRP_STATE_FAULT;
					vrrp->num_script_if_fault++;
				}
				continue;
			}

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

	/* Initialise the vrrp instance's tracked scripts */
	if (!LIST_ISEMPTY(vrrp->track_script)) {
		for (e = LIST_HEAD(vrrp->track_script); e; ELEMENT_NEXT(e)) {
			tsc = ELEMENT_DATA(e);

			initialise_track_script_state(tsc, vrrp);
		}
	}

	/* If have a sync group, initialise it's tracked scripts */
	if (vrrp->sync && !LIST_ISEMPTY(vrrp->sync->track_script)) {
		for (e = LIST_HEAD(vrrp->sync->track_script); e; ELEMENT_NEXT(e)) {
			tsc = ELEMENT_DATA(e);

			initialise_track_script_state(tsc, vrrp);
		}
	}

	vrrp_set_effective_priority(vrrp);
}

static void
remove_track_file(list track_files, element e)
{
	vrrp_tracked_file_t *tfile = ELEMENT_DATA(e);
	element e1;
	element e2, next2;
	vrrp_t *vrrp;
	tracked_file_t *tft;

	if (!LIST_ISEMPTY(tfile->tracking_vrrp)) {
		/* Seach through the vrrp instances tracking this file */
		for (e1 = LIST_HEAD(tfile->tracking_vrrp); e1; ELEMENT_NEXT(e1)) {
			vrrp = ELEMENT_DATA(e1);

			/* Search for the matching track file */
			for (e2 = LIST_HEAD(vrrp->track_file); e2; e2 = next2) {
				next2 = e2->next;
				tft = ELEMENT_DATA(e2);
				if (tft->file == tfile)
					free_list_element(vrrp->track_file, e2);
			}
		}
	}
	free_list_element(track_files, e);
}

static void
process_update_track_file_status(vrrp_tracked_file_t *tfile, int new_status, tracking_vrrp_t *tvp)
{
	int previous_status;

	previous_status = tfile->last_status * tvp->weight;
	if (previous_status < -254)
		previous_status = -254;
	else if (previous_status > 253)
		previous_status = 253;

	if (previous_status == new_status)
		return;

	if (new_status == -254) {
		down_instance(tvp->vrrp);
		tvp->vrrp->total_priority += new_status - previous_status;
	} else {
		if (previous_status == -254)
			try_up_instance(tvp->vrrp, false);

		if (tvp->vrrp->base_priority != VRRP_PRIO_OWNER) {
			tvp->vrrp->total_priority += new_status - previous_status;
			vrrp_set_effective_priority(tvp->vrrp);
		}
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
	for (e = LIST_HEAD(tfile->tracking_vrrp); e;  ELEMENT_NEXT(e)) {
		tvp = ELEMENT_DATA(e);

		/* If the tracking weight is 0, a non-zero value means
		 * failure, a 0 status means success */
		if (!tvp->weight)
			status = new_status ? -254 : 0;
		else {
			status = new_status * tvp->weight;
			if (status < -254)
				status = -254;
			else if (status > 253)
				status = 253;
		}

		process_update_track_file_status(tfile, status, tvp);
	}

	tfile->last_status = new_status;
}

static void
process_track_file(vrrp_tracked_file_t *tfile)
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

	update_track_file_status(tfile, (int)new_status);
}

static void
process_inotify(int fd)
{
	char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
	char *buf_ptr;
	ssize_t len;
	struct inotify_event* event;
	vrrp_tracked_file_t *tfile;
	element e;

	while (true) {
		if ((len = read(fd, buf, sizeof(buf))) < (ssize_t)sizeof(struct inotify_event)) {
			if (len == -1) {
				if (errno == EAGAIN)
					return;

				if (errno == EINTR)
					continue;

				log_message(LOG_INFO, "inotify read() returned error %d - %m", errno);
				return;
			}

			log_message(LOG_INFO, "inotify read() returned short length %zd", len);
			return;
		}

		for (buf_ptr = buf; buf_ptr < buf + len; buf_ptr += event->len + sizeof(struct inotify_event)) {
			event = (struct inotify_event*)buf_ptr;

			/* We are not interested in directories */
			if (event->mask & IN_ISDIR)
				continue;

			if (!(event->mask & (IN_DELETE | IN_CLOSE_WRITE | IN_MOVE))) {
				log_message(LOG_INFO, "Unknown inotify event 0x%x", event->mask);
				continue;
			}

			for (e = LIST_HEAD(vrrp_data->vrrp_track_files); e; ELEMENT_NEXT(e)) {
				tfile = ELEMENT_DATA(e);

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
					process_track_file(tfile);
				}
			}
		}
	}
}

void
init_track_files(list track_files)
{
	vrrp_tracked_file_t *tfile;
	char *resolved_path;
	char *dir_end = NULL;
	char *new_path;
	struct stat stat_buf;
	char sav_ch;
	element e, next;

	inotify_fd = -1;

	if (LIST_ISEMPTY(track_files))
		return;

	set_process_track_inotify(&process_inotify);

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

	for (e = LIST_HEAD(track_files); e; e = next) {
		next = e->next;
		tfile = ELEMENT_DATA(e);

		if (!tfile->tracking_vrrp) {
			/* No vrrp instance is tracking this file, so forget it */
			log_message(LOG_INFO, "Track file %s is not being used - removing", tfile->fname);
			remove_track_file(track_files, e);
			continue;
		}

		resolved_path = realpath(tfile->file_path, NULL);
		if (resolved_path) {
			if (strcmp(tfile->file_path, resolved_path)) {
				FREE(tfile->file_path);
				tfile->file_path = MALLOC(strlen(resolved_path + 1));
				strcpy(tfile->file_path, resolved_path);
			}

			/* The file exists, so read it now */
			process_track_file(tfile);
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
				log_message(LOG_INFO, "Track file directory for %s does not exist - removing", tfile->fname);
				remove_track_file(track_files, e);

				continue;
			}

			if (strcmp(tfile->file_path, resolved_path)) {
				new_path = MALLOC(strlen(resolved_path) + strlen((!dir_end) ? tfile->file_path : dir_end + 1) + 2);
				strcpy(new_path, resolved_path);
				strcat(new_path, "/");
				strcat(new_path, dir_end ? dir_end + 1 : tfile->file_path);
				FREE(tfile->file_path);
				tfile->file_path = new_path;
			}
			else if (dir_end)
				*dir_end = '/';
		}
		else {
			log_message(LOG_INFO, "track file %s is not accessible - ignoring", tfile->fname);
			remove_track_file(track_files, e);

			continue;
		}

		if (resolved_path)
			free(resolved_path);

		tfile->file_part = strrchr(tfile->file_path, '/') + 1;
		sav_ch = *tfile->file_part;
		*tfile->file_part = '\0';
		tfile->wd = inotify_add_watch(inotify_fd, tfile->file_path, IN_CLOSE_WRITE | IN_DELETE | IN_MOVE);
		*tfile->file_part = sav_ch;
	}
}

void
stop_track_files(void)
{
	close(inotify_fd);
	inotify_fd = -1;
}
