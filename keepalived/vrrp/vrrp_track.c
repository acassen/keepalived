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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

/* local include */
#include "vrrp_track.h"
#include "vrrp_if.h"
#include "vrrp_data.h"
#include "logger.h"
#include "memory.h"

/* Track interface dump */
void
dump_track(void *track_data)
{
	tracked_if *tip = track_data;
	log_message(LOG_INFO, "     %s weight %d", IF_NAME(tip->ifp), tip->weight);
}
void
alloc_track(list track_list, vector strvec)
{
	interface *ifp = NULL;
	tracked_if *tip = NULL;
	int weight = 0;
	char *tracked = VECTOR_SLOT(strvec, 0);

	ifp = if_get_by_ifname(tracked);

	/* Ignoring if no interface found */
	if (!ifp) {
		log_message(LOG_INFO, "     %s no match, ignoring...", tracked);
		return;
	}

	if (VECTOR_SIZE(strvec) >= 3 &&
	    !strcmp(VECTOR_SLOT(strvec, 1), "weight")) {
		weight = atoi(VECTOR_SLOT(strvec, 2));
		if (weight < -254 || weight > 254) {
			log_message(LOG_INFO, "     %s: weight must be between "
					 "[-254..254] inclusive. Ignoring...", tracked);
			weight = 0;
		}
	}

	tip         = (tracked_if *) MALLOC(sizeof (tracked_if));
	tip->ifp    = ifp;
	tip->weight = weight;

	list_add(track_list, tip);
}

vrrp_script *
find_script_by_name(char *name)
{
	element e;
	vrrp_script *scr;

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
	tracked_sc *tsc = track_data;
	log_message(LOG_INFO, "     %s weight %d", tsc->scr->sname, tsc->weight);
}
void
alloc_track_script(list track_list, vector strvec)
{
	vrrp_script *vsc = NULL;
	tracked_sc *tsc = NULL;
	int weight = 0;
	char *tracked = VECTOR_SLOT(strvec, 0);

	vsc = find_script_by_name(tracked);

	/* Ignoring if no interface found */
	if (!vsc) {
		log_message(LOG_INFO, "     %s no match, ignoring...", tracked);
		return;
	}

	/* default weight */
	weight = vsc->weight;

	if (VECTOR_SIZE(strvec) >= 3 &&
	    !strcmp(VECTOR_SLOT(strvec, 1), "weight")) {
		weight = atoi(VECTOR_SLOT(strvec, 2));
		if (weight < -254 || weight > 254) {
			weight = vsc->weight;
			log_message(LOG_INFO, "     %s: weight must be between [-254..254]"
				         " inclusive, ignoring...",
			       tracked);
		}
	}

	tsc         = (tracked_sc *) MALLOC(sizeof (tracked_sc));
	tsc->scr    = vsc;
	tsc->weight = weight;
	vsc->inuse++;
	list_add(track_list, tsc);
}

/* Test if all tracked interfaces are either UP or weight-tracked */
int
vrrp_tracked_up(list l)
{
	element e;
	tracked_if *tip;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		tip = ELEMENT_DATA(e);
		if (!tip->weight && !IF_ISUP(tip->ifp))
			return 0;
	}

	return 1;
}

/* Log tracked interface down */
void
vrrp_log_tracked_down(list l)
{
	element e;
	tracked_if *tip;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		tip = ELEMENT_DATA(e);
		if (!IF_ISUP(tip->ifp))
			log_message(LOG_INFO, "Kernel is reporting: interface %s DOWN",
			       IF_NAME(tip->ifp));
	}
}

/* Returns total weights of all tracked interfaces :
 * - a positive interface weight adds to the global weight when the
 *   interface is UP.
 * - a negative interface weight subtracts from the global weight when the
 *   interface is DOWN.
 *
 */
int
vrrp_tracked_weight(list l)
{
	element e;
	tracked_if *tip;
	int weight = 0;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		tip = ELEMENT_DATA(e);
		if (IF_ISUP(tip->ifp)) {
			if (tip->weight > 0)
				weight += tip->weight;
		} else {
			if (tip->weight < 0)
				weight += tip->weight;
		}
	}

	return weight;
}

/* Test if all tracked scripts are either OK or weight-tracked */
int
vrrp_script_up(list l)
{
	element e;
	tracked_sc *tsc;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		tsc = ELEMENT_DATA(e);
		if ((tsc->scr->result == VRRP_SCRIPT_STATUS_DISABLED) ||
		    (tsc->scr->result == VRRP_SCRIPT_STATUS_INIT_GOOD))
			continue;
		if (!tsc->weight && tsc->scr->result < tsc->scr->rise)
			return 0;
	}

	return 1;
}

/* Returns total weights of all tracked scripts :
 * - a positive weight adds to the global weight when the result is OK
 * - a negative weight subtracts from the global weight when the result is bad
 *
 */
int
vrrp_script_weight(list l)
{
	element e;
	tracked_sc *tsc;
	int weight = 0;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		tsc = ELEMENT_DATA(e);
		if (tsc->scr->result == VRRP_SCRIPT_STATUS_DISABLED)
			continue;
		if (tsc->scr->result >= tsc->scr->rise) {
			if (tsc->weight > 0)
				weight += tsc->weight;
		} else if (tsc->scr->result < tsc->scr->rise) {
			if (tsc->weight < 0)
				weight += tsc->weight;
		}
	}

	return weight;
}
