/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Interface tracking framework.
 *
 * Version:     $Id: vrrp_track.c,v 1.1.10 2005/02/15 01:15:22 acassen Exp $
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
 * Copyright (C) 2001-2005 Alexandre Cassen, <acassen@linux-vs.org>
 */

/* local include */
#include "vrrp_track.h"
#include "vrrp_if.h"
#include "vrrp_data.h"
#include "memory.h"

/* Track interface dump */
void
dump_track(void *track_data_obj)
{
	interface *ifp = track_data_obj;
	syslog(LOG_INFO, "     %s", IF_NAME(ifp));
}
void
alloc_track(list track_list, vector strvec)
{
	interface *ifp = NULL;
	char *tracked = VECTOR_SLOT(strvec, 0);

	ifp = if_get_by_ifname(tracked);

	/* Ignoring if no interface found */
	if (!ifp) {
		syslog(LOG_INFO, "     %s no match, ignoring...", tracked);
		return;
	}

	list_add(track_list, ifp);
}

/* Test if all tracked interfaces are UP */
int
vrrp_tracked_up(list l)
{
	element e;
	interface *ifp;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		ifp = ELEMENT_DATA(e);
		if (!IF_ISUP(ifp))
			return 0;
	}

	return 1;
}

/* Log tracked interface down */
void
vrrp_log_tracked_down(list l)
{
	element e;
	interface *ifp;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		ifp = ELEMENT_DATA(e);
		if (!IF_ISUP(ifp))
			syslog(LOG_INFO, "Kernel is reporting: interface %s DOWN",
			       IF_NAME(ifp));
	}
}
