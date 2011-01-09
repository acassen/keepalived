/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        VRRP instance index table.
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
#include "vrrp_index.h"
#include "vrrp_data.h"
#include "vrrp.h"
#include "memory.h"
#include "list.h"

/* VRID hash table */
void
alloc_vrrp_bucket(vrrp_rt *vrrp)
{
	list_add(&vrrp_data->vrrp_index[vrrp->vrid], vrrp);
}

vrrp_rt *
vrrp_index_lookup(const int vrid, const int fd)
{
	vrrp_rt *vrrp;
	element e;
	list l = &vrrp_data->vrrp_index[vrid];

	/* return if list is empty */
	if (LIST_ISEMPTY(l))
		return NULL;

	/*
	 * If list size's is 1 then no collisions. So
	 * Test and return the singleton.
	 */
	if (LIST_SIZE(l) == 1) {
		vrrp = ELEMENT_DATA(LIST_HEAD(l));
		return (vrrp->fd_in == fd) ? vrrp : NULL;
	}

	/*
	 * List collision on the vrid bucket. The same
	 * vrid is used on a different interface. We perform
	 * a fd lookup as collisions solver.
	 */ 
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp =  ELEMENT_DATA(e);
		if (vrrp->fd_in == fd)
			return vrrp;
	}

	/* No match */
	return NULL;
}

/* FD hash table */
void
alloc_vrrp_fd_bucket(vrrp_rt *vrrp)
{
	/* We use a mod key plus 1 */
	list_add(&vrrp_data->vrrp_index_fd[vrrp->fd_in%1024 + 1], vrrp);
}

void
remove_vrrp_fd_bucket(vrrp_rt *vrrp)
{
	list l = &vrrp_data->vrrp_index_fd[vrrp->fd_in%1024 + 1];
	list_del(l, vrrp);
}

void set_vrrp_fd_bucket(int old_fd, vrrp_rt *vrrp)
{
	vrrp_rt *vrrp_ptr;
	element e;
	list l = &vrrp_data->vrrp_index_fd[old_fd%1024 + 1];

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp_ptr =  ELEMENT_DATA(e);
		if (IF_INDEX(vrrp_ptr->ifp) == IF_INDEX(vrrp->ifp)) {
			vrrp_ptr->fd_in = vrrp->fd_in;
			vrrp_ptr->fd_out = vrrp->fd_out;
		}
	}
}
