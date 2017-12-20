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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

/* local include */
#include "vrrp_index.h"
#include "vrrp_data.h"
#include "vrrp.h"

/* VRID hash table */
int
get_vrrp_hash(const int vrid, const int fd)
{
	/* The values 31 and 37 are somewhat arbitrary, but need to be prime and
	 * coprime to VRRP_INDEX_FD_SIZE. They are chosen as being reasonably close
	 * to the square root of VRRP_INDEX_FD_SIZE. VRRP_INDEX_FD_SIZE should
	 * ideally be prime too.
	 * The reason that fd is divided by 2 is that each vrrp instance uses two
	 * sockets, and so the difference between the fds of consecutive vrrp
	 * instances is likely to be 2. */
	return (vrid * 31 + (fd/2) * 37) % VRRP_INDEX_FD_SIZE;
}

void
alloc_vrrp_bucket(vrrp_t *vrrp)
{
	list_add(&vrrp_data->vrrp_index[get_vrrp_hash(vrrp->vrid, vrrp->sockets->fd_in)], vrrp);
}

vrrp_t *
vrrp_index_lookup(const int vrid, const int fd)
{
	vrrp_t *vrrp;
	element e;
	list l = &vrrp_data->vrrp_index[get_vrrp_hash(vrid, fd)];

	/* return if list is empty */
	if (LIST_ISEMPTY(l))
		return NULL;

	/*
	 * If list size's is 1 then no collisions. So
	 * Test and return the singleton.
	 */
	if (LIST_SIZE(l) == 1) {
		vrrp = ELEMENT_DATA(LIST_HEAD(l));
		return (vrrp->sockets->fd_in == fd && vrrp->vrid == vrid) ? vrrp : NULL;
	}

	/*
	 * List collision on the vrid bucket. The same
	 * vrid is used on a different interface or different
	 * address family. We perform a fd lookup as collision solver.
	 */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp =  ELEMENT_DATA(e);
		if (vrrp->sockets->fd_in == fd && vrrp->vrid == vrid)
			return vrrp;
	}

	/* No match */
	return NULL;
}

/* FD hash table */
void
alloc_vrrp_fd_bucket(vrrp_t *vrrp)
{
	/* We use a mod key */
	list_add(&vrrp_data->vrrp_index_fd[FD_INDEX_HASH(vrrp->sockets->fd_in)], vrrp);
}

void remove_vrrp_fd_bucket(int old_fd)
{
	vrrp_t *vrrp_ptr;
	element e;
	element next;
	list l = &vrrp_data->vrrp_index_fd[FD_INDEX_HASH(old_fd)];

	for (e = LIST_HEAD(l); e; e = next) {
		next = e->next;
		vrrp_ptr = ELEMENT_DATA(e);
		if (vrrp_ptr->sockets->fd_in == old_fd) {
			if (e->prev)
				e->prev->next = e->next;
			else
				l->head = e->next;

			if (e->next)
				e->next->prev = e->prev;
			else
				l->tail = e->prev;
			l->count--;
			FREE(e);
		}
	}
	if (LIST_ISEMPTY(l))
		l->head = l->tail = NULL;
}

#ifdef _INCLUDE_UNUSED_CODE_
void set_vrrp_fd_bucket(int old_fd, vrrp_t *vrrp)
{
	vrrp_t *vrrp_ptr;
	element e;
	element next;
	list l = &vrrp_data->vrrp_index_fd[FD_INDEX_HASH(old_fd)];

	/* Release old stalled entries */
	remove_vrrp_fd_bucket(old_fd);

	/* Hash refreshed entries */
	l = vrrp_data->vrrp;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp_ptr = ELEMENT_DATA(e);

		if (vrrp_ptr->sockets->fd_in == old_fd) {
			/* Update new hash */
			vrrp_ptr->sockets->fd_in = vrrp->sockets->fd_in;
			vrrp_ptr->sockets->fd_out = vrrp->sockets->fd_out;
			alloc_vrrp_fd_bucket(vrrp_ptr);
		}
	}
}
#endif
