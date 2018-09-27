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
