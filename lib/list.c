/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        List structure manipulation.
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

#include <stdio.h>

#include "list.h"
#include "memory.h"

/* Multiple list helpers functions */
list
alloc_mlist_r(void (*free_func) (void *), void (*dump_func) (FILE *, const void *), size_t size)
{
	list new = (list) MALLOC(size * sizeof (struct _list));
	new->free = free_func;
	new->dump = dump_func;
	return new;
}

#ifdef _VRRP_FD_DEBUG_
void
dump_mlist(FILE *fp, list l, size_t size)
{
	element e;
	unsigned i;

	for (i = 0; i < size; i++) {
		for (e = LIST_HEAD(&l[i]); e; ELEMENT_NEXT(e))
			if (l->dump)
				(*l->dump) (fp, e->data);
	}
}
#endif

static void
free_melement(list l, void (*free_func) (void *))
{
	element e;
	element next;

	for (e = LIST_HEAD(l); e; e = next) {
		next = e->next;
		if (free_func)
			(*free_func) (e->data);
		FREE(e);
	}
}

void
free_mlist_r(list l, size_t size)
{
	size_t i;

	if (!l)
		return;

	for (i = 0; i < size; i++)
		free_melement(&l[i], l->free);
	FREE(l);
}

/* Simple list helpers functions */
list
alloc_list_r(void (*free_func) (void *), void (*dump_func) (FILE *fp, const void *))
{
	return alloc_mlist_r(free_func, dump_func, 1);
}

static element __attribute__ ((malloc))
alloc_element(void)
{
	return (element) MALLOC(sizeof (struct _element));
}

static inline void
__list_add(list l, element e)
{
	e->prev = l->tail;
	e->next = NULL;

	if (l->head == NULL)
		l->head = e;
	else
		l->tail->next = e;
	l->tail = e;
	l->count++;
}

void
list_add_r(list l, void *data)
{
	element e = alloc_element();

	e->data = data;

	__list_add(l, e);
}

void
list_add_head_r(list l, void *data)
{
	element e = alloc_element();

	e->data = data;

	e->next = l->head;
	e->prev = NULL;

	if (l->tail == NULL)
		l->tail = e;
	else
		l->head->prev = e;
	l->head = e;
	l->count++;
}

static inline void
__list_remove(list l, const element e)
{
	if (e->prev)
		e->prev->next = e->next;
	else
		l->head = e->next;

	if (e->next)
		e->next->prev = e->prev;
	else
		l->tail = e->prev;

	l->count--;
}

void
list_remove_r(list l, const element e)
{
	if (l->free)
		(*l->free) (e->data);

	__list_remove(l, e);
	FREE_ONLY(e);
}

void
list_extract(list l, const element e)
{
	__list_remove(l, e);
}

void
list_del_r(list l, const void *data)
{
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		if (ELEMENT_DATA(e) == data) {
			list_remove_r(l, e);
			return;
		}
	}
}

void
list_transfer(element e, list l_from, list l_to)
{
	__list_remove(l_from, e);
	__list_add(l_to, e);
}

void * __attribute__ ((pure))
list_element(const list l, size_t num)
{
	element e = LIST_HEAD(l);
	size_t i = 0;

	/* fetch element number num */
	for (i = 0; i < num; i++) {
		if (!e)
			return NULL;

		ELEMENT_NEXT(e);
	}

	if (e)
		return ELEMENT_DATA(e);
	return NULL;
}

void
dump_list(FILE *fp, const list l)
{
	element e;

	if (LIST_ISEMPTY(l))
		return;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e))
		if (l->dump)
			(*l->dump) (fp, e->data);
}

void
free_list_element_simple(void *data)
{
	FREE(data);
}

static void
free_elements(list l)
{
	element e;
	element next;

	for (e = LIST_HEAD(l); e; e = next) {
		next = e->next;
		if (l->free)
			(*l->free) (e->data);
		l->count--;
		FREE(e);
	}
#if 0
	if (l->count)
		log_message(LOG_INFO, "free_elements left %d elements on the list", l->count);
#endif
}

void
free_list_elements_r(list l)
{
	free_elements(l);

	l->head = NULL;
	l->tail = NULL;
}

void
free_list_r(list *lp)
{
	list l = *lp;

	if (!l)
		return;

	/* Remove the caller's reference to the list */
	*lp = NULL;

	free_elements(l);
	FREE(l);
}

void
free_list_element_r(list l, const element e)
{
	if (!l || !e)
		return;
	if (l->head == e)
		l->head = e->next;
	else
		e->prev->next = e->next;
	if (l->tail == e)
		l->tail = e->prev;
	else
		e->next->prev = e->prev;
	if (l->free)
		(*l->free) (e->data);
	l->count--;
	FREE_ONLY(e);
}

void
free_list_data_r(list l, const void *data)
{
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		if (ELEMENT_DATA(e) == data) {
			free_list_element_r(l, e);
			return;
		}
	}
}
