/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        list.c include file.
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

#ifndef _LIST_H
#define _LIST_H

#include <sys/types.h>
#include <stdio.h>

/* list definition */
typedef struct _element *element;
typedef struct _list *list;

struct _element {
	struct _element *next;
	struct _element *prev;
	void *data;
};

struct _list {
	struct _element *head;
	struct _element *tail;
	unsigned int count;
	void (*free) (void *);
	void (*dump) (FILE *, void *);
};

/* utility macro */
#define ELEMENT_NEXT(E)		((E) = (E)->next)
#define ELEMENT_DATA(E)		((E)->data)
#define LIST_HEAD(L)		(!(L) ? NULL : (L)->head)
#define LIST_TAIL_DATA(L)	((L)->tail->data)
#define LIST_ISEMPTY(L)		((L) == NULL || ((L)->head == NULL && (L)->tail == NULL))
#define LIST_EXISTS(L)		((L) != NULL)
#define LIST_SIZE(L)		((L)->count)
#define LIST_FOREACH(L,V,E)	for ((E) = ((L) ? LIST_HEAD(L) : NULL); (E) && ((V) = ELEMENT_DATA(E), 1); ELEMENT_NEXT(E))
#define LIST_FOREACH_NEXT(L,V,E,N) for ((E) = ((L) ? LIST_HEAD(L) : NULL); (E) && ((N) = (E)->next, (V) = ELEMENT_DATA(E), 1); (E) = (N))

/* Prototypes */
extern list alloc_list(void (*free_func) (void *), void (*dump_func) (FILE *, void *));
extern void free_list(list *);
extern void free_list_elements(list l);
extern void free_list_element(list l, element e);
extern void *list_element(list l, size_t num);
extern void dump_list(FILE *, list l);
extern void list_add(list l, void *data);
extern void list_remove(list l, element);
extern void list_del(list l, void *data);
extern list alloc_mlist(void (*free_func) (void *), void (*dump_func) (FILE *, void *), size_t size);
extern void free_mlist(list l, size_t size);

#endif
