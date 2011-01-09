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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

#ifndef _LIST_H
#define _LIST_H

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
	void (*dump) (void *);
};

/* utility macro */
#define ELEMENT_NEXT(E)		((E) = (E)->next)
#define ELEMENT_DATA(E)		((E)->data)
#define LIST_HEAD(L)		((L)->head)
#define LIST_TAIL_DATA(L)	((L)->tail->data)
#define LIST_ISEMPTY(L)		((L) == NULL || ((L)->head == NULL && (L)->tail == NULL))
#define LIST_SIZE(V)		((V)->count)

/* Prototypes */
extern list alloc_list(void (*free_func) (void *), void (*dump_func) (void *));
extern void free_list(list l);
extern void free_list_elements(list l);
extern void free_list_element(list l, element e);
extern void *list_element(list l, int num);
extern void dump_list(list l);
extern void list_add(list l, void *data);
extern void list_del(list l, void *data);
extern list alloc_mlist(void (*free_func) (void *), void (*dump_func) (void *), int size);
extern void dump_mlist(list l, int size);
extern void free_mlist(list l, int size);

#endif
