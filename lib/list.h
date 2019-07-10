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
	void (*dump) (FILE *, const void *);
};

/* utility macro */
#define ELEMENT_NEXT(E)		((E) = (E)->next)
#define ELEMENT_DATA(E)		((E)->data)
#define LIST_HEAD(L)		(!(L) ? NULL : (L)->head)
#define LIST_TAIL(L)		(!(L) ? NULL : (L)->tail)
#define LIST_HEAD_DATA(L)	((L)->head->data)
#define LIST_TAIL_DATA(L)	((L)->tail->data)
#define LIST_ISEMPTY(L)		(!(L) || ((L)->head == NULL && (L)->tail == NULL))
#define LIST_EXISTS(L)		((L) != NULL)
#define LIST_SIZE(L)		(!(L) ? 0 : (L)->count)
#define LIST_FOREACH(L,V,E)	for ((E) = ((L) ? LIST_HEAD(L) : NULL); (E) && ((V) = ELEMENT_DATA(E), 1); ELEMENT_NEXT(E))
#define LIST_FOREACH_FROM(F,V,E) for ((E) = (F); (E) && ((V) = ELEMENT_DATA(E), 1); ELEMENT_NEXT(E))
#define LIST_FOREACH_NEXT(L,V,E,N) for ((E) = ((L) ? LIST_HEAD(L) : NULL); (E) && ((N) = (E)->next, (V) = ELEMENT_DATA(E), 1); (E) = (N))

#ifdef _MEM_CHECK_
#define alloc_mlist(f,d,s)	(memcheck_log("alloc_mlist", NULL, (__FILE__), (__func__), (__LINE__)), \
				 alloc_mlist_r((f), (d), (s)))
#define free_mlist(f,s)		(memcheck_log("free_mlist", NULL, (__FILE__), (__func__), (__LINE__)), \
				 free_mlist_r((f), (s)))
#define alloc_list(f,d)		(memcheck_log("alloc_list", NULL, (__FILE__), (__func__), (__LINE__)), \
				 alloc_list_r((f), (d)))
#define free_list(l)		(memcheck_log("free_list", NULL, (__FILE__), (__func__), (__LINE__)), \
				 free_list_r((l)))
#define free_list_elements(l)	(memcheck_log("free_list_elements", NULL, (__FILE__), (__func__), (__LINE__)), \
				 free_list_elements_r((l)))
#define free_list_element(l,e)	(memcheck_log("free_list_element", NULL, (__FILE__), (__func__), (__LINE__)), \
				 free_list_element_r((l), (e)))
#define list_add(l,e)		(memcheck_log("list_add", NULL, (__FILE__), (__func__), (__LINE__)), \
				 list_add_r((l), (e)))
#define list_add_head(l,e)	(memcheck_log("list_add_head", NULL, (__FILE__), (__func__), (__LINE__)), \
				 list_add_head_r((l), (e)))
#define list_remove(l,e)	(memcheck_log("list_remove", NULL, (__FILE__), (__func__), (__LINE__)), \
				 list_remove_r((l), (e)))
#define list_del(l,d)		(memcheck_log("list_del", NULL, (__FILE__), (__func__), (__LINE__)), \
				 list_del_r((l), (d)))
#define free_list_data(l,d)	(memcheck_log("free_list_data", NULL, (__FILE__), (__func__), (__LINE__)), \
				 free_list_data_r((l), (d)))
#else
#define alloc_mlist(f,d,s)	(alloc_mlist_r((f), (d), (s)))
#define free_mlist(f,s)		(free_mlist_r((f), (s)))
#define alloc_list(f,d)		(alloc_list_r((f), (d)))
#define free_list(l)		(free_list_r((l)))
#define free_list_elements(l)	(free_list_elements_r((l)))
#define free_list_element(l,e)	(free_list_element_r((l), (e)))
#define list_add(l,e)		(list_add_r((l), (e)))
#define list_add_head(l,e)	(list_add_head_r((l), (e)))
#define list_remove(l,e)	(list_remove_r((l), (e)))
#define list_del(l,d)		(list_del_r((l), (d)))
#define free_list_data(l,d)	(free_list_data_r((l), (d)))
#endif


/* Prototypes */
extern list alloc_mlist_r(void (*) (void *), void (*) (FILE *, const void *), size_t);
#ifdef _VRRP_FD_DEBUG_
extern void dump_mlist(FILE *, list, size_t);
#endif
extern void free_mlist_r(list, size_t);
extern list alloc_list_r(void (*) (void *), void (*) (FILE *, const void *));
extern void free_list_r(list *);
extern void free_list_element_simple(void *);
extern void free_list_elements_r(list);
extern void free_list_element_r(list, const element);
extern void list_transfer(element, list, list);
extern void *list_element(list, size_t) __attribute__ ((pure));
extern void dump_list(FILE *, const list);
extern void list_add_r(list, void *);
extern void list_add_head_r(list, void *);
extern void list_remove_r(list, const element);
extern void list_extract(list, const element);
extern void list_del_r(list, const void *);
extern void free_list_data_r(list, const void *);

#endif
