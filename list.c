/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        List structure manipulation.
 *  
 * Version:     $Id: list.c,v 0.6.2 2002/06/16 05:23:31 acassen Exp $
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
 */

#include "list.h"
#include "memory.h"

list alloc_list(void (*free_func) (void *), void (*dump_func) (void *))
{
  list new = (list)MALLOC(sizeof(struct _list));
  new->free = free_func;
  new->dump = dump_func;
  return new;
}

static element alloc_element(void)
{
  element new = (element)MALLOC(sizeof(struct _element));
  return new;
}

void list_add(list l, void *data)
{
  element e = alloc_element();

  e->prev = l->tail;
  e->data = data;

  if (l->head == NULL)
    l->head = e;
  else
    l->tail->next = e;
  l->tail = e;
  l->count++;
}

void *list_element(list l, int num)
{
  element e;
  int i = 0;

  e = LIST_HEAD(l);

  /* fetch element number num */
  for (i = 0; i < num; i++)
    if (e)
      e = ELEMENT_NEXT(e);

  if (e)
    return ELEMENT_DATA(e);
  return NULL;
}

void dump_list(list l)
{
  element e;

  for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e))
    if (l->dump)
      (*l->dump) (e->data);
}

void free_list(list l)
{
  element e;
  element next;

  for (e = LIST_HEAD(l); e; e = next) {
    next = e->next;
    if (l->free)
      (*l->free) (e->data);
    FREE(e);
  }
  FREE(l);
}
