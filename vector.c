/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        Vector structure manipulation.
 *  
 * Version:     $Id: vector.c,v 0.5.5 2002/04/10 02:34:23 acassen Exp $
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

#include "vector.h"
#include "memory.h"

/* 
 * Initialize vector struct.
 * allocalted 'size' slot elements then return vector.
 */
vector vector_alloc(void)
{
  vector v = (vector)MALLOC(sizeof(struct _vector));
  return v;
}

/* allocated one slot */
void vector_alloc_slot(vector v)
{
  v->allocated += VECTOR_DEFAULT_SIZE;
  if (v->slot)
    v->slot = REALLOC(v->slot, sizeof(void *) * v->allocated);
  else
    v->slot = (void *)MALLOC(sizeof(void *) * v->allocated);
}

/* Free memory vector allocation */
void vector_free(vector v)
{
  FREE(v->slot);
  FREE(v);
}

/* Set a vector slot value */
void vector_set_slot(vector v, void *value)
{
  unsigned int i = v->allocated-1;

  v->slot[i] = value;
}

/* dump vector slots */
void vector_dump(vector v)
{
  int i;

  printf("Vector Size : %d\n", v->allocated);

  for (i = 0; i < v->allocated; i++)
    if (v->slot[i] != NULL)
      printf("  Slot [%d]: %p\n", i, VECTOR_SLOT(v, i));
}
