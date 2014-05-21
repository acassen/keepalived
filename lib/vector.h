/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        vector.c include file.
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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@linux-vs.org>
 */

#ifndef _VECTOR_H
#define _VECTOR_H

/* vector definition */
typedef struct _vector {
	unsigned int	active;
	unsigned int	allocated;
	void		**slot;
} vector_t;

/* Some defines */
#define VECTOR_DEFAULT_SIZE 1

/* Some usefull macros */
#define vector_slot(V,E) ((V)->slot[(E)])
#define vector_size(V)   ((V)->allocated)
#define vector_active(V) ((V)->active)
#define vector_foreach_slot(v,p,i) \
	for (i = 0; i < (v)->allocated && ((p) = (v)->slot[i]); i++)
#define FMT_STR_VSLOT(V,E) ((char*)vector_slot(V,E))

/* Prototypes */
extern vector_t *vector_alloc(void);
extern vector_t *vector_init(unsigned int);
extern void vector_alloc_slot(vector_t *);
extern void vector_insert_slot(vector_t *, int, void *);
extern vector_t *vector_copy(vector_t *);
extern void vector_ensure(vector_t *, unsigned int);
extern int vector_empty_slot(vector_t *);
extern int vector_set(vector_t *, void *);
extern void vector_set_slot(vector_t *, void *);
extern int vector_set_index(vector_t *, unsigned int, void *);
extern void *vector_lookup(vector_t *, unsigned int);
extern void *vector_lookup_ensure(vector_t *, unsigned int);
extern void vector_unset(vector_t *, unsigned int);
extern unsigned int vector_count(vector_t *);
extern void vector_only_wrapper_free(vector_t *);
extern void vector_only_index_free(void *);
extern void vector_only_slot_free(void *);
extern void vector_free(vector_t *);
extern void vector_dump(vector_t *);
extern void free_strvec(vector_t *);
extern void dump_strvec(vector_t *);

#endif
