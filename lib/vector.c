/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Vector structure manipulation.
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

#include "vector.h"
#include "memory.h"

/*
 * Initialize vector struct.
 * allocalted 'size' slot elements then return vector.
 */
vector_t *
vector_alloc(void)
{
	vector_t *v = (vector_t *) MALLOC(sizeof(vector_t));
	return v;
}

/* allocated one slot */
void
vector_alloc_slot(vector_t *v)
{
	v->allocated += VECTOR_DEFAULT_SIZE;
	if (v->slot)
		v->slot = REALLOC(v->slot, sizeof (void *) * v->allocated);
	else
		v->slot = (void *) MALLOC(sizeof (void *) * v->allocated);
}

/* Check assigned index, and if it runs short double index pointer */
static void
vector_ensure(vector_t *v, unsigned int num)
{
	if (v->allocated > num)
		return;

	v->slot = REALLOC(v->slot, sizeof(void *) * (v->allocated * 2));
	memset(&v->slot[v->allocated], 0, sizeof (void *) * v->allocated);
	v->allocated *= 2;

	if (v->allocated <= num)
		vector_ensure(v, num);
}

/* This function only returns next empty slot index.  It dose not mean
 * the slot's index memory is assigned, please call vector_ensure()
 * after calling this function.
 */
static int
vector_empty_slot(vector_t *v)
{
	unsigned int i;

	if (v->active == 0)
		return 0;

	for (i = 0; i < v->active; i++) {
		if (v->slot[i] == 0) {
			return i;
		}
	}

	return i;
}

/* Set value to the smallest empty slot. */
int
vector_set(vector_t *v, void *val)
{
	unsigned int i;

	i = vector_empty_slot(v);
	vector_ensure(v, i);

	v->slot[i] = val;

	if (v->active <= i)
		v->active = i + 1;

	return i;
}

/* Set a vector slot value */
void
vector_set_slot(vector_t *v, void *value)
{
	unsigned int i = v->allocated - 1;

	v->slot[i] = value;
	v->active = v->allocated;
}

/* Look up vector.  */
void *
vector_lookup(vector_t *v, unsigned int i)
{
	if (i >= v->active)
		return NULL;
	return v->slot[i];
}

/* Unset value at specified index slot. */
void
vector_unset(vector_t *v, unsigned int i)
{
	if (i >= v->allocated)
		return;

	v->slot[i] = NULL;

	if (i + 1 == v->active) {
		v->active--;
		while (i && v->slot[--i] == NULL && v->active--)
			;	/* Is this ugly ? */
	}
}

/* Count the number of not empty slot. */
unsigned int
vector_count(vector_t *v)
{
	unsigned int i;
	unsigned count = 0;

	for (i = 0; i < v->active; i++) {
		if (v->slot[i] != NULL) {
			count++;
		}
	}

	return count;
}

void
vector_free(vector_t *v)
{
	FREE(v->slot);
	FREE(v);
}

/* dump vector slots */
void
vector_dump(vector_t *v)
{
	unsigned int i;

	printf("Vector Size : %d, active %d\n", v->allocated, v->active);

	for (i = 0; i < v->allocated; i++) {
		if (v->slot[i] != NULL) {
			printf("  Slot [%d]: %p\n", i, vector_slot(v, i));
		}
	}
}

/* String vector related */
void
free_strvec(vector_t *strvec)
{
	unsigned int i;
	char *str;

	if (!strvec)
		return;

	for (i = 0; i < vector_size(strvec); i++) {
		if ((str = vector_slot(strvec, i)) != NULL) {
			FREE(str);
		}
	}

	vector_free(strvec);
}

