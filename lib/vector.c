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

#include "config.h"

#include "vector.h"
#include "memory.h"

/* Function to call if attempt to read beyond end of strvec */
static null_strvec_handler_t null_strvec_handler;

null_strvec_handler_t register_null_strvec_handler(null_strvec_handler_t null_strvec_func)
{
	null_strvec_handler_t old_handler = null_strvec_handler;

	null_strvec_handler = null_strvec_func;

	return old_handler;
}

null_strvec_handler_t unregister_null_strvec_handler(void)
{
	null_strvec_handler_t old_handler = null_strvec_handler;

	null_strvec_handler = NULL;

	return old_handler;
}

void *strvec_slot(const vector_t *strvec, size_t index)
{
	if (strvec &&
	    index < vector_size(strvec) &&
	    strvec->slot[index])
		return strvec->slot[index];

	if (null_strvec_handler)
		(*null_strvec_handler)(strvec, index);

	return "";
}

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

#ifdef _INCLUDE_UNUSED_CODE_
vector_t *
vector_init(unsigned int size)
{
	vector_t *v = vector_alloc();

	/* allocate at least one slot */
	if (size == 0)
		size = 1;

	v->allocated = size;
	v->active = 0;
	v->slot = (void *) MALLOC(sizeof(void *) * size);
	return v;
}
#endif

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

#ifdef _INCLUDE_UNUSED_CODE_
/* Insert a value into a specific slot */
void
vector_insert_slot(vector_t *v, unsigned int index, void *value)
{
	unsigned int i;

	vector_alloc_slot(v);
	for (i = (v->allocated / VECTOR_DEFAULT_SIZE) - 2; i >= index; i--)
		v->slot[i + 1] = v->slot[i];
	v->slot[index] = value;
	if (v->active >= index + 1)
		v->active++;
	else
		v->active = index + 1;
}

/* Copy / dup a vector */
vector_t *
vector_copy(vector_t *v)
{
	unsigned int size;
	vector_t *new = vector_alloc();

	new->active = v->active;
	new->allocated = v->allocated;

	size = sizeof(void *) * (v->allocated);
	new->slot = (void *) MALLOC(size);
	memcpy(new->slot, v->slot, size);

	return new;
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
#endif

/* Set a vector slot value */
void
vector_set_slot(vector_t *v, void *value)
{
	unsigned int i = v->allocated - 1;

	v->slot[i] = value;
	v->active = v->allocated;
}

#ifdef _INCLUDE_UNUSED_CODE_
/* Set value to specified index slot. */
int
vector_set_index(vector_t *v, unsigned int i, void *val)
{
	vector_ensure(v, i);

	v->slot[i] = val;

	if (v->active <= i)
		v->active = i + 1;

	return i;
}

/* Look up vector.  */
void *
vector_lookup(vector_t *v, unsigned int i)
{
	if (i >= v->active)
		return NULL;
	return v->slot[i];
}

/* Lookup vector, ensure it. */
void *
vector_lookup_ensure(vector_t *v, unsigned int i)
{
	vector_ensure(v, i);
	return v->slot[i];
}
#endif

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

#ifdef _INCLUDE_UNUSED_CODE_
/* Free memory vector allocation */
void
vector_only_wrapper_free(vector_t *v)
{
	FREE(v);
}

void
vector_only_slot_free(void *slot)
{
	FREE(slot);
}

void
vector_only_index_free(void *slot)
{
	vector_only_slot_free(slot);
}
#endif

void
vector_free(vector_t *v)
{
	FREE(v->slot);
	FREE(v);
}

/* dump vector slots */
void
vector_dump(FILE *fp, vector_t *v)
{
	unsigned int i;

	fprintf(fp, "Vector Size : %d, active %d\n", v->allocated, v->active);

	for (i = 0; i < v->allocated; i++) {
		if (v->slot[i] != NULL) {
			fprintf(fp, "  Slot [%d]: %p\n", i, vector_slot(v, i));
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

#ifdef _INCLUDE_UNUSED_CODE_
void
dump_strvec(vector_t *strvec)
{
	unsigned int i;
	char *str;

	if (!strvec)
		return;

	printf("String Vector : ");

	for (i = 0; i < vector_size(strvec); i++) {
		str = vector_slot(strvec, i);
		printf("[%i]=%s ", i, str);
	}
	printf("\n");
}
#endif
