/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Memory management framework. This framework is used to
 *              find any memory leak.
 *
 * Authors:     Alexandre Cassen, <acassen@linux-vs.org>
 *              Jan Holmberg, <jan@artech.net>
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

#include "memory.h"
#include "utils.h"

/* Global var */
unsigned long mem_allocated;	/* Total memory used in Bytes */

void *
xalloc(unsigned long size)
{
	void *mem;
	if ((mem = malloc(size)))
		mem_allocated += size;
	return mem;
}

void *
zalloc(unsigned long size)
{
	void *mem;
	if ((mem = malloc(size))) {
		memset(mem, 0, size);
		mem_allocated += size;
	}
	return mem;
}

void
xfree(void *p)
{
	mem_allocated -= sizeof (p);
	free(p);
	p = NULL;
}

/* KeepAlived memory management. in debug mode,
 * help finding eventual memory leak.
 * Allocation memory types manipulated are :
 *
 * +type+--------meaning--------+
 * ! 0  ! Free slot             !
 * ! 1  ! Overrun               !
 * ! 2  ! free null             !
 * ! 3  ! realloc null          !
 * ! 4  ! Not previus allocated !
 * ! 8  ! Last free list        !
 * ! 9  ! Allocated             !
 * +----+-----------------------+
 *
 * global variabel debug bit 9 ( 512 ) used to
 * flag some memory error.
 *
 */

#ifdef _DEBUG_

typedef struct {
	int type;
	int line;
	char *func;
	char *file;
	void *ptr;
	unsigned long size;
	long csum;
} MEMCHECK;

/* Last free pointers */
static MEMCHECK free_list[256];

static MEMCHECK alloc_list[MAX_ALLOC_LIST];
static int number_alloc_list = 0;
static int n = 0;		/* Alloc list pointer */
static int f = 0;		/* Free list pointer */

char *
keepalived_malloc(unsigned long size, char *file, char *function, int line)
{
	void *buf;
	int i = 0;
	long check;

	buf = zalloc(size + sizeof (long));

	check = 0xa5a5 + size;
	*(long *) ((char *) buf + size) = check;

	while (i < number_alloc_list) {
		if (alloc_list[i].type == 0)
			break;
		i++;
	}

	if (i == number_alloc_list)
		number_alloc_list++;

	assert(number_alloc_list < MAX_ALLOC_LIST);

	alloc_list[i].ptr = buf;
	alloc_list[i].size = size;
	alloc_list[i].file = file;
	alloc_list[i].func = function;
	alloc_list[i].line = line;
	alloc_list[i].csum = check;
	alloc_list[i].type = 9;

	if (debug & 1)
		printf("zalloc[%3d:%3d], %p, %4ld at %s, %3d, %s\n",
		       i, number_alloc_list, buf, size, file, line,
		       function);

	n++;
	return buf;
}

int
keepalived_free(void *buffer, char *file, char *function, int line)
{
	int i = 0;
	void *buf;

	/* If nullpointer remember */
	if (buffer == NULL) {
		i = number_alloc_list++;

		assert(number_alloc_list < MAX_ALLOC_LIST);

		alloc_list[i].ptr = buffer;
		alloc_list[i].size = 0;
		alloc_list[i].file = file;
		alloc_list[i].func = function;
		alloc_list[i].line = line;
		alloc_list[i].type = 2;
		if (debug & 1)
			printf("free NULL in %s, %3d, %s\n", file,
			       line, function);

		debug |= 512;	/* Memory Error detect */

		return n;
	} else
		buf = buffer;

	while (i < number_alloc_list) {
		if (alloc_list[i].type == 9 && alloc_list[i].ptr == buf) {
			if (*
			    ((long *) ((char *) alloc_list[i].ptr +
				       alloc_list[i].size)) ==
			    alloc_list[i].csum)
				alloc_list[i].type = 0;	/* Release */
			else {
				alloc_list[i].type = 1;	/* Overrun */
				if (debug & 1) {
					printf("free corrupt, buffer overrun [%3d:%3d], %p, %4ld at %s, %3d, %s\n",
					       i, number_alloc_list,
					       buf, alloc_list[i].size, file,
					       line, function);
					dump_buffer(alloc_list[i].ptr,
						    alloc_list[i].size + sizeof (long));
					printf("Check_sum\n");
					dump_buffer((char *) &alloc_list[i].csum,
						    sizeof(long));

					debug |= 512;	/* Memory Error detect */
				}
			}
			break;
		}
		i++;
	}

	/*  Not found */
	if (i == number_alloc_list) {
		printf("Free ERROR %p\n", buffer);
		number_alloc_list++;

		assert(number_alloc_list < MAX_ALLOC_LIST);

		alloc_list[i].ptr = buf;
		alloc_list[i].size = 0;
		alloc_list[i].file = file;
		alloc_list[i].func = function;
		alloc_list[i].line = line;
		alloc_list[i].type = 4;
		debug |= 512;

		return n;
	}

	if (buffer != NULL)
		xfree(buffer);

	if (debug & 1)
		printf("free  [%3d:%3d], %p, %4ld at %s, %3d, %s\n",
		       i, number_alloc_list, buf,
		       alloc_list[i].size, file, line, function);

	free_list[f].file = file;
	free_list[f].line = line;
	free_list[f].func = function;
	free_list[f].ptr = buffer;
	free_list[f].type = 8;
	free_list[f].csum = i;	/* Using this field for row id */

	f++;
	f &= 255;
	n--;

	return n;
}

void
keepalived_free_final(char *banner)
{
	unsigned int sum = 0, overrun = 0, badptr = 0;
	int i, j;
	i = 0;

	printf("\n---[ Keepalived memory dump for (%s)]---\n\n", banner);

	while (i < number_alloc_list) {
		switch (alloc_list[i].type) {
		case 3:
			badptr++;
			printf
			    ("null pointer to realloc(nil,%ld)! at %s, %3d, %s\n",
			     alloc_list[i].size, alloc_list[i].file,
			     alloc_list[i].line, alloc_list[i].func);
			break;
		case 4:
			badptr++;
			printf
			    ("pointer not found in table to free(%p) [%3d:%3d], at %s, %3d, %s\n",
			     alloc_list[i].ptr, i, number_alloc_list,
			     alloc_list[i].file, alloc_list[i].line,
			     alloc_list[i].func);
			for (j = 0; j < 256; j++)
				if (free_list[j].ptr == alloc_list[i].ptr)
					if (free_list[j].type == 8)
						printf
						    ("  -> pointer allready released at [%3d:%3d], at %s, %3d, %s\n",
						     (int) free_list[j].csum,
						     number_alloc_list,
						     free_list[j].file,
						     free_list[j].line,
						     free_list[j].func);
			break;
		case 2:
			badptr++;
			printf("null pointer to free(nil)! at %s, %3d, %s\n",
			       alloc_list[i].file, alloc_list[i].line,
			       alloc_list[i].func);
			break;
		case 1:
			overrun++;
			printf("%p [%3d:%3d], %4ld buffer overrun!:\n",
			       alloc_list[i].ptr, i, number_alloc_list,
			       alloc_list[i].size);
			printf(" --> source of malloc: %s, %3d, %s\n",
			       alloc_list[i].file, alloc_list[i].line,
			       alloc_list[i].func);
			break;
		case 9:
			sum += alloc_list[i].size;
			printf("%p [%3d:%3d], %4ld not released!:\n",
			       alloc_list[i].ptr, i, number_alloc_list,
			       alloc_list[i].size);
			printf(" --> source of malloc: %s, %3d, %s\n",
			       alloc_list[i].file, alloc_list[i].line,
			       alloc_list[i].func);
			break;
		}
		i++;
	}

	printf("\n\n---[ Keepalived memory dump summary for (%s) ]---\n", banner);
	printf("Total number of bytes not freed...: %d\n", sum);
	printf("Number of entries not freed.......: %d\n", n);
	printf("Maximum allocated entries.........: %d\n", number_alloc_list);
	printf("Number of bad entries.............: %d\n", badptr);
	printf("Number of buffer overrun..........: %d\n\n", overrun);

	if (sum || n || badptr || overrun)
		printf("=> Program seems to have some memory problem !!!\n\n");
	else
		printf("=> Program seems to be memory allocation safe...\n\n");
}

void *
keepalived_realloc(void *buffer, unsigned long size, char *file, char *function,
		   int line)
{
	int i = 0;
	void *buf, *buf2;
	long check;

	if (buffer == NULL) {
		printf("realloc %p %s, %3d %s\n", buffer, file, line, function);
		i = number_alloc_list++;

		assert(number_alloc_list < MAX_ALLOC_LIST);

		alloc_list[i].ptr = NULL;
		alloc_list[i].size = 0;
		alloc_list[i].file = file;
		alloc_list[i].func = function;
		alloc_list[i].line = line;
		alloc_list[i].type = 3;
		return keepalived_malloc(size, file, function, line);
	}

	buf = buffer;

	while (i < number_alloc_list) {
		if (alloc_list[i].ptr == buf) {
			buf = alloc_list[i].ptr;
			break;
		}
		i++;
	}

	/* not found */
	if (i == number_alloc_list) {
		printf("realloc ERROR no matching zalloc %p \n", buffer);
		number_alloc_list++;

		assert(number_alloc_list < MAX_ALLOC_LIST);

		alloc_list[i].ptr = buf;
		alloc_list[i].size = 0;
		alloc_list[i].file = file;
		alloc_list[i].func = function;
		alloc_list[i].line = line;
		alloc_list[i].type = 9;
		debug |= 512;	/* Memory Error detect */
		return NULL;
	}

	buf2 = ((char *) buf) + alloc_list[i].size;

	if (*(long *) (buf2) != alloc_list[i].csum) {
		alloc_list[i].type = 1;
		debug |= 512;	/* Memory Error detect */
	}
	buf = realloc(buffer, size + sizeof (long));

	check = 0xa5a5 + size;
	*(long *) ((char *) buf + size) = check;
	alloc_list[i].csum = check;

	if (debug & 1)
		printf("realloc [%3d:%3d] %p, %4ld %s %d %s -> %p %4ld %s %d %s\n",
		       i, number_alloc_list, alloc_list[i].ptr,
		       alloc_list[i].size, file, line, function, buf, size,
		       alloc_list[i].file, alloc_list[i].line,
		       alloc_list[i].func);

	alloc_list[i].ptr = buf;
	alloc_list[i].size = size;
	alloc_list[i].file = file;
	alloc_list[i].line = line;
	alloc_list[i].func = function;

	return buf;
}

#endif
