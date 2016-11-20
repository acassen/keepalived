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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include "config.h"

#ifdef _MEM_CHECK_
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#include <errno.h>
#include <string.h>

#include "memory.h"
#include "utils.h"
#include "bitops.h"
#include "logger.h"

#ifdef _MEM_CHECK_
/* Global var */
size_t mem_allocated;		/* Total memory used in Bytes */
size_t max_mem_allocated;	/* Maximum memory used in Bytes */

const char *terminate_banner;	/* banner string for report file */

static bool skip_mem_check_final;
#endif

static void *
xalloc(unsigned long size)
{
	void *mem = malloc(size);

	if (mem == NULL) {
		if (__test_bit(DONT_FORK_BIT, &debug))
			perror("Keepalived");
		else
			log_message(LOG_INFO, "Keepalived xalloc() error - %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

#ifdef _MEM_CHECK_
	mem_allocated += size - sizeof(long);
	if (mem_allocated > max_mem_allocated)
		max_mem_allocated = mem_allocated;
#endif

	return mem;
}

void *
zalloc(unsigned long size)
{
	void *mem = xalloc(size);

	if (mem)
		memset(mem, 0, size);

	return mem;
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
 * global variable debug bit 9 ( 512 ) used to
 * flag some memory error.
 *
 */

#ifdef _MEM_CHECK_

typedef struct {
	int type;
	int line;
	char *func;
	char *file;
	void *ptr;
	size_t size;
	long csum;
} MEMCHECK;

/* Last free pointers */
static MEMCHECK free_list[256];

static MEMCHECK alloc_list[MAX_ALLOC_LIST];
static int number_alloc_list = 0;
static int n = 0;		/* Alloc list pointer */
static int f = 0;		/* Free list pointer */

static FILE *log_op = NULL;

void *
keepalived_malloc(size_t size, char *file, char *function, int line)
{
	void *buf;
	int i;
	long check;

	buf = zalloc(size + sizeof (long));

	check = (long)size + 0xa5a5;
	*(long *) ((char *) buf + size) = check;

	for (i = 0; i < number_alloc_list; i++) {
		if (alloc_list[i].type == 0)
			break;
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

	fprintf(log_op, "zalloc[%3d:%3d], %p, %4zu at %s, %3d, %s\n",
	       i, number_alloc_list, buf, size, file, line, function);
#ifdef _MEM_CHECK_LOG_
	if (__test_bit(MEM_CHECK_LOG_BIT, &debug))
		log_message(LOG_INFO, "zalloc[%3d:%3d], %p, %4zu at %s, %3d, %s\n",
		       i, number_alloc_list, buf, size, file, line, function);
#endif

	n++;
	return buf;
}

int
keepalived_free(void *buffer, char *file, char *function, int line)
{
	int i = 0;
	void *buf = buffer;

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
		fprintf(log_op, "free NULL in %s, %3d, %s\n", file,
		       line, function);

		__set_bit(MEM_ERR_DETECT_BIT, &debug);	/* Memory Error detect */

		return n;
	}

	while (i < number_alloc_list) {
		if (alloc_list[i].type == 9 && alloc_list[i].ptr == buf) {
			if (*((long *) ((char *) alloc_list[i].ptr + alloc_list[i].size)) == alloc_list[i].csum) {
				alloc_list[i].type = 0;	/* Release */
				mem_allocated -= alloc_list[i].size - sizeof(long);
			} else {
				alloc_list[i].type = 1;	/* Overrun */
				fprintf(log_op, "free corrupt, buffer overrun [%3d:%3d], %p, %4zu at %s, %3d, %s\n",
				       i, number_alloc_list,
				       buf, alloc_list[i].size, file,
				       line, function);
				dump_buffer(alloc_list[i].ptr,
					    alloc_list[i].size + sizeof (long), log_op);
				fprintf(log_op, "Check_sum\n");
				dump_buffer((char *) &alloc_list[i].csum,
					    sizeof(long), log_op);

				__set_bit(MEM_ERR_DETECT_BIT, &debug);
			}
			break;
		}
		i++;
	}

	/*  Not found */
	if (i == number_alloc_list) {
		fprintf(log_op, "Free ERROR %p not found\n", buffer);
		number_alloc_list++;

		assert(number_alloc_list < MAX_ALLOC_LIST);

		alloc_list[i].ptr = buf;
		alloc_list[i].size = 0;
		alloc_list[i].file = file;
		alloc_list[i].func = function;
		alloc_list[i].line = line;
		alloc_list[i].type = 4;
		__set_bit(MEM_ERR_DETECT_BIT, &debug);

		return n;
	}

	fprintf(log_op, "free  [%3d:%3d], %p, %4zu at %s, %3d, %s\n",
	       i, number_alloc_list, buf,
	       alloc_list[i].size, file, line, function);
#ifdef _MEM_CHECK_LOG_
	if (__test_bit(MEM_CHECK_LOG_BIT, &debug))
		log_message(LOG_INFO, "free  [%3d:%3d], %p, %4zu at %s, %3d, %s\n",
		       i, number_alloc_list, buf,
		       alloc_list[i].size, file, line, function);
#endif

	if (buffer != NULL)
		free(buffer);

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

static void
keepalived_free_final(void)
{
	unsigned int overrun = 0, badptr = 0;
	size_t sum = 0;
	int i, j;
	i = 0;

	/* If this is a forked child, we don't want the dump */
	if (skip_mem_check_final)
		return;

	fprintf(log_op, "\n---[ Keepalived memory dump for (%s)]---\n\n", terminate_banner);

	while (i < number_alloc_list) {
		switch (alloc_list[i].type) {
		case 3:
			badptr++;
			fprintf
			    (log_op, "null pointer to realloc(nil,%zu)! at %s, %3d, %s\n",
			     alloc_list[i].size, alloc_list[i].file,
			     alloc_list[i].line, alloc_list[i].func);
			break;
		case 4:
			badptr++;
			fprintf
			    (log_op, "pointer not found in table to free(%p) [%3d:%3d], at %s, %3d, %s\n",
			     alloc_list[i].ptr, i, number_alloc_list,
			     alloc_list[i].file, alloc_list[i].line,
			     alloc_list[i].func);
			for (j = 0; j < 256; j++)
				if (free_list[j].ptr == alloc_list[i].ptr)
					if (free_list[j].type == 8)
						fprintf
						    (log_op, "  -> pointer already released at [%3d:%3d], at %s, %3d, %s\n",
						     (int) free_list[j].csum,
						     number_alloc_list,
						     free_list[j].file,
						     free_list[j].line,
						     free_list[j].func);
			break;
		case 2:
			badptr++;
			fprintf(log_op, "null pointer to free(nil)! at %s, %3d, %s\n",
			       alloc_list[i].file, alloc_list[i].line,
			       alloc_list[i].func);
			break;
		case 1:
			overrun++;
			fprintf(log_op, "%p [%3d:%3d], %4zu buffer overrun!:\n",
			       alloc_list[i].ptr, i, number_alloc_list,
			       alloc_list[i].size);
			fprintf(log_op, " --> source of malloc: %s, %3d, %s\n",
			       alloc_list[i].file, alloc_list[i].line,
			       alloc_list[i].func);
			break;
		case 9:
			sum += alloc_list[i].size;
			fprintf(log_op, "%p [%3d:%3d], %4zu not released!:\n",
			       alloc_list[i].ptr, i, number_alloc_list,
			       alloc_list[i].size);
			fprintf(log_op, " --> source of malloc: %s, %3d, %s\n",
			       alloc_list[i].file, alloc_list[i].line,
			       alloc_list[i].func);
			break;
		}
		i++;
	}

	fprintf(log_op, "\n\n---[ Keepalived memory dump summary for (%s) ]---\n", terminate_banner);
	fprintf(log_op, "Total number of bytes not freed...: %zu\n", sum);
	fprintf(log_op, "Number of entries not freed.......: %d\n", n);
	fprintf(log_op, "Maximum allocated entries.........: %d\n", number_alloc_list);
	fprintf(log_op, "Maximum memory allocated..........: %zu\n", max_mem_allocated);
	fprintf(log_op, "Number of bad entries.............: %d\n", badptr);
	fprintf(log_op, "Number of buffer overrun..........: %d\n\n", overrun);

	if (sum || n || badptr || overrun)
		fprintf(log_op, "=> Program seems to have some memory problem !!!\n\n");
	else
		fprintf(log_op, "=> Program seems to be memory allocation safe...\n\n");
}

void *
keepalived_realloc(void *buffer, size_t size, char *file, char *function,
		   int line)
{
	int i;
	void *buf = buffer, *buf2;
	long check;

	if (buffer == NULL) {
		fprintf(log_op, "realloc %p %s, %3d %s\n", buffer, file, line, function);
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

	for (i = 0; i < number_alloc_list; i++) {
		if (alloc_list[i].ptr == buf) {
			buf = alloc_list[i].ptr;
			break;
		}
	}

	/* not found */
	if (i == number_alloc_list) {
		fprintf(log_op, "realloc ERROR no matching zalloc %p \n", buffer);
		number_alloc_list++;

		assert(number_alloc_list < MAX_ALLOC_LIST);

		alloc_list[i].ptr = buf;
		alloc_list[i].size = 0;
		alloc_list[i].file = file;
		alloc_list[i].func = function;
		alloc_list[i].line = line;
		alloc_list[i].type = 9;
		__set_bit(MEM_ERR_DETECT_BIT, &debug);	/* Memory Error detect */
		return NULL;
	}

	buf2 = ((char *) buf) + alloc_list[i].size;

	if (*(long *) (buf2) != alloc_list[i].csum) {
		alloc_list[i].type = 1;
		__set_bit(MEM_ERR_DETECT_BIT, &debug);	/* Memory Error detect */
	}
	buf = realloc(buffer, size + sizeof (long));

	check = (long)size + 0xa5a5;
	*(long *) ((char *) buf + size) = check;
	alloc_list[i].csum = check;

	fprintf(log_op, "realloc [%3d:%3d] %p, %4zu %s %d %s -> %p %4zu %s %d %s\n",
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

void
mem_log_init(const char* prog_name, const char *banner)
{
	size_t log_name_len;
	char *log_name;

	if (__test_bit(LOG_CONSOLE_BIT, &debug)) {
		log_op = stderr;
		return;
	}

	if (log_op)
		fclose(log_op);

	log_name_len = 5 + strlen(prog_name) + 5 + 5 + 4 + 1;	/* "/tmp/" + prog_name + "_mem." + PID + ".log" + '\0" */
	log_name = malloc(log_name_len);
	if (!log_name) {
		log_message(LOG_INFO, "Unable to malloc log file name");
		log_op = stderr;
		return;
	}

	snprintf(log_name, log_name_len, "/tmp/%s_mem.%d.log", prog_name, getpid());
	log_op = fopen(log_name, "a");
	if (log_op == NULL) {
		log_message(LOG_INFO, "Unable to open %s for appending", log_name);
		log_op = stderr;
	}
	else {
		int fd = fileno(log_op);

		/* We don't want any children to inherit the log file */
		fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);

		/* Make the log output line buffered. This was to ensure that
		 * children didn't inherit the buffer, but the CLOEXEC above
		 * should resolve that. */
		setlinebuf(log_op);

		fprintf(log_op, "\n");
	}

	free(log_name);

	terminate_banner = banner;
}

void skip_mem_dump(void)
{
	skip_mem_check_final = true;
}

void enable_mem_log_termination(void)
{
	atexit(keepalived_free_final);
}
#endif
