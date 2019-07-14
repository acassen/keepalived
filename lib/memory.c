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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#ifdef _MEM_CHECK_
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <sys/stat.h>
#include <stdio.h>
#endif

#include <errno.h>
#include <string.h>

#include "memory.h"
#include "utils.h"
#include "bitops.h"
#include "logger.h"
#include "scheduler.h"

#ifdef _MEM_CHECK_
#include "timer.h"
#include "rbtree.h"
#include "list_head.h"

/* Global var */
size_t mem_allocated;			/* Total memory used in Bytes */
static size_t max_mem_allocated;	/* Maximum memory used in Bytes */

static const char *terminate_banner;	/* banner string for report file */

static bool skip_mem_check_final;
#endif

static void * __attribute__ ((malloc))
xalloc(unsigned long size)
{
	void *mem = malloc(size);

	if (mem == NULL) {
		if (__test_bit(DONT_FORK_BIT, &debug))
			perror("Keepalived");
		else
			log_message(LOG_INFO, "Keepalived xalloc() error - %s", strerror(errno));
		exit(KEEPALIVED_EXIT_NO_MEMORY);
	}

#ifdef _MEM_CHECK_
	mem_allocated += size - sizeof(long);
	if (mem_allocated > max_mem_allocated)
		max_mem_allocated = mem_allocated;
#endif

	return mem;
}

#ifdef _MEM_CHECK_
static
#endif
void * __attribute__ ((malloc))
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
 * +-type------------------+-meaning------------------+
 * ! FREE_SLOT             ! Free slot                !
 * ! OVERRUN               ! Overrun                  !
 * ! FREE_NULL             ! free null                !
 * ! REALLOC_NULL          ! realloc null             !
 * ! DOUBLE_FREE           ! double free              !
 * ! REALLOC_DOUBLE_FREE   ! realloc freed block      !
 * ! FREE_NOT_ALLOC        ! Not previously allocated !
 * ! REALLOC_NOT_ALLOC     ! Not previously allocated !
 * ! MALLOC_ZERO_SIZE      ! malloc with size 0       !
 * ! REALLOC_ZERO_SIZE     ! realloc with size 0      !
 * ! LAST_FREE             ! Last free list           !
 * ! ALLOCATED             ! Allocated                !
 * +-----------------------+--------------------------+
 *
 * global variable debug bit MEM_ERR_DETECT_BIT used to
 * flag some memory error.
 *
 */

#ifdef _MEM_CHECK_

enum slot_type {
	FREE_SLOT = 0,
	OVERRUN,
	FREE_NULL,
	REALLOC_NULL,
	DOUBLE_FREE,
	REALLOC_DOUBLE_FREE,
	FREE_NOT_ALLOC,
	REALLOC_NOT_ALLOC,
	MALLOC_ZERO_SIZE,
	REALLOC_ZERO_SIZE,
	LAST_FREE,
	ALLOCATED,
} ;

#define TIME_STR_LEN	9

#if ULONG_MAX == 0xffffffffffffffffUL
#define CHECK_VAL	0xa5a55a5aa5a55a5aUL
#elif ULONG_MAX == 0xffffffffUL
#define CHECK_VAL	0xa5a55a5aUL
#else
#define CHECK_VAL	0xa5a5
#endif

typedef struct {
	enum slot_type type;
	int line;
	const char *func;
	const char *file;
	void *ptr;
	size_t size;
	union {
		list_head_t l;	/* When on free list */
		rb_node_t t;
	};
	unsigned seq_num;
} MEMCHECK;

/* Last free pointers */
static LH_LIST_HEAD(free_list);
static unsigned free_list_size;

/* alloc_list entries used for 1000 VRRP instance each with VMAC interfaces is 33589 */
static rb_root_t alloc_list = RB_ROOT;
static LH_LIST_HEAD(bad_list);

static unsigned number_alloc_list;	/* number of alloc_list allocation entries */
static unsigned max_alloc_list;
static unsigned num_mallocs;
static unsigned num_reallocs;
static unsigned seq_num;

static FILE *log_op = NULL;

static inline int
memcheck_ptr_cmp(const MEMCHECK *m1, const MEMCHECK *m2)
{
	return (char *)m1->ptr - (char *)m2->ptr;
}

static inline int
memcheck_seq_cmp(const MEMCHECK *m1, const MEMCHECK *m2)
{
	return m1->seq_num - m2->seq_num;
}

static const char *
format_time(void)
{
	static char time_buf[TIME_STR_LEN+1];

	strftime(time_buf, sizeof time_buf, "%T ", localtime(&time_now.tv_sec));

	return time_buf;
}

void
memcheck_log(const char *called_func, const char *param, const char *file, const char *function, int line)
{
	int len = strlen(called_func) + (param ? strlen(param) : 0);

	if ((len = 36 - len) < 0)
		len = 0;

	fprintf(log_op, "%s%*s%s(%s) at %s, %d, %s\n",
	       format_time(), len, "", called_func, param ? param : "", file, line, function);
}

static MEMCHECK *
get_free_alloc_entry(void)
{
	MEMCHECK *entry;

	/* If number on free list < 256, allocate new entry, otherwise take head */
	if (free_list_size < 256)
		entry = malloc(sizeof *entry);
	else {
		entry = list_first_entry(&free_list, MEMCHECK, l);
		list_head_del(&entry->l);
		free_list_size--;
	}

	entry->seq_num = seq_num++;

	return entry;
}

static void *
keepalived_malloc_common(size_t size, const char *file, const char *function, int line, const char *name)
{
	void *buf;
	MEMCHECK *entry, *entry2;

	buf = zalloc(size + sizeof (unsigned long));

#ifndef _NO_UNALIGNED_ACCESS_
	*(unsigned long *) ((char *) buf + size) = size + CHECK_VAL;
#else
	unsigned long check_val = CHECK_VAL;

	memcpy((unsigned char *)buf + size, (unsigned char *)&check_val, sizeof(check_val));
#endif

	entry = get_free_alloc_entry();

	entry->ptr = buf;
	entry->size = size;
	entry->file = file;
	entry->func = function;
	entry->line = line;
	entry->type = ALLOCATED;

	rb_insert_sort(&alloc_list, entry, t, memcheck_ptr_cmp);
	if (++number_alloc_list > max_alloc_list)
		max_alloc_list = number_alloc_list;

	fprintf(log_op, "%s%s [%3u:%3u], %9p, %4zu at %s, %3d, %s%s\n",
	       format_time(), name, entry->seq_num, number_alloc_list, buf, size, file, line, function, !size ? " - size is 0" : "");
#ifdef _MEM_CHECK_LOG_
	if (__test_bit(MEM_CHECK_LOG_BIT, &debug))
		log_message(LOG_INFO, "%s[%3u:%3u], %9p, %4zu at %s, %3d, %s",
		       name, entry->seq_num, number_alloc_list, buf, size, file, line, function);
#endif

	num_mallocs++;

	if (!size) {
		/* Record malloc with 0 size */
		entry2 = get_free_alloc_entry();
		*entry2 = *entry;
		entry2->type = MALLOC_ZERO_SIZE;
		list_add_tail(&entry2->l, &bad_list);
	}

	/* coverity[leaked_storage] */
	return buf;
}

void *
keepalived_malloc(size_t size, const char *file, const char *function, int line)
{
	return keepalived_malloc_common(size, file, function, line, "zalloc");
}

char *
keepalived_strdup(const char *str, const char *file, const char *function, int line)
{
	char *str_p;

	str_p = keepalived_malloc_common(strlen(str) + 1, file, function, line, "strdup");
	return strcpy(str_p, str);
}

char *
keepalived_strndup(const char *str, size_t size, const char *file, const char *function, int line)
{
	char *str_p;

	str_p = keepalived_malloc_common(size + 1, file, function, line, "strndup");
	return strncpy(str_p, str, size);
}

static void *
keepalived_free_realloc_common(void *buffer, size_t size, const char *file, const char *function, int line, bool is_realloc)
{
	unsigned long check;
	MEMCHECK *entry, *entry2, *le;
	MEMCHECK search = {.ptr = buffer};
#ifdef _NO_UNALIGNED_ACCESS_
	unsigned long check_val = CHECK_VAL;
#endif

	/* If nullpointer remember */
	if (buffer == NULL) {
		entry = get_free_alloc_entry();

		entry->ptr = NULL;
		entry->size = size;
		entry->file = file;
		entry->func = function;
		entry->line = line;
		entry->type = !size ? FREE_NULL : REALLOC_NULL;

		if (!is_realloc)
			fprintf(log_op, "%s%-7s%9s, %9s, %4s at %s, %3d, %s\n", format_time(),
				"free", "ERROR", "NULL", "",
				file, line, function);
		else
			fprintf(log_op, "%s%-7s%9s, %9s, %4zu at %s, %3d, %s%s\n", format_time(),
				"realloc", "ERROR", "NULL",
				size, file, line, function, size ? " *** converted to malloc" : "");

		__set_bit(MEM_ERR_DETECT_BIT, &debug);

		list_add_tail(&entry->l, &bad_list);

		return !size ? NULL : keepalived_malloc(size, file, function, line);
	}

	entry = rb_search(&alloc_list, &search, t, memcheck_ptr_cmp);

	/* Not found */
	if (!entry) {
		entry = get_free_alloc_entry();

		entry->ptr = buffer;
		entry->size = size;
		entry->file = file;
		entry->func = function;
		entry->line = line;
		entry->type = !size ? FREE_NOT_ALLOC : REALLOC_NOT_ALLOC;
		entry->seq_num = seq_num++;

		if (!is_realloc)
			fprintf(log_op, "%s%-7s%9s, %9p,      at %s, %3d, %s - not found\n", format_time(),
				"free", "ERROR",
				buffer, file, line, function);
		else
			fprintf(log_op, "%s%-7s%9s, %9p, %4zu at %s, %3d, %s - not found\n", format_time(),
				"realloc", "ERROR",
				buffer, size, file, line, function);

		__set_bit(MEM_ERR_DETECT_BIT, &debug);

		list_for_each_entry_reverse(le, &free_list, l) {
			if (le->ptr == buffer &&
			    le->type == LAST_FREE) {
				fprintf
				    (log_op, "%11s-> pointer last released at [%3u:%3u], at %s, %3d, %s\n",
				     "", le->seq_num, number_alloc_list,
				     le->file, le->line,
				     le->func);

				entry->type = !size ? DOUBLE_FREE : REALLOC_DOUBLE_FREE;
				break;
			}
		};

		list_add_tail(&entry->l, &bad_list);

		/* coverity[leaked_storage] */
		return NULL;
	}

	check = entry->size + CHECK_VAL;
#ifndef _NO_UNALIGNED_ACCESS_
	if (*(unsigned long *)((char *)buffer + entry->size) != check) {
#else
	if (memcmp((unsigned char *)buffer + entry->size, (unsigned char *)&check_val, sizeof(check_val))) {
#endif
		entry2 = get_free_alloc_entry();

		*entry2 = *entry;
		entry2->type = OVERRUN;
		list_add_tail(&entry2->l, &bad_list);

		fprintf(log_op, "%s%s corrupt, buffer overrun [%3u:%3u], %9p, %4zu at %s, %3d, %s\n",
		       format_time(), !is_realloc ? "free" : "realloc",
		       entry->seq_num, number_alloc_list, buffer,
		       entry->size, file,
		       line, function);
		dump_buffer(entry->ptr,
			    entry->size + sizeof (check), log_op, TIME_STR_LEN);
		fprintf(log_op, "%*sCheck_sum\n", TIME_STR_LEN, "");
		dump_buffer((char *) &check,
			    sizeof(check), log_op, TIME_STR_LEN);

		__set_bit(MEM_ERR_DETECT_BIT, &debug);
	}

	mem_allocated -= entry->size;

	if (!size) {
		free(buffer);

		if (is_realloc) {
			fprintf(log_op, "%s%-7s[%3u:%3u], %9p, %4zu at %s, %3d, %s -> %9s, %4s at %s, %3d, %s\n",
			       format_time(), "realloc", entry->seq_num,
			       number_alloc_list, entry->ptr,
			       entry->size, entry->file,
			       entry->line, entry->func,
			       "made free", "", file, line, function);

			/* Record bad realloc */
			entry2 = get_free_alloc_entry();
			*entry2 = *entry;
			entry2->type = REALLOC_ZERO_SIZE;
			entry2->file = file;
			entry2->line = line;
			entry2->func = function;
			list_add_tail(&entry2->l, &bad_list);
		}
		else
			fprintf(log_op, "%s%-7s[%3u:%3u], %9p, %4zu at %s, %3d, %s -> %9s, %4s at %s, %3d, %s\n",
			       format_time(), "free", entry->seq_num,
			       number_alloc_list, entry->ptr,
			       entry->size, entry->file,
			       entry->line, entry->func,
			       "NULL", "", file, line, function);
#ifdef _MEM_CHECK_LOG_
		if (__test_bit(MEM_CHECK_LOG_BIT, &debug))
			log_message(LOG_INFO, "%-7s[%3u:%3u], %9p, %4zu at %s, %3d, %s",
			       is_realloc ? "realloc" : "free",
			       entry->seq_num, number_alloc_list, buffer,
			       entry->size, file, line, function);
#endif

		entry->file = file;
		entry->line = line;
		entry->func = function;
		entry->type = LAST_FREE;

		rb_erase(&entry->t, &alloc_list);
		list_add_tail(&entry->l, &free_list);
		free_list_size++;

		number_alloc_list--;

		return NULL;
	}

	buffer = realloc(buffer, size + sizeof (unsigned long));
	mem_allocated += size;

	if (mem_allocated > max_mem_allocated)
		max_mem_allocated = mem_allocated;

	fprintf(log_op, "%srealloc[%3u:%3u], %9p, %4zu at %s, %3d, %s -> %9p, %4zu at %s, %3d, %s\n",
	       format_time(), entry->seq_num,
	       number_alloc_list, entry->ptr,
	       entry->size, entry->file,
	       entry->line, entry->func,
	       buffer, size, file, line, function);
#ifdef _MEM_CHECK_LOG_
	if (__test_bit(MEM_CHECK_LOG_BIT, &debug))
		log_message(LOG_INFO, "realloc[%3u:%3u], %9p, %4zu at %s, %3d, %s -> %9p, %4zu at %s, %3d, %s",
		       entry->seq_num, number_alloc_list, entry->ptr,
		       entry->size, entry->file,
		       entry->line, entry->func,
		       buffer, size, file, line, function);
#endif

#ifndef _NO_UNALIGNED_ACCESS_
	*(unsigned long *) ((char *) buffer + size) = size + CHECK_VAL;
#else
	memcpy((unsigned char *)buffer + size, (unsigned char *)&check_val, sizeof(check_val));
#endif

	if (entry->ptr != buffer) {
		rb_erase(&entry->t, &alloc_list);
		entry->ptr = buffer;
		rb_insert_sort(&alloc_list, entry, t, memcheck_ptr_cmp);
	} else
		entry->ptr = buffer;
	entry->size = size;
	entry->file = file;
	entry->line = line;
	entry->func = function;

	num_reallocs++;

	/* coverity[leaked_storage] */
	return buffer;
}

void
keepalived_free(void *buffer, const char *file, const char *function, int line)
{
	keepalived_free_realloc_common(buffer, 0, file, function, line, false);
}

void *
keepalived_realloc(void *buffer, size_t size, const char *file,
		   const char *function, int line)
{
	return keepalived_free_realloc_common(buffer, size, file, function, line, true);
}

static void
keepalived_alloc_log(bool final)
{
	unsigned int overrun = 0, badptr = 0, zero_size = 0;
	size_t sum = 0;
	MEMCHECK *entry;

	if (final) {
		/* If this is a forked child, we don't want the dump */
		if (skip_mem_check_final)
			return;

		fprintf(log_op, "\n---[ Keepalived memory dump for (%s) ]---\n\n", terminate_banner);
	}
	else
		fprintf(log_op, "\n---[ Keepalived memory dump for (%s) at %s ]---\n\n", terminate_banner, format_time());

	/* List the blocks currently allocated */
	if (!RB_EMPTY_ROOT(&alloc_list)) {
		fprintf(log_op, "Entries %s\n\n", final ? "not released" : "currently allocated");
		rb_for_each_entry(entry, &alloc_list, t) {
			sum += entry->size;
			fprintf(log_op, "%9p [%3u:%3u], %4zu at %s, %3d, %s",
			       entry->ptr, entry->seq_num, number_alloc_list,
			       entry->size, entry->file, entry->line, entry->func);
			if (entry->type != ALLOCATED)
				fprintf(log_op, " type = %u", entry->type);
			fprintf(log_op, "\n");
		}
	}

	if (!list_empty(&bad_list)) {
		if (!RB_EMPTY_ROOT(&alloc_list))
			fprintf(log_op, "\n");
		fprintf(log_op, "Bad entry list\n\n");

		list_for_each_entry(entry, &bad_list, l) {
			switch (entry->type) {
			case FREE_NULL:
				badptr++;
				fprintf(log_op, "%9s %9s, %4s at %s, %3d, %s - null pointer to free\n",
				       "NULL", "", "", entry->file, entry->line, entry->func);
				break;
			case REALLOC_NULL:
				badptr++;
				fprintf(log_op, "%9s %9s, %4zu at %s, %3d, %s - null pointer to realloc (converted to malloc)\n",
				     "NULL", "", entry->size, entry->file, entry->line, entry->func);
				break;
			case FREE_NOT_ALLOC:
				badptr++;
				fprintf(log_op, "%9p %9s, %4s at %s, %3d, %s - pointer not found for free\n",
				     entry->ptr, "", "", entry->file, entry->line, entry->func);
				break;
			case REALLOC_NOT_ALLOC:
				badptr++;
				fprintf(log_op, "%9p %9s, %4zu at %s, %3d, %s - pointer not found for realloc\n",
				     entry->ptr, "", entry->size, entry->file, entry->line, entry->func);
				break;
			case DOUBLE_FREE:
				badptr++;
				fprintf(log_op, "%9p %9s, %4s at %s, %3d, %s - double free of pointer\n",
				     entry->ptr, "", "", entry->file, entry->line, entry->func);
				break;
			case REALLOC_DOUBLE_FREE:
				badptr++;
				fprintf(log_op, "%9p %9s, %4zu at %s, %3d, %s - realloc 0 size already freed\n",
				     entry->ptr, "", entry->size, entry->file, entry->line, entry->func);
				break;
			case OVERRUN:
				overrun++;
				fprintf(log_op, "%9p [%3u:%3u], %4zu at %s, %3d, %s - buffer overrun\n",
				       entry->ptr, entry->seq_num, number_alloc_list,
				       entry->size, entry->file, entry->line, entry->func);
				break;
			case MALLOC_ZERO_SIZE:
				zero_size++;
				fprintf(log_op, "%9p [%3u:%3u], %4zu at %s, %3d, %s - malloc zero size\n",
				       entry->ptr, entry->seq_num, number_alloc_list,
				       entry->size, entry->file, entry->line, entry->func);
				break;
			case REALLOC_ZERO_SIZE:
				zero_size++;
				fprintf(log_op, "%9p [%3u:%3u], %4zu at %s, %3d, %s - realloc zero size (handled as free)\n",
				       entry->ptr, entry->seq_num, number_alloc_list,
				       entry->size, entry->file, entry->line, entry->func);
				break;
			case ALLOCATED:	/* not used - avoid compiler warning */
			case FREE_SLOT:
			case LAST_FREE:
				break;
			}
		}
	}

	fprintf(log_op, "\n\n---[ Keepalived memory dump summary for (%s) ]---\n", terminate_banner);
	fprintf(log_op, "Total number of bytes %s...: %zu\n", final ? "not freed" : "allocated", sum);
	fprintf(log_op, "Number of entries %s.......: %u\n", final ? "not freed" : "allocated", number_alloc_list);
	fprintf(log_op, "Maximum allocated entries.........: %u\n", max_alloc_list);
	fprintf(log_op, "Maximum memory allocated..........: %zu\n", max_mem_allocated);
	fprintf(log_op, "Number of mallocs.................: %u\n", num_mallocs);
	fprintf(log_op, "Number of reallocs................: %u\n", num_reallocs);
	fprintf(log_op, "Number of bad entries.............: %u\n", badptr);
	fprintf(log_op, "Number of buffer overrun..........: %u\n", overrun);
	fprintf(log_op, "Number of 0 size allocations......: %u\n\n", zero_size);
	if (sum != mem_allocated)
		fprintf(log_op, "ERROR - sum of allocated %zu != mem_allocated %zu\n", sum, mem_allocated);

	if (final) {
		if (sum || number_alloc_list || badptr || overrun)
			fprintf(log_op, "=> Program seems to have some memory problem !!!\n\n");
		else
			fprintf(log_op, "=> Program seems to be memory allocation safe...\n\n");
	}
}

static void
keepalived_free_final(void)
{
	keepalived_alloc_log(true);
}

void
keepalived_alloc_dump(void)
{
	keepalived_alloc_log(false);
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

	log_name_len = 5 + strlen(prog_name) + 5 + 7 + 4 + 1;	/* "/tmp/" + prog_name + "_mem." + PID + ".log" + '\0" */
	log_name = malloc(log_name_len);
	if (!log_name) {
		log_message(LOG_INFO, "Unable to malloc log file name");
		log_op = stderr;
		return;
	}

	snprintf(log_name, log_name_len, "/tmp/%s_mem.%d.log", prog_name, getpid());
	log_op = fopen_safe(log_name, "w");
	if (log_op == NULL) {
		log_message(LOG_INFO, "Unable to open %s for appending", log_name);
		log_op = stderr;
	}
	else {
		int fd = fileno(log_op);

		/* We don't want any children to inherit the log file */
		if (fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC))
			log_message(LOG_INFO, "Warning - failed to set CLOEXEC on log file %s", log_name);

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

void
update_mem_check_log_perms(mode_t umask_bits)
{
	if (log_op)
		fchmod(fileno(log_op), (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) & ~umask_bits);
}
#endif
