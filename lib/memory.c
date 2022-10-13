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
#ifdef _OPENSSL_MEM_CHECK_
#include <openssl/crypto.h>
#endif


#include <errno.h>
#include <string.h>

#include "memory.h"
#include "utils.h"
#include "bitops.h"
#include "logger.h"
#include "scheduler.h"
#include "process.h"

#ifdef _MEM_CHECK_
#include "align.h"
#include "timer.h"
#include "rbtree_ka.h"
#include "list_head.h"
#endif

#define SRC_LOC_FMT	"%s:%d%s%s%s"
#define FUNC_PARAMS(func) func ? " (" : "", func ? func : "", func ? ")" : ""

struct mem_domain
{
	size_t mem_allocated;		/* Total memory used in Bytes */
	size_t max_mem_allocated;	/* Maximum memory used in Bytes */

	const char *terminate_banner;	/* banner string for report file */

	bool skip_mem_check_final;	/* Set for child processes of the keepalived process */
#ifdef _MEM_ERR_DEBUG_
	bool do_mem_err_debug;		/* keepalived terminates if there is a bad call */
#endif
	bool clear_alloc;		/* Initialise allocated memory to 0s */
	bool ignore_invalid;		/* Report free reallocs with NULL buffers, but don't queue them */

	unsigned number_alloc_list;	/* number of alloc_list allocation entries */
	unsigned max_alloc_list;
	unsigned num_mallocs;
	unsigned num_reallocs;
	unsigned seq_num;

	FILE *log_op;

	/* alloc_list entries used for 1000 VRRP instance each with VMAC interfaces is 33589 */
	rb_root_t alloc_list;
	list_head_t bad_list;
};

#ifdef _MEM_CHECK_
static struct mem_domain keepalived_mem = { .log_op = NULL, .clear_alloc = true, .ignore_invalid = false, .alloc_list = RB_ROOT, .bad_list = LIST_HEAD_INITIALIZER(keepalived_mem.bad_list) };
#endif
#ifdef _OPENSSL_MEM_CHECK_
static struct mem_domain openssl_mem = { .log_op = NULL, .clear_alloc = false, .ignore_invalid = true, .alloc_list = RB_ROOT, .bad_list = LIST_HEAD_INITIALIZER(openssl_mem.bad_list) };
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
#ifdef _MALLOC_CHECK_
	else {
		log_message(LOG_ERR, "zalloc(%zu) returned NULL", size);
		exit(1);
	}
#endif

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
static LIST_HEAD_INITIALIZE(free_list);
static unsigned free_list_size;

static inline int
memcheck_ptr_cmp(const void *key, const struct rb_node *a)
{
	return (const char *)key - (char *)rb_entry_const(a, MEMCHECK, t)->ptr;
}

static inline bool
memcheck_ptr_less(struct rb_node *a, const struct rb_node *b)
{
	return rb_entry(a, MEMCHECK, t)->ptr < rb_entry_const(b, MEMCHECK, t)->ptr;
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
	if (!__test_bit(MEM_CHECK_BIT, &debug))
		return;

	int len = strlen(called_func) + (param ? strlen(param) : 0);

	if ((len = 36 - len) < 0)
		len = 0;

	fprintf(keepalived_mem.log_op, "%s%*s%s(%s) at " SRC_LOC_FMT "\n",
	       format_time(), len, "", called_func, param ? param : "", file, line, FUNC_PARAMS(function));
}

static MEMCHECK *
get_free_alloc_entry(struct mem_domain *mem)
{
	MEMCHECK *entry;

	/* If number on free list < 256, allocate new entry, otherwise take head */
	if (free_list_size < 256)
		entry = malloc(sizeof *entry);
	else {
		entry = list_first_entry(&free_list, MEMCHECK, l);
		list_del_init(&entry->l);
		free_list_size--;
	}

	entry->seq_num = mem->seq_num++;

	return entry;
}

static void *
keepalived_malloc_common(struct mem_domain *mem, size_t size, const char *file, const char *function, int line, const char *name)
{
	void *buf;
	MEMCHECK *entry, *entry2;

	if (mem->clear_alloc)
		buf = zalloc(size + sizeof (unsigned long));
	else
		buf = malloc(size + sizeof (unsigned long));

	mem->mem_allocated += size;
	if (mem->mem_allocated > mem->max_mem_allocated)
		mem->max_mem_allocated = mem->mem_allocated;

#ifndef _NO_UNALIGNED_ACCESS_
	*(unsigned long *) PTR_CAST_ASSIGN((char *) buf + size) = size + CHECK_VAL;
#else
	unsigned long check_val = size + CHECK_VAL;

	memcpy((unsigned char *)buf + size, (unsigned char *)&check_val, sizeof(check_val));
#endif

	entry = get_free_alloc_entry(mem);

	entry->ptr = buf;
	entry->size = size;
	entry->file = file;
	entry->func = function;
	entry->line = line;
	entry->type = ALLOCATED;

	rb_add(&entry->t, &mem->alloc_list, memcheck_ptr_less);
	if (++mem->number_alloc_list > mem->max_alloc_list)
		mem->max_alloc_list = mem->number_alloc_list;

	fprintf(mem->log_op, "%s%s [%3u:%3u], %9p, %4zu at " SRC_LOC_FMT "%s\n",
	       format_time(), name, entry->seq_num, mem->number_alloc_list, buf, size, file, line, FUNC_PARAMS(function), !size ? " - size is 0" : "");
#ifdef _MEM_CHECK_LOG_
	if (__test_bit(MEM_CHECK_LOG_BIT, &debug))
		log_message(LOG_INFO, "%s[%3u:%3u], %9p, %4zu at " SRC_LOC_FMT,
		       name, entry->seq_num, mem->number_alloc_list, buf, size, file, line, FUNC_PARAMS(function));
#endif

	mem->num_mallocs++;

	if (!size) {
		/* Record malloc with 0 size */
		entry2 = get_free_alloc_entry(mem);
		*entry2 = *entry;
		entry2->type = MALLOC_ZERO_SIZE;
		list_add_tail(&entry2->l, &mem->bad_list);
	}

	/* coverity[leaked_storage] */
	return buf;
}

void *
keepalived_malloc(size_t size, const char *file, const char *function, int line)
{
	if (!__test_bit(MEM_CHECK_BIT, &debug))
		return zalloc(size);

	return keepalived_malloc_common(&keepalived_mem, size, file, function, line, "zalloc");
}

char *
keepalived_strdup(const char *str, const char *file, const char *function, int line)
{
	char *str_p;

	if (!__test_bit(MEM_CHECK_BIT, &debug)) {
#ifdef _MALLOC_CHECK_
		return strdup_check(str);
#else
		return strdup(str);
#endif
	}

	str_p = keepalived_malloc_common(&keepalived_mem, strlen(str) + 1, file, function, line, "strdup");
	return strcpy(str_p, str);
}

char *
keepalived_strndup(const char *str, size_t size, const char *file, const char *function, int line)
{
	char *str_p;

	if (!__test_bit(MEM_CHECK_BIT, &debug))
#ifdef _MALLOC_CHECK_
		return strndup_check(str, size);
#else
		return strndup(str, size);
#endif

	/* Note: keepalived_malloc_common initialises allocated memory to 0s.
	 * This means that after the strncpy, str_p will be NULL terminated. */
	str_p = keepalived_malloc_common(&keepalived_mem, size + 1, file, function, line, "strndup");
	return strncpy(str_p, str, size);
}

static void *
keepalived_free_realloc_common(struct mem_domain *mem, void *buffer, size_t size, const char *file, const char *function, int line, bool is_realloc)
{
	unsigned long check;
	MEMCHECK *entry, *entry2, *le;
	rb_node_t *entry_rb;
#ifdef _NO_UNALIGNED_ACCESS_
	unsigned long check_val;
#endif

	/* If nullpointer remember */
	if (buffer == NULL) {
		if (!mem->ignore_invalid) {
			entry = get_free_alloc_entry(mem);

			entry->ptr = NULL;
			entry->size = size;
			entry->file = file;
			entry->func = function;
			entry->line = line;
			entry->type = !!is_realloc ? FREE_NULL : REALLOC_NULL;

			list_add_tail(&entry->l, &mem->bad_list);
		}

		if (!is_realloc)
			fprintf(mem->log_op, "%s%-7s%9s, %9s, %4s at " SRC_LOC_FMT "\n", format_time(),
				"free", "ERROR", "NULL", "",
				file, line, FUNC_PARAMS(function));
		else
			fprintf(mem->log_op, "%s%-7s%9s, %9s, %4zu at " SRC_LOC_FMT "%s\n", format_time(),
				"realloc", "ERROR", "NULL",
				size, file, line, FUNC_PARAMS(function), size ? " *** converted to malloc" : "");

#ifdef _MEM_ERR_DEBUG_
		if (mem->do_mem_err_debug)
			__set_bit(MEM_ERR_DETECT_BIT, &debug);
#endif

		return !size ? NULL : keepalived_malloc_common(mem, size, file, function, line, mem->clear_alloc ? "zalloc" : "malloc");
	}

	entry_rb = rb_find(buffer, &mem->alloc_list, memcheck_ptr_cmp);

	/* Not found */
	if (!entry_rb) {
		entry = get_free_alloc_entry(mem);

		entry->ptr = buffer;
		entry->size = size;
		entry->file = file;
		entry->func = function;
		entry->line = line;
		entry->type = !is_realloc ? FREE_NOT_ALLOC : REALLOC_NOT_ALLOC;
		entry->seq_num = mem->seq_num++;

		if (!is_realloc)
			fprintf(mem->log_op, "%s%-7s%9s, %9p,      at " SRC_LOC_FMT " - not found\n", format_time(),
				"free", "ERROR",
				buffer, file, line, FUNC_PARAMS(function));
		else
			fprintf(mem->log_op, "%s%-7s%9s, %9p, %4zu at " SRC_LOC_FMT " - not found\n", format_time(),
				"realloc", "ERROR",
				buffer, size, file, line, FUNC_PARAMS(function));

#ifdef _MEM_ERR_DEBUG_
		if (mem->do_mem_err_debug)
			__set_bit(MEM_ERR_DETECT_BIT, &debug);
#endif

		list_for_each_entry_reverse(le, &free_list, l) {
			if (le->ptr == buffer &&
			    le->type == LAST_FREE) {
				fprintf
				    (mem->log_op, "%11s-> pointer last released at [%3u:%3u], at " SRC_LOC_FMT "\n",
				     "", le->seq_num, mem->number_alloc_list,
				     le->file, le->line,
				     FUNC_PARAMS(le->func));

				entry->type = !is_realloc ? DOUBLE_FREE : REALLOC_DOUBLE_FREE;
				break;
			}
		};

		list_add_tail(&entry->l, &mem->bad_list);

		/* coverity[leaked_storage] */
		return NULL;
	} else
		entry = rb_entry(entry_rb, MEMCHECK, t);

	check = entry->size + CHECK_VAL;
#ifndef _NO_UNALIGNED_ACCESS_
	if (*(unsigned long *) PTR_CAST_ASSIGN((char *)buffer + entry->size) != check) {
#else
	if (memcmp((unsigned char *)buffer + entry->size, (unsigned char *)&check, sizeof(check))) {
#endif
		entry2 = get_free_alloc_entry(mem);

		*entry2 = *entry;
		entry2->type = OVERRUN;
		list_add_tail(&entry2->l, &mem->bad_list);

		fprintf(mem->log_op, "%s%s corrupt, buffer overrun [%3u:%3u], %9p, %4zu at " SRC_LOC_FMT "\n",
		       format_time(), !is_realloc ? "free" : "realloc",
		       entry->seq_num, mem->number_alloc_list, buffer,
		       entry->size, file,
		       line, FUNC_PARAMS(function));
		dump_buffer(entry->ptr,
			    entry->size + sizeof (check), mem->log_op, TIME_STR_LEN);
		fprintf(mem->log_op, "%*sCheck_sum\n", TIME_STR_LEN, "");
		dump_buffer((char *) &check,
			    sizeof(check), mem->log_op, TIME_STR_LEN);

#ifdef _MEM_ERR_DEBUG_
		if (mem->do_mem_err_debug)
			__set_bit(MEM_ERR_DETECT_BIT, &debug);
#endif
	}

	mem->mem_allocated -= entry->size;

	if (!size) {
		free(buffer);

		if (is_realloc) {
			fprintf(mem->log_op, "%s%-7s[%3u:%3u], %9p, %4zu at " SRC_LOC_FMT " -> %9s, %4s at " SRC_LOC_FMT "\n",
			       format_time(), "realloc", entry->seq_num,
			       mem->number_alloc_list, entry->ptr,
			       entry->size, entry->file,
			       entry->line, FUNC_PARAMS(entry->func),
			       "made free", "", file, line, FUNC_PARAMS(function));

			/* Record bad realloc */
			entry2 = get_free_alloc_entry(mem);
			*entry2 = *entry;
			entry2->type = REALLOC_ZERO_SIZE;
			entry2->file = file;
			entry2->line = line;
			entry2->func = function;
			list_add_tail(&entry2->l, &mem->bad_list);
		}
		else
			fprintf(mem->log_op, "%s%-7s[%3u:%3u], %9p, %4zu at " SRC_LOC_FMT " -> %9s, %4s at " SRC_LOC_FMT "\n",
			       format_time(), "free", entry->seq_num,
			       mem->number_alloc_list, entry->ptr,
			       entry->size, entry->file,
			       entry->line, FUNC_PARAMS(entry->func),
			       "NULL", "", file, line, FUNC_PARAMS(function));
#ifdef _MEM_CHECK_LOG_
		if (__test_bit(MEM_CHECK_LOG_BIT, &debug))
			log_message(LOG_INFO, "%-7s[%3u:%3u], %9p, %4zu at " SRC_LOC_FMT,
			       is_realloc ? "realloc" : "free",
			       entry->seq_num, mem->number_alloc_list, buffer,
			       entry->size, file, line, FUNC_PARAMS(function));
#endif

		entry->file = file;
		entry->line = line;
		entry->func = function;
		entry->type = LAST_FREE;

		rb_erase(&entry->t, &mem->alloc_list);
		list_add_tail(&entry->l, &free_list);
		free_list_size++;

		mem->number_alloc_list--;

		/* coverity[leaked_storage] - entry2 is added to the bad_list */
		return NULL;
	}

	buffer = realloc(buffer, size + sizeof (unsigned long));
	mem->mem_allocated += size;

	if (mem->mem_allocated > mem->max_mem_allocated)
		mem->max_mem_allocated = mem->mem_allocated;

	fprintf(mem->log_op, "%srealloc[%3u:%3u], %9p, %4zu at " SRC_LOC_FMT " -> %9p, %4zu at " SRC_LOC_FMT "\n",
	       format_time(), entry->seq_num,
	       mem->number_alloc_list, entry->ptr,
	       entry->size, entry->file,
	       entry->line, FUNC_PARAMS(entry->func),
	       buffer, size, file, line, FUNC_PARAMS(function));
#ifdef _MEM_CHECK_LOG_
	if (__test_bit(MEM_CHECK_LOG_BIT, &debug))
		log_message(LOG_INFO, "realloc[%3u:%3u], %9p, %4zu at " SRC_LOC_FMT " -> %9p, %4zu at " SRC_LOC_FMT,
		       entry->seq_num, mem->number_alloc_list, entry->ptr,
		       entry->size, entry->file,
		       entry->line, FUNC_PARAMS(entry->func),
		       buffer, size, file, line, FUNC_PARAMS(function));
#endif

#ifndef _NO_UNALIGNED_ACCESS_
	*(unsigned long *) PTR_CAST_ASSIGN((char *) buffer + size) = size + CHECK_VAL;
#else
	check_val = size + CHECK_VAL;
	memcpy((unsigned char *)buffer + size, (unsigned char *)&check_val, sizeof(check_val));
#endif

	if (entry->ptr != buffer) {
		rb_erase(&entry->t, &mem->alloc_list);
		entry->ptr = buffer;
		rb_add(&entry->t, &mem->alloc_list, memcheck_ptr_less);
	} else
		entry->ptr = buffer;
	entry->size = size;
	entry->file = file;
	entry->line = line;
	entry->func = function;

	mem->num_reallocs++;

	/* coverity[leaked_storage] */
	return buffer;
}

void
keepalived_free(void *buffer, const char *file, const char *function, int line)
{
	if (!__test_bit(MEM_CHECK_BIT, &debug)) {
		free(buffer);
		return;
	}

	keepalived_free_realloc_common(&keepalived_mem, buffer, 0, file, function, line, false);
}

void *
keepalived_realloc(void *buffer, size_t size, const char *file,
		   const char *function, int line)
{
	if (!__test_bit(MEM_CHECK_BIT, &debug)) {
#ifdef _MALLOC_CHECK_
		return realloc_check(buffer, size);
#else
		return realloc(buffer, size);
#endif
	}

	return keepalived_free_realloc_common(&keepalived_mem, buffer, size, file, function, line, true);
}

static void
keepalived_alloc_log(struct mem_domain *mem, bool final)
{
	unsigned int overrun = 0, badptr = 0, zero_size = 0;
	size_t sum = 0;
	MEMCHECK *entry;

	if (final) {
		/* If this is a forked child, we don't want the dump */
		if (mem->skip_mem_check_final)
			return;

		fprintf(mem->log_op, "\n---[ Keepalived memory dump for (%s) ]---\n\n", mem->terminate_banner);
	}
	else
		fprintf(mem->log_op, "\n---[ Keepalived memory dump for (%s) at %s ]---\n\n", mem->terminate_banner, format_time());

	/* List the blocks currently allocated */
	if (!RB_EMPTY_ROOT(&mem->alloc_list)) {
		fprintf(mem->log_op, "Entries %s\n\n", final ? "not released" : "currently allocated");
		rb_for_each_entry(entry, &mem->alloc_list, t) {
			sum += entry->size;
			fprintf(mem->log_op, "%9p [%3u:%3u], %4zu at " SRC_LOC_FMT,
			       entry->ptr, entry->seq_num, mem->number_alloc_list,
			       entry->size, entry->file, entry->line, FUNC_PARAMS(entry->func));
			if (entry->type != ALLOCATED)
				fprintf(mem->log_op, " type = %u", entry->type);
			fprintf(mem->log_op, "\n");
		}
	}

	if (!list_empty(&mem->bad_list)) {
		if (!RB_EMPTY_ROOT(&mem->alloc_list))
			fprintf(mem->log_op, "\n");
		fprintf(mem->log_op, "Bad entry list\n\n");

		list_for_each_entry(entry, &mem->bad_list, l) {
			switch (entry->type) {
			case FREE_NULL:
				badptr++;
				fprintf(mem->log_op, "%9s %9s, %4s at " SRC_LOC_FMT " - null pointer to free\n",
				       "NULL", "", "", entry->file, entry->line, FUNC_PARAMS(entry->func));
				break;
			case REALLOC_NULL:
				badptr++;
				fprintf(mem->log_op, "%9s %9s, %4zu at " SRC_LOC_FMT " - null pointer to realloc (converted to malloc)\n",
				     "NULL", "", entry->size, entry->file, entry->line, FUNC_PARAMS(entry->func));
				break;
			case FREE_NOT_ALLOC:
				badptr++;
				fprintf(mem->log_op, "%9p %9s, %4s at " SRC_LOC_FMT " - pointer not found for free\n",
				     entry->ptr, "", "", entry->file, entry->line, FUNC_PARAMS(entry->func));
				break;
			case REALLOC_NOT_ALLOC:
				badptr++;
				fprintf(mem->log_op, "%9p %9s, %4zu at " SRC_LOC_FMT " - pointer not found for realloc\n",
				     entry->ptr, "", entry->size, entry->file, entry->line, FUNC_PARAMS(entry->func));
				break;
			case DOUBLE_FREE:
				badptr++;
				fprintf(mem->log_op, "%9p %9s, %4s at " SRC_LOC_FMT " - double free of pointer\n",
				     entry->ptr, "", "", entry->file, entry->line, FUNC_PARAMS(entry->func));
				break;
			case REALLOC_DOUBLE_FREE:
				badptr++;
				fprintf(mem->log_op, "%9p %9s, %4zu at " SRC_LOC_FMT " - realloc 0 size already freed\n",
				     entry->ptr, "", entry->size, entry->file, entry->line, FUNC_PARAMS(entry->func));
				break;
			case OVERRUN:
				overrun++;
				fprintf(mem->log_op, "%9p [%3u:%3u], %4zu at " SRC_LOC_FMT " - buffer overrun\n",
				       entry->ptr, entry->seq_num, mem->number_alloc_list,
				       entry->size, entry->file, entry->line, FUNC_PARAMS(entry->func));
				break;
			case MALLOC_ZERO_SIZE:
				zero_size++;
				fprintf(mem->log_op, "%9p [%3u:%3u], %4zu at " SRC_LOC_FMT " - malloc zero size\n",
				       entry->ptr, entry->seq_num, mem->number_alloc_list,
				       entry->size, entry->file, entry->line, FUNC_PARAMS(entry->func));
				break;
			case REALLOC_ZERO_SIZE:
				zero_size++;
				fprintf(mem->log_op, "%9p [%3u:%3u], %4zu at " SRC_LOC_FMT " - realloc zero size (handled as free)\n",
				       entry->ptr, entry->seq_num, mem->number_alloc_list,
				       entry->size, entry->file, entry->line, FUNC_PARAMS(entry->func));
				break;
			case ALLOCATED:	/* not used - avoid compiler warning */
			case FREE_SLOT:
			case LAST_FREE:
				break;
			}
		}
	}

	fprintf(mem->log_op, "\n\n---[ Keepalived memory dump summary for (%s) ]---\n", mem->terminate_banner);
	fprintf(mem->log_op, "Total number of bytes %s...: %zu\n", final ? "not freed" : "allocated", sum);
	fprintf(mem->log_op, "Number of entries %s.......: %u\n", final ? "not freed" : "allocated", mem->number_alloc_list);
	fprintf(mem->log_op, "Maximum allocated entries.........: %u\n", mem->max_alloc_list);
	fprintf(mem->log_op, "Maximum memory allocated..........: %zu\n", mem->max_mem_allocated);
	fprintf(mem->log_op, "Number of mallocs.................: %u\n", mem->num_mallocs);
	fprintf(mem->log_op, "Number of reallocs................: %u\n", mem->num_reallocs);
	fprintf(mem->log_op, "Number of bad entries.............: %u\n", badptr);
	fprintf(mem->log_op, "Number of buffer overrun..........: %u\n", overrun);
	fprintf(mem->log_op, "Number of 0 size allocations......: %u\n\n", zero_size);
	if (sum != mem->mem_allocated)
		fprintf(mem->log_op, "ERROR - sum of allocated %zu != mem_allocated %zu\n", sum, mem->mem_allocated);

	if (final) {
		if (sum || mem->number_alloc_list || badptr || overrun)
			fprintf(mem->log_op, "=> Program seems to have some memory problem !!!\n\n");
		else
			fprintf(mem->log_op, "=> Program seems to be memory allocation safe...\n\n");
	}
}

static void
keepalived_free_final(void)
{
	if (!__test_bit(MEM_CHECK_BIT, &debug))
		return;

	keepalived_alloc_log(&keepalived_mem, true);
}

void
keepalived_alloc_dump(void)
{
	if (!__test_bit(MEM_CHECK_BIT, &debug))
		return;

	keepalived_alloc_log(&keepalived_mem, false);
}

static void
mem_log_init_common(struct mem_domain *mem, const char* prog_name, const char *banner)
{
	size_t log_name_len;
	char *log_name;

	if (__test_bit(LOG_CONSOLE_BIT, &debug)) {
		mem->log_op = stderr;
		return;
	}

	if (mem->log_op)
		fclose(mem->log_op);

	log_name_len = strlen(tmp_dir) + 1 + strlen(prog_name) + 5 + PID_MAX_DIGITS + 4 + 1;	/* tmp_dir + "/" + prog_name + "_mem." + PID + ".log" + '\0" */
	log_name = malloc(log_name_len);
	if (!log_name) {
		log_message(LOG_INFO, "Unable to malloc log file name");
		mem->log_op = stderr;
		return;
	}

	snprintf(log_name, log_name_len, "%s/%s_mem.%d.log", tmp_dir, prog_name, getpid());
	mem->log_op = fopen_safe(log_name, "w");
	if (mem->log_op == NULL) {
		log_message(LOG_INFO, "Unable to open %s for appending", log_name);
		mem->log_op = stderr;
	}
	else {
		int fd = fileno(mem->log_op);

		/* We don't want any children to inherit the log file */
		if (fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC))
			log_message(LOG_INFO, "Warning - failed to set CLOEXEC on log file %s", log_name);

		/* Make the log output line buffered. This was to ensure that
		 * children didn't inherit the buffer, but the CLOEXEC above
		 * should resolve that. */
		setlinebuf(mem->log_op);

		fprintf(mem->log_op, "\n");
	}

	free(log_name);

	mem->terminate_banner = banner;
}

void
skip_mem_dump(void)
{
	keepalived_mem.skip_mem_check_final = true;
}

void
enable_mem_log_termination(void)
{
	atexit(keepalived_free_final);
}

void
update_mem_check_log_perms(mode_t umask_bits)
{
	if (keepalived_mem.log_op)
		fchmod(fileno(keepalived_mem.log_op), (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) & ~umask_bits);
}

void
log_mem_check_message(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(keepalived_mem.log_op, format, args);
	va_end(args);
	fprintf(keepalived_mem.log_op, "\n");
}
#endif

#ifdef _MEM_CHECK_
size_t
get_keepalived_cur_mem_allocated(void)
{
	return keepalived_mem.mem_allocated;
}

#ifdef _MEM_ERR_DEBUG_
void
set_keepalived_mem_err_debug(bool state)
{
	keepalived_mem.do_mem_err_debug = state;
}

bool
get_keepalived_mem_err_debug(void)
{
	return keepalived_mem.do_mem_err_debug;
}
#endif

void
mem_log_init(const char* prog_name, const char *banner)
{
	mem_log_init_common(&keepalived_mem, prog_name, banner);
}
#endif

#ifdef _OPENSSL_MEM_CHECK_
static void *
openssl_malloc(size_t size, const char *file, int line)
{
	return keepalived_malloc_common(&openssl_mem, size, file, NULL, line, "malloc");
}

static void
openssl_free(void *buffer, const char *file, int line)
{
	keepalived_free_realloc_common(&openssl_mem, buffer, 0, file, NULL, line, false);
}

static void *
openssl_realloc(void *buffer, size_t size, const char *file,
		   int line)
{
	return keepalived_free_realloc_common(&openssl_mem, buffer, size, file, NULL, line, true);
}

static void
openssl_free_final(void)
{
	keepalived_alloc_log(&openssl_mem, true);
}

void
openssl_mem_log_init(const char* prog_name, const char *banner)
{
	mem_log_init_common(&openssl_mem, prog_name, banner);

	if (!CRYPTO_set_mem_functions(&openssl_malloc, &openssl_realloc, &openssl_free))
		log_message(LOG_INFO, "Failed to set OpenSSL memory functions");
	else
		log_message(LOG_INFO, "OpenSSL memory functions set");

	atexit(openssl_free_final);
}
#endif
