/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        memory.c include file.
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

#ifndef _MEMORY_H
#define _MEMORY_H

#include "config.h"

/* system includes */
#include <stddef.h>
#ifdef _MEM_CHECK_
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <stdlib.h>
#endif

/* Local defines */
#ifdef _MEM_CHECK_

#define MALLOC(n)    ( keepalived_malloc((n), \
		      (__FILE__), (__func__), (__LINE__)) )
#define STRDUP(p)    (keepalived_strdup((p), \
		      (__FILE__), (__func__), (__LINE__)) )
#define STRNDUP(p,n) (keepalived_strndup((p),(n), \
		      (__FILE__), (__func__), (__LINE__)) )
#define FREE(b)      ( keepalived_free((b), \
		      (__FILE__), (__func__), (__LINE__)), \
		       (b) = NULL )
#define FREE_ONLY(b) ( keepalived_free((b), \
		      (__FILE__), (__func__), (__LINE__)))
#define REALLOC(b,n) ( keepalived_realloc((b), (n), \
		      (__FILE__), (__func__), (__LINE__)) )

extern size_t mem_allocated;

/* Memory debug prototypes defs */
extern void memcheck_log(const char *, const char *, const char *, const char *, int);
extern void *keepalived_malloc(size_t, const char *, const char *, int)
		__attribute__((alloc_size(1))) __attribute__((malloc));
extern char *keepalived_strdup(const char *, const char *, const char *, int)
		__attribute__((malloc)) __attribute__((nonnull (1)));
extern char *keepalived_strndup(const char *, size_t, const char *, const char *, int)
		__attribute__((malloc)) __attribute__((nonnull (1)));
extern void keepalived_free(void *, const char *, const char *, int);
extern void *keepalived_realloc(void *, size_t, const char *, const char *, int)
		__attribute__((alloc_size(2)));

extern void keepalived_alloc_dump(void);
extern void mem_log_init(const char *, const char *);
extern void skip_mem_dump(void);
extern void enable_mem_log_termination(void);

extern void update_mem_check_log_perms(mode_t);
#else

extern void *zalloc(unsigned long size);

#define MALLOC(n)    (zalloc(n))
#define FREE(p)      (free(p), (p) = NULL)
#define FREE_ONLY(p) (free(p))
#define REALLOC(p,n) (realloc((p),(n)))
#define STRDUP(p)    (strdup(p))
#define STRNDUP(p,n) (strndup((p),(n)))

#endif

/* Common defines */
typedef union _ptr_hack {
	void *p;
	const void *cp;
} ptr_hack_t;

#define FREE_CONST(ptr) { ptr_hack_t ptr_hack = { .cp = ptr }; FREE(ptr_hack.p); }
#define FREE_CONST_ONLY(ptr) { ptr_hack_t ptr_hack = { .cp = ptr }; FREE_ONLY(ptr_hack.p); }
#define REALLOC_CONST(ptr, n) ({ ptr_hack_t ptr_hack = { .cp = ptr }; REALLOC(ptr_hack.p, n); })

#define PMALLOC(p)	{ p = MALLOC(sizeof(*p)); }
#define FREE_PTR(p)	{ if (p) { FREE(p);} }
#define FREE_CONST_PTR(p) { if (p) { FREE_CONST(p);} }
#endif
