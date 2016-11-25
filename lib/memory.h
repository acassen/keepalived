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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@linux-vs.org>
 */

#ifndef _MEMORY_H
#define _MEMORY_H

/* system includes */
#include <stdlib.h>
#include <stdbool.h>

/* Local defines */
#ifdef _MEM_CHECK_

#define MAX_ALLOC_LIST 2048

#define MALLOC(n)    ( keepalived_malloc((n), \
		      (__FILE__), (char *)(__FUNCTION__), (__LINE__)) )
#define FREE(b)      ( keepalived_free((b), \
		      (__FILE__), (char *)(__FUNCTION__), (__LINE__)), \
		       (b) = NULL )
#define REALLOC(b,n) ( keepalived_realloc((b), (n), \
		      (__FILE__), (char *)(__FUNCTION__), (__LINE__)) )

extern size_t mem_allocated;

/* Memory debug prototypes defs */
extern void *keepalived_malloc(size_t, char *, char *, int)
		__attribute__((alloc_size(1))) __attribute__((malloc));
extern int keepalived_free(void *, char *, char *, int);
extern void *keepalived_realloc(void *, size_t, char *, char *, int)
		__attribute__((alloc_size(2)));

extern void mem_log_init(const char *, const char *);
extern void skip_mem_dump(void);
extern void enable_mem_log_termination(void);

#else

extern void *zalloc(unsigned long size);

#define MALLOC(n)    (zalloc(n))
#define FREE(p)      (free(p), (p) = NULL)
#define REALLOC(p,n) (realloc((p),(n)))

#endif

/* Common defines */
#define FREE_PTR(p)	{ if (p) { FREE(p);} }
#endif
