/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        memory.c include file.
 *
 * Version:     $Id: memory.h,v 1.0.1 2003/03/17 22:14:34 acassen Exp $
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
 */

#ifndef _MEMORY_H
#define _MEMORY_H

/* system includes */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Global var */
unsigned long mem_allocated;	/* Total memory used in Bytes */

/* extern types */
extern unsigned int debug;
extern unsigned long mem_allocated;
extern void *xalloc(unsigned long size);
extern void *zalloc(unsigned long size);
extern void xfree(void *p);

/* Global alloc macro */
#define ALLOC(n) (xalloc(n))

/* Local defines */
#ifdef _DEBUG_

#define MALLOC(n)    ( keepalived_malloc((n), \
                      (__FILE__), (__FUNCTION__), (__LINE__)) )
#define FREE(b)      ( keepalived_free((b), \
                      (__FILE__), (__FUNCTION__), (__LINE__)) )
#define REALLOC(b,n) ( keepalived_realloc((b), (n), \
                      (__FILE__), (__FUNCTION__), (__LINE__)) )

/* Memory debug prototypes defs */
extern char *keepalived_malloc(unsigned long, char *, char *, int);
extern int keepalived_free(void *, char *, char *, int);
extern void *keepalived_realloc(void *, unsigned long, char *, char *, int);
extern void keepalived_free_final(void);

#else

#define MALLOC(n)    (zalloc(n))
#define FREE(p)      (xfree(p))
#define REALLOC(p,n) (realloc((p),(n)))

#endif

/* Common defines */
#define FREE_PTR(P) if((P)) FREE((P));

#endif
