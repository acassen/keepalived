/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        timer.c include file.
 *  
 * Version:     $Id: timer.h,v 1.1.2 2003/09/08 01:18:41 acassen Exp $
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
 * Copyright (C) 2001, 2002, 2003 Alexandre Cassen, <acassen@linux-vs.org>
 */

#ifndef _TIMER_H
#define _TIMER_H

#include <sys/time.h>

typedef struct timeval TIMEVAL;

/* macro utilities */
#define TIMER_HZ      1000000
#define TIMER_MAX_SEC 1000
#define TIMER_SEC(T) ((T).tv_sec)
#define TIMER_ISNULL(T) ((T).tv_sec == 0 && (T).tv_usec == 0)
#define TIMER_RESET(T) (memset(&(T), 0, sizeof(struct timeval)))
#define TIMER_MICRO_ADJUST(T) ((T) = ((T) < TIMER_MAX_SEC)?TIMER_MAX_SEC:(T))

/* prototypes */
extern TIMEVAL timer_now(void);
extern TIMEVAL timer_dup(TIMEVAL b);
extern int timer_cmp(TIMEVAL a, TIMEVAL b);
extern TIMEVAL timer_sub(TIMEVAL a, TIMEVAL b);
extern TIMEVAL timer_sub_now(TIMEVAL a);
extern void timer_dump(TIMEVAL a);
extern unsigned long timer_tol(TIMEVAL a);

#endif
