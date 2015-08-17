/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        timer.c include file.
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

#ifndef _TIMER_H
#define _TIMER_H

#include <sys/time.h>

typedef struct timeval timeval_t;

/* Global vars */
extern timeval_t time_now;

/* Some defines */
#define TIME_MAX_FORWARD_US	2000000
#define TIMER_HZ		1000000
#define TIMER_CENTI_HZ		10000
#define TIMER_MAX_SEC		1000

/* Some usefull macros */
#define timer_sec(T) ((T).tv_sec)
#define timer_long(T) ((T).tv_sec * TIMER_HZ + (T).tv_usec)
#define timer_isnull(T) ((T).tv_sec == 0 && (T).tv_usec == 0)
#define timer_reset(T) (memset(&(T), 0, sizeof(timeval_t)))
/* call this instead of timer_reset() when you intend to set
 * all the fields of timeval manually afterwards. */
#define timer_reset_lazy(T) do { \
	if ( sizeof((T)) != sizeof((T).tv_sec) + sizeof((T).tv_usec) ) \
		timer_reset((T)); \
	} while (0)

/* prototypes */
extern timeval_t timer_now(void);
extern timeval_t set_time_now(void);
extern timeval_t timer_dup(timeval_t);
extern int timer_cmp(timeval_t, timeval_t);
extern timeval_t timer_sub(timeval_t, timeval_t);
extern timeval_t timer_add(timeval_t, timeval_t);
extern timeval_t timer_add_long(timeval_t, long);
extern timeval_t timer_sub_now(timeval_t);
extern timeval_t timer_add_now(timeval_t);
extern void timer_dump(timeval_t);
extern unsigned long timer_tol(timeval_t);

#endif
