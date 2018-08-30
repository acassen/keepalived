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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _TIMER_H
#define _TIMER_H

#include <sys/time.h>
#include <limits.h>
#include <string.h>

typedef struct timeval timeval_t;

/* Global vars */
extern timeval_t time_now;

/* Some defines */
#define TIMER_HZ		1000000U
#define TIMER_HZ_FLOAT		1000000.0
#define TIMER_CENTI_HZ		10000U
#define TIMER_MAX_SEC		1000U
#define TIMER_NEVER		ULONG_MAX	/* Used with time intervals in TIMER_HZ units */
#define TIMER_DISABLED		LONG_MIN	/* Value in timeval_t tv_sec */

#define	NSEC_PER_SEC		1000000000U	/* nanoseconds per second. Avoids typos by having a definition */

/* Some useful macros */
#define timer_long(T) (unsigned long)(((T).tv_sec * TIMER_HZ + (T).tv_usec))

#ifdef _TIMER_CHECK_
#define timer_now()	timer_now_r((__FILE__), (char *)(__FUNCTION__), (__LINE__))
#define set_time_now()	set_time_now_r((__FILE__), (char *)(__FUNCTION__), (__LINE__))
#endif

/* prototypes */
#ifdef _TIMER_CHECK_
extern timeval_t timer_now_r(const char *, const char *, int);
extern timeval_t set_time_now_r(const char *, const char *, int);
#else
extern timeval_t timer_now(void);
extern timeval_t set_time_now(void);
#endif
extern timeval_t timer_add_long(timeval_t, unsigned long);
extern timeval_t timer_sub_long(timeval_t, unsigned long);
extern timeval_t timer_sub_now(timeval_t);
extern timeval_t timer_add_now(timeval_t);
extern unsigned long timer_tol(timeval_t);
#ifdef _INCLUDE_UNUSED_CODE_
extern void timer_dump(timeval_t);
#endif

#endif
