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
#include <stdbool.h>

typedef struct timeval timeval_t;

/* Global vars */
extern timeval_t time_now;

#ifdef _TIMER_CHECK_
extern bool do_timer_check;
#endif

/* Some defines */
#define TIMER_HZ		1000000
#define TIMER_HZ_FLOAT		1000000.0F
#define TIMER_HZ_DOUBLE		((double)1000000.0F)
#define TIMER_CENTI_HZ		10000
#define TIMER_MAX_SEC		1000U
#define TIMER_NEVER		ULONG_MAX	/* Used with time intervals in TIMER_HZ units */
#define TIMER_DISABLED		LONG_MIN	/* Value in timeval_t tv_sec */

#define	NSEC_PER_SEC		1000000000	/* nanoseconds per second. Avoids typos by having a definition */

#ifdef _TIMER_CHECK_
#define timer_now()	timer_now_r((__FILE__), (__func__), (__LINE__))
#define set_time_now()	set_time_now_r((__FILE__), (__func__), (__LINE__))
#endif

#define RB_TIMER_CMP(obj)					\
static inline int						\
obj##_timer_cmp(const obj##_t *r1, const obj##_t *r2)		\
{								\
	if (r1->sands.tv_sec == TIMER_DISABLED) {		\
		if (r2->sands.tv_sec == TIMER_DISABLED)		\
			return 0;				\
		return 1;					\
	}							\
								\
	if (r2->sands.tv_sec == TIMER_DISABLED)			\
		return -1;					\
								\
	if (r1->sands.tv_sec != r2->sands.tv_sec)		\
		return r1->sands.tv_sec - r2->sands.tv_sec;	\
								\
	return r1->sands.tv_usec - r2->sands.tv_usec;		\
}

/* timer sub from current time */
static inline timeval_t
timer_sub_now(timeval_t a)
{
	timersub(&a, &time_now, &a);

	return a;
}

/* timer add to current time */
static inline timeval_t
timer_add_now(timeval_t a)
{
	timeradd(&time_now, &a, &a);

	return a;
}

/* Returns true if time a + diff_hz < time_now */
static inline bool
timer_cmp_now_diff(timeval_t a, unsigned long diff_hz)
{
	timeval_t b = { .tv_sec = diff_hz / TIMER_HZ, .tv_usec = diff_hz % TIMER_HZ };

	timeradd(&b, &a, &b);

	return !!timercmp(&b, &time_now, <);
}

/* Return time as unsigned long */
static inline unsigned long
timer_long(timeval_t a)
{
	return (unsigned long)a.tv_sec * TIMER_HZ + (unsigned long)a.tv_usec;
}

#ifdef _INCLUDE_UNUSED_CODE_
/* print timer value */
static inline void
timer_dump(timeval_t a)
{
	printf("=> %lu (usecs)\n", timer_tol(a));
}
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

#endif
