/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Timer manipulations.
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

#include "config.h"

#include <string.h>
#include <errno.h>
#include <sys/time.h>

#include "timer.h"
#ifdef _TIMER_CHECK_
#include "logger.h"
#endif

/* time_now holds current time */
timeval_t time_now;
#ifdef _TIMER_CHECK_
timeval_t last_time;
#endif

timeval_t
timer_add_long(timeval_t a, unsigned long b)
{
	if (b == TIMER_NEVER)
	{
		a.tv_usec = TIMER_HZ - 1;
		a.tv_sec = LONG_MAX;

		return a;
	}

	a.tv_usec += b % TIMER_HZ;
	a.tv_sec += b / TIMER_HZ;

	if (a.tv_usec >= TIMER_HZ) {
		a.tv_sec++;
		a.tv_usec -= TIMER_HZ;
	}

	return a;
}

timeval_t
timer_sub_long(timeval_t a, unsigned long b)
{
	if (a.tv_usec < (suseconds_t)(b % TIMER_HZ)) {
		a.tv_usec += TIMER_HZ;
		a.tv_sec--;
	}
	a.tv_usec -= b % TIMER_HZ;
	a.tv_sec -= b / TIMER_HZ;

	return a;
}

/* This function is a wrapper for gettimeofday(). It uses local storage to
 * guarantee that the returned time will always be monotonic. If the time goes
 * backwards, it returns the same as previous one and readjust its internal
 * drift. It is designed * to be used as a drop-in replacement of
 * gettimeofday(&now, NULL). It will normally return 0, unless <now> is NULL,
 * in which case it will return -1 and set errno to EFAULT.
 */
static int
monotonic_gettimeofday(timeval_t *now)
{
	static timeval_t mono_date;
	static timeval_t drift; /* warning: signed seconds! */
	timeval_t sys_date, adjusted;

	if (!now) {
		errno = EFAULT;
		return -1;
	}

	gettimeofday(&sys_date, NULL);

	/* on first call, we set mono_date to system date */
	if (mono_date.tv_sec == 0) {
		mono_date = sys_date;
		timerclear(&drift);
		*now = mono_date;
		return 0;
	}

	/* compute new adjusted time by adding the drift offset */
	timeradd(&sys_date, &drift, &adjusted);

	/* check for jumps in the past, and bound to last date */
	if (timercmp(&adjusted, &mono_date, >=)) {
		/* adjusted date is correct */
		mono_date = adjusted;
	} else {
		/* Now we have to recompute the drift between sys_date and
		 * mono_date. Since it can be negative and we don't want to
		 * play with negative carries in all computations, we take
		 * care of always having the microseconds positive.
		 */
		timersub(&mono_date, &sys_date, &drift);
	}

	*now = mono_date;
	return 0;
}

/* current time */
timeval_t
#ifdef _TIMER_CHECK_
timer_now_r(const char *file, const char *function, int line_no)
#else
timer_now(void)
#endif
{
	timeval_t curr_time;

	/* init timer */
	monotonic_gettimeofday(&curr_time);

#ifdef _TIMER_CHECK_
	unsigned long timediff = (curr_time.tv_sec - last_time.tv_sec) * 1000000 + curr_time.tv_usec - last_time.tv_usec;
	log_message(LOG_INFO, "timer_now called from %s %s:%d - difference %lu usec", file, function, line_no, timediff);
	last_time = curr_time;
#endif

	return curr_time;
}

/* sets and returns current time from system time */
timeval_t
#ifdef _TIMER_CHECK_
set_time_now_r(const char *file, const char *function, int line_no)
#else
set_time_now(void)
#endif
{
	/* init timer */
	monotonic_gettimeofday(&time_now);

#ifdef _TIMER_CHECK_
	unsigned long timediff = (time_now.tv_sec - last_time.tv_sec) * 1000000 + time_now.tv_usec - last_time.tv_usec;
	log_message(LOG_INFO, "set_time_now called from %s %s:%d, difference %lu usec", file, function, line_no, timediff);
	last_time = time_now;
#endif

	return time_now;
}

/* timer sub from current time */
timeval_t
timer_sub_now(timeval_t a)
{
	timersub(&a, &time_now, &a);

	return a;
}

/* timer add to current time */
timeval_t
timer_add_now(timeval_t a)
{
	/* Init current time if needed */
	if (!timerisset(&time_now))
		set_time_now();

	timeradd(&time_now, &a, &a);

	return a;
}

/* Return time as unsigned long */
unsigned long
timer_tol(timeval_t a)
{
	return (unsigned long)a.tv_sec * TIMER_HZ + (unsigned long)a.tv_usec;
}

#ifdef _INCLUDE_UNUSED_CODE_
/* print timer value */
void
timer_dump(timeval_t a)
{
	printf("=> %lu (usecs)\n", timer_tol(a));
}
#endif
