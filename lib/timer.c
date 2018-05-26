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

/* time_now holds current time */
timeval_t time_now;

timeval_t
timer_add_secs(timeval_t a, time_t secs)
{
	a.tv_sec += secs;

	return a;
}

timeval_t
timer_add_long(timeval_t a, unsigned long b)
{
	timeval_t ret;

	if (b == TIMER_NEVER)
	{
		ret.tv_usec = TIMER_HZ - 1;
		ret.tv_sec = LONG_MAX;

		return ret;
	}

	ret.tv_usec = a.tv_usec + (int)(b % TIMER_HZ);
	ret.tv_sec = a.tv_sec + (int)(b / TIMER_HZ);

	if (ret.tv_usec >= (int)TIMER_HZ) {
		ret.tv_sec++;
		ret.tv_usec -= TIMER_HZ;
	}

	return ret;
}

timeval_t
timer_sub_long(timeval_t a, unsigned long b)
{
	timeval_t ret;

	if (a.tv_usec < (int)(b % TIMER_HZ)) {
		a.tv_usec += TIMER_HZ;
		a.tv_sec--;
	}
	ret.tv_usec = a.tv_usec - (int)(b % TIMER_HZ);
	ret.tv_sec = a.tv_sec - (int)(b / TIMER_HZ);

	return ret;
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

	timerclear(now);

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
	if (timercmp(&adjusted, &mono_date, <))
		goto fixup;

	/* adjusted date is correct */
	mono_date = adjusted;
	*now = mono_date;
	return 0;

 fixup:
	/* Now we have to recompute the drift between sys_date and
	 * mono_date. Since it can be negative and we don't want to
	 * play with negative carries in all computations, we take
	 * care of always having the microseconds positive.
	 */
	timersub(&mono_date, &sys_date, &drift);
	*now = mono_date;
	return 0;
}

/* current time */
timeval_t
timer_now(void)
{
	timeval_t curr_time;

	/* init timer */
	monotonic_gettimeofday(&curr_time);

	return curr_time;
}

/* sets and returns current time from system time */
timeval_t
set_time_now(void)
{
	/* init timer */
	monotonic_gettimeofday(&time_now);

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
	unsigned long timer;
	timer = (unsigned long)a.tv_sec * TIMER_HZ + (unsigned long)a.tv_usec;
	return timer;
}

#ifdef _INCLUDE_UNUSED_CODE_
/* print timer value */
void
timer_dump(timeval_t a)
{
	printf("=> %lu (usecs)\n", timer_tol(a));
}
#endif
