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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "timer.h"

/* time_now holds current time */
timeval_t time_now = { tv_sec: 0, tv_usec: 0 };

/* set a timer to a specific value */
timeval_t
timer_dup(timeval_t b)
{
	timeval_t a;

	timer_reset_lazy(a);
	a.tv_sec = b.tv_sec;
	a.tv_usec = b.tv_usec;
	return a;
}

/* timer compare */
int
timer_cmp(timeval_t a, timeval_t b)
{
	int ret = a.tv_sec - b.tv_sec;
	if (! ret)
		return a.tv_usec - b.tv_usec;
	return ret;
}

/* timer sub */
timeval_t
timer_sub(timeval_t a, timeval_t b)
{
	timeval_t ret;

	timer_reset_lazy(ret);
	ret.tv_usec = a.tv_usec - b.tv_usec;
	ret.tv_sec = a.tv_sec - b.tv_sec;

	if (ret.tv_usec < 0) {
		ret.tv_usec += TIMER_HZ;
		ret.tv_sec--;
	}

	return ret;
}

/* timer add */
timeval_t
timer_add(timeval_t a, timeval_t b)
{
	timeval_t ret;

	timer_reset_lazy(ret);
	ret.tv_usec = a.tv_usec + b.tv_usec;
	ret.tv_sec = a.tv_sec + b.tv_sec;

	if (ret.tv_usec >= TIMER_HZ) {
		ret.tv_sec++;
		ret.tv_usec -= TIMER_HZ;
	}

	return ret;
}

timeval_t
timer_add_long(timeval_t a, long b)
{
	timeval_t ret;

	timer_reset_lazy(ret);
	ret.tv_usec = a.tv_usec + b % TIMER_HZ;
	ret.tv_sec = a.tv_sec + b / TIMER_HZ;

	if (ret.tv_usec >= TIMER_HZ) {
		ret.tv_sec++;
		ret.tv_usec -= TIMER_HZ;
	}

	return ret;
}

/* This function is a wrapper for gettimeofday(). It uses local storage to
 * guarantee that the returned time will always be monotonic. If the time goes
 * backwards, it returns the same as previous one and readjust its internal
 * drift. If the time goes forward further than TIME_MAX_FORWARD_US
 * microseconds since last call, it will bound it to that value. It is designed
 * to be used as a drop-in replacement of gettimeofday(&now, NULL). It will
 * normally return 0, unless <now> is NULL, in which case it will return -1 and
 * set errno to EFAULT.
 */
int monotonic_gettimeofday(timeval_t *now)
{
	static timeval_t mono_date;
	static timeval_t drift; /* warning: signed seconds! */
	timeval_t sys_date, adjusted, deadline;

	if (!now) {
		errno = EFAULT;
		return -1;
	}

	timer_reset_lazy(*now);

	gettimeofday(&sys_date, NULL);

	/* on first call, we set mono_date to system date */
	if (mono_date.tv_sec == 0) {
		mono_date = sys_date;
		timer_reset(drift);
		*now = mono_date;
		return 0;
	}

	/* compute new adjusted time by adding the drift offset */
	adjusted = timer_add(sys_date, drift);

	/* check for jumps in the past, and bound to last date */
	if (timer_cmp(adjusted, mono_date) < 0)
		goto fixup;

	/* check for jumps too far in the future, and bound them to
	 * TIME_MAX_FORWARD_US microseconds.
	 */
	deadline = timer_add_long(mono_date, TIME_MAX_FORWARD_US);
	if (timer_cmp (adjusted, deadline) >= 0) {
		mono_date = deadline;
		goto fixup;
	}

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
	drift = timer_sub(mono_date, sys_date);
	*now = mono_date;
	return 0;
}

/* current time */
timeval_t
timer_now(void)
{
	timeval_t curr_time;
	int old_errno = errno;

	/* init timer */
	if (monotonic_gettimeofday(&curr_time)) {
		timer_reset(curr_time);
		errno = old_errno;
	}

	return curr_time;
}

/* sets and returns current time from system time */
timeval_t
set_time_now(void)
{
	int old_errno = errno;

	/* init timer */
	if (monotonic_gettimeofday(&time_now)) {
		timer_reset(time_now);
		errno = old_errno;
	}

	return time_now;
}

/* timer sub from current time */
timeval_t
timer_sub_now(timeval_t a)
{
	return timer_sub(time_now, a);
}

/* timer add to current time */
timeval_t
timer_add_now(timeval_t a)
{
	/* Init current time if needed */
	if (timer_isnull(time_now))
		set_time_now();

	return timer_add(time_now, a);
}

/* print timer value */
void
timer_dump(timeval_t a)
{
	unsigned long timer;
	timer = a.tv_sec * TIMER_HZ + a.tv_usec;
	printf("=> %lu (usecs)\n", timer);
}

unsigned long
timer_tol(timeval_t a)
{
	unsigned long timer;
	timer = a.tv_sec * TIMER_HZ + a.tv_usec;
	return timer;
}
