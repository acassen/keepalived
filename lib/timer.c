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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "timer.h"

/* time_now holds current time */
TIMEVAL time_now = { tv_sec: 0, tv_usec: 0 };

/* set a timer to a specific value */
TIMEVAL
timer_dup(TIMEVAL b)
{
	TIMEVAL a;

	TIMER_RESET(a);
	a.tv_sec = b.tv_sec;
	a.tv_usec = b.tv_usec;
	return a;
}

/* timer compare */
int
timer_cmp(TIMEVAL a, TIMEVAL b)
{
	if (a.tv_sec > b.tv_sec)
		return 1;
	if (a.tv_sec < b.tv_sec)
		return -1;
	if (a.tv_usec > b.tv_usec)
		return 1;
	if (a.tv_usec < b.tv_usec)
		return -1;
	return 0;
}

/* timer sub */
TIMEVAL
timer_sub(TIMEVAL a, TIMEVAL b)
{
	TIMEVAL ret;

	TIMER_RESET(ret);
	ret.tv_usec = a.tv_usec - b.tv_usec;
	ret.tv_sec = a.tv_sec - b.tv_sec;

	if (ret.tv_usec < 0) {
		ret.tv_usec += TIMER_HZ;
		ret.tv_sec--;
	}

	return ret;
}

/* timer add */
TIMEVAL
timer_add_long(TIMEVAL a, long b)
{
	TIMEVAL ret;

	TIMER_RESET(ret);
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
int monotonic_gettimeofday(TIMEVAL *now)
{
	static TIMEVAL mono_date;
	static TIMEVAL drift; /* warning: signed seconds! */
	TIMEVAL sys_date, adjusted, deadline;

	if (!now) {
		errno = EFAULT;
		return -1;
	}

	gettimeofday(&sys_date, NULL);

	/* on first call, we set mono_date to system date */
	if (mono_date.tv_sec == 0) {
		mono_date = sys_date;
		drift.tv_sec = drift.tv_usec = 0;
		*now = mono_date;
		return 0;
	}

	/* compute new adjusted time by adding the drift offset */
	adjusted.tv_sec  = sys_date.tv_sec  + drift.tv_sec;
	adjusted.tv_usec = sys_date.tv_usec + drift.tv_usec;
	if (adjusted.tv_usec >= TIMER_HZ) {
		adjusted.tv_usec -= TIMER_HZ;
		adjusted.tv_sec++;
	}

	/* check for jumps in the past, and bound to last date */
	if (adjusted.tv_sec  <  mono_date.tv_sec ||
	    (adjusted.tv_sec  == mono_date.tv_sec &&
	     adjusted.tv_usec <  mono_date.tv_usec))
		goto fixup;

	/* check for jumps too far in the future, and bound them to
	 * TIME_MAX_FORWARD_US microseconds.
	 */
	deadline.tv_sec  = mono_date.tv_sec  + TIME_MAX_FORWARD_US / TIMER_HZ;
	deadline.tv_usec = mono_date.tv_usec + TIME_MAX_FORWARD_US % TIMER_HZ;
	if (deadline.tv_usec >= TIMER_HZ) {
		deadline.tv_usec -= TIMER_HZ;
		deadline.tv_sec++;
	}

	if (adjusted.tv_sec  >  deadline.tv_sec ||
	    (adjusted.tv_sec  == deadline.tv_sec &&
	     adjusted.tv_usec >= deadline.tv_usec)) {
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
	drift.tv_sec  = mono_date.tv_sec  - sys_date.tv_sec;
	drift.tv_usec = mono_date.tv_usec - sys_date.tv_usec;
	if (drift.tv_usec < 0) {
		drift.tv_usec += TIMER_HZ;
		drift.tv_sec--;
	}
	*now = mono_date;
	return 0;
}

/* current time */
TIMEVAL
timer_now(void)
{
	TIMEVAL curr_time;
	int old_errno = errno;

	/* init timer */
	TIMER_RESET(curr_time);
	monotonic_gettimeofday(&curr_time);
	errno = old_errno;

	return curr_time;
}

/* sets and returns current time from system time */
TIMEVAL
set_time_now(void)
{
	int old_errno = errno;

	/* init timer */
	TIMER_RESET(time_now);
	monotonic_gettimeofday(&time_now);
	errno = old_errno;

	return time_now;
}

/* timer sub from current time */
TIMEVAL
timer_sub_now(TIMEVAL a)
{
	return timer_sub(time_now, a);
}

/* print timer value */
void
timer_dump(TIMEVAL a)
{
	unsigned long timer;
	timer = a.tv_sec * TIMER_HZ + a.tv_usec;
	printf("=> %lu (usecs)\n", timer);
}

unsigned long
timer_tol(TIMEVAL a)
{
	unsigned long timer;
	timer = a.tv_sec * TIMER_HZ + a.tv_usec;
	return timer;
}

