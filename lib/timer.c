/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        Timer manipulations.
 *  
 * Version:     $Id: timer.c,v 1.1.15 2007/09/15 04:07:41 acassen Exp $
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
 * Copyright (C) 2001-2007 Alexandre Cassen, <acassen@freebox.fr>
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

/* current time */
TIMEVAL
timer_now(void)
{
	TIMEVAL curr_time;
	int old_errno = errno;

	/* init timer */
	TIMER_RESET(curr_time);
	gettimeofday(&curr_time, NULL);
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
	gettimeofday(&time_now, NULL);
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

