/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        Timer manipulations.
 *  
 * Version:     $Id: timer.c,v 0.7.6 2002/11/20 21:34:18 acassen Exp $
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
 */

#include <stdio.h>
#include <string.h>
#include "timer.h"

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

/* current time */
TIMEVAL
timer_now(void)
{
	TIMEVAL timer_now;

	/* init timer */
	TIMER_RESET(timer_now);
	gettimeofday(&timer_now, NULL);

	return timer_now;
}

/* timer sub from current time */
TIMEVAL
timer_sub_now(TIMEVAL a)
{
	return timer_sub(timer_now(), a);
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

