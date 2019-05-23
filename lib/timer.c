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
#include <time.h>
#include <stdbool.h>

#include "timer.h"
#ifdef _TIMER_CHECK_
#include "logger.h"
#endif

/* time_now holds current time */
timeval_t time_now;
#ifdef _TIMER_CHECK_
static timeval_t last_time;
bool do_timer_check;
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

static void
set_mono_offset(struct timespec *ts)
{
	struct timespec realtime, realtime_1, mono_offset;

	/* Calculate the offset of the realtime clock from the monotonic
	 * clock. We read the realtime clock twice and take the mean,
	 * which should then make it very close to the time the monotonic
	 * clock was read. */
	clock_gettime(CLOCK_REALTIME, &realtime);
	clock_gettime(CLOCK_MONOTONIC, &mono_offset);
	clock_gettime(CLOCK_REALTIME, &realtime_1);

	/* Calculate the mean realtime */
	realtime.tv_nsec = (realtime.tv_nsec + realtime_1.tv_nsec) / 2;
	if ((realtime.tv_sec + realtime_1.tv_sec) & 1)
		realtime.tv_nsec += NSEC_PER_SEC / 2;
	realtime.tv_sec = (realtime.tv_sec + realtime_1.tv_sec) / 2;

	if (realtime.tv_nsec < mono_offset.tv_nsec) {
		realtime.tv_nsec += NSEC_PER_SEC;
		realtime.tv_sec--;
	}
	realtime.tv_sec -= mono_offset.tv_sec;
	realtime.tv_nsec -= mono_offset.tv_nsec;

	*ts = realtime;
}

/* This function is a wrapper for gettimeofday(). It uses the monotonic clock to
 * guarantee that the returned time will always be monotonicly increasing.
 * When called for the first time it calculates the difference between the
 * monotonic clock and the realtime clock, and this difference is then subsequently
 * added to the monotonic clock to return a monotonic approximation to realtime.
 *
 * It is designed to be used as a drop-in replacement of gettimeofday(&now, NULL).
 * It will normally return 0, unless <now> is NULL, in which case it will
 * return -1 and set errno to EFAULT.
 */
static int
monotonic_gettimeofday(timeval_t *now)
{
	static struct timespec mono_offset;
	static bool initialised = false;
	struct timespec cur_time;

	if (!now) {
		errno = EFAULT;
		return -1;
	}

	if (!initialised) {
		set_mono_offset(&mono_offset);
		initialised = true;
	}

	/* Read the monotonic clock and add the offset we initially
	 * calculated of the realtime clock */
	clock_gettime(CLOCK_MONOTONIC, &cur_time);
	cur_time.tv_sec += mono_offset.tv_sec;
	cur_time.tv_nsec += mono_offset.tv_nsec;
	if (cur_time.tv_nsec > NSEC_PER_SEC) {
		cur_time.tv_nsec -= NSEC_PER_SEC;
		cur_time.tv_sec++;
	}

	TIMESPEC_TO_TIMEVAL(now, &cur_time);

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
	if (do_timer_check) {
		unsigned long timediff = (curr_time.tv_sec - last_time.tv_sec) * 1000000 + curr_time.tv_usec - last_time.tv_usec;
		log_message(LOG_INFO, "timer_now called from %s %s:%d - difference %lu usec", file, function, line_no, timediff);
		last_time = curr_time;
	}
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
	if (do_timer_check) {
		unsigned long timediff = (time_now.tv_sec - last_time.tv_sec) * 1000000 + time_now.tv_usec - last_time.tv_usec;
		log_message(LOG_INFO, "set_time_now called from %s %s:%d, time %ld.%6.6ld difference %lu usec", file, function, line_no, time_now.tv_sec, time_now.tv_usec, timediff);
		last_time = time_now;
	}
#endif

	return time_now;
}
