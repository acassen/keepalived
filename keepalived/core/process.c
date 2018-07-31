/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Process management
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
 * Copyright (C) 2001-2016 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <sys/mman.h>
#include <sys/resource.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#ifdef _HAVE_SCHED_RT_
#include <sched.h>
#endif

#include "process.h"
#include "logger.h"
#if HAVE_DECL_RLIMIT_RTTIME == 1
#include "signals.h"
#endif

#ifdef _HAVE_SCHED_RT_
static bool realtime_priority_set;

#if HAVE_DECL_RLIMIT_RTTIME == 1
static bool rlimit_rt_set;
static struct rlimit orig_rlimit_rt;
#endif
#endif

static bool priority_set;
static int orig_priority;

static void
set_process_dont_swap(size_t stack_reserve)
{
	/* Ensure stack pages allocated */
	size_t pagesize = (size_t)sysconf(_SC_PAGESIZE);
	char stack[stack_reserve];
	size_t i;

	stack[0] = 23;		/* A random number */
	for (i = 0; i < stack_reserve; i += pagesize)
		stack[i] = stack[0];

	if (mlockall(MCL_FUTURE) == -1)
		log_message(LOG_INFO, "Unable to lock process in memory - %s", strerror(errno));
}

static void
set_process_priority(int priority)
{
	orig_priority = getpriority(PRIO_PROCESS, 0);

	errno = 0;
	if (setpriority(PRIO_PROCESS, 0, priority) == -1 && errno) {
		log_message(LOG_INFO, "Unable to set process priority to %d - %s", priority, strerror(errno));
		return;
	}

	priority_set = true;
}

static void
reset_process_priority(void)
{
	errno = 0;
	if (setpriority(PRIO_PROCESS, 0, orig_priority) == -1 && errno) {
		log_message(LOG_INFO, "Unable to reset process priority - %m");
		return;
	}

	priority_set = false;
}

void
set_process_priorities(
#ifdef _HAVE_SCHED_RT_
		       int realtime_priority,
#if HAVE_DECL_RLIMIT_RTTIME == 1
		       int rlimit_rt,
#endif
#endif
		       int process_priority, int no_swap_stack_size)
{
#ifdef _HAVE_SCHED_RT_
	if (realtime_priority) {
		/* Set realtime priority */
		struct sched_param sp = {
			.sched_priority = realtime_priority
		};

		if (sched_setscheduler(getpid(), SCHED_RR | SCHED_RESET_ON_FORK, &sp))
			log_message(LOG_WARNING, "child process: cannot raise priority");
#if HAVE_DECL_RLIMIT_RTTIME == 1
		else if (rlimit_rt)
		{
			struct rlimit rlim;

			set_sigxcpu_handler();

			rlim.rlim_cur = rlimit_rt / 2;	/* Get warnings if approaching limit */
			rlim.rlim_max = rlimit_rt;
			if (setrlimit(RLIMIT_RTTIME, &rlim))
				log_message(LOG_WARNING, "child process cannot set realtime rlimit");
		}
#endif
	}
	else
#endif
	     if (process_priority)
		set_process_priority(process_priority);

// TODO - measure max stack usage
	if (no_swap_stack_size)
		set_process_dont_swap(no_swap_stack_size);
}

void
reset_process_priorities(void)
{
#ifdef _HAVE_SCHED_RT_
	if (realtime_priority_set) {
		/* Set realtime priority */
		struct sched_param sp = {
			.sched_priority = 0
		};

		if (sched_setscheduler(getpid(), SCHED_OTHER, &sp))
			log_message(LOG_WARNING, "child process: cannot reset realtime scheduling");
		else {
			realtime_priority_set = false;
#if HAVE_DECL_RLIMIT_RTTIME == 1
			if (rlimit_rt_set)
			{
				if (setrlimit(RLIMIT_RTTIME, &orig_rlimit_rt))
					log_message(LOG_WARNING, "child process cannot reset realtime rlimit");
				else
					rlimit_rt_set = false;

			}
#endif
		}
	}
#endif
	if (priority_set)
		reset_process_priority();
}
