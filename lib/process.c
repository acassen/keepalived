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
#ifndef RLIMIT_RTTIME
/* musl was very late defining RLIMIT_RTTIME, not until v1.20 */
#define RLIMIT_RTTIME	15
#endif
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include "process.h"
#include "utils.h"
#include "logger.h"
#include "signals.h"
#include "warnings.h"
#include "bitops.h"

static unsigned cur_rt_priority;
static unsigned max_rt_priority;
unsigned min_auto_priority_delay;

static unsigned cur_rlimit_rttime;
static unsigned default_rlimit_rttime;
static struct rlimit orig_rlimit_rt;

static int cur_priority;
static int orig_priority;
static bool orig_priority_set;
static unsigned cur_stack_reserve;

static struct rlimit orig_fd_limit;

/* rlimit values to set for child processes */
static bool rlimit_nofile_set;
static struct rlimit core;
static bool rlimit_core_set;

/* main_pid is used by child processes to ensure the main process
 * hasn't died during a window when PDEATHSIG is not set */
pid_t main_pid;

/* To avoid repeatedly calling getpid(), we set our pid here so that
 * it can simply be referenced. */
pid_t our_pid;

static void
set_process_dont_swap(size_t stack_reserve)
{
	/* Ensure stack pages allocated */
	size_t pagesize = (size_t)sysconf(_SC_PAGESIZE);
	char stack[stack_reserve];
	size_t i;

	if (cur_stack_reserve == stack_reserve)
		return;

	if (mlockall(MCL_CURRENT | MCL_FUTURE
#ifdef MCL_ONFAULT
					      | MCL_ONFAULT	/* Since Linux 4.4 */
#endif
							   ) == -1) {
		log_message(LOG_INFO, "Unable to lock process in memory - %s", strerror(errno));
		return;
	}

	if (stack_reserve > cur_stack_reserve) {
		stack[0] = 23;		/* A random number */
		for (i = 0; i < stack_reserve; i += pagesize)
			stack[i] = stack[0];
		stack[stack_reserve-1] = stack[0];
	}

	cur_stack_reserve = stack_reserve;
}

static void
reset_process_dont_swap(void)
{
	if (cur_stack_reserve) {
		munlockall();
		cur_stack_reserve = 0;
	}
}

static void
set_process_priority(int priority)
{
	if (!orig_priority_set) {
		orig_priority = getpriority(PRIO_PROCESS, 0);
		orig_priority_set = true;
	}

	errno = 0;
	if (setpriority(PRIO_PROCESS, 0, priority) == -1 && errno) {
		log_message(LOG_INFO, "Unable to set process priority to %d - %s", priority, strerror(errno));
		return;
	}

	cur_priority = priority;
}

static void
reset_process_priority(void)
{
	errno = 0;
	if (setpriority(PRIO_PROCESS, 0, orig_priority) == -1 && errno) {
		log_message(LOG_INFO, "Unable to reset process priority - %m");
		return;
	}

	cur_priority = 0;
}

/* NOTE: This function generates a "stack protector not protecting local variables:
   variable length buffer" warning */
RELAX_STACK_PROTECTOR_START
void
set_process_priorities(unsigned realtime_priority, int max_realtime_priority, unsigned min_delay,
		       int rlimit_rt, int process_priority, int no_swap_stack_size)
{
	if (max_realtime_priority != -1)
		max_rt_priority = max_realtime_priority;

	if (realtime_priority) {
		/* Set realtime priority */
		struct sched_param sp = {
			.sched_priority = realtime_priority
		};

		if (sched_setscheduler(our_pid, SCHED_RR | SCHED_RESET_ON_FORK, &sp))
			log_message(LOG_WARNING, "child process: cannot raise priority");
		else {
			cur_rt_priority = realtime_priority;
			if (rlimit_rt)
			{
				struct rlimit rlim;

				set_sigxcpu_handler();

				rlim.rlim_cur = rlimit_rt / 2;	/* Get warnings if approaching limit */
				rlim.rlim_max = rlimit_rt;
				if (setrlimit(RLIMIT_RTTIME, &rlim))
					log_message(LOG_WARNING, "child process cannot set realtime rlimit");
				else
					cur_rlimit_rttime = rlimit_rt;
			}
		}
	}
	else {
		if (process_priority)
			set_process_priority(process_priority);

		default_rlimit_rttime = rlimit_rt;
	}

	min_auto_priority_delay = min_delay;

// TODO - measure max stack usage
	if (no_swap_stack_size)
		set_process_dont_swap(no_swap_stack_size);
}
RELAX_STACK_PROTECTOR_END

void
reset_priority(void)
{
	if (cur_rt_priority) {
		/* Set realtime priority */
		struct sched_param sp = {
			.sched_priority = 0
		};

		if (sched_setscheduler(our_pid, SCHED_OTHER, &sp))
			log_message(LOG_WARNING, "child process: cannot reset realtime scheduling");
		else {
			cur_rt_priority = 0;
			if (cur_rlimit_rttime)
			{
				if (setrlimit(RLIMIT_RTTIME, &orig_rlimit_rt))
					log_message(LOG_WARNING, "child process cannot reset realtime rlimit");
				else
					cur_rlimit_rttime = 0;

			}
		}
	}

	if (cur_priority != orig_priority)
		reset_process_priority();
}

void
reset_process_priorities(void)
{
	reset_priority();

	reset_process_dont_swap();

	if (rlimit_nofile_set) {
		setrlimit(RLIMIT_NOFILE, &orig_fd_limit);
		rlimit_nofile_set = false;
	}
	if (rlimit_core_set) {
		setrlimit(RLIMIT_CORE, &core);
		rlimit_core_set = false;
	}
}

void
restore_priority(unsigned realtime_priority, int max_realtime_priority, unsigned min_delay,
		 int rlimit_rt, int process_priority, int no_swap_stack_size)
{
	/*
	 * max_realtime_priority == -1 => don't use rtsched - sets max_rt_priority
	 * realtime_priority - says use rt prio, set to realtime_priority, set cur_limit_rttime and setrtimie(RLIMIT_RTTIME)
	 *   else
	 *  	 use process_priority
	 *  	 set default_rlimit_rttime = rlimit_rt
	 * rlimit_rt - set RLIMIT_RTTIME
	 *
	 * if (!max_realtime)
	 * 	if (current_rt_prio)
	 *	 	switch back to normal scheduling at process_priority
	 *	 else
	 *	 	set prio to process_priority
	 * else if (current_rt_prio > max_realtime_priority)
	 * 	current_rt_prio = max_re...
	 * 	lower our priority
	 * else if realtime_priority > current_rt_prio
	 * 	set to realtime_priority
	 */

	if (cur_rt_priority) {
		/* We are currently using realtime */
		if (!realtime_priority && max_realtime_priority == -1) {
			/* Turn off rt_sched and set process_priority */
			struct sched_param sp = { .sched_priority = process_priority };
			sched_setscheduler(our_pid, SCHED_OTHER, &sp);
			cur_rt_priority = 0;
			max_rt_priority = 0;
		} else {
			unsigned new_priority = cur_rt_priority;
			if (max_realtime_priority != -1 && cur_priority > max_realtime_priority) {
				/* reduce priority */
				max_rt_priority = max_realtime_priority;
				new_priority = max_rt_priority;
			} else if (realtime_priority > cur_rt_priority) {
				/* increase priority */
				new_priority = realtime_priority;
			}
			set_process_priorities(new_priority, max_realtime_priority, min_delay, rlimit_rt, 0, 0);
		}
	} else {
		if (realtime_priority) {
			/* Set realtime prio */
			set_process_priorities(realtime_priority, max_realtime_priority, min_delay, rlimit_rt, 0, 0);
		} else if (process_priority != cur_priority) {
			set_process_priority(process_priority);
		}
	}

	if (max_realtime_priority != -1)
		max_rt_priority = max_realtime_priority;
	else
		max_rt_priority = 0;

	min_auto_priority_delay = min_delay;

	if (no_swap_stack_size)
		set_process_dont_swap(no_swap_stack_size);
	else
		reset_process_dont_swap();
}

void
increment_process_priority(void)
{
	if (!max_rt_priority)
		return;

	if (cur_rt_priority) {
		if (cur_rt_priority >= max_rt_priority)
			return;

		cur_rt_priority++;
	} else
		cur_rt_priority = sched_get_priority_min(SCHED_RR);

	set_process_priorities(cur_rt_priority, -1, 0,
			       cur_rlimit_rttime ? 0 : default_rlimit_rttime,
			       0, 0);

	log_message(LOG_INFO, "Set realtime priority %u", cur_rt_priority);
}

unsigned __attribute__((pure))
get_cur_priority(void)
{
	return cur_rt_priority;
}

unsigned __attribute__((pure))
get_cur_rlimit_rttime(void)
{
	return cur_rlimit_rttime;
}

int
set_process_cpu_affinity(cpu_set_t *set, const char *process)
{
	/* If not used then empty set */
	if (!CPU_COUNT(set))
		return 0;

	if (sched_setaffinity(0, sizeof(cpu_set_t), set)) {
		log_message(LOG_WARNING, "unable to set cpu affinity to %s process (%m)"
				       , process);
		return -1;
	}

	return 0;
}

int
get_process_cpu_affinity_string(cpu_set_t *set, char *buffer, size_t size)
{
	int i, num_cpus, len, s = size;
	char *cp = buffer;

	/* If not used then empty set */
	if (!CPU_COUNT(set))
		return 0;

	num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	for (i = 0; i < num_cpus; i++) {
		if (!CPU_ISSET(i, set))
			continue;

		len = integer_to_string(i, cp, s);
		if (len < 0 || s <= len + 1) {
			*cp = '\0';
			return -1;
		}
		*(cp + len) = ' ';
		cp += len + 1;
		s -= len + 1;
	}

	*cp = '\0';
	return 0;
}

void
set_child_rlimit(int resource, const struct rlimit *rlim)
{
	if (resource == RLIMIT_CORE) {
		core = *rlim;
		rlimit_core_set = true;
	}
	else
		log_message(LOG_INFO, "Unknown rlimit resource %d", resource);
}

void
set_max_file_limit(unsigned fd_required)
{
	struct rlimit limit = { .rlim_cur = 0 };

	if (orig_fd_limit.rlim_cur == 0) {
		if (getrlimit(RLIMIT_NOFILE, &orig_fd_limit))
			log_message(LOG_INFO, "Failed to get original RLIMIT_NOFILE, errno %d", errno);
		else
			limit = orig_fd_limit;
	} else if (getrlimit(RLIMIT_NOFILE, &limit))
		log_message(LOG_INFO, "Failed to get current RLIMIT_NOFILE, errno %d", errno);

	if (fd_required <= orig_fd_limit.rlim_cur &&
	    orig_fd_limit.rlim_cur == limit.rlim_cur)
		return;

	limit.rlim_cur = orig_fd_limit.rlim_cur > fd_required ? orig_fd_limit.rlim_cur : fd_required;
	limit.rlim_max = orig_fd_limit.rlim_max > fd_required ? orig_fd_limit.rlim_max : fd_required;

	if (setrlimit(RLIMIT_NOFILE, &limit) == -1)
		log_message(LOG_INFO, "Failed to set open file limit to %" PRI_rlim_t ":%" PRI_rlim_t " failed - errno %d", limit.rlim_cur, limit.rlim_max, errno);
	else if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "Set open file limit to %" PRI_rlim_t ":%" PRI_rlim_t ".", limit.rlim_cur, limit.rlim_max);

	/* We don't want child processes to get excessive limits */
	rlimit_nofile_set = (limit.rlim_cur != orig_fd_limit.rlim_cur);
}
