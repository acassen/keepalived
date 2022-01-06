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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _PROCESS_H
#define _PROCESS_H

#include <sched.h>
#include <sys/types.h>
#include <sys/resource.h>

#define	RT_RLIMIT_DEFAULT	10000

/* The maximum pid is 2^22 - see definition of PID_MAX_LIMIT in kernel source include/linux/threads.h */
#define PID_MAX_DIGITS		7

extern long min_auto_priority_delay;
extern pid_t main_pid;

extern void set_process_priorities(int, int, long, int, int, int);
extern void reset_process_priorities(void);
extern void increment_process_priority(void);
extern unsigned get_cur_priority(void) __attribute__((pure));
extern unsigned get_cur_rlimit_rttime(void) __attribute__((pure));
extern int set_process_cpu_affinity(cpu_set_t *, const char *);
extern int get_process_cpu_affinity_string(cpu_set_t *, char *, size_t);
extern void set_child_rlimit(int, const struct rlimit *);

extern void set_max_file_limit(unsigned);
#endif
