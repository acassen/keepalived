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

#include <sys/types.h>

#if HAVE_DECL_RLIMIT_RTTIME == 1
#define	RT_RLIMIT_DEFAULT	10000
#endif

extern void set_process_priorities(
#ifdef _HAVE_SCHED_RT_
			           int,
#if HAVE_DECL_RLIMIT_RTTIME == 1
			           int,
#endif
#endif
				   int, int);
extern void reset_process_priorities(void);

#endif
