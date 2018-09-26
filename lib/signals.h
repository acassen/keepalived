/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        signals.c include file.
 *
 * Author:      Kevin Lindsay, <kevinl@netnation.com>
 *              Alexandre Cassen, <acassen@linux-vs.org>
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

#ifndef _SIGNALS_H
#define _SIGNALS_H

#include "config.h"

#include <signal.h>
#include <stdbool.h>

#include "scheduler.h"

static inline int
sigmask_func(int how, const sigset_t *set, sigset_t *oldset)
{
#ifdef _WITH_PTHREADS_
    return pthread_sigmask(how, set, oldset);
#else
    return sigprocmask(how, set, oldset);
#endif
}

/* Prototypes */
extern int get_signum(const char *);
extern void signal_set(int, void (*) (void *, int), void *);
extern void signal_ignore(int);
extern int signal_handler_init(void);
extern void signal_handler_destroy(void);
extern void signal_handler_script(void);
extern void add_signal_read_thread(thread_master_t *);
extern void cancel_signal_read_thread(void);
#if HAVE_DECL_RLIMIT_RTTIME == 1
extern void set_sigxcpu_handler(void);
#endif

extern void signal_fd_close(int);

#ifdef THREAD_DUMP
extern void register_signal_thread_addresses(void);
#endif

#endif
