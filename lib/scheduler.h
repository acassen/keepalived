/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        scheduler.c include file.
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

#ifndef _SCHEDULER_H
#define _SCHEDULER_H

/* system includes */
#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>

#include "timer.h"

/* Thread itself. */
typedef struct _thread {
	unsigned long id;
	unsigned char type;		/* thread type */
	struct _thread *next;		/* next pointer of the thread */
	struct _thread *prev;		/* previous pointer of the thread */
	struct _thread_master *master;	/* pointer to the struct thread_master. */
	int (*func) (struct _thread *);	/* event function */
	void *arg;			/* event argument */
	timeval_t sands;		/* rest of time sands value. */
	union {
		int val;		/* second argument of the event. */
		int fd;			/* file descriptor in case of read/write. */
		struct {
			pid_t pid;	/* process id a child thread is wanting. */
			int status;	/* return status of the process */
		} c;
	} u;
} thread_t;

/* Linked list of thread. */
typedef struct _thread_list {
	thread_t *head;
	thread_t *tail;
	int count;
} thread_list_t;

/* Master of the threads. */
typedef struct _thread_master {
	thread_list_t read;
	thread_list_t write;
	thread_list_t timer;
	thread_list_t child;
	thread_list_t event;
	thread_list_t ready;
	thread_list_t unuse;
	fd_set readfd;
	fd_set writefd;
	fd_set exceptfd;
	int max_fd;
	unsigned long alloc;
} thread_master_t;

/* Thread types. */
enum {
	THREAD_READ,
	THREAD_WRITE,
	THREAD_TIMER,
	THREAD_EVENT,
	THREAD_CHILD,
	THREAD_READY,
	THREAD_UNUSED,
	THREAD_WRITE_TIMEOUT,
	THREAD_READ_TIMEOUT,
	THREAD_CHILD_TIMEOUT,
	THREAD_TERMINATE,
	THREAD_READY_FD,
	THREAD_IF_UP,
	THREAD_IF_DOWN
};

typedef enum {
	PROG_TYPE_PARENT,
	PROG_TYPE_VRRP,
	PROG_TYPE_CHECKER,
} prog_type_t;

/* MICRO SEC def */
#define BOOTSTRAP_DELAY TIMER_HZ
#define RESPAWN_TIMER	TIMER_NEVER

/* Macros. */
#define THREAD_ARG(X) ((X)->arg)
#define THREAD_FD(X)  ((X)->u.fd)
#define THREAD_VAL(X) ((X)->u.val)
#define THREAD_CHILD_PID(X) ((X)->u.c.pid)
#define THREAD_CHILD_STATUS(X) ((X)->u.c.status)

/* Exit codes */
#define KEEPALIVED_EXIT_FATAL	(EXIT_FAILURE+1)
#define KEEPALIVED_EXIT_CONFIG	(EXIT_FAILURE+2)

/* global vars exported */
extern thread_master_t *master;
prog_type_t prog_type;		/* Parent/VRRP/Checker process */
#ifdef _WITH_SNMP_
extern bool snmp_running;
#endif

/* Prototypes. */
extern void set_child_finder(bool (*)(pid_t, char const **));
extern bool report_child_status(int, pid_t, const char *);
extern thread_master_t *thread_make_master(void);
extern thread_t *thread_add_terminate_event(thread_master_t *);
extern void thread_cleanup_master(thread_master_t *);
extern void thread_destroy_master(thread_master_t *);
extern thread_t *thread_add_read(thread_master_t *, int (*func) (thread_t *), void *, int, unsigned long);
extern void thread_read_requeue(thread_master_t *, int, timeval_t);
extern void thread_requeue_read(thread_master_t *, int, unsigned long);
extern thread_t *thread_add_write(thread_master_t *, int (*func) (thread_t *), void *, int, unsigned long);
extern thread_t *thread_add_timer(thread_master_t *, int (*func) (thread_t *), void *, unsigned long);
extern thread_t *thread_add_child(thread_master_t *, int (*func) (thread_t *), void *, pid_t, unsigned long);
extern thread_t *thread_add_event(thread_master_t *, int (*func) (thread_t *), void *, int);
extern int thread_cancel(thread_t *);
extern thread_t *thread_fetch(thread_master_t *, thread_t *);
extern void thread_call(thread_t *);
extern void thread_child_handler(void *, int);
extern void launch_scheduler(void);
#endif
