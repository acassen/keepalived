/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        scheduler.c include file.
 *
 * Version:     $Id: scheduler.h,v 0.5.5 2002/04/10 02:34:23 acassen Exp $
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

#ifndef _SCHEDULER_H
#define _SCHEDULER_H

/* system includes */
#include <sys/time.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include "timer.h"

/* Thread itself. */
typedef struct _thread {
  unsigned long id;
  unsigned char type;			/* thread type */
  struct _thread *next;			/* next pointer of the thread */
  struct _thread *prev;			/* previous pointer of the thread */
  struct _thread_master *master;	/* pointer to the struct thread_master. */
  int (*func) (struct _thread *);	/* event function */
  void *arg;				/* event argument */
  TIMEVAL sands;			/* rest of time sands value. */
  union {
    int val;				/* second argument of the event. */
    int fd;				/* file descriptor in case of read/write. */
  } u;
} thread;

/* Linked list of thread. */
typedef struct _thread_list {
  thread *head;
  thread *tail;
  int count;
} thread_list;

/* Master of the theads. */
typedef struct _thread_master {
  thread_list read;
  thread_list write;
  thread_list timer;
  thread_list event;
  thread_list ready;
  thread_list unuse;
  fd_set readfd;
  fd_set writefd;
  fd_set exceptfd;
  unsigned long alloc;
} thread_master;

/* Thread types. */
#define THREAD_READ           0
#define THREAD_WRITE          1
#define THREAD_TIMER          2
#define THREAD_EVENT          3
#define THREAD_READY          4
#define THREAD_UNUSED         5
#define THREAD_WRITE_TIMEOUT  6
#define THREAD_READ_TIMEOUT   7
#define THREAD_TERMINATE      8

/* MICRO SEC def */
#define BOOTSTRAP_DELAY 1

/* Macros. */
#define THREAD_ARG(X) ((X)->arg)
#define THREAD_FD(X)  ((X)->u.fd)
#define THREAD_VAL(X) ((X)->u.val)

/* Prototypes. */
thread_master *thread_make_master(void);
thread *thread_add_terminate_event(thread_master *m);
void thread_destroy_master(thread_master *m);
thread *thread_add_read(thread_master *m
			, int (*func)(thread *)
			, void *arg
			, int fd
			, long timeout);
thread *thread_add_write(thread_master *m
			 , int (*func)(thread *)
			 , void *arg
			 , int fd
			 , long timeout);
thread *thread_add_timer(thread_master *m
			 , int (*func)(thread *)
			 , void *arg
			 , long timer);
thread *thread_add_event(thread_master *m
			 , int (*func)(thread *)
			 , void *arg
			 , int val);
void thread_cancel(thread *thread);
void thread_cancel_event(thread_master *m, void *arg);
thread *thread_fetch(thread_master *m, thread *fetch);
void thread_call(thread *thread);

#endif
