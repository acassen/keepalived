/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        scheduler.c include file.
 *
 * Version:     $Id: scheduler.h,v 0.4.9 2001/12/10 10:52:33 acassen Exp $
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

/* local includes */
#include "cfreader.h"
#include "check.h"

/* Thread itself. */
typedef struct timeval TIMEVAL;
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
#define TIMER_SEC_MICRO 1000000
#define TIMER_MAX_SEC   1000
#define BOOTSTRAP_DELAY 1

/* Macros. */
#define THREAD_ARG(X) ((X)->arg)
#define THREAD_ARG_CHECKER_ARG(X) ((X)->checker_arg)
#define THREAD_FD(X)  ((X)->u.fd)
#define THREAD_VAL(X) ((X)->u.val)

/* Prototypes. */
thread_master *thread_make_master(void);

thread *thread_add_terminate_event(thread_master *m);

void thread_destroy_master(thread_master *m);

thread_arg *thread_arg_new(configuration_data *root
			   , virtualserver *vserver
			   , realserver *rserver);

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

int thread_timer_cmp(TIMEVAL a, TIMEVAL b);

TIMEVAL thread_timer_sub(TIMEVAL a, TIMEVAL b);

void register_worker_thread(thread_master *master
			    , configuration_data *lstptr);

/* extern prototypes */
extern int tcp_connect_thread(thread *thread);
extern int http_connect_thread(thread *thread);
extern int ssl_connect_thread(thread *thread);
extern int misc_check_thread(thread *thread);
extern int vrrp_dispatcher_init_thread(thread *thread);

#endif
