/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        scheduler.c include file.
 *
 * Version:     $Id: scheduler.h,v 0.3.7 2001/09/14 00:37:56 acassen Exp $
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

/* Linked list of thread. */
struct thread_list
{
  struct thread *head;
  struct thread *tail;
  int count;
};

/* Master of the theads. */
struct thread_master
{
  struct thread_list read;
  struct thread_list write;
  struct thread_list timer;
  struct thread_list event;
  struct thread_list ready;
  struct thread_list unuse;
  fd_set readfd;
  fd_set writefd;
  fd_set exceptfd;
  unsigned long alloc;
};

/* Thread itself. */
struct thread
{
  unsigned long id;
  unsigned char type;		/* thread type */
  struct thread *next;		/* next pointer of the thread */
  struct thread *prev;		/* previous pointer of the thread */
  struct thread_master *master;	/* pointer to the struct thread_master. */
  int (*func) (struct thread *); /* event function */
  void *arg;			/* event argument */
  struct timeval sands;	/* rest of time sands value. */
  union {
    int val;			/* second argument of the event. */
    int fd;			/* file descriptor in case of read/write. */
  } u;
};

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
#define TIMER_MAX_SEC   10

/* Macros. */
#define THREAD_ARG(X) ((X)->arg)
#define THREAD_ARG_CHECKER_ARG(X) ((X)->checker_arg)
#define THREAD_FD(X)  ((X)->u.fd)
#define THREAD_VAL(X) ((X)->u.val)

/* Prototypes. */
struct thread_master *thread_make_master ();

struct thread *
thread_add_terminate_event (struct thread_master *m);

void
thread_destroy_master (struct thread_master *m);

struct thread_arg *
thread_arg_new (configuration_data *root,
                virtualserver *vserver,
                realserver *rserver);

struct thread *
thread_add_read (struct thread_master *m, 
		 int (*func)(struct thread *),
		 void *arg,
		 int fd,
                 long timeout);

struct thread *
thread_add_write (struct thread_master *m,
		 int (*func)(struct thread *),
		 void *arg,
		 int fd,
                 long timeout);

struct thread *
thread_add_timer (struct thread_master *m,
		  int (*func)(struct thread *),
		  void *arg,
		  long timer);

struct thread *
thread_add_event (struct thread_master *m,
		  int (*func)(struct thread *), 
		  void *arg,
		  int val);


void
thread_cancel (struct thread *thread);

void
thread_cancel_event (struct thread_master *m, void *arg);

struct thread *
thread_fetch (struct thread_master *m, 
	      struct thread *fetch);

void
thread_call (struct thread *thread);

struct timeval
thread_timer_sub (struct timeval a, struct timeval b);

void
register_worker_thread(struct thread_master *master,
                       configuration_data *lstptr);

/* extern prototypes */
extern int
tcp_connect_thread(struct thread *thread);

extern int
http_connect_thread(struct thread *thread);

extern int
misc_check_thread(struct thread *thread);

#endif
