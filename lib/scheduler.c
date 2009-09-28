/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Scheduling framework. This code is highly inspired from
 *              the thread management routine (thread.c) present in the 
 *              very nice zebra project (http://www.zebra.org).
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
 * Copyright (C) 2001-2009 Alexandre Cassen, <acassen@freebox.fr>
 */

#include <signal.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <unistd.h>
#include "scheduler.h"
#include "memory.h"
#include "utils.h"
#include "signals.h"
#include "logger.h"

/* global vars */
thread_master *master = NULL;

/* Make thread master. */
thread_master *
thread_make_master(void)
{
	thread_master *new;

	new = (thread_master *) MALLOC(sizeof (thread_master));
	return new;
}

/* Add a new thread to the list. */
static void
thread_list_add(thread_list * list, thread * thread_obj)
{
	thread_obj->next = NULL;
	thread_obj->prev = list->tail;
	if (list->tail)
		list->tail->next = thread_obj;
	else
		list->head = thread_obj;
	list->tail = thread_obj;
	list->count++;
}

/* Add a new thread to the list. */
void
thread_list_add_before(thread_list * list, thread * point, thread * thread_obj)
{
	thread_obj->next = point;
	thread_obj->prev = point->prev;
	if (point->prev)
		point->prev->next = thread_obj;
	else
		list->head = thread_obj;
	point->prev = thread_obj;
	list->count++;
}

/* Add a thread in the list sorted by timeval */
void
thread_list_add_timeval(thread_list * list, thread * thread_obj)
{
	struct _thread *tt;

	for (tt = list->head; tt; tt = tt->next) {
		if (timer_cmp(thread_obj->sands, tt->sands) <= 0)
			break;
	}

	if (tt)
		thread_list_add_before(list, tt, thread_obj);
	else
		thread_list_add(list, thread_obj);
}

/* Delete a thread from the list. */
thread *
thread_list_delete(thread_list * list, thread * thread_obj)
{
	if (thread_obj->next)
		thread_obj->next->prev = thread_obj->prev;
	else
		list->tail = thread_obj->prev;
	if (thread_obj->prev)
		thread_obj->prev->next = thread_obj->next;
	else
		list->head = thread_obj->next;
	thread_obj->next = thread_obj->prev = NULL;
	list->count--;
	return thread_obj;
}

/* Free all unused thread. */
static void
thread_clean_unuse(thread_master * m)
{
	thread *thread_obj;

	thread_obj = m->unuse.head;
	while (thread_obj) {
		struct _thread *t;

		t = thread_obj;
		thread_obj = t->next;

		thread_list_delete(&m->unuse, t);

		/* free the thread */
		FREE(t);
		m->alloc--;
	}
}

/* Move thread to unuse list. */
static void
thread_add_unuse(thread_master * m, thread * thread_obj)
{
	assert(m != NULL);
	assert(thread_obj->next == NULL);
	assert(thread_obj->prev == NULL);
	assert(thread_obj->type == THREAD_UNUSED);
	thread_list_add(&m->unuse, thread_obj);
}

/* Move list element to unuse queue */
static void
thread_destroy_list(thread_master * m, thread_list thread_list_obj)
{
	thread *thread_obj;

	thread_obj = thread_list_obj.head;

	while (thread_obj) {
		struct _thread *t;

		t = thread_obj;
		thread_obj = t->next;

		if (t->type == THREAD_READY_FD ||
		    t->type == THREAD_READ ||
		    t->type == THREAD_WRITE ||
		    t->type == THREAD_READ_TIMEOUT ||
		    t->type == THREAD_WRITE_TIMEOUT)
			close (t->u.fd);

		thread_list_delete(&thread_list_obj, t);
		t->type = THREAD_UNUSED;
		thread_add_unuse(m, t);
	}
}

/* Cleanup master */
static void
thread_cleanup_master(thread_master * m)
{
	/* Unuse current thread lists */
	thread_destroy_list(m, m->read);
	thread_destroy_list(m, m->write);
	thread_destroy_list(m, m->timer);
	thread_destroy_list(m, m->event);
	thread_destroy_list(m, m->ready);

	/* Clear all FDs */
	FD_ZERO(&m->readfd);
	FD_ZERO(&m->writefd);
	FD_ZERO(&m->exceptfd);

	/* Clean garbage */
	thread_clean_unuse(m);
}

/* Stop thread scheduler. */
void
thread_destroy_master(thread_master * m)
{
	thread_cleanup_master(m);
	FREE(m);
}

/* Delete top of the list and return it. */
thread *
thread_trim_head(thread_list * list)
{
	if (list->head)
		return thread_list_delete(list, list->head);
	return NULL;
}

/* Make new thread. */
thread *
thread_new(thread_master * m)
{
	thread *new;

	/* If one thread is already allocated return it */
	if (m->unuse.head) {
		new = thread_trim_head(&m->unuse);
		memset(new, 0, sizeof (thread));
		return new;
	}

	new = (thread *) MALLOC(sizeof (thread));
	m->alloc++;
	return new;
}

/* Add new read thread. */
thread *
thread_add_read(thread_master * m, int (*func) (thread *)
		, void *arg, int fd, long timer)
{
	thread *thread_obj;

	assert(m != NULL);

	if (FD_ISSET(fd, &m->readfd)) {
		log_message(LOG_WARNING, "There is already read fd [%d]", fd);
		return NULL;
	}

	thread_obj = thread_new(m);
	thread_obj->type = THREAD_READ;
	thread_obj->id = 0;
	thread_obj->master = m;
	thread_obj->func = func;
	thread_obj->arg = arg;
	FD_SET(fd, &m->readfd);
	thread_obj->u.fd = fd;

	/* Compute read timeout value */
	set_time_now();
	thread_obj->sands = timer_add_long(time_now, timer);

	/* Sort the thread. */
	thread_list_add_timeval(&m->read, thread_obj);

	return thread_obj;
}

/* Add new write thread. */
thread *
thread_add_write(thread_master * m, int (*func) (thread *)
		 , void *arg, int fd, long timer)
{
	thread *thread_obj;

	assert(m != NULL);

	if (FD_ISSET(fd, &m->writefd)) {
		log_message(LOG_WARNING, "There is already write fd [%d]", fd);
		return NULL;
	}

	thread_obj = thread_new(m);
	thread_obj->type = THREAD_WRITE;
	thread_obj->id = 0;
	thread_obj->master = m;
	thread_obj->func = func;
	thread_obj->arg = arg;
	FD_SET(fd, &m->writefd);
	thread_obj->u.fd = fd;

	/* Compute write timeout value */
	set_time_now();
	thread_obj->sands = timer_add_long(time_now, timer);

	/* Sort the thread. */
	thread_list_add_timeval(&m->write, thread_obj);

	return thread_obj;
}

/* Add timer event thread. */
thread *
thread_add_timer(thread_master * m, int (*func) (thread *)
		 , void *arg, long timer)
{
	thread *thread_obj;

	assert(m != NULL);

	thread_obj = thread_new(m);
	thread_obj->type = THREAD_TIMER;
	thread_obj->id = 0;
	thread_obj->master = m;
	thread_obj->func = func;
	thread_obj->arg = arg;

	/* Do we need jitter here? */
	set_time_now();
	thread_obj->sands = timer_add_long(time_now, timer);

	/* Sort by timeval. */
	thread_list_add_timeval(&m->timer, thread_obj);

	return thread_obj;
}

/* Add a child thread. */
thread *
thread_add_child(thread_master * m, int (*func) (thread *)
		 , void * arg, pid_t pid, long timer)
{
	thread *thread_obj;

	assert(m != NULL);

	thread_obj = thread_new(m);
	thread_obj->type = THREAD_CHILD;
	thread_obj->id = 0;
	thread_obj->master = m;
	thread_obj->func = func;
	thread_obj->arg = arg;
	thread_obj->u.c.pid = pid;
	thread_obj->u.c.status = 0;

	/* Compute write timeout value */
	set_time_now();
	thread_obj->sands = timer_add_long(time_now, timer);

	/* Sort by timeval. */
	thread_list_add_timeval(&m->child, thread_obj);

	return thread_obj;
}

/* Add simple event thread. */
thread *
thread_add_event(thread_master * m, int (*func) (thread *)
		 , void *arg, int val)
{
	thread *thread_obj;

	assert(m != NULL);

	thread_obj = thread_new(m);
	thread_obj->type = THREAD_EVENT;
	thread_obj->id = 0;
	thread_obj->master = m;
	thread_obj->func = func;
	thread_obj->arg = arg;
	thread_obj->u.val = val;
	thread_list_add(&m->event, thread_obj);

	return thread_obj;
}

/* Add simple event thread. */
thread *
thread_add_terminate_event(thread_master * m)
{
	thread *thread_obj;

	assert(m != NULL);

	thread_obj = thread_new(m);
	thread_obj->type = THREAD_TERMINATE;
	thread_obj->id = 0;
	thread_obj->master = m;
	thread_obj->func = NULL;
	thread_obj->arg = NULL;
	thread_obj->u.val = 0;
	thread_list_add(&m->event, thread_obj);

	return thread_obj;
}

/* Cancel thread from scheduler. */
void
thread_cancel(thread * thread_obj)
{
	switch (thread_obj->type) {
	case THREAD_READ:
		assert(FD_ISSET(thread_obj->u.fd, &thread_obj->master->readfd));
		FD_CLR(thread_obj->u.fd, &thread_obj->master->readfd);
		thread_list_delete(&thread_obj->master->read, thread_obj);
		break;
	case THREAD_WRITE:
		assert(FD_ISSET(thread_obj->u.fd, &thread_obj->master->writefd));
		FD_CLR(thread_obj->u.fd, &thread_obj->master->writefd);
		thread_list_delete(&thread_obj->master->write, thread_obj);
		break;
	case THREAD_TIMER:
		thread_list_delete(&thread_obj->master->timer, thread_obj);
		break;
	case THREAD_CHILD:
		/* Does this need to kill the child, or is that the
		 * caller's job?
		 * This function is currently unused, so leave it for now.
		 */
		thread_list_delete(&thread_obj->master->child, thread_obj);
		break;
	case THREAD_EVENT:
		thread_list_delete(&thread_obj->master->event, thread_obj);
		break;
	case THREAD_READY:
	case THREAD_READY_FD:
		thread_list_delete(&thread_obj->master->ready, thread_obj);
		break;
	default:
		break;
	}

	thread_obj->type = THREAD_UNUSED;
	thread_add_unuse(thread_obj->master, thread_obj);
}

/* Delete all events which has argument value arg. */
void
thread_cancel_event(thread_master * m, void *arg)
{
	thread *thread_obj;

	thread_obj = m->event.head;
	while (thread_obj) {
		struct _thread *t;

		t = thread_obj;
		thread_obj = t->next;

		if (t->arg == arg) {
			thread_list_delete(&m->event, t);
			t->type = THREAD_UNUSED;
			thread_add_unuse(m, t);
		}
	}
}

/* Update timer value */
static void
thread_update_timer(thread_list *list, TIMEVAL *timer_min)
{
	if (list->head) {
		if (!TIMER_ISNULL(*timer_min)) {
			if (timer_cmp(list->head->sands, *timer_min) <= 0) {
				*timer_min = list->head->sands;
			}
		} else {
			*timer_min = list->head->sands;
		}
	}
}

/* Compute the wait timer. Take care of timeouted fd */
static void
thread_compute_timer(thread_master * m, TIMEVAL * timer_wait)
{
	TIMEVAL timer_min;

	/* Prepare timer */
	TIMER_RESET(timer_min);
	thread_update_timer(&m->timer, &timer_min);
	thread_update_timer(&m->write, &timer_min);
	thread_update_timer(&m->read, &timer_min);
	thread_update_timer(&m->child, &timer_min);

	/* Take care about monothonic clock */
	if (!TIMER_ISNULL(timer_min)) {
		timer_min = timer_sub(timer_min, time_now);
		if (timer_min.tv_sec < 0) {
			timer_min.tv_sec = timer_min.tv_usec = 0;
		} else if (timer_min.tv_sec >= 1) {
			timer_min.tv_sec = 1;
			timer_min.tv_usec = 0;
		}

		timer_wait->tv_sec = timer_min.tv_sec;
		timer_wait->tv_usec = timer_min.tv_usec;
	} else {
		timer_wait->tv_sec = 1;
		timer_wait->tv_usec = 0;
	}
}

/* Fetch next ready thread. */
thread *
thread_fetch(thread_master * m, thread * fetch)
{
	int ret, old_errno;
	thread *thread_obj;
	fd_set readfd;
	fd_set writefd;
	fd_set exceptfd;
	TIMEVAL timer_wait;
	int signal_fd;

	assert(m != NULL);

	/* Timer initialization */
	memset(&timer_wait, 0, sizeof (TIMEVAL));

retry:	/* When thread can't fetch try to find next thread again. */

	/* If there is event process it first. */
	while ((thread_obj = thread_trim_head(&m->event))) {
		*fetch = *thread_obj;

		/* If daemon hanging event is received return NULL pointer */
		if (thread_obj->type == THREAD_TERMINATE) {
			thread_obj->type = THREAD_UNUSED;
			thread_add_unuse(m, thread_obj);
			return NULL;
		}
		thread_obj->type = THREAD_UNUSED;
		thread_add_unuse(m, thread_obj);
		return fetch;
	}

	/* If there is ready threads process them */
	while ((thread_obj = thread_trim_head(&m->ready))) {
		*fetch = *thread_obj;
		thread_obj->type = THREAD_UNUSED;
		thread_add_unuse(m, thread_obj);
		return fetch;
	}

	/*
	 * Re-read the current time to get the maximum accuracy.
	 * Calculate select wait timer. Take care of timeouted fd.
	 */
	set_time_now();
	thread_compute_timer(m, &timer_wait);

	/* Call select function. */
	readfd = m->readfd;
	writefd = m->writefd;
	exceptfd = m->exceptfd;

	signal_fd = signal_rfd();
	FD_SET(signal_fd, &readfd);

	ret = select(FD_SETSIZE, &readfd, &writefd, &exceptfd, &timer_wait);

	/* we have to save errno here because the next syscalls will set it */
	old_errno = errno;

	/* handle signals synchronously, including child reaping */
	if (FD_ISSET(signal_fd, &readfd))
		signal_run_callback();

	/* Update current time */
	set_time_now();

	if (ret < 0) {
		if (old_errno == EINTR)
			goto retry;
		/* Real error. */
		DBG("select error: %s", strerror(old_errno));
		assert(0);
	}

	/* Timeout children */
	thread_obj = m->child.head;
	while (thread_obj) {
		struct _thread *t;

		t = thread_obj;
		thread_obj = t->next;

		if (timer_cmp(time_now, t->sands) >= 0) {
			thread_list_delete(&m->child, t);
			thread_list_add(&m->ready, t);
			t->type = THREAD_CHILD_TIMEOUT;
		}
	}

	/* Read thead. */
	thread_obj = m->read.head;
	while (thread_obj) {
		struct _thread *t;

		t = thread_obj;
		thread_obj = t->next;

		if (FD_ISSET(t->u.fd, &readfd)) {
			assert(FD_ISSET(t->u.fd, &m->readfd));
			FD_CLR(t->u.fd, &m->readfd);
			thread_list_delete(&m->read, t);
			thread_list_add(&m->ready, t);
			t->type = THREAD_READY_FD;
		} else {
			if (timer_cmp(time_now, t->sands) >= 0) {
				FD_CLR(t->u.fd, &m->readfd);
				thread_list_delete(&m->read, t);
				thread_list_add(&m->ready, t);
				t->type = THREAD_READ_TIMEOUT;
			}
		}
	}

	/* Write thead. */
	thread_obj = m->write.head;
	while (thread_obj) {
		struct _thread *t;

		t = thread_obj;
		thread_obj = t->next;

		if (FD_ISSET(t->u.fd, &writefd)) {
			assert(FD_ISSET(t->u.fd, &writefd));
			FD_CLR(t->u.fd, &m->writefd);
			thread_list_delete(&m->write, t);
			thread_list_add(&m->ready, t);
			t->type = THREAD_READY_FD;
		} else {
			if (timer_cmp(time_now, t->sands) >= 0) {
				FD_CLR(t->u.fd, &m->writefd);
				thread_list_delete(&m->write, t);
				thread_list_add(&m->ready, t);
				t->type = THREAD_WRITE_TIMEOUT;
			}
		}
	}
	/* Exception thead. */
	/*... */

	/* Timer update. */
	thread_obj = m->timer.head;
	while (thread_obj) {
		struct _thread *t;

		t = thread_obj;
		thread_obj = t->next;

		if (timer_cmp(time_now, t->sands) >= 0) {
			thread_list_delete(&m->timer, t);
			thread_list_add(&m->ready, t);
			t->type = THREAD_READY;
		}
	}

	/* Return one event. */
	thread_obj = thread_trim_head(&m->ready);

	/* There is no ready thread. */
	if (!thread_obj)
		goto retry;

	*fetch = *thread_obj;
	thread_obj->type = THREAD_UNUSED;
	thread_add_unuse(m, thread_obj);

	return fetch;
}

/* Synchronous signal handler to reap child processes */
void
thread_child_handler(void * v, int sig) {
	thread_master * m = v;
	/*
	 * This is O(n^2), but there will only be a few entries on
	 * this list.
	 */
	thread *thread_obj;
	pid_t pid;
	int status = 77;
	while ((pid = waitpid(-1, &status, WNOHANG))) {
		if (pid == -1) {
			if (errno == ECHILD)
				return;
			DBG("waitpid error: %s", strerror(errno));
			assert(0);
		} else {
			thread_obj = m->child.head;
			while (thread_obj) {
				struct _thread *t;
				t = thread_obj;
				thread_obj = t->next;
				if (pid == t->u.c.pid) {
					thread_list_delete(&m->child, t);
					thread_list_add(&m->ready, t);
					t->u.c.status = status;
					t->type = THREAD_READY;
					break;
				}
			}
		}
	}
}


/* Make unique thread id for non pthread version of thread manager. */
unsigned long int
thread_get_id(void)
{
	static unsigned long int counter = 0;
	return ++counter;
}

/* Call thread ! */
void
thread_call(thread * thread_obj)
{
	thread_obj->id = thread_get_id();
	(*thread_obj->func) (thread_obj);
}

/* Our infinite scheduling loop */
void
launch_scheduler(void)
{
	thread thread_obj;

	signal_set(SIGCHLD, thread_child_handler, master);

	/*
	 * Processing the master thread queues,
	 * return and execute one ready thread.
	 */
	while (thread_fetch(master, &thread_obj)) {
		/* Run until error, used for debuging only */
#ifdef _DEBUG_
		if ((debug & 520) == 520) {
			debug &= ~520;
			thread_add_terminate_event(master);
		}
#endif
		thread_call(&thread_obj);
	}
}
