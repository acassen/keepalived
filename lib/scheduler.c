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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include "config.h"

/* SNMP should be included first: it redefines "FREE" */
#ifdef _WITH_SNMP_
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#undef FREE
#endif

#ifndef _DEBUG_
#define NDEBUG
#endif
#include <assert.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef HAVE_SIGNALFD
#include <sys/signalfd.h>
#endif

#include "scheduler.h"
#include "memory.h"
#include "utils.h"
#include "signals.h"
#include "logger.h"
#ifdef _DEBUG_
#include "bitops.h"
#endif

/* global vars */
thread_master_t *master = NULL;
#ifndef _DEBUG_
prog_type_t prog_type;		/* Parent/VRRP/Checker process */
#endif
#ifdef _WITH_SNMP_
bool snmp_running;		/* True if this process is running SNMP */
#endif

#ifdef _WITH_LVS_
#include "../keepalived/include/check_daemon.h"
#endif
#ifdef _WITH_VRRP_
#include "../keepalived/include/vrrp_daemon.h"
#endif

/* Function that returns if pid is a known child, and sets *prog_name accordingly */
static bool (*child_finder)(pid_t pid, char const **prog_name);

void
set_child_finder(bool (*func)(pid_t, char const **))
{
	child_finder = func;
}

/* report_child_status returns true if the exit is a hard error, so unable to continue */
bool
report_child_status(int status, pid_t pid, char const *prog_name)
{
	char const *prog_id = NULL;
	char pid_buf[10];	/* "pid 32767" + '\0' */
	int exit_status ;
	bool keepalived_child_process = false;

	if (prog_name) {
		prog_id = prog_name;
		keepalived_child_process = true;
	}
	else if (child_finder && child_finder(pid, &prog_id))
		keepalived_child_process = true;

	if (WIFEXITED(status)) {
		exit_status = WEXITSTATUS(status);

		/* Handle exit codes of vrrp or checker child */
		if (keepalived_child_process &&
		    (exit_status == KEEPALIVED_EXIT_FATAL ||
		     exit_status == KEEPALIVED_EXIT_CONFIG)) {
			log_message(LOG_INFO, "%s exited with permanent error %s. Terminating", prog_id, exit_status == KEEPALIVED_EXIT_CONFIG ? "CONFIG" : "FATAL" );
			return true;
		}

		if (exit_status != EXIT_SUCCESS
#ifndef _DEBUG_
						&& prog_type == PROG_TYPE_PARENT
#endif
										) {
			if (!prog_id) {
				snprintf(pid_buf, sizeof(pid_buf), "pid %d", pid);
				prog_id = pid_buf;
			}

			log_message(LOG_INFO, "%s exited with status %d", prog_id, exit_status);
		}

		return false;
	}
	if (WIFSIGNALED(status)) {
		if (!prog_id) {
			snprintf(pid_buf, sizeof(pid_buf), "pid %d", pid);
			prog_id = pid_buf;
		}

		if (WTERMSIG(status) == SIGSEGV) {
			log_message(LOG_INFO, "%s exited due to segmentation fault (SIGSEGV).", prog_id);
			log_message(LOG_INFO, "  Please report a bug at %s", "https://github.com/acassen/keepalived/issues");
			log_message(LOG_INFO, "  %s", "and include this log from when keepalived started, what happened");
			log_message(LOG_INFO, "  %s", "immediately before the crash, and your configuration file.");
		}
		else
			log_message(LOG_INFO, "%s exited due to signal %d", prog_id, WTERMSIG(status));

		return false;
	}

	return false;
}

/* Make thread master. */
thread_master_t *
thread_make_master(void)
{
	thread_master_t *new;

	new = (thread_master_t *) MALLOC(sizeof (thread_master_t));
	return new;
}

/* Add a new thread to the list. */
static void
thread_list_add(thread_list_t * list, thread_t * thread)
{
	thread->next = NULL;
	thread->prev = list->tail;
	if (list->tail)
		list->tail->next = thread;
	else
		list->head = thread;
	list->tail = thread;
	list->count++;
}

/* Add a new thread to the list. */
static void
thread_list_add_before(thread_list_t * list, thread_t * point, thread_t * thread)
{
	thread->next = point;
	thread->prev = point->prev;
	if (point->prev)
		point->prev->next = thread;
	else
		list->head = thread;
	point->prev = thread;
	list->count++;
}

/* Add a thread in the list sorted by timeval */
static void
thread_list_add_timeval(thread_list_t * list, thread_t * thread)
{
	thread_t *tt;

	if (thread->sands.tv_sec == TIMER_DISABLED) {
		thread_list_add(list, thread);
		return;
	}

	for (tt = list->head; tt; tt = tt->next) {
		if (tt->sands.tv_sec == TIMER_DISABLED || timercmp(&thread->sands, &tt->sands, <=))
			break;
	}

	if (tt)
		thread_list_add_before(list, tt, thread);
	else
		thread_list_add(list, thread);
}

/* Delete a thread from the list. */
static thread_t *
thread_list_delete(thread_list_t * list, thread_t * thread)
{
	if (thread->next)
		thread->next->prev = thread->prev;
	else
		list->tail = thread->prev;
	if (thread->prev)
		thread->prev->next = thread->next;
	else
		list->head = thread->next;
	thread->next = thread->prev = NULL;
	list->count--;
	return thread;
}

/* Free all unused thread. */
static void
thread_clean_unuse(thread_master_t * m)
{
	thread_t *thread;

	thread = m->unuse.head;
	while (thread) {
		thread_t *t;

		t = thread;
		thread = t->next;

		thread_list_delete(&m->unuse, t);

		/* free the thread */
		FREE(t);
		m->alloc--;
	}
}

/* Move thread to unuse list. */
static void
thread_add_unuse(thread_master_t * m, thread_t * thread)
{
	assert(m != NULL);
	assert(thread->next == NULL);
	assert(thread->prev == NULL);
	assert(thread->type == THREAD_UNUSED);
	thread_list_add(&m->unuse, thread);
}

/* Move list element to unuse queue */
static void
thread_destroy_list(thread_master_t * m, thread_list_t thread_list)
{
	thread_t *thread;

	thread = thread_list.head;

	while (thread) {
		thread_t *t;

		t = thread;
		thread = t->next;

		thread_list_delete(&thread_list, t);
		t->type = THREAD_UNUSED;
		thread_add_unuse(m, t);
	}
}

/* Cleanup master */
void
thread_cleanup_master(thread_master_t * m)
{
	/* Unuse current thread lists */
	thread_destroy_list(m, m->read);
	thread_destroy_list(m, m->write);
	thread_destroy_list(m, m->timer);
	thread_destroy_list(m, m->child);
	thread_destroy_list(m, m->event);
	thread_destroy_list(m, m->ready);

	/* Clear all FDs */
	FD_ZERO(&m->readfd);
	FD_ZERO(&m->writefd);
	FD_ZERO(&m->exceptfd);

	/* Clean garbage */
	thread_clean_unuse(m);

	memset(m, 0, sizeof(*m));
}

/* Stop thread scheduler. */
void
thread_destroy_master(thread_master_t * m)
{
	thread_cleanup_master(m);
	FREE(m);
}

/* Delete top of the list and return it. */
static thread_t *
thread_trim_head(thread_list_t * list)
{
	if (list->head)
		return thread_list_delete(list, list->head);
	return NULL;
}

/* Make new thread. */
static thread_t *
thread_new(thread_master_t * m)
{
	thread_t *new;

	/* If one thread is already allocated return it */
	if (m->unuse.head) {
		new = thread_trim_head(&m->unuse);
		memset(new, 0, sizeof (thread_t));
		return new;
	}

	new = (thread_t *) MALLOC(sizeof (thread_t));
	m->alloc++;
	return new;
}

/* Add new read thread. */
thread_t *
thread_add_read(thread_master_t * m, int (*func) (thread_t *)
		, void *arg, int fd, unsigned long timer)
{
	thread_t *thread;

	assert(m != NULL);

	if (FD_ISSET(fd, &m->readfd)) {
		log_message(LOG_WARNING, "There is already read fd [%d]", fd);
		return NULL;
	}

	thread = thread_new(m);
	thread->type = THREAD_READ;
	thread->id = 0;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	FD_SET(fd, &m->readfd);
	thread->u.fd = fd;

	/* Ensure we can be efficient with select */
	if (fd > m->max_fd)
		m->max_fd = fd;

	/* Compute read timeout value */
	if (timer == TIMER_NEVER)
		thread->sands.tv_sec = TIMER_DISABLED;
	else {
		set_time_now();
		thread->sands = timer_add_long(time_now, timer);
	}

	/* Sort the thread. */
	thread_list_add_timeval(&m->read, thread);

	return thread;
}

void
thread_read_requeue(thread_master_t *m, int fd, timeval_t new_sands)
{
	thread_t *tt;
	thread_t *insert = NULL;

	for (tt = m->read.head; tt; tt = tt->next) {
		if (!insert && timercmp(&new_sands, &tt->sands, <=))
			insert = tt;
		if (tt->u.fd == fd)
			break;
	}

	if (!tt)
		return;

	tt->sands = new_sands;

	if (tt == insert)
		return;

	thread_list_delete(&m->read, tt);

	if (insert)
		thread_list_add_before(&m->read, insert, tt);
	else
		thread_list_add_timeval(&m->read, tt);
}

void
thread_requeue_read(thread_master_t *m, int fd, unsigned long timer)
{
	set_time_now();

	thread_read_requeue(m, fd, timer_add_long(time_now, timer));
}

/* Add new write thread. */
thread_t *
thread_add_write(thread_master_t * m, int (*func) (thread_t *)
		 , void *arg, int fd, unsigned long timer)
{
	thread_t *thread;

	assert(m != NULL);

	if (FD_ISSET(fd, &m->writefd)) {
		log_message(LOG_WARNING, "There is already write fd [%d]", fd);
		return NULL;
	}

	thread = thread_new(m);
	thread->type = THREAD_WRITE;
	thread->id = 0;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	FD_SET(fd, &m->writefd);
	thread->u.fd = fd;

	/* Ensure we can be efficient with select */
	if (fd > m->max_fd)
		m->max_fd = fd;

	/* Compute write timeout value */
	if (timer == TIMER_NEVER)
		thread->sands.tv_sec = TIMER_DISABLED;
	else {
		set_time_now();
		thread->sands = timer_add_long(time_now, timer);
	}

	/* Sort the thread. */
	thread_list_add_timeval(&m->write, thread);

	return thread;
}

/* Add timer event thread. */
thread_t *
thread_add_timer(thread_master_t * m, int (*func) (thread_t *)
		 , void *arg, unsigned long timer)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_TIMER;
	thread->id = 0;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;

	/* Do we need jitter here? */
	if (timer == TIMER_NEVER)
		thread->sands.tv_sec = TIMER_DISABLED;
	else {
		set_time_now();
		thread->sands = timer_add_long(time_now, timer);
	}

	/* Sort by timeval. */
	thread_list_add_timeval(&m->timer, thread);

	return thread;
}

/* Add a child thread. */
thread_t *
thread_add_child(thread_master_t * m, int (*func) (thread_t *)
		 , void * arg, pid_t pid, unsigned long timer)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_CHILD;
	thread->id = 0;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.c.pid = pid;
	thread->u.c.status = 0;

	/* Compute child timeout value */
	if (timer == TIMER_NEVER)
		thread->sands.tv_sec = TIMER_DISABLED;
	else {
		set_time_now();
		thread->sands = timer_add_long(time_now, timer);
	}

	/* Sort by timeval. */
	thread_list_add_timeval(&m->child, thread);

	return thread;
}

/* Add simple event thread. */
thread_t *
thread_add_event(thread_master_t * m, int (*func) (thread_t *)
		 , void *arg, int val)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_EVENT;
	thread->id = 0;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.val = val;
	thread_list_add(&m->event, thread);

	return thread;
}

/* Add simple event thread. */
thread_t *
thread_add_terminate_event(thread_master_t * m)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_TERMINATE;
	thread->id = 0;
	thread->master = m;
	thread->func = NULL;
	thread->arg = NULL;
	thread->u.val = 0;
	thread_list_add(&m->event, thread);

	return thread;
}

/* Cancel thread from scheduler. */
int
thread_cancel(thread_t * thread)
{
	if (!thread)
		return -1;

	switch (thread->type) {
	case THREAD_READ:
		assert(FD_ISSET(thread->u.fd, &thread->master->readfd));
		FD_CLR(thread->u.fd, &thread->master->readfd);
		thread_list_delete(&thread->master->read, thread);
		break;
	case THREAD_WRITE:
		assert(FD_ISSET(thread->u.fd, &thread->master->writefd));
		FD_CLR(thread->u.fd, &thread->master->writefd);
		thread_list_delete(&thread->master->write, thread);
		break;
	case THREAD_TIMER:
		thread_list_delete(&thread->master->timer, thread);
		break;
	case THREAD_CHILD:
		/* Does this need to kill the child, or is that the
		 * caller's job?
		 * This function is currently unused, so leave it for now.
		 */
		thread_list_delete(&thread->master->child, thread);
		break;
	case THREAD_EVENT:
		thread_list_delete(&thread->master->event, thread);
		break;
	case THREAD_READY:
	case THREAD_READY_FD:
		thread_list_delete(&thread->master->ready, thread);
		break;
	default:
		break;
	}

	thread->type = THREAD_UNUSED;
	thread_add_unuse(thread->master, thread);
	return 0;
}

#ifdef _INCLUDE_UNUSED_CODE_
/* Delete all events which has argument value arg. */
void
thread_cancel_event(thread_master_t * m, void *arg)
{
	thread_t *thread;

	thread = m->event.head;
	while (thread) {
		thread_t *t;

		t = thread;
		thread = t->next;

		if (t->arg == arg) {
			thread_list_delete(&m->event, t);
			t->type = THREAD_UNUSED;
			thread_add_unuse(m, t);
		}
	}
}
#endif

/* Update timer value */
static void
thread_update_timer(thread_list_t *list, timeval_t *timer_min)
{
	if (!list->head)
		return;

	if (list->head->sands.tv_sec == TIMER_DISABLED)
		return;

	if (!timerisset(timer_min) ||
	    timercmp(&list->head->sands, timer_min, <=))
		*timer_min = list->head->sands;
}

/* Compute the wait timer. Take care of timeouted fd */
static void
thread_compute_timer(thread_master_t * m, timeval_t * timer_wait)
{
	timeval_t timer_min;

	/* Prepare timer */
	timerclear(&timer_min);
	thread_update_timer(&m->timer, &timer_min);
	thread_update_timer(&m->write, &timer_min);
	thread_update_timer(&m->read, &timer_min);
	thread_update_timer(&m->child, &timer_min);

	if (timerisset(&timer_min)) {
		/* Take care about monotonic clock */
		timersub(&timer_min, &time_now, &timer_min);
		if (timer_min.tv_sec < 0) {
			timer_min.tv_sec = timer_min.tv_usec = 0;
		}

		timer_wait->tv_sec = timer_min.tv_sec;
		timer_wait->tv_usec = timer_min.tv_usec;
	} else {
		/* set timer to a VERY long time */
		timer_wait->tv_sec = LONG_MAX;
		timer_wait->tv_usec = 0;
	}
}

/* Fetch next ready thread. */
thread_t *
thread_fetch(thread_master_t * m, thread_t * fetch)
{
	int num_fds, old_errno;
	thread_t *thread;
	fd_set readfd;
	fd_set writefd;
	fd_set exceptfd;
	timeval_t timer_wait;
	int signal_fd;
	int fdsetsize;
#ifdef _WITH_SNMP_
	int snmpblock = 0;
#endif
	bool timer_expired;

	assert(m != NULL);

	/* Timer initialization */
	memset(&timer_wait, 0, sizeof (timeval_t));

retry:	/* When thread can't fetch try to find next thread again. */

	/* If there is event process it first. */
	while ((thread = thread_trim_head(&m->event))) {
		*fetch = *thread;

		/* If daemon hanging event is received return NULL pointer */
		if (thread->type == THREAD_TERMINATE) {
			thread->type = THREAD_UNUSED;
			thread_add_unuse(m, thread);
			return NULL;
		}
		thread->type = THREAD_UNUSED;
		thread_add_unuse(m, thread);
		return fetch;
	}

	/* If there is ready threads process them */
	while ((thread = thread_trim_head(&m->ready))) {
		*fetch = *thread;
		thread->type = THREAD_UNUSED;
		thread_add_unuse(m, thread);
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
	fdsetsize = m->max_fd + 1;

	signal_fd = signal_rfd();
	FD_SET(signal_fd, &readfd);
	if (signal_fd >= m->max_fd)
		fdsetsize = signal_fd + 1;

#ifdef _WITH_SNMP_
	/* When SNMP is enabled, we may have to select() on additional
	 * FD. snmp_select_info() will add them to `readfd'. The trick
	 * with this function is its last argument. We need to set it
	 * to 0 to update our timer. */
	if (snmp_running) {
		snmpblock = 0;
		snmp_select_info(&fdsetsize, &readfd, &timer_wait, &snmpblock);
	}
#endif

#ifdef _SELECT_DEBUG_
	/* if (prog_type == PROG_TYPE_VRRP) */
		log_message(LOG_INFO, "select with timer %lu.%6.6ld, fdsetsize %d", timer_wait.tv_sec, timer_wait.tv_usec, fdsetsize);
#endif

	num_fds = select(fdsetsize, &readfd, &writefd, &exceptfd, &timer_wait);

#ifdef _SELECT_DEBUG_
	/* if (prog_type == PROG_TYPE_VRRP) */
		log_message(LOG_INFO, "Select returned %d, readfd 0x%lx, writefd 0x%lx, exceptfd 0x%lx, timer %lu.%6.6ld", num_fds, readfd.fds_bits[0], writefd.fds_bits[0], exceptfd.fds_bits[0], timer_wait.tv_sec, timer_wait.tv_usec);
#endif

	/* we have to save errno here because the next syscalls will set it */
	old_errno = errno;

	if (num_fds < 0) {
		if (old_errno == EINTR)
			goto retry;
		/* Real error. */
		DBG("select error: %s", strerror(old_errno));
		assert(0);
	}

	/* Handle SNMP stuff */
#ifdef _WITH_SNMP_
	if (snmp_running) {
		if (num_fds > 0)
			snmp_read(&readfd);
		else if (num_fds == 0)
			snmp_timeout();
	}
#endif

	/* handle signals synchronously, including child reaping */
	if (num_fds && FD_ISSET(signal_fd, &readfd)) {
		signal_run_callback();
		num_fds--;
	}

	/* Update current time */
	set_time_now();

	timer_expired = !timerisset(&timer_wait);

	if (timer_expired) {
		/* Timeout children */
		thread = m->child.head;
		while (thread) {
			thread_t *t;

			t = thread;
			thread = t->next;

			if (timercmp(&time_now, &t->sands, >=)) {
				thread_list_delete(&m->child, t);
				thread_list_add(&m->ready, t);
				t->type = THREAD_CHILD_TIMEOUT;
			} else
				break;
		}
	}

	/* Read thread. */
	thread = m->read.head;
	while (thread && (num_fds || timer_expired)) {
		thread_t *t;

		t = thread;
		thread = t->next;

		if (num_fds && FD_ISSET(t->u.fd, &readfd)) {
			assert(FD_ISSET(t->u.fd, &m->readfd));
			FD_CLR(t->u.fd, &m->readfd);
			thread_list_delete(&m->read, t);
			thread_list_add(&m->ready, t);
			t->type = THREAD_READY_FD;
			num_fds--;
		} else if (timer_expired &&
			   t->sands.tv_sec != TIMER_DISABLED &&
			   timercmp(&time_now, &t->sands, >=)) {
			FD_CLR(t->u.fd, &m->readfd);
			thread_list_delete(&m->read, t);
			thread_list_add(&m->ready, t);
			t->type = THREAD_READ_TIMEOUT;
		}
	}

	/* Write thead. */
	thread = m->write.head;
	while (thread && (num_fds || timer_expired)) {
		thread_t *t;

		t = thread;
		thread = t->next;

		if (num_fds && FD_ISSET(t->u.fd, &writefd)) {
			assert(FD_ISSET(t->u.fd, &writefd));
			FD_CLR(t->u.fd, &m->writefd);
			thread_list_delete(&m->write, t);
			thread_list_add(&m->ready, t);
			t->type = THREAD_READY_FD;
			num_fds--;
		} else {
			if (timer_expired &&
			    timercmp(&time_now, &t->sands, >=)) {
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
	if (timer_expired) {
		thread = m->timer.head;
		while (thread) {
			thread_t *t;

			t = thread;
			thread = t->next;

			if (timercmp(&time_now, &t->sands, >=)) {
				thread_list_delete(&m->timer, t);
				thread_list_add(&m->ready, t);
				t->type = THREAD_READY;
			} else
				break;
		}
	}

	/* Return one event. */
	thread = thread_trim_head(&m->ready);

#ifdef _WITH_SNMP_
	run_alarms();
	netsnmp_check_outstanding_agent_requests();
#endif

	/* There is no ready thread. */
	if (!thread)
		goto retry;

	*fetch = *thread;
	thread->type = THREAD_UNUSED;
	thread_add_unuse(m, thread);

	return fetch;
}

static void
process_child_termination(pid_t pid, int status)
{
	bool respawn;
	thread_master_t * m = master;
	/*
	 * This is O(n^2), but there will only be a few entries on
	 * this list.
	 */
	thread_t *thread;

	respawn = !report_child_status(status, pid, NULL);

	thread = m->child.head;
	while (thread) {
		thread_t *t;
		t = thread;
		thread = t->next;
		if (pid == t->u.c.pid) {
			thread_list_delete(&m->child, t);
			t->u.c.status = status;
			if (respawn) {
				t->type = THREAD_READY;
				thread_list_add(&m->ready, t);
			}
			else {
				/* The child had a permanant error, so no point in respawning */
				raise(SIGTERM);
			}

			break;
		}
	}
}

/* Synchronous signal handler to reap child processes */
void
thread_child_handler(__attribute__((unused)) void *v, __attribute__((unused)) int unused)
{
	pid_t pid;
	int status;

	while ((pid = waitpid(-1, &status, WNOHANG))) {
		if (pid == -1) {
			if (errno == ECHILD)
				return;
			DBG("waitpid error: %s", strerror(errno));
			assert(0);
		}
		process_child_termination(pid, status);
	}
}

/* Make unique thread id for non pthread version of thread manager. */
static unsigned long
thread_get_id(void)
{
	static unsigned long int counter = 0;
	return ++counter;
}

#ifdef _TIMER_DEBUG_
static const char *
get_thread_type_str(int id)
{
	if (id == THREAD_READ) return "READ";
	if (id == THREAD_WRITE) return "WRITE";
	if (id == THREAD_TIMER) return "TIMER";
	if (id == THREAD_EVENT) return "EVENT";
	if (id == THREAD_CHILD) return "CHILD";
	if (id == THREAD_READY) return "READY";
	if (id == THREAD_UNUSED) return "UNUSED";
	if (id == THREAD_WRITE_TIMEOUT) return "WRITE_TIMEOUT";
	if (id == THREAD_READ_TIMEOUT) return "READ_TIMEOUT";
	if (id == THREAD_CHILD_TIMEOUT) return "CHILD_TIMEOUT";
	if (id == THREAD_TERMINATE) return "TERMINATE";
	if (id == THREAD_READY_FD) return "READY_FD";

	return "unknown";
}
#endif

/* Call thread ! */
void
thread_call(thread_t * thread)
{
	thread->id = thread_get_id();
#ifdef _TIMER_DEBUG_
#ifndef _DEBUG_
	if (prog_type == PROG_TYPE_VRRP)
#endif
		log_message(LOG_INFO, "Calling thread function, type %s, addr 0x%p, val/fd/pid %d, status %d", get_thread_type_str(thread->type), thread->func, thread->u.val, thread->u.c.status);
#endif
	(*thread->func) (thread);
}

/* Our infinite scheduling loop */
void
launch_scheduler(void)
{
	thread_t thread;

	signal_set(SIGCHLD, thread_child_handler, master);

	/*
	 * Processing the master thread queues,
	 * return and execute one ready thread.
	 */
	while (thread_fetch(master, &thread)) {
		/* Run until error, used for debuging only */
#ifdef _DEBUG_
		if (__test_bit(MEM_ERR_DETECT_BIT, &debug)
#ifdef _WITH_VRRP_
		    && __test_bit(DONT_RELEASE_VRRP_BIT, &debug)
#endif
							        ) {
			__clear_bit(MEM_ERR_DETECT_BIT, &debug);
#ifdef _WITH_VRRP_
			__clear_bit(DONT_RELEASE_VRRP_BIT, &debug);
#endif
			thread_add_terminate_event(master);
		}
#endif
		thread_call(&thread);
	}
}
