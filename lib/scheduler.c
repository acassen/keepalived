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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

/* SNMP should be included first: it redefines "FREE" */
#ifdef _WITH_SNMP_
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>
#undef FREE
#endif

#ifndef _DEBUG_
#define NDEBUG
#endif
#include <assert.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <unistd.h>

#include "scheduler.h"
#include "memory.h"
#include "utils.h"
#include "signals.h"
#include "logger.h"
#include "bitops.h"

/* global vars */
thread_master_t *master = NULL;
#ifndef _DEBUG_
prog_type_t prog_type;		/* Parent/VRRP/Checker process */
#endif

#ifdef _WITH_LVS_
#include "../keepalived/include/check_daemon.h"
#endif
#ifdef _WITH_VRRP_
#include "../keepalived/include/vrrp_daemon.h"
#endif
#include "../keepalived/include/main.h"

/* Function that returns prog_name if pid is a known child */
static char const * (*child_finder_name)(pid_t);

/* Functions for handling an optimised list of child threads if there can be many */
static void (*child_adder)(thread_t *);
static thread_t *(*child_finder)(pid_t);
static void (*child_remover)(thread_t *);
static void (*child_finder_destroy)(void);
static size_t child_finder_list_size;

static size_t
get_pid_hash(pid_t pid)
{
	return (unsigned)pid % child_finder_list_size;
}

static void
default_child_adder(thread_t *thread)
{
	list_add(&thread->master->child_pid_index[get_pid_hash(thread->u.c.pid)], thread);
}

static thread_t *
default_child_finder(pid_t pid)
{
	thread_t *thread;
	element e;
	list l = &master->child_pid_index[get_pid_hash(pid)];

	if (LIST_ISEMPTY(l))
		return NULL;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		thread = ELEMENT_DATA(e);
		if (thread->u.c.pid == pid)
			return thread;
	}

	return NULL;
}

static void
default_child_remover(thread_t *thread)
{
	list_del(&thread->master->child_pid_index[get_pid_hash(thread->u.c.pid)], thread);
}

static bool
default_child_finder_init(size_t num_entries)
{
	child_finder_list_size = 1;

	if (num_entries < 32)
		return false;

	/* We make the default list size largest power of 2 < num_entries / 2,
	 * subject to a limit of 256 */
	while ((num_entries /= 2) > 1 && child_finder_list_size < 256)
		child_finder_list_size <<= 1;

	master->child_pid_index = alloc_mlist(NULL, NULL, child_finder_list_size);

	return true;
}

static void
default_child_finder_destroy(void)
{
	if (master->child_pid_index) {
		free_mlist(master->child_pid_index, child_finder_list_size);
		master->child_pid_index = NULL;
	}
}

void
set_child_finder_name(char const * (*func)(pid_t))
{
	child_finder_name = func;
}

void
set_child_finder(void (*adder_func)(thread_t *),
		 thread_t *(*finder_func)(pid_t),
		 void (*remover_func)(thread_t *),
		 bool (*init_func)(size_t),	/* returns true if child_finder to be used */
		 void (*destroy_func)(void),
		 size_t num_entries)
{
	bool using_child_finder = false;

	if (child_finder_destroy)
		child_finder_destroy();

	if (adder_func == DEFAULT_CHILD_FINDER) {
		if (default_child_finder_init(num_entries)) {
			child_adder = default_child_adder;
			child_finder = default_child_finder;
			child_remover = default_child_remover;
			child_finder_destroy = default_child_finder_destroy;

			using_child_finder = true;
		}
	} else if (child_adder && init_func && init_func(num_entries)) {
		child_adder = adder_func;
		child_finder = finder_func;
		child_remover = remover_func;
		child_finder_destroy = destroy_func;

		using_child_finder = true;
	}

	if (using_child_finder)
		log_message(LOG_INFO, "Using optimised child finder");
	else {
		child_adder = NULL;
		child_finder = NULL;
		child_remover = NULL;
		child_finder_destroy = NULL;
	}
}

static void
destroy_child_finder(void)
{
	set_child_finder(NULL, NULL, NULL, NULL, NULL, 0);
}

#ifndef _DEBUG_
/* report_child_status returns true if the exit is a hard error, so unable to continue */
bool
report_child_status(int status, pid_t pid, char const *prog_name)
{
	char const *prog_id = NULL;
	char pid_buf[12];	/* "pid 4194303" + '\0' - see definition of PID_MAX_LIMIT in include/linux/threads.h */
	int exit_status ;

	if (prog_name)
		prog_id = prog_name;
	else if (child_finder_name)
		prog_id = child_finder_name(pid);

	if (!prog_id) {
		snprintf(pid_buf, sizeof(pid_buf), "pid %d", pid);
		prog_id = pid_buf;
	}

	if (WIFEXITED(status)) {
		exit_status = WEXITSTATUS(status);

		/* Handle exit codes of vrrp or checker child */
		if (exit_status == KEEPALIVED_EXIT_FATAL ||
		    exit_status == KEEPALIVED_EXIT_CONFIG) {
			log_message(LOG_INFO, "%s exited with permanent error %s. Terminating", prog_id, exit_status == KEEPALIVED_EXIT_CONFIG ? "CONFIG" : "FATAL" );
			return true;
		}

		if (exit_status != EXIT_SUCCESS)
			log_message(LOG_INFO, "%s exited with status %d", prog_id, exit_status);
	} else if (WIFSIGNALED(status)) {
		if (WTERMSIG(status) == SIGSEGV) {
			log_message(LOG_INFO, "%s exited due to segmentation fault (SIGSEGV).", prog_id);
			log_message(LOG_INFO, "  Please report a bug at %s", "https://github.com/acassen/keepalived/issues");
			log_message(LOG_INFO, "  %s", "and include this log from when keepalived started, what happened");
			log_message(LOG_INFO, "  %s", "immediately before the crash, and your configuration file.");
		}
		else
			log_message(LOG_INFO, "%s exited due to signal %d", prog_id, WTERMSIG(status));
	}

	return false;
}
#endif

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

	for (tt = list->head; tt; tt = tt->next) {
		if (timer_cmp(thread->sands, tt->sands) <= 0)
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

	destroy_child_finder();

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

	/* Compute read timeout value */
	set_time_now();
	thread->sands = timer_add_long(time_now, timer);

	/* Sort the thread. */
	thread_list_add_timeval(&m->read, thread);

	return thread;
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

	/* Compute write timeout value */
	set_time_now();
	thread->sands = timer_add_long(time_now, timer);

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
	set_time_now();
	thread->sands = timer_add_long(time_now, timer);

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

	/* Compute write timeout value */
	set_time_now();
	thread->sands = timer_add_long(time_now, timer);

	/* Sort by timeval. */
	thread_list_add_timeval(&m->child, thread);

	if (child_adder)
		child_adder(thread);

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
	case THREAD_READ_TIMEOUT:
	case THREAD_WRITE_TIMEOUT:
	case THREAD_CHILD_TIMEOUT:
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
	if (list->head) {
		if (!timer_isnull(*timer_min)) {
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
thread_compute_timer(thread_master_t * m, timeval_t * timer_wait)
{
	timeval_t timer_min;

	/* Prepare timer */
	timer_reset(timer_min);
	thread_update_timer(&m->timer, &timer_min);
	thread_update_timer(&m->write, &timer_min);
	thread_update_timer(&m->read, &timer_min);
	thread_update_timer(&m->child, &timer_min);

	/* Take care about monotonic clock */
	if (!timer_isnull(timer_min)) {
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
thread_t *
thread_fetch(thread_master_t * m, thread_t * fetch)
{
	int ret, old_errno;
	thread_t *thread;
	fd_set readfd;
	fd_set writefd;
	fd_set exceptfd;
	timeval_t timer_wait;
	int signal_fd;
#ifdef _WITH_SNMP_
	timeval_t snmp_timer_wait;
	int snmpblock = 0;
	int fdsetsize;
#endif
	bool timers_done;

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

	signal_fd = signal_rfd();
	if (signal_fd != -1)
		FD_SET(signal_fd, &readfd);

#ifdef _WITH_SNMP_
	/* When SNMP is enabled, we may have to select() on additional
	 * FD. snmp_select_info() will add them to `readfd'. The trick
	 * with this function is its last argument. We need to set it
	 * to 0 and we need to use the provided new timer only if it
	 * is still set to 0. */
	fdsetsize = FD_SETSIZE;
	snmpblock = 0;
	memcpy(&snmp_timer_wait, &timer_wait, sizeof(timeval_t));
	snmp_select_info(&fdsetsize, &readfd, &snmp_timer_wait, &snmpblock);
	if (snmpblock == 0)
		memcpy(&timer_wait, &snmp_timer_wait, sizeof(timeval_t));
#endif

	ret = select(FD_SETSIZE, &readfd, &writefd, &exceptfd, &timer_wait);

	/* we have to save errno here because the next syscalls will set it */
	old_errno = errno;

	if (ret < 0 && old_errno != EINTR) {
		/* Real error. */
		DBG("select error: %s", strerror(old_errno));
		assert(0);
	}

	/* Handle SNMP stuff */
#ifdef _WITH_SNMP_
	if (ret > 0)
		snmp_read(&readfd);
	else if (ret == 0)
		snmp_timeout();
#endif

	/* handle signals synchronously, including child reaping */
	if (ret > 0 && FD_ISSET(signal_fd, &readfd))
		signal_run_callback();

	/* Update current time */
	set_time_now();

	/* Timeout children */
	thread = m->child.head;
	while (thread) {
		thread_t *t;

		t = thread;
		thread = t->next;

		if (timer_cmp(time_now, t->sands) >= 0) {
			thread_list_delete(&m->child, t);
			thread_list_add(&m->ready, t);
			if (child_remover)
				child_remover(t);
			t->type = THREAD_CHILD_TIMEOUT;
		} else
			break;
	}

	/* Read thead. */
	thread = m->read.head;
	timers_done = false;
	while (thread) {
		thread_t *t;

		t = thread;
		thread = t->next;

		if (ret > 0 && FD_ISSET(t->u.fd, &readfd)) {
			assert(FD_ISSET(t->u.fd, &m->readfd));
			FD_CLR(t->u.fd, &m->readfd);
			thread_list_delete(&m->read, t);
			thread_list_add(&m->ready, t);
			t->type = THREAD_READY_FD;
		} else if (!timers_done) {
			if (timer_cmp(time_now, t->sands) >= 0) {
				FD_CLR(t->u.fd, &m->readfd);
				thread_list_delete(&m->read, t);
				thread_list_add(&m->ready, t);
				t->type = THREAD_READ_TIMEOUT;
			}
			else
				timers_done = true;
		}
	}

	/* Write thead. */
	thread = m->write.head;
	timers_done = false;
	while (thread) {
		thread_t *t;

		t = thread;
		thread = t->next;

		if (ret > 0 && FD_ISSET(t->u.fd, &writefd)) {
			assert(FD_ISSET(t->u.fd, &writefd));
			FD_CLR(t->u.fd, &m->writefd);
			thread_list_delete(&m->write, t);
			thread_list_add(&m->ready, t);
			t->type = THREAD_READY_FD;
		} else if (!timers_done) {
			if (timer_cmp(time_now, t->sands) >= 0) {
				FD_CLR(t->u.fd, &m->writefd);
				thread_list_delete(&m->write, t);
				thread_list_add(&m->ready, t);
				t->type = THREAD_WRITE_TIMEOUT;
			}
			else
				timers_done = true;
		}
	}
	/* Exception thead. */
	/*... */

	/* Timer update. */
	thread = m->timer.head;
	while (thread) {
		thread_t *t;

		t = thread;
		thread = t->next;

		if (timer_cmp(time_now, t->sands) >= 0) {
			thread_list_delete(&m->timer, t);
			thread_list_add(&m->ready, t);
			t->type = THREAD_READY;
		} else
			break;
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

/* Synchronous signal handler to reap child processes */
static void
thread_child_handler(void * v, __attribute__ ((unused)) int unused)
{
	thread_master_t * m = v;
	thread_t *thread;
	pid_t pid;
	int status;
	bool permanent_vrrp_checker_error = false;

	while ((pid = waitpid(-1, &status, WNOHANG))) {
		if (pid == -1) {
			if (errno == ECHILD)
				return;
			DBG("waitpid error: %s", strerror(errno));
			assert(0);
		} else {
#ifndef _DEBUG_
			if (prog_type == PROG_TYPE_PARENT)
				permanent_vrrp_checker_error = report_child_status(status, pid, NULL);
#endif

			if (child_finder)
				thread = child_finder(pid);
			else {
				for (thread = m->child.head; thread; thread = thread->next) {
					if (pid == thread->u.c.pid)
						break;
				}
			}

			if (!thread)
				return;

			thread_list_delete(&m->child, thread);
			if (child_remover)
				child_remover(thread);

			if (permanent_vrrp_checker_error)
			{
				/* The child had a permanant error, so no point in respawning */
				thread->type = THREAD_UNUSED;
				thread_list_add(&m->unuse, thread);

				raise(SIGTERM);
			}
			else
			{
				thread->type = THREAD_READY;
				thread->u.c.status = status;
				thread_list_add(&m->ready, thread);
			}
		}
	}
}


/* Make unique thread id for non pthread version of thread manager. */
static unsigned long
thread_get_id(void)
{
	static unsigned long int counter = 0;
	return ++counter;
}

/* Call thread ! */
void
thread_call(thread_t * thread)
{
	thread->id = thread_get_id();
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
#if defined _DEBUG_ && defined _MEM_CHECK_
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
