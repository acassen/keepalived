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
#include "bitops.h"
#include "git-commit.h"
#include <sys/utsname.h>
#include <linux/version.h>

/* global vars */
thread_master_t *master = NULL;
#ifndef _DEBUG_
prog_type_t prog_type;		/* Parent/VRRP/Checker process */
#endif
#ifdef _WITH_SNMP_
bool snmp_running;		/* True if this process is running SNMP */
#endif

/* local variables */
static bool shutting_down;

#ifdef _WITH_LVS_
#include "../keepalived/include/check_daemon.h"
#endif
#ifdef _WITH_VRRP_
#include "../keepalived/include/vrrp_daemon.h"
#endif

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

void
set_child_remover(void (*remover_func)(thread_t *))
{
	child_remover = remover_func;
}

void
destroy_child_finder(void)
{
	set_child_finder(NULL, NULL, NULL, NULL, NULL, 0);
}

#ifndef _DEBUG_
static const char *
get_end(const char *str, size_t max_len)
{
	size_t len = strlen(str);
	const char *end;

	if (len <= max_len)
		return str + len;

	end = str + max_len;
	if (*end == ' ')
		return end;

	while (end > str && *--end != ' ');
	if (end > str)
		return end;

	return str + max_len;
}

static void
log_options(const char *option, const char *option_str)
{
	const char *p = option_str;
	size_t opt_len = strlen(option);
	const char *end;
	bool first_line = true;

	while (*p) {
		end = get_end(p, 100 - opt_len);
		if (first_line) {
			log_message(LOG_INFO, "  %s: %.*s", option, (int)(end - p), p);
			first_line = false;
		}
		else
			log_message(LOG_INFO, "%*s%.*s", (int)(3 + strlen(option) + 2), "", (int)(end - p), p);
		p = end;
		while (*p == ' ')
			p++;
	}
}

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
			struct utsname uname_buf;

			log_message(LOG_INFO, "%s exited due to segmentation fault (SIGSEGV).", prog_id);
			log_message(LOG_INFO, "  %s", "Please report a bug at https://github.com/acassen/keepalived/issues");
			log_message(LOG_INFO, "  %s", "and include this log from when keepalived started, a description");
			log_message(LOG_INFO, "  %s", "of what happened before the crash, your configuration file and the details below.");
			log_message(LOG_INFO, "  %s", "Also provide the output of keepalived -v, what Linux distro and version");
			log_message(LOG_INFO, "  %s", "you are running on, and whether keepalived is being run in a container or VM.");
			log_message(LOG_INFO, "  %s", "A failure to provide all this information may mean the crash cannot be investigated.");
			log_message(LOG_INFO, "  %s", "If you are able to provide a stack backtrace with gdb that would really help.");
			log_message(LOG_INFO, "  Source version %s %s%s", PACKAGE_VERSION,
#ifdef GIT_COMMIT
									   ", git commit ", GIT_COMMIT
#else
									   "", ""
#endif
				   );
			log_message(LOG_INFO, "  Built with kernel headers for Linux %d.%d.%d",
						(LINUX_VERSION_CODE >> 16) & 0xff,
						(LINUX_VERSION_CODE >>  8) & 0xff,
						(LINUX_VERSION_CODE      ) & 0xff);
			uname(&uname_buf);
			log_message(LOG_INFO, "  Running on %s %s %s", uname_buf.sysname, uname_buf.release, uname_buf.version);
			log_options("configure options", KEEPALIVED_CONFIGURE_OPTIONS);
			log_options("Config options", CONFIGURATION_OPTIONS);
			log_options("System options", SYSTEM_OPTIONS);
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

static void
thread_list_make_ready(thread_list_t *list, thread_t *thread, thread_master_t *m, thread_type_t type)
{
	thread_list_delete(list, thread);
	thread->type = type;
	thread_list_add(&m->ready, thread);
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
thread_destroy_list(thread_master_t *m, thread_list_t *thread_list)
{
	thread_t *thread;

	thread = thread_list->head;

	while (thread) {
		thread_t *t;

		t = thread;
		thread = t->next;

		thread_list_delete(thread_list, t);
		t->type = THREAD_UNUSED;
		thread_add_unuse(m, t);
	}
}

/* Cleanup master */
void
thread_cleanup_master(thread_master_t * m)
{
	/* Unuse current thread lists */
	thread_destroy_list(m, &m->read);
	thread_destroy_list(m, &m->write);
	thread_destroy_list(m, &m->timer);
	thread_destroy_list(m, &m->child);
	thread_destroy_list(m, &m->event);
	thread_destroy_list(m, &m->ready);

	destroy_child_finder();

	/* Clear all FDs */
	FD_ZERO(&m->readfd);
	FD_ZERO(&m->writefd);

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

static void
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

thread_t *
thread_add_timer_shutdown(thread_master_t *m, int(*func)(thread_t *),
			  void *arg, unsigned long timer)
{
	thread_t *thread = thread_add_timer(m, func, arg, timer);

	thread->type = THREAD_TIMER_SHUTDOWN;

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

	if (child_adder)
		child_adder(thread);

	return thread;
}

void
thread_children_reschedule(thread_master_t *m, int (*func)(thread_t *), unsigned long timer)
{
	thread_t *thread;

	set_time_now();
	for (thread = m->child.head; thread; thread = thread->next) {
		thread->func = func;
		thread->sands = timer_add_long(time_now, timer);
	}
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

/* Add terminate event thread. */
static thread_t *
thread_add_generic_terminate_event(thread_master_t * m, thread_type_t type, int (*func)(thread_t *))
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = type;
	thread->id = 0;
	thread->master = m;
	thread->func = func;
	thread->arg = NULL;
	thread->u.val = 0;
	thread_list_add(&m->event, thread);

	return thread;
}

thread_t *
thread_add_terminate_event(thread_master_t *m)
{
	return thread_add_generic_terminate_event(m, THREAD_TERMINATE, NULL);
}

thread_t *
thread_add_start_terminate_event(thread_master_t *m, int(*func)(thread_t *))
{
	return thread_add_generic_terminate_event(m, THREAD_TERMINATE_START, func);
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
		if (thread->master->max_fd == thread->u.fd) {
			/* Recalculate max_fd */
			while (thread->master->max_fd &&
			       !FD_ISSET(thread->master->max_fd, &thread->master->readfd) &&
			       !FD_ISSET(thread->master->max_fd, &thread->master->writefd))
				thread->master->max_fd--;
		}
		thread_list_delete(&thread->master->read, thread);
		break;
	case THREAD_WRITE:
		assert(FD_ISSET(thread->u.fd, &thread->master->writefd));
		FD_CLR(thread->u.fd, &thread->master->writefd);
		if (thread->master->max_fd == thread->u.fd) {
			/* Recalculate max_fd */
			while (thread->master->max_fd &&
			       !FD_ISSET(thread->master->max_fd, &thread->master->readfd) &&
			       !FD_ISSET(thread->master->max_fd, &thread->master->writefd))
				thread->master->max_fd--;
		}
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

void
thread_cancel_read(thread_master_t *m, int fd)
{
	thread_t *thread;

	thread = m->read.head;
	while (thread) {
		thread_t *t = thread;
		thread = t->next;

		if (t->u.fd == fd) {
			if (!FD_ISSET(fd, &m->readfd))
				log_message(LOG_WARNING, "Read fd not set [%d]", fd);
			else
				FD_CLR(fd, &m->readfd);
			thread_cancel(t);
			return;
		}
	}
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
static thread_list_t *
thread_fetch_next_queue(thread_master_t *m)
{
	int num_fds, old_errno;
	thread_t *thread;
	thread_t *t;
	fd_set readfd;
	fd_set writefd;
	timeval_t timer_wait;
	int fdsetsize;
#ifdef _WITH_SNMP_
	int snmpblock;
	timeval_t snmp_timer_wait;
	bool is_snmp_timer;
#endif
	bool timer_expired;
	bool timers_done;

	assert(m != NULL);

	/* Timer initialization */
	memset(&timer_wait, 0, sizeof (timeval_t));

retry:	/* When thread can't fetch try to find next thread again. */

	/* If there is event process it first. */
	if (m->event.head)
		return &m->event;

	/* If there are ready threads process them */
	if (m->ready.head)
		return &m->ready;

	/*
	 * Re-read the current time to get the maximum accuracy.
	 * Calculate select wait timer. Take care of timeouted fd.
	 */
	set_time_now();
	thread_compute_timer(m, &timer_wait);

	/* Call select function. */
	readfd = m->readfd;
	writefd = m->writefd;

	/* Recalculate max_fd if necessary */
	while (!FD_ISSET(m->max_fd, &m->readfd) &&
	       !FD_ISSET(m->max_fd, &m->writefd) &&
	       m->max_fd)
		m->max_fd--;

	fdsetsize = m->max_fd + 1;

#ifdef _WITH_SNMP_
	/* When SNMP is enabled, we may have to select() on additional
	 * FD. snmp_select_info() will add them to `readfd'. The trick
	 * with this function is its last argument. We need to set it
	 * true to set its own timer that we then compare against ours. */
	is_snmp_timer = false;
	if (snmp_running) {
		snmpblock = true;
		snmp_select_info(&fdsetsize, &readfd, &snmp_timer_wait, &snmpblock);
		if (!snmpblock && timercmp(&snmp_timer_wait, &timer_wait, <=)) {
			timer_wait = snmp_timer_wait;
			is_snmp_timer = true;
		}
	}
#endif

#ifdef _SELECT_DEBUG_
	if (prog_type == PROG_TYPE_VRRP)
		log_message(LOG_INFO, "select with timer %lu.%6.6ld, fdsetsize %d, readfds 0x%lx, writefds 0x%lx", timer_wait.tv_sec, timer_wait.tv_usec, fdsetsize, readfd.fds_bits[0], writefd.fds_bits[0]);
#endif

	/* Don't call select() if timer_wait is 0 */
	errno = 0;
	if (!timerisset(&timer_wait))
		num_fds = 0;
	else
		num_fds = select(fdsetsize, &readfd, &writefd, NULL, &timer_wait);

	/* we have to save errno here because the next syscalls will set it */
	old_errno = errno;

#ifdef _SELECT_DEBUG_
	if (prog_type == PROG_TYPE_VRRP)
		log_message(LOG_INFO, "Select returned %d, errno %d, readfd 0x%lx, writefd 0x%lx, timer %lu.%6.6ld", num_fds, old_errno, readfd.fds_bits[0], writefd.fds_bits[0], timer_wait.tv_sec, timer_wait.tv_usec);
#endif

	if (num_fds < 0) {
		if (old_errno == EINTR)
			goto retry;
		/* Real error. */
		DBG("select error: %s", strerror(old_errno));
		assert(0);
	}

	timer_expired = (num_fds == 0 || !timerisset(&timer_wait));

	/* Handle SNMP stuff */
#ifdef _WITH_SNMP_
	if (snmp_running) {
		/* We could optimise this by calling snmp_select_info() BEFORE
		 * setting the timer and fds we want, so we see what snmp wants.
		 * We would then know if any of snmp's fds were set */
		if (num_fds > 0)
			snmp_read(&readfd);
		else if (timer_expired && is_snmp_timer)
			snmp_timeout();
	}
#endif

	/* Update current time */
	set_time_now();

	if (timer_expired) {
		/* Timeout children */
		thread = m->child.head;
		while (thread) {
			t = thread;
			thread = t->next;

			if (t->sands.tv_sec == TIMER_DISABLED)
				break;

			if (timercmp(&time_now, &t->sands, >=)) {
				thread_list_make_ready(&m->child, t, m, THREAD_CHILD_TIMEOUT);
				if (child_remover)
					child_remover(t);
			}
			else
				break;
		}
	}

	/* Read thread. */
	thread = m->read.head;
	timers_done = !timer_expired;
	while (thread && (num_fds || !timers_done)) {
		t = thread;
		thread = t->next;

		if (num_fds && FD_ISSET(t->u.fd, &readfd)) {
			assert(FD_ISSET(t->u.fd, &m->readfd));
			num_fds--;
			FD_CLR(t->u.fd, &m->readfd);
			thread_list_make_ready(&m->read, t, m, THREAD_READY_FD);
		} else if (!timers_done &&
			   t->sands.tv_sec != TIMER_DISABLED &&
			   timercmp(&time_now, &t->sands, >=)) {
			FD_CLR(t->u.fd, &m->readfd);
			thread_list_make_ready(&m->read, t, m, THREAD_READ_TIMEOUT);
		}
		else
			timers_done = true;
	}

	/* Write thread. */
	thread = m->write.head;
	timers_done = !timer_expired;
	while (thread && (num_fds || !timers_done)) {
		t = thread;
		thread = t->next;

		if (num_fds && FD_ISSET(t->u.fd, &writefd)) {
			assert(FD_ISSET(t->u.fd, &writefd));
			num_fds--;
			FD_CLR(t->u.fd, &m->writefd);
			thread_list_make_ready(&m->write, t, m, THREAD_READY_FD);
		} else if (!timers_done &&
			   t->sands.tv_sec != TIMER_DISABLED &&
			   timercmp(&time_now, &t->sands, >=)) {
			FD_CLR(t->u.fd, &m->writefd);
			thread_list_make_ready(&m->write, t, m, THREAD_WRITE_TIMEOUT);
		}
		else
			timers_done = true;
	}
	/* Exception thead. */
	/*... */

	/* Timer update. */
	if (timer_expired) {
		thread = m->timer.head;
		while (thread) {
			t = thread;
			thread = t->next;

			if (timercmp(&time_now, &t->sands, >=))
				thread_list_make_ready(&m->timer, t, m, t->type);
			else
				break;
		}
	}

#ifdef _WITH_SNMP_
	run_alarms();
	netsnmp_check_outstanding_agent_requests();
#endif

	/* There is no ready thread. */
	if (!m->ready.head)
		goto retry;

	return &m->ready;
}

void
process_threads(thread_master_t *m)
{
	thread_t* thread;
	thread_list_t* thread_list;
	int thread_type;

	/*
	 * Processing the master thread queues,
	 * return and execute one ready thread.
	 */
	while ((thread_list = thread_fetch_next_queue(m))) {
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

		thread = thread_trim_head(thread_list);
		/* If we are shutting down, only process relevant thread types */
		if (!shutting_down ||
(thread->type == THREAD_READY_FD && thread->sands.tv_sec == TIMER_DISABLED) ||
		    thread->type == THREAD_CHILD ||
		    thread->type == THREAD_CHILD_TIMEOUT ||
		    thread->type == THREAD_TIMER_SHUTDOWN ||
		    thread->type == THREAD_TERMINATE) {
			if (thread->func)
				thread_call(thread);

			if (!shutting_down && thread->type == THREAD_TERMINATE_START)
{
				shutting_down = true;
}
		}

		thread_type = thread->type;
		thread->type = THREAD_UNUSED;
		thread_add_unuse(master, thread);

		/* If daemon hanging event is received stop processing */
		if (thread_type == THREAD_TERMINATE)
			return;
	}
}

static void
process_child_termination(pid_t pid, int status)
{
	thread_master_t * m = master;
	thread_t *thread;
	bool permanent_vrrp_checker_error = false;

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
	thread->u.c.status = status;
	if (child_remover)
		child_remover(thread);

	if (permanent_vrrp_checker_error || __test_bit(CONFIG_TEST_BIT, &debug))
	{
		/* The child had a permanant error, or we were just testing the config,
		 * so no point in respawning */
		thread->type = THREAD_UNUSED;
		thread_list_add(&m->unuse, thread);

		if (!__test_bit(CONFIG_TEST_BIT, &debug))
			raise(SIGTERM);
	}
	else
		thread_list_add(&m->ready, thread);
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
static inline unsigned long
thread_get_id(void)
{
	static unsigned long int counter = 0;
	return ++counter;
}

#ifdef _TIMER_DEBUG_
static const char *
get_thread_type_str(thread_type_t id)
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
	signal_set(SIGCHLD, thread_child_handler, master);

	process_threads(master);
}
