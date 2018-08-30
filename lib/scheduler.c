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
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <unistd.h>
#ifdef HAVE_SIGNALFD
#include <sys/signalfd.h>
#endif
#include <sys/utsname.h>
#include <linux/version.h>

#include "scheduler.h"
#include "memory.h"
#include "utils.h"
#include "signals.h"
#include "logger.h"
#include "bitops.h"
#include "git-commit.h"
#if !HAVE_EPOLL_CREATE1 || !defined TFD_NONBLOCK
#include "old_socket.h"
#endif

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
static int sav_argc;
static char **sav_argv;

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

/* Update timer value */
static void
thread_update_timer(rb_root_t *root, timeval_t *timer_min)
{
	thread_t *first;

	if (!root->rb_node)
		return;

	first = rb_entry(rb_first(root), thread_t, n);
	if (!first)
		return;

	if (first->sands.tv_sec == TIMER_DISABLED)
		return;

	if (!timerisset(timer_min) ||
	    timercmp(&first->sands, timer_min, <=))
		*timer_min = first->sands;
}

/* Compute the wait timer. Take care of timeouted fd */
static void
thread_set_timer(thread_master_t *m)
{
	timeval_t timer_wait;
	struct itimerspec its;

	/* Prepare timer */
	timerclear(&timer_wait);
	thread_update_timer(&m->timer, &timer_wait);
	thread_update_timer(&m->write, &timer_wait);
	thread_update_timer(&m->read, &timer_wait);
	thread_update_timer(&m->child, &timer_wait);

	if (timerisset(&timer_wait)) {
		/* Re-read the current time to get the maximum accuracy */
		set_time_now();

		/* Take care about monotonic clock */
		timersub(&timer_wait, &time_now, &timer_wait);

		if (timer_wait.tv_sec < 0) {
			/* This will disable the timerfd */
			timerclear(&timer_wait);
		}
	} else {
		/* set timer to a VERY long time */
		timer_wait.tv_sec = LONG_MAX;
		timer_wait.tv_usec = 0;
	}

	its.it_value.tv_sec = timer_wait.tv_sec;
	if (!timerisset(&timer_wait)) {
		/* We really want to avoid doing the select since
		 * testing shows it takes about 13 microseconds
		 * for the timer to expire. */
		its.it_value.tv_nsec = 1;
	}
	else
		its.it_value.tv_nsec = timer_wait.tv_usec * 1000;

	/* We don't want periodic timer expiry */
	its.it_interval.tv_sec = its.it_interval.tv_nsec = 0;

	timerfd_settime(m->timer_fd, 0, &its, NULL);

#ifdef _EPOLL_DEBUG_
	if (prog_type == PROG_TYPE_VRRP)
		log_message(LOG_INFO, "setting timer_fd %lu.%9.9ld", its.it_value.tv_sec, its.it_value.tv_nsec);
#endif
}

static int
thread_timerfd_handler(thread_t *thread)
{
	thread_master_t *m = thread->master;
	uint64_t expired;
	ssize_t len;

	len = read(m->timer_fd, &expired, sizeof(expired));
	if (len < 0)
		log_message(LOG_ERR, "scheduler: Error reading on timerfd fd:%d (%m)", m->timer_fd);

	/* Register next timerfd thread */
	m->timer_thread = thread_add_read(m, thread_timerfd_handler, NULL, m->timer_fd, TIMER_NEVER);

	return 0;
}

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

	LIST_FOREACH(l, thread, e) {
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

void
save_cmd_line_options(int argc, char **argv)
{
	sav_argc = argc;
	sav_argv = argv;
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
log_options(const char *option, const char *option_str, unsigned indent)
{
	const char *p = option_str;
	size_t opt_len = strlen(option);
	const char *end;
	bool first_line = true;

	while (*p) {
		/* Skip leading spaces */
		while (*p == ' ')
			p++;

		end = get_end(p, 100 - opt_len);
		if (first_line) {
			log_message(LOG_INFO, "%*s%s: %.*s", indent, "", option, (int)(end - p), p);
			first_line = false;
		}
		else
			log_message(LOG_INFO, "%*s%.*s", (int)(indent + opt_len + 2), "", (int)(end - p), p);
		p = end;
	}
}

void
log_command_line(unsigned indent)
{
	size_t len = 0;
	char *log_str;
	char *p;
	int i;

	if (!sav_argv)
		return;

	for (i = 0; i < sav_argc; i++)
		len += strlen(sav_argv[i]) + 3;	/* Add opening and closing 's, and following space or '\0' */

	log_str = MALLOC(len);

	for (i = 0, p = log_str; i < sav_argc; i++)
		p += sprintf(p, "%s'%s'", i ? " " : "", sav_argv[i]);

	log_options("Command line", log_str, indent);

	FREE(log_str);
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
			log_command_line(2);
			log_options("configure options", KEEPALIVED_CONFIGURE_OPTIONS, 2);
			log_options("Config options", CONFIGURATION_OPTIONS, 2);
			log_options("System options", SYSTEM_OPTIONS, 2);

//			if (__test_bit(DONT_RESPAWN_BIT, &debug))
//				segv_termination = true;
		}
		else
			log_message(LOG_INFO, "%s exited due to signal %d", prog_id, WTERMSIG(status));
	}

	return false;
}
#endif

/* epoll related */
static int
thread_events_resize(thread_master_t *m, int delta)
{
	unsigned int new_size;

	m->epoll_count += delta;
	if (m->epoll_count < m->epoll_size)
		return 0;

	new_size = ((m->epoll_count / THREAD_EPOLL_REALLOC_THRESH) + 1);
	new_size *= THREAD_EPOLL_REALLOC_THRESH;

	m->epoll_events = REALLOC(m->epoll_events, new_size * sizeof(struct epoll_event));
	if (!m->epoll_events) {
		m->epoll_size = 0;
		return -1;
	}

	m->epoll_size = new_size;
	return 0;
}

static inline int
thread_event_cmp(const thread_event_t *event1, const thread_event_t *event2)
{
	if (event1->fd < event2->fd)
		return -1;
	if (event1->fd > event2->fd)
		return 1;
	return 0;
}

static thread_event_t *
thread_event_new(thread_master_t *m, int fd)
{
	thread_event_t *event;

	event = (thread_event_t *) MALLOC(sizeof(thread_event_t));
	if (!event)
		return NULL;

	if (thread_events_resize(m, 1) < 0) {
		FREE(event);
		return NULL;
	}

	event->fd = fd;

	rb_insert_sort(&m->io_events, event, n, thread_event_cmp);

	return event;
}

static thread_event_t *
thread_event_get(thread_master_t *m, int fd)
{
	thread_event_t event = { .fd = fd };

	return rb_search(&m->io_events, &event, n, thread_event_cmp);
}

static int
thread_event_set(thread_t *thread)
{
	thread_event_t *event = thread->event;
	thread_master_t *m = thread->master;
	struct epoll_event ev;
	int op = EPOLL_CTL_ADD;

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.data.ptr = event;
	if (__test_bit(THREAD_FL_READ_BIT, &event->flags))
		ev.events |= EPOLLIN | EPOLLHUP | EPOLLERR;

	if (__test_bit(THREAD_FL_WRITE_BIT, &event->flags))
		ev.events |= EPOLLOUT;

	if (__test_bit(THREAD_FL_EPOLL_BIT, &event->flags))
		op = EPOLL_CTL_MOD;

	if (epoll_ctl(m->epoll_fd, op, event->fd, &ev) < 0) {
		log_message(LOG_INFO, "scheduler: Error performing control on EPOLL instance (%m)");
		return -1;
	}

	__set_bit(THREAD_FL_EPOLL_BIT, &event->flags);
	return 0;
}

int
thread_event_cancel(thread_t *thread)
{
	thread_event_t *event = thread->event;
	thread_master_t *m = thread->master;

	if (!event) {
		log_message(LOG_INFO, "scheduler: Error performing DEL op no event linked?!");
		return -1;
	}

	if (m->epoll_fd != -1 && epoll_ctl(m->epoll_fd, EPOLL_CTL_DEL, event->fd, NULL) < 0) {
		log_message(LOG_INFO, "scheduler: Error performing DEL op for fd:%d (%m)", event->fd);
		return -1;
	}

	rb_erase(&event->n, &m->io_events);
	m->current_event = NULL;
	thread->event = NULL;
	FREE(event);
	return 0;
}

static int
thread_event_del(thread_t *thread, unsigned flag)
{
	thread_event_t *event = thread->event;
	int ret;

	if (flag == THREAD_FL_EPOLL_READ_BIT &&
	    __test_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags)) {
		__clear_bit(THREAD_FL_READ_BIT, &event->flags);
		if (!__test_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags))
			return thread_event_cancel(thread);

		ret = thread_event_set(thread);
		if (ret < 0)
			return -1;
		event->read = NULL;
		__clear_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags);
		return 0;
	}

	if (flag == THREAD_FL_EPOLL_WRITE_BIT &&
		   __test_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags)) {
		__clear_bit(THREAD_FL_WRITE_BIT, &event->flags);
		if (!__test_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags))
			return thread_event_cancel(thread);

		ret = thread_event_set(thread);
		if (ret < 0)
			return -1;
		event->write = NULL;
		__clear_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags);
	}

	return 0;
}

/* Make thread master. */
thread_master_t *
thread_make_master(void)
{
	thread_master_t *new;

	new = (thread_master_t *) MALLOC(sizeof (thread_master_t));

#if HAVE_EPOLL_CREATE1
	new->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
#else
	new->epoll_fd = epoll_create(0);
#endif
	if (new->epoll_fd < 0) {
		log_message(LOG_INFO, "scheduler: Error creating EPOLL instance (%m)");
		FREE(new);
		return NULL;
	}

#if !HAVE_EPOLL_CREATE1
	if (set_sock_flags(new->epoll_fd, F_SETFD, FD_CLOEXEC))
		log_message(LOG_INFO, "Unable to set CLOEXEC on epoll_fd - %s (%d)", strerror(errno), errno);
#endif

	new->read = RB_ROOT;
	new->write = RB_ROOT;
	new->timer = RB_ROOT;
	new->child = RB_ROOT;
	new->io_events = RB_ROOT;
	INIT_LIST_HEAD(&new->event);
	INIT_LIST_HEAD(&new->signal);
	INIT_LIST_HEAD(&new->ready);
	INIT_LIST_HEAD(&new->unuse);

	/* Register timerfd thread */
	new->timer_fd = timerfd_create(CLOCK_MONOTONIC,
#ifdef TFD_NONBLOCK				/* Since Linux 2.6.27 */
						        TFD_NONBLOCK | TFD_CLOEXEC
#else
							0
#endif
										  );
	if (new->timer_fd < 0) {
		log_message(LOG_ERR, "scheduler: Cant create timerfd (%m)");
		FREE(new);
		return NULL;
	}

#ifndef TFD_NONBLOCK
	if (set_sock_flags(new->timer_fd, F_SETFL, O_NONBLOCK))
		log_message(LOG_INFO, "Unable to set NONBLOCK on timer_fd - %s (%d)", strerror(errno), errno);

	if (set_sock_flags(new->timer_fd, F_SETFD, FD_CLOEXEC))
		log_message(LOG_INFO, "Unable to set CLOEXEC on timer_fd - %s (%d)", strerror(errno), errno);
#endif

	signal_handler_init();

	new->timer_thread = thread_add_read(new, thread_timerfd_handler, NULL, new->timer_fd, TIMER_NEVER);

	add_signal_read_thread(new);

	return new;
}

/* Dump rbtree */
int
thread_rb_dump(rb_root_t *root, const char *tree)
{
	thread_t *thread;
	int i = 1;

	log_message(LOG_INFO, "----[ Begin rb_dump %s ]----", tree);
	rb_for_each_entry(thread, root, n)
		log_message(LOG_INFO, "#%.2d Thread timer: %lu.%6.6ld", i++, thread->sands.tv_sec, thread->sands.tv_usec);
	log_message(LOG_INFO, "----[ End rb_dump ]----");

	return 0;
}

int
thread_list_dump(list_head_t *l, const char *list)
{
	thread_t *thread;
	int i = 1;

	log_message(LOG_INFO, "----[ Begin list_dump %s ]----", list);
	list_for_each_entry(thread, l, next) {
		log_message(LOG_INFO, "#%.2d Thread:%p id:%ld sands: %lu.%6.6ld",
		       i++, thread, thread->id, thread->sands.tv_sec, thread->sands.tv_usec);
//		if (i > 10) break;
	}
	log_message(LOG_INFO, "----[ End list_dump ]----");

	return 0;
}

/* Timer cmp helper */
static int
thread_timer_cmp(thread_t *t1, thread_t *t2)
{
	if (t1->sands.tv_sec != t2->sands.tv_sec) {
		if (t1->sands.tv_sec == TIMER_DISABLED)
			return 1;
		if (t2->sands.tv_sec == TIMER_DISABLED)
			return -1;
		return t1->sands.tv_sec - t2->sands.tv_sec;
	}
	return t1->sands.tv_usec - t2->sands.tv_usec;
}

/* Free all unused thread. */
static void
thread_clean_unuse(thread_master_t * m)
{
	thread_t *thread, *thread_tmp;
	list_head_t *l = &m->unuse;

	list_for_each_entry_safe(thread, thread_tmp, l, next) {
		list_head_del(&thread->next);

		/* free the thread */
		FREE(thread);
		m->alloc--;
	}

	INIT_LIST_HEAD(l);
}

/* Move thread to unuse list. */
static void
thread_add_unuse(thread_master_t *m, thread_t *thread)
{
	assert(m != NULL);
	assert(thread->type == THREAD_UNUSED);
	thread->event = NULL;
	INIT_LIST_HEAD(&thread->next);
	list_add_tail(&thread->next, &m->unuse);
}

/* Move list element to unuse queue */
static void
thread_destroy_list(thread_master_t *m, list_head_t *l)
{
	thread_t *thread, *thread_tmp;

	list_for_each_entry_safe(thread, thread_tmp, l, next) {
		if (thread->event) {
			thread_del_read(thread);
			thread_del_write(thread);
		}
		list_head_del(&thread->next);
		thread->type = THREAD_UNUSED;
		INIT_LIST_HEAD(&thread->next);
		list_add_tail(&thread->next, &m->unuse);
	}
}

static void
thread_destroy_rb(thread_master_t *m, rb_root_t *root)
{
	thread_t *thread, *thread_tmp;

	rb_for_each_entry_safe(thread, thread_tmp, root, n) {
		rb_erase(&thread->n, root);
		thread->type = THREAD_UNUSED;
		INIT_LIST_HEAD(&thread->next);
		list_add_tail(&thread->next, &m->unuse);
	}
}

/* Cleanup master */
void
thread_cleanup_master(thread_master_t * m)
{
	/* Unuse current thread lists */
	thread_destroy_rb(m, &m->read);
	thread_destroy_rb(m, &m->write);
	thread_destroy_rb(m, &m->timer);
	thread_destroy_rb(m, &m->child);
	thread_destroy_list(m, &m->event);
	thread_destroy_list(m, &m->signal);
	thread_destroy_list(m, &m->ready);

	destroy_child_finder();

	/* Clean garbage */
	thread_clean_unuse(m);
}

/* Stop thread scheduler. */
void
thread_destroy_master(thread_master_t * m)
{
	if (m->epoll_fd != -1) {
		close(m->epoll_fd);
		m->epoll_fd = -1;
	}

	if (m->timer_fd != -1)
		close(m->timer_fd);

	if (signal_rfd() != -1)
		signal_handler_destroy();

	thread_cleanup_master(m);

	FREE(m);
}

/* Delete top of the list and return it. */
static thread_t *
thread_trim_head(list_head_t *l)
{
	thread_t *thread;

	if (list_empty(l))
		return NULL;

	thread = list_first_entry(l, thread_t, next);
	list_del_init(&thread->next);
	return thread;
}

/* Make new thread. */
static thread_t *
thread_new(thread_master_t *m)
{
	thread_t *new;

	/* If one thread is already allocated return it */
	new = thread_trim_head(&m->unuse);
	if (new) {
	//	memset(new, 0, sizeof(thread_t));
		INIT_LIST_HEAD(&new->next);
		return new;
	}

	new = (thread_t *) MALLOC(sizeof(thread_t));
	INIT_LIST_HEAD(&new->next);
	m->alloc++;
	return new;
}

/* Add new read thread. */
thread_t *
thread_add_read(thread_master_t *m, int (*func) (thread_t *), void *arg, int fd, unsigned long timer)
{
	thread_event_t *event;
	thread_t *thread;
	int ret;

	assert(m != NULL);

	/* I feel lucky ! :D */
	if (m->current_event && m->current_event->fd == fd) {
		event = m->current_event;
		goto update;
	}

	event = thread_event_get(m, fd);
	if (event && __test_bit(THREAD_FL_READ_BIT, &event->flags) && event->read) {
		log_message(LOG_INFO, "scheduler: There is already read event %p (read %p) registered on fd [%d]", event, event->read, fd);
		return NULL;
	}

	if (!event) {
		event = thread_event_new(m, fd);
		if (!event) {
			log_message(LOG_INFO, "scheduler: Cant allocate read event for fd [%d](%m)", fd);
			return NULL;
		}
	}

  update:
	thread = thread_new(m);
	thread->type = THREAD_READ;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.fd = fd;
	thread->event = event;

	/* Set & flag event */
	__set_bit(THREAD_FL_READ_BIT, &event->flags);
	event->read = thread;
	if (!__test_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags)) {
		ret = thread_event_set(thread);
		if (ret < 0) {
			log_message(LOG_INFO, "scheduler: Cant register read event for fd [%d](%m)", fd);
			thread->type = THREAD_UNUSED;
			thread_add_unuse(m, thread);
			return NULL;
		}
		__set_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags);
	}

	/* Compute read timeout value */
	if (timer == TIMER_NEVER)
		thread->sands.tv_sec = TIMER_DISABLED;
	else {
		set_time_now();
		thread->sands = timer_add_long(time_now, timer);
	}

	/* Sort the thread. */
	rb_insert_sort(&m->read, thread, n, thread_timer_cmp);

	return thread;
}

int
thread_del_read(thread_t *thread)
{
	thread_event_t *event;
	int ret;

	if (!thread)
		return -1;

	event = thread->event;
	if (!event)
		return -1;

	ret = thread_event_del(thread, THREAD_FL_EPOLL_READ_BIT);
	if (ret < 0)
		return -1;

	return 0;
}

static void
thread_del_read_fd(thread_master_t *m, int fd)
{
	thread_event_t *event;

	event = thread_event_get(m, fd);
	if (!event || !event->read)
		return;

	thread_del_read(event->read);
}

static void
thread_read_requeue(thread_master_t *m, int fd, timeval_t new_sands)
{
	thread_t *thread;
	thread_t *prev, *next;
	rb_node_t *prev_node, *next_node;
	thread_event_t *event;

	event = thread_event_get(m, fd);
	if (!event || !event->read)
		return;

	thread = event->read;

	thread->sands = new_sands;

	prev_node = rb_prev(&thread->n);
	next_node = rb_next(&thread->n);

	if (!prev_node && !next_node)
		return;

	prev = rb_entry(prev_node, thread_t, n);
	next = rb_entry(next_node, thread_t, n);

	/* If new timer is between our predecessor and sucessor, it can stay where it is */
	if ((!prev || timercmp(&prev->sands, &new_sands, <=)) &&
	    (!next || timercmp(&next->sands, &new_sands, >=)))
		return;

	/* Can this be optimised? */
	rb_erase(&thread->n, &thread->master->read);
	rb_insert_sort(&thread->master->read, thread, n, thread_timer_cmp);
}

void
thread_requeue_read(thread_master_t *m, int fd, unsigned long timer)
{
	set_time_now();

	thread_read_requeue(m, fd, timer_add_long(time_now, timer));
}

/* Add new write thread. */
thread_t *
thread_add_write(thread_master_t *m, int (*func) (thread_t *), void *arg, int fd, unsigned long timer)
{
	thread_event_t *event;
	thread_t *thread;
	int ret;

	assert(m != NULL);

	/* I feel lucky ! :D */
	if (m->current_event && m->current_event->fd == fd) {
		event = m->current_event;
		goto update;
	}

	event = thread_event_get(m, fd);
	if (event && __test_bit(THREAD_FL_WRITE_BIT, &event->flags) && event->write) {
		log_message(LOG_INFO, "scheduler: There is already write event registered on fd [%d]", fd);
		return NULL;
	}

	if (!event) {
		event = thread_event_new(m, fd);
		if (!event) {
			log_message(LOG_INFO, "scheduler: Cant allocate write event for fd [%d](%m)", fd);
			return NULL;
		}
	}

  update:
	thread = thread_new(m);
	thread->type = THREAD_WRITE;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.fd = fd;
	thread->event = event;

	/* Set & flag event */
	__set_bit(THREAD_FL_WRITE_BIT, &event->flags);
	event->write = thread;
	if (!__test_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags)) {
		ret = thread_event_set(thread);
		if (ret < 0) {
			log_message(LOG_INFO, "scheduler: Cant register write event for fd [%d](%m)" , fd);
			thread->type = THREAD_UNUSED;
			thread_add_unuse(m, thread);
			return NULL;
		}
		__set_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags);
	}

	/* Compute write timeout value */
	if (timer == TIMER_NEVER)
		thread->sands.tv_sec = TIMER_DISABLED;
	else {
		set_time_now();
		thread->sands = timer_add_long(time_now, timer);
	}

	/* Sort the thread. */
	rb_insert_sort(&m->write, thread, n, thread_timer_cmp);

	return thread;
}

int
thread_del_write(thread_t *thread)
{
	thread_event_t *event;
	int ret;

	if (!thread)
		return -1;

	event = thread->event;
	if (!event)
		return -1;

	ret = thread_event_del(thread, THREAD_FL_EPOLL_WRITE_BIT);
	if (ret < 0)
		return -1;

	return 0;
}

/* Add timer event thread. */
thread_t *
thread_add_timer(thread_master_t *m, int (*func) (thread_t *), void *arg, unsigned long timer)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_TIMER;
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
	rb_insert_sort(&m->timer, thread, n, thread_timer_cmp);

	return thread;
}

static void
timer_thread_update_timeout(thread_t *thread, unsigned long timer)
{
	timeval_t sands;
	thread_t *prev, *next;
	rb_node_t *prev_node, *next_node;

	set_time_now();
	sands = timer_add_long(time_now, timer);

	if (timercmp(&thread->sands, &sands, ==))
		return;

	thread->sands = sands;

	prev_node = rb_prev(&thread->n);
	next_node = rb_next(&thread->n);

	if (!prev_node && !next_node)
		return;

	prev = rb_entry(prev_node, thread_t, n);
	next = rb_entry(next_node, thread_t, n);

	/* If new timer is between our predecessor and sucessor, it can stay where it is */
	if ((!prev || timercmp(&prev->sands, &sands, <=)) &&
	    (!next || timercmp(&next->sands, &sands, >=)))
		return;

	/* Can this be optimised? */
	rb_erase(&thread->n, &thread->master->timer);
	rb_insert_sort(&thread->master->timer, thread, n, thread_timer_cmp);
}

thread_t *
thread_add_timer_shutdown(thread_master_t *m, int(*func)(thread_t *), void *arg, unsigned long timer)
{
	thread_t *thread = thread_add_timer(m, func, arg, timer);

	thread->type = THREAD_TIMER_SHUTDOWN;

	return thread;
}

/* Add a child thread. */
thread_t *
thread_add_child(thread_master_t * m, int (*func) (thread_t *), void * arg, pid_t pid, unsigned long timer)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_CHILD;
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
// We may want an rbtree for pid
	rb_insert_sort(&m->child, thread, n, thread_timer_cmp);

// Do we need this?
	if (child_adder)
		child_adder(thread);

	return thread;
}

void
thread_children_reschedule(thread_master_t *m, int (*func)(thread_t *), unsigned long timer)
{
	thread_t *thread;

// What is this used for ??
	set_time_now();
	rb_for_each_entry(thread, &m->child, n) {
		thread->func = func;
		thread->sands = timer_add_long(time_now, timer);
	}
}

/* Add simple event thread. */
thread_t *
thread_add_event(thread_master_t * m, int (*func) (thread_t *), void *arg, int val)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_EVENT;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.val = val;
	INIT_LIST_HEAD(&thread->next);
	list_add_tail(&thread->next, &m->event);

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
	thread->master = m;
	thread->func = func;
	thread->arg = NULL;
	thread->u.val = 0;
	INIT_LIST_HEAD(&thread->next);
	list_add_tail(&thread->next, &m->event);

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

// TODO
#if 0
/* Add signal thread. */
thread_t *
thread_add_signal(thread_master_t *m, int (*func) (thread_t *), void *arg, int val)
{
	thread_t *thread;
	sigset_t mask;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_SIGNAL;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.val = val;
	INIT_LIST_HEAD(&thread->next);
	list_add_tail(&thread->next, &m->signal);

	/* Update signalfd accordingly */
	sigemptyset(&mask);
	sigaddset(&mask, val);
	sigorset(&mask, &mask, &m->signal_mask);
	if (!memcmp(&m->signal_mask, &mask, sizeof(mask)))
		return thread;
	m->signal_mask = mask;
	sigprocmask(SIG_BLOCK, &mask, NULL);
	signalfd(m->signal_fd, &mask, SFD_NONBLOCK);

	return thread;
}
#endif

/* Cancel thread from scheduler. */
void
thread_cancel(thread_t *thread)
{
	thread_master_t *m;

	if (!thread)
		return;

	m = thread->master;

	switch (thread->type) {
	case THREAD_READ:
		thread_event_del(thread, THREAD_FL_EPOLL_READ_BIT);
		rb_erase(&thread->n, &m->read);
		break;
	case THREAD_WRITE:
		thread_event_del(thread, THREAD_FL_EPOLL_WRITE_BIT);
		rb_erase(&thread->n, &m->write);
		break;
	case THREAD_TIMER:
		rb_erase(&thread->n, &m->timer);
		break;
	case THREAD_CHILD:
		/* Does this need to kill the child, or is that the
		 * caller's job?
		 * This function is currently unused, so leave it for now.
		 */
		rb_erase(&thread->n, &m->child);
		break;
	case THREAD_EVENT:
	case THREAD_READY:
	case THREAD_READY_FD:
	case THREAD_READ_TIMEOUT:
	case THREAD_WRITE_TIMEOUT:
	case THREAD_CHILD_TIMEOUT:
		list_head_del(&thread->next);
		break;
	default:
		break;
	}

	thread->type = THREAD_UNUSED;
	thread_add_unuse(m, thread);
}

void
thread_cancel_read(thread_master_t *m, int fd)
{
	thread_t *thread, *thread_tmp;

	rb_for_each_entry_safe(thread, thread_tmp, &m->read, n) {
		if (thread->u.fd == fd) {
			if (thread->event->write)
				thread_cancel(thread->event->write);
			thread_cancel(thread);
			break;
		}
	}
}

#ifdef _INCLUDE_UNUSED_CODE_
/* Delete all events which has argument value arg. */
void
thread_cancel_event(thread_master_t *m, void *arg)
{
	thread_t *thread, *thread_tmp;
	list_head_t *l = &m->event;

// Why doesn't this use thread_cancel() above
	list_for_each_entry_safe(thread, thread_tmp, l, next) {
		if (thread->arg == arg) {
			list_head_del(&thread->next);
			thread->type = THREAD_UNUSED;
			thread_add_unuse(m, thread);
		}
	}
}
#endif

/* Move ready thread into ready queue */
static int
thread_move_ready(thread_master_t *m, rb_root_t *root, thread_t *thread, int type)
{
	rb_erase(&thread->n, root);
	INIT_LIST_HEAD(&thread->next);
	list_add_tail(&thread->next, &m->ready);
	if (thread->type != THREAD_TIMER_SHUTDOWN)
		thread->type = type;
	return 0;
}

/* Move ready thread into ready queue */
static int
thread_rb_move_ready(thread_master_t *m, rb_root_t *root, int type)
{
	thread_t *thread, *thread_tmp;

	rb_for_each_entry_safe(thread, thread_tmp, root, n) {
		if (thread->sands.tv_sec != TIMER_DISABLED && timercmp(&time_now, &thread->sands, >=))
			thread_move_ready(m, root, thread, type);
	}

	return 0;
}

#ifdef _WITH_SNMP_
static int
snmp_read_thread(thread_t *thread)
{
	fd_set snmp_fdset;

	FD_ZERO(&snmp_fdset);
	FD_SET(thread->u.fd, &snmp_fdset);

	snmp_read(&snmp_fdset);
	netsnmp_check_outstanding_agent_requests();

	thread_add_read(thread->master, snmp_read_thread, thread->arg, thread->u.fd, TIMER_NEVER);

	return 0;
}

int
snmp_timeout_thread(thread_t *thread)
{
	snmp_timeout();
	run_alarms();
	netsnmp_check_outstanding_agent_requests();

	thread->master->snmp_timer_thread = thread_add_timer(thread->master, snmp_timeout_thread, thread->arg, TIMER_NEVER);

	return 0;
}

// See https://vincent.bernat.im/en/blog/2012-snmp-event-loop
static void
snmp_epoll_info(thread_master_t *m)
{
	fd_set snmp_fdset;
	int fdsetsize = 0;
	int max_fdsetsize;
	struct timeval snmp_timer_wait = { .tv_sec = TIMER_DISABLED };
	int snmpblock = true;
	unsigned long *old_set, *new_set;	// Must be unsigned for ffsl() to work for us
	unsigned long diff;
	int i;
	int fd;
	int bit;

#if 0
// TODO
#if sizeof fd_mask  != sizeof diff
#error "snmp_epoll_info sizeof(fd_mask) does not match old_set/new_set/diff"
#endif
#endif

	FD_ZERO(&snmp_fdset);

	/* When SNMP is enabled, we may have to select() on additional
	 * FD. snmp_select_info() will add them to `readfd'. The trick
	 * with this function is its last argument. We need to set it
	 * true to set its own timer that we then compare against ours. */
	snmp_select_info(&fdsetsize, &snmp_fdset, &snmp_timer_wait, &snmpblock);

	if (snmpblock)
		snmp_timer_wait.tv_sec = TIMER_DISABLED;
	timer_thread_update_timeout(m->snmp_timer_thread, timer_long(snmp_timer_wait));

	max_fdsetsize = m->snmp_fdsetsize > fdsetsize ? m->snmp_fdsetsize : fdsetsize;
	if (!max_fdsetsize)
		return;

	for (i = 0, old_set = (unsigned long *)&m->snmp_fdset, new_set = (unsigned long *)&snmp_fdset; i <= max_fdsetsize / (int)sizeof(*new_set); i++, old_set++, new_set++) {
		if (*old_set == *new_set)
			continue;

		diff = *old_set ^ *new_set;
		fd = i * sizeof(*old_set) * CHAR_BIT - 1;
		do {
			bit = ffsl(diff);
			diff >>= bit;
			fd += bit;
			if (FD_ISSET(fd, &snmp_fdset)) {
				/* Add the fd */
				thread_add_read(m, snmp_read_thread, 0, fd, TIMER_NEVER);
				FD_SET(fd, &m->snmp_fdset);
			} else {
				/* Remove the fd */
				thread_del_read_fd(m, fd);
				FD_CLR(fd, &m->snmp_fdset);
			}
		} while (diff);
	}
	m->snmp_fdsetsize = fdsetsize;
}
#endif

/* Fetch next ready thread. */
static list_head_t *
thread_fetch_next_queue(thread_master_t *m)
{
	int sav_errno;
	int last_epoll_errno = 0;
	int ret;
	int i;

	assert(m != NULL);

	/* If there is event process it first. */
	if (m->event.next != &m->event)
		return &m->event;

	/* If there are ready threads process them */
	if (m->ready.next != &m->ready)
		return &m->ready;

#if 0	// NEW
	/* If there is event process it first. */
	while ((thread = thread_trim_head(&m->event))) {
		*fetch = *thread;
		m->current_event = thread->event;

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
		m->current_event = thread->event;
		thread->type = THREAD_UNUSED;
		thread_add_unuse(m, thread);
		return fetch;
	}
#endif

retry:
#ifdef _WITH_SNMP_
	if (snmp_running)
		snmp_epoll_info(m);
#endif

	/* Calculate and set select wait timer. Take care of timeouted fd.  */
	thread_set_timer(m);

#ifdef _EPOLL_DEBUG_
	if (prog_type == PROG_TYPE_VRRP)
		log_message(LOG_INFO, "calling epoll_wait");
	thread_rb_dump(&m->read, "read");
	thread_rb_dump(&m->write, "write");
	thread_rb_dump(&m->child, "child");
	thread_rb_dump(&m->timer, "timer");
	thread_list_dump(&m->event, "event");
	thread_list_dump(&m->ready, "ready");
	thread_list_dump(&m->signal, "signal");
	thread_list_dump(&m->unuse, "unuse");
#endif

	/* Call epoll function. */
	ret = epoll_wait(m->epoll_fd, m->epoll_events, m->epoll_count, -1);
	sav_errno = errno;

#ifdef _EPOLL_DEBUG_
	if (prog_type == PROG_TYPE_VRRP)
		log_message(LOG_INFO, "epoll_wait returned %d, errno %d", ret, sav_errno);
#endif

	if (ret < 0) {
		if (sav_errno == EINTR)
			goto retry;

		/* Real error. */
		if (sav_errno != last_epoll_errno) {
			/* Log the error first time only */
			log_message(LOG_INFO, "scheduler: epoll_wait error: %s", strerror(sav_errno));
			last_epoll_errno = sav_errno;
		}
		assert(0);

		/* Make sure we don't sit it a tight loop */
		if (sav_errno == EBADF || sav_errno == EFAULT || sav_errno == EINVAL)
			sleep(1);

		goto retry;
	}

	/* Handle epoll events */
	for (i = 0; i < ret; i++) {
		struct epoll_event *ep_ev;
		thread_event_t *ev;

		ep_ev = &m->epoll_events[i];
		ev = ep_ev->data.ptr;

		/* Error */
// TODO - no thread processing function handles THREAD_READ_ERROR/THREAD_WRITE_ERROR yet
		if (ep_ev->events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
			if (ev->read) {
				thread_move_ready(m, &m->read, ev->read, THREAD_READ_ERROR);
				ev->read = NULL;
			}

			if (ev->write) {
				thread_move_ready(m, &m->write, ev->write, THREAD_WRITE_ERROR);
				ev->write = NULL;
			}

			continue;
		}

		/* READ */
		if (ep_ev->events & EPOLLIN) {
			if (!ev->read) {
				log_message(LOG_INFO, "scheduler: No read thread bound on fd:%d (fl:0x%.4X)"
					      , ev->fd, ep_ev->events);
				assert(0);
			}
			thread_move_ready(m, &m->read, ev->read, THREAD_READY_FD);
			ev->read = NULL;
		}

		/* WRITE */
		if (ep_ev->events & EPOLLOUT) {
			if (!ev->write) {
				log_message(LOG_INFO, "scheduler: No write thread bound on fd:%d (fl:0x%.4X)"
					      , ev->fd, ep_ev->events);
				assert(0);
			}
			thread_move_ready(m, &m->write, ev->write, THREAD_READY_FD);
			ev->write = NULL;
		}
	}

	/* Update current time */
	set_time_now();

	/* Read, Write, Timer thead. */
	thread_rb_move_ready(m, &m->read, THREAD_READ_TIMEOUT);
	thread_rb_move_ready(m, &m->write, THREAD_WRITE_TIMEOUT);
	thread_rb_move_ready(m, &m->timer, THREAD_READY);
	thread_rb_move_ready(m, &m->child, THREAD_CHILD_TIMEOUT);

	/* There is no ready thread. */
	if (m->ready.next == &m->ready)
		goto retry;

	return &m->ready;
}

/* Make unique thread id for non pthread version of thread manager. */
static inline unsigned long
thread_get_id(thread_master_t *m)
{
	return m->id++;
}

/* Call thread ! */
static inline void
thread_call(thread_t * thread)
{
#ifdef _TIMER_DEBUG_
#ifndef _DEBUG_
	if (prog_type == PROG_TYPE_VRRP)
#endif
		log_message(LOG_INFO, "Calling thread function, type %s, addr 0x%p, val/fd/pid %d, status %d", get_thread_type_str(thread->type), thread->func, thread->u.val, thread->u.c.status);
#endif

	thread->id = thread_get_id(thread->master);
	(*thread->func) (thread);
}

void
process_threads(thread_master_t *m)
{
	thread_t* thread;
	list_head_t *thread_list;
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
// TODO - the next test will no longer work since timer will now match as well as signal and interfaces in fault state
(thread->type == THREAD_READY_FD && thread->sands.tv_sec == TIMER_DISABLED) ||
		    thread->type == THREAD_CHILD ||
		    thread->type == THREAD_CHILD_TIMEOUT ||
		    thread->type == THREAD_TIMER_SHUTDOWN ||
		    thread->type == THREAD_TERMINATE) {
			if (thread->func)
				thread_call(thread);

			if (thread->type == THREAD_TERMINATE_START)
				shutting_down = true;
		}

		m->current_event = (thread->type == THREAD_READY_FD) ? thread->event : NULL;
		thread_type = thread->type;
		thread->type = THREAD_UNUSED;
		thread_add_unuse(master, thread);

		/* If we are shutting down, and the shutdown timer is not running and
		 * all children have terminated, then we can terminate */
		if (shutting_down && !m->shutdown_timer_running && !m->child.rb_node)
			return;

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
		rb_for_each_entry(thread, &m->child, n) {
			if (pid == thread->u.c.pid)
				break;
		}
	}

	if (!thread)
		return;

	thread->u.c.status = status;
	if (child_remover)
		child_remover(thread);

	if (permanent_vrrp_checker_error)
	{
		/* The child had a permanant error, so no point in respawning */
		rb_erase(&thread->n, &m->child);
		thread->type = THREAD_UNUSED;
		thread_add_unuse(m, thread);
	}
	else
		thread_move_ready(m, &m->child, thread, THREAD_CHILD);
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

void
thread_add_base_threads(thread_master_t *m)
{
	m->timer_thread = thread_add_read(m, thread_timerfd_handler, NULL, m->timer_fd, TIMER_NEVER);
	add_signal_read_thread(m);
#ifdef _WITH_SNMP_
	m->snmp_timer_thread = thread_add_timer(m, snmp_timeout_thread, 0, TIMER_NEVER);
#endif
}

/* Our infinite scheduling loop */
void
launch_thread_scheduler(thread_master_t *m)
{
// TODO - do this somewhere better
	signal_set(SIGCHLD, thread_child_handler, m);

	process_threads(m);
}
