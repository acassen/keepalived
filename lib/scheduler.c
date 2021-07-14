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

#include <errno.h>
#include <sys/wait.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/signalfd.h>
#include <sys/utsname.h>
#include <linux/version.h>
#include <sched.h>

#include "scheduler.h"
#include "memory.h"
#include "rbtree.h"
#include "utils.h"
#include "signals.h"
#include "logger.h"
#include "bitops.h"
#include "git-commit.h"
#include "timer.h"
#include "assert_debug.h"
#include "warnings.h"
#include "utils.h"
#include "process.h"


#ifdef THREAD_DUMP
typedef struct _func_det {
	const char *name;
	thread_func_t func;
	rb_node_t n;
} func_det_t;
#endif

/* global vars */
thread_master_t *master = NULL;
#ifndef _ONE_PROCESS_DEBUG_
prog_type_t prog_type;		/* Parent/VRRP/Checker process */
#endif
#ifdef _WITH_SNMP_
bool snmp_running;		/* True if this process is running SNMP */
#endif
#ifdef _EPOLL_DEBUG_
bool do_epoll_debug;
#endif
#ifdef _EPOLL_THREAD_DUMP_
bool do_epoll_thread_dump;
#endif
#ifdef _SCRIPT_DEBUG_
bool do_script_debug;
#endif

/* local variables */
static bool shutting_down;
static int sav_argc;
static char * const *sav_argv;
#ifdef THREAD_DUMP
static rb_root_t funcs = RB_ROOT;
#endif
#ifdef _VRRP_FD_DEBUG_
static void (*extra_threads_debug)(void);
#endif
#ifndef _ONE_PROCESS_DEBUG_
static void (*shutdown_function)(int);
#endif

/* Function that returns prog_name if pid is a known child */
static char const * (*child_finder_name)(pid_t);

/* Function forward references */
#ifdef _WITH_SNMP_
static void snmp_epoll_reset(thread_master_t *);
#endif


#ifdef THREAD_DUMP
static const char *
get_thread_type_str(thread_type_t id)
{
	if (id == THREAD_READ) return "READ";
	if (id == THREAD_WRITE) return "WRITE";
	if (id == THREAD_TIMER) return "TIMER";
	if (id == THREAD_TIMER_SHUTDOWN) return "TIMER_SHUTDOWN";
	if (id == THREAD_EVENT) return "EVENT";
	if (id == THREAD_CHILD) return "CHILD";
	if (id == THREAD_READY) return "READY";
	if (id == THREAD_UNUSED) return "UNUSED";
	if (id == THREAD_WRITE_TIMEOUT) return "WRITE_TIMEOUT";
	if (id == THREAD_READ_TIMEOUT) return "READ_TIMEOUT";
	if (id == THREAD_CHILD_TIMEOUT) return "CHILD_TIMEOUT";
	if (id == THREAD_CHILD_TERMINATED) return "CHILD_TERMINATED";
	if (id == THREAD_TERMINATE_START) return "TERMINATE_START";
	if (id == THREAD_TERMINATE) return "TERMINATE";
	if (id == THREAD_READY_TIMER) return "READY_TIMER";
	if (id == THREAD_READY_READ_FD) return "READY_READ_FD";
	if (id == THREAD_READY_WRITE_FD) return "READY_WRITE_FD";
	if (id == THREAD_READ_ERROR) return "READ_ERROR";
	if (id == THREAD_WRITE_ERROR) return "WRITE_ERROR";
#ifdef USE_SIGNAL_THREADS
	if (id == THREAD_SIGNAL) return "SIGNAL";
#endif

	return "unknown";
}

static inline int
function_cmp(const func_det_t *func1, const func_det_t *func2)
{
	if (func1->func < func2->func)
		return -1;
	if (func1->func > func2->func)
		return 1;
	return 0;
}

static const char *
get_function_name(thread_func_t func)
{
	func_det_t func_det = { .func = func };
	func_det_t *match;
	static char address[19];

	if (!RB_EMPTY_ROOT(&funcs)) {
		match = rb_search(&funcs, &func_det, n, function_cmp);
		if (match)
			return match->name;
	}

	snprintf(address, sizeof address, "%p", func);
	return address;
}

const char *
get_signal_function_name(void (*func)(void *, int))
{
	/* The cast should really be (int (*)(thread_t *))func, but gcc 8.1 produces
	 * a warning with -Wcast-function-type, that the cast is to an incompatible
	 * function type. Since we don't actually call the function, but merely use
	 * it to compare function addresses, what we cast it do doesn't really matter */
	return get_function_name((void *)func);
}

void
register_thread_address(const char *func_name, thread_func_t func)
{
	func_det_t *func_det;

	PMALLOC(func_det);
	if (!func_det)
		return;

	func_det->name = func_name;
	func_det->func = func;

	rb_insert_sort(&funcs, func_det, n, function_cmp);
}

void
register_signal_handler_address(const char *func_name, void (*func)(void *, int))
{
	/* See comment in get_signal_function_name() above */
	register_thread_address(func_name, (void *)func);
}

void
deregister_thread_addresses(void)
{
	func_det_t *func_det, *func_det_tmp;

	if (RB_EMPTY_ROOT(&funcs))
		return;

	rb_for_each_entry_safe(func_det, func_det_tmp, &funcs, n) {
		rb_erase(&func_det->n, &funcs);
		FREE(func_det);
	}
}
#endif

#ifdef _VRRP_FD_DEBUG_
void
set_extra_threads_debug(void (*func)(void))
{
	extra_threads_debug = func;
}
#endif

#ifndef _ONE_PROCESS_DEBUG_
/* The shutdown function is called if the scheduler gets repeated errors calling
 * epoll_wait() and so is unable to continue.
 * github issue 1809 reported the healthchecker process getting error EINVAL with
 * a particular configuration; this looks as though it was memory corruption but
 * we have no way of tracking down how that happened. This provides a way to escape
 * the error if it happens again, by the process terminating, and it will then be
 * restarted by the parent process. */
void
register_shutdown_function(void (*func)(int))
{
	/* The function passed here must not use the scheduler to shutdown */
	shutdown_function = func;
}
#endif

/* Move ready thread into ready queue */
static int
thread_move_ready(thread_master_t *m, rb_root_cached_t *root, thread_t *thread, int type)
{
	rb_erase_cached(&thread->n, root);
	INIT_LIST_HEAD(&thread->e_list);
	list_add_tail(&thread->e_list, &m->ready);
	if (thread->type != THREAD_TIMER_SHUTDOWN)
		thread->type = type;
	return 0;
}

/* Move ready thread into ready queue */
static void
thread_rb_move_ready(thread_master_t *m, rb_root_cached_t *root, int type)
{
	thread_t *thread, *thread_tmp;

	rb_for_each_entry_safe_cached(thread, thread_tmp, root, n) {
		if (thread->sands.tv_sec == TIMER_DISABLED || timercmp(&time_now, &thread->sands, <))
			break;

		if (type == THREAD_READ_TIMEOUT)
			thread->event->read = NULL;
		else if (type == THREAD_WRITE_TIMEOUT)
			thread->event->write = NULL;
		thread_move_ready(m, root, thread, type);
	}
}

/* Update timer value */
static void
thread_update_timer(rb_root_cached_t *root, timeval_t *timer_min)
{
	const thread_t *first;

	if (!root->rb_root.rb_node)
		return;

	first = rb_entry(rb_first_cached(root), thread_t, n);

	if (first->sands.tv_sec == TIMER_DISABLED)
		return;

	if (!timerisset(timer_min) ||
	    timercmp(&first->sands, timer_min, <=))
		*timer_min = first->sands;
}

/* Compute the wait timer. Take care of timeouted fd */
static timeval_t
thread_set_timer(thread_master_t *m)
{
	timeval_t timer_wait, timer_wait_time;
	struct itimerspec its;

	/* Prepare timer */
	timerclear(&timer_wait_time);
	thread_update_timer(&m->timer, &timer_wait_time);
	thread_update_timer(&m->write, &timer_wait_time);
	thread_update_timer(&m->read, &timer_wait_time);
	thread_update_timer(&m->child, &timer_wait_time);

	if (timerisset(&timer_wait_time)) {
		/* Re-read the current time to get the maximum accuracy */
		set_time_now();

		/* Take care about monotonic clock */
		timersub(&timer_wait_time, &time_now, &timer_wait);

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
		/* We could try to avoid doing the epoll_wait since
		 * testing shows it takes about 4 microseconds
		 * for the timer to expire. */
		its.it_value.tv_nsec = 1;
	}
	else
		its.it_value.tv_nsec = timer_wait.tv_usec * 1000;

	/* We don't want periodic timer expiry */
	its.it_interval.tv_sec = its.it_interval.tv_nsec = 0;

	if (timerfd_settime(m->timer_fd, 0, &its, NULL))
		log_message(LOG_INFO, "Setting timer_fd returned errno %d - %m", errno);

#ifdef _EPOLL_DEBUG_
	if (do_epoll_debug)
		log_message(LOG_INFO, "Setting timer_fd %ld.%9.9ld", its.it_value.tv_sec, its.it_value.tv_nsec);
#endif

	return timer_wait_time;
}

static void
thread_timerfd_handler(thread_ref_t thread)
{
	thread_master_t *m = thread->master;
	uint64_t expired;
	ssize_t len;

	len = read(m->timer_fd, &expired, sizeof(expired));
	if (len < 0)
		log_message(LOG_ERR, "scheduler: Error reading on timerfd fd:%d (%m)", m->timer_fd);

	/* Read, Write, Timer, Child thread. */
	thread_rb_move_ready(m, &m->read, THREAD_READ_TIMEOUT);
	thread_rb_move_ready(m, &m->write, THREAD_WRITE_TIMEOUT);
	thread_rb_move_ready(m, &m->timer, THREAD_READY_TIMER);
	thread_rb_move_ready(m, &m->child, THREAD_CHILD_TIMEOUT);

	/* Register next timerfd thread */
	m->timer_thread = thread_add_read(m, thread_timerfd_handler, NULL, m->timer_fd, TIMER_NEVER, 0);
}

/* Child PID cmp helper */
static inline int
thread_child_pid_cmp(const thread_t *t1, const thread_t *t2)
{
	return less_equal_greater_than(t1->u.c.pid, t2->u.c.pid);
}

void
set_child_finder_name(char const * (*func)(pid_t))
{
	child_finder_name = func;
}

void
save_cmd_line_options(int argc, char * const *argv)
{
	sav_argc = argc;
	sav_argv = argv;
}

char * const *
get_cmd_line_options(int *argc)
{
	*argc = sav_argc;
	return sav_argv;
}


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
			log_message(LOG_INFO, "%*s%s: %.*s", (int)indent, "", option, (int)(end - p), p);
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

RELAX_STRICT_OVERFLOW_START
	for (i = 0, p = log_str; i < sav_argc; i++) {
RELAX_END
		p += sprintf(p, "%s'%s'", i ? " " : "", sav_argv[i]);
	}

	log_options("Command line", log_str, indent);

	FREE(log_str);
}

#ifndef _ONE_PROCESS_DEBUG_
unsigned
calc_restart_delay(const timeval_t *last_start_time, unsigned *next_restart_delay, const char *name)
{
	unsigned restart_delay = *next_restart_delay;

	/* If it had been running for more than a minute,
	 * we can restart the process immediately. */
	if (time_now.tv_sec - last_start_time->tv_sec > 60 ||
	    (time_now.tv_sec - last_start_time->tv_sec == 60 &&
	     time_now.tv_usec >= last_start_time->tv_usec)) {
		*next_restart_delay = 0;
		return 0;
	}

#if 0
	/* If it ran for longer than the last restart delay, we can start
	 * again immediately. */
	if (restart_delay &&
	    (time_now.tv_sec - last_start_time->tv_sec > restart_delay ||
	     (time_now.tv_sec - last_start_time->tv_sec == restart_delay &&
	      time_now.tv_usec >= last_start_time->tv_usec))) {
		*next_restart_delay = 0;
		return 0;
	}
#endif

	/* next restart delay starts at 1, double each subsequent time,
	 * up to a limit of 1 minute. */
	if (!restart_delay)
		*next_restart_delay = 1;
	else if (*next_restart_delay > 30)
		*next_restart_delay = 60;
	else
		*next_restart_delay *= 2;

	log_message(LOG_INFO, "Restart of %s process delayed %u seconds to limit respawn rate", name, restart_delay);

	return restart_delay;
}

void
log_child_died(const char *process, pid_t pid)
{
	log_message(LOG_ALERT, "%s child process(%d) died: Respawning", process, pid);
	log_message(LOG_INFO, "  Please log an issue at https://github.com/acassen/keepalived/issues/");
	log_message(LOG_INFO, "  and include a full copy of your keepalived configuration files, and");
	log_message(LOG_INFO, "  copies of the keepalived system log entries around the time this happened");
}

/* report_child_status returns true if the exit is a hard error, so unable to continue */
bool
report_child_status(int status, pid_t pid, char const *prog_name)
{
	char const *prog_id = NULL;
	char pid_buf[4 + PID_MAX_DIGITS + 1];	/* "pid 4194303" + '\0' */
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
			log_message(LOG_INFO, "  %s", "Also provide the output of keepalived -v, and whether keepalived is being");
			log_message(LOG_INFO, "  %s", "run in a container or VM.");
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
			log_message(LOG_INFO, "%s exited due to signal %d (%s)%s", prog_id, WTERMSIG(status), strsignal(WTERMSIG(status)),
					WTERMSIG(status) == SIGKILL ? " - has rlimit_rttime been exceeded?" : "");
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

	if (m->epoll_events)
		FREE(m->epoll_events);
	m->epoll_events = MALLOC(new_size * sizeof(struct epoll_event));
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

	PMALLOC(event);
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

static thread_event_t * __attribute__ ((pure))
thread_event_get(thread_master_t *m, int fd)
{
	thread_event_t event = { .fd = fd };

	return rb_search(&m->io_events, &event, n, thread_event_cmp);
}

static int
thread_event_set(const thread_t *thread)
{
	thread_event_t *event = thread->event;
	thread_master_t *m = thread->master;
	struct epoll_event ev = { .events = 0, .data.ptr = event };
	int op;

	if (__test_bit(THREAD_FL_READ_BIT, &event->flags))
		ev.events |= EPOLLIN;

	if (__test_bit(THREAD_FL_WRITE_BIT, &event->flags))
		ev.events |= EPOLLOUT;

	if (__test_bit(THREAD_FL_EPOLL_BIT, &event->flags))
		op = EPOLL_CTL_MOD;
	else
		op = EPOLL_CTL_ADD;

	if (epoll_ctl(m->epoll_fd, op, event->fd, &ev) < 0) {
		log_message(LOG_INFO, "scheduler: Error %d performing control on EPOLL instance for fd %d (%m)", errno, event->fd);
		return -1;
	}

	__set_bit(THREAD_FL_EPOLL_BIT, &event->flags);
	return 0;
}

static int
thread_event_cancel(const thread_t *thread_cp)
{
	thread_t *thread = no_const(thread_t, thread_cp);
	thread_event_t *event = thread->event;
	thread_master_t *m = thread->master;

	if (!event) {
		log_message(LOG_INFO, "scheduler: Error performing epoll_ctl DEL op no event linked?!");
		return -1;
	}

	/* Ignore error if it was an SNMP fd, since we don't know
	 * if they have been closed */
	if (m->epoll_fd != -1 &&
	    epoll_ctl(m->epoll_fd, EPOLL_CTL_DEL, event->fd, NULL) < 0)
		log_message(LOG_INFO, "scheduler: Error performing epoll_ctl DEL op for fd:%d (%m)", event->fd);

	rb_erase(&event->n, &m->io_events);
	if (event == m->current_event)
		m->current_event = NULL;
	thread_events_resize(m, -1);
	FREE(thread->event);
	return 0;
}

static int
thread_event_del(const thread_t *thread_cp, unsigned flag)
{
	thread_t *thread = no_const(thread_t, thread_cp);
	thread_event_t *event = thread->event;

	if (!__test_bit(flag, &event->flags))
		return 0;

	if (flag == THREAD_FL_EPOLL_READ_BIT) {
		__clear_bit(THREAD_FL_READ_BIT, &event->flags);
		if (!__test_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags))
			return thread_event_cancel(thread);

		event->read = NULL;
	}
	else if (flag == THREAD_FL_EPOLL_WRITE_BIT) {
		__clear_bit(THREAD_FL_WRITE_BIT, &event->flags);
		if (!__test_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags))
			return thread_event_cancel(thread);

		event->write = NULL;
	}

	if (thread_event_set(thread) < 0)
		return -1;

	__clear_bit(flag, &event->flags);
	return 0;
}

/* Make thread master. */
thread_master_t *
thread_make_master(void)
{
	thread_master_t *new;

	PMALLOC(new);

	new->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (new->epoll_fd < 0) {
		log_message(LOG_INFO, "scheduler: Error creating EPOLL instance (%m)");
		FREE(new);
		return NULL;
	}

	new->read = RB_ROOT_CACHED;
	new->write = RB_ROOT_CACHED;
	new->timer = RB_ROOT_CACHED;
	new->child = RB_ROOT_CACHED;
	new->io_events = RB_ROOT;
	new->child_pid = RB_ROOT;
	INIT_LIST_HEAD(&new->event);
#ifdef USE_SIGNAL_THREADS
	INIT_LIST_HEAD(&new->signal);
#endif
	INIT_LIST_HEAD(&new->ready);
	INIT_LIST_HEAD(&new->unuse);


	/* Register timerfd thread */
	new->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (new->timer_fd < 0) {
		log_message(LOG_ERR, "scheduler: Cant create timerfd (%m)");
		FREE(new);
		return NULL;
	}

	new->signal_fd = signal_handler_init();

	new->timer_thread = thread_add_read(new, thread_timerfd_handler, NULL, new->timer_fd, TIMER_NEVER, 0);

	add_signal_read_thread(new);

	return new;
}

#ifdef THREAD_DUMP
static const char *
timer_delay(timeval_t sands)
{
	static char str[43];

	if (sands.tv_sec == TIMER_DISABLED)
		return "NEVER";
	if (sands.tv_sec == 0 && sands.tv_usec == 0)
		return "UNSET";

	if (timercmp(&sands, &time_now, >=)) {
		sands = timer_sub_now(sands);
		snprintf(str, sizeof str, "%ld.%6.6ld", sands.tv_sec, sands.tv_usec);
	} else {
		timersub(&time_now, &sands, &sands);
		snprintf(str, sizeof str, "-%ld.%6.6ld", sands.tv_sec, sands.tv_usec);
	}

	return str;
}

/* Dump rbtree */
static inline void
write_thread_entry(FILE *fp, unsigned index, const thread_t *thread)
{
	conf_write(fp, "#%.2u Thread:%p type %s, event %p, val/fd/pid %d, fd_flags %x, timer: %s, func %s(), id %lu"
		     , index, thread, get_thread_type_str(thread->type)
		     , thread->event, thread->u.val
		     , thread->u.f.flags, timer_delay(thread->sands)
		     , get_function_name(thread->func), thread->id);
}

static void
thread_rb_dump(const rb_root_cached_t *root, const char *tree, FILE *fp)
{
	thread_t *thread;
	unsigned i = 1;

	conf_write(fp, "----[ Begin rb_dump %s ]----", tree);

	rb_for_each_entry_cached(thread, root, n)
		write_thread_entry(fp, i++, thread);

	conf_write(fp, "----[ End rb_dump ]----");
}

static void
thread_list_dump(const list_head_t *l, const char *list_type, FILE *fp)
{
	thread_t *thread;
	unsigned i = 1;

	conf_write(fp, "----[ Begin list_dump %s ]----", list_type);

	list_for_each_entry(thread, l, e_list)
		write_thread_entry(fp, i++, thread);

	conf_write(fp, "----[ End list_dump ]----");
}

static void
event_rb_dump(const rb_root_t *root, const char *tree, FILE *fp)
{
	thread_event_t *event;
	int i = 1;

	conf_write(fp, "----[ Begin rb_dump %s ]----", tree);
	rb_for_each_entry(event, root, n)
		conf_write(fp, "#%.2d event %p fd %d, flags: 0x%lx, read %p, write %p"
			     , i++, event, event->fd, event->flags
			     , event->read, event->write);
	conf_write(fp, "----[ End rb_dump ]----");
}

void
dump_thread_data(const thread_master_t *m, FILE *fp)
{
	thread_rb_dump(&m->read, "read", fp);
	thread_rb_dump(&m->write, "write", fp);
	thread_rb_dump(&m->child, "child", fp);
	thread_rb_dump(&m->timer, "timer", fp);
	thread_list_dump(&m->event, "event", fp);
	thread_list_dump(&m->ready, "ready", fp);
#ifdef USE_SIGNAL_THREADS
	thread_list_dump(&m->signal, "signal", fp);
#endif
	thread_list_dump(&m->unuse, "unuse", fp);
	event_rb_dump(&m->io_events, "io_events", fp);
}
#endif

/* declare thread_timer_cmp() for rbtree compares */
RB_TIMER_CMP(thread);

/* Free all unused thread. */
static void
thread_clean_unuse(thread_master_t * m)
{
	thread_t *thread, *thread_tmp;
	list_head_t *l = &m->unuse;

	list_for_each_entry_safe(thread, thread_tmp, l, e_list) {
		list_del_init(&thread->e_list);

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

	thread->type = THREAD_UNUSED;
	thread->event = NULL;
	INIT_LIST_HEAD(&thread->e_list);
	list_add_tail(&thread->e_list, &m->unuse);
}

/* Move list element to unuse queue */
static void
thread_destroy_list(thread_master_t *m, list_head_t *l)
{
	thread_t *thread, *thread_tmp;

	list_for_each_entry_safe(thread, thread_tmp, l, e_list) {
		/* The following thread types are relevant for the ready list */
		if (thread->type == THREAD_READY_READ_FD ||
		    thread->type == THREAD_READY_WRITE_FD ||
		    thread->type == THREAD_READ_TIMEOUT ||
		    thread->type == THREAD_WRITE_TIMEOUT ||
		    thread->type == THREAD_READ_ERROR ||
		    thread->type == THREAD_WRITE_ERROR) {
			/* Do we have a thread_event, and does it need deleting? */
			if (thread->event) {
				thread_del_read(thread);
				thread_del_write(thread);
			}

			/* Do we have a file descriptor that needs closing ? */
			if (thread->u.f.flags & THREAD_DESTROY_CLOSE_FD)
				thread_close_fd(thread);

			/* Do we need to free arg? */
			if (thread->u.f.flags & THREAD_DESTROY_FREE_ARG)
				FREE(thread->arg);
		}

		list_del_init(&thread->e_list);
		thread_add_unuse(m, thread);
	}
}

static void
thread_destroy_rb(thread_master_t *m, rb_root_cached_t *root)
{
	thread_t *thread, *thread_tmp;

	rb_for_each_entry_safe_cached(thread, thread_tmp, root, n) {
		rb_erase_cached(&thread->n, root);

		/* The following are relevant for the read and write rb lists */
		if (thread->type == THREAD_READ ||
		    thread->type == THREAD_WRITE) {
			/* Do we have a thread_event, and does it need deleting? */
			if (thread->type == THREAD_READ)
				thread_del_read(thread);
			else if (thread->type == THREAD_WRITE)
				thread_del_write(thread);

			/* Do we have a file descriptor that needs closing ? */
			if (thread->u.f.flags & THREAD_DESTROY_CLOSE_FD)
				thread_close_fd(thread);

			/* Do we need to free arg? */
			if (thread->u.f.flags & THREAD_DESTROY_FREE_ARG)
				FREE(thread->arg);
		}

		thread_add_unuse(m, thread);
	}
}

/* Cleanup master */
void
thread_cleanup_master(thread_master_t * m)
{
	/* Unuse current thread lists */
	m->current_event = NULL;
	thread_destroy_rb(m, &m->read);
	thread_destroy_rb(m, &m->write);
	thread_destroy_rb(m, &m->timer);
	thread_destroy_rb(m, &m->child);
	thread_destroy_list(m, &m->event);
#ifdef USE_SIGNAL_THREADS
	thread_destroy_list(m, &m->signal);
#endif
	thread_destroy_list(m, &m->ready);
	m->child_pid = RB_ROOT;

	if (m->current_thread) {
		thread_add_unuse(m, m->current_thread);
		m->current_thread = NULL;
	}

	/* Clean garbage */
	thread_clean_unuse(m);

	FREE(m->epoll_events);
	m->epoll_size = 0;
	m->epoll_count = 0;

	m->timer_thread = NULL;

#ifdef _WITH_SNMP_
	m->snmp_timer_thread = NULL;
	FD_ZERO(&m->snmp_fdset);
	m->snmp_fdsetsize = 0;
#endif
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

	if (m->signal_fd != -1)
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

	thread = list_first_entry(l, thread_t, e_list);
	list_del_init(&thread->e_list);
	return thread;
}

/* Make unique thread id for non pthread version of thread manager. */
static inline unsigned long
thread_get_id(thread_master_t *m)
{
	return m->id++;
}

/* Make new thread. */
static thread_t *
thread_new(thread_master_t *m)
{
	thread_t *new;

	/* If one thread is already allocated return it */
	new = thread_trim_head(&m->unuse);
	if (!new) {
		PMALLOC(new);
		m->alloc++;
	}

	INIT_LIST_HEAD(&new->e_list);
	new->id = thread_get_id(m);
	return new;
}

/* Add new read thread. */
thread_ref_t
thread_add_read_sands(thread_master_t *m, thread_func_t func, void *arg, int fd, const timeval_t *sands, unsigned flags)
{
	thread_event_t *event;
	thread_t *thread;

	assert(m != NULL);

	/* I feel lucky ! :D */
	if (m->current_event && m->current_event->fd == fd)
		event = m->current_event;
	else
		event = thread_event_get(m, fd);

	if (!event) {
		if (!(event = thread_event_new(m, fd))) {
			log_message(LOG_INFO, "scheduler: Cant allocate read event for fd [%d](%m)", fd);
			return NULL;
		}
	}
	else if (__test_bit(THREAD_FL_READ_BIT, &event->flags) && event->read) {
		log_message(LOG_INFO, "scheduler: There is already read event %p (read %p) registered on fd [%d]", event, event->read, fd);
		return NULL;
	}

	thread = thread_new(m);
	thread->type = THREAD_READ;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.f.fd = fd;
	thread->u.f.flags = flags;
	thread->event = event;

	/* Set & flag event */
	__set_bit(THREAD_FL_READ_BIT, &event->flags);
	event->read = thread;
	if (!__test_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags)) {
		if (thread_event_set(thread) < 0) {
			log_message(LOG_INFO, "scheduler: Cant register read event for fd [%d](%m)", fd);
			thread_add_unuse(m, thread);
			return NULL;
		}
		__set_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags);
	}

	thread->sands = *sands;

	/* Sort the thread. */
	rb_insert_sort_cached(&m->read, thread, n, thread_timer_cmp);

	return thread;
}

thread_ref_t
thread_add_read(thread_master_t *m, thread_func_t func, void *arg, int fd, unsigned long timer, unsigned flags)
{
	timeval_t sands;

	/* Compute read timeout value */
	if (timer == TIMER_NEVER) {
		sands.tv_sec = TIMER_DISABLED;
		sands.tv_usec = 0;
	} else {
		set_time_now();
		sands = timer_add_long(time_now, timer);
	}

	return thread_add_read_sands(m, func, arg, fd, &sands, flags);
}

void
thread_del_read(thread_ref_t thread)
{
	if (!thread || !thread->event)
		return;

	thread_event_del(thread, THREAD_FL_EPOLL_READ_BIT);
}

#ifdef _WITH_SNMP_
static void
thread_del_read_fd(thread_master_t *m, int fd)
{
	const thread_event_t *event;

	event = thread_event_get(m, fd);
	if (!event || !event->read)
		return;

	thread_cancel(event->read);
}
#endif

static void
thread_read_requeue(thread_master_t *m, int fd, const timeval_t *new_sands)
{
	thread_t *thread;
	thread_event_t *event;

	event = thread_event_get(m, fd);
	if (!event || !event->read)
		return;

	thread = event->read;

	if (thread->type != THREAD_READ) {
		/* If the thread is not on the read list, don't touch it */
		return;
	}

	thread->sands = *new_sands;

	rb_move_cached(&thread->master->read, thread, n, thread_timer_cmp);
}

/* Adjust the timeout of a read thread */
void
thread_requeue_read(thread_master_t *m, int fd, const timeval_t *sands)
{
	thread_read_requeue(m, fd, sands);
}

/* Add new write thread. */
thread_ref_t
thread_add_write(thread_master_t *m, thread_func_t func, void *arg, int fd, unsigned long timer, unsigned flags)
{
	thread_event_t *event;
	thread_t *thread;

	assert(m != NULL);

	/* I feel lucky ! :D */
	if (m->current_event && m->current_event->fd == fd)
		event = m->current_event;
	else
		event = thread_event_get(m, fd);

	if (!event) {
		if (!(event = thread_event_new(m, fd))) {
			log_message(LOG_INFO, "scheduler: Cant allocate write event for fd [%d](%m)", fd);
			return NULL;
		}
	}
	else if (__test_bit(THREAD_FL_WRITE_BIT, &event->flags) && event->write) {
		log_message(LOG_INFO, "scheduler: There is already write event registered on fd [%d]", fd);
		return NULL;
	}

	thread = thread_new(m);
	thread->type = THREAD_WRITE;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.f.fd = fd;
	thread->u.f.flags = flags;
	thread->event = event;

	/* Set & flag event */
	__set_bit(THREAD_FL_WRITE_BIT, &event->flags);
	event->write = thread;
	if (!__test_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags)) {
		if (thread_event_set(thread) < 0) {
			log_message(LOG_INFO, "scheduler: Cant register write event for fd [%d](%m)" , fd);
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
	rb_insert_sort_cached(&m->write, thread, n, thread_timer_cmp);

	return thread;
}

void
thread_del_write(thread_ref_t thread)
{
	if (!thread || !thread->event)
		return;

	thread_event_del(thread, THREAD_FL_EPOLL_WRITE_BIT);
}

void
thread_close_fd(thread_ref_t thread_cp)
{
	thread_t *thread = no_const(thread_t, thread_cp);

	if (thread->u.f.fd == -1)
		return;

	if (thread->event)
		thread_event_cancel(thread);

	close(thread->u.f.fd);
	thread->u.f.fd = -1;
}

/* Add timer event thread. */
thread_ref_t
thread_add_timer(thread_master_t *m, thread_func_t func, void *arg, unsigned long timer)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_TIMER;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.val = 0;

	/* Do we need jitter here? */
	if (timer == TIMER_NEVER)
		thread->sands.tv_sec = TIMER_DISABLED;
	else {
		set_time_now();
		thread->sands = timer_add_long(time_now, timer);
	}

	/* Sort by timeval. */
	rb_insert_sort_cached(&m->timer, thread, n, thread_timer_cmp);

	return thread;
}

void
timer_thread_update_timeout(thread_ref_t thread_cp, unsigned long timer)
{
	thread_t *thread = no_const(thread_t, thread_cp);
	timeval_t sands;

	if (thread->type > THREAD_MAX_WAITING) {
		/* It is probably on the ready list, so we'd better just let it run */
		return;
	}

	set_time_now();
	sands = timer_add_long(time_now, timer);

	if (timercmp(&thread->sands, &sands, ==))
		return;

	thread->sands = sands;

	rb_move_cached(&thread->master->timer, thread, n, thread_timer_cmp);
}

thread_ref_t
thread_add_timer_shutdown(thread_master_t *m, thread_func_t func, void *arg, unsigned long timer)
{
	union {
		thread_t *p;
		const thread_t *cp;
	} thread;

	thread.cp = thread_add_timer(m, func, arg, timer);

	thread.p->type = THREAD_TIMER_SHUTDOWN;

	return thread.cp;
}

/* Add a child thread. */
thread_ref_t
thread_add_child(thread_master_t * m, thread_func_t func, void * arg, pid_t pid, unsigned long timer)
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
	rb_insert_sort_cached(&m->child, thread, n, thread_timer_cmp);

	/* Sort by PID */
	rb_insert_sort(&m->child_pid, thread, rb_data, thread_child_pid_cmp);

	return thread;
}

void
thread_children_reschedule(thread_master_t *m, thread_func_t func, unsigned long timer)
{
	thread_t *thread;

// What is this used for ??
	set_time_now();
	rb_for_each_entry_cached(thread, &m->child, n) {
		thread->func = func;
		thread->sands = timer_add_long(time_now, timer);
	}
}

/* Add simple event thread. */
thread_ref_t
thread_add_event(thread_master_t * m, thread_func_t func, void *arg, int val)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_EVENT;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.val = val;
	INIT_LIST_HEAD(&thread->e_list);
	list_add_tail(&thread->e_list, &m->event);

	return thread;
}

/* Add terminate event thread. */
static thread_ref_t
thread_add_generic_terminate_event(thread_master_t * m, thread_type_t type, thread_func_t func)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = type;
	thread->master = m;
	thread->func = func;
	thread->arg = NULL;
	thread->u.val = 0;
	INIT_LIST_HEAD(&thread->e_list);
	list_add_tail(&thread->e_list, &m->event);

	return thread;
}

thread_ref_t
thread_add_terminate_event(thread_master_t *m)
{
	return thread_add_generic_terminate_event(m, THREAD_TERMINATE, NULL);
}

thread_ref_t
thread_add_start_terminate_event(thread_master_t *m, thread_func_t func)
{
	return thread_add_generic_terminate_event(m, THREAD_TERMINATE_START, func);
}

#ifdef USE_SIGNAL_THREADS
/* Add signal thread. */
thread_ref_t
thread_add_signal(thread_master_t *m, thread_func_t func, void *arg, int signum)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_SIGNAL;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.val = signum;
	INIT_LIST_HEAD(&thread->e_list);
	list_add_tail(&thread->e_list, &m->signal);

	/* Update signalfd accordingly */
	if (sigismember(&m->signal_mask, signum))
		return thread;
	sigaddset(&m->signal_mask, signum);
	signalfd(m->signal_fd, &m->signal_mask, 0);

	return thread;
}
#endif

/* Cancel thread from scheduler. */
void
thread_cancel(thread_ref_t thread_cp)
{
	thread_t *thread = no_const(thread_t, thread_cp);
	thread_master_t *m;

	if (!thread || thread->type == THREAD_UNUSED)
		return;

	m = thread->master;

	switch (thread->type) {
	case THREAD_READ:
		thread_event_del(thread, THREAD_FL_EPOLL_READ_BIT);
		rb_erase_cached(&thread->n, &m->read);
		break;
	case THREAD_WRITE:
		thread_event_del(thread, THREAD_FL_EPOLL_WRITE_BIT);
		rb_erase_cached(&thread->n, &m->write);
		break;
	case THREAD_TIMER:
		rb_erase_cached(&thread->n, &m->timer);
		break;
	case THREAD_CHILD:
		/* Does this need to kill the child, or is that the
		 * caller's job?
		 * This function is currently unused, so leave it for now.
		 */
		rb_erase_cached(&thread->n, &m->child);
		rb_erase(&thread->rb_data, &m->child_pid);
		break;
	case THREAD_READY_READ_FD:
	case THREAD_READ_TIMEOUT:
	case THREAD_READ_ERROR:
		if (thread->event)
			thread_event_del(thread, THREAD_FL_EPOLL_READ_BIT);
		list_del_init(&thread->e_list);
		break;
	case THREAD_READY_WRITE_FD:
	case THREAD_WRITE_TIMEOUT:
	case THREAD_WRITE_ERROR:
		if (thread->event)
			thread_event_del(thread, THREAD_FL_EPOLL_WRITE_BIT);
		list_del_init(&thread->e_list);
		break;
	case THREAD_EVENT:
	case THREAD_READY:
#ifdef USE_SIGNAL_THREADS
	case THREAD_SIGNAL:
#endif
	case THREAD_CHILD_TIMEOUT:
	case THREAD_CHILD_TERMINATED:
		list_del_init(&thread->e_list);
		break;
	default:
		break;
	}

	thread_add_unuse(m, thread);
}

void
thread_cancel_read(thread_master_t *m, int fd)
{
	thread_t *thread, *thread_tmp;

	rb_for_each_entry_safe_cached(thread, thread_tmp, &m->read, n) {
		if (thread->u.f.fd == fd) {
			if (thread->event->write) {
				thread_cancel(thread->event->write);
				thread->event->write = NULL;
			}
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
	list_for_each_entry_safe(thread, thread_tmp, l, e_list) {
		if (thread->arg == arg) {
			list_del_init(&thread->e_list);
			thread_add_unuse(m, thread);
		}
	}
}
#endif

#ifdef _WITH_SNMP_
static void
snmp_read_thread(thread_ref_t thread)
{
	fd_set snmp_fdset;
	thread_event_t *event;

	FD_ZERO(&snmp_fdset);
	FD_SET(thread->u.f.fd, &snmp_fdset);

	if (thread->type == THREAD_READ_ERROR) {
		/* We need to remove the epoll entry for this fd since the snmp
		 * code may close it. If it remains open, snmp_epoll_reset will
		 * sort it out. */
		thread_event_del(thread, THREAD_FL_EPOLL_READ_BIT);
		FD_CLR(thread->u.f.fd, &master->snmp_fdset);
	}

	snmp_read(&snmp_fdset);
	netsnmp_check_outstanding_agent_requests();

	if (thread->type == THREAD_READ_ERROR)
		snmp_epoll_reset(thread->master);
	else {
		snmp_epoll_info(thread->master);

		if (FD_ISSET(thread->u.f.fd, &master->snmp_fdset)) {
			event = thread_event_get(thread->master, thread->u.f.fd);
			if (!event || !event->read)
				thread_add_read(thread->master, snmp_read_thread, thread->arg, thread->u.f.fd, TIMER_NEVER, 0);
		}
	}
}

void
snmp_timeout_thread(thread_ref_t thread)
{
	snmp_timeout();
	run_alarms();
	netsnmp_check_outstanding_agent_requests();

	thread->master->snmp_timer_thread = thread_add_timer(thread->master, snmp_timeout_thread, thread->arg, TIMER_NEVER);

	snmp_epoll_info(thread->master);
}

// See https://vincent.bernat.im/en/blog/2012-snmp-event-loop
void
snmp_epoll_info(thread_master_t *m)
{
	fd_set snmp_fdset;
	int fdsetsize = 0;
	int max_fdsetsize;
	int set_words;
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
	 * FDs. snmp_select_info() will add them to `readfd'. The trick
	 * with this function is its last argument. We need to set it
	 * true to set its own timer, we then update the snmp timer thread timeout */
	snmp_select_info(&fdsetsize, &snmp_fdset, &snmp_timer_wait, &snmpblock);

	if (snmpblock)
		snmp_timer_wait.tv_sec = TIMER_DISABLED;
	timer_thread_update_timeout(m->snmp_timer_thread, timer_long(snmp_timer_wait));

	max_fdsetsize = m->snmp_fdsetsize > fdsetsize ? m->snmp_fdsetsize : fdsetsize;
	if (!max_fdsetsize)
		return;
	set_words = (max_fdsetsize - 1) / (sizeof(*old_set) * CHAR_BIT) + 1;

	/* coverity[ptr_arith] */
	for (i = 0, old_set = PTR_CAST(unsigned long, &m->snmp_fdset), new_set = PTR_CAST(unsigned long, &snmp_fdset); i < set_words; i++, old_set++, new_set++) {
		if (*old_set == *new_set)
			continue;

		diff = *old_set ^ *new_set;
		fd = i * sizeof(*old_set) * CHAR_BIT - 1;
		while (diff) {
			bit = ffsl(diff);
			if (bit == sizeof(diff) * CHAR_BIT)
				diff = 0;
			else
				diff >>= bit;
			fd += bit;
			if (FD_ISSET(fd, &snmp_fdset)) {
				/* Add the fd */
				thread_add_read(m, snmp_read_thread, 0, fd, TIMER_NEVER, 0);
				FD_SET(fd, &m->snmp_fdset);
			} else {
				/* Remove the fd */
				thread_del_read_fd(m, fd);
				FD_CLR(fd, &m->snmp_fdset);
			}
		}
	}
	m->snmp_fdsetsize = fdsetsize;
}

/* If a file descriptor was registered with epoll, but it has been closed, the registration
 * will have been lost, even though the new fd value is the same. We therefore need to
 * unregister all the fds we had registered, and reregister them. */
static void
snmp_epoll_update(thread_master_t *m, bool reset)
{
	fd_set snmp_fdset;
	int fdsetsize = 0;
	unsigned set_words;
	struct timeval snmp_timer_wait = { .tv_sec = TIMER_DISABLED };
	int snmpblock = true;
	unsigned long *old_set, *new_set;	// Must be unsigned for ffsl() to work for us
	unsigned long bits;
	unsigned i;
	int fd;
	int bit;

	FD_ZERO(&snmp_fdset);

	snmp_select_info(&fdsetsize, &snmp_fdset, &snmp_timer_wait, &snmpblock);

	set_words = m->snmp_fdsetsize ? (m->snmp_fdsetsize - 1) / (sizeof(*old_set) * CHAR_BIT) + 1 : 0;

	/* Clear all the fds that were registered with epoll */
	for (i = 0, old_set = PTR_CAST(unsigned long, &m->snmp_fdset); i < set_words; i++, old_set++) {
		bits = *old_set;
		fd = i * sizeof(*old_set) * CHAR_BIT - 1;
		while (bits) {
			bit = ffsl(bits);
			if (bit == sizeof(bits) * CHAR_BIT)
				bits = 0;
			else
				bits >>= bit;
			fd += bit;

			/* Remove the fd */
			thread_del_read_fd(m, fd);
			FD_CLR(fd, &m->snmp_fdset);
		}
	}

	if (reset) {
		/* Add the file descriptors that are now in use */
		set_words = fdsetsize ? (fdsetsize - 1) / (sizeof(*new_set) * CHAR_BIT) + 1 : 0;

		for (i = 0, new_set = PTR_CAST(unsigned long, &snmp_fdset); i < set_words; i++, new_set++) {
			bits = *new_set;
			fd = i * sizeof(*new_set) * CHAR_BIT - 1;
			while (bits) {
				bit = ffsl(bits);
				if (bit == sizeof(bits) * CHAR_BIT)
					bits = 0;
				else
					bits >>= bit;
				fd += bit;

				/* Add the fd */
				thread_add_read(m, snmp_read_thread, 0, fd, TIMER_NEVER, 0);
				FD_SET(fd, &m->snmp_fdset);
			}
		}
	} else
		fdsetsize = 0;

	m->snmp_fdsetsize = fdsetsize;
}

static void
snmp_epoll_reset(thread_master_t *m)
{
	snmp_epoll_update(m, true);
}

void
snmp_epoll_clear(thread_master_t *m)
{
	snmp_epoll_update(m, false);
	thread_cancel(m->snmp_timer_thread);
	m->snmp_timer_thread = NULL;
}
#endif

/* Fetch next ready thread. */
static list_head_t *
thread_fetch_next_queue(thread_master_t *m)
{
	int last_epoll_errno = 0;
#ifndef _ONE_PROCESS_DEBUG_
	unsigned last_epoll_errno_count = 0;
#endif
	int ret;
	int i;
	timeval_t earliest_timer;

	assert(m != NULL);

	/* If there is event process it first. */
	if (!list_empty(&m->event))
		return &m->event;

	/* If there are ready threads process them */
	if (!list_empty(&m->ready))
		return &m->ready;

	do {
		/* Calculate and set wait timer. Take care of timeouted fd.  */
		earliest_timer = thread_set_timer(m);

#ifdef _VRRP_FD_DEBUG_
		if (extra_threads_debug)
			extra_threads_debug();
#endif

#ifdef _EPOLL_THREAD_DUMP_
		if (do_epoll_thread_dump)
			dump_thread_data(m, NULL);
#endif

#ifdef _EPOLL_DEBUG_
		if (do_epoll_debug)
			log_message(LOG_INFO, "calling epoll_wait");
#endif

		/* Call epoll function. */
		ret = epoll_wait(m->epoll_fd, m->epoll_events, m->epoll_count, -1);

#ifdef _EPOLL_DEBUG_
		if (do_epoll_debug) {
			int sav_errno = errno;

			if (ret == -1)
				log_message(LOG_INFO, "epoll_wait returned %d, errno %d", ret, sav_errno);
			else
				log_message(LOG_INFO, "epoll_wait returned %d fds", ret);

			errno = sav_errno;
		}
#endif

		if (ret < 0) {
			if (check_EINTR(errno))
				continue;

			/* Real error. */
			if (errno != last_epoll_errno) {
				last_epoll_errno = errno;

				/* Log the error first time only */
				log_message(LOG_INFO, "scheduler: epoll_wait error: %d (%m)", errno);

#ifndef _ONE_PROCESS_DEBUG_
				last_epoll_errno_count = 1;
#endif
			}
#ifndef _ONE_PROCESS_DEBUG_
			else if (++last_epoll_errno_count == 5 && shutdown_function) {
				/* We aren't goint to be able to recover, so exit and let our parent restart us */
				log_message(LOG_INFO, "scheduler: epoll_wait has returned errno %d for 5 successive calls - terminating", last_epoll_errno);
				shutdown_function(KEEPALIVED_EXIT_PROGRAM_ERROR);
			}
#endif

			/* Make sure we don't sit it a tight loop */
			if (last_epoll_errno == EBADF || last_epoll_errno == EFAULT || last_epoll_errno == EINVAL)
				sleep(1);

			continue;
		} else
			last_epoll_errno = 0;

		/* Check to see if we are long overdue. This can happen on a very heavily loaded system */
		if (min_auto_priority_delay && timerisset(&earliest_timer)) {
			/* Re-read the current time to get the maximum accuracy */
			set_time_now();

			/* Take care about monotonic clock */
			timersub(&earliest_timer, &time_now, &earliest_timer);

			/* If it is over min_auto_increment_delay usecs after the timer should have expired,
			 * we are not running soon enough. */
			if (earliest_timer.tv_sec < 0) {
				if (earliest_timer.tv_sec * -1000000 - earliest_timer.tv_usec > min_auto_priority_delay) {
					if (earliest_timer.tv_usec) {
						earliest_timer.tv_sec++;
						earliest_timer.tv_usec = 1000000 - earliest_timer.tv_usec;
					}
					log_message(LOG_INFO, "A thread timer expired %ld.%6.6ld seconds ago", -earliest_timer.tv_sec, earliest_timer.tv_usec);

					/* Set realtime scheduling if not already using it, or if already in use,
					 * increase the priority. */
					increment_process_priority();

#ifdef _EPOLL_THREAD_DUMP_
					if (do_epoll_thread_dump)
						dump_thread_data(m, NULL);
#endif
				}
			}
		}

		/* Handle epoll events */
		for (i = 0; i < ret; i++) {
			struct epoll_event *ep_ev;
			thread_event_t *ev;

			ep_ev = &m->epoll_events[i];
			ev = ep_ev->data.ptr;

#ifdef _EPOLL_DEBUG_
			if (do_epoll_debug)
				log_message(LOG_INFO, "Handling event 0x%x for fd %d", ep_ev->events, ev->fd);
#endif

			/* Error */
			if (ep_ev->events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
				if (ev->read) {
					thread_move_ready(m, &m->read, ev->read, THREAD_READ_ERROR);
					ev->read = NULL;
				} else if (ev->write) {
					thread_move_ready(m, &m->write, ev->write, THREAD_WRITE_ERROR);
					ev->write = NULL;
				}

				if (__test_bit(LOG_DETAIL_BIT, &debug) &&
				    ep_ev->events & EPOLLRDHUP)
					log_message(LOG_INFO, "Received EPOLLRDHUP for fd %d", ev->fd);

				continue;
			}

			/* READ */
			if (ep_ev->events & EPOLLIN) {
				if (!ev->read) {
					log_message(LOG_INFO, "scheduler: No read thread bound on fd:%d (fl:0x%.4X)"
						      , ev->fd, ep_ev->events);
					continue;
				}
				thread_move_ready(m, &m->read, ev->read, THREAD_READY_READ_FD);
				ev->read = NULL;
			}

			/* WRITE */
			if (ep_ev->events & EPOLLOUT) {
				if (!ev->write) {
					log_message(LOG_INFO, "scheduler: No write thread bound on fd:%d (fl:0x%.4X)"
						      , ev->fd, ep_ev->events);
					continue;
				}
				thread_move_ready(m, &m->write, ev->write, THREAD_READY_WRITE_FD);
				ev->write = NULL;
			}
		}

		/* Update current time */
		set_time_now();

		/* If there is a ready thread, return it. */
		if (!list_empty(&m->ready))
			return &m->ready;
	} while (true);
}

/* Call thread ! */
static inline void
thread_call(thread_t * thread)
{
#ifdef _EPOLL_DEBUG_
	if (do_epoll_debug)
		log_message(LOG_INFO, "Calling thread function %s(), type %s, val/fd/pid %d, status %d id %lu", get_function_name(thread->func), get_thread_type_str(thread->type), thread->u.val, thread->u.c.status, thread->id);
#endif

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
#ifdef _MEM_ERR_DEBUG_
		if (do_mem_err_debug &&
		    __test_bit(MEM_ERR_DETECT_BIT, &debug)
#ifdef _WITH_VRRP_
		    && __test_bit(DONT_RELEASE_VRRP_BIT, &debug)
#endif
								) {
			__clear_bit(MEM_ERR_DETECT_BIT, &debug);
#ifdef _WITH_VRRP_
			__clear_bit(DONT_RELEASE_VRRP_BIT, &debug);
#endif
			thread_add_terminate_event(m);
		}
#endif

		/* If we are shutting down, only process relevant thread types.
		 * We only want timer and signal fd, and don't want inotify, vrrp socket,
		 * snmp_read, bfd_receiver, bfd pipe in vrrp/check, dbus pipe or netlink fds. */
		if (!(thread = thread_trim_head(thread_list)))
			continue;

		m->current_thread = thread;
		thread_type = thread->type;

		if (thread && thread->type == THREAD_CHILD_TIMEOUT) {
			/* We remove the thread from the child_pid queue here so that
			 * if the termination arrives before we processed the timeout
			 * we can still handle the termination. */
			rb_erase(&thread->rb_data, &master->child_pid);
		}

		if (!shutting_down ||
		    ((thread->type == THREAD_READY_READ_FD ||
		      thread->type == THREAD_READY_WRITE_FD ||
		      thread->type == THREAD_READ_ERROR ||
		      thread->type == THREAD_WRITE_ERROR) &&
		     (thread->u.f.fd == m->timer_fd ||
		      thread->u.f.fd == m->signal_fd
#ifdef _WITH_SNMP_
		      || (snmp_running && FD_ISSET(thread->u.f.fd, &m->snmp_fdset))
#endif
							       )) ||
		    thread->type == THREAD_CHILD ||
		    thread->type == THREAD_CHILD_TIMEOUT ||
		    thread->type == THREAD_CHILD_TERMINATED ||
		    thread->type == THREAD_TIMER_SHUTDOWN ||
		    thread->type == THREAD_TERMINATE) {
			if (thread->func)
				thread_call(thread);

			/* If m->current_thread has been cleared, the thread
			 * has been freed. This happens during a reload. */
			thread = m->current_thread;

			if (thread_type == THREAD_TERMINATE_START)
				shutting_down = true;
		} else if (thread->type == THREAD_READY_READ_FD ||
			   thread->type == THREAD_READY_WRITE_FD ||
			   thread->type == THREAD_READ_TIMEOUT ||
			   thread->type == THREAD_WRITE_TIMEOUT ||
			   thread->type == THREAD_READ_ERROR ||
			   thread->type == THREAD_WRITE_ERROR) {
			thread_close_fd(thread);

			if (thread->u.f.flags & THREAD_DESTROY_FREE_ARG)
				FREE(thread->arg);
		}

		if (thread) {
			m->current_event = (thread_type == THREAD_READY_READ_FD || thread_type == THREAD_READY_WRITE_FD) ? thread->event : NULL;
			thread_add_unuse(m, thread);
			m->current_thread = NULL;
		} else
			m->current_event = NULL;

		/* If we are shutting down, and the shutdown timer is not running and
		 * all children have terminated, then we can terminate */
		if (shutting_down && !m->shutdown_timer_running && !m->child.rb_root.rb_node)
			break;

		/* If daemon hanging event is received stop processing */
		if (thread_type == THREAD_TERMINATE)
			break;
	}
}

static void
process_child_termination(pid_t pid, int status)
{
	thread_master_t * m = master;
	thread_t th = { .u.c.pid = pid };
	thread_t *thread;

	thread = rb_search(&master->child_pid, &th, rb_data, thread_child_pid_cmp);

#ifdef _EPOLL_DEBUG_
	if (do_epoll_debug)
		log_message(LOG_INFO, "Child %d terminated with status 0x%x, thread_id %lu", pid, (unsigned)status, thread ? thread->id : 0);
#endif

	if (!thread)
		return;

	rb_erase(&thread->rb_data, &master->child_pid);

	thread->u.c.status = status;

	if (thread->type == THREAD_CHILD_TIMEOUT) {
		/* The child had been timed out, but we have not processed the timeout
		 * and it is still on the thread->ready queue. Since we have now got
		 * the termination, just handle the termination instead. */
		thread->type = THREAD_CHILD_TERMINATED;
	}
	else
		thread_move_ready(m, &m->child, thread, THREAD_CHILD_TERMINATED);
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
			log_message(LOG_DEBUG, "waitpid error %d (%m)", errno);
			assert(0);

			return;
		}

#ifdef _SCRIPT_DEBUG_
		if (do_script_debug)
			log_message(LOG_INFO, "waitpid for %d returned 0x%x", pid, (unsigned)status);
#endif

		process_child_termination(pid, status);
	}
}

void
thread_add_base_threads(thread_master_t *m,
#ifndef _WITH_SNMP_
					    __attribute__ ((unused))
#endif
								     bool with_snmp)
{
	m->timer_thread = thread_add_read(m, thread_timerfd_handler, NULL, m->timer_fd, TIMER_NEVER, 0);
	add_signal_read_thread(m);
#ifdef _WITH_SNMP_
	if (with_snmp)
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

#ifdef THREAD_DUMP
void
register_scheduler_addresses(void)
{
#ifdef _WITH_SNMP_
	register_thread_address("snmp_timeout_thread", snmp_timeout_thread);
	register_thread_address("snmp_read_thread", snmp_read_thread);
#endif
	register_thread_address("thread_timerfd_handler", thread_timerfd_handler);

	register_signal_handler_address("thread_child_handler", thread_child_handler);
}
#endif
