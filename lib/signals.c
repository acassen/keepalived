/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Signals framework.
 *
 * Author:      Kevin Lindsay, <kevinl@netnation.com>
 *              Alexandre Cassen, <acassen@linux-vs.org>
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

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#ifdef HAVE_SIGNALFD
#include <sys/signalfd.h>
#endif
#ifdef _INCLUDE_UNUSED_CODE_
#include <sys/epoll.h>
#endif
#include <inttypes.h>

#include "signals.h"
#include "utils.h"
#include "logger.h"
#include "scheduler.h"
#include "assert_debug.h"

#ifdef _WITH_JSON_
#include "../keepalived/include/vrrp_json.h"
#endif

#ifdef _WITH_JSON_
  /* We need to include the realtime signals, but
   * unfortunately SIGRTMIN/SIGRTMAX are not constants.
   * I'm not clear if _NSIG is always defined, so play safe.
   * Although we are not meant to use __SIGRTMAX, we are
   * using it here as an upper bound, which is rather different. */
  #ifdef _NSIG
    #define SIG_MAX	_NSIG
  #elif defined __SIGRTMAX
    #define SIG_MAX __SIGRTMAX
  #else
    #define SIG_MAX 64
  #endif
#else
  /* The signals currently used are HUP, INT, TERM, USR1,
   * USR2, CHLD and XCPU. */
  #if SIGCHLD > SIGUSR2
    /* Architectures except alpha and sparc - see signal(7) */
    #if HAVE_DECL_RLIMIT_RTTIME == 1
      #define SIG_MAX SIGXCPU
    #else
      #define SIG_MAX SIGCHLD
    #endif
  #else
    /* alpha and sparc */
    #define SIG_MAX SIGUSR2
  #endif
#endif

/* Local Vars */
#ifndef USE_SIGNAL_THREADS
static void (*signal_handler_func[SIG_MAX]) (void *, int sig);
static void *signal_v[SIG_MAX];
#endif

#ifdef HAVE_SIGNALFD
static int signal_fd = -1;
static sigset_t signal_fd_set;
#else
static int signal_pipe[2] = { -1, -1 };
#endif

/* Remember signal disposition for not default disposition */
static sigset_t dfl_sig;

/* Signal handlers set in parent */
static sigset_t parent_sig;

/* Signal handling thread */
static thread_ref_t signal_thread;

int __attribute__((pure))
get_signum(const char *sigfunc)
{
	if (!strcmp(sigfunc, "STOP"))
		return SIGTERM;
	else if (!strcmp(sigfunc, "RELOAD"))
		return SIGHUP;
	else if (!strcmp(sigfunc, "DATA"))
		return SIGUSR1;
	else if (!strcmp(sigfunc, "STATS"))
		return SIGUSR2;
#ifdef _WITH_JSON_
	else if (!strcmp(sigfunc, "JSON"))
		return SIGJSON;
#endif

	/* Not found */
	return -1;
}

#if HAVE_DECL_RLIMIT_RTTIME == 1
static void
log_sigxcpu(__attribute__((unused)) void * ptr, __attribute__((unused)) int signum)
{
	log_message(LOG_INFO, "%s process has used too much CPU time, %s_rlimit_rtime may need to be increased",
#ifdef _DEBUG_
		    "Main debug",
#else
#ifdef _WITH_VRRP_
		    prog_type == PROG_TYPE_VRRP ? "VRRP" :
#endif
#ifdef _WITH_LVS_
		    prog_type == PROG_TYPE_CHECKER ? "Checker" :
#endif
#ifdef _WITH_BFD_
		    prog_type == PROG_TYPE_BFD ? "BFD" :
#endif
		    "Unknown",
#endif
#ifdef _DEBUG_
		    "UNDEFINED"
#else
#ifdef _WITH_VRRP_
		    prog_type == PROG_TYPE_VRRP ? "vrrp" :
#endif
#ifdef _WITH_LVS_
		    prog_type == PROG_TYPE_CHECKER ? "checker" :
#endif
#ifdef _WITH_BFD_
		    prog_type == PROG_TYPE_BFD ? "bfd" :
#endif
		    "Unknown"
#endif
		    );
}
#endif

#ifdef _INCLUDE_UNUSED_CODE_
/* Local signal test */
bool
signal_pending(void)
{
	int rc;
	int efd;
	struct epoll_event ev = { .events = EPOLLIN };

	efd = epoll_create(1);
#ifdef HAVE_SIGNALFD
	epoll_ctl(efd, EPOLL_CTL_ADD, signal_fd,  &ev);
#else
	epoll_ctl(efd, EPOLL_CTL_ADD, signal_pipe[0],  &ev);
#endif
	rc = epoll_wait(efd, &ev, 1, 0);
	close(efd);

	return rc > 0;
}
#endif

/* Signal flag */
#ifndef HAVE_SIGNALFD
static void
signal_handler(uint32_t sig)
{
	if (write(signal_pipe[1], &sig, sizeof(uint32_t)) != sizeof(uint32_t)) {
		DBG("signal_pipe write error %s", strerror(errno));
		assert(0);

		log_message(LOG_INFO, "BUG - write to signal_pipe[1] error %s - please report", strerror(errno));
	}
}
#endif

/* Signal wrapper */
void
signal_set(int signo, void (*func) (void *, int), void *v)
{
	int ret;
	sigset_t sset;
	struct sigaction sig;
#ifndef HAVE_SIGNALFD
	struct sigaction osig;
#endif
#ifdef _SIGNAL_DEBUG_
	static int max_signo = SIG_MAX;
	static int min_signo = 1;

	if ((signo < min_signo) || (signo > max_signo)) {
		log_message(LOG_ERR, "BUG - signal %d out of range (1..%d)", signo, SIG_MAX);
		if (signo > max_signo)
			max_signo = signo;
		else
			min_signo = signo;
		return;
	}
#endif

	if (func == (void *)SIG_DFL)
		sigaddset(&dfl_sig, signo);
	else
		sigdelset(&dfl_sig, signo);

	if (func == (void*)SIG_IGN || func == (void*)SIG_DFL) {
		/* We are no longer handling the signal, so
		 * clear our handlers */
		func = NULL;
		v = NULL;
	}

#ifdef HAVE_SIGNALFD
	sigemptyset(&sset);
	sigaddset(&sset, signo);

	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;

	if (!func) {
		sigdelset(&signal_fd_set, signo);
		sig.sa_handler = SIG_IGN;
	}
	else {
		sigaddset(&signal_fd_set, signo);
		sigmask_func(SIG_BLOCK, &sset, NULL);
		sig.sa_handler = SIG_DFL;
	}

	/* Don't open signal_fd if clearing the handler */
	if (func || signal_fd != -1) {
		ret = signalfd(signal_fd, &signal_fd_set, 0);
		if (ret == -1)
			log_message(LOG_INFO, "BUG - signal_fd update failed - %d (%s), please report", errno, strerror(errno));
	}

	if (sigaction(signo, &sig, NULL))
		log_message(LOG_INFO, "sigaction failed for signalfd");

	if (!func)
		sigmask_func(SIG_UNBLOCK, &sset, NULL);
#else
	if (func)
		sig.sa_handler = signal_handler;
	else
		sig.sa_handler = (void*)func;

	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;
	sig.sa_flags |= SA_RESTART;

	/* Block the signal we are about to configure, to avoid
	 * any race conditions while setting the handler and
	 * parameter */
	if (func) {
		sigemptyset(&sset);
		sigaddset(&sset, signo);
		sigmask_func(SIG_BLOCK, &sset, NULL);

		/* Remember what signals we set, so any child processes can clear them */
		sigaddset(&parent_sig, signo);
	}
	else
		sigdelset(&parent_sig, signo);

	ret = sigaction(signo, &sig, &osig);
#endif

	signal_handler_func[signo-1] = func;
	signal_v[signo-1] = v;

#ifndef HAVE_SIGNALFD
	if (ret < 0)
		return;

	/* Release the signal */
	if (func != NULL)
		sigmask_func(SIG_UNBLOCK, &sset, NULL);
#endif
}

/* Signal Ignore */
void
signal_ignore(int signo)
{
	signal_set(signo, (void *)SIG_IGN, NULL);
	sigdelset(&parent_sig, signo);
}

/* Handlers callback  */
static int
signal_run_callback(thread_ref_t thread)
{
	uint32_t sig;
#ifdef HAVE_SIGNALFD
	struct signalfd_siginfo siginfo;

	while (read(signal_fd, &siginfo, sizeof(struct signalfd_siginfo)) == sizeof(struct signalfd_siginfo)) {
		sig = siginfo.ssi_signo;
#else
	while (read(signal_pipe[0], &sig, sizeof(uint32_t)) == sizeof(uint32_t)) {
#endif

#ifdef _EPOLL_DEBUG_
		if (do_epoll_debug) {
			if (sig >= 1 && sig < sizeof(signal_handler_func) / sizeof(signal_handler_func[0]))
				log_message(LOG_INFO, "Signal %" PRIu32 ", func %s()", sig, get_signal_function_name(signal_handler_func[sig-1]));
			else
				log_message(LOG_INFO, "Signal %" PRIu32 ", unknown function", sig);
		}
#endif

#ifdef USE_SIGNAL_THREADS
		/* This is instead of signal_handler_func[] array if signals are
		 * handled by threads. The thread handling function would have to
		 * do a thread_add_signal() to reinstate itself. */
		list_for_each_entry_safe(t, t_tmp, &m->signal, next) {
			if (t->u.val == sig) {
				list_head_del(&t->next);
				INIT_LIST_HEAD(&t->next);
				list_add_tail(&t->next, &m->ready);
				t->type = THREAD_READY;
			}
		}
#else
		if (sig >= 1 && sig <= SIG_MAX && signal_handler_func[sig-1])
			signal_handler_func[sig-1](signal_v[sig-1], sig);
#endif
	}

	signal_thread = thread_add_read(master, signal_run_callback, NULL, thread->u.f.fd, TIMER_NEVER, false);

	return 0;
}

static void
clear_signal_handler_addresses(void)
{
	int i;

	for (i = 0; i < SIG_MAX; i++)
		signal_handler_func[i] = NULL;
}

/* Handlers intialization */
void
add_signal_read_thread(thread_master_t *thread_master)
{
	signal_thread = thread_add_read(thread_master, signal_run_callback, NULL, thread_master->signal_fd, TIMER_NEVER, false);
}

void
cancel_signal_read_thread(void)
{
	if (signal_thread) {
		thread_cancel(signal_thread);
		signal_thread = NULL;
	}
}

static int
open_signal_fd(void)
{
#ifdef HAVE_SIGNALFD
	sigemptyset(&signal_fd_set);

#ifdef SFD_NONBLOCK	/* From Linux 2.6.26 */
	signal_fd = signalfd(signal_fd, &signal_fd_set, SFD_NONBLOCK | SFD_CLOEXEC);
#else
	signal_fd = signalfd(signal_fd, &signal_fd_set, 0);

	if (signal_fd != -1) {
		fcntl(signal_fd, F_SETFL, O_NONBLOCK | fcntl(signal_fd, F_GETFL));
		fcntl(signal_fd, F_SETFD, FD_CLOEXEC | fcntl(signal_fd, F_GETFD));
	}
#endif
	if (signal_fd == -1)
		log_message(LOG_INFO, "BUG - signal_fd init failed - %d (%s), please report", errno, strerror(errno));

	return signal_fd;
#else
	if (open_pipe(signal_pipe))
		log_message(LOG_INFO, "BUG - pipe in open_signal_fd() failed - %d (%s), please report", errno, strerror(errno));

	return signal_pipe[0];
#endif
}

static void
signal_handler_parent_init(void)
{
	sigset_t sset;
	int sig;
	struct sigaction act;

	/* Ignore all signals except essential ones */
	sigemptyset(&sset);
	sigaddset(&sset, SIGILL);
	sigaddset(&sset, SIGFPE);
	sigaddset(&sset, SIGSEGV);
	sigaddset(&sset, SIGBUS);
	sigaddset(&sset, SIGKILL);
	sigaddset(&sset, SIGSTOP);

	dfl_sig = sset;

	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	for (sig = 1; sig <= SIGRTMAX; sig++) {
		if (!sigismember(&sset, sig))
			sigaction(sig, &act, NULL);
	}

#ifdef HAVE_SIGNALFD
	sigemptyset(&sset);
	sigmask_func(SIG_SETMASK, &sset, NULL);
#endif
}

#ifndef _DEBUG_
static void
signal_handler_child_init(void)
{
	struct sigaction act;
	int sig;

	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	for (sig = 1; sig <= SIGRTMAX; sig++) {
		if (sigismember(&parent_sig, sig))
			sigaction(sig, &act, NULL);
	}
}
#endif

int
signal_handler_init(void)
{
	int fd;

#ifdef _DEBUG_
	signal_handler_parent_init();
#else
	if (prog_type == PROG_TYPE_PARENT)
		signal_handler_parent_init();
	else
		signal_handler_child_init();
#endif

	sigemptyset(&parent_sig);

	fd = open_signal_fd();

	clear_signal_handler_addresses();

	return fd;
}

static void
signal_handlers_clear(void *state)
{
	/* Ensure no more pending signals */
	signal_set(SIGHUP, state, NULL);
	signal_set(SIGINT, state, NULL);
	signal_set(SIGTERM, state, NULL);
	signal_set(SIGCHLD, state, NULL);
	signal_set(SIGUSR1, state, NULL);
	signal_set(SIGUSR2, state, NULL);
#if HAVE_DECL_RLIMIT_RTTIME == 1
	signal_set(SIGXCPU, state, NULL);
#endif
#ifdef _WITH_JSON_
	signal_set(SIGJSON, state, NULL);
#endif
}

void
signal_handler_destroy(void)
{
	if (signal_thread) {
		thread_cancel(signal_thread);
		signal_thread = NULL;
	}

#ifdef HAVE_SIGNALFD
	if (signal_fd != -1) {
		close(signal_fd);
		signal_fd = -1;
	}
	sigemptyset(&signal_fd_set);
#endif

	signal_handlers_clear(SIG_IGN);

#ifndef HAVE_SIGNALFD
	if (signal_pipe[1] != -1) {
		close(signal_pipe[1]);
		signal_pipe[1] = -1;
	}
	if (signal_pipe[0] != -1) {
		close(signal_pipe[0]);
		signal_pipe[0] = -1;
	}
#endif
}

/* Called prior to exec'ing a script. The script can reasonably
 * expect to have the standard signal disposition */
void
signal_handler_script(void)
{
	struct sigaction dfl;
	int sig;
#ifdef HAVE_SIGNALFD
	sigset_t sset;

	if (signal_fd != -1){
		close(signal_fd);
		signal_fd = -1;
	}
#endif

	dfl.sa_handler = SIG_DFL;
	dfl.sa_flags = 0;
	sigemptyset(&dfl.sa_mask);

	for (sig = 1; sig <= SIGRTMAX; sig++) {
		if (!sigismember(&dfl_sig, sig))
			sigaction(sig, &dfl, NULL);
	}

#ifdef HAVE_SIGNALFD
	sigemptyset(&sset);
	sigmask_func(SIG_SETMASK, &sset, NULL);
#endif
}

#if HAVE_DECL_RLIMIT_RTTIME == 1
void
set_sigxcpu_handler(void)
{
	signal_set(SIGXCPU, log_sigxcpu, NULL);
#ifdef THREAD_DUMP
	register_signal_handler_address("log_sigxcpu", log_sigxcpu);
#endif
}
#endif

void signal_fd_close(int min_fd)
{
#ifdef HAVE_SIGNALFD
	if (signal_fd >= min_fd) {
		close(signal_fd);
		signal_fd = -1;
	}
#else
	if (signal_pipe[0] >= min_fd) {
		close(signal_pipe[0]);
		signal_pipe[0] = -1;
	}
	if (signal_pipe[1] >= min_fd) {
		close(signal_pipe[1]);
		signal_pipe[1] = -1;
	}
#endif
}

#ifdef THREAD_DUMP
void
register_signal_thread_addresses(void)
{
        register_thread_address("signal_run_callback", signal_run_callback);
}
#endif
