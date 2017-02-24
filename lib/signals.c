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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include "config.h"

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#ifndef _DEBUG_
#define NDEBUG
#endif
#include <assert.h>
#ifdef HAVE_SIGNALFD
#include <sys/signalfd.h>
#endif

#include "signals.h"
#include "utils.h"
#include "logger.h"

/* Local Vars */
static void (*signal_SIGHUP_handler) (void *, int sig);
static void *signal_SIGHUP_v;
static void (*signal_SIGINT_handler) (void *, int sig);
static void *signal_SIGINT_v;
static void (*signal_SIGTERM_handler) (void *, int sig);
static void *signal_SIGTERM_v;
static void (*signal_SIGCHLD_handler) (void *, int sig);
static void *signal_SIGCHLD_v;
static void (*signal_SIGUSR1_handler) (void *, int sig);
static void *signal_SIGUSR1_v;
static void (*signal_SIGUSR2_handler) (void *, int sig);
static void *signal_SIGUSR2_v;

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

#ifdef _INCLUDE_UNUSED_CODE_
/* Local signal test */
int
signal_pending(void)
{
	fd_set readset;
	int rc;
	struct timeval timeout = {
		.tv_sec = 0,
		.tv_usec = 0
	};

	FD_ZERO(&readset);
#ifdef HAVE_SIGNALFD
	FD_SET(signal_fd, &readset);

	rc = select(signal_fd + 1, &readset, NULL, NULL, &timeout);
#else
	FD_SET(signal_pipe[0], &readset);

	rc = select(signal_pipe[0] + 1, &readset, NULL, NULL, &timeout);
#endif

	return rc > 0 ? 1 : 0;
}
#endif

/* Signal flag */
#ifndef HAVE_SIGNALFD
static void
signal_handler(int sig)
{
	if (write(signal_pipe[1], &sig, sizeof(int)) != sizeof(int)) {
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
		sigprocmask(SIG_BLOCK, &sset, NULL);
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
		sigprocmask(SIG_UNBLOCK, &sset, NULL);
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
		sigprocmask(SIG_BLOCK, &sset, NULL);

		/* If we are the parent, remember what signals
		 * we set, so vrrp and checker children can clear them */
		sigaddset(&parent_sig, signo);
	}

	ret = sigaction(signo, &sig, &osig);
#endif

	switch(signo) {
	case SIGHUP:
		signal_SIGHUP_handler = func;
		signal_SIGHUP_v = v;
		break;
	case SIGINT:
		signal_SIGINT_handler = func;
		signal_SIGINT_v = v;
		break;
	case SIGTERM:
		signal_SIGTERM_handler = func;
		signal_SIGTERM_v = v;
		break;
	case SIGCHLD:
		signal_SIGCHLD_handler = func;
		signal_SIGCHLD_v = v;
		break;
	case SIGUSR1:
		signal_SIGUSR1_handler = func;
		signal_SIGUSR1_v = v;
		break;
	case SIGUSR2:
		signal_SIGUSR2_handler = func;
		signal_SIGUSR2_v = v;
		break;
	}

#ifndef HAVE_SIGNALFD
	if (ret < 0)
		return;

	/* Release the signal */
	if (func != NULL)
		sigprocmask(SIG_UNBLOCK, &sset, NULL);
#endif
}

/* Signal Ignore */
void
signal_ignore(int signo)
{
	signal_set(signo, (void *)SIG_IGN, NULL);
}

static void
clear_signal_handler_addresses(void)
{
	signal_SIGHUP_handler = NULL;
	signal_SIGINT_handler = NULL;
	signal_SIGTERM_handler = NULL;
	signal_SIGCHLD_handler = NULL;
	signal_SIGUSR1_handler = NULL;
	signal_SIGUSR2_handler = NULL;
}

/* Handlers intialization */
void
open_signal_fd(void)
{
#ifdef HAVE_SIGNALFD
	sigemptyset(&signal_fd_set);

#ifdef SFD_NONBLOCK	/* From Linux 2.6.26 */
	signal_fd = signalfd(signal_fd, &signal_fd_set, SFD_NONBLOCK | SFD_CLOEXEC);
#else
	signal_fd = signalfd(signal_fd, &signal_fd_set, 0);

	fcntl(signal_fd, F_SETFL, O_NONBLOCK | fcntl(signal_fd, F_GETFL));
	fcntl(signal_fd, F_SETFD, FD_CLOEXEC | fcntl(signal_fd, F_GETFD));
#endif
	if (signal_fd == -1)
		log_message(LOG_INFO, "BUG - signal_fd init failed - %d (%s), please report", errno, strerror(errno));
#else
	int n;

#ifdef HAVE_PIPE2
	n = pipe2(signal_pipe, O_CLOEXEC | O_NONBLOCK);
#else
	n = pipe(signal_pipe);
#endif

	assert(!n);
	if (n)
		log_message(LOG_INFO, "BUG - pipe in signal_handler_init failed - %d (%s), please report", errno, strerror(errno));

#ifndef HAVE_PIPE2
	fcntl(signal_pipe[0], F_SETFL, O_NONBLOCK | fcntl(signal_pipe[0], F_GETFL));
	fcntl(signal_pipe[1], F_SETFL, O_NONBLOCK | fcntl(signal_pipe[1], F_GETFL));

	fcntl(signal_pipe[0], F_SETFD, FD_CLOEXEC | fcntl(signal_pipe[0], F_GETFD));
	fcntl(signal_pipe[1], F_SETFD, FD_CLOEXEC | fcntl(signal_pipe[1], F_GETFD));
#endif
#endif
}

void
signal_handler_init(void)
{
	sigset_t sset;
	int sig;
	struct sigaction act;

	open_signal_fd();

	clear_signal_handler_addresses();

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

	sigemptyset(&parent_sig);

#ifdef HAVE_SIGNALFD
	sigemptyset(&sset);
	sigprocmask(SIG_SETMASK, &sset, NULL);
#endif
}

void
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

	open_signal_fd();

	clear_signal_handler_addresses();
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
}

void
signal_handler_destroy(void)
{
#ifdef HAVE_SIGNALFD
	close(signal_fd);
	signal_fd = -1;
	sigemptyset(&signal_fd_set);
#endif

	signal_handlers_clear(SIG_IGN);

#ifndef HAVE_SIGNALFD
	close(signal_pipe[1]);
	close(signal_pipe[0]);
	signal_pipe[1] = -1;
	signal_pipe[0] = -1;
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
	sigprocmask(SIG_SETMASK, &sset, NULL);
#endif
}

int
signal_rfd(void)
{
#ifdef HAVE_SIGNALFD
	return signal_fd;
#else
	return signal_pipe[0];
#endif
}

/* Handlers callback  */
void
signal_run_callback(void)
{
#ifdef HAVE_SIGNALFD
	struct signalfd_siginfo siginfo;

	while(read(signal_fd, &siginfo, sizeof(struct signalfd_siginfo)) == sizeof(struct signalfd_siginfo)) {
		switch(siginfo.ssi_signo) {
#else
	int sig;

	while(read(signal_pipe[0], &sig, sizeof(int)) == sizeof(int)) {
		switch(sig) {
#endif
		case SIGHUP:
			if (signal_SIGHUP_handler)
				signal_SIGHUP_handler(signal_SIGHUP_v, SIGHUP);
			break;
		case SIGINT:
			if (signal_SIGINT_handler)
				signal_SIGINT_handler(signal_SIGINT_v, SIGINT);
			break;
		case SIGTERM:
			if (signal_SIGTERM_handler)
				signal_SIGTERM_handler(signal_SIGTERM_v, SIGTERM);
			break;
		case SIGCHLD:
			if (signal_SIGCHLD_handler)
#ifdef HAVE_SIGNALFD
				signal_SIGCHLD_handler(&siginfo, SIGCHLD);
#else
				signal_SIGCHLD_handler(signal_SIGCHLD_v, SIGCHLD);
#endif
			break;
		case SIGUSR1:
			if (signal_SIGUSR1_handler)
				signal_SIGUSR1_handler(signal_SIGUSR1_v, SIGUSR1);
			break;
		case SIGUSR2:
			if (signal_SIGUSR2_handler)
				signal_SIGUSR2_handler(signal_SIGUSR2_v, SIGUSR2);
			break;
		default:
			break;
		}
	}
}

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
