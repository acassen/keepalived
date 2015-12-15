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

#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <assert.h>
#include <syslog.h>

#include "signals.h"
#include "utils.h"

/* Local Vars */
void (*signal_SIGHUP_handler) (void *, int sig);
void *signal_SIGHUP_v;
void (*signal_SIGINT_handler) (void *, int sig);
void *signal_SIGINT_v;
void (*signal_SIGTERM_handler) (void *, int sig);
void *signal_SIGTERM_v;
void (*signal_SIGCHLD_handler) (void *, int sig);
void *signal_SIGCHLD_v;
void (*signal_SIGUSR1_handler) (void *, int sig);
void *signal_SIGUSR1_v;
void (*signal_SIGUSR2_handler) (void *, int sig);
void *signal_SIGUSR2_v;

static int signal_pipe[2] = { -1, -1 };

/* Remember our initial signal disposition */
int initialised_default_signals;
sigset_t ign_sig;
sigset_t dfl_sig;

/* Local signal test */
/* Currently unused
int
signal_pending(void)
{
	fd_set readset;
	int rc;
	struct timeval timeout = { 0, 0 };

	FD_ZERO(&readset);
	FD_SET(signal_pipe[0], &readset);

	rc = select(signal_pipe[0] + 1, &readset, NULL, NULL, &timeout);

	return rc>0?1:0;
}
*/

/* Signal flag */
static void
signal_handler(int sig)
{
	if (write(signal_pipe[1], &sig, sizeof(int)) != sizeof(int)) {
		DBG("signal_pipe write error %s", strerror(errno));
		assert(0);
	}
}	

/* Signal wrapper */
void *
signal_set(int signo, void (*func) (void *, int), void *v)
{
	int ret;
	sigset_t sset;
	struct sigaction sig;
	struct sigaction osig;

	if (func == (void*)SIG_IGN || func == (void*)SIG_DFL) {
		sig.sa_handler = (void*)func;

		/* We are no longer handling the signal, so
		 * clear our handlers
		 */
		func = NULL;
		v = NULL;
	}
	else
		sig.sa_handler = signal_handler;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;
#ifdef SA_RESTART
	sig.sa_flags |= SA_RESTART;
#endif				/* SA_RESTART */

	/* Block the signal we are about to configure, to avoid
	 * any race conditions while setting the handler and
	 * parameter */
	if (func != NULL) {
		sigemptyset(&sset);
		sigaddset(&sset, signo);
		sigprocmask(SIG_BLOCK, &sset, NULL);
	}

	ret = sigaction(signo, &sig, &osig);

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

	if (ret < 0)
		return (SIG_ERR);

	/* Release the signal */
	if (func != NULL)
		sigprocmask(SIG_UNBLOCK, &sset, NULL);

	return ((osig.sa_flags & SA_SIGINFO) ? (void*)osig.sa_sigaction : (void*)osig.sa_handler);
}

/* Signal Ignore */
void *
signal_ignore(int signo)
{
	return signal_set(signo, (void*)SIG_IGN, NULL);
}

/* Handlers intialization */
void
signal_handler_init(void)
{
	sigset_t sset;
	int sig;
	struct sigaction act, oact;
	int n;

#ifdef HAVE_PIPE2
	n = pipe2(signal_pipe, O_CLOEXEC | O_NONBLOCK);
#else
	n = pipe(signal_pipe);

	fcntl(signal_pipe[0], F_SETFL, O_NONBLOCK | fcntl(signal_pipe[0], F_GETFL));
	fcntl(signal_pipe[1], F_SETFL, O_NONBLOCK | fcntl(signal_pipe[1], F_GETFL));

	fcntl(signal_pipe[0], F_SETFD, FD_CLOEXEC | fcntl(signal_pipe[0], F_GETFD));
	fcntl(signal_pipe[1], F_SETFD, FD_CLOEXEC | fcntl(signal_pipe[1], F_GETFD));
#endif
	assert(!n);

	signal_SIGHUP_handler = NULL;
	signal_SIGINT_handler = NULL;
	signal_SIGTERM_handler = NULL;
	signal_SIGCHLD_handler = NULL;
	signal_SIGUSR1_handler = NULL;
	signal_SIGUSR2_handler = NULL;

	if (!initialised_default_signals) {
		/* Ignore all signals set to default (except essential ones) */
		sigfillset(&sset);
		sigdelset(&sset, SIGILL);
		sigdelset(&sset, SIGFPE);
		sigdelset(&sset, SIGSEGV);
		sigdelset(&sset, SIGBUS);
		sigdelset(&sset, SIGKILL);
		sigdelset(&sset, SIGSTOP);

		act.sa_handler = SIG_IGN;
		sigemptyset(&act.sa_mask);
		act.sa_flags = 0;

		sigemptyset(&ign_sig);
		sigemptyset(&dfl_sig);

		for (sig = 1; sig <= SIGRTMAX; sig++) {
			if (sigismember(&sset, sig)){
				sigaction(sig, NULL, &oact);

				/* Remember the original disposition, and ignore
				 * any default action signals
				 */
				if ( oact.sa_handler == SIG_IGN)
					sigaddset(&ign_sig, sig);
				else if ( oact.sa_handler == SIG_DFL) {
					sigaction(sig, &act, NULL);
					sigaddset(&dfl_sig, sig);
				}
			}
		}

		initialised_default_signals = 1;
	}
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
signal_handler_reset(void)
{
	signal_handlers_clear(SIG_DFL);
}

void
signal_handler_destroy(void)
{
	signal_handlers_clear(SIG_IGN);
	close(signal_pipe[1]);
	close(signal_pipe[0]);
	signal_pipe[1] = -1;
	signal_pipe[0] = -1;
}

/* Called prior to exec'ing a script. The script can reasonably
 * expect to have the standard signal disposition */
void
signal_handler_script(void)
{
	struct sigaction ign, dfl;
	int sig;

	ign.sa_handler = SIG_IGN;
	ign.sa_flags = 0;
	sigemptyset(&ign.sa_mask);
	dfl.sa_handler = SIG_DFL;
	dfl.sa_flags = 0;
	sigemptyset(&dfl.sa_mask);

	for (sig = 1; sig <= SIGRTMAX; sig++) {
		if (sigismember(&ign_sig, sig))
			sigaction(sig, &ign, NULL);
		else if (sigismember(&dfl_sig, sig))
			sigaction(sig, &dfl, NULL);
	}
}

int
signal_rfd(void)
{
	return(signal_pipe[0]);
}

/* Handlers callback  */
void
signal_run_callback(void)
{
	int sig;

	while(read(signal_pipe[0], &sig, sizeof(int)) == sizeof(int)) {
		switch(sig) {
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
				signal_SIGCHLD_handler(signal_SIGCHLD_v, SIGCHLD);
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
