/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        Signals framework.
 *  
 * Version:     $Id: signals.c,v 1.1.15 2007/09/15 04:07:41 acassen Exp $
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
 * Copyright (C) 2001-2007 Alexandre Cassen, <acassen@freebox.fr>
 */

#include <signal.h>
#include <string.h>

#include "signals.h"

/* Local Vars */
static int signal_mask;
void (*signal_SIGHUP_handler) (int sig);
void (*signal_SIGINT_handler) (int sig);
void (*signal_SIGTERM_handler) (int sig);
void (*signal_SIGCHLD_handler) (int sig);

/* Local signal test */
int
signal_pending(void)
{
	return (signal_mask) ? 1 : 0;
}

/* Signal flag */
void
signal_handler(int sig)
{
	switch(sig) {
	case SIGHUP:
		signal_mask |= SIGNAL_SIGHUP;
		break;
	case SIGINT:
		signal_mask |= SIGNAL_SIGINT;
		break;
	case SIGTERM:
		signal_mask |= SIGNAL_SIGTERM;
		break;
	case SIGCHLD:
		signal_mask |= SIGNAL_SIGCHLD;
		break;
	}
}

/* Signal wrapper */
void *
signal_set(int signo, void (*func) (int))
{
	int ret;
	struct sigaction sig;
	struct sigaction osig;

	sig.sa_handler = signal_handler;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;
#ifdef SA_RESTART
	sig.sa_flags |= SA_RESTART;
#endif				/* SA_RESTART */

	ret = sigaction(signo, &sig, &osig);

	switch(signo) {
	case SIGHUP:
		signal_SIGHUP_handler = func;
		break;
	case SIGINT:
		signal_SIGINT_handler = func;
		break;
	case SIGTERM:
		signal_SIGTERM_handler = func;
		break;
	case SIGCHLD:
		signal_SIGCHLD_handler = func;
		break;
	}

	if (ret < 0)
		return (SIG_ERR);
	else
		return (osig.sa_handler);
}

/* Signal Ignore */
void *
signal_ignore(int signo)
{
	return signal_set(signo, SIG_IGN);
}

/*
 * SIGCHLD handler. Reap all zombie child.
 * WNOHANG prevent against parent process get
 * stuck waiting child termination.
 */
void
dummy_handler(int sig)
{
	/* Dummy */
}

void
signal_noignore_sigchld(void)
{
	struct sigaction sa;
	sigset_t mask;

	/* Need to remove the NOCHLD flag */
	sigemptyset(&mask);
	sa.sa_handler = dummy_handler;
	sa.sa_mask = mask;
	sa.sa_flags = 0;

	sigaction(SIGCHLD, &sa, NULL);

	/* Block SIGCHLD so that we only receive it
	 * when required (ie when its unblocked in the
	 * select loop)
	 */
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, NULL);
}

/* Handlers intialization */
void
signal_handler_init(void)
{
	signal_mask = 0;
	signal_SIGHUP_handler = NULL;
	signal_SIGINT_handler = NULL;
	signal_SIGTERM_handler = NULL;
	signal_SIGCHLD_handler = NULL;
}

/* Handlers callback according to global signal mask */
void
signal_run_callback(void)
{
	if (SIGNAL_SIGHUP & signal_mask) {
		signal_mask &= ~SIGNAL_SIGHUP;
		if (signal_SIGHUP_handler)
			signal_SIGHUP_handler(SIGHUP);
	}

	if (SIGNAL_SIGINT & signal_mask) {
		signal_mask &= ~SIGNAL_SIGINT;
		if (signal_SIGINT_handler)
			signal_SIGINT_handler(SIGINT);
	}

	if (SIGNAL_SIGTERM & signal_mask) {
		signal_mask &= ~SIGNAL_SIGTERM;
		if (signal_SIGTERM_handler)
			signal_SIGTERM_handler(SIGTERM);
	}

	if (SIGNAL_SIGCHLD & signal_mask) {
		signal_mask &= ~SIGNAL_SIGCHLD;
		if (signal_SIGCHLD_handler)
			signal_SIGCHLD_handler(SIGCHLD);
	}
}
