/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Main program structure.
 *
 * Version:     $Id: main.c,v 1.1.9 2005/02/07 03:18:31 acassen Exp $
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
 * Copyright (C) 2001-2005 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include <syslog.h>
#include "daemon.h"
#include "utils.h"

/* Daemonization function coming from zebra source code */
pid_t
xdaemon(int nochdir, int noclose, int exitflag)
{
	pid_t pid;

	/* In case of fork is error. */
	pid = fork();
	if (pid < 0) {
		syslog(LOG_INFO, "xdaemon: fork error");
		return -1;
	}

	/* In case of this is parent process. */
	if (pid != 0) {
		if (!exitflag)
			exit(0);
		else
			return pid;
	}

	/* Become session leader and get pid. */
	pid = setsid();
	if (pid < -1) {
		syslog(LOG_INFO, "xdaemon: setsid error");
		return -1;
	}

	/* Change directory to root. */
	if (!nochdir)
		chdir("/");

	/* File descriptor close. */
	if (!noclose) {
		int fd;

		fd = open("/dev/null", O_RDWR, 0);
		if (fd != -1) {
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			if (fd > 2)
				close(fd);
		}
	}

	umask(0);
	return 0;
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

/* Signal wrapper */
void *
signal_set(int signo, void (*func) (int))
{
	int ret;
	struct sigaction sig;
	struct sigaction osig;

	sig.sa_handler = func;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;
#ifdef SA_RESTART
	sig.sa_flags |= SA_RESTART;
#endif				/* SA_RESTART */

	ret = sigaction(signo, &sig, &osig);

	if (ret < 0)
		return (SIG_ERR);
	else
		return (osig.sa_handler);
}

/* Signal remove */
void *
signal_ignore(int signo)
{
	return signal_set(signo, SIG_IGN);
}
