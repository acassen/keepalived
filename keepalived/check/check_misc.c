/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        MISC CHECK. Perform a system call to run an extra
 *              system prog or script.
 *
 * Version:     $Id: check_misc.c,v 1.1.6 2004/02/21 02:31:28 acassen Exp $
 *
 * Authors:     Alexandre Cassen, <acassen@linux-vs.org>
 *              Eric Jarman, <ehj38230@cmsu2.cmsu.edu>
 *		Bradley Baetz, <bradley.baetz@optusnet.com.au>
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
 * Copyright (C) 2001-2004 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include "check_misc.h"
#include "check_api.h"
#include "memory.h"
#include "ipwrapper.h"
#include "smtp.h"
#include "utils.h"
#include "parser.h"
#include "notify.h"
#include "daemon.h"

int misc_check_thread(thread *);
int misc_check_child_thread(thread *);
int misc_check_child_timeout_thread(thread *);

/* Configuration stream handling */
void
free_misc_check(void *data)
{
	misc_checker *misc_chk = CHECKER_DATA(data);

	FREE(misc_chk->path);
	FREE(misc_chk);
	FREE(data);
}

void
dump_misc_check(void *data)
{
	misc_checker *misc_chk = CHECKER_DATA(data);

	syslog(LOG_INFO, "   Keepalive method = MISC_CHECK");
	syslog(LOG_INFO, "   script = %s", misc_chk->path);
	syslog(LOG_INFO, "   timeout = %lu", misc_chk->timeout/TIMER_HZ);
}

void
misc_check_handler(vector strvec)
{
	misc_checker *misc_chk = (misc_checker *) MALLOC(sizeof (misc_checker));

	/* queue new checker */
	queue_checker(free_misc_check, dump_misc_check, misc_check_thread,
		      misc_chk);
}

void
misc_path_handler(vector strvec)
{
	misc_checker *misc_chk = CHECKER_GET();
	misc_chk->path = CHECKER_VALUE_STRING(strvec);
}

void
misc_timeout_handler(vector strvec)
{
	misc_checker *misc_chk = CHECKER_GET();
	misc_chk->timeout = CHECKER_VALUE_INT(strvec) * TIMER_HZ;
}

void
install_misc_check_keyword(void)
{
	install_keyword("MISC_CHECK", &misc_check_handler);
	install_sublevel();
	install_keyword("misc_path", &misc_path_handler);
	install_keyword("misc_timeout", &misc_timeout_handler);
	install_sublevel_end();
}

int
misc_check_thread(thread * thread)
{
	checker *checker;
	misc_checker *misc_chk;
	int status;
	pid_t pid;

	checker = THREAD_ARG(thread);
	misc_chk = CHECKER_ARG(checker);

	/*
	 * Register a new checker thread & return
	 * if checker is disabled
	 */
	if (!CHECKER_ENABLED(checker)) {
		/* Register next timer checker */
		thread_add_timer(thread->master, misc_check_thread, checker,
				 checker->vs->delay_loop);
		return 0;
	}

	/* Register next timer checker */
	thread_add_timer(thread->master, misc_check_thread, checker,
			 checker->vs->delay_loop);

	/* Daemonization to not degrade our scheduling timer */
	pid = fork();

	/* In case of fork is error. */
	if (pid < 0) {
		syslog(LOG_INFO, "Failed fork process");
		return -1;
	}

	/* In case of this is parent process */
	if (pid) {
		long timeout;
		timeout = (misc_chk->timeout) ? misc_chk->timeout : checker->vs->delay_loop;

		thread_add_child(thread->master, misc_check_child_thread,
				 checker, pid, timeout);
		return 0;
	}

	/* Child part */
	closeall(0);

	open("/dev/null", O_RDWR);
	dup(0);
	dup(0);

	/* Also need to reset the signal state */
	{
		sigset_t empty_set;
		sigemptyset(&empty_set);
		sigprocmask(SIG_SETMASK, &empty_set, NULL);

		signal(SIGHUP, SIG_DFL);
		signal(SIGINT, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGKILL, SIG_DFL);
	}

	status = system_call(misc_chk->path);

	if (status < 0 || !WIFEXITED(status))
		status = 0; /* Script errors aren't server errors */
	else
		status = WEXITSTATUS(status);

	exit(status);
}

int
misc_check_child_thread(thread * thread)
{
	int wait_status;
	checker *checker;
	misc_checker *misc_chk;

	checker = THREAD_ARG(thread);
	misc_chk = CHECKER_ARG(checker);

	if (thread->type == THREAD_CHILD_TIMEOUT) {
		pid_t pid;

		pid = THREAD_CHILD_PID(thread);

		/* The child hasn't responded. Kill it off. */
		if (svr_checker_up(checker->id, checker->rs)) {
			syslog(LOG_INFO, "Misc check to [%s] for [%s] timed out",
			       inet_ntop2(CHECKER_RIP(checker)),
			       misc_chk->path);
			smtp_alert(thread->master, checker->rs, NULL, NULL,
				   "DOWN",
				   "=> MISC CHECK script timeout on service <=");
			update_svr_checker_state(DOWN, checker->id
						     , checker->vs
						     , checker->rs);
		}

		kill(pid, SIGTERM);
		thread_add_child(thread->master, misc_check_child_timeout_thread,
				 checker, pid, 2);
		return 0;
	}

	wait_status = THREAD_CHILD_STATUS(thread);

	if (WIFEXITED(wait_status)) {
		int status;
		status = WEXITSTATUS(wait_status);
		if (status == 0) {
			/* everything is good */
			if (!svr_checker_up(checker->id, checker->rs)) {
				syslog(LOG_INFO, "Misc check to [%s] for [%s] success.",
				       inet_ntop2(CHECKER_RIP(checker)),
				       misc_chk->path);
				smtp_alert(thread->master, checker->rs, NULL, NULL,
					   "UP",
					   "=> MISC CHECK succeed on service <=");
				update_svr_checker_state(UP, checker->id
							   , checker->vs
							   , checker->rs);
			}
		} else {
			if (svr_checker_up(checker->id, checker->rs)) {
				syslog(LOG_INFO, "Misc check to [%s] for [%s] failed.",
				       inet_ntop2(CHECKER_RIP(checker)),
				       misc_chk->path);
				smtp_alert(thread->master, checker->rs, NULL, NULL,
					   "DOWN",
					   "=> MISC CHECK failed on service <=");
				update_svr_checker_state(DOWN, checker->id
							     , checker->vs
							     , checker->rs);
			}
		}
	}

	return 0;
}

int
misc_check_child_timeout_thread(thread * thread)
{
	pid_t pid;

	if (thread->type != THREAD_CHILD_TIMEOUT)
		return 0;

	/* OK, it still hasn't exited. Now really kill it off. */
	pid = THREAD_CHILD_PID(thread);
	if (kill(pid, SIGKILL) < 0) {
		/* Its possible it finished while we're handing this */
		if (errno != ESRCH)
			DBG("kill error: %s", strerror(errno));
		return 0;
	}

	syslog(LOG_WARNING, "Process [%d] didn't respond to SIGTERM", pid);
	waitpid(pid, NULL, 0);

	return 0;
}
