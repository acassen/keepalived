/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        MISC CHECK. Perform a system call to run an extra
 *              system prog or script.
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
 * Copyright (C) 2001-2009 Alexandre Cassen, <acassen@freebox.fr>
 */

#include "check_misc.h"
#include "check_api.h"
#include "memory.h"
#include "ipwrapper.h"
#include "logger.h"
#include "smtp.h"
#include "utils.h"
#include "parser.h"
#include "notify.h"
#include "daemon.h"
#include "signals.h"

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
	log_message(LOG_INFO, "   Keepalive method = MISC_CHECK");
	log_message(LOG_INFO, "   script = %s", misc_chk->path);
	log_message(LOG_INFO, "   timeout = %lu", misc_chk->timeout/TIMER_HZ);
	log_message(LOG_INFO, "   dynamic = %s", misc_chk->dynamic ? "YES" : "NO");
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
misc_dynamic_handler(vector strvec)
{
	misc_checker *misc_chk = CHECKER_GET();
	misc_chk->dynamic = 1;
}

void
install_misc_check_keyword(void)
{
	install_keyword("MISC_CHECK", &misc_check_handler);
	install_sublevel();
	install_keyword("misc_path", &misc_path_handler);
	install_keyword("misc_timeout", &misc_timeout_handler);
	install_keyword("misc_dynamic", &misc_dynamic_handler);
	install_sublevel_end();
}

int
misc_check_thread(thread * thread_obj)
{
	checker *checker_obj;
	misc_checker *misc_chk;
	int status, ret;
	pid_t pid;

	checker_obj = THREAD_ARG(thread_obj);
	misc_chk = CHECKER_ARG(checker_obj);

	/*
	 * Register a new checker thread & return
	 * if checker is disabled
	 */
	if (!CHECKER_ENABLED(checker_obj)) {
		/* Register next timer checker */
		thread_add_timer(thread_obj->master, misc_check_thread, checker_obj,
				 checker_obj->vs->delay_loop);
		return 0;
	}

	/* Register next timer checker */
	thread_add_timer(thread_obj->master, misc_check_thread, checker_obj,
			 checker_obj->vs->delay_loop);

	/* Daemonization to not degrade our scheduling timer */
	pid = fork();

	/* In case of fork is error. */
	if (pid < 0) {
		log_message(LOG_INFO, "Failed fork process");
		return -1;
	}

	/* In case of this is parent process */
	if (pid) {
		long timeout;
		timeout = (misc_chk->timeout) ? misc_chk->timeout : checker_obj->vs->delay_loop;

		thread_add_child(thread_obj->master, misc_check_child_thread,
				 checker_obj, pid, timeout);
		return 0;
	}

	/* Child part */
	signal_handler_destroy();
	closeall(0);

	open("/dev/null", O_RDWR);
	ret = dup(0);
	ret = dup(0);

	status = system_call(misc_chk->path);

	if (status < 0 || !WIFEXITED(status))
		status = 0; /* Script errors aren't server errors */
	else
		status = WEXITSTATUS(status);

	exit(status);
}

int
misc_check_child_thread(thread * thread_obj)
{
	int wait_status;
	checker *checker_obj;
	misc_checker *misc_chk;

	checker_obj = THREAD_ARG(thread_obj);
	misc_chk = CHECKER_ARG(checker_obj);

	if (thread_obj->type == THREAD_CHILD_TIMEOUT) {
		pid_t pid;

		pid = THREAD_CHILD_PID(thread_obj);

		/* The child hasn't responded. Kill it off. */
		if (svr_checker_up(checker_obj->id, checker_obj->rs)) {
			log_message(LOG_INFO, "Misc check to [%s] for [%s] timed out",
			       inet_ntop2(CHECKER_RIP(checker_obj)),
			       misc_chk->path);
			smtp_alert(checker_obj->rs, NULL, NULL,
				   "DOWN",
				   "=> MISC CHECK script timeout on service <=");
			update_svr_checker_state(DOWN, checker_obj->id
						     , checker_obj->vs
						     , checker_obj->rs);
		}

		kill(pid, SIGTERM);
		thread_add_child(thread_obj->master, misc_check_child_timeout_thread,
				 checker_obj, pid, 2);
		return 0;
	}

	wait_status = THREAD_CHILD_STATUS(thread_obj);

	if (WIFEXITED(wait_status)) {
		int status;
		status = WEXITSTATUS(wait_status);
		if (status == 0 ||
                    (misc_chk->dynamic == 1 && status >= 2 && status <= 255)) {
			/*
			 * The actual weight set when using misc_dynamic is two less than
			 * the exit status returned.  Effective range is 0..253.
			 * Catch legacy case of status being 0 but misc_dynamic being set.
			 */
			if (misc_chk->dynamic == 1 && status != 0)
				update_svr_wgt(status - 2, checker_obj->vs, checker_obj->rs);

			/* everything is good */
			if (!svr_checker_up(checker_obj->id, checker_obj->rs)) {
				log_message(LOG_INFO, "Misc check to [%s] for [%s] success.",
				       inet_ntop2(CHECKER_RIP(checker_obj)),
				       misc_chk->path);
				smtp_alert(checker_obj->rs, NULL, NULL,
					   "UP",
					   "=> MISC CHECK succeed on service <=");
				update_svr_checker_state(UP, checker_obj->id
							   , checker_obj->vs
							   , checker_obj->rs);
			}
		} else {
			if (svr_checker_up(checker_obj->id, checker_obj->rs)) {
				log_message(LOG_INFO, "Misc check to [%s] for [%s] failed.",
				       inet_ntop2(CHECKER_RIP(checker_obj)),
				       misc_chk->path);
				smtp_alert(checker_obj->rs, NULL, NULL,
					   "DOWN",
					   "=> MISC CHECK failed on service <=");
				update_svr_checker_state(DOWN, checker_obj->id
							     , checker_obj->vs
							     , checker_obj->rs);
			}
		}
	}

	return 0;
}

int
misc_check_child_timeout_thread(thread * thread_obj)
{
	pid_t pid;

	if (thread_obj->type != THREAD_CHILD_TIMEOUT)
		return 0;

	/* OK, it still hasn't exited. Now really kill it off. */
	pid = THREAD_CHILD_PID(thread_obj);
	if (kill(pid, SIGKILL) < 0) {
		/* Its possible it finished while we're handing this */
		if (errno != ESRCH)
			DBG("kill error: %s", strerror(errno));
		return 0;
	}

	log_message(LOG_WARNING, "Process [%d] didn't respond to SIGTERM", pid);
	waitpid(pid, NULL, 0);

	return 0;
}
