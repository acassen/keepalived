/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        MISC CHECK. Perform a system call to run an extra
 *              system prog or script.
 *
 * Version:     $Id: check_misc.c,v 1.0.1 2003/03/17 22:14:34 acassen Exp $
 *
 * Authors:     Alexandre Cassen, <acassen@linux-vs.org>
 *              Eric Jarman, <ehj38230@cmsu2.cmsu.edu>
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
 */

#include "check_misc.h"
#include "check_api.h"
#include "memory.h"
#include "ipwrapper.h"
#include "smtp.h"
#include "utils.h"
#include "parser.h"
#include "notify.h"

int misc_check_thread(thread *);

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
install_misc_check_keyword(void)
{
	install_keyword("MISC_CHECK", &misc_check_handler);
	install_sublevel();
	install_keyword("misc_path", &misc_path_handler);
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
	if (pid)
		return 0;

	/* Child part */
	closeall(0);

	open("/dev/null", O_RDWR);
	dup(0);
	dup(0);

	status = system_call(misc_chk->path);

	if (status >= 0) {	/* script error assumed  not an svr error */
		if (status == 0) {
			/* everything is good */
			if (!ISALIVE(checker->rs)) {
				smtp_alert(thread->master, checker->rs, NULL, NULL,
					   "UP",
					   "=> MISC CHECK succeed on service <=");
				perform_svr_state(UP, checker->vs, checker->rs);
			}
		} else {
			if (ISALIVE(checker->rs)) {
				smtp_alert(thread->master, checker->rs, NULL, NULL,
					   "DOWN",
					   "=> MISC CHECK failed on service <=");
				perform_svr_state(DOWN, checker->vs, checker->rs);
			}
		}
	}

	exit(0);
}
