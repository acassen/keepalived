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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <errno.h>
#include <signal.h>

#include "main.h"
#include "check_misc.h"
#include "check_api.h"
#include "ipwrapper.h"
#include "logger.h"
#include "smtp.h"
#include "utils.h"
#include "parser.h"
#include "daemon.h"
#include "global_data.h"
#include "global_parser.h"

static int misc_check_thread(thread_t *);
static int misc_check_child_thread(thread_t *);
static int misc_check_child_timeout_thread(thread_t *);

/* Configuration stream handling */
static void
free_misc_check(void *data)
{
	misc_checker_t *misck_checker = CHECKER_DATA(data);

	FREE(misck_checker->script.cmd_str);
	FREE(misck_checker->script.args);
	FREE(misck_checker);
	FREE(data);
}

static void
dump_misc_check(void *data)
{
	misc_checker_t *misck_checker = CHECKER_DATA(data);
	log_message(LOG_INFO, "   Keepalive method = MISC_CHECK");
	log_message(LOG_INFO, "   script = %s", misck_checker->script.cmd_str);
	log_message(LOG_INFO, "   timeout = %lu", misck_checker->timeout/TIMER_HZ);
	log_message(LOG_INFO, "   dynamic = %s", misck_checker->dynamic ? "YES" : "NO");
	log_message(LOG_INFO, "   uid:gid = %d:%d", misck_checker->script.uid, misck_checker->script.gid);
}

static void
misc_check_handler(__attribute__((unused)) vector_t *strvec)
{
	misc_checker_t *misck_checker = (misc_checker_t *) MALLOC(sizeof (misc_checker_t));

	misck_checker->script.uid = default_script_uid;
	misck_checker->script.gid = default_script_gid;

	/* queue new checker */
	queue_checker(free_misc_check, dump_misc_check, misc_check_thread,
		      misck_checker, NULL);
}

static void
misc_path_handler(vector_t *strvec)
{
	misc_checker_t *misck_checker = CHECKER_GET();
	misck_checker->script.cmd_str = CHECKER_VALUE_STRING(strvec);
	misck_checker->script.args = set_script_params_array(strvec, true);
}

static void
misc_timeout_handler(vector_t *strvec)
{
	misc_checker_t *misck_checker = CHECKER_GET();
	misck_checker->timeout = CHECKER_VALUE_UINT(strvec) * TIMER_HZ;
}

static void
misc_dynamic_handler(__attribute__((unused)) vector_t *strvec)
{
	misc_checker_t *misck_checker = CHECKER_GET();
	misck_checker->dynamic = 1;
}

static void
misc_user_handler(vector_t *strvec)
{
	misc_checker_t *misck_checker = CHECKER_GET();

	if (vector_size(strvec) < 2) {
		log_message(LOG_INFO, "No user specified for misc checker script %s", misck_checker->script.cmd_str);
		return;
	}

	if (set_script_uid_gid(strvec, 1, &misck_checker->script.uid, &misck_checker->script.gid))
		log_message(LOG_INFO, "Failed to set uid/gid for misc checker script %s", misck_checker->script.cmd_str);
}

void
install_misc_check_keyword(void)
{
	install_keyword("MISC_CHECK", &misc_check_handler);
	install_sublevel();
	install_keyword("misc_path", &misc_path_handler);
	install_keyword("misc_timeout", &misc_timeout_handler);
	install_keyword("misc_dynamic", &misc_dynamic_handler);
	install_keyword("warmup", &warmup_handler);
	install_keyword("user", &misc_user_handler);
	install_sublevel_end();
}

/* Check that the scripts are secure */
int
check_misc_script_security(void)
{
	element e, next;
	checker_t *checker;
	misc_checker_t *misc_script;
	int script_flags = 0;
	int flags;
	bool insecure;

	if (LIST_ISEMPTY(checkers_queue))
		return 0;

	for (e = LIST_HEAD(checkers_queue); e; e = next) {
		next = e->next;
		checker = ELEMENT_DATA(e);

		if (checker->launch != misc_check_thread)
			continue;

		misc_script = CHECKER_ARG(checker);

		script_flags |= (flags = check_script_secure(&misc_script->script));

		/* Mark not to run if needs inhibiting */
		insecure = false;
		if (flags & SC_INHIBIT) {
			log_message(LOG_INFO, "Disabling misc script %s due to insecure", misc_script->script.cmd_str);
			insecure = true;
		}
		else if (flags & SC_NOTFOUND) {
			log_message(LOG_INFO, "Disabling misc script %s since not found", misc_script->script.cmd_str);
			insecure = true;
		}
		else if (!(flags & SC_EXECUTABLE))
			insecure = true;

		if (insecure) {
			/* Remove the script */
			free_list_element(checkers_queue, e);
		}
	}

	return script_flags;
}

static int
misc_check_thread(thread_t * thread)
{
	checker_t *checker;
	misc_checker_t *misck_checker;

	checker = THREAD_ARG(thread);
	misck_checker = CHECKER_ARG(checker);

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

	misck_checker->forcing_termination = false;

	/* Register next timer checker */
	thread_add_timer(thread->master, misc_check_thread, checker,
			 checker->vs->delay_loop);

	/* Execute the script in a child process. Parent returns, child doesn't */
	return system_call_script(thread->master, misc_check_child_thread,
				  checker, (misck_checker->timeout) ? misck_checker->timeout : checker->vs->delay_loop,
				  &misck_checker->script);
}

static int
misc_check_child_thread(thread_t * thread)
{
	int wait_status;
	pid_t pid;
	checker_t *checker;
	misc_checker_t *misck_checker;

	checker = THREAD_ARG(thread);
	misck_checker = CHECKER_ARG(checker);

	if (thread->type == THREAD_CHILD_TIMEOUT) {
		pid = THREAD_CHILD_PID(thread);

		/* The child hasn't responded. Kill it off. */
		if (svr_checker_up(checker->id, checker->rs)) {
			log_message(LOG_INFO, "Misc check to [%s] for [%s] timed out"
					    , inet_sockaddrtos(&checker->rs->addr)
					    , misck_checker->script.cmd_str);
			smtp_alert(checker->rs, NULL, NULL,
				   "DOWN",
				   "=> MISC CHECK script timeout on service <=");
			update_svr_checker_state(DOWN, checker->id
						     , checker->vs
						     , checker->rs);
		}

		misck_checker->forcing_termination = true;
		kill(-pid, SIGTERM);
		thread_add_child(thread->master, misc_check_child_timeout_thread,
				 checker, pid, 2);
		return 0;
	}

	wait_status = THREAD_CHILD_STATUS(thread);

	if (WIFEXITED(wait_status)) {
		int status;
		status = WEXITSTATUS(wait_status);
		if (status == 0 ||
		    (misck_checker->dynamic == 1 && status >= 2 && status <= 255)) {
			/*
			 * The actual weight set when using misc_dynamic is two less than
			 * the exit status returned.  Effective range is 0..253.
			 * Catch legacy case of status being 0 but misc_dynamic being set.
			 */
			if (misck_checker->dynamic == 1 && status != 0)
				update_svr_wgt(status - 2, checker->vs,
					       checker->rs, true);

			/* everything is good */
			if (!svr_checker_up(checker->id, checker->rs)) {
				log_message(LOG_INFO, "Misc check to [%s] for [%s] success."
						    , inet_sockaddrtos(&checker->rs->addr)
						    , misck_checker->script.cmd_str);
				smtp_alert(checker->rs, NULL, NULL,
					   "UP",
					   "=> MISC CHECK succeed on service <=");
				update_svr_checker_state(UP, checker->id
							   , checker->vs
							   , checker->rs);
			}
		} else {
			if (svr_checker_up(checker->id, checker->rs)) {
				log_message(LOG_INFO, "Misc check to [%s] for [%s] failed."
						    , inet_sockaddrtos(&checker->rs->addr)
						    , misck_checker->script.cmd_str);
				smtp_alert(checker->rs, NULL, NULL,
					   "DOWN",
					   "=> MISC CHECK failed on service <=");
				update_svr_checker_state(DOWN, checker->id
							     , checker->vs
							     , checker->rs);
			}
		}
	}
	else if (WIFSIGNALED(wait_status)) {
	        if (misck_checker->forcing_termination && WTERMSIG(wait_status) == SIGTERM) {
	                /* The script terminated due to a SIGTERM, and we sent it a SIGTERM to
	                 * terminate the process. Now make sure any children it created have
	                 * died too. */
	                pid = THREAD_CHILD_PID(thread);
	                kill(-pid, SIGKILL);
	        }
	}

	misck_checker->forcing_termination = false;

	return 0;
}

static int
misc_check_child_timeout_thread(thread_t * thread)
{
	pid_t pid;
	checker_t *checker;
	misc_checker_t *misck_checker;

	if (thread->type != THREAD_CHILD_TIMEOUT)
		return 0;

	/* OK, it still hasn't exited. Now really kill it off. */
	pid = THREAD_CHILD_PID(thread);
	if (kill(-pid, SIGKILL) < 0) {
		/* Its possible it finished while we're handing this */
		if (errno != ESRCH) {
			DBG("kill error: %s", strerror(errno));
		}
		return 0;
	}

	log_message(LOG_WARNING, "Process [%d] didn't respond to SIGTERM", pid);

	checker = THREAD_ARG(thread);
	misck_checker = CHECKER_ARG(checker);

	misck_checker->forcing_termination = false;

	return 0;
}

#ifdef _TIMER_DEBUG_
void
print_check_misc_addresses(void)
{
	log_message(LOG_INFO, "Address of dump_misc_check() is 0x%p", dump_misc_check);
	log_message(LOG_INFO, "Address of misc_check_child_thread() is 0x%p", misc_check_child_thread);
	log_message(LOG_INFO, "Address of misc_check_child_timeout_thread() is 0x%p", misc_check_child_timeout_thread);
	log_message(LOG_INFO, "Address of misc_check_thread() is 0x%p", misc_check_thread);
}
#endif
