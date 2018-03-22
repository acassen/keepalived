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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include "main.h"
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
#include "global_data.h"
#include "global_parser.h"

static int misc_check_thread(thread_t *);
static int misc_check_child_thread(thread_t *);

static bool script_user_set;
static misc_checker_t *new_misck_checker;
static bool have_dynamic_misc_checker;

void
clear_dynamic_misc_check_flag(void)
{
	have_dynamic_misc_checker = false;
}

/* Configuration stream handling */
static void
free_misc_check(void *data)
{
	misc_checker_t *misck_checker = CHECKER_DATA(data);

	FREE(misck_checker->path);
	FREE(misck_checker);
	FREE(data);
}

static void
dump_misc_check(void *data)
{
	checker_t *checker = data;
	misc_checker_t *misck_checker = checker->data;

	log_message(LOG_INFO, "   Keepalive method = MISC_CHECK");
	log_message(LOG_INFO, "   script = %s", misck_checker->path);
	log_message(LOG_INFO, "   timeout = %lu", misck_checker->timeout/TIMER_HZ);
	log_message(LOG_INFO, "   dynamic = %s", misck_checker->dynamic ? "YES" : "NO");
	log_message(LOG_INFO, "   uid:gid = %d:%d", misck_checker->uid, misck_checker->gid);
	log_message(LOG_INFO, "   insecure = %s", misck_checker->insecure ? "Yes" : "No");
	dump_checker_opts(checker);
}

static bool
misc_check_compare(void *a, void *b)
{
	misc_checker_t *old = CHECKER_DATA(a);
	misc_checker_t *new = CHECKER_DATA(b);

	if (strcmp(old->path, new->path) != 0)
		return false;

	return true;
}

static void
misc_check_handler(__attribute__((unused)) vector_t *strvec)
{
	checker_t *checker;

	new_misck_checker = (misc_checker_t *) MALLOC(sizeof (misc_checker_t));
	new_misck_checker->state = SCRIPT_STATE_IDLE;

	script_user_set = false;

	/* queue new checker */
	checker = queue_checker(free_misc_check, dump_misc_check, misc_check_thread, misc_check_compare, new_misck_checker, NULL);

	/* Set non-standard default value */
	checker->default_retry = 0;
}

static void
misc_path_handler(vector_t *strvec)
{
	if (!new_misck_checker)
		return;

	new_misck_checker->path = CHECKER_VALUE_STRING(strvec);
}

static void
misc_timeout_handler(vector_t *strvec)
{
	if (!new_misck_checker)
		return;

	new_misck_checker->timeout = CHECKER_VALUE_UINT(strvec) * TIMER_HZ;
}

static void
misc_dynamic_handler(__attribute__((unused)) vector_t *strvec)
{
	if (!new_misck_checker)
		return;

	new_misck_checker->dynamic = true;

	if (have_dynamic_misc_checker)
		log_message(LOG_INFO, "Warning - more than one dynamic misc checker per real srver will cause problems");
	else
		have_dynamic_misc_checker = true;
}

static void
misc_user_handler(vector_t *strvec)
{
	if (!new_misck_checker)
		return;

	if (vector_size(strvec) < 2) {
		log_message(LOG_INFO, "No user specified for misc checker script %s", new_misck_checker->path);
		return;
	}

	if (set_script_uid_gid(strvec, 1, &new_misck_checker->uid, &new_misck_checker->gid)) {
		log_message(LOG_INFO, "Failed to set uid/gid for misc checker script %s - removing", new_misck_checker->path);
		dequeue_new_checker();
		new_misck_checker = NULL;
	}
	else
		script_user_set = true;
}

static void
misc_end_handler(void)
{
	if (!new_misck_checker)
		return;

	if (!new_misck_checker->path) {
		log_message(LOG_INFO, "No script path has been specified for MISC_CHECKER - skipping");
		dequeue_new_checker();
		new_misck_checker = NULL;
		return;
	}

	if (!script_user_set)
	{
		if ( set_default_script_user(NULL, NULL, global_data->script_security)) {
			log_message(LOG_INFO, "Unable to set default user for misc script %s - removing", new_misck_checker->path);
			dequeue_new_checker();
			new_misck_checker = NULL;
			return;
		}

		new_misck_checker->uid = default_script_uid;
		new_misck_checker->gid = default_script_gid;
	}

	new_misck_checker = NULL;
}

void
install_misc_check_keyword(void)
{
	install_keyword("MISC_CHECK", &misc_check_handler);
	install_sublevel();
	install_checker_common_keywords(false);
	install_keyword("misc_path", &misc_path_handler);
	install_keyword("misc_timeout", &misc_timeout_handler);
	install_keyword("misc_dynamic", &misc_dynamic_handler);
	install_keyword("user", &misc_user_handler);
	install_sublevel_end_handler(&misc_end_handler);
	install_sublevel_end();
}

/* Check that the scripts are secure */
int
check_misc_script_security(void)
{
	element e;
	checker_t *checker;
	misc_checker_t *misc_script;
	int script_flags = 0;
	int flags;
	notify_script_t script;

	if (LIST_ISEMPTY(checkers_queue))
		return 0;

	for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
		checker = ELEMENT_DATA(e);

		if (checker->launch != misc_check_thread)
			continue;

		misc_script = CHECKER_ARG(checker);

		/* If the misc check script starts "</" (possibly with white space between
		 * the '<' and '/'), it is checking for a file being openable,
		 * so it won't be executed */
		if (misc_script->path[0] == '<' &&
		    misc_script->path[strspn(misc_script->path + 1, " \t") + 1] == '/')
			return 0;

		script.name = misc_script->path;
		script.uid = misc_script->uid;
		script.gid = misc_script->gid;

		script_flags |= (flags = check_script_secure(&script, global_data->script_security, false));

		/* The script path may have been updated if it wasn't an absolute path */
		misc_script->path = script.name;

		/* Mark not to run if needs inhibiting */
		if (flags & SC_INHIBIT) {
			log_message(LOG_INFO, "Disabling misc script %s due to insecure", misc_script->path);
			misc_script->insecure = true;
		}
		else if (flags & SC_NOTFOUND) {
			log_message(LOG_INFO, "Disabling misc script %s since not found/accessible", misc_script->path);
			misc_script->insecure = true;
		}
		else if (!(flags & SC_EXECUTABLE))
			misc_script->insecure = true;
	}

	return script_flags;
}

void
check_misc_set_child_finder(void)
{
	element e;
	checker_t *checker;
	misc_checker_t *misc_script;
	size_t num_misc_checkers = 0;

	if (LIST_ISEMPTY(checkers_queue))
		return;

	for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
		checker = ELEMENT_DATA(e);

		if (checker->launch != misc_check_thread)
			continue;

		misc_script = CHECKER_ARG(checker);
		if (!misc_script->insecure)
			num_misc_checkers++;
	}

	if (!num_misc_checkers)
		return;

	set_child_finder(DEFAULT_CHILD_FINDER, NULL, NULL, NULL, NULL, num_misc_checkers);
}

static int
misc_check_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	misc_checker_t *misck_checker;
	int ret;

	misck_checker = CHECKER_ARG(checker);

	/* If the script has been identified as insecure, don't execute it.
	 * To stop attempting to execute it again, don't re-add the timer. */
	if (misck_checker->insecure)
		return 0;

	/*
	 * Register a new checker thread & return
	 * if checker is disabled
	 */
	if (!checker->enabled) {
		/* Register next timer checker */
		thread_add_timer(thread->master, misc_check_thread, checker,
				 checker->delay_loop);
		return 0;
	}

	/* Execute the script in a child process. Parent returns, child doesn't */
	ret = system_call_script(thread->master, misc_check_child_thread,
				  checker, (misck_checker->timeout) ? misck_checker->timeout : checker->delay_loop,
				  misck_checker->path, misck_checker->uid, misck_checker->gid);
	if (!ret) {
		misck_checker->last_ran = time_now;
		misck_checker->state = SCRIPT_STATE_RUNNING;
	}

	return ret;
}

static int
misc_check_child_thread(thread_t * thread)
{
	int wait_status;
	pid_t pid;
	checker_t *checker;
	misc_checker_t *misck_checker;
	timeval_t next_time;
	int sig_num;
	unsigned timeout = 0;
	char *script_exit_type = NULL;
	bool script_success;
	char *reason = NULL;
	int reason_code;

	checker = THREAD_ARG(thread);
	misck_checker = CHECKER_ARG(checker);

	if (thread->type == THREAD_CHILD_TIMEOUT) {
		pid = THREAD_CHILD_PID(thread);

		if (misck_checker->state == SCRIPT_STATE_RUNNING) {
			misck_checker->state = SCRIPT_STATE_REQUESTING_TERMINATION;
			sig_num = SIGTERM;
			timeout = 2;
		} else if (misck_checker->state == SCRIPT_STATE_REQUESTING_TERMINATION) {
			misck_checker->state = SCRIPT_STATE_FORCING_TERMINATION;
			sig_num = SIGKILL;
			timeout = 2;
		} else if (misck_checker->state == SCRIPT_STATE_FORCING_TERMINATION) {
			log_message(LOG_INFO, "Child (PID %d) failed to terminate after kill", pid);
			sig_num = SIGKILL;
			timeout = 10;	/* Give it longer to terminate */
		}

		if (timeout) {
			/* If kill returns an error, we can't kill the process since either the process has terminated,
			 * or we don't have permission. If we can't kill it, there is no point trying again. */
			if (!kill(-pid, sig_num))
				timeout = 1000;
		} else if (misck_checker->state != SCRIPT_STATE_IDLE) {
			log_message(LOG_INFO, "Child thread pid %d timeout with unknown script state %d", pid, misck_checker->state);
			timeout = 10;	/* We need some timeout */
		}

		if (timeout)
			thread_add_child(thread->master, misc_check_child_thread, checker, pid, timeout * TIMER_HZ);

		return 0;
	}

	wait_status = THREAD_CHILD_STATUS(thread);

	if (WIFEXITED(wait_status)) {
		int status = WEXITSTATUS(wait_status);

		if (status == 0 ||
		    (misck_checker->dynamic && status >= 2 && status <= 255)) {
			/*
			 * The actual weight set when using misc_dynamic is two less than
			 * the exit status returned.  Effective range is 0..253.
			 * Catch legacy case of status being 0 but misc_dynamic being set.
			 */
			if (misck_checker->dynamic && status != 0)
				update_svr_wgt(status - 2, checker->vs,
					       checker->rs, true);

			/* everything is good */
			if (!checker->is_up || !misck_checker->initial_state_reported) {
				script_exit_type = "succeeded";
				script_success = true;
				misck_checker->initial_state_reported = true;
			}

			checker->retry_it = 0;
		} else if (checker->is_up) {
			if (checker->retry_it < checker->retry)
				checker->retry_it++;
			else {
				script_exit_type = "failed";
				script_success = false;
				reason = "exited with status";
				reason_code = status;

				checker->retry_it = 0;
			}
		}
	}
	else if (WIFSIGNALED(wait_status)) {
	        if (misck_checker->state == SCRIPT_STATE_REQUESTING_TERMINATION && WTERMSIG(wait_status) == SIGTERM) {
	                /* The script terminated due to a SIGTERM, and we sent it a SIGTERM to
	                 * terminate the process. Now make sure any children it created have
	                 * died too. */
	                pid = THREAD_CHILD_PID(thread);
	                kill(-pid, SIGKILL);
	        }

		/* We treat forced termination as a failure */
		if (checker->is_up) {
			if (checker->retry_it < checker->retry)
				checker->retry_it++;
			else {
				if ((misck_checker->state == SCRIPT_STATE_REQUESTING_TERMINATION &&
				     WTERMSIG(wait_status) == SIGTERM) ||
				    (misck_checker->state == SCRIPT_STATE_FORCING_TERMINATION &&
				     (WTERMSIG(wait_status) == SIGTERM || WTERMSIG(wait_status) == SIGKILL)))
					script_exit_type = "timed out";
				else {
					script_exit_type = "failed";
					reason = "due to signal";
					reason_code = WTERMSIG(wait_status);
				}

				script_success = false;

				checker->retry_it = 0;
			}
		}
	}

	if (script_exit_type) {
		char message[40];

		if (reason)
			log_message(LOG_INFO, "Misc check to [%s] for [%s] %s (%s %d)."
					    , inet_sockaddrtos(&checker->rs->addr)
					    , misck_checker->path
					    , script_exit_type
					    , reason
					    , reason_code);
		else
			log_message(LOG_INFO, "Misc check to [%s] for [%s] %s."
					    , inet_sockaddrtos(&checker->rs->addr)
					    , misck_checker->path
					    , script_exit_type);

		snprintf(message, sizeof(message), "=> MISC CHECK %s on service <=", script_exit_type);
		smtp_alert(checker, NULL, NULL,
			   script_success ? "UP " : "DOWN", message);
		update_svr_checker_state(script_success ? UP : DOWN, checker);
	}

	/* Register next timer checker */
	next_time = timer_add_long(misck_checker->last_ran, checker->retry_it ? checker->delay_before_retry : checker->delay_loop);
	next_time = timer_sub_now(next_time);
	if (next_time.tv_sec < 0 ||
	    (next_time.tv_sec == 0 && next_time.tv_usec == 0))
		next_time.tv_sec = 0, next_time.tv_usec = 1;

	thread_add_timer(thread->master, misc_check_thread, checker, timer_tol(next_time));

	misck_checker->state = SCRIPT_STATE_IDLE;

	return 0;
}
