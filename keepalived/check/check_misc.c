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

#include <errno.h>
#include <signal.h>
#include <stdio.h>

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
#include "keepalived_magic.h"
#ifdef THREAD_DUMP
#include "scheduler.h"
#endif
#include "check_parser.h"

static void misc_check_thread(thread_ref_t);
static void misc_check_child_thread(thread_ref_t);

static bool script_user_set;

/* Configuration stream handling */
static void
free_misc_check(checker_t *checker)
{
	misc_checker_t *misck_checker = checker->data;

	if (misck_checker->script.args)
		FREE(misck_checker->script.args);
	FREE(misck_checker);
	FREE(checker);
}

static void
dump_misc_check(FILE *fp, const checker_t *checker)
{
	const misc_checker_t *misck_checker = checker->data;
	char time_str[26];

	conf_write(fp, "   Keepalive method = MISC_CHECK");
	conf_write(fp, "   script = %s", cmd_str(&misck_checker->script));
	conf_write(fp, "   timeout = %lu", misck_checker->timeout/TIMER_HZ);
	conf_write(fp, "   dynamic = %s", misck_checker->dynamic ? "YES" : "NO");
	conf_write(fp, "   uid:gid = %u:%u", misck_checker->script.uid, misck_checker->script.gid);
	ctime_r(&misck_checker->last_ran.tv_sec, time_str);
	conf_write(fp, "   Last ran = %ld.%6.6ld (%.24s.%6.6ld)", misck_checker->last_ran.tv_sec, misck_checker->last_ran.tv_usec, time_str, misck_checker->last_ran.tv_usec);
	conf_write(fp, "   Last status = %u", misck_checker->last_exit_code);
}

static bool
compare_misc_check(const checker_t *old_c, checker_t *new_c)
{
	const misc_checker_t *old = old_c->data;
	const misc_checker_t *new = new_c->data;

	if (new->dynamic != old->dynamic)
		return false;

	return notify_script_compare(&old->script, &new->script);
}

static void
migrate_misc_check(checker_t *new_c, const checker_t *old_c)
{
	const misc_checker_t *old = old_c->data;
	misc_checker_t *new = new_c->data;

	new->last_exit_code = old->last_exit_code;
	new->last_ran = old->last_ran;

	if (!new->dynamic || old->last_exit_code == 1)
		return;

	new_c->cur_weight = new->last_exit_code - (new->last_exit_code ? 2 : 0) - new_c->rs->iweight;
}

static const checker_funcs_t misc_checker_funcs = { CHECKER_MISC, free_misc_check, dump_misc_check, compare_misc_check, migrate_misc_check };

static void
misc_check_handler(__attribute__((unused)) const vector_t *strvec)
{
	misc_checker_t *new_misck_checker;

	PMALLOC(new_misck_checker);
	new_misck_checker->state = SCRIPT_STATE_IDLE;

	script_user_set = false;

	/* queue new checker */
	queue_checker(&misc_checker_funcs, misc_check_thread, new_misck_checker, NULL, false);

	/* Set non-standard default value */
	current_checker->default_retry = 0;
}

static void
misc_path_handler(__attribute__((unused)) const vector_t *strvec)
{
	const vector_t *strvec_qe;
	misc_checker_t *new_misck_checker = current_checker->data;

	/* We need to allow quoted and escaped strings for the script and parameters */
	strvec_qe = alloc_strvec_quoted_escaped(NULL);

	set_script_params_array(strvec_qe, &new_misck_checker->script, 0);

	free_strvec(strvec_qe);
}

static void
misc_timeout_handler(const vector_t *strvec)
{
	unsigned timeout;
	misc_checker_t *new_misck_checker = current_checker->data;

	if (!read_unsigned_strvec(strvec, 1, &timeout, 0, UINT_MAX / TIMER_HZ, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid misc_timeout value '%s'", strvec_slot(strvec, 1));
		return;
	}

	new_misck_checker->timeout = timeout * TIMER_HZ;
}

static void
misc_dynamic_handler(__attribute__((unused)) const vector_t *strvec)
{
	misc_checker_t *new_misck_checker = current_checker->data;

	new_misck_checker->dynamic = true;
}

static void
misc_user_handler(const vector_t *strvec)
{
	misc_checker_t *new_misck_checker = current_checker->data;

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "No user specified for misc checker script %s", cmd_str(&new_misck_checker->script));
		return;
	}

	if (set_script_uid_gid(strvec, 1, &new_misck_checker->script.uid, &new_misck_checker->script.gid)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Failed to set uid/gid for misc checker script %s - removing", cmd_str(&new_misck_checker->script));
		dequeue_new_checker();
	}
	else
		script_user_set = true;
}

static void
misc_end_handler(void)
{
	misc_checker_t *new_misck_checker = current_checker->data;

	if (!new_misck_checker->script.args) {
		report_config_error(CONFIG_GENERAL_ERROR, "No script path has been specified for MISC_CHECKER - skipping");
		dequeue_new_checker();
		return;
	}

	if (!script_user_set)
	{
		if (get_default_script_user(&new_misck_checker->script.uid, &new_misck_checker->script.gid)) {
			report_config_error(CONFIG_GENERAL_ERROR, "Unable to set default user for misc script %s - removing", cmd_str(&new_misck_checker->script));
			dequeue_new_checker();
			return;
		}
	}
}

void
install_misc_check_keyword(void)
{
	vpp_t check_ptr;

	install_keyword("MISC_CHECK", &misc_check_handler);
	check_ptr = install_sublevel(VPP &current_checker);
	install_checker_common_keywords(false);
	install_keyword("misc_path", &misc_path_handler);
	install_keyword("misc_timeout", &misc_timeout_handler);
	install_keyword("misc_dynamic", &misc_dynamic_handler);
	install_keyword("user", &misc_user_handler);
	install_level_end_handler(&misc_end_handler);
	install_sublevel_end(check_ptr);
}

/* Check that the scripts are secure */
unsigned
check_misc_script_security(magic_t magic)
{
	virtual_server_t *vs;
	real_server_t *rs;
	checker_t *checker, *checker_tmp;
	misc_checker_t *misc_script;
	unsigned script_flags = 0;
	unsigned flags;
	bool insecure;

	list_for_each_entry(vs, &check_data->vs, e_list) {
		list_for_each_entry(rs, &vs->rs, e_list) {
			list_for_each_entry_safe(checker, checker_tmp, &rs->checkers_list, rs_list) {
				if (checker->launch != misc_check_thread)
					continue;

				misc_script = CHECKER_ARG(checker);

				script_flags |= (flags = check_script_secure(&misc_script->script, magic));

				/* Mark not to run if needs inhibiting */
				insecure = false;
				if (flags & SC_INHIBIT) {
					log_message(LOG_INFO, "Disabling misc script %s due to insecure", cmd_str(&misc_script->script));
					insecure = true;
				}
				else if (flags & SC_NOTFOUND) {
					log_message(LOG_INFO, "Disabling misc script %s since not found/accessible", cmd_str(&misc_script->script));
					insecure = true;
				}
				else if (!(flags & (SC_EXECUTABLE | SC_SYSTEM)))
					insecure = true;

				if (insecure) {
					/* Remove the script */
					free_checker(checker);
				}
			}
		}
	}

	return script_flags;
}

static void
misc_check_thread(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	misc_checker_t *misck_checker;
	int ret;

	misck_checker = CHECKER_ARG(checker);

	/*
	 * Register a new checker thread & return
	 * if checker is disabled
	 */
	if (!checker->enabled) {
		/* Register next timer checker */
		thread_add_timer(thread->master, misc_check_thread, checker,
				 checker->delay_loop);
		return;
	}

	/* Execute the script in a child process. Parent returns, child doesn't */
	ret = system_call_script(thread->master, misc_check_child_thread,
				  checker, (misck_checker->timeout) ? misck_checker->timeout : checker->vs->delay_loop,
				  &misck_checker->script);
	if (!ret) {
		misck_checker->last_ran = time_now;
		misck_checker->state = SCRIPT_STATE_RUNNING;
	}
}

static void
misc_check_child_thread(thread_ref_t thread)
{
	int wait_status;
	pid_t pid;
	checker_t *checker;
	misc_checker_t *misck_checker;
	timeval_t next_time;
	int sig_num;
	unsigned timeout = 0;
	const char *script_exit_type = NULL;
	bool script_success = false;
	const char *reason = NULL;
	int reason_code = 0;	/* Avoid uninitialised warning by older versions of gcc */
	bool rs_was_alive;
	bool message_only = false;

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
			if (kill(-pid, sig_num)) {
				if (errno == ESRCH) {
					/* The process does not exist, and we should
					 * have reaped its exit status, otherwise it
					 * would exist as a zombie process. */
					log_message(LOG_INFO, "Misc script %s child (PID %d) lost, register checker again", misck_checker->script.args[0], pid);
					misck_checker->state = SCRIPT_STATE_IDLE;
					timeout = 0;
					goto recheck;
				} else {
					log_message(LOG_INFO, "kill -%d of process %s(%d) with new state %u failed with errno %d", sig_num, misck_checker->script.args[0], pid, misck_checker->state, errno);
					timeout = 1000;
				}
			}
		} else if (misck_checker->state != SCRIPT_STATE_IDLE) {
			log_message(LOG_INFO, "Child thread pid %d timeout with unknown script state %u", pid, misck_checker->state);
			timeout = 10;	/* We need some timeout */
		}

		if (timeout)
			thread_add_child(thread->master, misc_check_child_thread, checker, pid, timeout * TIMER_HZ);

		return;
	}

	wait_status = THREAD_CHILD_STATUS(thread);

	if (WIFEXITED(wait_status)) {
		unsigned status = WEXITSTATUS(wait_status);
		int64_t effective_weight;

		if (status == 0 ||
		    (misck_checker->dynamic && status >= 2 && status <= 255)) {
			/*
			 * The actual weight set when using misc_dynamic is two less than
			 * the exit status returned.  Effective range is 0..253.
			 * Catch legacy case of status being 0 but misc_dynamic being set.
			 */
			if (status != misck_checker->last_exit_code) {
				effective_weight = checker->rs->effective_weight - checker->cur_weight;
				checker->cur_weight = status ? status - 2 - checker->rs->iweight : 0;
				effective_weight += checker->cur_weight;
				update_svr_wgt(effective_weight, checker->vs, checker->rs, true);
				misck_checker->last_exit_code = status;
			}

			/* everything is good */
			if (!checker->is_up || !checker->has_run) {
				script_exit_type = "succeeded";
				script_success = true;
			}

			checker->retry_it = 0;
		} else if (checker->is_up || !checker->has_run) {
			script_exit_type = "failed";
			reason = "exited with status";
			reason_code = status;

			if (checker->retry_it < checker->retry) {
				checker->retry_it++;
				if (global_data->checker_log_all_failures || checker->log_all_failures)
					message_only = true;
				else
					script_exit_type = NULL; /* this disables all message handling */
			} else {
				checker->retry_it = 0;
				checker->rs->effective_weight -= checker->cur_weight;
				checker->cur_weight = 0;
				misck_checker->last_exit_code = status;
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
		if (checker->is_up || !checker->has_run) {
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

			if (checker->retry_it < checker->retry) {
				checker->retry_it++;
				if (global_data->checker_log_all_failures || checker->log_all_failures)
					message_only = true;
				else
					script_exit_type = NULL; /* this disables all message handling */
			} else
				checker->retry_it = 0;
		}
	}

	if (script_exit_type) { /* not the case if retry check will follow and log_all_failures unset */
		char message[40];

		if (!script_success) {
			/*
			 * retry is always the fixed value of config parameter retry
			 * If retry > 0 then on the regulary scheduled check fail retry_it is 1, on the first retry check fail retry_it is 2 and so on
			 * but on the last retry check fail, retry_it is 0
			 */
			if (checker->retry) {
				if (checker->retry_it == 1) /* failed regulary scheduled check */
					snprintf(message, sizeof(message), ", will do %u %s", checker->retry, checker->retry == 1 ? "retry" : "retries");
				else if (checker->retry_it > 1) /* failed retry check, but not the last */
					snprintf(message, sizeof(message), " on retry %u/%u", checker->retry_it - 1, checker->retry);
				else /* failed last retry check */
					snprintf(message, sizeof(message), " after %u %s", checker->retry, checker->retry == 1 ? "retry" : "retries" );
			} else /* retry 0 */
				snprintf(message, sizeof(message), " with retry disabled");
		} else
			message[0] = '\0';

		if (reason)
			log_message(LOG_INFO, "Misc check for [%s VS %s] by [%s] %s%s (%s %d)."
					    , FMT_CHK(checker)
					    , FMT_VS(checker->vs)
					    , misck_checker->script.args[0]
					    , script_exit_type
					    , message
					    , reason
					    , reason_code);
		else
			log_message(LOG_INFO, "Misc check for [%s VS %s] by [%s] %s%s."
					    , FMT_CHK(checker)
					    , FMT_VS(checker->vs)
					    , misck_checker->script.args[0]
					    , script_exit_type
					    , message);

		if (!message_only) {
			rs_was_alive = checker->rs->alive;
			update_svr_checker_state(script_success ? UP : DOWN, checker);
			if (!script_success)
				checker->cur_weight = 0;

			if (checker->rs->smtp_alert &&
			    (rs_was_alive != checker->rs->alive || !global_data->no_checker_emails)) {
				snprintf(message, sizeof(message), "=> MISC CHECK %s on service <=", script_exit_type);
				smtp_alert(SMTP_MSG_RS, checker, NULL, message);
			}
		}
	}

recheck:
	/* Register next timer checker */
	next_time = timer_add_long(misck_checker->last_ran, checker->retry_it ? checker->delay_before_retry : checker->delay_loop);
	next_time = timer_sub_now(next_time);
	if (next_time.tv_sec < 0 ||
	    (next_time.tv_sec == 0 && next_time.tv_usec == 0))
		next_time.tv_sec = 0, next_time.tv_usec = 1;

	thread_add_timer(thread->master, misc_check_thread, checker, timer_long(next_time));

	misck_checker->state = SCRIPT_STATE_IDLE;

	checker->has_run = true;
}

#ifdef THREAD_DUMP
void
register_check_misc_addresses(void)
{
	register_thread_address("misc_check_child_thread", misc_check_child_thread);
	register_thread_address("misc_check_thread", misc_check_thread);
}
#endif
