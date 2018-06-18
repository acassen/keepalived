/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Healthcheckrs child process handling.
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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#ifdef _HAVE_SCHED_RT_
#include <sched.h>
#endif
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/prctl.h>

#include "check_daemon.h"
#include "check_parser.h"
#include "ipwrapper.h"
#include "check_ssl.h"
#include "check_api.h"
#include "global_data.h"
#include "pidfile.h"
#include "signals.h"
#include "process.h"
#include "logger.h"
#include "main.h"
#include "parser.h"
#include "bitops.h"
#include "keepalived_netlink.h"
#ifdef _WITH_SNMP_CHECKER_
  #include "check_snmp.h"
#endif
#include "utils.h"
#ifdef _WITH_BFD_
#include "bfd_daemon.h"
#include "check_bfd.h"
#endif
#include "timer.h"

/* Global variables */
bool using_ha_suspend;

/* local variables */
static char *check_syslog_ident;
static bool two_phase_terminate;

static int
lvs_notify_fifo_script_exit(__attribute__((unused)) thread_t *thread)
{
	log_message(LOG_INFO, "lvs notify fifo script terminated");

	return 0;
}

void
checker_dispatcher_release(void)
{
#ifdef _WITH_BFD_
	checker_bfd_dispatcher_release();
#endif
	cancel_signal_read_thread();
}


/* Daemon stop sequence */
static int
checker_terminate_phase2(void)
{
	/* Remove the notify fifo */
	notify_fifo_close(&global_data->notify_fifo, &global_data->lvs_notify_fifo);

	/* Destroy master thread */
	signal_handler_destroy();
	checker_dispatcher_release();
	thread_destroy_master(master);
	master = NULL;
	free_checkers_queue();
	free_ssl();

	ipvs_stop();
#ifdef _WITH_SNMP_CHECKER_
	if (global_data && global_data->enable_snmp_checker)
		check_snmp_agent_close();
#endif

	/* Stop daemon */
	pidfile_rm(checkers_pidfile);

	/* Clean data */
	if (global_data)
		free_global_data(global_data);
	if (check_data)
		free_check_data(check_data);
	free_parent_mallocs_exit();

	/*
	 * Reached when terminate signal catched.
	 * finally return to parent process.
	 */
	log_message(LOG_INFO, "Stopped");

	if (log_file_name)
		close_log_file();
	closelog();

#ifndef _MEM_CHECK_LOG_
	FREE_PTR(check_syslog_ident);
#else
	if (check_syslog_ident)
		free(check_syslog_ident);
#endif
	close_std_fd();

	return 0;
}

static int
checker_shutdown_backstop_thread(thread_t *thread)
{
        log_message(LOG_ERR, "backstop thread invoked: shutdown timer %srunning, child count %d",
			thread->master->shutdown_timer_running ? "" : "not ", thread->master->child.count);

        checker_terminate_phase2();

        return 0;
}

static void
checker_terminate_phase1(bool schedule_next_thread)
{
	if (using_ha_suspend || __test_bit(LOG_ADDRESS_CHANGES, &debug))
		kernel_netlink_close();

	/* Terminate all script processes */
	if (master->child.count)
		script_killall(master, SIGTERM, true);

	/* Send shutdown messages */
	if (!__test_bit(DONT_RELEASE_IPVS_BIT, &debug) &&
	    !__test_bit(CONFIG_TEST_BIT, &debug))
		clear_services();

	if (schedule_next_thread) {
		/* If there are no child processes, we can terminate immediately,
		 * otherwise add a thread to allow reasonable time for children to terminate */
		if (master->child.count) {
			/* Add a backstop timer for the shutdown */
			thread_add_timer(master, checker_shutdown_backstop_thread, NULL, TIMER_HZ);
		}
		else
			thread_add_terminate_event(master);
	}
}

static int
start_checker_termination_thread(__attribute__((unused)) thread_t * thread)
{
	/* This runs in the context of a thread */
	two_phase_terminate = true;

	checker_terminate_phase1(true);

	return 0;
}

/* Daemon stop sequence */
static void
stop_check(int status)
{
	/* This runs in the main process, not in the context of a thread */
	checker_terminate_phase1(false);

	checker_terminate_phase2();

	/* unreachable */
	exit(status);
}

/* Daemon init sequence */
static void
start_check(list old_checkers_queue)
{
	init_checkers_queue();

	/* Parse configuration file */
	if (reload)
		global_data = alloc_global_data();
	check_data = alloc_check_data();
	if (!check_data)
		stop_check(KEEPALIVED_EXIT_FATAL);

	init_data(conf_file, check_init_keywords);

	if (reload)
		init_global_data(global_data);

	/* fill 'vsg' members of the virtual_server_t structure.
	 * We must do that after parsing config, because
	 * vs and vsg declarations may appear in any order,
	 * but we must do it before validate_check_config().
	 */
	link_vsg_to_vs();

	/* Post initializations */
	if (!validate_check_config()) {
		stop_check(KEEPALIVED_EXIT_CONFIG);
		return;
	}

#ifdef _MEM_CHECK_
	log_message(LOG_INFO, "Configuration is using : %zu Bytes", mem_allocated);
#endif

	/* If we are just testing the configuration, then we terminate now */
	if (__test_bit(CONFIG_TEST_BIT, &debug)) {
		stop_check(KEEPALIVED_EXIT_OK);
		return;
	}

	/* Initialize sub-system if any virtual servers are configured */
	if ((!LIST_ISEMPTY(check_data->vs) || (reload && !LIST_ISEMPTY(old_check_data->vs))) &&
	    ipvs_start() != IPVS_SUCCESS) {
		stop_check(KEEPALIVED_EXIT_FATAL);
		return;
	}

	/* Create a notify FIFO if needed, and open it */
	notify_fifo_open(&global_data->notify_fifo, &global_data->lvs_notify_fifo, lvs_notify_fifo_script_exit, "lvs_");

	/* Get current active addresses, and start update process */
	if (using_ha_suspend || __test_bit(LOG_ADDRESS_CHANGES, &debug)) {
		if (reload)
			kernel_netlink_set_recv_bufs();
		else
			kernel_netlink_init();
	}
	else if (reload)
		kernel_netlink_close();

	/* Remove any entries left over from previous invocation */
	if (!reload && global_data->lvs_flush)
		ipvs_flush_cmd();

#ifdef _WITH_SNMP_CHECKER_
	if (!reload && global_data->enable_snmp_checker)
		check_snmp_agent_init(global_data->snmp_socket);
#endif

	/* SSL load static data & initialize common ctx context */
	if (check_data->ssl_required && !init_ssl_ctx())
		stop_check(KEEPALIVED_EXIT_FATAL);

	/* Set the process priority and non swappable if configured */
	set_process_priorities(
#ifdef _HAVE_SCHED_RT_
                               global_data->checker_realtime_priority,
#if HAVE_DECL_RLIMIT_RTTIME == 1
                               global_data->checker_rlimit_rt,
#endif
#endif
			       global_data->checker_process_priority, global_data->checker_no_swap ? 4096 : 0);

	/* Processing differential configuration parsing */
	if (reload)
		clear_diff_services(old_checkers_queue);

	/* We can send SMTP messages from here so set the time */
	set_time_now();

	/* Initialize IPVS topology */
	if (!init_services())
		stop_check(KEEPALIVED_EXIT_FATAL);

	/* Dump configuration */
	if (__test_bit(DUMP_CONF_BIT, &debug)) {
		dump_global_data(NULL, global_data);
		dump_check_data(NULL, check_data);
	}

	/* Register checkers thread */
	register_checkers_thread();

	add_signal_read_thread();
}

#ifndef _DEBUG_
/* Reload thread */
static int
reload_check_thread(__attribute__((unused)) thread_t * thread)
{
	list old_checkers_queue;

	log_message(LOG_INFO, "Reloading");

	/* set the reloading flag */
	SET_RELOAD;

	log_message(LOG_INFO, "Got SIGHUP, reloading checker configuration");

	/* Terminate all script process */
	script_killall(master, SIGTERM, false);

	/* Remove the notify fifo - we don't know if it will be the same after a reload */
	notify_fifo_close(&global_data->notify_fifo, &global_data->lvs_notify_fifo);

	/* Destroy master thread */
	checker_dispatcher_release();
	thread_cleanup_master(master);

	/* Save previous checker data */
	old_checkers_queue = checkers_queue;
	checkers_queue = NULL;

	free_ssl();
	ipvs_stop();

	/* Save previous conf data */
	old_check_data = check_data;
	check_data = NULL;
	old_global_data = global_data;
	global_data = NULL;

	/* Reload the conf */
	start_check(old_checkers_queue);

	/* free backup data */
	free_check_data(old_check_data);
	free_global_data(old_global_data);
	free_list(&old_checkers_queue);
	UNSET_RELOAD;

	return 0;
}

static void
sigreload_check(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	thread_add_event(master, reload_check_thread, NULL, 0);
}

/* Terminate handler */
static void
sigend_check(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	if (master)
		thread_add_start_terminate_event(master, start_checker_termination_thread);
}

/* CHECK Child signal handling */
static void
check_signal_init(void)
{
	signal_handler_child_init();
	signal_set(SIGHUP, sigreload_check, NULL);
	signal_set(SIGINT, sigend_check, NULL);
	signal_set(SIGTERM, sigend_check, NULL);
	signal_ignore(SIGPIPE);
}

/* CHECK Child respawning thread */
static int
check_respawn_thread(thread_t * thread)
{
	pid_t pid;

	/* Fetch thread args */
	pid = THREAD_CHILD_PID(thread);

	/* Restart respawning thread */
	if (thread->type == THREAD_CHILD_TIMEOUT) {
		thread_add_child(master, check_respawn_thread, NULL,
				 pid, RESPAWN_TIMER);
		return 0;
	}

	/* We catch a SIGCHLD, handle it */
	if (!__test_bit(CONFIG_TEST_BIT, &debug))
		raise(SIGTERM);
	else if (!__test_bit(DONT_RESPAWN_BIT, &debug)) {
		log_message(LOG_ALERT, "Healthcheck child process(%d) died: Respawning", pid);
		start_check_child();
	} else {
		log_message(LOG_ALERT, "Healthcheck child process(%d) died: Exiting", pid);
		checkers_child = 0;
		raise(SIGTERM);
	}
	return 0;
}
#endif

/* Register CHECK thread */
int
start_check_child(void)
{
#ifndef _DEBUG_
	pid_t pid;
	char *syslog_ident;

	/* Initialize child process */
	if (log_file_name)
		flush_log_file();

	pid = fork();

	if (pid < 0) {
		log_message(LOG_INFO, "Healthcheck child process: fork error(%s)"
			       , strerror(errno));
		return -1;
	} else if (pid) {
		checkers_child = pid;
		log_message(LOG_INFO, "Starting Healthcheck child process, pid=%d"
			       , pid);

		/* Start respawning thread */
		thread_add_child(master, check_respawn_thread, NULL,
				 pid, RESPAWN_TIMER);

		return 0;
	}
	prctl(PR_SET_PDEATHSIG, SIGTERM);

	/* Clear any child finder functions set in parent */
	set_child_finder_name(NULL);
	destroy_child_finder();

	prog_type = PROG_TYPE_CHECKER;

#ifdef _WITH_BFD_
	/* Close the write end of the BFD checker event notification pipe */
	close(bfd_checker_event_pipe[1]);

#ifdef _WITH_VRRP_
	close(bfd_vrrp_event_pipe[0]);
	close(bfd_vrrp_event_pipe[1]);
#endif
#endif

	if ((global_data->instance_name
#if HAVE_DECL_CLONE_NEWNET
			   || global_data->network_namespace
#endif
					       ) &&
	     (check_syslog_ident = make_syslog_ident(PROG_CHECK)))
		syslog_ident = check_syslog_ident;
	else
		syslog_ident = PROG_CHECK;

	/* Opening local CHECK syslog channel */
	if (!__test_bit(NO_SYSLOG_BIT, &debug))
		openlog(syslog_ident, LOG_PID | ((__test_bit(LOG_CONSOLE_BIT, &debug)) ? LOG_CONS : 0)
				    , (log_facility==LOG_DAEMON) ? LOG_LOCAL2 : log_facility);

	if (log_file_name)
		open_log_file(log_file_name,
				"check",
#if HAVE_DECL_CLONE_NEWNET
				global_data->network_namespace,
#else
				NULL,
#endif
				global_data->instance_name);

#ifdef _MEM_CHECK_
	mem_log_init(PROG_CHECK, "Healthcheck child process");
#endif

	free_parent_mallocs_startup(true);

	/* Child process part, write pidfile */
	if (!pidfile_write(checkers_pidfile, getpid())) {
		log_message(LOG_INFO, "Healthcheck child process: cannot write pidfile");
		exit(KEEPALIVED_EXIT_FATAL);
	}

	/* Create the new master thread */
	signal_handler_destroy();
	thread_destroy_master(master);	/* This destroys any residual settings from the parent */
	master = thread_make_master();
#endif

	/* If last process died during a reload, we can get there and we
	 * don't want to loop again, because we're not reloading anymore.
	 */
	UNSET_RELOAD;

#ifndef _DEBUG_
	/* Signal handling initialization */
	check_signal_init();
#endif

	/* Start Healthcheck daemon */
	start_check(NULL);

#ifdef _DEBUG_
	return 0;
#endif

	/* Launch the scheduling I/O multiplexer */
	launch_scheduler();

	/* Finish healthchecker daemon process */
	if (two_phase_terminate)
		checker_terminate_phase2();
	else
		stop_check(KEEPALIVED_EXIT_OK);

	/* unreachable */
	exit(KEEPALIVED_EXIT_OK);
}

#ifdef _TIMER_DEBUG_
void
print_check_daemon_addresses(void)
{
	log_message(LOG_INFO, "Address of check_respawn_thread() is 0x%p", check_respawn_thread);
	log_message(LOG_INFO, "Address of reload_check_thread() is 0x%p", reload_check_thread);
}
#endif
