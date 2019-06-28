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
#include <sys/time.h>
#include <sys/resource.h>

#ifdef THREAD_DUMP
#ifdef _WITH_SNMP_
#include "snmp.h"
#endif
#include "scheduler.h"
#include "smtp.h"
#include "check_dns.h"
#include "check_http.h"
#include "check_misc.h"
#include "check_smtp.h"
#include "check_tcp.h"
#endif
#include "check_daemon.h"
#include "check_parser.h"
#include "ipwrapper.h"
#include "check_ssl.h"
#include "check_api.h"
#include "global_data.h"
#include "pidfile.h"
#include "signals.h"
#include "process.h"
#include "memory.h"
#include "logger.h"
#include "main.h"
#include "parser.h"
#include "bitops.h"
#include "keepalived_netlink.h"
#include "check_print.h"
#ifdef _WITH_SNMP_CHECKER_
  #include "check_snmp.h"
#endif
#include "utils.h"
#ifdef _WITH_BFD_
#include "bfd_daemon.h"
#include "check_bfd.h"
#endif
#include "timer.h"
#ifdef _WITH_CN_PROC_
#include "track_process.h"
#endif

/* Global variables */
bool using_ha_suspend;

/* local variables */
static const char *check_syslog_ident;
static bool two_phase_terminate;

/* set fd ulimits  */
static void
set_checker_max_fds(void)
{
	/* Allow for:
	 *   0	stdin
	 *   1	stdout
	 *   2	strerr
	 *   3	memcheck log (debugging)
	 *   4	log file
	 *   5	epoll
	 *   6	timerfd
	 *   7	signalfd
	 *   8	bfd pipe
	 *   9	closed
	 *   10	closed
	 *   11	FIFO
	 *   12	closed
	 *   13	passwd file
	 *   14	Unix domain socket
	 *   One per checker using UDP/TCP
	 *   One per SMTP alert
	 *   qty 10 spare
	 */
	set_max_file_limit(14 + check_data->num_checker_fd_required + check_data->num_smtp_alert + 10);
}

static int
lvs_notify_fifo_script_exit(__attribute__((unused)) thread_ref_t thread)
{
	log_message(LOG_INFO, "lvs notify fifo script terminated");

	return 0;
}

static void
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
	struct rusage usage;

	/* Remove the notify fifo */
	notify_fifo_close(&global_data->notify_fifo, &global_data->lvs_notify_fifo);

	/* Destroy master thread */
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
	if (__test_bit(LOG_DETAIL_BIT, &debug)) {
		getrusage(RUSAGE_SELF, &usage);
		log_message(LOG_INFO, "Stopped - used %ld.%6.6ld user time, %ld.%6.6ld system time", usage.ru_utime.tv_sec, usage.ru_utime.tv_usec, usage.ru_stime.tv_sec, usage.ru_stime.tv_usec);
	}
	else
		log_message(LOG_INFO, "Stopped");

#ifdef ENABLE_LOG_TO_FILE
	if (log_file_name)
		close_log_file();
#endif
	closelog();

#ifndef _MEM_CHECK_LOG_
	FREE_CONST_PTR(check_syslog_ident);
#else
	if (check_syslog_ident)
		free(no_const_char_p(check_syslog_ident));
#endif
	close_std_fd();

	return 0;
}

static int
checker_shutdown_backstop_thread(thread_ref_t thread)
{
	int count = 0;
	thread_ref_t t;

	/* Force terminate all script processes */
	if (thread->master->child.rb_root.rb_node)
		script_killall(thread->master, SIGKILL, true);

	rb_for_each_entry_cached_const(t, &thread->master->child, n)
		count++;

	log_message(LOG_ERR, "backstop thread invoked: shutdown timer %srunning, child count %d",
			thread->master->shutdown_timer_running ? "" : "not ", count);

	if (thread->master->shutdown_timer_running)
		thread_add_timer_shutdown(thread->master, checker_shutdown_backstop_thread, NULL, TIMER_HZ / 10);
	else
		thread_add_terminate_event(thread->master);

	return 0;
}

static void
checker_terminate_phase1(bool schedule_next_thread)
{
	if (using_ha_suspend || __test_bit(LOG_ADDRESS_CHANGES, &debug))
		kernel_netlink_close();

	/* Terminate all script processes */
	if (master->child.rb_root.rb_node)
		script_killall(master, SIGTERM, true);

	/* Send shutdown messages */
	if (!__test_bit(DONT_RELEASE_IPVS_BIT, &debug)) {
		if (global_data->lvs_flush_onstop == LVS_FLUSH_FULL) {
			log_message(LOG_INFO, "Flushing lvs on shutdown in oneshot");
			ipvs_flush_cmd();
		} else
			clear_services();
	}

	if (schedule_next_thread) {
		/* If there are no child processes, we can terminate immediately,
		 * otherwise add a thread to allow reasonable time for children to terminate */
		if (master->child.rb_root.rb_node) {
			/* Add a backstop timer for the shutdown */
			thread_add_timer_shutdown(master, checker_shutdown_backstop_thread, NULL, TIMER_HZ);
		}
		else
			thread_add_terminate_event(master);
	}
}

#ifndef _DEBUG_
static int
start_checker_termination_thread(__attribute__((unused)) thread_ref_t thread)
{
	/* This runs in the context of a thread */
	two_phase_terminate = true;

	checker_terminate_phase1(true);

	return 0;
}
#endif

/* Daemon stop sequence */
static void
stop_check(int status)
{
	if (__test_bit(CONFIG_TEST_BIT, &debug))
		return;

	/* This runs in the main process, not in the context of a thread */
	checker_terminate_phase1(false);

	checker_terminate_phase2();

	/* unreachable */
	exit(status);
}

/* Daemon init sequence */
static void
start_check(list old_checkers_queue, data_t *prev_global_data)
{
	init_checkers_queue();

	/* Parse configuration file */
	if (reload)
		global_data = alloc_global_data();
	check_data = alloc_check_data();
	if (!check_data) {
		stop_check(KEEPALIVED_EXIT_FATAL);
		return;
	}

	init_data(conf_file, check_init_keywords);

	if (reload)
		init_global_data(global_data, prev_global_data, true);

	/* Update process name if necessary */
	if ((!reload && global_data->lvs_process_name) ||
	    (reload &&
	     (!global_data->lvs_process_name != !prev_global_data->lvs_process_name ||
	      (global_data->lvs_process_name && strcmp(global_data->lvs_process_name, prev_global_data->lvs_process_name)))))
		set_process_name(global_data->lvs_process_name);

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
	if (__test_bit(CONFIG_TEST_BIT, &debug))
		return;

	/* Initialize sub-system if any virtual servers are configured */
	if ((!LIST_ISEMPTY(check_data->vs) || (reload && !LIST_ISEMPTY(old_check_data->vs))) &&
	    ipvs_start() != IPVS_SUCCESS) {
		stop_check(KEEPALIVED_EXIT_FATAL);
		return;
	}

	/* Ensure we can open sufficient file descriptors */
	set_checker_max_fds();

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

	/* Processing differential configuration parsing */
	if (reload) {
		clear_diff_services(old_checkers_queue);
		check_new_rs_state();
	}

	/* We can send SMTP messages from here so set the time */
	set_time_now();

	/* Initialize IPVS topology */
	if (!init_services())
		stop_check(KEEPALIVED_EXIT_FATAL);

	/* Dump configuration */
	if (__test_bit(DUMP_CONF_BIT, &debug))
		dump_data_check(NULL);

	/* Register checkers thread */
	register_checkers_thread();

	/* Set the process priority and non swappable if configured */
	set_process_priorities(
#ifdef _HAVE_SCHED_RT_
			       global_data->checker_realtime_priority,
#if HAVE_DECL_RLIMIT_RTTIME == 1
			       global_data->checker_rlimit_rt,
#endif
#endif
			       global_data->checker_process_priority, global_data->checker_no_swap ? 4096 : 0);

#ifdef _HAVE_SCHED_RT_
	/* Set the process cpu affinity if configured */
	set_process_cpu_affinity(&global_data->checker_cpu_mask, "checker");
#endif
}

void
check_validate_config(void)
{
	start_check(NULL, NULL);
}

#ifndef _DEBUG_
/* Reload thread */
static int
reload_check_thread(__attribute__((unused)) thread_ref_t thread)
{
	list old_checkers_queue;
	bool with_snmp = false;

	log_message(LOG_INFO, "Reloading");

	/* Use standard scheduling while reloading */
	reset_process_priorities();

	/* set the reloading flag */
	SET_RELOAD;

	log_message(LOG_INFO, "Got SIGHUP, reloading checker configuration");

	/* Terminate all script process */
	script_killall(master, SIGTERM, false);

	/* Remove the notify fifo - we don't know if it will be the same after a reload */
	notify_fifo_close(&global_data->notify_fifo, &global_data->lvs_notify_fifo);

#if !defined _DEBUG_ && defined _WITH_SNMP_CHECKER_
	if (prog_type == PROG_TYPE_CHECKER && global_data->enable_snmp_checker)
		with_snmp = true;
#endif

	/* Destroy master thread */
	checker_dispatcher_release();
	thread_cleanup_master(master);
	thread_add_base_threads(master, with_snmp);

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
	start_check(old_checkers_queue, old_global_data);

	/* free backup data */
	free_check_data(old_check_data);
	free_global_data(old_global_data);
	free_list(&old_checkers_queue);
	UNSET_RELOAD;

	return 0;
}

static int
print_check_data(__attribute__((unused)) thread_ref_t thread)
{
        check_print_data();
        return 0;
}

static void
sigusr1_check(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	log_message(LOG_INFO, "Printing checker data for process(%d) on signal",
		    getpid());
	thread_add_event(master, print_check_data, NULL, 0);
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
	signal_set(SIGHUP, sigreload_check, NULL);
	signal_set(SIGINT, sigend_check, NULL);
	signal_set(SIGTERM, sigend_check, NULL);
	signal_set(SIGUSR1, sigusr1_check, NULL);
	signal_ignore(SIGPIPE);
}

/* CHECK Child respawning thread */
static int
check_respawn_thread(thread_ref_t thread)
{
	/* We catch a SIGCHLD, handle it */
	checkers_child = 0;

	if (!__test_bit(DONT_RESPAWN_BIT, &debug)) {
		log_message(LOG_ALERT, "Healthcheck child process(%d) died: Respawning", thread->u.c.pid);
		start_check_child();
	} else {
		log_message(LOG_ALERT, "Healthcheck child process(%d) died: Exiting", thread->u.c.pid);
		raise(SIGTERM);
	}
	return 0;
}
#endif

#ifdef THREAD_DUMP
static void
register_check_thread_addresses(void)
{
	register_scheduler_addresses();
	register_signal_thread_addresses();
	register_notify_addresses();

	register_smtp_addresses();
	register_keepalived_netlink_addresses();
#ifdef _WITH_SNMP_
	register_snmp_addresses();
#endif

	register_check_dns_addresses();
	register_check_http_addresses();
	register_check_misc_addresses();
	register_check_smtp_addresses();
	register_check_ssl_addresses();
	register_check_tcp_addresses();
#ifdef _WITH_BFD_
	register_check_bfd_addresses();
#endif

#ifndef _DEBUG_
	register_thread_address("reload_check_thread", reload_check_thread);
	register_thread_address("start_checker_termination_thread", start_checker_termination_thread);
#endif
	register_thread_address("lvs_notify_fifo_script_exit", lvs_notify_fifo_script_exit);
	register_thread_address("checker_shutdown_backstop_thread", checker_shutdown_backstop_thread);

#ifndef _DEBUG_
	register_signal_handler_address("sigreload_check", sigreload_check);
	register_signal_handler_address("sigend_check", sigend_check);
#endif
}
#endif

/* Register CHECK thread */
int
start_check_child(void)
{
#ifndef _DEBUG_
	pid_t pid;
	const char *syslog_ident;

	/* Initialize child process */
#ifdef ENABLE_LOG_TO_FILE
	if (log_file_name)
		flush_log_file();
#endif

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
				 pid, TIMER_NEVER);

		return 0;
	}
	prctl(PR_SET_PDEATHSIG, SIGTERM);

	prog_type = PROG_TYPE_CHECKER;

	initialise_debug_options();

#ifdef _WITH_BFD_
	/* Close the write end of the BFD checker event notification pipe and the track_process fd */
	close(bfd_checker_event_pipe[1]);

#ifdef _WITH_VRRP_
	close(bfd_vrrp_event_pipe[0]);
	close(bfd_vrrp_event_pipe[1]);
#endif
#endif
#ifdef _WITH_CN_PROC_
	close_track_processes();
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

#ifdef ENABLE_LOG_TO_FILE
	if (log_file_name)
		open_log_file(log_file_name,
				"check",
#if HAVE_DECL_CLONE_NEWNET
				global_data->network_namespace,
#else
				NULL,
#endif
				global_data->instance_name);
#endif

#ifdef _MEM_CHECK_
	mem_log_init(PROG_CHECK, "Healthcheck child process");
#endif

	free_parent_mallocs_startup(true);

	/* Clear any child finder functions set in parent */
	set_child_finder_name(NULL);

	/* Child process part, write pidfile */
	if (!pidfile_write(checkers_pidfile, getpid())) {
		log_message(LOG_INFO, "Healthcheck child process: cannot write pidfile");
		exit(KEEPALIVED_EXIT_FATAL);
	}

	/* Create the new master thread */
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
	start_check(NULL, NULL);

#ifdef _DEBUG_
	return 0;
#endif

#ifdef THREAD_DUMP
	register_check_thread_addresses();
#endif

	/* Launch the scheduling I/O multiplexer */
	launch_thread_scheduler(master);

	/* Finish healthchecker daemon process */
	if (two_phase_terminate)
		checker_terminate_phase2();
	else
		stop_check(KEEPALIVED_EXIT_OK);

#ifdef THREAD_DUMP
	deregister_thread_addresses();
#endif

	/* unreachable */
	exit(KEEPALIVED_EXIT_OK);
}

#ifdef THREAD_DUMP
void
register_check_parent_addresses(void)
{
#ifndef _DEBUG_
	register_thread_address("print_check_data", print_check_data);
	register_thread_address("check_respawn_thread", check_respawn_thread);
#endif
}
#endif
