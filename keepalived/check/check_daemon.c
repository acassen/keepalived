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

#include <sched.h>
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
#include "check_udp.h"
#endif
#include "check_daemon.h"
#include "check_parser.h"
#include "ipwrapper.h"
#include "check_ssl.h"
#include "check_api.h"
#include "check_ping.h"
#include "check_file.h"
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
#include "track_file.h"
#ifdef _WITH_TRACK_PROCESS_
#include "track_process.h"
#endif
#ifdef _USE_SYSTEMD_NOTIFY_
#include "systemd.h"
#endif
#ifndef _ONE_PROCESS_DEBUG_
#include "config_notify.h"
#endif

/* Global variables */
bool using_ha_suspend;

/* local variables */
static const char *check_syslog_ident;
#ifndef _ONE_PROCESS_DEBUG_
static bool two_phase_terminate;
static timeval_t check_start_time;
static unsigned check_next_restart_delay;
#endif

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
	 *   15 memfd for config
	 *   16 eventfd for notifying load/reload complete
	 *   One per checker using UDP/TCP/PING
	 *   One per SMTP alert
	 *   qty 10 spare
	 */
	set_max_file_limit(17 + check_data->num_checker_fd_required + check_data->num_smtp_alert + 10);
}

static void
lvs_notify_fifo_script_exit(__attribute__((unused)) thread_ref_t thread)
{
	log_message(LOG_INFO, "lvs notify fifo script terminated");
}

static void
checker_dispatcher_release(void)
{
#ifdef _WITH_BFD_
	checker_bfd_dispatcher_release();
#endif
	cancel_signal_read_thread();
	cancel_kernel_netlink_threads();
}

static bool
checker_ipvs_syncd_needed(void)
{
#ifdef _WITH_VRRP_
	if (global_data->lvs_syncd.vrrp_name)
		return false;
#endif

        return !!global_data->lvs_syncd.ifname;
}

/* Daemon stop sequence */
static int
checker_terminate_phase2(void)
{
	struct rusage usage;

	/* Remove the notify fifo */
	notify_fifo_close(&global_data->notify_fifo, &global_data->lvs_notify_fifo);

#ifdef _WITH_SNMP_CHECKER_
	if (global_data && global_data->enable_snmp_checker)
		check_snmp_agent_close();
#endif

	/* Destroy master thread */
	checker_dispatcher_release();
	thread_destroy_master(master);
	master = NULL;
	free_checkers_queue();
	free_ssl();
	set_ping_group_range(false);

	/* If we are running both master and backup, stop them now */
	if (checker_ipvs_syncd_needed()) {
		ipvs_syncd_cmd(IPVS_STOPDAEMON, NULL, IPVS_MASTER, true);
		ipvs_syncd_cmd(IPVS_STOPDAEMON, NULL, IPVS_BACKUP, true);
	}
	ipvs_stop();

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
		free(no_const_char_p(check_syslog_ident));	/* malloc'd by make_syslog_ident() */
#endif
	close_std_fd();

	return 0;
}

static void
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
}

static void
checker_terminate_phase1(bool schedule_next_thread)
{
	if (using_ha_suspend || __test_bit(LOG_ADDRESS_CHANGES, &debug))
		kernel_netlink_close();

	/* Terminate all script processes */
	if (master->child.rb_root.rb_node)
		script_killall(master, SIGTERM, true);

	/* Stop monitoring files */
	if (!list_empty(&check_data->track_files))
		stop_track_files();

	/* Send shutdown messages */
	if (!__test_bit(DONT_RELEASE_IPVS_BIT, &debug))
		clear_services();

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

#ifndef _ONE_PROCESS_DEBUG_
static void
start_checker_termination_thread(__attribute__((unused)) thread_ref_t thread)
{
	/* This runs in the context of a thread */
	two_phase_terminate = true;

	checker_terminate_phase1(true);
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

static void
set_effective_weights(void)
{
	virtual_server_t *vs;
	real_server_t *rs;
	checker_t *checker;

	list_for_each_entry(vs, &check_data->vs, e_list) {
		list_for_each_entry(rs, &vs->rs, e_list) {
			rs->effective_weight = rs->iweight;
		}
        }

	list_for_each_entry(checker, &checkers_queue, e_list) {
		checker->rs->effective_weight += checker->cur_weight;
	}
}

/* Daemon init sequence */
static void
start_check(list_head_t *old_checkers_queue, data_t *prev_global_data)
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

	init_data(conf_file, check_init_keywords, false);

#ifndef _ONE_PROCESS_DEBUG_
	/* Notify parent config has been read if appropriate */
	if (!__test_bit(CONFIG_TEST_BIT, &debug))
		notify_config_read();
#endif

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
	if (!validate_check_config()
#ifndef _ONE_PROCESS_DEBUG_
	    || (global_data->reload_check_config && get_config_status() != CONFIG_OK)
#endif
				    ) {
		stop_check(KEEPALIVED_EXIT_CONFIG);
		return;
	}

	/* If we are just testing the configuration, then we terminate now */
	if (__test_bit(CONFIG_TEST_BIT, &debug))
		return;

	/* Initialize sub-system if any virtual servers are configured */
	if ((!list_empty(&check_data->vs) || (reload && !list_empty(&old_check_data->vs))) &&
	    ipvs_start() != IPVS_SUCCESS) {
		stop_check(KEEPALIVED_EXIT_FATAL);
		return;
	}

	/* Set LVS timeouts */
	if (global_data->lvs_timeouts.tcp_timeout ||
	    global_data->lvs_timeouts.tcp_fin_timeout ||
	    global_data->lvs_timeouts.udp_timeout)
		ipvs_set_timeouts(&global_data->lvs_timeouts);
	else if (reload)
		ipvs_set_timeouts(NULL);

	/* If we are managing the sync daemon, then stop any
	 * instances of it that may have been running if
	 * we terminated abnormally */
	if (checker_ipvs_syncd_needed() &&
	    (!reload ||
	     ipvs_syncd_changed(&prev_global_data->lvs_syncd, &global_data->lvs_syncd))) {
		ipvs_syncd_cmd(IPVS_STOPDAEMON, NULL, IPVS_MASTER, true);
		ipvs_syncd_cmd(IPVS_STOPDAEMON, NULL, IPVS_BACKUP, true);
	}

	if (checker_ipvs_syncd_needed()) {
		/* If we are running both master and backup, start them now */
		if (global_data->lvs_syncd.syncid == PARAMETER_UNSET)
			global_data->lvs_syncd.syncid = 0;

		ipvs_syncd_cmd(IPVS_STARTDAEMON, &global_data->lvs_syncd, IPVS_MASTER_BACKUP, false);
	}

	/* Ensure we can open sufficient file descriptors */
	set_checker_max_fds();

	/* Create a notify FIFO if needed, and open it */
	notify_fifo_open(&global_data->notify_fifo, &global_data->lvs_notify_fifo, lvs_notify_fifo_script_exit, "lvs_");

	/* Get current active addresses, and start update process */
	if (using_ha_suspend || __test_bit(LOG_ADDRESS_CHANGES, &debug)) {
		if (reload)
			kernel_netlink_set_recv_bufs();
		kernel_netlink_init();
	}
	else if (reload)
		kernel_netlink_close();

	/* Remove any entries left over from previous invocation */
	if (!reload && global_data->lvs_flush)
		ipvs_flush_cmd();

#ifdef _WITH_SNMP_CHECKER_
	if (global_data->enable_snmp_checker) {
		if (reload)
			snmp_epoll_info(master);
		else
			check_snmp_agent_init(global_data->snmp_socket);
	}
#endif

	/* SSL load static data & initialize common ctx context */
	if (check_data->ssl_required && !init_ssl_ctx())
		stop_check(KEEPALIVED_EXIT_FATAL);

	/* We can send SMTP messages from here so set the time */
	set_time_now();

	/* Set up the track files */
	add_rs_to_track_files();
	init_track_files(&check_data->track_files);

	/* Processing differential configuration parsing */
	set_track_file_weights();
	if (reload)
		clear_diff_services(old_checkers_queue);
	set_track_file_checkers_down();
	set_effective_weights();
	if (reload)
		check_new_rs_state();

	/* Initialize IPVS topology */
	if (!init_services())
		stop_check(KEEPALIVED_EXIT_FATAL);

	/* Dump configuration */
	if (__test_bit(DUMP_CONF_BIT, &debug))
		dump_data_check(NULL);

	/* Register checkers thread */
	register_checkers_thread();

	/* Set the process priority and non swappable if configured */
	set_process_priorities(global_data->checker_realtime_priority, global_data->max_auto_priority, global_data->min_auto_priority_delay,
			       global_data->checker_rlimit_rt, global_data->checker_process_priority, global_data->checker_no_swap ? 4096 : 0);

	/* Set the process cpu affinity if configured */
	set_process_cpu_affinity(&global_data->checker_cpu_mask, "checker");
}

void
check_validate_config(void)
{
	start_check(NULL, NULL);
}

#ifndef _ONE_PROCESS_DEBUG_
/* Reload thread */
static void
reload_check_thread(__attribute__((unused)) thread_ref_t thread)
{
	list_head_t old_checkers_queue;
	bool with_snmp = false;

	log_message(LOG_INFO, "Reloading");

	/* Use standard scheduling while reloading */
	reset_process_priorities();

	reinitialise_global_vars();

	/* set the reloading flag */
	SET_RELOAD;

	/* Terminate all script process */
	script_killall(master, SIGTERM, false);

	if (!list_empty(&check_data->track_files))
		stop_track_files();

	/* Remove the notify fifo - we don't know if it will be the same after a reload */
	notify_fifo_close(&global_data->notify_fifo, &global_data->lvs_notify_fifo);

#if !defined _ONE_PROCESS_DEBUG_ && defined _WITH_SNMP_CHECKER_
	if (prog_type == PROG_TYPE_CHECKER && global_data->enable_snmp_checker)
		with_snmp = true;
#endif

	/* Destroy master thread */
	checker_dispatcher_release();
	thread_cleanup_master(master);
	thread_add_base_threads(master, with_snmp);

	/* Save previous checker data */
	list_copy(&old_checkers_queue, &checkers_queue);
	init_checkers_queue();

	free_ssl();
	ipvs_stop();

	/* Save previous conf data */
	old_check_data = check_data;
	check_data = NULL;
	old_global_data = global_data;
	global_data = NULL;

	/* Reload the conf */
	start_check(&old_checkers_queue, old_global_data);

	/* free backup data */
	free_check_data(old_check_data);
	free_global_data(old_global_data);
	free_checker_list(&old_checkers_queue);
	UNSET_RELOAD;

#ifdef _MEM_CHECK_
	log_message(LOG_INFO, "Configuration is using : %zu Bytes", mem_allocated);
#endif
}

static void
print_check_data(__attribute__((unused)) thread_ref_t thread)
{
	check_print_data();
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
#ifdef THREAD_DUMP
	signal_set(SIGTDUMP, thread_dump_signal, NULL);
#endif
	signal_ignore(SIGPIPE);
}

/* This function runs in the parent process. */
static void
delayed_restart_check_child_thread(__attribute__((unused)) thread_ref_t thread)
{
	start_check_child();
}

/* CHECK Child respawning thread. This function runs in the parent process. */
static void
check_respawn_thread(thread_ref_t thread)
{
	unsigned restart_delay;

	/* We catch a SIGCHLD, handle it */
	checkers_child = 0;

	if (report_child_status(thread->u.c.status, thread->u.c.pid, NULL))
		thread_add_terminate_event(thread->master);
	else if (!__test_bit(DONT_RESPAWN_BIT, &debug)) {
		log_child_died("Healthcheck", thread->u.c.pid);

		restart_delay = calc_restart_delay(&check_start_time, &check_next_restart_delay, "Healthcheck");
		if (!restart_delay)
			start_check_child();
		else
			thread_add_timer(thread->master, delayed_restart_check_child_thread, NULL, restart_delay * TIMER_HZ);
	} else {
		log_message(LOG_ALERT, "Healthcheck child process(%d) died: Exiting", thread->u.c.pid);
		raise(SIGTERM);
	}
}
#endif

#ifdef THREAD_DUMP
static void
register_check_thread_addresses(void)
{
	/* Remove anything we might have inherited from parent */
	deregister_thread_addresses();

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
	register_check_ping_addresses();
	register_check_udp_addresses();
	register_check_file_addresses();
#ifdef _WITH_BFD_
	register_check_bfd_addresses();
#endif

#ifndef _ONE_PROCESS_DEBUG_
	register_thread_address("reload_check_thread", reload_check_thread);
	register_thread_address("start_checker_termination_thread", start_checker_termination_thread);
#endif
	register_thread_address("lvs_notify_fifo_script_exit", lvs_notify_fifo_script_exit);
	register_thread_address("checker_shutdown_backstop_thread", checker_shutdown_backstop_thread);

#ifndef _ONE_PROCESS_DEBUG_
	register_signal_handler_address("sigreload_check", sigreload_check);
	register_signal_handler_address("sigend_check", sigend_check);
#endif
}
#endif

/* Register CHECK thread */
int
start_check_child(void)
{
#ifndef _ONE_PROCESS_DEBUG_
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
		check_start_time = time_now;

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
#ifdef _WITH_TRACK_PROCESS_
	close_track_processes();
#endif

	if ((global_data->instance_name || global_data->network_namespace) &&
	     (check_syslog_ident = make_syslog_ident(PROG_CHECK)))
		syslog_ident = check_syslog_ident;
	else
		syslog_ident = PROG_CHECK;

	/* Opening local CHECK syslog channel */
	if (!__test_bit(NO_SYSLOG_BIT, &debug))
		open_syslog(syslog_ident);

#ifdef ENABLE_LOG_TO_FILE
	if (log_file_name)
		open_log_file(log_file_name,
				"check",
				global_data->network_namespace,
				global_data->instance_name);
#endif

#ifdef _MEM_CHECK_
	mem_log_init(PROG_CHECK, "Healthcheck child process");
#endif

	free_parent_mallocs_startup(true);

	/* Clear any child finder functions set in parent */
	set_child_finder_name(NULL);

	/* Create an independant file descriptor for the shared config file */
	separate_config_file();

	/* Child process part, write pidfile */
	if (!pidfile_write(checkers_pidfile, getpid())) {
		log_message(LOG_INFO, "Healthcheck child process: cannot write pidfile");
		exit(KEEPALIVED_EXIT_FATAL);
	}

#ifdef _USE_SYSTEMD_NOTIFY_
	systemd_unset_notify();
#endif

	/* Create the new master thread */
	thread_destroy_master(master);	/* This destroys any residual settings from the parent */
	master = thread_make_master();
#endif

	/* If last process died during a reload, we can get there and we
	 * don't want to loop again, because we're not reloading anymore.
	 */
	UNSET_RELOAD;

#ifndef _ONE_PROCESS_DEBUG_
	/* Signal handling initialization */
	check_signal_init();

	/* Register emergency shutdown function */
	register_shutdown_function(stop_check);
#endif

	/* Start Healthcheck daemon */
	start_check(NULL, NULL);

#ifdef _ONE_PROCESS_DEBUG_
	return 0;
#endif

#ifdef THREAD_DUMP
	register_check_thread_addresses();
#endif

#ifdef _MEM_CHECK_
	log_message(LOG_INFO, "Configuration is using : %zu Bytes", mem_allocated);
#endif

	/* Launch the scheduling I/O multiplexer */
	launch_thread_scheduler(master);

	/* Finish healthchecker daemon process */
#ifndef _ONE_PROCESS_DEBUG_
	if (two_phase_terminate)
		checker_terminate_phase2();
	else
#endif
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
#ifndef _ONE_PROCESS_DEBUG_
	register_thread_address("print_check_data", print_check_data);
	register_thread_address("check_respawn_thread", check_respawn_thread);
	register_thread_address("delayed_restart_check_child_thread", delayed_restart_check_child_thread);
#endif
}
#endif
