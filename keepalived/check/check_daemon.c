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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <string.h>

#include "check_daemon.h"
#include "check_parser.h"
#include "ipwrapper.h"
#include "ipvswrapper.h"
#include "check_data.h"
#include "check_ssl.h"
#include "check_api.h"
#include "global_data.h"
#include "pidfile.h"
#include "daemon.h"
#include "signals.h"
#include "notify.h"
#include "process.h"
#include "logger.h"
#include "list.h"
#include "main.h"
#include "memory.h"
#include "parser.h"
#include "bitops.h"
#include "vrrp_netlink.h"
#include "vrrp_if.h"
#ifdef _WITH_SNMP_CHECKER_
  #include "check_snmp.h"
#endif

static char *check_syslog_ident;

/* Daemon stop sequence */
static void
stop_check(int status)
{
	/* Terminate all script process */
	script_killall(master, SIGTERM);

	/* Destroy master thread */
	signal_handler_destroy();
	thread_destroy_master(master);
	free_checkers_queue();
	free_ssl();
	if (!__test_bit(DONT_RELEASE_IPVS_BIT, &debug))
		clear_services();
	ipvs_stop();
#ifdef _WITH_SNMP_CHECKER_
	if (global_data->enable_snmp_checker)
		check_snmp_agent_close();
#endif

	/* Stop daemon */
	pidfile_rm(checkers_pidfile);

	/* Clean data */
	free_global_data(global_data);
	free_check_data(check_data);
#ifdef _WITH_VRRP_
	free_interface_queue();
#endif
	free_parent_mallocs_exit();

	/*
	 * Reached when terminate signal catched.
	 * finally return to parent process.
	 */
	log_message(LOG_INFO, "Stopped");

	closelog();

#ifndef _MEM_CHECK_LOG_
	FREE_PTR(check_syslog_ident);
#else
	if (check_syslog_ident)
		free(check_syslog_ident);
#endif

	exit(status);
}

/* Daemon init sequence */
static void
start_check(void)
{
	/* Initialize sub-system */
	if (ipvs_start() != IPVS_SUCCESS) {
		stop_check(KEEPALIVED_EXIT_FATAL);
		return;
	}

	init_checkers_queue();
#ifdef _WITH_VRRP_
	init_interface_queue();
	kernel_netlink_init();
#endif

	/* Parse configuration file */
	global_data = alloc_global_data();
	check_data = alloc_check_data();
	if (!check_data)
		stop_check(KEEPALIVED_EXIT_FATAL);

	init_data(conf_file, check_init_keywords);

	init_global_data(global_data);

	/* Post initializations */
	if (!validate_check_config()) {
		stop_check(KEEPALIVED_EXIT_CONFIG);
		return;
	}

#ifdef _MEM_CHECK_
	log_message(LOG_INFO, "Configuration is using : %zu Bytes", mem_allocated);
#endif

	/* Remove any entries left over from previous invocation */
	if (!reload && global_data->lvs_flush)
		ipvs_flush_cmd();

#ifdef _WITH_SNMP_CHECKER_
	if (!reload && global_data->enable_snmp_checker)
		check_snmp_agent_init(global_data->snmp_socket);
#endif

	/* SSL load static data & initialize common ctx context */
	if (!init_ssl_ctx())
		stop_check(KEEPALIVED_EXIT_FATAL);

	/* fill 'vsg' members of the virtual_server_t structure.
	 * We must do that after parsing config, because
	 * vs and vsg declarations may appear in any order
	 */
	link_vsg_to_vs();

	/* Set the process priority and non swappable if configured */
	if (global_data->checker_process_priority)
		set_process_priority(global_data->checker_process_priority);

	if (global_data->checker_no_swap)
		set_process_dont_swap(4096);	/* guess a stack size to reserve */

	/* Processing differential configuration parsing */
	if (reload)
		clear_diff_services();

	/* Initialize IPVS topology */
	if (!init_services())
		stop_check(KEEPALIVED_EXIT_FATAL);

	/* Dump configuration */
	if (__test_bit(DUMP_CONF_BIT, &debug)) {
		dump_global_data(global_data);
		dump_check_data(check_data);
	}

#ifdef _WITH_VRRP_
	/* Initialize linkbeat */
	init_interface_linkbeat();
#endif

	/* Register checkers thread */
	register_checkers_thread();
}

/* Reload handler */
static int reload_check_thread(thread_t *);

static void
sighup_check(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	thread_add_event(master, reload_check_thread, NULL, 0);
}

/* Terminate handler */
static void
sigend_check(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	if (master)
		thread_add_terminate_event(master);
}

/* CHECK Child signal handling */
static void
check_signal_init(void)
{
	signal_handler_init(0);
	signal_set(SIGHUP, sighup_check, NULL);
	signal_set(SIGINT, sigend_check, NULL);
	signal_set(SIGTERM, sigend_check, NULL);
	signal_ignore(SIGPIPE);
}

/* Reload thread */
static int
reload_check_thread(__attribute__((unused)) thread_t * thread)
{
	/* set the reloading flag */
	SET_RELOAD;

	log_message(LOG_INFO, "Got SIGHUP, reloading checker configuration");

	/* Terminate all script process */
	script_killall(master, SIGTERM);

	/* Destroy master thread */
#ifdef _WITH_VRRP_
	kernel_netlink_close();
#endif
	thread_cleanup_master(master);
	free_global_data(global_data);

	free_checkers_queue();
#ifdef _WITH_VRRP_
	free_interface_queue();
#endif
	free_ssl();
	ipvs_stop();

	/* Save previous conf data */
	old_check_data = check_data;
	check_data = NULL;

	/* Reload the conf */
	start_check();

	/* free backup data */
	free_check_data(old_check_data);
	UNSET_RELOAD;

	return 0;
}

/* CHECK Child respawning thread */
#ifndef _DEBUG_
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
	if (!__test_bit(DONT_RESPAWN_BIT, &debug)) {
		log_message(LOG_ALERT, "Healthcheck child process(%d) died: Respawning", pid);
		start_check_child();
	} else {
		log_message(LOG_ALERT, "Healthcheck child process(%d) died: Exiting", pid);
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

	if ((instance_name
#if HAVE_DECL_CLONE_NEWNET
			   || network_namespace
#endif
					       ) &&
	     (check_syslog_ident = make_syslog_ident(PROG_CHECK)))
		syslog_ident = check_syslog_ident;
	else
		syslog_ident = PROG_CHECK;

	/* Opening local CHECK syslog channel */
	openlog(syslog_ident, LOG_PID | ((__test_bit(LOG_CONSOLE_BIT, &debug)) ? LOG_CONS : 0)
			    , (log_facility==LOG_DAEMON) ? LOG_LOCAL2 : log_facility);

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

	/* Signal handling initialization */
	check_signal_init();

	/* Start Healthcheck daemon */
	start_check();

	/* Launch the scheduling I/O multiplexer */
	launch_scheduler();

	/* Finish healthchecker daemon process */
	stop_check(EXIT_SUCCESS);

	/* unreachable */
	exit(EXIT_SUCCESS);
}
