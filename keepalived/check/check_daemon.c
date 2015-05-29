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

#include "check_daemon.h"
#include "check_parser.h"
#include "ipwrapper.h"
#include "ipvswrapper.h"
#include "check_data.h"
#include "check_ssl.h"
#include "check_api.h"
#include "global_data.h"
#include "ipwrapper.h"
#include "ipvswrapper.h"
#include "pidfile.h"
#include "daemon.h"
#include "signals.h"
#include "logger.h"
#include "list.h"
#include "main.h"
#include "memory.h"
#include "parser.h"
#include "bitops.h"
#include "vrrp_netlink.h"
#include "vrrp_if.h"
#ifdef _WITH_SNMP_
  #include "check_snmp.h"
#endif

extern char *checkers_pidfile;

/* Daemon stop sequence */
static void
stop_check(void)
{
	/* Destroy master thread */
	signal_handler_destroy();
	thread_destroy_master(master);
	free_checkers_queue();
	free_ssl();
	if (!__test_bit(DONT_RELEASE_IPVS_BIT, &debug))
		clear_services();
	ipvs_stop();
#ifdef _WITH_SNMP_
	if (snmp)
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

#ifdef _DEBUG_
	keepalived_free_final("Healthcheck child process");
#endif

	/*
	 * Reached when terminate signal catched.
	 * finally return to parent process.
	 */
	closelog();
	exit(0);
}

/* Daemon init sequence */
static void
start_check(void)
{
	/* Initialize sub-system */
	if (ipvs_start() != IPVS_SUCCESS) {
		stop_check();
		return;
	}
	init_checkers_queue();
#ifdef _WITH_VRRP_
	init_interface_queue();
	kernel_netlink_init();
#endif
#ifdef _WITH_SNMP_
	if (!reload && snmp)
		check_snmp_agent_init(snmp_socket);
#endif

	/* Parse configuration file */
	global_data = alloc_global_data();
	check_data = alloc_check_data();
	init_data(conf_file, check_init_keywords);
	if (!check_data) {
		stop_check();
		return;
	}
	init_global_data(global_data);

	/* Post initializations */
	log_message(LOG_INFO, "Configuration is using : %lu Bytes", mem_allocated);

	/* SSL load static data & initialize common ctx context */
	if (!init_ssl_ctx()) {
		stop_check();
		return;
	}

	/* fill 'vsg' members of the virtual_server_t structure.
	 * We must do that after parsing config, because
	 * vs and vsg declarations may appear in any order
	 */
	link_vsg_to_vs();

	/* Processing differential configuration parsing */
	if (reload)
		clear_diff_services();

	/* Initialize IPVS topology */
	if (!init_services()) {
		stop_check();
		return;
	}

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
int reload_check_thread(thread_t *);
void
sighup_check(void *v, int sig)
{
	thread_add_event(master, reload_check_thread, NULL, 0);
}

/* Terminate handler */
void
sigend_check(void *v, int sig)
{
	if (master)
		thread_add_terminate_event(master);
}

/* CHECK Child signal handling */
void
check_signal_init(void)
{
	signal_handler_init();
	signal_set(SIGHUP, sighup_check, NULL);
	signal_set(SIGINT, sigend_check, NULL);
	signal_set(SIGTERM, sigend_check, NULL);
	signal_ignore(SIGPIPE);
}

/* Reload thread */
int
reload_check_thread(thread_t * thread)
{
	/* set the reloading flag */
	SET_RELOAD;

	log_message(LOG_INFO, "Got SIGHUP, reloading checker configuration");

	/* Signals handling */
	signal_reset();
	signal_handler_destroy();

	/* Destroy master thread */
#ifdef _WITH_VRRP_
	kernel_netlink_close();
#endif
	thread_destroy_master(master);
	master = thread_make_master();
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
	mem_allocated = 0;
	check_signal_init();
	signal_set(SIGCHLD, thread_child_handler, master);
	start_check();

	/* free backup data */
	free_check_data(old_check_data);
	UNSET_RELOAD;

	return 0;
}

/* CHECK Child respawning thread */
int
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

/* Register CHECK thread */
int
start_check_child(void)
{
#ifndef _DEBUG_
	pid_t pid;
	int ret;

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

	/* Opening local CHECK syslog channel */
	openlog(PROG_CHECK, LOG_PID | ((__test_bit(LOG_CONSOLE_BIT, &debug)) ? LOG_CONS : 0)
			  , (log_facility==LOG_DAEMON) ? LOG_LOCAL2 : log_facility);

	/* Child process part, write pidfile */
	if (!pidfile_write(checkers_pidfile, getpid())) {
		log_message(LOG_INFO, "Healthcheck child process: cannot write pidfile");
		exit(0);
	}

	/* Create the new master thread */
	signal_handler_destroy();
	thread_destroy_master(master);
	master = thread_make_master();

	/* change to / dir */
	ret = chdir("/");
	if (ret < 0) {
		log_message(LOG_INFO, "Healthcheck child process: error chdir");
	}

	/* Set mask */
	umask(0);
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
	stop_check();
	exit(0);
}
