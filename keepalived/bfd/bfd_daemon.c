/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        BFD child process handling
 *
 * Author:      Ilya Voronin, <ivoronin@gmail.com>
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
 * Copyright (C) 2015-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "bfd.h"
#include "bfd_daemon.h"
#include "bfd_data.h"
#include "bfd_parser.h"
#include "bfd_scheduler.h"
#include "bfd_event.h"
#include "pidfile.h"
#include "logger.h"
#include "signals.h"
#include "list.h"
#include "main.h"
#include "parser.h"
#include "time.h"
#include "global_data.h"
#include "bitops.h"
#include "utils.h"
#include "scheduler.h"
#include "process.h"
#include "utils.h"
#ifdef _WITH_CN_PROC_
#include "track_process.h"
#endif

/* Global variables */
int bfd_vrrp_event_pipe[2] = { -1, -1};
int bfd_checker_event_pipe[2] = { -1, -1};

/* Local variables */
static const char *bfd_syslog_ident;

#ifndef _DEBUG_
static int reload_bfd_thread(thread_ref_t);
#endif

/* Daemon stop sequence */
static void
stop_bfd(int status)
{
	struct rusage usage;

	if (__test_bit(CONFIG_TEST_BIT, &debug))
		return;

	/* Stop daemon */
	pidfile_rm(bfd_pidfile);

	/* Clean data */
	free_global_data(global_data);
	bfd_dispatcher_release(bfd_data);
	free_bfd_data(bfd_data);
	free_bfd_buffer();
	thread_destroy_master(master);
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
	FREE_CONST_PTR(bfd_syslog_ident);
#else
	if (bfd_syslog_ident)
		free(no_const_char_p(bfd_syslog_ident));
#endif
	close_std_fd();

	exit(status);
}

/* Daemon init sequence */
void
open_bfd_pipes(void)
{
#ifdef _WITH_VRRP_
	/* Open BFD VRRP control pipe */
	if (open_pipe(bfd_vrrp_event_pipe) == -1) {
		log_message(LOG_ERR, "Unable to create BFD vrrp event pipe: %m");
		stop_keepalived();
		return;
	}
#endif

#ifdef _WITH_LVS_
	/* Open BFD checker control pipe */
	if (open_pipe(bfd_checker_event_pipe) == -1) {
		log_message(LOG_ERR, "Unable to create BFD checker event pipe: %m");
		stop_keepalived();
		return;
	}
#endif
}

/* Daemon init sequence */
static void
start_bfd(__attribute__((unused)) data_t *prev_global_data)
{
	srandom(time(NULL));

	if (reload)
		global_data = alloc_global_data();
	if (!(bfd_data = alloc_bfd_data())) {
		stop_bfd(KEEPALIVED_EXIT_FATAL);
		return;
	}

	alloc_bfd_buffer();

	init_data(conf_file, bfd_init_keywords);
	if (reload)
		init_global_data(global_data, prev_global_data, true);

	/* Update process name if necessary */
	if ((!reload && global_data->bfd_process_name) ||
	    (reload &&
	     (!global_data->bfd_process_name != !prev_global_data->bfd_process_name ||
	      (global_data->bfd_process_name && strcmp(global_data->bfd_process_name, prev_global_data->bfd_process_name)))))
		set_process_name(global_data->bfd_process_name);

	/* If we are just testing the configuration, then we terminate now */
	if (__test_bit(CONFIG_TEST_BIT, &debug))
		return;
	bfd_complete_init();

	/* Post initializations */
#ifdef _MEM_CHECK_
	log_message(LOG_INFO, "Configuration is using : %zu Bytes", mem_allocated);
#endif

	if (__test_bit(DUMP_CONF_BIT, &debug))
		dump_bfd_data(NULL, bfd_data);

	thread_add_event(master, bfd_dispatcher_init, bfd_data, 0);

	/* Set the process priority and non swappable if configured */
// TODO - measure max stack usage
	set_process_priorities(
#ifdef _HAVE_SCHED_RT_
			global_data->bfd_realtime_priority,
#if HAVE_DECL_RLIMIT_RTTIME == 1
			global_data->bfd_rlimit_rt,
#endif
#endif
			global_data->bfd_process_priority, global_data->bfd_no_swap ? 4096 : 0);

#ifdef _HAVE_SCHED_RT_
	/* Set the process cpu affinity if configured */
	set_process_cpu_affinity(&global_data->bfd_cpu_mask, "bfd");
#endif
}

void
bfd_validate_config(void)
{
	start_bfd(NULL);
}

#ifndef _DEBUG_
/* Reload handler */
static void
sigreload_bfd(__attribute__ ((unused)) void *v,
	   __attribute__ ((unused)) int sig)
{
	thread_add_event(master, reload_bfd_thread, NULL, 0);
}

/* Terminate handler */
static void
sigend_bfd(__attribute__ ((unused)) void *v,
	   __attribute__ ((unused)) int sig)
{
	if (master)
		thread_add_terminate_event(master);
}

/* BFD Child signal handling */
static void
bfd_signal_init(void)
{
	signal_set(SIGHUP, sigreload_bfd, NULL);
	signal_set(SIGINT, sigend_bfd, NULL);
	signal_set(SIGTERM, sigend_bfd, NULL);
	signal_ignore(SIGPIPE);
}

/* Reload thread */
static int
reload_bfd_thread(__attribute__((unused)) thread_ref_t thread)
{
	timeval_t timer;
	timer = timer_now();

	log_message(LOG_INFO, "Reloading");

	/* Use standard scheduling while reloading */
	reset_process_priorities();

	/* set the reloading flag */
	SET_RELOAD;

	/* Destroy master thread */
	bfd_dispatcher_release(bfd_data);
	thread_cleanup_master(master);
	thread_add_base_threads(master, false);

	old_bfd_data = bfd_data;
	bfd_data = NULL;
	old_global_data = global_data;
	global_data = NULL;

	/* Reload the conf */
	signal_set(SIGCHLD, thread_child_handler, master);
	start_bfd(old_global_data);

	free_bfd_data(old_bfd_data);
	free_global_data(old_global_data);

	UNSET_RELOAD;

	set_time_now();
	log_message(LOG_INFO, "Reload finished in %lu usec", -timer_long(timer_sub_now(timer)));

	return 0;
}

/* BFD Child respawning thread */
static int
bfd_respawn_thread(thread_ref_t thread)
{
	/* We catch a SIGCHLD, handle it */
	bfd_child = 0;

	if (!__test_bit(DONT_RESPAWN_BIT, &debug)) {
		log_message(LOG_ALERT, "BFD child process(%d) died: Respawning", thread->u.c.pid);
		start_bfd_child();
	} else {
		log_message(LOG_ALERT, "BFD child process(%d) died: Exiting", thread->u.c.pid);
		raise(SIGTERM);
	}
	return 0;
}
#endif

#ifndef _DEBUG_
#ifdef THREAD_DUMP
static void
register_bfd_thread_addresses(void)
{
	register_scheduler_addresses();
	register_signal_thread_addresses();

	register_bfd_scheduler_addresses();

	register_thread_address("bfd_dispatcher_init", bfd_dispatcher_init);
	register_thread_address("reload_bfd_thread", reload_bfd_thread);

	register_signal_handler_address("sigreload_bfd", sigreload_bfd);
	register_signal_handler_address("sigend_bfd", sigend_bfd);
	register_signal_handler_address("thread_child_handler", thread_child_handler);
}
#endif
#endif

int
start_bfd_child(void)
{
#ifndef _DEBUG_
	pid_t pid;
	int ret;
	const char *syslog_ident;

	/* Initialize child process */
#ifdef ENABLE_LOG_TO_FILE
	if (log_file_name)
		flush_log_file();
#endif

	pid = fork();

	if (pid < 0) {
		log_message(LOG_INFO, "BFD child process: fork error(%m)");
		return -1;
	} else if (pid) {
		bfd_child = pid;
		log_message(LOG_INFO, "Starting BFD child process, pid=%d",
			    pid);

		/* Start respawning thread */
		thread_add_child(master, bfd_respawn_thread, NULL,
				 pid, TIMER_NEVER);
		return 0;
	}
	prctl(PR_SET_PDEATHSIG, SIGTERM);

	prog_type = PROG_TYPE_BFD;

	/* Close the read end of the event notification pipes, and the track_process fd */
#ifdef _WITH_VRRP_
	close(bfd_vrrp_event_pipe[0]);
#ifdef _WITH_CN_PROC_
	close_track_processes();
#endif
#endif
#ifdef _WITH_LVS_
	close(bfd_checker_event_pipe[0]);
#endif

	initialise_debug_options();

	if ((global_data->instance_name
#if HAVE_DECL_CLONE_NEWNET
			   || global_data->network_namespace
#endif
					       ) &&
	     (bfd_syslog_ident = make_syslog_ident(PROG_BFD)))
		syslog_ident = bfd_syslog_ident;
	else
		syslog_ident = PROG_BFD;

	/* Opening local BFD syslog channel */
	if (!__test_bit(NO_SYSLOG_BIT, &debug))
		openlog(syslog_ident, LOG_PID | ((__test_bit(LOG_CONSOLE_BIT, &debug)) ? LOG_CONS : 0)
				    , (log_facility==LOG_DAEMON) ? LOG_LOCAL2 : log_facility);

#ifdef ENABLE_LOG_TO_FILE
	if (log_file_name)
		open_log_file(log_file_name,
				"bfd",
#if HAVE_DECL_CLONE_NEWNET
				global_data->network_namespace,
#else
				NULL,
#endif
				global_data->instance_name);
#endif

#ifdef _MEM_CHECK_
	mem_log_init(PROG_BFD, "BFD child process");
#endif

	free_parent_mallocs_startup(true);

	/* Clear any child finder functions set in parent */
	set_child_finder_name(NULL);

	/* Child process part, write pidfile */
	if (!pidfile_write(bfd_pidfile, getpid())) {
		/* Fatal error */
		log_message(LOG_INFO,
			    "BFD child process: cannot write pidfile");
		exit(0);
	}

	/* Create the new master thread */
	thread_destroy_master(master);
	master = thread_make_master();

	/* change to / dir */
	ret = chdir("/");
	if (ret < 0) {
		log_message(LOG_INFO, "BFD child process: error chdir");
	}
#endif

	/* If last process died during a reload, we can get there and we
	 * don't want to loop again, because we're not reloading anymore.
	 */
	UNSET_RELOAD;

#ifndef _DEBUG_
	/* Signal handling initialization */
	bfd_signal_init();
#endif

	/* Start BFD daemon */
	start_bfd(NULL);

#ifdef _DEBUG_
	return 0;
#else

#ifdef THREAD_DUMP
	register_bfd_thread_addresses();
#endif

	/* Launch the scheduling I/O multiplexer */
	launch_thread_scheduler(master);

#ifdef THREAD_DUMP
	deregister_thread_addresses();
#endif

	/* Finish BFD daemon process */
	stop_bfd(EXIT_SUCCESS);

	/* unreachable */
	exit(EXIT_SUCCESS);
#endif
}

#ifdef THREAD_DUMP
void
register_bfd_parent_addresses(void)
{
#ifndef _DEBUG_
	register_thread_address("bfd_respawn_thread", bfd_respawn_thread);
#endif
}
#endif
