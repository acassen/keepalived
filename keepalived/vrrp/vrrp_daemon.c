/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        VRRP child process handling.
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
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>

#include "vrrp_daemon.h"
#include "vrrp_scheduler.h"
#include "vrrp_arp.h"
#include "vrrp_ndisc.h"
#include "keepalived_netlink.h"
#include "vrrp_iptables.h"
#ifdef _HAVE_FIB_ROUTING_
#include "vrrp_iprule.h"
#include "vrrp_iproute.h"
#endif
#include "vrrp_parser.h"
#include "vrrp.h"
#include "vrrp_print.h"
#include "global_data.h"
#include "pidfile.h"
#include "logger.h"
#include "signals.h"
#include "process.h"
#include "bitops.h"
#include "rttables.h"
#if defined _WITH_SNMP_RFC || defined _WITH_SNMP_VRRP_
  #include "vrrp_snmp.h"
#endif
#ifdef _WITH_DBUS_
  #include "vrrp_dbus.h"
#endif
#include "list.h"
#include "main.h"
#include "parser.h"
#include "utils.h"
#include "vrrp_notify.h"
#ifdef _LIBNL_DYNAMIC_
#include "libnl_link.h"
#endif
#include "vrrp_track.h"
#ifdef _WITH_JSON_
#include "vrrp_json.h"
#endif
#ifdef _WITH_BFD_
#include "bfd_daemon.h"
#endif

/* Global variables */
bool non_existent_interface_specified;

/* Forward declarations */
static int print_vrrp_data(thread_t * thread);
static int print_vrrp_stats(thread_t * thread);
#ifdef _WITH_JSON_
static int print_vrrp_json(thread_t * thread);
#endif
#ifndef _DEBUG_
static int reload_vrrp_thread(thread_t * thread);
#endif

/* local variables */
static char *vrrp_syslog_ident;
static bool two_phase_terminate;

#ifdef _WITH_LVS_
static bool
vrrp_ipvs_needed(void)
{
	return !!(global_data->lvs_syncd.ifname);
}
#endif

static int
vrrp_terminate_phase2(int exit_status)
{
#ifdef _NETLINK_TIMERS_
	report_and_clear_netlink_timers("Starting shutdown instances");
#endif

	if (!__test_bit(DONT_RELEASE_VRRP_BIT, &debug))
		shutdown_vrrp_instances();

#ifdef _NETLINK_TIMERS_
	report_and_clear_netlink_timers("Completed shutdown instances");
#endif

#if defined _WITH_SNMP_RFC || defined _WITH_SNMP_VRRP_
	if (
#ifdef _WITH_SNMP_RFC_
	    global_data->enable_snmp_vrrp ||
#endif
#ifdef _WITH_SNMP_RFCV2_
	    global_data->enable_snmp_rfcv2 ||
#endif
#ifdef _WITH_SNMP_RFCV3_
	    global_data->enable_snmp_rfcv3 ||
#endif
	    false)
		vrrp_snmp_agent_close();
#endif

#ifdef _WITH_LVS_
	if (vrrp_ipvs_needed()) {
		/* Clean ipvs related */
		ipvs_stop();
	}
#endif

	/* We mustn't receive a SIGCHLD after master is destroyed */
	signal_handler_destroy();

	kernel_netlink_close_cmd();
	thread_destroy_master(master);
	master = NULL;
	gratuitous_arp_close();
	ndisc_close();

#ifdef _WITH_DBUS_
	if (global_data->enable_dbus)
		dbus_stop();
#endif

	if (global_data->vrrp_notify_fifo.fd != -1)
		notify_fifo_close(&global_data->notify_fifo, &global_data->vrrp_notify_fifo);

	free_global_data(global_data);
	free_vrrp_data(vrrp_data);
	free_vrrp_buffer();
	free_interface_queue();
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
	FREE_PTR(vrrp_syslog_ident);
#else
	if (vrrp_syslog_ident)
		free(vrrp_syslog_ident);
#endif
	close_std_fd();

	/* Stop daemon */
	pidfile_rm(vrrp_pidfile);

	exit(exit_status);
}

static int
vrrp_shutdown_timer_thread(thread_t *thread)
{
	thread->master->shutdown_timer_running = false;
	thread_add_terminate_event(thread->master);

	return 0;
}

static int
vrrp_shutdown_backstop_thread(thread_t *thread)
{
	log_message(LOG_ERR, "Backstop thread invoked: shutdown timer %srunning, child count %d",
			thread->master->shutdown_timer_running ? "" : "not ", thread->master->child.count);

	thread_add_terminate_event(thread->master);

	return 0;
}

/* Daemon stop sequence */
static void
vrrp_terminate_phase1(bool schedule_next_thread)
{
	/* Terminate all script processes */
	if (master->child.count)
		script_killall(master, SIGTERM, true);

	kernel_netlink_close_monitor();

#ifdef _NETLINK_TIMERS_
	report_and_clear_netlink_timers("Start shutdown");
#endif

	/* Ensure any interfaces are in backup mode,
	 * sending a priority 0 vrrp message
	 */
	if (!__test_bit(DONT_RELEASE_VRRP_BIT, &debug))
		restore_vrrp_interfaces();

#ifdef _NETLINK_TIMERS_
	report_and_clear_netlink_timers("Restored interfaces");
#endif

	if (vrrp_data->vrrp_track_files)
		stop_track_files();

#ifdef _HAVE_LIBIPTC_
	iptables_fini();
#endif

	/* Clear static entries */
#ifdef _HAVE_FIB_ROUTING_
	netlink_rulelist(vrrp_data->static_rules, IPRULE_DEL, false);
	netlink_rtlist(vrrp_data->static_routes, IPROUTE_DEL);
#endif
	netlink_iplist(vrrp_data->static_addresses, IPADDRESS_DEL, false);

#ifdef _NETLINK_TIMERS_
	report_and_clear_netlink_timers("Static addresses/routes/rules cleared");
#endif

	/* Clean data */
	vrrp_dispatcher_release(vrrp_data);

	/* Send shutdown notifications */
	notify_shutdown();

	if (schedule_next_thread) {
		if (!LIST_ISEMPTY(vrrp_data->vrrp)) {
			/* This is not nice, but it significantly increases the chances
			 * of an IGMP leave group being sent for some reason.
			 * Since we are about to exit, it doesn't affect anything else
			 * running. */
			thread_add_timer_shutdown(master, vrrp_shutdown_timer_thread, NULL, TIMER_HZ);
			master->shutdown_timer_running = true;
		}
		else if (master->child.count) {
			/* Add a backstop timer for the shutdown */
			thread_add_timer_shutdown(master, vrrp_shutdown_backstop_thread, NULL, TIMER_HZ);
		}
		else
			thread_add_terminate_event(master);
	}
}

static int
start_vrrp_termination_thread(__attribute__((unused)) thread_t * thread)
{
	/* This runs in the context of a thread */
	two_phase_terminate = true;

	vrrp_terminate_phase1(true);

	return 0;
}

/* Daemon stop sequence */
static void
stop_vrrp(int status)
{
	/* This runs in the main process, not in the context of a thread */
	vrrp_terminate_phase1(false);

	vrrp_terminate_phase2(status);

	/* unreachable */
	exit(status);
}

/* Daemon init sequence */
static void
start_vrrp(void)
{
	/* Clear the flags used for optimising performance */
	clear_summary_flags();

	/* Initialize sub-system */
	kernel_netlink_init();

	if (reload)
		global_data = alloc_global_data();

	/* Parse configuration file */
	vrrp_data = alloc_vrrp_data();
	if (!vrrp_data) {
		stop_vrrp(KEEPALIVED_EXIT_FATAL);
		return;
	}

	init_data(conf_file, vrrp_init_keywords);

	if (non_existent_interface_specified) {
		log_message(LOG_INFO, "Non-existent interface specified in configuration");
		stop_vrrp(KEEPALIVED_EXIT_CONFIG);
		return;
	}

	if (reload)
		init_global_data(global_data);

	/* Set our copy of time */
	set_time_now();

	if (!__test_bit(CONFIG_TEST_BIT, &debug)) {
		/* Set the process priority and non swappable if configured */
		set_process_priorities(
#ifdef _HAVE_SCHED_RT_
				       global_data->vrrp_realtime_priority,
#if HAVE_DECL_RLIMIT_RTTIME == 1
				       global_data->vrrp_rlimit_rt,
#endif
#endif
				       global_data->vrrp_process_priority, global_data->vrrp_no_swap ? 4096 : 0);

#if defined _WITH_SNMP_RFC || defined _WITH_SNMP_VRRP_
		if (!reload && (
#ifdef _WITH_SNMP_VRRP_
		     global_data->enable_snmp_vrrp ||
#endif
#ifdef _WITH_SNMP_RFCV2_
		     global_data->enable_snmp_rfcv2 ||
#endif
#ifdef _WITH_SNMP_RFCV3_
		     global_data->enable_snmp_rfcv3 ||
#endif
		     false)) {
			vrrp_snmp_agent_init(global_data->snmp_socket);
#ifdef _WITH_SNMP_RFC_
			vrrp_start_time = time_now;
#endif
		}
#endif

#ifdef _WITH_LVS_
		if (vrrp_ipvs_needed()) {
			/* Initialize ipvs related */
			if (ipvs_start() != IPVS_SUCCESS) {
				stop_vrrp(KEEPALIVED_EXIT_FATAL);
				return;
			}

			/* Set LVS timeouts */
			if (global_data->lvs_tcp_timeout ||
			    global_data->lvs_tcpfin_timeout ||
			    global_data->lvs_udp_timeout)
				ipvs_set_timeouts(global_data->lvs_tcp_timeout, global_data->lvs_tcpfin_timeout, global_data->lvs_udp_timeout);

			/* If we are managing the sync daemon, then stop any
			 * instances of it that may have been running if
			 * we terminated abnormally */
			ipvs_syncd_cmd(IPVS_STOPDAEMON, NULL, IPVS_MASTER, true, true);
			ipvs_syncd_cmd(IPVS_STOPDAEMON, NULL, IPVS_BACKUP, true, true);
		}
#endif

		if (reload) {
			kernel_netlink_set_recv_bufs();

			clear_diff_saddresses();
#ifdef _HAVE_FIB_ROUTING_
			clear_diff_srules();
			clear_diff_sroutes();
#endif
			clear_diff_script();
#ifdef _WITH_BFD_
			clear_diff_bfd();
#endif
		}
		else {
			/* Clear leftover static entries */
			netlink_iplist(vrrp_data->static_addresses, IPADDRESS_DEL, false);
#ifdef _HAVE_FIB_ROUTING_
			netlink_rtlist(vrrp_data->static_routes, IPROUTE_DEL);
			netlink_error_ignore = ENOENT;
			netlink_rulelist(vrrp_data->static_rules, IPRULE_DEL, true);
			netlink_error_ignore = 0;
#endif
		}

#ifdef _WITH_DBUS_
		if (!reload && global_data->enable_dbus)
			if (!dbus_start())
				global_data->enable_dbus = false;
#endif
	}

	/* Complete VRRP initialization */
	if (!vrrp_complete_init()) {
		stop_vrrp(KEEPALIVED_EXIT_CONFIG);
		return;
	}

	/* If we are just testing the configuration, then we terminate now */
	if (__test_bit(CONFIG_TEST_BIT, &debug)) {
		stop_vrrp(KEEPALIVED_EXIT_OK);
		return;
	}

	/* Start or stop gratuitous arp/ndisc as appropriate */
	if (have_ipv4_instance)
		gratuitous_arp_init();
	else
		gratuitous_arp_close();
	if (have_ipv6_instance)
		ndisc_init();
	else
		ndisc_close();

	/* We need to delay the init of iptables to after vrrp_complete_init()
	 * has been called so we know whether we want IPv4 and/or IPv6 */
	iptables_init();

	/* Initialise any tracking files */
	if (vrrp_data->vrrp_track_files)
		init_track_files(vrrp_data->vrrp_track_files);

	/* Make sure we don't have any old iptables/ipsets settings left around */
#ifdef _HAVE_LIBIPTC_
	if (!reload)
		iptables_cleanup();

	iptables_startup(reload);
#endif

	if (!reload)
		vrrp_restore_interfaces_startup();

	/* clear_diff_vrrp must be called after vrrp_complete_init, since the latter
	 * sets ifp on the addresses, which is used for the address comparison */
	if (reload)
		clear_diff_vrrp();

#ifdef _WITH_DBUS_
	if (reload && global_data->enable_dbus)
		dbus_reload(old_vrrp_data->vrrp, vrrp_data->vrrp);
#endif

	/* Post initializations */
#ifdef _MEM_CHECK_
	log_message(LOG_INFO, "Configuration is using : %zu Bytes", mem_allocated);
#endif

	/* Set static entries */
	netlink_iplist(vrrp_data->static_addresses, IPADDRESS_ADD, false);
#ifdef _HAVE_FIB_ROUTING_
	netlink_rtlist(vrrp_data->static_routes, IPROUTE_ADD);
	netlink_rulelist(vrrp_data->static_rules, IPRULE_ADD, false);
#endif

	/* Dump configuration */
	if (__test_bit(DUMP_CONF_BIT, &debug))
		dump_data_vrrp(NULL);

	/* Init & start the VRRP packet dispatcher */
	thread_add_event(master, vrrp_dispatcher_init, NULL,
			 VRRP_DISPATCHER);
}

#ifndef _DEBUG_
static int
send_reload_advert_thread(thread_t *thread)
{
	vrrp_t *vrrp = THREAD_ARG(thread);

	if (vrrp->state == VRRP_STATE_MAST)
		vrrp_send_adv(vrrp, vrrp->effective_priority);

	/* If this is the last vrrp instance to send an advert, schedule the
	 * actual reload. */
	if (THREAD_VAL(thread))
		thread_add_event(master, reload_vrrp_thread, NULL, 0);

	return 0;
}

static void
sigreload_vrrp(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	element e;
	vrrp_t *vrrp;
	int num_master_inst = 0;
	int i;

	/* We want to send adverts for the vrrp instances which are
	 * in master state. After that the reload can be initiated */
	if (!LIST_ISEMPTY(vrrp_data->vrrp)) {
		for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
			vrrp = ELEMENT_DATA(e);
			if (vrrp->state == VRRP_STATE_MAST)
				num_master_inst++;
		}

		for (e = LIST_HEAD(vrrp_data->vrrp), i = 0; e; ELEMENT_NEXT(e)) {
			vrrp = ELEMENT_DATA(e);
			if (vrrp->state == VRRP_STATE_MAST) {
				i++;
				thread_add_event(master, send_reload_advert_thread, vrrp, i == num_master_inst);
			}
		}
	}

	if (num_master_inst == 0)
		thread_add_event(master, reload_vrrp_thread, NULL, 0);
}

static void
sigusr1_vrrp(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	log_message(LOG_INFO, "Printing VRRP data for process(%d) on signal",
		    getpid());
	thread_add_event(master, print_vrrp_data, NULL, 0);
}

static void
sigusr2_vrrp(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	log_message(LOG_INFO, "Printing VRRP stats for process(%d) on signal",
		    getpid());
	thread_add_event(master, print_vrrp_stats, NULL, 0);
}

#ifdef _WITH_JSON_
static void
sigjson_vrrp(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	log_message(LOG_INFO, "Printing VRRP as json for process(%d) on signal",
		getpid());
	thread_add_event(master, print_vrrp_json, NULL, 0);
}
#endif

/* Terminate handler */
static void
sigend_vrrp(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	if (master)
		thread_add_start_terminate_event(master, start_vrrp_termination_thread);
}

/* VRRP Child signal handling */
static void
vrrp_signal_init(void)
{
	signal_handler_child_init();
	signal_set(SIGHUP, sigreload_vrrp, NULL);
	signal_set(SIGINT, sigend_vrrp, NULL);
	signal_set(SIGTERM, sigend_vrrp, NULL);
	signal_set(SIGUSR1, sigusr1_vrrp, NULL);
	signal_set(SIGUSR2, sigusr2_vrrp, NULL);
#ifdef _WITH_JSON_
	signal_set(SIGJSON, sigjson_vrrp, NULL);
#endif
	signal_ignore(SIGPIPE);
}

/* Reload thread */
static int
reload_vrrp_thread(__attribute__((unused)) thread_t * thread)
{
	log_message(LOG_INFO, "Reloading");

	/* set the reloading flag */
	SET_RELOAD;

	/* Terminate all script process */
	script_killall(master, SIGTERM, false);

	if (vrrp_data->vrrp_track_files)
		stop_track_files();

	vrrp_initialised = false;

	/* Destroy master thread */
	vrrp_dispatcher_release(vrrp_data);
	thread_cleanup_master(master);
#ifdef _WITH_LVS_
	if (global_data->lvs_syncd.ifname)
		ipvs_syncd_cmd(IPVS_STOPDAEMON, &global_data->lvs_syncd,
		       (global_data->lvs_syncd.vrrp->state == VRRP_STATE_MAST) ? IPVS_MASTER:
										 IPVS_BACKUP,
		       true, false);
#endif

	/* Remove the notify fifo - we don't know if it will be the same after a reload */
	notify_fifo_close(&global_data->notify_fifo, &global_data->vrrp_notify_fifo);

#ifdef _WITH_LVS_
	if (vrrp_ipvs_needed()) {
		/* Clean ipvs related */
		ipvs_stop();
	}
#endif

	/* Save previous conf data */
	old_vrrp_data = vrrp_data;
	vrrp_data = NULL;
	old_global_data = global_data;
	global_data = NULL;
	reset_interface_queue();
#ifdef _HAVE_FIB_ROUTING_
	reset_next_rule_priority();
#endif

	/* Reload the conf */
	start_vrrp();

#ifdef _WITH_LVS_
	if (global_data->lvs_syncd.ifname)
		ipvs_syncd_cmd(IPVS_STARTDAEMON, &global_data->lvs_syncd,
			       (global_data->lvs_syncd.vrrp->state == VRRP_STATE_MAST) ? IPVS_MASTER:
											 IPVS_BACKUP,
			       true, false);
#endif

	/* free backup data */
	free_vrrp_data(old_vrrp_data);
	free_global_data(old_global_data);

	free_old_interface_queue();

	UNSET_RELOAD;

	return 0;
}
#endif

static int
print_vrrp_data(__attribute__((unused)) thread_t * thread)
{
	vrrp_print_data();
	return 0;
}

static int
print_vrrp_stats(__attribute__((unused)) thread_t * thread)
{
	vrrp_print_stats();
	return 0;
}

#ifdef _WITH_JSON_
static int
print_vrrp_json(__attribute__((unused)) thread_t * thread)
{
	vrrp_print_json();
	return 0;
}
#endif

/* VRRP Child respawning thread */
#ifndef _DEBUG_
static int
vrrp_respawn_thread(thread_t * thread)
{
	pid_t pid;

	/* Fetch thread args */
	pid = THREAD_CHILD_PID(thread);

	/* Restart respawning thread */
	if (thread->type == THREAD_CHILD_TIMEOUT) {
		thread_add_child(master, vrrp_respawn_thread, NULL,
				 pid, RESPAWN_TIMER);
		return 0;
	}

	/* We catch a SIGCHLD, handle it */
	if (__test_bit(CONFIG_TEST_BIT, &debug))
		raise(SIGTERM);
	else if (!__test_bit(DONT_RESPAWN_BIT, &debug)) {
		log_message(LOG_ALERT, "VRRP child process(%d) died: Respawning", pid);
		start_vrrp_child();
	} else {
		log_message(LOG_ALERT, "VRRP child process(%d) died: Exiting", pid);
		vrrp_child = 0;
		raise(SIGTERM);
	}
	return 0;
}
#endif

/* Register VRRP thread */
int
start_vrrp_child(void)
{
#ifndef _DEBUG_
	pid_t pid;
	char *syslog_ident;

	/* Initialize child process */
	if (log_file_name)
		flush_log_file();

	pid = fork();

	if (pid < 0) {
		log_message(LOG_INFO, "VRRP child process: fork error(%s)"
			       , strerror(errno));
		return -1;
	} else if (pid) {
		vrrp_child = pid;
		log_message(LOG_INFO, "Starting VRRP child process, pid=%d"
			       , pid);

		/* Start respawning thread */
		thread_add_child(master, vrrp_respawn_thread, NULL,
				 pid, RESPAWN_TIMER);

		return 0;
	}
	prctl(PR_SET_PDEATHSIG, SIGTERM);

	prog_type = PROG_TYPE_VRRP;

#ifdef _WITH_BFD_
	/* Close the write end of the BFD vrrp event notification pipe */
	close(bfd_vrrp_event_pipe[1]);

#ifdef _WITH_LVS_
	close(bfd_checker_event_pipe[0]);
	close(bfd_checker_event_pipe[1]);
#endif
#endif

	/* Opening local VRRP syslog channel */
	if ((global_data->instance_name
#if HAVE_DECL_CLONE_NEWNET
			   || global_data->network_namespace
#endif
					       ) &&
	    (vrrp_syslog_ident = make_syslog_ident(PROG_VRRP)))
			syslog_ident = vrrp_syslog_ident;
	else
		syslog_ident = PROG_VRRP;

	if (!__test_bit(NO_SYSLOG_BIT, &debug))
		openlog(syslog_ident, LOG_PID | ((__test_bit(LOG_CONSOLE_BIT, &debug)) ? LOG_CONS : 0)
				    , (log_facility==LOG_DAEMON) ? LOG_LOCAL1 : log_facility);

	if (log_file_name)
		open_log_file(log_file_name,
				"vrrp",
#if HAVE_DECL_CLONE_NEWNET
				global_data->network_namespace,
#else
				NULL,
#endif
				global_data->instance_name);

	signal_handler_destroy();

#ifdef _MEM_CHECK_
	mem_log_init(PROG_VRRP, "VRRP Child process");
#endif

	free_parent_mallocs_startup(true);

	/* Clear any child finder functions set in parent */
	set_child_finder_name(NULL);
	destroy_child_finder();

	/* Child process part, write pidfile */
	if (!pidfile_write(vrrp_pidfile, getpid())) {
		/* Fatal error */
		log_message(LOG_INFO, "VRRP child process: cannot write pidfile");
		exit(0);
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
	vrrp_signal_init();
#endif

#ifdef _LIBNL_DYNAMIC_
	libnl_init();
#endif

	/* Start VRRP daemon */
	start_vrrp();

#ifdef _DEBUG_
	return 0;
#endif

	/* Launch the scheduling I/O multiplexer */
	launch_scheduler();

	/* Finish VRRP daemon process */
	vrrp_terminate_phase2(EXIT_SUCCESS);

	/* unreachable */
	exit(EXIT_SUCCESS);
}

#ifdef _TIMER_DEBUG_
void
print_vrrp_daemon_addresses(void)
{
	log_message(LOG_INFO, "Address of print_vrrp_data() is 0x%p", print_vrrp_data);
	log_message(LOG_INFO, "Address of print_vrrp_stats() is 0x%p", print_vrrp_stats);
	log_message(LOG_INFO, "Address of reload_vrrp_thread() is 0x%p", reload_vrrp_thread);
	log_message(LOG_INFO, "Address of vrrp_respawn_thread() is 0x%p", vrrp_respawn_thread);
}
#endif
