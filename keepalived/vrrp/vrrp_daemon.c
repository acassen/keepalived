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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

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
#ifdef _WITH_SNMP_
  #include "vrrp_snmp.h"
#endif
#ifdef _WITH_DBUS_
  #include "vrrp_dbus.h"
#endif
#include "list.h"
#include "main.h"
#include "parser.h"
#include "utils.h"
#ifdef _LIBNL_DYNAMIC_
#include "libnl_link.h"
#endif
#include "vrrp_track.h"
#ifdef _WITH_JSON_
#include "vrrp_json.h"
#endif

/* Global variables */
bool non_existent_interface_specified;

/* Forward declarations */
static int print_vrrp_data(thread_t * thread);
static int print_vrrp_stats(thread_t * thread);
#ifdef _WITH_JSON_
static int print_vrrp_json(thread_t * thread);
#endif
static int reload_vrrp_thread(thread_t * thread);

static char *vrrp_syslog_ident;

#ifdef _WITH_LVS_
static bool
vrrp_ipvs_needed(void)
{
	return !!(global_data->lvs_syncd.ifname);
}
#endif

static int
vrrp_notify_fifo_script_exit(__attribute__((unused)) thread_t *thread)
{
	log_message(LOG_INFO, "vrrp notify fifo script terminated");

	return 0;
}

/* Daemon stop sequence */
static void
stop_vrrp(int status)
{
	/* Ensure any interfaces are in backup mode,
	 * sending a priority 0 vrrp message
	 */
	restore_vrrp_interfaces();

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
	netlink_iplist(vrrp_data->static_addresses, IPADDRESS_DEL);

#ifdef _WITH_SNMP_
	if (global_data->enable_snmp_keepalived || global_data->enable_snmp_rfcv2 || global_data->enable_snmp_rfcv3)
		vrrp_snmp_agent_close();
#endif

	/* Stop daemon */
	pidfile_rm(vrrp_pidfile);

	/* Clean data */
	vrrp_dispatcher_release(vrrp_data);

	/* This is not nice, but it significantly increases the chances
	 * of an IGMP leave group being sent for some reason.
	 * Since we are about to exit, it doesn't affect anything else
	 * running. */
	if (!LIST_ISEMPTY(vrrp_data->vrrp))
		sleep(1);

	if (!__test_bit(DONT_RELEASE_VRRP_BIT, &debug))
		shutdown_vrrp_instances();

#ifdef _WITH_LVS_
	if (vrrp_ipvs_needed()) {
		/* Clean ipvs related */
		ipvs_stop();
	}
#endif

	/* Terminate all script processes */
	script_killall(master, SIGTERM);

	/* We mustn't receive a SIGCHLD after master is destroyed */
	signal_handler_destroy();

	kernel_netlink_close();
	thread_destroy_master(master);
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

	exit(status);
}

/* Daemon init sequence */
static void
start_vrrp(void)
{
	/* Initialize sub-system */
	init_interface_queue();
	kernel_netlink_init();
	gratuitous_arp_init();
	ndisc_init();

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

	init_global_data(global_data);

	/* Set the process priority and non swappable if configured */
	if (global_data->vrrp_process_priority)
		set_process_priority(global_data->vrrp_process_priority);

// TODO - measure max stack usage
	if (global_data->vrrp_no_swap)
		set_process_dont_swap(4096);	/* guess a stack size to reserve */

#ifdef _WITH_SNMP_
	if (!reload && (global_data->enable_snmp_keepalived || global_data->enable_snmp_rfcv2 || global_data->enable_snmp_rfcv3)) {
		vrrp_snmp_agent_init(global_data->snmp_socket);
#ifdef _WITH_SNMP_RFC_
		vrrp_start_time = timer_now();
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
		clear_diff_saddresses();
#ifdef _HAVE_FIB_ROUTING_
		clear_diff_srules();
		clear_diff_sroutes();
#endif
		clear_diff_script();
	}
	else {
		/* Clear leftover static entries */
		netlink_iplist(vrrp_data->static_addresses, IPADDRESS_DEL);
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

	/* Complete VRRP initialization */
	if (!vrrp_complete_init()) {
		stop_vrrp(KEEPALIVED_EXIT_CONFIG);
		return;
	}

	/* We need to delay the init of iptables to after vrrp_complete_init()
	 * has been called so we know whether we want IPv4 and/or IPv6 */
	iptables_init();

	/* Create a notify FIFO if needed, and open it */
	if (global_data->vrrp_notify_fifo.name)
		notify_fifo_open(&global_data->notify_fifo, &global_data->vrrp_notify_fifo, vrrp_notify_fifo_script_exit, "vrrp_");

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
	netlink_iplist(vrrp_data->static_addresses, IPADDRESS_ADD);
#ifdef _HAVE_FIB_ROUTING_
	netlink_rtlist(vrrp_data->static_routes, IPROUTE_ADD);
	netlink_rulelist(vrrp_data->static_rules, IPRULE_ADD, false);
#endif

	/* Dump configuration */
	if (__test_bit(DUMP_CONF_BIT, &debug)) {
		list ifl;

		dump_global_data(global_data);
		dump_vrrp_data(vrrp_data);
		ifl = get_if_list();
		if (!LIST_ISEMPTY(ifl))
			dump_list(ifl);

		clear_rt_names();
	}

	/* Init & start the VRRP packet dispatcher */
	thread_add_event(master, vrrp_dispatcher_init, NULL,
			 VRRP_DISPATCHER);
}

static void
sighup_vrrp(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
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
		thread_add_terminate_event(master);
}

/* VRRP Child signal handling */
static void
vrrp_signal_init(void)
{
	signal_handler_child_init();
	signal_set(SIGHUP, sighup_vrrp, NULL);
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
	/* set the reloading flag */
	SET_RELOAD;

	/* Terminate all script process */
	script_killall(master, SIGTERM);

	if (vrrp_data->vrrp_track_files)
		stop_track_files();

	vrrp_initialised = false;

	/* Destroy master thread */
	vrrp_dispatcher_release(vrrp_data);
	kernel_netlink_close();
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

	free_global_data(global_data);
	free_vrrp_buffer();
	gratuitous_arp_close();
	ndisc_close();

#ifdef _WITH_LVS_
	if (vrrp_ipvs_needed()) {
		/* Clean ipvs related */
		ipvs_stop();
	}
#endif

	/* Save previous conf data */
	old_vrrp_data = vrrp_data;
	vrrp_data = NULL;
	reset_interface_queue();

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
	free_old_interface_queue();

	UNSET_RELOAD;

	return 0;
}

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
	if (!__test_bit(DONT_RESPAWN_BIT, &debug)) {
		log_message(LOG_ALERT, "VRRP child process(%d) died: Respawning", pid);
		start_vrrp_child();
	} else {
		log_message(LOG_ALERT, "VRRP child process(%d) died: Exiting", pid);
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

	/* Opening local VRRP syslog channel */
	if ((instance_name
#if HAVE_DECL_CLONE_NEWNET
			   || network_namespace
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
		open_log_file(log_file_name, "vrrp", network_namespace, instance_name);

	signal_handler_destroy();

#ifdef _MEM_CHECK_
	mem_log_init(PROG_VRRP, "VRRP Child process");
#endif

	free_parent_mallocs_startup(true);

	/* Clear any child finder functions set in parent */
	set_child_finder_name(NULL);
	set_child_finder(NULL, NULL, NULL, NULL, NULL, 0);	/* Currently these won't be set */

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

	/* Signal handling initialization */
	vrrp_signal_init();

#ifdef _LIBNL_DYNAMIC_
	libnl_init();
#endif

	/* Start VRRP daemon */
	start_vrrp();

	/* Launch the scheduling I/O multiplexer */
	launch_scheduler();

	/* Finish VRRP daemon process */
	stop_vrrp(EXIT_SUCCESS);

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
