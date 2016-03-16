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

#include "vrrp_daemon.h"
#include "vrrp_scheduler.h"
#include "vrrp_if.h"
#include "vrrp_arp.h"
#include "vrrp_ndisc.h"
#include "vrrp_netlink.h"
#include "vrrp_ipaddress.h"
#include "vrrp_iptables.h"
#include "vrrp_iproute.h"
#include "vrrp_iprule.h"
#include "vrrp_parser.h"
#include "vrrp_data.h"
#include "vrrp.h"
#include "vrrp_print.h"
#include "global_data.h"
#include "pidfile.h"
#include "daemon.h"
#include "logger.h"
#include "signals.h"
#include "process.h"
#include "bitops.h"
#ifdef _WITH_LVS_
  #include "ipvswrapper.h"
#endif
#ifdef _WITH_SNMP_
  #include "vrrp_snmp.h"
#endif
#ifdef _HAVE_LIBIPSET_
  #include "vrrp_ipset.h"
#endif
#include "list.h"
#include "main.h"
#include "memory.h"
#include "parser.h"

/* Daemon stop sequence */
static void
stop_vrrp(void)
{
	/* Ensure any interfaces are in backup mode,
	 * sending a priority 0 vrrp message
	 */
	restore_vrrp_interfaces();

#ifdef _HAVE_LIBIPTC_
	iptables_fini();
#endif

	/* Clear static entries */
	netlink_rulelist(vrrp_data->static_rules, IPRULE_DEL, false);
	netlink_rtlist(vrrp_data->static_routes, IPROUTE_DEL);
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
	sleep ( 1 );

	if (!__test_bit(DONT_RELEASE_VRRP_BIT, &debug))
		shutdown_vrrp_instances();

#ifdef _WITH_LVS_
	if (vrrp_ipvs_needed()) {
		/* Clean ipvs related */
		ipvs_stop();
	}
#endif

	kernel_netlink_close();
	thread_destroy_master(master);
	gratuitous_arp_close();
	ndisc_close();

	free_global_data(global_data);
	free_vrrp_data(vrrp_data);
	free_vrrp_buffer();
	free_interface_queue();

	signal_handler_destroy();

#ifdef _DEBUG_
	keepalived_free_final("VRRP Child process");
#endif

	/*
	 * Reached when terminate signal catched.
	 * finally return to parent process.
	 */
	log_message(LOG_INFO, "Stopped");

	closelog();

	exit(0);
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

#ifdef _HAVE_LIBIPTC_
	iptables_init();
#endif

	/* Parse configuration file */
	vrrp_data = alloc_vrrp_data();
	init_data(conf_file, vrrp_init_keywords);
	if (!vrrp_data) {
		stop_vrrp();
		return;
	}
	init_global_data(global_data);

	/* Set the process priority and non swappable if configured */
	if (global_data->vrrp_process_priority)
		set_process_priority(global_data->vrrp_process_priority);

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
			stop_vrrp();
			return;
		}

#ifdef _HAVE_IPVS_SYNCD_
		/* If we are managing the sync daemon, then stop any
		 * instances of it that may have been running if
		 * we terminated abnormally */
		ipvs_syncd_cmd(IPVS_STOPDAEMON, NULL, IPVS_MASTER, 0, true);
		ipvs_syncd_cmd(IPVS_STOPDAEMON, NULL, IPVS_BACKUP, 0, true);
#endif
	}
#endif

	if (reload) {
		clear_diff_saddresses();
		clear_diff_srules();
		clear_diff_sroutes();
		clear_diff_vrrp();
		clear_diff_script();
	}
	else {
		/* Clear leftover static entries */
		netlink_iplist(vrrp_data->static_addresses, IPADDRESS_DEL);
		netlink_rtlist(vrrp_data->static_routes, IPROUTE_DEL);
		netlink_error_ignore = ENOENT;
		netlink_rulelist(vrrp_data->static_rules, IPRULE_DEL, true);
		netlink_error_ignore = 0;
	}

	/* Complete VRRP initialization */
	if (!vrrp_complete_init()) {
		if (vrrp_ipvs_needed()) {
			stop_vrrp();
		}
		return;
	}

#ifdef _HAVE_LIBIPTC_
	iptables_startup();
#endif

	/* Post initializations */
#ifdef _DEBUG_
	log_message(LOG_INFO, "Configuration is using : %lu Bytes", mem_allocated);
#endif

	/* Set static entries */
	if (!reload) {
		netlink_iplist(vrrp_data->static_addresses, IPADDRESS_ADD);
		netlink_rtlist(vrrp_data->static_routes, IPROUTE_ADD);
		netlink_rulelist(vrrp_data->static_rules, IPRULE_ADD, false);
	}

	/* Dump configuration */
	if (__test_bit(DUMP_CONF_BIT, &debug)) {
		list ifl;

		dump_global_data(global_data);
		dump_vrrp_data(vrrp_data);
		ifl = get_if_list();
		if (!LIST_ISEMPTY(ifl))
			dump_list(ifl);
	}

	/* Initialize linkbeat */
	init_interface_linkbeat();

	/* Init & start the VRRP packet dispatcher */
	thread_add_event(master, vrrp_dispatcher_init, NULL,
			 VRRP_DISPATCHER);
}

/* Reload handler */
int reload_vrrp_thread(thread_t * thread);
void
sighup_vrrp(void *v, int sig)
{
	thread_add_event(master, reload_vrrp_thread, NULL, 0);
}
int print_vrrp_data(thread_t * thread);
void
sigusr1_vrrp(void *v, int sig)
{
	log_message(LOG_INFO, "Printing VRRP data for process(%d) on signal",
		    getpid());
	thread_add_event(master, print_vrrp_data, NULL, 0);
}

int print_vrrp_stats(thread_t * thread);
void
sigusr2_vrrp(void *v, int sig)
{
	log_message(LOG_INFO, "Printing VRRP stats for process(%d) on signal",
		    getpid());
	thread_add_event(master, print_vrrp_stats, NULL, 0);
}

/* Terminate handler */
void
sigend_vrrp(void *v, int sig)
{
	if (master)
		thread_add_terminate_event(master);
}

/* VRRP Child signal handling */
void
vrrp_signal_init(void)
{
	signal_handler_init();
	signal_set(SIGHUP, sighup_vrrp, NULL);
	signal_set(SIGINT, sigend_vrrp, NULL);
	signal_set(SIGTERM, sigend_vrrp, NULL);
	signal_set(SIGUSR1, sigusr1_vrrp, NULL);
	signal_set(SIGUSR2, sigusr2_vrrp, NULL);
	signal_ignore(SIGPIPE);
}

/* Reload thread */
int
reload_vrrp_thread(thread_t * thread)
{
	/* set the reloading flag */
	SET_RELOAD;

	/* Destroy master thread */
	vrrp_dispatcher_release(vrrp_data);
	kernel_netlink_close();
	thread_destroy_master(master);
	master = thread_make_master();
#ifdef _HAVE_IPVS_SYNCD_
	/* TODO - Note: this didn't work if we found ipvs_syndc on vrrp before on old_vrrp */
	if (global_data->lvs_syncd_if)
		ipvs_syncd_cmd(IPVS_STOPDAEMON, NULL,
		       (global_data->lvs_syncd_vrrp->state == VRRP_STATE_MAST) ? IPVS_MASTER:
										 IPVS_BACKUP,
		       global_data->lvs_syncd_syncid, false);
#endif
	free_global_data(global_data);
	free_interface_queue();
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

	/* Reload the conf */
#ifdef _DEBUG_
	mem_allocated = 0;
#endif
	start_vrrp();

#ifdef _HAVE_IPVS_SYNCD_
	if (global_data->lvs_syncd_if)
		ipvs_syncd_cmd(IPVS_STARTDAEMON, NULL,
			       (global_data->lvs_syncd_vrrp->state == VRRP_STATE_MAST) ? IPVS_MASTER:
											 IPVS_BACKUP,
			       global_data->lvs_syncd_syncid, false);
#endif

	/* free backup data */
	free_vrrp_data(old_vrrp_data);
	UNSET_RELOAD;

	return 0;
}

int
print_vrrp_data(thread_t * thread)
{
	vrrp_print_data();
	return 0;
}

int
print_vrrp_stats(thread_t * thread)
{
	vrrp_print_stats();
	return 0;
}


/* VRRP Child respawning thread */
int
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

/* Register VRRP thread */
int
start_vrrp_child(void)
{
#ifndef _DEBUG_
	pid_t pid;
	int ret;

	/* Initialize child process */
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

	signal_handler_destroy();

	/* Opening local VRRP syslog channel */
	openlog(PROG_VRRP, LOG_PID | ((__test_bit(LOG_CONSOLE_BIT, &debug)) ? LOG_CONS : 0)
			 , (log_facility==LOG_DAEMON) ? LOG_LOCAL1 : log_facility);

	/* Child process part, write pidfile */
	if (!pidfile_write(vrrp_pidfile, getpid())) {
		/* Fatal error */
		log_message(LOG_INFO, "VRRP child process: cannot write pidfile");
		exit(0);
	}

	/* Create the new master thread */
	thread_destroy_master(master);
	master = thread_make_master();

	/* change to / dir */
	ret = chdir("/");
	if (ret < 0) {
		log_message(LOG_INFO, "VRRP child process: error chdir");
	}

	/* Set mask */
	umask(0);
#endif

	/* If last process died during a reload, we can get there and we
	 * don't want to loop again, because we're not reloading anymore.
	 */
	UNSET_RELOAD;

	/* Signal handling initialization */
	vrrp_signal_init();

	/* Start VRRP daemon */
	start_vrrp();

	/* Launch the scheduling I/O multiplexer */
	launch_scheduler();

	/* Finish VRRP daemon process */
	stop_vrrp();
	exit(0);
}
