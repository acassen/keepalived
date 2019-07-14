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
#include <sys/time.h>
#include <sys/resource.h>

#ifdef THREAD_DUMP
#ifdef _WITH_SNMP_
#include "snmp.h"
#endif
#include "scheduler.h"
#include "smtp.h"
#include "vrrp_track.h"
#endif
#include "vrrp_daemon.h"
#include "vrrp_scheduler.h"
#include "vrrp_arp.h"
#include "vrrp_ndisc.h"
#include "keepalived_netlink.h"
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
#include "memory.h"
#include "bitops.h"
#include "rttables.h"
#if defined _WITH_SNMP_RFC_ || defined _WITH_SNMP_VRRP_
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
#include "vrrp_track.h"
#ifdef _WITH_JSON_
#include "vrrp_json.h"
#endif
#ifdef _WITH_BFD_
#include "bfd_daemon.h"
#endif
#ifdef _WITH_FIREWALL_
#include "vrrp_firewall.h"
#endif
#ifdef _WITH_CN_PROC_
#include "track_process.h"
#endif

/* Global variables */
bool non_existent_interface_specified;

/* Forward declarations */
#ifndef _DEBUG_
static int print_vrrp_data(thread_ref_t);
static int print_vrrp_stats(thread_ref_t);
static int reload_vrrp_thread(thread_ref_t);
#ifdef _WITH_JSON_
static int print_vrrp_json(thread_ref_t);
#endif
#endif
#ifdef _WITH_PERF_
perf_t perf_run = PERF_NONE;
#endif

/* local variables */
static const char *vrrp_syslog_ident;
#ifndef _DEBUG_
static bool two_phase_terminate;
#endif

#ifdef _VRRP_FD_DEBUG_
bool do_vrrp_fd_debug;
#endif

#ifndef _DEBUG_
#ifdef _VRRP_FD_DEBUG_
static void
dump_vrrp_fd(void)
{
	element e;
	sock_t *sock;
	vrrp_t *vrrp;
	timeval_t time_diff;

	log_message(LOG_INFO, "----[ Begin VRRP fd dump ]----");

	LIST_FOREACH(vrrp_data->vrrp_socket_pool, sock, e) {
		log_message(LOG_INFO, "  Sockets %d, %d", sock->fd_in, sock->fd_out);

		rb_for_each_entry_cached(vrrp, &sock->rb_sands, rb_sands) {
			if (vrrp->sands.tv_sec == TIMER_DISABLED)
				log_message(LOG_INFO, "    %s: sands DISABLED", vrrp->iname);
			else {
				timersub(&vrrp->sands, &time_now, &time_diff);
				if (time_diff.tv_sec >= 0)
					log_message(LOG_INFO, "    %s: sands %ld.%6.6ld", vrrp->iname, time_diff.tv_sec, time_diff.tv_usec);
				else
					log_message(LOG_INFO, "    %s: sands -%ld.%6.6ld", vrrp->iname, -time_diff.tv_sec - (time_diff.tv_usec ? 1 : 0), time_diff.tv_usec ? 1000000 - time_diff.tv_usec : 0);
			}
		}

		rb_for_each_entry(vrrp, &sock->rb_vrid, rb_vrid)
			log_message(LOG_INFO, "    %s: vrid %d", vrrp->iname, vrrp->vrid);
	}

	log_message(LOG_INFO, "----[ End VRRP fd dump ]----");
}
#endif
#endif

static void
set_vrrp_max_fds(void)
{
	if (!vrrp_data->vrrp)
		return;

	/* Allow:
	 * 2 per vrrp instance - always needed for VMAC instances
	 *
	 * plus:
	 *
	 * stdin/stdout/stderr
	 * logger
	 * logger file
	 * timer fd
	 * inotify fd
	 * signal fd
	 * epoll fd
	 * 3 for SNMP
	 * 2 for netlink
	 * bfd pipe
	 * 2 * notify fifo pipes
	 * track_file (only one open at a time)
	 * mem_check file
	 * USR1/USR2/JSON data
	 * smtp-alert file
	 *
	 * plus:
	 *
	 * 20 spare (in case we have forgotten anything)
	 */
	set_max_file_limit(LIST_SIZE(vrrp_data->vrrp) * 2 + vrrp_data->num_smtp_alert + 21 + 20);
}

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
	struct rusage usage;

#ifdef _NETLINK_TIMERS_
	if (do_netlink_timers)
		report_and_clear_netlink_timers("Starting shutdown instances");
#endif

	if (!__test_bit(DONT_RELEASE_VRRP_BIT, &debug))
		shutdown_vrrp_instances();

#ifdef _NETLINK_TIMERS_
	if (do_netlink_timers)
		report_and_clear_netlink_timers("Completed shutdown instances");
#endif

#if defined _WITH_SNMP_RFC_ || defined _WITH_SNMP_VRRP_
	if (
#ifdef _WITH_SNMP_VRRP_
	    global_data->enable_snmp_vrrp ||
#endif
#ifdef _WITH_SNMP_RFCV2_
	    global_data->enable_snmp_rfcv2 ||
#endif
#ifdef _WITH_SNMP_RFCV3_
	    global_data->enable_snmp_rfcv3 ||
#endif
	    snmp_option)
		vrrp_snmp_agent_close();
#endif

#ifdef _WITH_LVS_
	if (vrrp_ipvs_needed()) {
		/* Clean ipvs related */
		ipvs_stop();
	}
#endif

	kernel_netlink_close_cmd();
	thread_destroy_master(master);
	master = NULL;
	gratuitous_arp_close();
	ndisc_close();
#ifdef _WITH_LINKBEAT_
	close_interface_linkbeat();
#endif

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
	FREE_CONST_PTR(vrrp_syslog_ident);
#else
	if (vrrp_syslog_ident)
		free(no_const_char_p(vrrp_syslog_ident));
#endif
	close_std_fd();

	/* Stop daemon */
	pidfile_rm(vrrp_pidfile);

	exit(exit_status);
}

static int
vrrp_shutdown_backstop_thread(thread_ref_t thread)
{
	int count = 0;
	thread_ref_t t;

	/* Force terminate all script processes */
	if (thread->master->child.rb_root.rb_node)
		script_killall(thread->master, SIGKILL, true);

	rb_for_each_entry_cached_const(t, &thread->master->child, n)
		count++;

	log_message(LOG_ERR, "Backstop thread invoked: shutdown timer %srunning, child count %d",
			thread->master->shutdown_timer_running ? "" : "not ", count);

	thread_add_terminate_event(thread->master);

	return 0;
}

static int
vrrp_shutdown_timer_thread(thread_ref_t thread)
{
	thread->master->shutdown_timer_running = false;

	if (thread->master->child.rb_root.rb_node)
		thread_add_timer_shutdown(thread->master, vrrp_shutdown_backstop_thread, NULL, TIMER_HZ / 10);
	else
		thread_add_terminate_event(thread->master);

	return 0;
}

/* Daemon stop sequence */
static void
vrrp_terminate_phase1(bool schedule_next_thread)
{
#ifdef _WITH_PERF_
	if (perf_run == PERF_END)
		run_perf("vrrp", global_data->network_namespace, global_data->instance_name);
#endif

#ifdef _WITH_CN_PROC_
	/* Stop monitoring process terminations */
	end_process_monitor();
#endif

	/* Terminate all script processes */
	if (master->child.rb_root.rb_node)
		script_killall(master, SIGTERM, true);

	kernel_netlink_close_monitor();

#ifdef _NETLINK_TIMERS_
	if (do_netlink_timers)
		report_and_clear_netlink_timers("Start shutdown");
#endif

#ifdef _WITH_LVS_
        if (global_data->lvs_syncd.vrrp) {
                /* Stop syncd if controlled by this VRRP instance. */
                ipvs_syncd_cmd(IPVS_STOPDAEMON, &global_data->lvs_syncd,
                               (global_data->lvs_syncd.vrrp->state == VRRP_STATE_MAST) ? IPVS_MASTER: IPVS_BACKUP,
                               true, false);
        }
#endif

	/* Ensure any interfaces are in backup mode,
	 * sending a priority 0 vrrp message
	 */
	if (!__test_bit(DONT_RELEASE_VRRP_BIT, &debug))
		restore_vrrp_interfaces();

#ifdef _NETLINK_TIMERS_
	if (do_netlink_timers)
		report_and_clear_netlink_timers("Restored interfaces");
#endif

	if (vrrp_data->vrrp_track_files)
		stop_track_files();

#ifdef _WITH_FIREWALL_
	firewall_fini();
#endif

	/* Clear static entries */
#ifdef _HAVE_FIB_ROUTING_
	netlink_rulelist(vrrp_data->static_rules, IPRULE_DEL, false);
	netlink_rtlist(vrrp_data->static_routes, IPROUTE_DEL);
#endif
	netlink_iplist(vrrp_data->static_addresses, IPADDRESS_DEL, false);

#ifdef _NETLINK_TIMERS_
	if (do_netlink_timers)
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
		else if (master->child.rb_root.rb_node) {
			/* Add a backstop timer for the shutdown */
			thread_add_timer_shutdown(master, vrrp_shutdown_backstop_thread, NULL, TIMER_HZ);
		}
		else
			thread_add_terminate_event(master);
	}
}

#ifndef _DEBUG_
static int
start_vrrp_termination_thread(__attribute__((unused)) thread_ref_t thread)
{
	/* This runs in the context of a thread */
	two_phase_terminate = true;

	vrrp_terminate_phase1(true);

	return 0;
}
#endif

/* Daemon stop sequence */
static void
stop_vrrp(int status)
{
	if (__test_bit(CONFIG_TEST_BIT, &debug))
		return;

	/* This runs in the main process, not in the context of a thread */
	vrrp_terminate_phase1(false);

	vrrp_terminate_phase2(status);

	/* unreachable */
	exit(status);
}

/* Daemon init sequence */
static void
start_vrrp(data_t *prev_global_data)
{
	/* Clear the flags used for optimising performance */
	clear_summary_flags();

	/* Initialize sub-system */
	if (!__test_bit(CONFIG_TEST_BIT, &debug))
		kernel_netlink_init();

	if (!global_data)
		global_data = alloc_global_data();
	else if (global_data->default_ifname) {
		/* We need to set the default_ifp here on startup, since
		 * the parent process doesn't know about the interfaces */
		global_data->default_ifp = if_get_by_ifname(global_data->default_ifname, IF_CREATE_IF_DYNAMIC);
		if (!global_data->default_ifp)
			log_message(LOG_INFO, "WARNING - default interface %s doesn't exist", global_data->default_ifname);
	}

	/* Parse configuration file */
	vrrp_data = alloc_vrrp_data();
	if (!vrrp_data) {
		stop_vrrp(KEEPALIVED_EXIT_FATAL);
		return;
	}

	init_data(conf_file, vrrp_init_keywords);

	/* Update process name if necessary */
	if ((!reload && global_data->vrrp_process_name) ||
	    (reload &&
	     (!global_data->vrrp_process_name != !prev_global_data->vrrp_process_name ||
	      (global_data->vrrp_process_name && strcmp(global_data->vrrp_process_name, prev_global_data->vrrp_process_name)))))
		set_process_name(global_data->vrrp_process_name);

	if (non_existent_interface_specified) {
		report_config_error(CONFIG_BAD_IF, "Non-existent interface specified in configuration");
		stop_vrrp(KEEPALIVED_EXIT_CONFIG);
		return;
	}

	if (reload)
		init_global_data(global_data, prev_global_data, true);

	/* Set our copy of time */
	set_time_now();

	if (!__test_bit(CONFIG_TEST_BIT, &debug)) {
#if defined _WITH_SNMP_RFC_ || defined _WITH_SNMP_VRRP_
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
		     snmp_option)) {
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
	}

	/* Complete VRRP initialization */
	if (!vrrp_complete_init()) {
		stop_vrrp(KEEPALIVED_EXIT_CONFIG);
		return;
	}

	/* If we are just testing the configuration, then we terminate now */
	if (__test_bit(CONFIG_TEST_BIT, &debug))
		return;

	/* Start or stop gratuitous arp/ndisc as appropriate */
	if (have_ipv4_instance)
		gratuitous_arp_init();
	else
		gratuitous_arp_close();
	if (have_ipv6_instance)
		ndisc_init();
	else
		ndisc_close();

#ifdef _WITH_FIREWALL_
	/* We need to delay the init of iptables to after vrrp_complete_init()
	 * has been called so we know whether we want IPv4 and/or IPv6 */
	firewall_init();

	/* Make sure we don't have any old iptables/ipsets settings left around */
	if (!reload)
		firewall_cleanup();

	firewall_startup(reload);
#endif

	if (!reload)
		vrrp_restore_interfaces_startup();

	/* clear_diff_vrrp must be called after vrrp_complete_init, since the latter
	 * sets ifp on the addresses, which is used for the address comparison */
	if (reload) {
		clear_diff_vrrp();
		vrrp_dispatcher_release(old_vrrp_data);
	}

#ifdef _WITH_DBUS_
	if (global_data->enable_dbus) {
		if (reload && old_global_data->enable_dbus)
			dbus_reload(old_vrrp_data->vrrp, vrrp_data->vrrp);
		else {
			if (!dbus_start())
				global_data->enable_dbus = false;
		}
	}
	else if (reload && old_global_data->enable_dbus)
		dbus_stop();
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
	if (!reload && global_data->vrrp_startup_delay) {
		log_message(LOG_INFO, "Delaying startup for %g seconds", global_data->vrrp_startup_delay / TIMER_HZ_DOUBLE);
		thread_add_timer(master, vrrp_dispatcher_init, NULL,
				 global_data->vrrp_startup_delay);
	} else
		thread_add_event(master, vrrp_dispatcher_init, NULL, 0);

	/* Set the process priority and non swappable if configured */
	set_process_priorities(
#ifdef _HAVE_SCHED_RT_
			       global_data->vrrp_realtime_priority,
#if HAVE_DECL_RLIMIT_RTTIME == 1
			       global_data->vrrp_rlimit_rt,
#endif
#endif
			       global_data->vrrp_process_priority, global_data->vrrp_no_swap ? 4096 : 0);

#ifdef _HAVE_SCHED_RT_
	/* Set the process cpu affinity if configured */
	set_process_cpu_affinity(&global_data->vrrp_cpu_mask, "vrrp");
#endif

	/* Ensure we can open sufficient file descriptors */
	set_vrrp_max_fds();
}

#ifndef _DEBUG_
static int
send_reload_advert_thread(thread_ref_t thread)
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
reload_vrrp_thread(__attribute__((unused)) thread_ref_t thread)
{
	bool with_snmp = false;

	log_message(LOG_INFO, "Reloading");

	/* Use standard scheduling while reloading */
	reset_process_priorities();

	/* set the reloading flag */
	SET_RELOAD;

	/* Terminate all script process */
	script_killall(master, SIGTERM, false);

	if (vrrp_data->vrrp_track_files)
		stop_track_files();

	vrrp_initialised = false;

#if !defined _DEBUG_ && defined _WITH_SNMP_VRRP_
	if (
#ifdef _WITH_SNMP_VRRP_
	    global_data->enable_snmp_vrrp ||
#endif
#ifdef _WITH_SNMP_RFCV2_
	    global_data->enable_snmp_rfcv2 ||
#endif
#ifdef _WITH_SNMP_RFCV3_
	    global_data->enable_snmp_rfcv3 ||
#endif
	    snmp_option)
		with_snmp = true;
#endif

	/* Destroy master thread */
#ifdef _WITH_BFD_
	cancel_vrrp_threads();
#endif
	thread_cleanup_master(master);
	thread_add_base_threads(master, with_snmp);

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
	start_vrrp(old_global_data);

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

static int
print_vrrp_data(__attribute__((unused)) thread_ref_t thread)
{
	vrrp_print_data();
	return 0;
}

static int
print_vrrp_stats(__attribute__((unused)) thread_ref_t thread)
{
	vrrp_print_stats();
	return 0;
}

#ifdef _WITH_JSON_
static int
print_vrrp_json(__attribute__((unused)) thread_ref_t thread)
{
	vrrp_print_json();
	return 0;
}
#endif

/* VRRP Child respawning thread */
static int
vrrp_respawn_thread(thread_ref_t thread)
{
	/* We catch a SIGCHLD, handle it */
	vrrp_child = 0;

	if (!__test_bit(DONT_RESPAWN_BIT, &debug)) {
		log_message(LOG_ALERT, "VRRP child process(%d) died: Respawning", thread->u.c.pid);
		start_vrrp_child();
	} else {
		log_message(LOG_ALERT, "VRRP child process(%d) died: Exiting", thread->u.c.pid);
		raise(SIGTERM);
	}
	return 0;
}
#endif

#ifdef THREAD_DUMP
static void
register_vrrp_thread_addresses(void)
{
	register_scheduler_addresses();
	register_signal_thread_addresses();
	register_notify_addresses();

	register_smtp_addresses();
	register_keepalived_netlink_addresses();
#ifdef _WITH_SNMP_
	register_snmp_addresses();
#endif

	register_vrrp_if_addresses();
	register_vrrp_scheduler_addresses();
#ifdef _WITH_DBUS_
	register_vrrp_dbus_addresses();
#endif
	register_vrrp_fifo_addresses();
	register_vrrp_inotify_addresses();
#ifdef _WITH_CN_PROC_
	register_process_monitor_addresses();
#endif

#ifndef _DEBUG_
	register_thread_address("print_vrrp_data", print_vrrp_data);
	register_thread_address("print_vrrp_stats", print_vrrp_stats);
	register_thread_address("reload_vrrp_thread", reload_vrrp_thread);
	register_thread_address("start_vrrp_termination_thread", start_vrrp_termination_thread);
	register_thread_address("send_reload_advert_thread", send_reload_advert_thread);
#endif
	register_thread_address("vrrp_shutdown_backstop_thread", vrrp_shutdown_backstop_thread);
	register_thread_address("vrrp_shutdown_timer_thread", vrrp_shutdown_timer_thread);

#ifndef _DEBUG_
	register_signal_handler_address("sigreload_vrrp", sigreload_vrrp);
	register_signal_handler_address("sigend_vrrp", sigend_vrrp);
	register_signal_handler_address("sigusr1_vrrp", sigusr1_vrrp);
	register_signal_handler_address("sigusr2_vrrp", sigusr2_vrrp);
#ifdef _WITH_JSON_
	register_signal_handler_address("sigjson_vrrp", sigjson_vrrp);
#endif
#endif
}
#endif

/* Register VRRP thread */
int
start_vrrp_child(void)
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
		log_message(LOG_INFO, "VRRP child process: fork error(%s)"
			       , strerror(errno));
		return -1;
	} else if (pid) {
		vrrp_child = pid;
		log_message(LOG_INFO, "Starting VRRP child process, pid=%d"
			       , pid);

		/* Start respawning thread */
		thread_add_child(master, vrrp_respawn_thread, NULL,
				 pid, TIMER_NEVER);

		return 0;
	}

	prctl(PR_SET_PDEATHSIG, SIGTERM);

#ifdef _WITH_PERF_
	if (perf_run == PERF_ALL)
		run_perf("vrrp", global_data->network_namespace, global_data->instance_name);
#endif

	prog_type = PROG_TYPE_VRRP;

	initialise_debug_options();

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

#ifdef ENABLE_LOG_TO_FILE
	if (log_file_name)
		open_log_file(log_file_name,
				"vrrp",
#if HAVE_DECL_CLONE_NEWNET
				global_data->network_namespace,
#else
				NULL,
#endif
				global_data->instance_name);
#endif

#ifdef _MEM_CHECK_
	mem_log_init(PROG_VRRP, "VRRP Child process");
#endif

	free_parent_mallocs_startup(true);

	/* Clear any child finder functions set in parent */
	set_child_finder_name(NULL);

	/* Child process part, write pidfile */
	if (!pidfile_write(vrrp_pidfile, getpid())) {
		/* Fatal error */
		log_message(LOG_INFO, "VRRP child process: cannot write pidfile");
		exit(0);
	}

#ifdef _VRRP_FD_DEBUG_
	if (do_vrrp_fd_debug)
		set_extra_threads_debug(dump_vrrp_fd);
#endif

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

	/* Start VRRP daemon */
	start_vrrp(NULL);

#ifdef _DEBUG_
	return 0;
#endif

#ifdef THREAD_DUMP
	register_vrrp_thread_addresses();
#endif

#ifdef _WITH_PERF_
	if (perf_run == PERF_RUN)
		run_perf("vrrp", global_data->network_namespace, global_data->instance_name);
#endif
	/* Launch the scheduling I/O multiplexer */
	launch_thread_scheduler(master);

#ifdef THREAD_DUMP
	deregister_thread_addresses();
#endif

	/* Finish VRRP daemon process */
	vrrp_terminate_phase2(EXIT_SUCCESS);

	/* unreachable */
	exit(EXIT_SUCCESS);
}

void
vrrp_validate_config(void)
{
	start_vrrp(NULL);
}

#ifdef THREAD_DUMP
void
register_vrrp_parent_addresses(void)
{
#ifndef _DEBUG_
	register_thread_address("vrrp_respawn_thread", vrrp_respawn_thread);
#endif
}
#endif
