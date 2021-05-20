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

#include <sched.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>

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
#include "vrrp_iprule.h"
#include "vrrp_iproute.h"
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
#include "list_head.h"
#include "main.h"
#include "parser.h"
#include "utils.h"
#include "vrrp_notify.h"
#include "track_file.h"
#ifdef _WITH_JSON_
#include "vrrp_json.h"
#endif
#ifdef _WITH_BFD_
#include "bfd_daemon.h"
#endif
#ifdef _WITH_FIREWALL_
#include "vrrp_firewall.h"
#endif
#ifdef _WITH_TRACK_PROCESS_
#include "track_process.h"
#endif
#ifdef _WITH_LVS_
#include "ipvswrapper.h"
#endif
#ifdef _USE_SYSTEMD_NOTIFY_
#include "systemd.h"
#endif
#ifndef _ONE_PROCESS_DEBUG_
#include "config_notify.h"
#endif


/* Global variables */
bool non_existent_interface_specified;
const char * const igmp_link_local_mcast_reports = "/proc/sys/net/ipv4/igmp_link_local_mcast_reports";

/* Forward declarations */
#ifndef _ONE_PROCESS_DEBUG_
static void print_vrrp_data(thread_ref_t);
static void print_vrrp_stats(thread_ref_t);
static void reload_vrrp_thread(thread_ref_t);
#ifdef _WITH_JSON_
static void print_vrrp_json(thread_ref_t);
#endif
#endif
#ifdef _WITH_PERF_
perf_t perf_run = PERF_NONE;
#endif

/* local variables */
static const char *vrrp_syslog_ident;
static char sav_igmp_link_local_mcast_reports;
#ifndef _ONE_PROCESS_DEBUG_
static bool two_phase_terminate;
static timeval_t vrrp_start_time;
static unsigned vrrp_next_restart_delay;
#endif

#ifdef _VRRP_FD_DEBUG_
bool do_vrrp_fd_debug;
#endif

#ifndef _ONE_PROCESS_DEBUG_
#ifdef _VRRP_FD_DEBUG_
static void
dump_vrrp_fd(void)
{
	sock_t *sock;
	vrrp_t *vrrp;
	timeval_t time_diff;

	log_message(LOG_INFO, "----[ Begin VRRP fd dump ]----");

	list_for_each_entry(sock, &vrrp_data->vrrp_socket_pool, e_list) {
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
	vrrp_t *vrrp;
	int cnt = 0;

	if (list_empty(&vrrp_data->vrrp))
		return;

	/* This is called at boot so ok performing full walk */
	list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list)
		cnt++;

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
	 * memfd for config
	 * eventfd for notifying load/reload complete
	 *
	 * plus:
	 *
	 * 20 spare (in case we have forgotten anything)
	 */
	set_max_file_limit(cnt * 2 + vrrp_data->num_smtp_alert + 23 + 20);
}

#ifdef _WITH_LVS_
static bool
vrrp_ipvs_needed(void)
{
	return global_data->lvs_syncd.ifname &&
	       (global_data->lvs_syncd.vrrp || global_data->lvs_syncd.vrrp_name);
}
#endif

static void
set_disable_local_igmp(void)
{
	char buf;
	int fd;
	ssize_t len;

	if ((fd = open(igmp_link_local_mcast_reports, O_RDWR)) == -1) {
		log_message(LOG_INFO, "Unable to open %s - errno %d", igmp_link_local_mcast_reports, errno);
		global_data->disable_local_igmp = false;
		return;
	}

	if ((len = read(fd, &sav_igmp_link_local_mcast_reports, 1)) != 1) {
		log_message(LOG_INFO, "Unable to read %s - errno %d", igmp_link_local_mcast_reports, errno);
		global_data->disable_local_igmp = false;
		close(fd);
		return;
	}

	if (sav_igmp_link_local_mcast_reports == '1') {
		buf = '0';
		lseek(fd, 0, SEEK_SET);
		if (write(fd, &buf, 1) != 1) {
			log_message(LOG_INFO, "Unable to write %s - errno %d", igmp_link_local_mcast_reports, errno);
			global_data->disable_local_igmp = false;
			close(fd);
			return;
		}
	}

	close(fd);
}

static void
reset_disable_local_igmp(void)
{
	int fd;

	if (sav_igmp_link_local_mcast_reports == '1') {
		fd = open(igmp_link_local_mcast_reports, O_RDWR);
		if (fd == -1 || write(fd, &sav_igmp_link_local_mcast_reports, 1) == -1)
			log_message(LOG_INFO, "Unable to write %s - errno %d", igmp_link_local_mcast_reports, errno);
		if (fd != -1)
			close(fd);
	}
}

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

#ifdef _WITH_FIREWALL_
	firewall_fini();
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

	clear_rt_names();

	if (global_data->vrrp_notify_fifo.fd != -1)
		notify_fifo_close(&global_data->notify_fifo, &global_data->vrrp_notify_fifo);

	if (global_data->disable_local_igmp)
		reset_disable_local_igmp();

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
		free(no_const_char_p(vrrp_syslog_ident));	/* malloc'd by make_syslog_ident() */
#endif
	close_std_fd();

	/* Stop daemon */
	pidfile_rm(vrrp_pidfile);

	exit(exit_status);
}

static void
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
}

static void
vrrp_shutdown_timer_thread(thread_ref_t thread)
{
	thread->master->shutdown_timer_running = false;

	if (thread->master->child.rb_root.rb_node)
		thread_add_timer_shutdown(thread->master, vrrp_shutdown_backstop_thread, NULL, TIMER_HZ / 10);
	else
		thread_add_terminate_event(thread->master);
}

/* Daemon stop sequence */
static void
vrrp_terminate_phase1(bool schedule_next_thread)
{
#ifdef _WITH_PERF_
	if (perf_run == PERF_END)
		run_perf("vrrp", global_data->network_namespace, global_data->instance_name);
#endif

#ifdef _WITH_TRACK_PROCESS_
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
	if (vrrp_ipvs_needed()) {
		/* Stop syncd if controlled by this vrrp process. */
		ipvs_syncd_cmd(IPVS_STOPDAEMON, &global_data->lvs_syncd,
			       global_data->lvs_syncd.vrrp->state == VRRP_STATE_MAST ? IPVS_MASTER: IPVS_BACKUP,
			       false);
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

	if (!list_empty(&vrrp_data->vrrp_track_files))
		stop_track_files();

	/* Clear static entries */
	netlink_rulelist(&vrrp_data->static_rules, IPRULE_DEL, false);
	netlink_rtlist(&vrrp_data->static_routes, IPROUTE_DEL, false);
	netlink_iplist(&vrrp_data->static_addresses, IPADDRESS_DEL, false);

#ifdef _NETLINK_TIMERS_
	if (do_netlink_timers)
		report_and_clear_netlink_timers("Static addresses/routes/rules cleared");
#endif

	/* Clean data */
	vrrp_dispatcher_release(vrrp_data);

	/* Send shutdown notifications */
	notify_shutdown();

	if (schedule_next_thread) {
		if (!list_empty(&vrrp_data->vrrp)) {
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

#ifndef _ONE_PROCESS_DEBUG_
static void
start_vrrp_termination_thread(__attribute__((unused)) thread_ref_t thread)
{
	/* This runs in the context of a thread */
	two_phase_terminate = true;

	vrrp_terminate_phase1(true);
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

	/* Parse configuration file */
	vrrp_data = alloc_vrrp_data();
	if (!vrrp_data) {
		stop_vrrp(KEEPALIVED_EXIT_FATAL);
		return;
	}

	init_data(conf_file, vrrp_init_keywords, false);

#ifndef _ONE_PROCESS_DEBUG_
	/* Notify parent config has been read if appropriate */
	if (!__test_bit(CONFIG_TEST_BIT, &debug))
		notify_config_read();
#endif

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
		if ((
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
			if (reload)
				snmp_epoll_info(master);
			else
				vrrp_snmp_agent_init(global_data->snmp_socket);
#ifdef _WITH_SNMP_RFC_
			snmp_vrrp_start_time = time_now;
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
		}
#endif

		if (reload) {
			kernel_netlink_set_recv_bufs();

			clear_diff_static_rules();
			clear_diff_static_routes();
			clear_diff_static_addresses();
			clear_diff_script();
#ifdef _WITH_BFD_
			clear_diff_bfd();
#endif
		}
		else {
			/* Clear leftover static entries */
			netlink_iplist(&vrrp_data->static_addresses, IPADDRESS_DEL, false);
			netlink_rtlist(&vrrp_data->static_routes, IPROUTE_DEL, false);
			netlink_error_ignore = ENOENT;
			netlink_rulelist(&vrrp_data->static_rules, IPRULE_DEL, true);
			netlink_error_ignore = 0;
		}
	}

	if (!__test_bit(CONFIG_TEST_BIT, &debug)) {
		/* Init & start the VRRP packet dispatcher */
		if (!reload && global_data->vrrp_startup_delay) {
			vrrp_delayed_start_time = timer_add_long(time_now, global_data->vrrp_startup_delay);
			log_message(LOG_INFO, "Delaying startup for %g seconds", global_data->vrrp_startup_delay / TIMER_HZ_DOUBLE);
		}
		thread_add_event(master, vrrp_dispatcher_init, NULL, 0);

		if (!reload && global_data->disable_local_igmp)
			set_disable_local_igmp();
	}

	/* Complete VRRP initialization */
	if (!vrrp_complete_init()
#ifndef _ONE_PROCESS_DEBUG_
	    || (global_data->reload_check_config && get_config_status() != CONFIG_OK)
#endif
	    			 ) {
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

	if (!reload)
		vrrp_restore_interfaces_startup();

	/* clear_diff_vrrp must be called after vrrp_complete_init, since the latter
	 * sets ifp on the addresses, which is used for the address comparison */
	if (reload) {
		clear_diff_vrrp();
		vrrp_dispatcher_release(old_vrrp_data);

		/* Set previous sync group states to suppress duplicate notifies */
		set_previous_sync_group_states();
	}

#ifdef _WITH_DBUS_
	if (global_data->enable_dbus) {
		if (reload && old_global_data->enable_dbus)
			dbus_reload(&old_vrrp_data->vrrp, &vrrp_data->vrrp);
		else {
			if (!dbus_start())
				global_data->enable_dbus = false;
		}
	}
	else if (reload && old_global_data->enable_dbus)
		dbus_stop();
#endif

	/* Set static entries */
	netlink_iplist(&vrrp_data->static_addresses, IPADDRESS_ADD, false);
	netlink_rtlist(&vrrp_data->static_routes, IPROUTE_ADD, false);
	netlink_rulelist(&vrrp_data->static_rules, IPRULE_ADD, false);

	/* Dump configuration */
	if (__test_bit(DUMP_CONF_BIT, &debug))
		dump_data_vrrp(NULL);

	/* Set the process priority and non swappable if configured */
	set_process_priorities(global_data->vrrp_realtime_priority, global_data->max_auto_priority, global_data->min_auto_priority_delay,
			       global_data->vrrp_rlimit_rt, global_data->vrrp_process_priority, global_data->vrrp_no_swap ? 4096 : 0);

	/* Set the process cpu affinity if configured */
	set_process_cpu_affinity(&global_data->vrrp_cpu_mask, "vrrp");

	/* Ensure we can open sufficient file descriptors */
	set_vrrp_max_fds();
}

#ifndef _ONE_PROCESS_DEBUG_
static void
send_reload_advert_thread(thread_ref_t thread)
{
	vrrp_t *vrrp = THREAD_ARG(thread);

	if (vrrp->state == VRRP_STATE_MAST)
		vrrp_send_adv(vrrp, vrrp->effective_priority);

	/* If this is the last vrrp instance to send an advert, schedule the
	 * actual reload. */
	if (THREAD_VAL(thread))
		thread_add_event(master, reload_vrrp_thread, NULL, 0);
}

static void
sigreload_vrrp(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	vrrp_t *vrrp;
	int num_master_inst = 0;
	int i = 0;

	/* We want to send adverts for the vrrp instances which are
	 * in master state. After that the reload can be initiated */
	if (!list_empty(&vrrp_data->vrrp)) {
		list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
			if (vrrp->state == VRRP_STATE_MAST)
				num_master_inst++;
		}

		list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
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
sigusr2_vrrp(__attribute__((unused)) void *v, int sig)
{
	log_message(LOG_INFO, "Printing %sVRRP stats for process(%d) on signal",
		    sig == SIGSTATS_CLEAR ? "and clearing " : "", getpid());
	thread_add_event(master, print_vrrp_stats, NULL, sig);
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
	signal_set(SIGSTATS_CLEAR, sigusr2_vrrp, NULL);
#ifdef _WITH_JSON_
	signal_set(SIGJSON, sigjson_vrrp, NULL);
#endif
#ifdef THREAD_DUMP
	signal_set(SIGTDUMP, thread_dump_signal, NULL);
#endif
	signal_ignore(SIGPIPE);
}

/* Reload thread */
static void
reload_vrrp_thread(__attribute__((unused)) thread_ref_t thread)
{
	bool with_snmp = false;
#ifdef _WITH_LVS_
	bool want_syncd_master;
#endif

	log_message(LOG_INFO, "Reloading");

	/* Use standard scheduling while reloading */
	reset_process_priorities();

	reinitialise_global_vars();

	/* set the reloading flag */
	SET_RELOAD;

	/* Terminate all script process */
	script_killall(master, SIGTERM, false);

	if (!list_empty(&vrrp_data->vrrp_track_files))
		stop_track_files();

	vrrp_initialised = false;

#if !defined _ONE_PROCESS_DEBUG_ && defined _WITH_SNMP_VRRP_
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
	cancel_kernel_netlink_threads();
	thread_cleanup_master(master);
	thread_add_base_threads(master, with_snmp);

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
	reset_next_rule_priority();

	/* Reload the conf */
	start_vrrp(old_global_data);

#ifdef _WITH_LVS_
	if (vrrp_ipvs_needed()) {
		/* coverity[var_deref_op] */
		want_syncd_master = (global_data->lvs_syncd.vrrp->state == VRRP_STATE_MAST);
		if (ipvs_syncd_changed(&old_global_data->lvs_syncd, &global_data->lvs_syncd))
			ipvs_syncd_cmd(IPVS_STOPDAEMON, NULL, want_syncd_master ? IPVS_MASTER : IPVS_BACKUP, true);
		ipvs_syncd_cmd(IPVS_STARTDAEMON, NULL, want_syncd_master ? IPVS_MASTER : IPVS_BACKUP, true);
		ipvs_syncd_cmd(IPVS_STOPDAEMON, NULL, want_syncd_master ? IPVS_BACKUP : IPVS_MASTER, true);
	}
#endif

	/* free backup data */
	free_vrrp_data(old_vrrp_data);
	old_vrrp_data = NULL;
	free_global_data(old_global_data);
	old_global_data = NULL;

	free_old_interface_queue();

	UNSET_RELOAD;

	/* Post initializations */
#ifdef _MEM_CHECK_
	log_message(LOG_INFO, "Configuration is using : %zu Bytes", mem_allocated);
#endif
}

static void
print_vrrp_data(__attribute__((unused)) thread_ref_t thread)
{
	vrrp_print_data();
}

static void
print_vrrp_stats(thread_ref_t thread)
{
	vrrp_print_stats(thread->u.val == SIGSTATS_CLEAR);
}

#ifdef _WITH_JSON_
static void
print_vrrp_json(__attribute__((unused)) thread_ref_t thread)
{
	vrrp_print_json();
}
#endif

/* This function runs in the parent process. */
static void
delayed_restart_vrrp_child_thread(__attribute__((unused)) thread_ref_t thread)
{
	start_vrrp_child();
}

/* VRRP Child respawning thread. This function runs in the parent process. */
static void
vrrp_respawn_thread(thread_ref_t thread)
{
	unsigned restart_delay;

	/* We catch a SIGCHLD, handle it */
	vrrp_child = 0;

	if (report_child_status(thread->u.c.status, thread->u.c.pid, NULL))
		thread_add_terminate_event(thread->master);
	else if (!__test_bit(DONT_RESPAWN_BIT, &debug)) {
		log_child_died("VRRP", thread->u.c.pid);

		restart_delay = calc_restart_delay(&vrrp_start_time, &vrrp_next_restart_delay, "VRRP");
		if (!restart_delay)
			start_vrrp_child();
		else
			thread_add_timer(thread->master, delayed_restart_vrrp_child_thread, NULL, restart_delay * TIMER_HZ);
	} else {
		log_message(LOG_ALERT, "VRRP child process(%d) died: Exiting", thread->u.c.pid);
		raise(SIGTERM);
	}
}
#endif

#ifdef THREAD_DUMP
static void
register_vrrp_thread_addresses(void)
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

	register_vrrp_if_addresses();
	register_vrrp_scheduler_addresses();
#ifdef _WITH_DBUS_
	register_vrrp_dbus_addresses();
#endif
	register_vrrp_fifo_addresses();
	register_track_file_inotify_addresses();
#ifdef _WITH_TRACK_PROCESS_
	register_process_monitor_addresses();
#endif

#ifndef _ONE_PROCESS_DEBUG_
	register_thread_address("print_vrrp_data", print_vrrp_data);
	register_thread_address("print_vrrp_stats", print_vrrp_stats);
	register_thread_address("reload_vrrp_thread", reload_vrrp_thread);
	register_thread_address("start_vrrp_termination_thread", start_vrrp_termination_thread);
	register_thread_address("send_reload_advert_thread", send_reload_advert_thread);
#endif
	register_thread_address("vrrp_shutdown_backstop_thread", vrrp_shutdown_backstop_thread);
	register_thread_address("vrrp_shutdown_timer_thread", vrrp_shutdown_timer_thread);

#ifndef _ONE_PROCESS_DEBUG_
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
		log_message(LOG_INFO, "VRRP child process: fork error(%s)"
			       , strerror(errno));
		return -1;
	} else if (pid) {
		vrrp_child = pid;
		vrrp_start_time = time_now;

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
	if ((global_data->instance_name || global_data->network_namespace) &&
	    (vrrp_syslog_ident = make_syslog_ident(PROG_VRRP)))
			syslog_ident = vrrp_syslog_ident;
	else
		syslog_ident = PROG_VRRP;

	if (!__test_bit(NO_SYSLOG_BIT, &debug))
		open_syslog(syslog_ident);

#ifdef ENABLE_LOG_TO_FILE
	if (log_file_name)
		open_log_file(log_file_name,
				"vrrp",
				global_data->network_namespace,
				global_data->instance_name);
#endif

#ifdef _MEM_CHECK_
	mem_log_init(PROG_VRRP, "VRRP Child process");
#endif

	free_parent_mallocs_startup(true);

	/* Clear any child finder functions set in parent */
	set_child_finder_name(NULL);

	/* Create an independant file descriptor for the shared config file */
	separate_config_file();

	/* Child process part, write pidfile */
	if (!pidfile_write(vrrp_pidfile, getpid())) {
		/* Fatal error */
		log_message(LOG_INFO, "VRRP child process: cannot write pidfile");
		exit(0);
	}

#ifdef _USE_SYSTEMD_NOTIFY_
	systemd_unset_notify();
#endif

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

#ifndef _ONE_PROCESS_DEBUG_
	/* Signal handling initialization */
	vrrp_signal_init();

	/* Register emergency shutdown function */
	register_shutdown_function(stop_vrrp);
#endif

	/* Start VRRP daemon */
	start_vrrp(NULL);

#ifdef _ONE_PROCESS_DEBUG_
	return 0;
#endif

#ifdef THREAD_DUMP
	register_vrrp_thread_addresses();
#endif

	/* Post initializations */
#ifdef _MEM_CHECK_
	/* Note: there may be a proc_events_ack_timer thread which will not
	 * exist when the same configuration is reloaded. This is a thread_t,
	 * which currently adds 120 bytes to the allocated memory. */
	log_message(LOG_INFO, "Configuration is using : %zu Bytes", mem_allocated);
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
#ifndef _ONE_PROCESS_DEBUG_
	register_thread_address("vrrp_respawn_thread", vrrp_respawn_thread);
	register_thread_address("delayed_restart_vrrp_child_thread", delayed_restart_vrrp_child_thread);
#endif
}
#endif
