/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        VRRP child process handling.
 *
 * Version:     $Id: vrrp_daemon.c,v 1.1.1 2003/07/24 22:36:16 acassen Exp $
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
 */

#include "vrrp_daemon.h"
#include "vrrp_scheduler.h"
#include "vrrp_if.h"
#include "vrrp_arp.h"
#include "vrrp_netlink.h"
#include "vrrp_ipaddress.h"
#include "vrrp_iproute.h"
#include "vrrp_parser.h"
#include "vrrp_data.h"
#include "vrrp.h"
#include "global_data.h"
#include "pidfile.h"
#include "daemon.h"
#include "list.h"
#include "memory.h"
#include "parser.h"
#include "watchdog.h"

/* Global vars */
vrrp_conf_data *vrrp_data;
vrrp_conf_data *old_vrrp_data;
int vrrp_wdog_sd = -1;

/* VRRP watchdog data */
wdog_data vrrp_wdog_data = {
	"VRRP Child",
	WDOG_VRRP,
	-1,
	-1,
	start_vrrp_child
};

/* Externals vars */
extern thread_master *master;
extern conf_data *data;
extern unsigned int debug;
extern int reload;
extern pid_t vrrp_child;
extern char *conf_file;
extern int wdog_delay_vrrp;

/* Daemon stop sequence */
static void
stop_vrrp(void)
{
	/* Destroy master thread */
	thread_destroy_master(master);

	/* Clear static entries */
	netlink_iplist_ipv4(vrrp_data->static_addresses, IPADDRESS_DEL);
	netlink_rtlist_ipv4(vrrp_data->static_routes, IPROUTE_DEL);

	if (!(debug & 8))
		shutdown_vrrp_instances();
	free_interface_queue();
	gratuitous_arp_close();

	/* Stop daemon */
	pidfile_rm(VRRP_PID_FILE);

	/* Clean data */
	free_global_data(data);
	free_vrrp_data(vrrp_data);

#ifdef _DEBUG_
	keepalived_free_final("VRRP Child process");
#endif

	/* free watchdog sd */
	wdog_close(vrrp_wdog_sd, WDOG_VRRP);

	/*
	 * Reached when terminate signal catched.
	 * finally return to parent process.
	 */
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
	if_mii_poller_init();
	gratuitous_arp_init();

	/* Parse configuration file */
	data = alloc_global_data();
	vrrp_data = alloc_vrrp_data();
	init_data(conf_file, vrrp_init_keywords);
	if (!vrrp_data) {
		stop_vrrp();
		return;
	}

	if (reload) {
		clear_diff_saddresses();
		clear_diff_sroutes();
		clear_diff_vrrp();
	}

	/* Complete VRRP initialization */
	if (!vrrp_complete_init()) {
		stop_vrrp();
		return;
	}

	/* Post initializations */
	syslog(LOG_INFO, "Configuration is using : %lu Bytes", mem_allocated);

	/* Set static entries */
	netlink_iplist_ipv4(vrrp_data->static_addresses, IPADDRESS_ADD);
	netlink_rtlist_ipv4(vrrp_data->static_routes, IPROUTE_ADD);

	/* Dump configuration */
	if (debug & 4) {
		dump_global_data(data);
		dump_vrrp_data(vrrp_data);
	}

	/* Init & start the VRRP packet dispatcher */
	thread_add_event(master, vrrp_dispatcher_init, NULL,
			 VRRP_DISPATCHER);
}

/* Reload handler */
int
reload_vrrp_thread(thread * thread)
{
	/* set the reloading flag */
	SET_RELOAD;

	/* Destroy master thread */
	thread_destroy_master(master);
	master = thread_make_master();
	free_global_data(data);
	free_interface_queue();
	gratuitous_arp_close();

	/* Save previous conf data */
	old_vrrp_data = vrrp_data;
	vrrp_data = NULL;

	/* Reload the conf */
	mem_allocated = 0;
	start_vrrp();

	/* free backup data */
	free_vrrp_data(old_vrrp_data);
	UNSET_RELOAD;

	return 0;
}

/* Reload handler */
void
sighup_vrrp(int sig)
{
	syslog(LOG_INFO, "Reloading VRRP child process on signal");
	thread_add_event(master, reload_vrrp_thread, NULL, 0);
}

/* Terminate handler */
void
sigend_vrrp(int sig)
{
	syslog(LOG_INFO, "Terminating VRRP child process on signal");
	thread_add_terminate_event(master);
}

/* VRRP Child signal handling */
void
vrrp_signal_init(void)
{
	signal_set(SIGHUP, sighup_vrrp);
	signal_set(SIGINT, sigend_vrrp);
	signal_set(SIGTERM, sigend_vrrp);
	signal_set(SIGKILL, sigend_vrrp);
	signal_noignore_sigchld();
}

/* Register VRRP thread */
int
start_vrrp_child(void)
{
	pid_t pid;

	/* Dont start if pid is already running */
	if (vrrp_running()) {
		syslog(LOG_INFO, "VRRP child process already running");
		return -1;
	}

	/* Initialize child process */
	pid = fork();

	if (pid < 0) {
		syslog(LOG_INFO, "VRRP child process: fork error(%s)"
			       , strerror(errno));
		return -1;
	} else if (pid) {
		int poll_delay = (wdog_delay_vrrp) ? wdog_delay_vrrp : WATCHDOG_DELAY;
		vrrp_child = pid;
		syslog(LOG_INFO, "Starting VRRP child process, pid=%d"
			       , pid);
		/* Connect child watchdog */
		vrrp_wdog_data.wdog_pid = pid;
		thread_add_timer(master, wdog_boot_thread, &vrrp_wdog_data,
				 poll_delay);
		return 0;
	}

	/* Opening local VRRP syslog channel */
	openlog(PROG_VRRP, LOG_PID | (debug & 1) ? LOG_CONS : 0, LOG_LOCAL1);

	/* Child process part, write pidfile */
	if (!pidfile_write(VRRP_PID_FILE, getpid())) {
		/* Fatal error */
		syslog(LOG_INFO, "VRRP child process: cannot write pidfile");
		exit(0);
	}

	/* Create the new master thread */
	thread_destroy_master(master);
	master = thread_make_master();

	/* Signal handling initialization */
	vrrp_signal_init();

	/* change to / dir */
	chdir("/");

	/* Set mask */
	umask(0);

	/* Start VRRP daemon */
	start_vrrp();

	/* Register vrrp software watchdog */
	vrrp_wdog_sd = wdog_init(WDOG_VRRP);

	/* Launch the scheduling I/O multiplexer */
	launch_scheduler();

	/* Finish VRRP daemon process */
	stop_vrrp();
	exit(0);
}
