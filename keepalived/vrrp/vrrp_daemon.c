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
#include "vrrp_iproute.h"
#include "vrrp_parser.h"
#include "vrrp_data.h"
#include "vrrp.h"
#include "global_data.h"
#include "pidfile.h"
#include "daemon.h"
#include "logger.h"
#include "signals.h"
#include "bitops.h"
#ifdef _WITH_LVS_
  #include "ipvswrapper.h"
#endif
#ifdef _WITH_SNMP_
  #include "vrrp_snmp.h"
#endif
#include "list.h"
#include "main.h"
#include "memory.h"
#include "parser.h"

extern char *vrrp_pidfile;

/* Daemon stop sequence */
static void
stop_vrrp(void)
{
	signal_handler_destroy();

	if (!__test_bit(DONT_RELEASE_VRRP_BIT, &debug))
		shutdown_vrrp_instances();

	/* Clear static entries */
	netlink_rtlist(vrrp_data->static_routes, IPROUTE_DEL);
	netlink_iplist(vrrp_data->static_addresses, IPADDRESS_DEL);

#ifdef _WITH_SNMP_
	if (snmp)
		vrrp_snmp_agent_close();
#endif

	/* Stop daemon */
	pidfile_rm(vrrp_pidfile);

#ifdef _WITH_LVS_
	if (vrrp_ipvs_needed()) {
		/* Clean ipvs related */
		ipvs_stop();
	}
#endif

	/* Clean data */
	free_global_data(global_data);
	vrrp_dispatcher_release(vrrp_data);
	free_vrrp_data(vrrp_data);
	free_vrrp_buffer();
	free_interface_queue();
	kernel_netlink_close();
	thread_destroy_master(master);
	gratuitous_arp_close();
	ndisc_close();

#ifdef _DEBUG_
	keepalived_free_final("VRRP Child process");
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
start_vrrp(void)
{
	/* Initialize sub-system */
	init_interface_queue();
	kernel_netlink_init();
	gratuitous_arp_init();
	ndisc_init();
#ifdef _WITH_SNMP_
	if (!reload && snmp)
		vrrp_snmp_agent_init();
#endif

	/* Parse configuration file */
	global_data = alloc_global_data();
	vrrp_data = alloc_vrrp_data();
	alloc_vrrp_buffer();
	init_data(conf_file, vrrp_init_keywords);
	if (!vrrp_data) {
		stop_vrrp();
		return;
	}

#ifdef _WITH_LVS_
	if (vrrp_ipvs_needed()) {
		/* Initialize ipvs related */
		if (ipvs_start() != IPVS_SUCCESS) {
			stop_vrrp();
			return;
		}
	}
#endif

	if (reload) {
		clear_diff_saddresses();
		clear_diff_sroutes();
		clear_diff_vrrp();
		clear_diff_script();
	}

	/* Complete VRRP initialization */
	if (!vrrp_complete_init()) {
		if (vrrp_ipvs_needed()) {
			stop_vrrp();
		}
		return;
	}

	/* Post initializations */
	log_message(LOG_INFO, "Configuration is using : %lu Bytes", mem_allocated);

	/* Set static entries */
	netlink_iplist(vrrp_data->static_addresses, IPADDRESS_ADD);
	netlink_rtlist(vrrp_data->static_routes, IPROUTE_ADD);

	/* Dump configuration */
	if (__test_bit(DUMP_CONF_BIT, &debug)) {
		dump_global_data(global_data);
		dump_vrrp_data(vrrp_data);
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

	/* Signal handling */
	signal_reset();
	signal_handler_destroy();

	/* Destroy master thread */
	vrrp_dispatcher_release(vrrp_data);
	kernel_netlink_close();
	thread_destroy_master(master);
	master = thread_make_master();
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
	mem_allocated = 0;
	vrrp_signal_init();
	signal_set(SIGCHLD, thread_child_handler, master);
	start_vrrp();

	/* free backup data */
	free_vrrp_data(old_vrrp_data);
	UNSET_RELOAD;

	return 0;
}

void
print_vrrp(FILE *file, vrrp_t *vrrp)
{
	char auth_data[sizeof(vrrp->auth_data) + 1];
	fprintf(file, " VRRP Instance = %s\n", vrrp->iname);
	if (vrrp->family == AF_INET6)
		fprintf(file, "   Using Native IPv6\n");
	if (vrrp->state == VRRP_STATE_BACK) {
		fprintf(file, "   State = BACKUP\n");
		fprintf(file, "   Master router = %s\n",
			inet_sockaddrtos(&vrrp->master_saddr));
	}
	else if (vrrp->state == VRRP_STATE_FAULT)
		fprintf(file, "   State = FAULT\n");
	else if (vrrp->state == VRRP_STATE_MAST)
		fprintf(file, "   State = MASTER\n");
	else
		fprintf(file, "   State = %d\n", vrrp->state);
	fprintf(file, "   Last transition = %ld\n",
		vrrp->last_transition.tv_sec);
	fprintf(file, "   Listening device = %s\n", IF_NAME(vrrp->ifp));
	if (vrrp->dont_track_primary)
		fprintf(file, "   VRRP interface tracking disabled\n");
	if (vrrp->lvs_syncd_if)
		fprintf(file, "   Runing LVS sync daemon on interface = %s\n",
		       vrrp->lvs_syncd_if);
	if (vrrp->garp_delay)
		fprintf(file, "   Gratuitous ARP delay = %d\n",
		       vrrp->garp_delay/TIMER_HZ);
	fprintf(file, "   Virtual Router ID = %d\n", vrrp->vrid);
	fprintf(file, "   Priority = %d\n", vrrp->base_priority);
	fprintf(file, "   Advert interval = %dsec\n",
	       vrrp->adver_int / TIMER_HZ);
	if (vrrp->nopreempt)
		fprintf(file, "   Preempt disabled\n");
	if (vrrp->preempt_delay)
		fprintf(file, "   Preempt delay = %ld secs\n",
		       vrrp->preempt_delay / TIMER_HZ);
	if (vrrp->auth_type) {
		fprintf(file, "   Authentication type = %s\n",
		       (vrrp->auth_type ==
			VRRP_AUTH_AH) ? "IPSEC_AH" : "SIMPLE_PASSWORD");
		/* vrrp->auth_data is not \0 terminated */
		memcpy(auth_data, vrrp->auth_data, sizeof(vrrp->auth_data));
		auth_data[sizeof(vrrp->auth_data)] = '\0';
		fprintf(file, "   Password = %s\n", auth_data);
	}
	//if (!LIST_ISEMPTY(vrrp->track_ifp)) {
	//	fprintf(file, "   Tracked interfaces = %d\n", LIST_SIZE(vrrp->track_ifp));
	//	dump_list(vrrp->track_ifp);
	//}
	//if (!LIST_ISEMPTY(vrrp->track_script)) {
	//	fprintf(file, "   Tracked scripts = %d\n",
	//	       LIST_SIZE(vrrp->track_script));
	//	dump_list(vrrp->track_script);
	//}
	//if (!LIST_ISEMPTY(vrrp->vip)) {
	//	fprintf(file, "   Virtual IP = %d\n", LIST_SIZE(vrrp->vip));
	//	dump_list(vrrp->vip);
	//}
	//if (!LIST_ISEMPTY(vrrp->evip)) {
	//	fprintf(file, "   Virtual IP Excluded = %d\n", LIST_SIZE(vrrp->evip));
	//	dump_list(vrrp->evip);
	//}
	//if (!LIST_ISEMPTY(vrrp->vroutes)) {
	//	fprintf(file, "   Virtual Routes = %d\n", LIST_SIZE(vrrp->vroutes));
	//	dump_list(vrrp->vroutes);
	//}
	if (vrrp->script_backup)
		fprintf(file, "   Backup state transition script = %s\n",
		       vrrp->script_backup);
	if (vrrp->script_master)
		fprintf(file, "   Master state transition script = %s\n",
		       vrrp->script_master);
	if (vrrp->script_fault)
		fprintf(file, "   Fault state transition script = %s\n",
		       vrrp->script_fault);
	if (vrrp->script_stop)
		fprintf(file, "   Stop state transition script = %s\n",
		       vrrp->script_stop);
	if (vrrp->script)
		fprintf(file, "   Generic state transition script = '%s'\n",
		       vrrp->script);
	if (vrrp->smtp_alert)
			fprintf(file, "   Using smtp notification\n");

}

void
print_vgroup(FILE *file, vrrp_sgroup_t *vgroup)
{
	int i;
	char *str;

	fprintf(file, " VRRP Sync Group = %s, %s\n", vgroup->gname,
       		(vgroup->state == VRRP_STATE_MAST) ? "MASTER" : "BACKUP");
	for (i = 0; i < vector_size(vgroup->iname); i++) {
		str = vector_slot(vgroup->iname, i);
		fprintf(file, "   monitor = %s\n", str);
	}
	if (vgroup->script_backup)
		fprintf(file, "   Backup state transition script = %s\n",
		       vgroup->script_backup);
	if (vgroup->script_master)
		fprintf(file, "   Master state transition script = %s\n",
		       vgroup->script_master);
	if (vgroup->script_fault)
		fprintf(file, "   Fault state transition script = %s\n",
		       vgroup->script_fault);
	if (vgroup->script)
		fprintf(file, "   Generic state transition script = '%s\n'",
		       vgroup->script);
	if (vgroup->smtp_alert)
		fprintf(file, "   Using smtp notification\n");

}

int
print_vrrp_data(thread_t * thread)
{
  	FILE *file;
	file = fopen ("/tmp/keepalived.data","w");

        list l = vrrp_data->vrrp;
	element e;
	vrrp_t *vrrp;
	vrrp_sgroup_t *vgroup;
	fprintf(file, "------< VRRP Topology >------\n");
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		print_vrrp(file, vrrp);
	}

	if (!LIST_ISEMPTY(vrrp_data->vrrp_sync_group)) {
		fprintf(file, "------< VRRP Sync groups >------\n");
		l = vrrp_data->vrrp_sync_group;
		for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
			vgroup = ELEMENT_DATA(e);
			print_vgroup(file, vgroup);
		}
	}
        fclose(file);
	return 0;
}

int
print_vrrp_stats(thread_t * thread)
{
  	FILE *file;
	file = fopen ("/tmp/keepalived.stats","w");

	list l = vrrp_data->vrrp;
	element e;
	vrrp_t *vrrp;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		fprintf(file, "VRRP Instance: %s\n", vrrp->iname);
		fprintf(file, "  Advertisements:\n");
		fprintf(file, "    Received: %d\n", vrrp->stats->advert_rcvd);
		fprintf(file, "    Sent: %d\n", vrrp->stats->advert_sent);
		fprintf(file, "  Became master: %d\n", vrrp->stats->become_master);
		fprintf(file, "  Released master: %d\n",
			vrrp->stats->release_master);
		fprintf(file, "  Packet Errors:\n");
		fprintf(file, "    Length: %d\n", vrrp->stats->packet_len_err);
		fprintf(file, "    TTL: %d\n", vrrp->stats->ip_ttl_err);
		fprintf(file, "    Invalide Type: %d\n",
			vrrp->stats->invalid_type_rcvd);
		fprintf(file, "    Advertisement Interval: %d\n",
			vrrp->stats->advert_interval_err);
		fprintf(file, "    Address List: %d\n",
			vrrp->stats->addr_list_err);
		fprintf(file, "  Authentication Errors:\n");
		fprintf(file, "    Invalid Type: %d\n",
			vrrp->stats->invalid_authtype);
		fprintf(file, "    Type Mismatch: %d\n",
			vrrp->stats->authtype_mismatch);
		fprintf(file, "    Failure: %d\n",
			vrrp->stats->auth_failure);
		fprintf(file, "  Priority Zero:\n");
		fprintf(file, "    Received: %d\n", vrrp->stats->pri_zero_rcvd);
		fprintf(file, "    Sent: %d\n", vrrp->stats->pri_zero_sent);
	}

	fclose(file);
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
	signal_handler_destroy();
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
