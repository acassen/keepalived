/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Sheduling framework for vrrp code.
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

#include "vrrp_scheduler.h"
#include "vrrp_ipsecah.h"
#include "vrrp_if.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_vmac.h"
#endif
#include "vrrp.h"
#include "vrrp_sync.h"
#include "vrrp_notify.h"
#include "vrrp_netlink.h"
#include "vrrp_data.h"
#include "vrrp_index.h"
#include "vrrp_arp.h"
#include "vrrp_ndisc.h"
#include "vrrp_if.h"
#include "ipvswrapper.h"
#include "memory.h"
#include "notify.h"
#include "list.h"
#include "logger.h"
#include "timer.h"
#include "main.h"
#include "smtp.h"
#include "signals.h"
#include "bitops.h"
#ifdef _WITH_SNMP_
#include "vrrp_snmp.h"
#endif
#include <netinet/ip.h>

/* global vars */
timeval_t garp_next_time;
thread_t *garp_thread;

/* VRRP FSM (Finite State Machine) design.
 *
 * The state transition diagram implemented is :
 *
 *                         +---------------+
 *        +----------------|               |----------------+
 *        |                |     Fault     |                |
 *        |  +------------>|               |<------------+  |
 *        |  |             +---------------+             |  |
 *        |  |                     |                     |  |
 *        |  |                     V                     |  |
 *        |  |             +---------------+             |  |
 *        |  |  +--------->|               |<---------+  |  |
 *        |  |  |          |  Initialize   |          |  |  |
 *        |  |  |  +-------|               |-------+  |  |  |
 *        |  |  |  |       +---------------+       |  |  |  |
 *        |  |  |  |                               |  |  |  |
 *        V  |  |  V                               V  |  |  V
 *     +---------------+                       +---------------+
 *     |               |---------------------->|               |
 *     |    Master     |                       |    Backup     |
 *     |               |<----------------------|               |
 *     +---------------+                       +---------------+
 */
static void vrrp_backup(vrrp_t *, char *, ssize_t);
static void vrrp_leave_master(vrrp_t *, char *, ssize_t);
static void vrrp_leave_fault(vrrp_t *, char *, ssize_t);
static void vrrp_become_master(vrrp_t *, char *, ssize_t);

static void vrrp_goto_master(vrrp_t *);
static void vrrp_master(vrrp_t *);
static void vrrp_fault(vrrp_t *);

static int vrrp_update_priority(thread_t * thread);
static int vrrp_script_child_timeout_thread(thread_t * thread);
static int vrrp_script_child_thread(thread_t * thread);
static int vrrp_script_thread(thread_t * thread);

static int vrrp_read_dispatcher_thread(thread_t *);

static struct {
	void (*read) (vrrp_t *, char *, ssize_t);
	void (*read_timeout) (vrrp_t *);
} VRRP_FSM[VRRP_MAX_FSM_STATE + 1] =
{
/*    Stream Read Handlers      |    Stream Read_to handlers   *
 *------------------------------+------------------------------*/
	{NULL,				NULL},
	{vrrp_backup,			vrrp_goto_master},	/*  BACKUP          */
	{vrrp_leave_master,		vrrp_master},		/*  MASTER          */
	{vrrp_leave_fault,		vrrp_fault},		/*  FAULT           */
	{vrrp_become_master,		vrrp_goto_master}	/*  GOTO_MASTER     */
};

/* VRRP TSM (Transition State Matrix) design.
 *
 * Introducing the Synchronization extension to VRRP
 * protocol, introduce the need for a transition machinery.
 * This mecanism can be designed using a diagonal matrix.
 * We call this matrix the VRRP TSM:
 *
 *   \ E |  B  |  M  |  F  |
 *   S \ |     |     |     |
 * ------+-----+-----+-----+     Legend:
 *   B   |  x     1     2  |       B: VRRP BACKUP state
 * ------+                 |       M: VRRP MASTER state
 *   M   |  3     x     4  |       F: VRRP FAULT state
 * ------+                 |       S: VRRP start state (before transition)
 *   F   |  5     6     x  |       E: VRRP end state (after transition)
 * ------+-----------------+       [1..6]: Handler functions.
 *
 * So we have have to implement n(n-1) handlers in order to deal with
 * all transitions possible. This matrix defines the maximum handlers
 * to implement for having the most time optimized transition machine.
 * For example:
 *     . The handler (1) will sync all the BACKUP VRRP instances of a
 *       group to MASTER state => we will call it vrrp_sync_master.
 *     .... and so on for all other state ....
 *
 * This matrix is the strict implementation way. For readability and
 * performance we have implemented some handlers directly into the VRRP
 * FSM. For instance the handlers (5) & (6) are directly into the VRRP
 * FSM since it will speed up convergence to init state.
 * Additionnaly, we have implemented some other handlers into the matrix
 * in order to speed up group synchronization takeover. For instance
 * transitions :
 *    o B->B: To catch wantstate MASTER transition to force sync group
 *            to this transition state too.
 *    o F->F: To speed up FAULT state transition if group is not already
 *            synced to FAULT state.
 */
static struct {
	void (*handler) (vrrp_t *);
} VRRP_TSM[VRRP_MAX_TSM_STATE + 1][VRRP_MAX_TSM_STATE + 1] =
{
  { {NULL}, {NULL},                      {NULL},             {NULL}            },
  { {NULL}, {vrrp_sync_master_election}, {vrrp_sync_master}, {vrrp_sync_fault} },
  { {NULL}, {vrrp_sync_backup},          {vrrp_sync_master}, {vrrp_sync_fault} },
  { {NULL}, {vrrp_sync_backup},          {vrrp_sync_master}, {vrrp_sync_fault} }
};

/* SMTP alert notifier */
static void
vrrp_smtp_notifier(vrrp_t * vrrp)
{
	if (vrrp->smtp_alert) {
		if (vrrp->state == VRRP_STATE_MAST)
			smtp_alert(NULL, vrrp, NULL,
				   "Entering MASTER state",
				   "=> VRRP Instance is now owning VRRP VIPs <=");
		if (vrrp->state == VRRP_STATE_BACK)
			smtp_alert(NULL, vrrp, NULL,
				   "Entering BACKUP state",
				   "=> VRRP Instance is nolonger owning VRRP VIPs <=");
	}
}

/* Log interface message */
static void vrrp_log_int_down(vrrp_t *vrrp)
{
	if (!IF_ISUP(vrrp->ifp))
		log_message(LOG_INFO, "Kernel is reporting: interface %s DOWN",
		       IF_NAME(vrrp->ifp));
	if (!LIST_ISEMPTY(vrrp->track_ifp))
		vrrp_log_tracked_down(vrrp->track_ifp);
}

static void vrrp_log_int_up(vrrp_t *vrrp)
{
	if (IF_ISUP(vrrp->ifp))
		log_message(LOG_INFO, "Kernel is reporting: interface %s UP",
		       IF_NAME(vrrp->ifp));
	if (!LIST_ISEMPTY(vrrp->track_ifp))
		log_message(LOG_INFO, "Kernel is reporting: tracked interface are UP");
}

/*
 * Initialize state handling
 * --rfc2338.6.4.1
 */
static void
vrrp_init_state(list l)
{
	vrrp_t *vrrp;
	vrrp_sgroup_t *vgroup;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		/* The effective priority is never changed for PRIO_OWNER */
		if (vrrp->base_priority != VRRP_PRIO_OWNER) {
			/* In case of VRRP SYNC, we have to carefully check that we are
			 * not running floating priorities on any VRRP instance, or they
			 * are all running with the same tracking conf.
			 */
			if (vrrp->sync && !vrrp->sync->global_tracking) {
				element e2;
				tracked_sc_t *sc;
				tracked_if_t *tip;
				bool int_warning = false;
				bool script_warning = false;

				if (!LIST_ISEMPTY(vrrp->track_ifp)) {
					for (e2 = LIST_HEAD(vrrp->track_ifp); e2; ELEMENT_NEXT(e2)) {
						tip = ELEMENT_DATA(e2);
						if (tip->weight) {
							tip->weight = 0;
							int_warning = true;
						}
					}
				}

				if (!LIST_ISEMPTY(vrrp->track_script)) {
					for (e2 = LIST_HEAD(vrrp->track_script); e2; ELEMENT_NEXT(e2)) {
						sc = ELEMENT_DATA(e2);
						if (sc->weight) {
							sc->scr->inuse--;
							script_warning = true;
						}
					}
				}

				if (int_warning)
					log_message(LOG_INFO, "VRRP_Instance(%s) : ignoring weights of "
							 "tracked interface due to SYNC group", vrrp->iname);
				if (script_warning)
					log_message(LOG_INFO, "VRRP_Instance(%s) : ignoring "
							 "tracked script with weights due to SYNC group", vrrp->iname);
			} else {
				/* Register new priority update thread */
				thread_add_timer(master, vrrp_update_priority,
						 vrrp, vrrp->master_adver_int);
			}
		}

		if (vrrp->wantstate == VRRP_STATE_MAST
			|| vrrp->wantstate == VRRP_STATE_GOTO_MASTER) {
#ifdef _WITH_LVS_
			/* Check if sync daemon handling is needed */
			if (global_data->lvs_syncd.ifname &&
			    global_data->lvs_syncd.vrrp == vrrp)
				ipvs_syncd_cmd(IPVS_STARTDAEMON,
					       &global_data->lvs_syncd,
					       IPVS_MASTER,
					       false,
					       false);
#endif
#ifdef _WITH_SNMP_RFCV3_
			vrrp->stats->master_reason = VRRPV3_MASTER_REASON_PREEMPTED;
#endif
			vrrp->state = VRRP_STATE_GOTO_MASTER;
		} else {
			vrrp->ms_down_timer = 3 * vrrp->adver_int
			    + VRRP_TIMER_SKEW(vrrp);
#ifdef _WITH_LVS_
			/* Check if sync daemon handling is needed */
			if (global_data->lvs_syncd.ifname &&
			    global_data->lvs_syncd.vrrp == vrrp)
				ipvs_syncd_cmd(IPVS_STARTDAEMON,
					       &global_data->lvs_syncd,
					       IPVS_BACKUP,
					       false,
					       false);
#endif
			log_message(LOG_INFO, "VRRP_Instance(%s) Entering BACKUP STATE",
			       vrrp->iname);

			/* Set BACKUP state */
			vrrp_restore_interface(vrrp, false, false);
			vrrp->state = VRRP_STATE_BACK;
			vrrp_smtp_notifier(vrrp);
			notify_instance_exec(vrrp, VRRP_STATE_BACK);
#ifdef _WITH_SNMP_KEEPALIVED_
			vrrp_snmp_instance_trap(vrrp);
#endif
			vrrp->last_transition = timer_now();

			/* Init group if needed  */
			if ((vgroup = vrrp->sync)) {
				if (GROUP_STATE(vgroup) != VRRP_STATE_BACK) {
					vgroup->state = VRRP_STATE_BACK;
					vrrp_sync_smtp_notifier(vgroup);
					notify_group_exec(vgroup, VRRP_STATE_BACK);
#ifdef _WITH_SNMP_KEEPALIVED_
					vrrp_snmp_group_trap(vgroup);
#endif
				}
			}
		}
#ifdef _WITH_SNMP_RFC_
		vrrp->stats->uptime = timer_now();
#endif
	}
}

static void
vrrp_init_sands(list l)
{
	vrrp_t *vrrp;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		vrrp_init_instance_sands(vrrp);
	}
}

/* if run after vrrp_init_state(), it will be able to detect scripts that
 * have been disabled because of a sync group and will avoid to start them.
 */
static void
vrrp_init_script(list l)
{
	vrrp_script_t *vscript;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vscript = ELEMENT_DATA(e);
		if (vscript->insecure) {
			/* The script cannot be run for security reasons */
			vscript->result = vscript->rise;
		}
		else if (!vscript->inuse)
			vscript->result = VRRP_SCRIPT_STATUS_DISABLED;
		else {
			switch (vscript->result) {
			case VRRP_SCRIPT_STATUS_INIT:
				vscript->result = vscript->rise - 1; /* one success is enough */
				break;
			case VRRP_SCRIPT_STATUS_INIT_GOOD:
				vscript->result = vscript->rise; /* one failure is enough */
				break;
			case VRRP_SCRIPT_STATUS_INIT_FAILED:
				vscript->result = 0; /* assume failed by config */
				break;
			}

			thread_add_event(master, vrrp_script_thread, vscript, (int)vscript->interval);
		}
	}
}

/* Timer functions */
static timeval_t
vrrp_compute_timer(const int fd)
{
	vrrp_t *vrrp;
	element e;
	list l = &vrrp_data->vrrp_index_fd[fd%1024 + 1];
	timeval_t timer;

	/* Multiple instances on the same interface */
	timer_reset(timer);
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (timer_cmp(vrrp->sands, timer) < 0 ||
		    timer_isnull(timer))
			timer = timer_dup(vrrp->sands);
	}

	return timer;
}

static unsigned long
vrrp_timer_fd(const int fd)
{
	timeval_t timer;

	timer = vrrp_compute_timer(fd);
// TODO - if the result of the following test is -ve, then a thread has already expired
// and so shouldn't we run straight away? Or else ignore timers in past and take the next
// one in the future?
	if (timer_cmp(timer, time_now) < 0)
		return TIMER_MAX_SEC;

	return timer_long(timer_sub(timer, time_now));
}

static int
vrrp_timer_vrid_timeout(const int fd)
{
	vrrp_t *vrrp;
	element e;
	list l = &vrrp_data->vrrp_index_fd[fd%1024 + 1];
	timeval_t timer;
	int vrid = 0;

	/* Multiple instances on the same interface */
	timer_reset(timer);
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (timer_cmp(vrrp->sands, timer) < 0 ||
		    timer_isnull(timer)) {
			timer = timer_dup(vrrp->sands);
			vrid = vrrp->vrid;
		}
	}
	return vrid;
}

/* Thread functions */
static void
vrrp_register_workers(list l)
{
	sock_t *sock;
	timeval_t timer;
	unsigned long vrrp_timer = 0;
	element e;

	/* Init compute timer */
	memset(&timer, 0, sizeof (struct timeval));

	/* Init the VRRP instances state */
	vrrp_init_state(vrrp_data->vrrp);

	/* Init VRRP instances sands */
	vrrp_init_sands(vrrp_data->vrrp);

	/* Init VRRP tracking scripts */
	if (!LIST_ISEMPTY(vrrp_data->vrrp_script))
		vrrp_init_script(vrrp_data->vrrp_script);

	/* Register VRRP workers threads */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		sock = ELEMENT_DATA(e);
		/* jump to asynchronous handling */
		vrrp_timer = vrrp_timer_fd(sock->fd_in);

		/* Register a timer thread if interface is shut */
		if (sock->fd_in == -1)
			sock->thread = thread_add_timer(master, vrrp_read_dispatcher_thread,
							sock, vrrp_timer);
		else
			sock->thread = thread_add_read(master, vrrp_read_dispatcher_thread,
						       sock, sock->fd_in, vrrp_timer);
	}
}

/* VRRP dispatcher functions */
static int
already_exist_sock(list l, sa_family_t family, int proto, ifindex_t ifindex, bool unicast)
{
	sock_t *sock;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		sock = ELEMENT_DATA(e);
		if ((sock->family == family)	&&
		    (sock->proto == proto)	&&
		    (sock->ifindex == ifindex)	&&
		    (sock->unicast == unicast))
			return 1;
	}
	return 0;
}

static void
alloc_sock(sa_family_t family, list l, int proto, ifindex_t ifindex, bool unicast)
{
	sock_t *new;

	new = (sock_t *)MALLOC(sizeof (sock_t));
	new->family = family;
	new->proto = proto;
	new->ifindex = ifindex;
	new->unicast = unicast;

	list_add(l, new);
}

static void
vrrp_create_sockpool(list l)
{
	vrrp_t *vrrp;
	list p = vrrp_data->vrrp;
	element e;
	ifindex_t ifindex;
	int proto;
	bool unicast;

	for (e = LIST_HEAD(p); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		ifindex =
#ifdef _HAVE_VRRP_VMAC_
			  (__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags)) ? IF_BASE_INDEX(vrrp->ifp) :
#endif
										    IF_INDEX(vrrp->ifp);
		unicast = !LIST_ISEMPTY(vrrp->unicast_peer);
#if defined _WITH_VRRP_AUTH_
		if (vrrp->version == VRRP_VERSION_2 && vrrp->auth_type == VRRP_AUTH_AH)
			proto = IPPROTO_IPSEC_AH;
		else
#endif
			proto = IPPROTO_VRRP;

		/* add the vrrp element if not exist */
		if (!already_exist_sock(l, vrrp->family, proto, ifindex, unicast))
			alloc_sock(vrrp->family, l, proto, ifindex, unicast);
	}
}

static void
vrrp_open_sockpool(list l)
{
	sock_t *sock;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		sock = ELEMENT_DATA(e);
		sock->fd_in = open_vrrp_read_socket(sock->family, sock->proto,
					       sock->ifindex, sock->unicast);
		if (sock->fd_in == -1)
			sock->fd_out = -1;
		else
			sock->fd_out = open_vrrp_send_socket(sock->family, sock->proto,
							     sock->ifindex, sock->unicast);
	}
}

static void
vrrp_set_fds(list l)
{
	sock_t *sock;
	vrrp_t *vrrp;
	list p = vrrp_data->vrrp;
	element e_sock;
	element e_vrrp;
	int proto;
	ifindex_t ifindex;
	bool unicast;

	for (e_sock = LIST_HEAD(l); e_sock; ELEMENT_NEXT(e_sock)) {
		sock = ELEMENT_DATA(e_sock);
		for (e_vrrp = LIST_HEAD(p); e_vrrp; ELEMENT_NEXT(e_vrrp)) {
			vrrp = ELEMENT_DATA(e_vrrp);
			ifindex =
#ifdef _HAVE_VRRP_VMAC_
				  (__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags)) ? IF_BASE_INDEX(vrrp->ifp) :
#endif
											    IF_INDEX(vrrp->ifp);
			unicast = !LIST_ISEMPTY(vrrp->unicast_peer);
#if defined _WITH_VRRP_AUTH_
			if (vrrp->version == VRRP_VERSION_2 && vrrp->auth_type == VRRP_AUTH_AH)
				proto = IPPROTO_IPSEC_AH;
			else
#endif
				proto = IPPROTO_VRRP;

			if ((sock->ifindex == ifindex)	&&
			    (sock->family == vrrp->family) &&
			    (sock->proto == proto)	&&
			    (sock->unicast == unicast)) {
				vrrp->fd_in = sock->fd_in;
				vrrp->fd_out = sock->fd_out;

				/* append to hash index */
				alloc_vrrp_fd_bucket(vrrp);
			}
		}
	}
}

/*
 * We create & allocate a socket pool here. The soft design
 * can be sum up by the following sketch :
 *
 *    fd1  fd2    fd3  fd4          fdi  fdi+1
 * -----\__/--------\__/---........---\__/---
 *    | ETH0 |    | ETH1 |          | ETHn |
 *    +------+    +------+          +------+
 *
 * Here we have n physical NIC. Each NIC own a maximum of 2 fds.
 * (one for VRRP the other for IPSEC_AH). All our VRRP instances
 * are multiplexed through this fds. So our design can handle 2*n
 * multiplexing points.
 */
int
vrrp_dispatcher_init(__attribute__((unused)) thread_t * thread)
{
	/* create the VRRP socket pool list */
	vrrp_create_sockpool(vrrp_data->vrrp_socket_pool);

	/* open the VRRP socket pool */
	vrrp_open_sockpool(vrrp_data->vrrp_socket_pool);

	/* set VRRP instance fds to sockpool */
	vrrp_set_fds(vrrp_data->vrrp_socket_pool);

	/* register read dispatcher worker thread */
	vrrp_register_workers(vrrp_data->vrrp_socket_pool);

	/* Dump socket pool */
	if (__test_bit(LOG_DETAIL_BIT, &debug))
		dump_list(vrrp_data->vrrp_socket_pool);
	return 1;
}

void
vrrp_dispatcher_release(vrrp_data_t *data)
{
	free_list(&data->vrrp_socket_pool);
}

static void
vrrp_backup(vrrp_t * vrrp, char *buffer, ssize_t len)
{
	struct iphdr *iph;
	ipsec_ah_t *ah;

	if (vrrp->family == AF_INET) {
		iph = (struct iphdr *) buffer;

		if (iph->protocol == IPPROTO_IPSEC_AH) {
			ah = (ipsec_ah_t *) (buffer + sizeof (struct iphdr));
			if (ntohl(ah->seq_number) >= vrrp->ipsecah_counter->seq_number)
				vrrp->ipsecah_counter->cycle = 0;
		}
	}

	if (!VRRP_ISUP(vrrp)) {
		vrrp_log_int_down(vrrp);
		log_message(LOG_INFO, "VRRP_Instance(%s) Now in FAULT state",
		       vrrp->iname);
		if (vrrp->state != VRRP_STATE_FAULT) {
			notify_instance_exec(vrrp, VRRP_STATE_FAULT);
			vrrp->state = VRRP_STATE_FAULT;
#ifdef _WITH_SNMP_KEEPALIVED_
			vrrp_snmp_instance_trap(vrrp);
#endif
		}
	} else {
		vrrp_state_backup(vrrp, buffer, len);
	}
}

static void
vrrp_become_master(vrrp_t * vrrp, char *buffer, __attribute__((unused)) ssize_t len)
{
	struct iphdr *iph;
	ipsec_ah_t *ah;

	if (vrrp->family == AF_INET) {
		iph = (struct iphdr *) buffer;

		/*
		 * If we are in IPSEC AH mode, we must be sync
		 * with the remote IPSEC AH VRRP instance counter.
		 */
		if (vrrp->version == VRRP_VERSION_2 && iph->protocol == IPPROTO_IPSEC_AH) {
			log_message(LOG_INFO, "VRRP_Instance(%s) IPSEC-AH : seq_num sync",
			       vrrp->iname);
			ah = (ipsec_ah_t *) (buffer + sizeof (struct iphdr));
			vrrp->ipsecah_counter->seq_number = ntohl(ah->seq_number) + 1;
			vrrp->ipsecah_counter->cycle = 0;
		}
	}

	/* Then jump to master state */
	vrrp->wantstate = VRRP_STATE_MAST;
	vrrp_state_goto_master(vrrp);
}

static void
vrrp_leave_master(vrrp_t * vrrp, char *buffer, ssize_t len)
{
	if (!VRRP_ISUP(vrrp)) {
		vrrp_log_int_down(vrrp);
		vrrp->wantstate = VRRP_STATE_GOTO_FAULT;
		vrrp_state_leave_master(vrrp);
	} else if (vrrp_state_master_rx(vrrp, buffer, len)) {
		vrrp_state_leave_master(vrrp);
		vrrp_smtp_notifier(vrrp);
	}
}

#ifdef _WITH_VRRP_AUTH_
static void
vrrp_ah_sync(vrrp_t *vrrp)
{
	/*
	 * Transition to BACKUP state for AH
	 * seq number synchronization.
	 */
	log_message(LOG_INFO, "VRRP_Instance(%s) in FAULT state jump to AH sync",
	       vrrp->iname);
	vrrp->wantstate = VRRP_STATE_BACK;
	vrrp_state_leave_master(vrrp);
}
#endif

static void
vrrp_leave_fault(vrrp_t * vrrp, char *buffer, ssize_t len)
{
	if (!VRRP_ISUP(vrrp))
		return;

	if (vrrp_state_fault_rx(vrrp, buffer, len) == VRRP_STATE_MAST) {
		if (!vrrp->sync || vrrp_sync_leave_fault(vrrp)) {
			log_message(LOG_INFO,
			       "VRRP_Instance(%s) prio is higher than received advert",
			       vrrp->iname);
			vrrp_become_master(vrrp, buffer, len);
#ifdef _WITH_SNMP_RFC_
#ifdef _WITH_SNMP_RFCV3_
			vrrp->stats->master_reason = VRRPV3_MASTER_REASON_PREEMPTED;
#endif
			vrrp->stats->uptime = timer_now();
#endif
		}
	} else {
		if (!vrrp->sync || vrrp_sync_leave_fault(vrrp)) {
			log_message(LOG_INFO, "VRRP_Instance(%s) Entering BACKUP STATE",
			       vrrp->iname);
			vrrp->state = VRRP_STATE_BACK;
			vrrp_smtp_notifier(vrrp);
			notify_instance_exec(vrrp, VRRP_STATE_BACK);
#ifdef _WITH_SNMP_KEEPALIVED_
			vrrp_snmp_instance_trap(vrrp);
#endif
			vrrp->last_transition = timer_now();
#ifdef _WITH_SNMP_RFC_
			vrrp->stats->uptime = vrrp->last_transition;
#endif
		}
	}
}

static void
vrrp_goto_master(vrrp_t * vrrp)
{
	if (!VRRP_ISUP(vrrp)) {
		vrrp_log_int_down(vrrp);
		log_message(LOG_INFO, "VRRP_Instance(%s) Now in FAULT state",
		       vrrp->iname);
		if (vrrp->state != VRRP_STATE_FAULT)
			notify_instance_exec(vrrp, VRRP_STATE_FAULT);
		vrrp->state = VRRP_STATE_FAULT;
		vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
		notify_instance_exec(vrrp, VRRP_STATE_FAULT);
#ifdef _WITH_SNMP_KEEPALIVED_
		vrrp_snmp_instance_trap(vrrp);
#endif
		vrrp->last_transition = timer_now();

		return;
	}

#if defined _WITH_VRRP_AUTH_
	/* If becoming MASTER in IPSEC AH AUTH, we reset the anti-replay */
	if (vrrp->version == VRRP_VERSION_2 && vrrp->ipsecah_counter->cycle) {
		vrrp->ipsecah_counter->cycle = 0;
		vrrp->ipsecah_counter->seq_number = 0;
	}
#endif

#ifdef _WITH_SNMP_RFCV3_
	if ((vrrp->version == VRRP_VERSION_2 && vrrp->ms_down_timer >= 3 * vrrp->adver_int) ||
	    (vrrp->version == VRRP_VERSION_3 && vrrp->ms_down_timer >= 3 * vrrp->master_adver_int))
		vrrp->stats->master_reason = VRRPV3_MASTER_REASON_MASTER_NO_RESPONSE;
#endif
	/* handle master state transition */
	vrrp->wantstate = VRRP_STATE_MAST;
	vrrp_state_goto_master(vrrp);
}

/* Delayed gratuitous ARP thread */
static int
vrrp_gratuitous_arp_thread(thread_t * thread)
{
	vrrp_t *vrrp = THREAD_ARG(thread);

	/* Simply broadcast the gratuitous ARP */
	vrrp_send_link_update(vrrp, vrrp->garp_rep);

	return 0;
}

/* Delayed gratuitous ARP thread after receiving a lower priority advert */
int
vrrp_lower_prio_gratuitous_arp_thread(thread_t * thread)
{
	vrrp_t *vrrp = THREAD_ARG(thread);

	/* Simply broadcast the gratuitous ARP */
	vrrp_send_link_update(vrrp, vrrp->garp_lower_prio_rep);

	return 0;
}

/* Set effective priorty, issue message on changes */
void
vrrp_set_effective_priority(vrrp_t *vrrp, uint8_t new_prio)
{
	if (vrrp->effective_priority == new_prio)
		return;

	log_message(LOG_INFO, "VRRP_Instance(%s) Changing effective priority from %d to %d",
		    vrrp->iname, vrrp->effective_priority, new_prio);

	vrrp->effective_priority = new_prio;
}


/* Update VRRP effective priority based on multiple checkers.
 * This is a thread which is executed every master_adver_int
 * unless the vrrp instance is part of a sync group and there
 * isn't global tracking for the group.
 */
static int
vrrp_update_priority(thread_t * thread)
{
	vrrp_t *vrrp = THREAD_ARG(thread);
	int prio_offset, new_prio;

	/* compute prio_offset right here */
	prio_offset = 0;

	/* Now we will sum the weights of all interfaces which are tracked. */
	if (!LIST_ISEMPTY(vrrp->track_ifp))
		 prio_offset += vrrp_tracked_weight(vrrp->track_ifp);

	/* Now we will sum the weights of all scripts which are tracked. */
	if (!LIST_ISEMPTY(vrrp->track_script))
		prio_offset += vrrp_script_weight(vrrp->track_script);

	/* WARNING! we must compute new_prio on a signed int in order
	   to detect overflows and avoid wrapping. */
	new_prio = vrrp->base_priority + prio_offset;
	if (new_prio < 1)
		new_prio = 1;
	else if (new_prio >= VRRP_PRIO_OWNER)
		new_prio = VRRP_PRIO_OWNER - 1;
	vrrp_set_effective_priority(vrrp, (uint8_t)new_prio);

	/* Register next priority update thread */
	thread_add_timer(master, vrrp_update_priority, vrrp, vrrp->master_adver_int);
	return 0;
}

static void
vrrp_master(vrrp_t * vrrp)
{
	/* Check if interface we are running on is UP */
	if (vrrp->wantstate != VRRP_STATE_GOTO_FAULT) {
		if (!VRRP_ISUP(vrrp)) {
			vrrp_log_int_down(vrrp);
			vrrp->wantstate = VRRP_STATE_GOTO_FAULT;
		}
	}

	/* Then perform the state transition */
	if (vrrp->wantstate == VRRP_STATE_GOTO_FAULT ||
	    vrrp->wantstate == VRRP_STATE_BACK ||
	    (vrrp->version == VRRP_VERSION_2 && vrrp->ipsecah_counter->cycle)) {
		vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);

		/* handle backup state transition */
		vrrp_state_leave_master(vrrp);

		if (vrrp->state == VRRP_STATE_BACK)
			log_message(LOG_INFO, "VRRP_Instance(%s) Now in BACKUP state",
				    vrrp->iname);
		if (vrrp->state == VRRP_STATE_FAULT)
			log_message(LOG_INFO, "VRRP_Instance(%s) Now in FAULT state",
				    vrrp->iname);
	} else if (vrrp->state == VRRP_STATE_MAST) {
		/*
		 * Send the VRRP advert.
		 * If we catch the master transition
		 * <=> vrrp_state_master_tx(...) = 1
		 * register a gratuitous arp thread delayed to garp_delay secs.
		 */
		if (vrrp_state_master_tx(vrrp, 0)) {
			if (vrrp->garp_delay)
				thread_add_timer(master, vrrp_gratuitous_arp_thread,
						 vrrp, vrrp->garp_delay);
			vrrp_smtp_notifier(vrrp);
		}
	}
}

static void
vrrp_fault(vrrp_t * vrrp)
{
	vrrp_sgroup_t *vgroup = vrrp->sync;

	if (vgroup) {
		if (!vrrp_sync_leave_fault(vrrp))
			return;
	} else if (VRRP_ISUP(vrrp))
		vrrp_log_int_up(vrrp);
	else
		return;

	/* refresh the multicast fd */
	if (new_vrrp_socket(vrrp) < 0)
		return;

#if defined _WITH_VRRP_AUTH_
	/*
	 * We force the IPSEC AH seq_number sync
	 * to be done in read advert handler.
	 * So we ignore this timeouted state until remote
	 * VRRP MASTER send its advert for the concerned
	 * instance.
	 */
	if (vrrp->version == VRRP_VERSION_2 && vrrp->auth_type == VRRP_AUTH_AH) {
		vrrp_ah_sync(vrrp);
	} else
#endif
	{
		/* Otherwise, we transit to init state */
		if (vrrp->init_state == VRRP_STATE_BACK) {
			vrrp->state = VRRP_STATE_BACK;
			notify_instance_exec(vrrp, VRRP_STATE_BACK);
			if (vrrp->preempt_delay)
				vrrp->preempt_time = timer_add_long(timer_now(), vrrp->preempt_delay);
#ifdef _WITH_SNMP_KEEPALIVED_
			vrrp_snmp_instance_trap(vrrp);
#endif
			vrrp->last_transition = timer_now();
			log_message(LOG_INFO, "VRRP_Instance(%s): Entering BACKUP STATE", vrrp->iname);
		} else {
#ifdef _WITH_SNMP_RFCV3_
			vrrp->stats->master_reason = VRRPV3_MASTER_REASON_PREEMPTED;
#endif
			log_message(LOG_INFO, "VRRP_Instance(%s): Transition to MASTER STATE", vrrp->iname);
			vrrp_goto_master(vrrp);
		}
	}
#ifdef _WITH_SNMP_RFC_
	vrrp->stats->uptime = timer_now();
#endif
}

/* Handle dispatcher read timeout */
static int
vrrp_dispatcher_read_timeout(int fd)
{
	vrrp_t *vrrp;
	int vrid = 0;
	int prev_state = 0;

	/* Searching for matching instance */
	vrid = vrrp_timer_vrid_timeout(fd);
	vrrp = vrrp_index_lookup(vrid, fd);

	/* Run the FSM handler */
	prev_state = vrrp->state;
	VRRP_FSM_READ_TO(vrrp);

	/* handle instance synchronization */
//	printf("Send [%s] TSM transtition : [%d,%d] Wantstate = [%d]\n"
//	       , vrrp->iname
//	       , prev_state
//	       , vrrp->state
//	       , vrrp->wantstate);
	VRRP_TSM_HANDLE(prev_state, vrrp);

	/*
	 * We are sure the instance exist. So we can
	 * compute new sands timer safely.
	 */
	vrrp_init_instance_sands(vrrp);

	/*
	 * If quick sync is set, refresh sands to one advert interval, i.e. the next
	 * timeout will occur in one interval instead of three, and a check for a
	 * possible transition check will perform more quickly.
	 */
	if (vrrp->quick_sync) {
		vrrp->sands = timer_add_long(time_now, vrrp->adver_int);
		vrrp->quick_sync = 0;
	}

	return vrrp->fd_in;
}

/* Handle dispatcher read packet */
static int
vrrp_dispatcher_read(sock_t * sock)
{
	vrrp_t *vrrp;
	vrrphdr_t *hd;
	ssize_t len = 0;
	int prev_state = 0;
	unsigned proto = 0;
	struct sockaddr_storage src_addr;
	socklen_t src_addr_len = sizeof(src_addr);

	/* Clean the read buffer */
	memset(vrrp_buffer, 0, vrrp_buffer_len);

	/* read & affect received buffer */
	len = recvfrom(sock->fd_in, vrrp_buffer, vrrp_buffer_len, 0,
		       (struct sockaddr *) &src_addr, &src_addr_len);
	hd = vrrp_get_header(sock->family, vrrp_buffer, &proto);

	/* Searching for matching instance */
	vrrp = vrrp_index_lookup(hd->vrid, sock->fd_in);

	/* If no instance found => ignore the advert */
	if (!vrrp)
		return sock->fd_in;

	vrrp->pkt_saddr = src_addr;

	/* Run the FSM handler */
	prev_state = vrrp->state;
	VRRP_FSM_READ(vrrp, vrrp_buffer, len);

	/* handle instance synchronization */
//	printf("Read [%s] TSM transtition : [%d,%d] Wantstate = [%d]\n"
//	       , vrrp->iname
//	       , prev_state
//	       , vrrp->state
//	       , vrrp->wantstate);
	VRRP_TSM_HANDLE(prev_state, vrrp);

	/*
	 * Refresh sands only if found matching instance.
	 * Otherwize the packet is simply ignored...
	 */
	vrrp_init_instance_sands(vrrp);

	return sock->fd_in;
}

/* Our read packet dispatcher */
static int
vrrp_read_dispatcher_thread(thread_t * thread)
{
	unsigned long vrrp_timer;
	sock_t *sock;
	int fd;

	/* Fetch thread arg */
	sock = THREAD_ARG(thread);

	/* Dispatcher state handler */
	if (thread->type == THREAD_READ_TIMEOUT || sock->fd_in == -1)
		fd = vrrp_dispatcher_read_timeout(sock->fd_in);
	else
		fd = vrrp_dispatcher_read(sock);

	/* register next dispatcher thread */
	vrrp_timer = vrrp_timer_fd(fd);
	if (fd == -1)
		sock->thread = thread_add_timer(thread->master, vrrp_read_dispatcher_thread,
						sock, vrrp_timer);
	else
		sock->thread = thread_add_read(thread->master, vrrp_read_dispatcher_thread,
					       sock, fd, vrrp_timer);

	return 0;
}

/* Script tracking threads */
static int
vrrp_script_thread(thread_t * thread)
{
	vrrp_script_t *vscript = THREAD_ARG(thread);

	vscript->forcing_termination = false;

	/* Register next timer tracker */
	thread_add_timer(thread->master, vrrp_script_thread, vscript,
			 vscript->interval);

	/* Execute the script in a child process. Parent returns, child doesn't */
	return system_call_script(thread->master, vrrp_script_child_thread,
				  vscript, (vscript->timeout) ? vscript->timeout : vscript->interval,
				  vscript->script, vscript->uid, vscript->gid);
}

static int
vrrp_script_child_thread(thread_t * thread)
{
	int wait_status;
	pid_t pid;
	vrrp_script_t *vscript = THREAD_ARG(thread);

	if (thread->type == THREAD_CHILD_TIMEOUT) {
		pid = THREAD_CHILD_PID(thread);

		/* The child hasn't responded. Kill it off. */
		if (vscript->result > vscript->rise) {
			vscript->result--;
		} else {
			if (vscript->result == vscript->rise)
				log_message(LOG_INFO, "VRRP_Script(%s) timed out", vscript->sname);
			vscript->result = 0;
		}
		vscript->forcing_termination = true;
		kill(-pid, SIGTERM);
		thread_add_child(thread->master, vrrp_script_child_timeout_thread,
				 vscript, pid, 2);
		return 0;
	}

	wait_status = THREAD_CHILD_STATUS(thread);

	if (WIFEXITED(wait_status)) {
		int status;
		status = WEXITSTATUS(wait_status);
		if (status == 0) {
			/* success */
			if (vscript->result < vscript->rise - 1) {
				vscript->result++;
			} else {
				if (vscript->result < vscript->rise)
					log_message(LOG_INFO, "VRRP_Script(%s) succeeded", vscript->sname);
				vscript->result = vscript->rise + vscript->fall - 1;
			}
		} else {
			/* failure */
			if (vscript->result > vscript->rise) {
				vscript->result--;
			} else {
				if (vscript->result >= vscript->rise)
					log_message(LOG_INFO, "VRRP_Script(%s) failed", vscript->sname);
				vscript->result = 0;
			}
		}
	}
	else if (WIFSIGNALED(wait_status)) {
		if (vscript->forcing_termination && WTERMSIG(wait_status) == SIGTERM) {
			/* The script terminated due to a SIGTERM, and we sent it a SIGTERM to
			 * terminate the process. Now make sure any children it created have
			 * died too. */
			pid = THREAD_CHILD_PID(thread);
			kill(-pid, SIGKILL);
		}
	}

	vscript->forcing_termination = false;

	return 0;
}

static int
vrrp_script_child_timeout_thread(thread_t * thread)
{
	pid_t pid;
	vrrp_script_t *vscript = THREAD_ARG(thread);

	if (thread->type != THREAD_CHILD_TIMEOUT)
		return 0;

	/* OK, it still hasn't exited. Now really kill it off. */
	pid = THREAD_CHILD_PID(thread);
	if (kill(-pid, SIGKILL) < 0) {
		/* Its possible it finished while we're handing this */
		if (errno != ESRCH) {
			DBG("kill error: %s", strerror(errno));
		}

		return 0;
	}

	log_message(LOG_WARNING, "Process [%d] didn't respond to SIGTERM", pid);

	vscript->forcing_termination = false;

	return 0;
}

/* Delayed ARP/NA thread */
int
vrrp_arp_thread(thread_t *thread)
{
	element e, a;
	list l;
	ip_address_t *ipaddress;
	timeval_t next_time = {
		.tv_sec = INT_MAX	/* We're never going to delay this long - I hope! */
	};
	interface_t *ifp;
	vrrp_t *vrrp;
	enum {
		VIP,
		EVIP
	} i;

	set_time_now();

	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		if (!vrrp->garp_pending && !vrrp->gna_pending)
			continue;

		vrrp->garp_pending = false;
		vrrp->gna_pending = false;

		if (vrrp->state != VRRP_STATE_MAST ||
		    !vrrp->vipset)
			continue;

		for (i = VIP; i <= EVIP; i++) {
			l = (i == VIP) ? vrrp->vip : vrrp->evip;

			if (!LIST_ISEMPTY(l)) {
				for (a = LIST_HEAD(l); a; ELEMENT_NEXT(a)) {
					ipaddress = ELEMENT_DATA(a);
					if (!ipaddress->garp_gna_pending)
						continue;
					if (!ipaddress->set) {
						ipaddress->garp_gna_pending = false;
						continue;
					}

					ifp = IF_BASE_IFP(ipaddress->ifp);

					/* This should never happen */
					if (!ifp->garp_delay) {
						ipaddress->garp_gna_pending = false;
						continue;
					}

					if (!IP_IS6(ipaddress)) {
						if (timer_cmp(time_now, ifp->garp_delay->garp_next_time) >= 0) {
							send_gratuitous_arp_immediate(ifp, ipaddress);
							ipaddress->garp_gna_pending = false;
						}
						else {
							vrrp->garp_pending = true;
							if (timer_cmp(ifp->garp_delay->garp_next_time, next_time) < 0)
								next_time = ifp->garp_delay->garp_next_time;
						}
					}
					else {
						if (timer_cmp(time_now, ifp->garp_delay->gna_next_time) >= 0) {
							ndisc_send_unsolicited_na_immediate(ifp, ipaddress);
							ipaddress->garp_gna_pending = false;
						}
						else {
							vrrp->gna_pending = true;
							if (timer_cmp(ifp->garp_delay->gna_next_time, next_time) < 0)
								next_time = ifp->garp_delay->gna_next_time;
						}
					}
				}
			}
		}
	}

	if (next_time.tv_sec != INT_MAX) {
		/* Register next timer tracker */
		garp_next_time = next_time;

		garp_thread = thread_add_timer(thread->master, vrrp_arp_thread, NULL,
						 timer_long(timer_sub_now(next_time)));
	}
	else
		garp_thread = NULL;

	return 0;
}
