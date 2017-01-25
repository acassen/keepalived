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

#include <errno.h>
#include <netinet/ip.h>
#include <signal.h>
#if defined _WITH_VRRP_AUTH_
#include <netinet/in.h>
#endif

#include "vrrp_scheduler.h"
#include "vrrp_track.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_vmac.h"
#endif
#include "vrrp_sync.h"
#include "vrrp_notify.h"
#include "vrrp_data.h"
#include "vrrp_index.h"
#include "vrrp_arp.h"
#include "vrrp_ndisc.h"
#include "vrrp_if.h"
#include "global_data.h"
#include "memory.h"
#include "list.h"
#include "logger.h"
#include "main.h"
#include "smtp.h"
#include "utils.h"
#include "bitops.h"
#ifdef _WITH_SNMP_
#include "vrrp_snmp.h"
#endif
#include "vrrp_print.h"
#include "vrrp_sock.h"

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

static void vrrp_goto_master(vrrp_t *);
static void vrrp_master(vrrp_t *);

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
	{NULL,				NULL}			/*  FAULT           */
};

#define	TSM_DEBUG

/* VRRP TSM (Transition State Matrix) design.
 *
 * Introducing the Synchronization extension to VRRP
 * protocol, introduce the need for a transition machinery.
 * This mechanism can be designed using a diagonal matrix.
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
 * FSM or they are handled when the trigger events to/from FAULT state occur.
 * For instance the handlers (2), (4), (5) & (6) are handled when it is 
 * detected that a script or an interface has failed or recovered since
 * it will speed up convergence to init state.
 * Additionaly, we have implemented some other handlers into the matrix
 * in order to speed up group synchronization takeover. For instance
 * transition:
 *    o B->B: To catch wantstate MASTER transition to force sync group
 *            to this transition state too.
 *    o F->F: To speed up FAULT state transition if group is not already
 *            synced to FAULT state.
 */
static struct {
	void (*handler) (vrrp_t *);
} VRRP_TSM[VRRP_MAX_TSM_STATE + 1][VRRP_MAX_TSM_STATE + 1] =
{
/* From:	  To: >	  BACKUP			MASTER		    FAULT */
/*   v    */	{ {NULL}, {NULL},			{NULL},		   {NULL} },
/* BACKUP */	{ {NULL}, {NULL},			{vrrp_sync_master}, {NULL} },
/* MASTER */	{ {NULL}, {vrrp_sync_backup},		{vrrp_sync_master}, {NULL} },
/* FAULT  */	{ {NULL}, {NULL},			{vrrp_sync_master}, {NULL} }
};

/* SMTP alert notifier */
void
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
	bool is_up;
	int new_state;

	/* Do notifications for any sync groups in fault state */
	for (e = LIST_HEAD(vrrp_data->vrrp_sync_group); e; ELEMENT_NEXT(e)) {
		/* Init group if needed  */
		vgroup = ELEMENT_DATA(e);
		if (vgroup->state == VRRP_STATE_FAULT) {
			vrrp_sync_smtp_notifier(vgroup);
			notify_group_exec(vgroup, VRRP_STATE_FAULT);
#ifdef _WITH_SNMP_KEEPALIVED_
			vrrp_snmp_group_trap(vgroup);
#endif
		}
	}

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		/* wantstate is the state we would be in disregarding any sync group */
		if (vrrp->wantstate == VRRP_STATE_INIT) {
			vrrp->wantstate = vrrp->state == VRRP_STATE_FAULT ? VRRP_STATE_FAULT :
					    vrrp->init_state == VRRP_STATE_MAST && vrrp->base_priority == VRRP_PRIO_OWNER ? VRRP_STATE_MAST :
					    VRRP_STATE_BACK;
		}
		new_state = vrrp->sync ? vrrp->sync->state : vrrp->wantstate;

		is_up = (VRRP_ISUP(vrrp) && (!vrrp->sync || GROUP_STATE(vrrp->sync) != VRRP_STATE_FAULT));
		if (is_up &&
		    vrrp->base_priority == VRRP_PRIO_OWNER &&
		    vrrp->init_state == VRRP_STATE_MAST) {
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
			vrrp->state = VRRP_STATE_MAST;
		} else {
			if (new_state == VRRP_STATE_BACK && vrrp->init_state == VRRP_STATE_MAST)
				vrrp->ms_down_timer = vrrp->master_adver_int + VRRP_TIMER_SKEW_MIN(vrrp);
			else
				vrrp->ms_down_timer = 3 * vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);
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

			/* Set interface state */
			vrrp_restore_interface(vrrp, false, false);
			if (is_up) {
				vrrp->state = VRRP_STATE_BACK;
				log_message(LOG_INFO, "VRRP_Instance(%s) Entering BACKUP STATE", vrrp->iname);
			}
			else {
				vrrp->state = VRRP_STATE_FAULT;
				log_message(LOG_INFO, "VRRP_Instance(%s) Entering FAULT STATE", vrrp->iname);
			}
			vrrp_smtp_notifier(vrrp);
			notify_instance_exec(vrrp, vrrp->state);
#ifdef _WITH_SNMP_KEEPALIVED_
			vrrp_snmp_instance_trap(vrrp);
#endif
			vrrp->last_transition = timer_now();
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

// TODO 1 this is probably not the right way of bringing up the address owner immediately
		if (vrrp->base_priority != VRRP_PRIO_OWNER || vrrp->init_state != VRRP_STATE_MAST)
			vrrp_init_instance_sands(vrrp);
		else
			vrrp->sands = timer_now();
	}
}

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
		else if (vscript->result != VRRP_SCRIPT_STATUS_DISABLED) {
			if (vscript->result == VRRP_SCRIPT_STATUS_INIT)
				vscript->result = vscript->rise - 1; /* one success is enough */
			else if (vscript->result == VRRP_SCRIPT_STATUS_INIT_FAILED)
				vscript->result = 0; /* assume failed by config */

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
	timerclear(&timer);
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (!timerisset(&timer) ||
		    timercmp(&vrrp->sands, &timer, <))
			timer = vrrp->sands;
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
	if (timercmp(&timer, &time_now, <))
		return TIMER_MAX_SEC;

	timersub(&timer, &time_now, &timer);
	return timer_long(timer);
}

static void
thread_requeue_read_relative(vrrp_t *vrrp, uint32_t timer)
{
	thread_read_requeue(master, vrrp->sockets->fd_in, timer_sub_long(vrrp->sands, timer));
}

// TODO //static int
//static vrrp_t *
//vrrp_timer_timeout(const int fd)
//{
//	vrrp_t *vrrp;
//	element e;
//	list l = &vrrp_data->vrrp_index_fd[fd%1024 + 1];
//	timeval_t timer;
//	vrrp_t *best_vrrp = NULL;
//
//	/* Multiple instances on the same interface */
//	timerclear(&timer);
//	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
//		vrrp = ELEMENT_DATA(e);
//		if (vrrp->fd_in == fd &&
//		    (!timerisset(&timer) ||
//		     timercmp(&vrrp->sands, &timer, <))) {
//			timer = vrrp->sands;
//			best_vrrp = vrrp;
//		}
//	}
//
//	return best_vrrp;
//}

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
		if (vrrp->auth_type == VRRP_AUTH_AH)
			proto = IPPROTO_AH;
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
	interface_t *ifp;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		sock = ELEMENT_DATA(e);
		if (!sock->ifindex) {
			sock->fd_in = sock->fd_out = -1;
			continue;
		}
		ifp = if_get_by_ifindex(sock->ifindex);
		sock->fd_in = open_vrrp_read_socket(sock->family, sock->proto,
					       ifp, sock->unicast);
		if (sock->fd_in == -1)
			sock->fd_out = -1;
		else
			sock->fd_out = open_vrrp_send_socket(sock->family, sock->proto,
							     ifp, sock->unicast);
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
			if (vrrp->auth_type == VRRP_AUTH_AH)
				proto = IPPROTO_AH;
			else
#endif
				proto = IPPROTO_VRRP;

			if ((sock->ifindex == ifindex)	&&
			    (sock->family == vrrp->family) &&
			    (sock->proto == proto)	&&
			    (sock->unicast == unicast)) {
				vrrp->sockets = sock;

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
 * TODO TODO - this description is way out of date
 * Here we have n physical NIC. Each NIC own a maximum of 2 fds.
 * (one for VRRP the other for IPSEC_AH). All our VRRP instances
 * are multiplexed through this fds. So our design can handle 2*n
 * multiplexing points.
 */
int
vrrp_dispatcher_init(__attribute__((unused)) thread_t * thread)
{
	vrrp_create_sockpool(vrrp_data->vrrp_socket_pool);

	/* open the VRRP socket pool */
	vrrp_open_sockpool(vrrp_data->vrrp_socket_pool);

	/* set VRRP instance fds to sockpool */
	vrrp_set_fds(vrrp_data->vrrp_socket_pool);

	/* create the VRRP socket pool list */
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
#ifdef _WITH_VRRP_AUTH_
	struct iphdr *iph;
	ipsec_ah_t *ah;

	if (vrrp->auth_type == VRRP_AUTH_AH) {
		iph = (struct iphdr *) buffer;

		if (iph->protocol == IPPROTO_AH) {
			ah = (ipsec_ah_t *) (buffer + sizeof (struct iphdr));
			if (ntohl(ah->seq_number) >= vrrp->ipsecah_counter.seq_number)
				vrrp->ipsecah_counter.cycle = false;
		}
// TODO - what if mismatch between configured and received auth type?
	}
#endif

	vrrp_state_backup(vrrp, buffer, len);
}

/* This is called if receive a packet when master */
static void
vrrp_leave_master(vrrp_t * vrrp, char *buffer, ssize_t len)
{
	if (vrrp_state_master_rx(vrrp, buffer, len))
	{
		vrrp_state_leave_master(vrrp);
		vrrp_smtp_notifier(vrrp);
	}
}

static void
vrrp_goto_master(vrrp_t * vrrp)
{
#if defined _WITH_VRRP_AUTH_
	/* If becoming MASTER in IPSEC AH AUTH, we reset the anti-replay */
	if (vrrp->version == VRRP_VERSION_2 && vrrp->ipsecah_counter.cycle) {
		vrrp->ipsecah_counter.cycle = false;
		vrrp->ipsecah_counter.seq_number = 0;
	}
#endif

#ifdef _WITH_SNMP_RFCV3_
// TODO - what is this test doing?
	if (vrrp->ms_down_timer >= 3 * vrrp->master_adver_int)
		vrrp->stats->master_reason = VRRPV3_MASTER_REASON_MASTER_NO_RESPONSE;
#endif
	/* handle master state transition */
	vrrp->wantstate = VRRP_STATE_MAST;
	vrrp_state_goto_master(vrrp);
}

/* Delayed gratuitous ARP thread */
int
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
vrrp_set_effective_priority(vrrp_t *vrrp)
{
	uint8_t new_prio;
	bool increasing_priority;
	uint32_t old_down_timer;

	/* Don't change priority if address owner */
	if (vrrp->base_priority == VRRP_PRIO_OWNER)
		return;

	if (vrrp->total_priority < 1)
		new_prio = 1;
	else if (vrrp->total_priority >= VRRP_PRIO_OWNER)
		new_prio = VRRP_PRIO_OWNER - 1;
	else
		new_prio = (uint8_t)vrrp->total_priority;

	if (vrrp->effective_priority == new_prio)
		return;

	log_message(LOG_INFO, "VRRP_Instance(%s) Changing effective priority from %d to %d",
		    vrrp->iname, vrrp->effective_priority, new_prio);

	increasing_priority = (new_prio > vrrp->effective_priority);

	vrrp->effective_priority = new_prio;
	old_down_timer = vrrp->ms_down_timer;
	vrrp->ms_down_timer = 3 * vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);

	if (vrrp->state == VRRP_STATE_BACK && increasing_priority)
		thread_requeue_read_relative(vrrp, old_down_timer - vrrp->ms_down_timer);
}

static void
vrrp_master(vrrp_t * vrrp)
{
	/* Send the VRRP advert */
	vrrp_state_master_tx(vrrp);
}

void
try_up_instance(vrrp_t *vrrp)
{
	int wantstate;

	if (--vrrp->num_script_if_fault)
		return;

	if (vrrp->init_state == VRRP_STATE_MAST && vrrp->base_priority == VRRP_PRIO_OWNER)
		vrrp->wantstate = VRRP_STATE_MAST;
	else
		vrrp->wantstate = VRRP_STATE_BACK;

	vrrp->master_adver_int = vrrp->adver_int;
	vrrp->ms_down_timer = 3 * vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);

	if (vrrp->sync && --vrrp->sync->num_member_fault)
		return;

	/* If the sync group can't go to master, we must go to backup state */
	wantstate = vrrp->wantstate;
	if (vrrp->sync && !vrrp_sync_can_goto_master(vrrp))
		vrrp->wantstate = VRRP_STATE_BACK;

	/* We can come up */
	vrrp_state_leave_fault(vrrp);
	vrrp_init_instance_sands(vrrp);

	thread_requeue_read(master, vrrp->sockets->fd_in, vrrp->ms_down_timer);

	vrrp->wantstate = wantstate;

	if (vrrp->sync) {
		if (vrrp->state == VRRP_STATE_MAST)
			vrrp_sync_master(vrrp);
		else
			vrrp_sync_backup(vrrp);
	}
}

/* Handle dispatcher read timeout */
static int
vrrp_dispatcher_read_timeout(int fd)
{
	vrrp_t *vrrp;
	int prev_state;
	element e;
	list l = &vrrp_data->vrrp_index_fd[fd%1024 + 1];

	set_time_now();

	/* Multiple instances on the same interface */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (vrrp->sockets->fd_in != fd)
			continue;

		if (timercmp(&vrrp->sands, &time_now, >))
			continue;

		/* Run the FSM handler */
		prev_state = vrrp->state;
		VRRP_FSM_READ_TO(vrrp);

		/* handle instance synchronization */
#ifdef TSM_DEBUG
		printf("Send [%s] TSM transtition : [%d,%d] Wantstate = [%d]\n",
			vrrp->iname, prev_state, vrrp->state, vrrp->wantstate);
#endif
		VRRP_TSM_HANDLE(prev_state, vrrp);

		vrrp_init_instance_sands(vrrp);
	}

	return fd;
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

	if (vrrp->state == VRRP_STATE_FAULT) {
		/* We just ignore a message received when we are in fault state */
		return sock->fd_in;
	}

	vrrp->pkt_saddr = src_addr;

	/* Run the FSM handler */
	prev_state = vrrp->state;
	VRRP_FSM_READ(vrrp, vrrp_buffer, len);

	/* handle instance synchronization */
#ifdef TSM_DEBUG
	printf("Read [%s] TSM transtition : [%d,%d] Wantstate = [%d]\n",
		vrrp->iname, prev_state, vrrp->state, vrrp->wantstate);
#endif
	VRRP_TSM_HANDLE(prev_state, vrrp);

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
				  &vscript->script);
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
		int8_t status;
		status = (int8_t)WEXITSTATUS(wait_status);

		/* Report if status has changed */
		if (status != vscript->last_status) {
			log_message(LOG_INFO, "Script `%s` now returning %d", vscript->sname, status);
			vscript->last_status = status;
		}

		if (status == 0) {
			/* success */
			if (vscript->result < vscript->rise - 1) {
				vscript->result++;
			} else {
				if (vscript->result < vscript->rise) {
					log_message(LOG_INFO, "VRRP_Script(%s) succeeded", vscript->sname);
					update_script_priorities(vscript, true);
				}
				vscript->result = vscript->rise + vscript->fall - 1;
			}
		} else {
			/* failure */
			if (vscript->result > vscript->rise) {
				vscript->result--;
			} else {
				if (vscript->result == vscript->rise) {
					log_message(LOG_INFO, "VRRP_Script(%s) failed", vscript->sname);
					update_script_priorities(vscript, false);
				}
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
						if (timercmp(&time_now, &ifp->garp_delay->garp_next_time, >=)) {
							send_gratuitous_arp_immediate(ifp, ipaddress);
							ipaddress->garp_gna_pending = false;
						}
						else {
							vrrp->garp_pending = true;
							if (timercmp(&ifp->garp_delay->garp_next_time, &next_time, <))
								next_time = ifp->garp_delay->garp_next_time;
						}
					}
					else {
						if (timercmp(&time_now, &ifp->garp_delay->gna_next_time, >=)) {
							ndisc_send_unsolicited_na_immediate(ifp, ipaddress);
							ipaddress->garp_gna_pending = false;
						}
						else {
							vrrp->gna_pending = true;
							if (timercmp(&ifp->garp_delay->gna_next_time, &next_time, <))
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

#ifdef _WITH_DUMP_THREADS_
static char *
get_func_name_from_addr(void *func)
{
/*
func
 handle_dbus_msg
 http_read_thread
 http_response_thread
 if_linkbeat_refresh_thread
 kernel_netlink
 print_vrrp_data
 print_vrrp_stats
 reload_vrrp_thread
 SMTP_FSM[status].send
 smtp_read_thread
 smtp_send_thread
 ssl_read_thread
 tcp_connect_thread
*/
	if (func == vrrp_arp_thread) return "vrrp_arp_thread";
	if (func == vrrp_dispatcher_init) return "vrrp_dispatcher_init";
	if (func == vrrp_gratuitous_arp_thread) return "vrrp_gratuitous_arp_thread";
	if (func == vrrp_lower_prio_gratuitous_arp_thread) return "vrrp_lower_prio_gratuitous_arp_thread";
	if (func == vrrp_read_dispatcher_thread) return "vrrp_read_dispatcher_thread";
//	if (func == vrrp_respawn_thread) return "vrrp_respawn_thread";
	if (func == vrrp_script_child_timeout_thread) return "vrrp_script_child_timeout_thread";
	if (func == vrrp_script_thread) return "vrrp_script_thread";

	return NULL;
}

static void
dump_thread_list( FILE *fp, thread_list_t *tlist, const char *type)
{
	thread_t *thread;
	char time_buf[26];
	char *func_name;

	fprintf(fp, "\n  %s thread list dump\n", type);
	for (thread = tlist->head; thread; thread = thread->next) {
		fprintf(fp, "\n    type = %d (%s)\n", thread->type,
				thread->type == THREAD_READ ? "THREAD_READ" :
				thread->type == THREAD_WRITE ? "THREAD_WRITE" :
				thread->type == THREAD_TIMER ? "THREAD_TIMER" :
				thread->type == THREAD_EVENT ? "THREAD_EVENT" :
				thread->type == THREAD_CHILD ? "THREAD_CHILD" :
				thread->type == THREAD_READY ? "THREAD_READY" :
				thread->type == THREAD_UNUSED ? "THREAD_UNUSED" :
				thread->type == THREAD_WRITE_TIMEOUT ? "THREAD_WRITE_TIMEOUT" :
				thread->type == THREAD_READ_TIMEOUT ? "THREAD_READ_TIMEOUT" :
				thread->type == THREAD_CHILD_TIMEOUT ? "THREAD_CHILD_TIMEOUT" :
				thread->type == THREAD_TERMINATE ? "THREAD_TERMINATE" :
				thread->type == THREAD_READY_FD ? "THREAD_READY_FD" :
				"unknown");

		fprintf(fp, "    id = %lu\n", thread->id);
		fprintf(fp, "    union = %d\n", thread->u.val);
		ctime_r(&thread->sands.tv_sec, time_buf);
		fprintf(fp, "    sands = %.19s.%6.6lu\n", time_buf, thread->sands.tv_usec);
		if ((func_name = get_func_name_from_addr(thread->func)))
			fprintf(fp, "    func = %s()\n", func_name);
		else
			fprintf(fp, "    func = %p\n", thread->func);
	}
}

static void
dump_fd_set(FILE *fp, fd_set *fd, const char *type)
{
	fprintf(fp, "\n  %s fd_set dump\n", type);
	fprintf(fp, "    0x%lx\n", __FDS_BITS(fd)[0]);
}

void
dump_threads(void)
{
	FILE *fp;
	char time_buf[26];
	element e;
	vrrp_t *vrrp;

	fp = fopen("/tmp/thread_dump", "a");

	set_time_now();
	ctime_r(&time_now.tv_sec, time_buf);

	fprintf(fp, "\n%.19s.%6.6ld: Thread dump\n", time_buf, time_now.tv_usec);

	dump_thread_list(fp, &master->read, "read");
	dump_thread_list(fp, &master->write, "write");
	dump_thread_list(fp, &master->timer, "timer");
	dump_thread_list(fp, &master->child, "child");
	dump_thread_list(fp, &master->event, "event");
	dump_thread_list(fp, &master->ready, "ready");
	dump_thread_list(fp, &master->unuse, "unuse");
	dump_fd_set(fp, &master->readfd, "read");
	dump_fd_set(fp, &master->writefd, "write");
	dump_fd_set(fp, &master->exceptfd, "except");
	fprintf(fp, "alloc = %lu\n", master->alloc);

	fprintf(fp, "\n");
	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		ctime_r(&vrrp->sands.tv_sec, time_buf);
		fprintf(fp, "VRRP instance %s, sands %.19s.%6.6lu, status %s\n", vrrp->iname, time_buf, vrrp->sands.tv_usec,
				vrrp->state == VRRP_STATE_INIT ? "INIT" :
				vrrp->state == VRRP_STATE_BACK ? "BACKUP" :
				vrrp->state == VRRP_STATE_MAST ? "MASTER" :
				vrrp->state == VRRP_STATE_FAULT ? "FAULT" :
				vrrp->state == VRRP_DISPATCHER ? "DISPATCHER" : "unknown");
	}
	fclose(fp);
}
#endif

#ifdef _TIMER_DEBUG_
void
print_vrrp_scheduler_addresses(void)
{
	log_message(LOG_INFO, "Address of vrrp_arp_thread() is 0x%p", vrrp_arp_thread);
	log_message(LOG_INFO, "Address of vrrp_dispatcher_init() is 0x%p", vrrp_dispatcher_init);
	log_message(LOG_INFO, "Address of vrrp_lower_prio_gratuitous_arp_thread() is 0x%p", vrrp_lower_prio_gratuitous_arp_thread);
	log_message(LOG_INFO, "Address of vrrp_script_child_thread() is 0x%p", vrrp_script_child_thread);
	log_message(LOG_INFO, "Address of vrrp_read_dispatcher_thread() is 0x%p", vrrp_read_dispatcher_thread);
}
#endif
