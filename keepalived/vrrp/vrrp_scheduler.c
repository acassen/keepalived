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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <errno.h>
#include <netinet/ip.h>
#include <signal.h>
#if defined _WITH_VRRP_AUTH_
#include <netinet/in.h>
#endif
#include <stdint.h>
#include <stdio.h>

#include "vrrp_scheduler.h"
#include "vrrp_track.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_vmac.h"
#endif
#include "vrrp_sync.h"
#include "vrrp_notify.h"
#include "vrrp_data.h"
#include "vrrp_arp.h"
#include "vrrp_ndisc.h"
#include "vrrp_if.h"
#include "global_data.h"
#include "memory.h"
#include "list.h"
#include "logger.h"
#include "main.h"
#include "signals.h"
#include "utils.h"
#include "bitops.h"
#include "vrrp_sock.h"
#ifdef _WITH_SNMP_RFCV3_
#include "vrrp_snmp.h"
#endif
#ifdef _WITH_BFD_
#include "bfd_event.h"
#include "bfd_daemon.h"
#endif
#ifdef THREAD_DUMP
#include "scheduler.h"
#endif

/* global vars */
timeval_t garp_next_time;
thread_t *garp_thread;
bool vrrp_initialised;

#ifdef _TSM_DEBUG_
bool do_tsm_debug;
#endif

/* local variables */
#ifdef _WITH_BFD_
static thread_t *bfd_thread;		 /* BFD control pipe read thread */
#endif

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

static int vrrp_script_child_thread(thread_t *);
static int vrrp_script_thread(thread_t *);
#ifdef _WITH_BFD_
static int vrrp_bfd_thread(thread_t *);
#endif

static int vrrp_read_dispatcher_thread(thread_t *);

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

	/* We can send SMTP messages from this point, so set the time */
	set_time_now();

	/* Do notifications for any sync groups in fault state */
	for (e = LIST_HEAD(vrrp_data->vrrp_sync_group); e; ELEMENT_NEXT(e)) {
		/* Init group if needed  */
		vgroup = ELEMENT_DATA(e);

		if (vgroup->state == VRRP_STATE_FAULT)
			send_group_notifies(vgroup);
	}

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		/* wantstate is the state we would be in disregarding any sync group */
		if (vrrp->state == VRRP_STATE_FAULT)
			vrrp->wantstate = VRRP_STATE_FAULT;

		new_state = vrrp->sync ? vrrp->sync->state : vrrp->wantstate;

		is_up = VRRP_ISUP(vrrp);

		if (is_up &&
		    new_state == VRRP_STATE_MAST &&
		    !vrrp->num_script_init && (!vrrp->sync || !vrrp->sync->num_member_init) &&
		    (vrrp->base_priority == VRRP_PRIO_OWNER ||
		     vrrp->reload_master) &&
		    vrrp->wantstate == VRRP_STATE_MAST) {
#ifdef _WITH_LVS_
			/* Check if sync daemon handling is needed */
			if (global_data->lvs_syncd.ifname &&
			    global_data->lvs_syncd.vrrp == vrrp)
				ipvs_syncd_cmd(IPVS_STARTDAEMON,
					       &global_data->lvs_syncd,
					       vrrp->state == VRRP_STATE_MAST ? IPVS_MASTER : IPVS_BACKUP,
					       false,
					       false);
#endif
			if (!vrrp->reload_master) {
#ifdef _WITH_SNMP_RFCV3_
				vrrp->stats->next_master_reason = VRRPV3_MASTER_REASON_PREEMPTED;
#endif

				/* The simplest way to become master is to timeout from the backup state
				 * very quickly (1usec) */
				vrrp->state = VRRP_STATE_BACK;
				vrrp->ms_down_timer = 1;
			}

// TODO Do we need ->	vrrp_restore_interface(vrrp, false, false);
// It removes everything, so probably if !reload
		} else {
			if (new_state == VRRP_STATE_BACK && vrrp->wantstate == VRRP_STATE_MAST)
				vrrp->ms_down_timer = vrrp->master_adver_int + VRRP_TIMER_SKEW_MIN(vrrp);
			else
				vrrp->ms_down_timer = 3 * vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);

#ifdef _WITH_SNMP_RFCV3_
			vrrp->stats->next_master_reason = VRRPV3_MASTER_REASON_MASTER_NO_RESPONSE;
#endif

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
			if (is_up && new_state != VRRP_STATE_FAULT && !vrrp->num_script_init && (!vrrp->sync || !vrrp->sync->num_member_init)) {
				if (is_up) {
					vrrp->state = VRRP_STATE_BACK;
					log_message(LOG_INFO, "(%s) Entering BACKUP STATE (init)", vrrp->iname);
				}
				else {
					vrrp->state = VRRP_STATE_FAULT;
					log_message(LOG_INFO, "(%s) Entering FAULT STATE (init)", vrrp->iname);
				}
				send_instance_notifies(vrrp);
			}
			vrrp->last_transition = timer_now();
		}
#ifdef _WITH_SNMP_RFC_
		vrrp->stats->uptime = timer_now();
#endif
	}
}

/* Declare vrrp_timer_cmp() rbtree compare function */
RB_TIMER_CMP(vrrp);

/* Compute the new instance sands */
void
vrrp_init_instance_sands(vrrp_t * vrrp)
{
	set_time_now();

	if (vrrp->state == VRRP_STATE_MAST) {
		if (vrrp->reload_master)
			vrrp->sands = time_now;
		else
			vrrp->sands = timer_add_long(time_now, vrrp->adver_int);
	}
	else if (vrrp->state == VRRP_STATE_BACK) {
		/*
		 * When in the BACKUP state the expiry timer should be updated to
		 * time_now plus the Master Down Timer, when a non-preemptable packet is
		 * received.
		 */
		vrrp->sands = timer_add_long(time_now, vrrp->ms_down_timer);
	}
	else if (vrrp->state == VRRP_STATE_FAULT || vrrp->state == VRRP_STATE_INIT)
		vrrp->sands.tv_sec = TIMER_DISABLED;

	rb_move_cached(&vrrp->sockets->rb_sands, vrrp, rb_sands, vrrp_timer_cmp);
}

static void
vrrp_init_sands(list l)
{
	vrrp_t *vrrp;
	element e;

	LIST_FOREACH(l, vrrp, e) {
		vrrp->sands.tv_sec = TIMER_DISABLED;
		rb_insert_sort_cached(&vrrp->sockets->rb_sands, vrrp, rb_sands, vrrp_timer_cmp);
		vrrp_init_instance_sands(vrrp);
		vrrp->reload_master = false;
	}
}

static void
vrrp_init_script(list l)
{
	vrrp_script_t *vscript;
	element e;

	LIST_FOREACH(l, vscript, e) {
		if (vscript->init_state == SCRIPT_INIT_STATE_INIT)
			vscript->result = vscript->rise - 1; /* one success is enough */
		else if (vscript->init_state == SCRIPT_INIT_STATE_FAILED)
			vscript->result = 0; /* assume failed by config */

		thread_add_event(master, vrrp_script_thread, vscript, (int)vscript->interval);
	}
}

/* Timer functions */
static timeval_t *
vrrp_compute_timer(const sock_t *sock)
{
	vrrp_t *vrrp;
	static timeval_t timer = { .tv_sec = TIMER_DISABLED };

	/* The sock won't exist if there isn't a vrrp instance on it,
	 * so rb_first will always exist. */
	vrrp = rb_entry(rb_first_cached(&sock->rb_sands), vrrp_t, rb_sands);
	if (vrrp)
		return &vrrp->sands;

	return &timer;
}

void
vrrp_thread_requeue_read(vrrp_t *vrrp)
{
	thread_requeue_read(master, vrrp->sockets->fd_in, vrrp_compute_timer(vrrp->sockets));
}

/* Thread functions */
static void
vrrp_register_workers(list l)
{
	sock_t *sock;
	timeval_t timer;
	element e;

	/* Init compute timer */
	memset(&timer, 0, sizeof(timer));

	/* Init the VRRP instances state */
	vrrp_init_state(vrrp_data->vrrp);

	/* Init VRRP instances sands */
	vrrp_init_sands(vrrp_data->vrrp);

	/* Init VRRP tracking scripts */
	if (!LIST_ISEMPTY(vrrp_data->vrrp_script))
		vrrp_init_script(vrrp_data->vrrp_script);

#ifdef _WITH_BFD_
	if (!LIST_ISEMPTY(vrrp_data->vrrp)) {
// TODO - should we only do this if we have track_bfd? Probably not
		/* Init BFD tracking thread */
		bfd_thread = thread_add_read(master, vrrp_bfd_thread, NULL,
					     bfd_vrrp_event_pipe[0], TIMER_NEVER);
	}
#endif

	/* Register VRRP workers threads */
	LIST_FOREACH(l, sock, e) {
		/* Register a timer thread if interface exists */
		if (sock->fd_in != -1)
			sock->thread = thread_add_read_sands(master, vrrp_read_dispatcher_thread,
						       sock, sock->fd_in, vrrp_compute_timer(sock));
	}
}

void
vrrp_thread_add_read(vrrp_t *vrrp)
{
	vrrp->sockets->thread = thread_add_read_sands(master, vrrp_read_dispatcher_thread,
						vrrp->sockets, vrrp->sockets->fd_in, vrrp_compute_timer(vrrp->sockets));
}

/* VRRP dispatcher functions */
static sock_t *
already_exist_sock(list l, sa_family_t family, int proto, ifindex_t ifindex, bool unicast)
{
	sock_t *sock;
	element e;

	LIST_FOREACH(l, sock, e) {
		if ((sock->family == family)	&&
		    (sock->proto == proto)	&&
		    (sock->ifindex == ifindex)	&&
		    (sock->unicast == unicast))
			return sock;
	}

	return NULL;
}

static sock_t *
alloc_sock(sa_family_t family, list l, int proto, ifindex_t ifindex, bool unicast)
{
	sock_t *new;

	new = (sock_t *)MALLOC(sizeof (sock_t));
	new->family = family;
	new->proto = proto;
	new->ifindex = ifindex;
	new->unicast = unicast;
	new->rb_vrid = RB_ROOT;
	new->rb_sands = RB_ROOT_CACHED;

	list_add(l, new);

	return new;
}

static inline int
vrrp_vrid_cmp(const vrrp_t *v1, const vrrp_t *v2)
{
	return v1->vrid - v2->vrid;
}

static void
vrrp_create_sockpool(list l)
{
	vrrp_t *vrrp;
	element e;
	ifindex_t ifindex;
	int proto;
	bool unicast;
	sock_t *sock;

	LIST_FOREACH(vrrp_data->vrrp, vrrp, e) {
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
		if (!(sock = already_exist_sock(l, vrrp->family, proto, ifindex, unicast)))
			sock = alloc_sock(vrrp->family, l, proto, ifindex, unicast);

		/* Add the vrrp_t indexed by vrid to the socket */
		rb_insert_sort(&sock->rb_vrid, vrrp, rb_vrid, vrrp_vrid_cmp);

		if (vrrp->kernel_rx_buf_size)
			sock->rx_buf_size += vrrp->kernel_rx_buf_size;
		else if (global_data->vrrp_rx_bufs_policy & RX_BUFS_SIZE)
			sock->rx_buf_size += global_data->vrrp_rx_bufs_size;
		else if (global_data->vrrp_rx_bufs_policy & RX_BUFS_POLICY_ADVERT)
			sock->rx_buf_size += global_data->vrrp_rx_bufs_multiples * vrrp_adv_len(vrrp);
		else if (global_data->vrrp_rx_bufs_policy & RX_BUFS_POLICY_MTU)
			sock->rx_buf_size += global_data->vrrp_rx_bufs_multiples * vrrp->ifp->mtu;
	}
}

static void
vrrp_open_sockpool(list l)
{
	sock_t *sock;
	element e;
	interface_t *ifp;

	LIST_FOREACH(l, sock, e) {
		if (!sock->ifindex) {
			sock->fd_in = sock->fd_out = -1;
			continue;
		}
		ifp = if_get_by_ifindex(sock->ifindex);
		sock->fd_in = open_vrrp_read_socket(sock->family, sock->proto,
					       ifp, sock->unicast, sock->rx_buf_size);
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
	element e;

	LIST_FOREACH(l, sock, e) {
		rb_for_each_entry(vrrp, &sock->rb_vrid, rb_vrid)
			vrrp->sockets = sock;
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
		dump_list(NULL, vrrp_data->vrrp_socket_pool);

	vrrp_initialised = true;

	return 1;
}

void
vrrp_dispatcher_release(vrrp_data_t *data)
{
	free_list(&data->vrrp_socket_pool);
#ifdef _WITH_BFD_
	thread_cancel(bfd_thread);
	bfd_thread = NULL;
#endif
}

static void
vrrp_goto_master(vrrp_t * vrrp)
{
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

static void
vrrp_master(vrrp_t * vrrp)
{
	/* Send the VRRP advert */
	vrrp_state_master_tx(vrrp);
}

void
try_up_instance(vrrp_t *vrrp, bool leaving_init)
{
	int wantstate;

	if (leaving_init) {
		if (vrrp->num_script_if_fault)
			return;
	}
	else if (--vrrp->num_script_if_fault || vrrp->num_script_init)
		return;

	if (vrrp->wantstate == VRRP_STATE_MAST && vrrp->base_priority == VRRP_PRIO_OWNER) {
		vrrp->wantstate = VRRP_STATE_MAST;
#ifdef _WITH_SNMP_RFCV3_
		vrrp->stats->next_master_reason = VRRPV3_MASTER_REASON_PREEMPTED;
#endif
	} else {
		vrrp->wantstate = VRRP_STATE_BACK;
#ifdef _WITH_SNMP_RFCV3_
		vrrp->stats->next_master_reason = VRRPV3_MASTER_REASON_MASTER_NO_RESPONSE;
#endif
	}

	vrrp->master_adver_int = vrrp->adver_int;
	if (vrrp->wantstate == VRRP_STATE_MAST && vrrp->base_priority == VRRP_PRIO_OWNER)
		vrrp->ms_down_timer = vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);
	else
		vrrp->ms_down_timer = 3 * vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);

	if (vrrp->sync) {
		if (leaving_init) {
			if (vrrp->sync->num_member_fault)
				return;
		}
		else if (--vrrp->sync->num_member_fault || vrrp->sync->num_member_init)
			return;
	}

	/* If the sync group can't go to master, we must go to backup state */
	wantstate = vrrp->wantstate;
	if (vrrp->sync && vrrp->wantstate == VRRP_STATE_MAST && !vrrp_sync_can_goto_master(vrrp))
		vrrp->wantstate = VRRP_STATE_BACK;

	/* We can come up */
	vrrp_state_leave_fault(vrrp);

	vrrp_init_instance_sands(vrrp);
	vrrp_thread_requeue_read(vrrp);

	vrrp->wantstate = wantstate;

	if (vrrp->sync) {
		if (vrrp->state == VRRP_STATE_MAST)
			vrrp_sync_master(vrrp);
		else
			vrrp_sync_backup(vrrp);
	}
}

#ifdef _WITH_BFD_
static void
vrrp_handle_bfd_event(bfd_event_t * evt)
{
	vrrp_tracked_bfd_t *vbfd;
	tracking_vrrp_t *tbfd;
	vrrp_t * vrrp;
	element e, e1;
	struct timeval time_now;
	struct timeval timer_tmp;
	uint32_t delivery_time;

	if (__test_bit(LOG_DETAIL_BIT, &debug)) {
		time_now = timer_now();
		timersub(&time_now, &evt->sent_time, &timer_tmp);
		delivery_time = timer_long(timer_tmp);
		log_message(LOG_INFO, "Received BFD event: instance %s is in"
			    " state %s (delivered in %i usec)",
			    evt->iname, BFD_STATE_STR(evt->state), delivery_time);
	}

	LIST_FOREACH(vrrp_data->vrrp_track_bfds, vbfd, e) {
		if (strcmp(vbfd->bname, evt->iname))
			continue;

		if ((vbfd->bfd_up && evt->state == BFD_STATE_UP) ||
		    (!vbfd->bfd_up && evt->state == BFD_STATE_DOWN))
			continue;

		vbfd->bfd_up = (evt->state == BFD_STATE_UP);

		LIST_FOREACH(vbfd->tracking_vrrp, tbfd, e1) {
			vrrp = tbfd->vrrp;

			log_message(LOG_INFO, "VRRP_Instance(%s) Tracked BFD"
				    " instance %s is %s", vrrp->iname, evt->iname, vbfd->bfd_up ? "UP" : "DOWN");

			if (tbfd->weight) {
				if (vbfd->bfd_up)
					vrrp->total_priority += abs(tbfd->weight);
				else
					vrrp->total_priority -= abs(tbfd->weight);
				vrrp_set_effective_priority(vrrp);

				continue;
			}

			if (vbfd->bfd_up)
				try_up_instance(vrrp, false);
			else
				down_instance(vrrp);
		}

		break;
	}
}

static int
vrrp_bfd_thread(thread_t * thread)
{
	bfd_event_t evt;

	bfd_thread = thread_add_read(master, vrrp_bfd_thread, NULL,
				     thread->u.fd, TIMER_NEVER);

	if (thread->type != THREAD_READY_FD)
		return 0;

	while (read(thread->u.fd, &evt, sizeof(bfd_event_t)) != -1)
		vrrp_handle_bfd_event(&evt);

	return 0;
}
#endif

/* Handle dispatcher read timeout */
static int
vrrp_dispatcher_read_timeout(sock_t *sock)
{
	vrrp_t *vrrp;
	int prev_state;

	set_time_now();

	rb_for_each_entry_cached(vrrp, &sock->rb_sands, rb_sands) {
		if (vrrp->sands.tv_sec == TIMER_DISABLED ||
		    timercmp(&vrrp->sands, &time_now, >))
			break;

		prev_state = vrrp->state;

		if (vrrp->state == VRRP_STATE_BACK) {
			if (__test_bit(LOG_DETAIL_BIT, &debug))
				log_message(LOG_INFO, "(%s) Receive advertisement timeout", vrrp->iname);
			vrrp_goto_master(vrrp);
		}
		else if (vrrp->state == VRRP_STATE_MAST)
			vrrp_master(vrrp);

		/* handle instance synchronization */
#ifdef _TSM_DEBUG_
		if (do_tsm_debug)
			log_message(LOG_INFO, "Send [%s] TSM transition : [%d,%d] Wantstate = [%d]",
				vrrp->iname, prev_state, vrrp->state, vrrp->wantstate);
#endif
		VRRP_TSM_HANDLE(prev_state, vrrp);

		vrrp_init_instance_sands(vrrp);
	}

	return sock->fd_in;
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
	vrrp_t vrrp_lookup;

	/* Clean the read buffer */
	memset(vrrp_buffer, 0, vrrp_buffer_len);

	/* read & affect received buffer */
	len = recvfrom(sock->fd_in, vrrp_buffer, vrrp_buffer_len, 0,
		       (struct sockaddr *) &src_addr, &src_addr_len);
	hd = vrrp_get_header(sock->family, vrrp_buffer, &proto);

	vrrp_lookup.vrid = hd->vrid;
	vrrp = rb_search(&sock->rb_vrid, &vrrp_lookup, rb_vrid, vrrp_vrid_cmp);

	/* If no instance found => ignore the advert */
	if (!vrrp)
		return sock->fd_in;

	if (vrrp->state == VRRP_STATE_FAULT ||
	    vrrp->state == VRRP_STATE_INIT) {
		/* We just ignore a message received when we are in fault state or
		 * not yet fully initialised */
		return sock->fd_in;
	}

	vrrp->pkt_saddr = src_addr;

	prev_state = vrrp->state;

	if (vrrp->state == VRRP_STATE_BACK)
		vrrp_state_backup(vrrp, vrrp_buffer, len);
	else if (vrrp->state == VRRP_STATE_MAST) {
		if (vrrp_state_master_rx(vrrp, vrrp_buffer, len))
			vrrp_state_leave_master(vrrp, false);
	} else
		log_message(LOG_INFO, "(%s) In dispatcher_read with state %d", vrrp->iname, vrrp->state);

	/* handle instance synchronization */
#ifdef _TSM_DEBUG_
	if (do_tsm_debug)
		log_message(LOG_INFO, "Read [%s] TSM transition : [%d,%d] Wantstate = [%d]",
			vrrp->iname, prev_state, vrrp->state, vrrp->wantstate);
#endif
	VRRP_TSM_HANDLE(prev_state, vrrp);

	/* If we have sent an advert, reset the timer */
	if (vrrp->state != VRRP_STATE_MAST || !vrrp->lower_prio_no_advert)
		vrrp_init_instance_sands(vrrp);

	return sock->fd_in;
}

/* Our read packet dispatcher */
static int
vrrp_read_dispatcher_thread(thread_t * thread)
{
	sock_t *sock;
	int fd;

	/* Fetch thread arg */
	sock = THREAD_ARG(thread);

	/* Dispatcher state handler */
	if (thread->type == THREAD_READ_TIMEOUT || sock->fd_in == -1)
		fd = vrrp_dispatcher_read_timeout(sock);
	else
		fd = vrrp_dispatcher_read(sock);

	/* register next dispatcher thread */
	if (fd != -1)
		sock->thread = thread_add_read_sands(thread->master, vrrp_read_dispatcher_thread,
					       sock, fd, vrrp_compute_timer(sock));

	return 0;
}

static int
vrrp_script_thread(thread_t * thread)
{
	vrrp_script_t *vscript = THREAD_ARG(thread);
	int ret;

	/* Register next timer tracker */
	thread_add_timer(thread->master, vrrp_script_thread, vscript,
			 vscript->interval);

	if (vscript->state != SCRIPT_STATE_IDLE) {
		/* We don't want the system to be overloaded with scripts that we are executing */
		log_message(LOG_INFO, "Track script %s is %s, expect idle - skipping run",
			    vscript->sname, vscript->state == SCRIPT_STATE_RUNNING ? "already running" : "being timed out");

		return 0;
	}

	/* Execute the script in a child process. Parent returns, child doesn't */
	ret = system_call_script(thread->master, vrrp_script_child_thread,
				  vscript, (vscript->timeout) ? vscript->timeout : vscript->interval,
				  &vscript->script);
	if (!ret)
		vscript->state = SCRIPT_STATE_RUNNING;

	return ret;
}

static int
vrrp_script_child_thread(thread_t * thread)
{
	int wait_status;
	pid_t pid;
	vrrp_script_t *vscript = THREAD_ARG(thread);
	int sig_num;
	unsigned timeout = 0;
	char *script_exit_type = NULL;
	bool script_success;
	char *reason = NULL;
	int reason_code;

	if (thread->type == THREAD_CHILD_TIMEOUT) {
		pid = THREAD_CHILD_PID(thread);

		if (vscript->state == SCRIPT_STATE_RUNNING) {
			vscript->state = SCRIPT_STATE_REQUESTING_TERMINATION;
			sig_num = SIGTERM;
			timeout = 2;
		} else if (vscript->state == SCRIPT_STATE_REQUESTING_TERMINATION) {
			vscript->state = SCRIPT_STATE_FORCING_TERMINATION;
			sig_num = SIGKILL;
			timeout = 2;
		} else if (vscript->state == SCRIPT_STATE_FORCING_TERMINATION) {
			log_message(LOG_INFO, "Child (PID %d) failed to terminate after kill", pid);
			sig_num = SIGKILL;
			timeout = 10;	/* Give it longer to terminate */
		}

		/* Kill it off. */
		if (timeout) {
			/* If kill returns an error, we can't kill the process since either the process has terminated,
			 * or we don't have permission. If we can't kill it, there is no point trying again. */
			if (kill(-pid, sig_num)) {
				if (errno == ESRCH) {
					/* The process does not exist; presumably it
					 * has just terminated. We should get
					 * notification of it's termination, so allow
					 * that to handle it. */
					timeout = 1;
				} else {
					log_message(LOG_INFO, "kill -%d of process %s(%d) with new state %d failed with errno %d", sig_num, vscript->script.args[0], pid, vscript->state, errno);
					timeout = 1000;
				}
			}
		} else if (vscript->state != SCRIPT_STATE_IDLE) {
			log_message(LOG_INFO, "Child thread pid %d timeout with unknown script state %d", pid, vscript->state);
			timeout = 10;	/* We need some timeout */
		}

		if (timeout)
			thread_add_child(thread->master, vrrp_script_child_thread, vscript, pid, timeout * TIMER_HZ);

		return 0;
	}

	wait_status = THREAD_CHILD_STATUS(thread);

	if (WIFEXITED(wait_status)) {
		int status = WEXITSTATUS(wait_status);

		/* Report if status has changed */
		if (status != vscript->last_status)
			log_message(LOG_INFO, "Script `%s` now returning %d", vscript->sname, status);

		if (status == 0) {
			/* success */
			script_exit_type = "succeeded";
			script_success = true;
		} else {
			/* failure */
			script_exit_type = "failed";
			script_success = false;
			reason = "exited with status";
			reason_code = status;
		}

		vscript->last_status = status;
	}
	else if (WIFSIGNALED(wait_status)) {
		if (vscript->state == SCRIPT_STATE_REQUESTING_TERMINATION && WTERMSIG(wait_status) == SIGTERM) {
			/* The script terminated due to a SIGTERM, and we sent it a SIGTERM to
			 * terminate the process. Now make sure any children it created have
			 * died too. */
			pid = THREAD_CHILD_PID(thread);
			kill(-pid, SIGKILL);
		}

		/* We treat forced termination as a failure */
		if ((vscript->state == SCRIPT_STATE_REQUESTING_TERMINATION && WTERMSIG(wait_status) == SIGTERM) ||
		    (vscript->state == SCRIPT_STATE_FORCING_TERMINATION && (WTERMSIG(wait_status) == SIGKILL || WTERMSIG(wait_status) == SIGTERM)))
			script_exit_type = "timed_out";
		else {
			script_exit_type = "failed";
			reason = "due to signal";
			reason_code = WTERMSIG(wait_status);
		}
		script_success = false;
	}

	if (script_exit_type) {
		if (script_success) {
			if (vscript->result < vscript->rise - 1) {
				vscript->result++;
			} else if (vscript->result != vscript->rise + vscript->fall - 1) {
				if (vscript->result < vscript->rise) {	/* i.e. == vscript->rise - 1 */
					log_message(LOG_INFO, "VRRP_Script(%s) %s", vscript->sname, script_exit_type);
					update_script_priorities(vscript, true);
				}
				vscript->result = vscript->rise + vscript->fall - 1;
			}
		} else {
			if (vscript->result > vscript->rise) {
				vscript->result--;
			} else {
				if (vscript->result == vscript->rise ||
				    vscript->init_state == SCRIPT_INIT_STATE_INIT) {
					if (reason)
						log_message(LOG_INFO, "VRRP_Script(%s) %s (%s %d)", vscript->sname, script_exit_type, reason, reason_code);
					else
						log_message(LOG_INFO, "VRRP_Script(%s) %s", vscript->sname, script_exit_type);
					update_script_priorities(vscript, false);
				}
				vscript->result = 0;
			}
		}
	}

	vscript->state = SCRIPT_STATE_IDLE;
	vscript->init_state = SCRIPT_INIT_STATE_DONE;

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
void
dump_threads(void)
{
	FILE *fp;
	char time_buf[26];
	element e;
	vrrp_t *vrrp;
	char *file_name;

	file_name = make_file_name("/tmp/thread_dump.dat",
					"vrrp",
#if HAVE_DECL_CLONE_NEWNET
					global_data->network_namespace,
#else
					NULL,
#endif
					global_data->instance_name);
	fp = fopen(file_name, "a");
	FREE(file_name);

	set_time_now();
	ctime_r(&time_now.tv_sec, time_buf);

	fprintf(fp, "\n%.19s.%6.6ld: Thread dump\n", time_buf, time_now.tv_usec);

	dump_thread_data(master, fp);

	fprintf(fp, "alloc = %lu\n", master->alloc);

	fprintf(fp, "\n");
	LIST_FOREACH(vrrp_data->vrrp, vrrp, e) {
		ctime_r(&vrrp->sands.tv_sec, time_buf);
		fprintf(fp, "VRRP instance %s, sands %.19s.%6.6lu, status %s\n", vrrp->iname, time_buf, vrrp->sands.tv_usec,
				vrrp->state == VRRP_STATE_INIT ? "INIT" :
				vrrp->state == VRRP_STATE_BACK ? "BACKUP" :
				vrrp->state == VRRP_STATE_MAST ? "MASTER" :
				vrrp->state == VRRP_STATE_FAULT ? "FAULT" :
				vrrp->state == VRRP_STATE_STOP ? "STOP" :
				vrrp->state == VRRP_DISPATCHER ? "DISPATCHER" : "unknown");
	}
	fclose(fp);
}
#endif

#ifdef THREAD_DUMP
void
register_vrrp_scheduler_addresses(void)
{
	register_thread_address("vrrp_arp_thread", vrrp_arp_thread);
	register_thread_address("vrrp_dispatcher_init", vrrp_dispatcher_init);
	register_thread_address("vrrp_gratuitous_arp_thread", vrrp_gratuitous_arp_thread);
	register_thread_address("vrrp_lower_prio_gratuitous_arp_thread", vrrp_lower_prio_gratuitous_arp_thread);
	register_thread_address("vrrp_script_child_thread", vrrp_script_child_thread);
	register_thread_address("vrrp_script_thread", vrrp_script_thread);
	register_thread_address("vrrp_read_dispatcher_thread", vrrp_read_dispatcher_thread);
#ifdef _WITH_BFD_
	register_thread_address("vrrp_bfd_thread", vrrp_bfd_thread);
#endif
}
#endif
