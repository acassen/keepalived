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
#include <inttypes.h>

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
#include "list_head.h"
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
#ifdef _WITH_LVS_
#include "ipvswrapper.h"
#endif

/* For load testing recvmsg() */
/* #define DEBUG_RECVMSG */

/* For _RECVMSG_DEBUG_ we want load testing code as well */
#ifdef _RECVMSG_DEBUG_
#define DEBUG_RECVMSG	1
#endif

/* global vars */
timeval_t garp_next_time;
thread_ref_t garp_thread;
bool vrrp_initialised;
timeval_t vrrp_delayed_start_time;

#ifdef _TSM_DEBUG_
bool do_tsm_debug;
#endif
#ifdef _RECVMSG_DEBUG_
bool do_recvmsg_debug;
bool do_recvmsg_debug_dump;
#endif

/* local variables */
#ifdef _WITH_BFD_
static thread_ref_t bfd_thread;		 /* BFD control pipe read thread */
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

static void vrrp_script_child_thread(thread_ref_t);
static void vrrp_script_thread(thread_ref_t);
#ifdef _WITH_BFD_
static void vrrp_bfd_thread(thread_ref_t);
#endif

static void vrrp_read_dispatcher_thread(thread_ref_t);

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
vrrp_init_state(list_head_t *l)
{
	vrrp_t *vrrp;
	vrrp_sgroup_t *vgroup;
	bool is_up;
	int new_state;

	/* We can send SMTP messages from this point, so set the time */
	set_time_now();

	/* Do notifications for any sync groups in fault or backup state */
	list_for_each_entry(vgroup, &vrrp_data->vrrp_sync_group, e_list) {
		/* Init group if needed  */
		if ((vgroup->state == VRRP_STATE_FAULT ||
		     vgroup->state == VRRP_STATE_BACK) &&
		     !vgroup->state_same_at_reload)
			send_group_notifies(vgroup);
		vgroup->state_same_at_reload = false;
	}

	list_for_each_entry(vrrp, l, e_list) {
		int vrrp_begin_state = vrrp->state;

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
			    global_data->lvs_syncd.vrrp == vrrp &&
			    !global_data->lvs_syncd.daemon_set_reload)
				ipvs_syncd_cmd(IPVS_STARTDAEMON,
					       &global_data->lvs_syncd,
					       vrrp->state == VRRP_STATE_MAST ? IPVS_MASTER : IPVS_BACKUP,
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
			    global_data->lvs_syncd.vrrp == vrrp &&
			    !global_data->lvs_syncd.daemon_set_reload)
				ipvs_syncd_cmd(IPVS_STARTDAEMON,
					       &global_data->lvs_syncd,
					       IPVS_BACKUP,
					       false);
#endif

			/* Set interface state */
			vrrp_restore_interface(vrrp, false, false);
			if (is_up && new_state != VRRP_STATE_FAULT && !vrrp->num_script_init && (!vrrp->sync || !vrrp->sync->num_member_init)) {
				if (vrrp->state != VRRP_STATE_BACK) {
					log_message(LOG_INFO, "(%s) Entering BACKUP STATE (init)", vrrp->iname);
					vrrp->state = VRRP_STATE_BACK;
				}
			} else {
				/* Note: if we have alpha mode scripts, we enter fault state, but don't want
				 * to log it here */
				if (vrrp_begin_state != vrrp->state)
					log_message(LOG_INFO, "(%s) Entering FAULT STATE (init)", vrrp->iname);
				vrrp->state = VRRP_STATE_FAULT;
			}
			if (vrrp_begin_state != vrrp->state) {
				if (vrrp->state != VRRP_STATE_FAULT || vrrp->num_script_if_fault)
					send_instance_notifies(vrrp);
				vrrp->last_transition = timer_now();
			}
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
vrrp_init_instance_sands(vrrp_t *vrrp)
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
		if (vrrp_delayed_start_time.tv_sec) {
			if (timercmp(&time_now, &vrrp_delayed_start_time, <))
				vrrp->sands = timer_add_long(vrrp_delayed_start_time, vrrp->ms_down_timer);
			else {
				/* If we clear the delayed_start_time once past, then
				 * the code will be slightly more efficient */
				if (time_now.tv_sec > vrrp_delayed_start_time.tv_sec)
					vrrp_delayed_start_time.tv_sec = 0;
				vrrp->sands = timer_add_long(time_now, vrrp->ms_down_timer);
			}
		} else
			vrrp->sands = timer_add_long(time_now, vrrp->ms_down_timer);
	}
	else if (vrrp->state == VRRP_STATE_FAULT || vrrp->state == VRRP_STATE_INIT)
		vrrp->sands.tv_sec = TIMER_DISABLED;

	rb_move_cached(&vrrp->sockets->rb_sands, vrrp, rb_sands, vrrp_timer_cmp);
}

static void
vrrp_init_sands(list_head_t *l)
{
	vrrp_t *vrrp;

	list_for_each_entry(vrrp, l, e_list) {
		vrrp->sands.tv_sec = TIMER_DISABLED;
		rb_insert_sort_cached(&vrrp->sockets->rb_sands, vrrp, rb_sands, vrrp_timer_cmp);
		vrrp_init_instance_sands(vrrp);
		vrrp->reload_master = false;
	}
}

static void
vrrp_init_script(list_head_t *l)
{
	vrrp_script_t *vscript;

	list_for_each_entry(vscript, l, e_list) {
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

	/* The sock won't exist if there isn't a vrrp instance on it,
	 * so rb_first will always exist. */
	vrrp = rb_entry(rb_first_cached(&sock->rb_sands), vrrp_t, rb_sands);
	return &vrrp->sands;
}

void
vrrp_thread_requeue_read(vrrp_t *vrrp)
{
	thread_requeue_read(master, vrrp->sockets->fd_in, vrrp_compute_timer(vrrp->sockets));
}

/* Thread functions */
static void
vrrp_register_workers(list_head_t *l)
{
	sock_t *sock;
	timeval_t timer;

	/* Init compute timer */
	memset(&timer, 0, sizeof(timer));

	/* Init the VRRP instances state */
	vrrp_init_state(&vrrp_data->vrrp);

	/* Init VRRP instances sands */
	vrrp_init_sands(&vrrp_data->vrrp);

	/* Init VRRP tracking scripts */
	if (!list_empty(&vrrp_data->vrrp_script))
		vrrp_init_script(&vrrp_data->vrrp_script);

#ifdef _WITH_BFD_
	if (!list_empty(&vrrp_data->vrrp)) {
// TODO - should we only do this if we have track_bfd? Probably not
		/* Init BFD tracking thread */
		bfd_thread = thread_add_read(master, vrrp_bfd_thread, NULL,
					     bfd_vrrp_event_pipe[0], TIMER_NEVER, 0);
	}
#endif

	/* Register VRRP workers threads */
	list_for_each_entry(sock, l, e_list) {
		/* Register a timer thread if interface exists */
		if (sock->fd_in != -1)
			sock->thread = thread_add_read_sands(master, vrrp_read_dispatcher_thread,
						       sock, sock->fd_in, vrrp_compute_timer(sock), 0);
	}
}

void
vrrp_thread_add_read(vrrp_t *vrrp)
{
	vrrp->sockets->thread = thread_add_read_sands(master, vrrp_read_dispatcher_thread,
						vrrp->sockets, vrrp->sockets->fd_in, vrrp_compute_timer(vrrp->sockets), 0);
}

/* VRRP dispatcher functions */
static sock_t * __attribute__ ((pure))
already_exist_sock(list_head_t *l, sa_family_t family, int proto, interface_t *ifp, const struct sockaddr_storage *unicast_src)
{
	sock_t *sock;

	list_for_each_entry(sock, l, e_list) {
		if ((sock->family == family)	&&
		    (sock->proto == proto)	&&
		    (sock->ifp == ifp)		&&
		    (!unicast_src == !sock->unicast_src) &&
		    (!unicast_src || !inet_sockaddrcmp(sock->unicast_src, unicast_src)))
			return sock;
	}

	return NULL;
}

static sock_t *
alloc_sock(sa_family_t family, list_head_t *l, int proto, interface_t *ifp, const struct sockaddr_storage *unicast_src)
{
	sock_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->e_list);
	new->family = family;
	new->proto = proto;
	if (unicast_src)
		new->unicast_src = unicast_src;
	new->ifp = ifp;
	new->rb_vrid = RB_ROOT;
	new->rb_sands = RB_ROOT_CACHED;

	list_add_tail(&new->e_list, l);

	return new;
}

static inline int
vrrp_vrid_cmp(const vrrp_t *v1, const vrrp_t *v2)
{
	return less_equal_greater_than(v1->vrid, v2->vrid);
}

static void
vrrp_create_sockpool(list_head_t *l)
{
	vrrp_t *vrrp;
	interface_t *ifp;
	int proto;
	sock_t *sock;
	struct sockaddr_storage *unicast_src;

	list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
		if (list_empty(&vrrp->unicast_peer))
			unicast_src = NULL;
		else
			unicast_src = &vrrp->saddr;

		ifp =
#ifdef _HAVE_VRRP_VMAC_
		      (__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags)) ? vrrp->configured_ifp :
#endif
										vrrp->ifp;

		proto = IPPROTO_VRRP;
#if defined _WITH_VRRP_AUTH_
		if (vrrp->auth_type == VRRP_AUTH_AH)
			proto = IPPROTO_AH;
#endif

		/* add the vrrp element if not exist */
		if (!(sock = already_exist_sock(l, vrrp->family, proto, ifp, unicast_src)))
			sock = alloc_sock(vrrp->family, l, proto, ifp, unicast_src);

		/* Add the vrrp_t indexed by vrid to the socket */
		rb_insert_sort(&sock->rb_vrid, vrrp, rb_vrid, vrrp_vrid_cmp);

		if (vrrp->kernel_rx_buf_size)
			sock->rx_buf_size += vrrp->kernel_rx_buf_size;
		else if (global_data->vrrp_rx_bufs_policy & RX_BUFS_SIZE)
			sock->rx_buf_size += global_data->vrrp_rx_bufs_size;
		else if (global_data->vrrp_rx_bufs_policy & RX_BUFS_POLICY_ADVERT)
			sock->rx_buf_size += global_data->vrrp_rx_bufs_multiples * vrrp_adv_len(vrrp);
		else if (vrrp->ifp && global_data->vrrp_rx_bufs_policy & RX_BUFS_POLICY_MTU)
			sock->rx_buf_size += global_data->vrrp_rx_bufs_multiples * vrrp->ifp->mtu;
	}
}

static void
vrrp_open_sockpool(list_head_t *l)
{
	sock_t *sock;

	list_for_each_entry(sock, l, e_list) {
		if (sock->ifp && !sock->ifp->ifindex) {
			sock->fd_in = sock->fd_out = -1;
			continue;
		}

		/* coverity[var_deref_model] */
		open_sockpool_socket(sock);
	}
}

static void
vrrp_set_fds(list_head_t *l)
{
	sock_t *sock;
	vrrp_t *vrrp;

	list_for_each_entry(sock, l, e_list) {
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
void
vrrp_dispatcher_init(__attribute__((unused)) thread_ref_t thread)
{
	vrrp_create_sockpool(&vrrp_data->vrrp_socket_pool);

	/* open the VRRP socket pool */
	vrrp_open_sockpool(&vrrp_data->vrrp_socket_pool);

	/* set VRRP instance fds to sockpool */
	vrrp_set_fds(&vrrp_data->vrrp_socket_pool);

	/* create the VRRP socket pool list */
	/* register read dispatcher worker thread */
	vrrp_register_workers(&vrrp_data->vrrp_socket_pool);

	/* Dump socket pool */
	if (__test_bit(LOG_DETAIL_BIT, &debug))
		dump_sock_list(NULL, &vrrp_data->vrrp_socket_pool);

	vrrp_initialised = true;
}

#ifdef _WITH_BFD_
void
cancel_vrrp_threads(void)
{
	if (bfd_thread) {
		thread_cancel(bfd_thread);
		bfd_thread = NULL;
	}
}
#endif

void
vrrp_dispatcher_release(vrrp_data_t *data)
{
	free_sock_list(&data->vrrp_socket_pool);

#ifdef _WITH_BFD_
	cancel_vrrp_threads();
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
void
vrrp_gratuitous_arp_thread(thread_ref_t thread)
{
	vrrp_t *vrrp = THREAD_ARG(thread);

	/* Simply broadcast the gratuitous ARP */
	vrrp_send_link_update(vrrp, vrrp->garp_rep);
}

/* Delayed gratuitous ARP thread after receiving a lower priority advert */
void
vrrp_lower_prio_gratuitous_arp_thread(thread_ref_t thread)
{
	vrrp_t *vrrp = THREAD_ARG(thread);

	/* Simply broadcast the gratuitous ARP */
	vrrp_send_link_update(vrrp, vrrp->garp_lower_prio_rep);
}

void
try_up_instance(vrrp_t *vrrp, bool leaving_init)
{
	int wantstate;
	ip_address_t ip_addr = {};

	if (leaving_init) {
		if (vrrp->num_script_if_fault)
			return;
	}
	else if (--vrrp->num_script_if_fault || vrrp->num_script_init) {
		if (!vrrp->num_script_if_fault) {
			if (vrrp->sync) {
				vrrp->sync->num_member_fault--;
				vrrp->sync->state = VRRP_STATE_INIT;
			}
			vrrp->wantstate = VRRP_STATE_BACK;
		}

		return;
	}

	if (vrrp->wantstate == VRRP_STATE_MAST && vrrp->base_priority == VRRP_PRIO_OWNER) {
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

	/* If we are using unicast, the master may have lost us from its ARP cache.
	 * We want to renew the ARP cache on the master, so that it can send adverts
	 * to us straight away, without a delay before it sends an ARP request message
	 * and we respond. If we don't do this, we can time out and transition to master
	 * before the master renews its ARP entry, since the master cannot send us adverts
	 * until it has done so. */
	if (!list_empty(&vrrp->unicast_peer) &&
	    vrrp->ifp &&
	    vrrp->saddr.ss_family != AF_UNSPEC) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "%s: sending gratuitous %s for %s", vrrp->iname, vrrp->family == AF_INET ? "ARP" : "NA", inet_sockaddrtos(&vrrp->saddr));

		ip_addr.ifp = IF_BASE_IFP(vrrp->ifp);

		if (vrrp->saddr.ss_family == AF_INET) {
			ip_addr.u.sin.sin_addr.s_addr = PTR_CAST(struct sockaddr_in, &vrrp->saddr)->sin_addr.s_addr;
			send_gratuitous_arp_immediate(ip_addr.ifp, &ip_addr);
		} else {
			/* IPv6 */
			ip_addr.u.sin6_addr = PTR_CAST(struct sockaddr_in6, &vrrp->saddr)->sin6_addr;
			ndisc_send_unsolicited_na_immediate(ip_addr.ifp, &ip_addr);
		}
	}

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
	tracking_obj_t *tbfd;
	vrrp_t * vrrp;
	struct timeval cur_time;
	struct timeval timer_tmp;
	uint32_t delivery_time;

	if (__test_bit(LOG_DETAIL_BIT, &debug)) {
		cur_time = timer_now();
		timersub(&cur_time, &evt->sent_time, &timer_tmp);
		delivery_time = timer_long(timer_tmp);
		log_message(LOG_INFO, "Received BFD event: instance %s is in"
			    " state %s (delivered in %" PRIu32 " usec)",
			    evt->iname, BFD_STATE_STR(evt->state), delivery_time);
	}

	list_for_each_entry(vbfd, &vrrp_data->vrrp_track_bfds, e_list) {
		if (strcmp(vbfd->bname, evt->iname))
			continue;

		if ((vbfd->bfd_up && evt->state == BFD_STATE_UP) ||
		    (!vbfd->bfd_up && evt->state == BFD_STATE_DOWN))
			continue;

		vbfd->bfd_up = (evt->state == BFD_STATE_UP);

		list_for_each_entry(tbfd, &vbfd->tracking_vrrp, e_list) {
			vrrp = tbfd->obj.vrrp;

			log_message(LOG_INFO, "VRRP_Instance(%s) Tracked BFD"
				    " instance %s is %s", vrrp->iname, evt->iname, vbfd->bfd_up ? "UP" : "DOWN");

			if (tbfd->weight) {
				if (vbfd->bfd_up)
					vrrp->total_priority += abs(tbfd->weight) * tbfd->weight_multiplier;
				else
					vrrp->total_priority -= abs(tbfd->weight) * tbfd->weight_multiplier;
				vrrp_set_effective_priority(vrrp);

				continue;
			}

			if (!!vbfd->bfd_up == (tbfd->weight_multiplier == 1))
				try_up_instance(vrrp, false);
			else
				down_instance(vrrp);
		}

		break;
	}
}

static void
vrrp_bfd_thread(thread_ref_t thread)
{
	bfd_event_t evt;

	bfd_thread = thread_add_read(master, vrrp_bfd_thread, NULL,
				     thread->u.f.fd, TIMER_NEVER, 0);

	if (thread->type != THREAD_READY_READ_FD)
		return;

	while (read(thread->u.f.fd, &evt, sizeof(bfd_event_t)) != -1)
		vrrp_handle_bfd_event(&evt);
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
			vrrp_state_master_tx(vrrp);

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
vrrp_dispatcher_read(sock_t *sock)
{
	vrrp_t *vrrp;
	const vrrphdr_t *hd;
	ssize_t len = 0;
	int prev_state = 0;
	struct sockaddr_storage src_addr = { .ss_family = AF_UNSPEC };
	vrrp_t vrrp_lookup;
#ifdef _NETWORK_TIMESTAMP_
	char control_buf[128] __attribute__((aligned(__alignof__(struct cmsghdr))));
#else
	char control_buf[64] __attribute__((aligned(__alignof__(struct cmsghdr))));
#endif
	struct iovec iovec = { .iov_base = vrrp_buffer, .iov_len = vrrp_buffer_len };
	struct msghdr msghdr = { .msg_name = &src_addr, .msg_namelen = sizeof(src_addr),
				 .msg_iov = &iovec, .msg_iovlen = 1,
				 .msg_control = control_buf, .msg_controllen = sizeof(control_buf) };
	struct cmsghdr *cmsg;
	bool expected_cmsg;
	unsigned eintr_count;
	unsigned long rx_vrid_map[BIT_WORD(256 + BIT_PER_LONG - 1)] = { 0 };
	bool terminate_receiving = false;
#ifdef DEBUG_RECVMSG
	unsigned recv_data_count = 0;
#endif
	const struct iphdr *iph;

	/* Strategy here is to handle incoming adverts pending into socket recvq
	 * but stop if receive 2nd advert for a VRID on socket (this applies to
	 * both configured and unconfigured VRIDs).
	 * Seems a good tradeoff while simulating */
	while (!terminate_receiving) {
		/* read & affect received buffer */
		eintr_count = 0;
		while ((len = recvmsg(sock->fd_in, &msghdr, MSG_TRUNC | MSG_CTRUNC)) == -1 &&
		       check_EINTR(errno) && eintr_count++ < 10);
		if (len < 0) {
#ifdef DEBUG_RECVMSG
#ifdef _RECVMSG_DEBUG_
			if (do_recvmsg_debug && (!recv_data_count || !check_EAGAIN(errno)))
				log_message(LOG_INFO, "recvmsg(%d) returned errno %d, %u eintr", sock->fd_in, errno, eintr_count);
#endif

#ifdef _RECVMSG_DEBUG_
			if (do_recvmsg_debug)
#endif
			{
				if (check_EINTR(errno))
					log_message(LOG_INFO, "recvmsg(%d) looped %u times due to EINTR before terminating loop"
							    , sock->fd_in, eintr_count);
			}
#endif

			if (!check_EAGAIN(errno))
				log_message(LOG_INFO, "recvmsg(%d) returned %d (%m)"
						    , sock->fd_in, errno);
#ifdef DEBUG_RECVMSG
			else if (
#ifdef _RECVMSG_DEBUG_
				 do_recvmsg_debug &&
#endif
				 recv_data_count == 0)
				log_message(LOG_INFO, "recvmsg(%d) returned EAGAIN without any data being received"
						    , sock->fd_in);

#ifdef _RECVMSG_DEBUG_
			if (do_recvmsg_debug)
#endif
			{
				if (recv_data_count != 1)
					log_message(LOG_INFO, "recvmsg(%d) loop received %u packets"
							    , sock->fd_in, recv_data_count);
			}
#endif
			break;
		}
#ifdef _RECVMSG_DEBUG_
		else if (do_recvmsg_debug)
			log_message(LOG_INFO, "recvmsg(%d) looped %u times due to EINTR before returning %zd bytes from %s"
					    , sock->fd_in, eintr_count, len, inet_sockaddrtos(&src_addr));
#elif defined DEBUG_RECVMSG
		if (eintr_count)
			log_message(LOG_INFO, "recvmsg(%d) looped %u times due to EINTR before returning %ld"
					    , sock->fd_in, eintr_count, len);
#endif

		/* Don't attempt to process data if no data received */
		if (len == 0) {
			log_message(LOG_INFO, "recvmsg(%d) returned data length 0", sock->fd_in);
			continue;
		}

#ifdef _RECVMSG_DEBUG_
		if (do_recvmsg_debug_dump) {
			log_buffer("Received data", vrrp_buffer, len);
		}
#endif

#ifdef DEBUG_RECVMSG
		recv_data_count++;
#endif

		if (msghdr.msg_flags & MSG_TRUNC) {
			log_message(LOG_INFO, "recvmsg(%d) message truncated from %zd to %zu bytes"
					    , sock->fd_in, len, vrrp_buffer_len);
			continue;
		}

		if (msghdr.msg_flags & MSG_CTRUNC) {
			log_message(LOG_INFO, "recvmsg(%d), control message truncated from %zu to %" PRI_MSG_CONTROLLEN " bytes"
					    , sock->fd_in, sizeof(control_buf), msghdr.msg_controllen);
			msghdr.msg_controllen = 0;
		}

		/* Check the received data includes at least the IP, possibly
		 * the AH header and the VRRP header */
		if (!(hd = vrrp_get_header(sock->family, vrrp_buffer, len)))
			break;

		/* Defense strategy here is to handle no more than one advert
		 * per VRID in order to flush socket rcvq...
		 * This is a best effort mitigation */
		if (__test_and_set_bit_array(hd->vrid, rx_vrid_map))
			terminate_receiving = true;

		vrrp_lookup.vrid = hd->vrid;
		vrrp = rb_search(&sock->rb_vrid, &vrrp_lookup, rb_vrid, vrrp_vrid_cmp);

		/* No instance found => ignore the advert */
		if (!vrrp) {
			if (global_data->log_unknown_vrids)
				log_message(LOG_INFO, "Unknown VRID(%d) received on interface(%s). ignoring..."
						    , hd->vrid, IF_NAME(sock->ifp));
			continue;
		}

		if (vrrp->state == VRRP_STATE_FAULT || vrrp->state == VRRP_STATE_INIT) {
			/* We just ignore a message received when we are in fault state or
			 * not yet fully initialised */
			continue;
		}

		/* Save non packet data */
		vrrp->pkt_saddr = src_addr;
		vrrp->rx_ttl_hop_limit = -1;           /* Default to not received */
		if (sock->family == AF_INET) {
			iph = PTR_CAST_CONST(struct iphdr, vrrp_buffer);
			vrrp->multicast_pkt = IN_MULTICAST(htonl(iph->daddr));
			vrrp->rx_ttl_hop_limit = iph->ttl;
		} else
			vrrp->multicast_pkt = false;
		for (cmsg = CMSG_FIRSTHDR(&msghdr); cmsg; cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
			expected_cmsg = false;
			if (cmsg->cmsg_level == IPPROTO_IPV6) {
				expected_cmsg = true;

				if (cmsg->cmsg_type == IPV6_HOPLIMIT &&
				    cmsg->cmsg_len - sizeof(struct cmsghdr) == sizeof(unsigned int))
					vrrp->rx_ttl_hop_limit = *PTR_CAST(unsigned int, CMSG_DATA(cmsg));
				else
				if (cmsg->cmsg_type == IPV6_PKTINFO &&
				    cmsg->cmsg_len - sizeof(struct cmsghdr) == sizeof(struct in6_pktinfo))
					vrrp->multicast_pkt = IN6_IS_ADDR_MULTICAST(&(PTR_CAST(struct in6_pktinfo, CMSG_DATA(cmsg)))->ipi6_addr);
				else
					expected_cmsg = false;
			}
#ifdef _NETWORK_TIMESTAMP_
			else if (do_network_timestamp && cmsg->cmsg_level == SOL_SOCKET) {
				struct timespec *ts = (void *)CMSG_DATA(cmsg);
				char time_buf[9];

				expected_cmsg = true;
				if (cmsg->cmsg_type == SO_TIMESTAMPNS) {
					strftime(time_buf, sizeof time_buf, "%T", localtime(&ts->tv_sec));
					log_message(LOG_INFO, "TIMESTAMPNS (socket %d - VRID %u) %s.%9.9ld"
							    , sock->fd_in, hd->vrid, time_buf, ts->tv_nsec);
				}
#if 0
				if (cmsg->cmsg_type == SO_TIMESTAMP) {
					struct timeval *tv = (void *)CMSG_DATA(cmsg);
					log_message(LOG_INFO, "TIMESTAMP message (%d - %u)  %ld.%9.9ld"
							    , sock->fd_in, hd->vrid, tv->tv_sec, tv->tv_usec);
				}
				else if (cmsg->cmsg_type == SO_TIMESTAMPING) {
					struct timespec *ts = (void *)CMSG_DATA(cmsg);
					log_message(LOG_INFO, "TIMESTAMPING message (%d - %u)  %ld.%9.9ld, raw %ld.%9.9ld"
							    , sock->fd_in, hd->vrid, ts->tv_sec, ts->tv_nsec, (ts+2)->tv_sec, (ts+2)->tv_nsec);
				}
#endif
				else
					expected_cmsg = false;
			}
#endif

			if (!expected_cmsg)
				log_message(LOG_INFO, "fd %d, unexpected control msg len %" PRI_MSG_CONTROLLEN ", level %d, type %d"
						    , sock->fd_in, cmsg->cmsg_len
						    , cmsg->cmsg_level, cmsg->cmsg_type);
		}

		/* For multicast, we attempt to bind the socket to ::1 to stop receiving any (non ::1)
		 * unicast packets, but if that fails we will receive unicast packets on the multicast socket,
		 * so just discard them here.
		 * For unicast sockets, if any other instance on the same interface is using multicast we
		 * will also receive the multicast packets, so also discard them here. */
		if (sock->family == AF_INET6 && vrrp->multicast_pkt != list_empty(&vrrp->unicast_peer)) {
			if (__test_bit(LOG_DETAIL_BIT, &debug))
				log_message(LOG_INFO, "(%s) discarding %sicast packet on %sicast instance", vrrp->iname, vrrp->multicast_pkt ? "mult" : "un", list_empty(&vrrp->unicast_peer) ? "mult" : "un");
			continue;
		}

		prev_state = vrrp->state;

		if (vrrp->state == VRRP_STATE_BACK)
			vrrp_state_backup(vrrp, hd, vrrp_buffer, len);
		else if (vrrp->state == VRRP_STATE_MAST) {
			if (vrrp_state_master_rx(vrrp, hd, vrrp_buffer, len))
				vrrp_state_leave_master(vrrp, false);
		} else
			log_message(LOG_INFO, "(%s) In dispatcher_read with state %d"
					    , vrrp->iname, vrrp->state);


		/* handle instance synchronization */
#ifdef _TSM_DEBUG_
		if (do_tsm_debug)
			log_message(LOG_INFO, "Read [%s] TSM transition : [%d,%d] Wantstate = [%d]"
					    , vrrp->iname, prev_state, vrrp->state, vrrp->wantstate);
#endif
		VRRP_TSM_HANDLE(prev_state, vrrp);

		/* If we have sent an advert, reset the timer */
		if (vrrp->state != VRRP_STATE_MAST || !vrrp->lower_prio_no_advert)
			vrrp_init_instance_sands(vrrp);
	}

	return sock->fd_in;
}

/* Our read packet dispatcher */
static void
vrrp_read_dispatcher_thread(thread_ref_t thread)
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
						     sock, fd, vrrp_compute_timer(sock), 0);
}

static void
vrrp_script_thread(thread_ref_t thread)
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
	}

	/* Execute the script in a child process. Parent returns, child doesn't */
#ifdef _SCRIPT_DEBUG_
	if (do_script_debug)
		log_message(LOG_INFO, "Running vrrp script %s", vscript->sname);
#endif
	ret = system_call_script(thread->master, vrrp_script_child_thread,
				  vscript, (vscript->timeout) ? vscript->timeout : vscript->interval,
				  &vscript->script);
	if (!ret)
		vscript->state = SCRIPT_STATE_RUNNING;
}

static void
vrrp_script_child_thread(thread_ref_t thread)
{
	int wait_status;
	pid_t pid;
	vrrp_script_t *vscript = THREAD_ARG(thread);
	int sig_num;
	unsigned timeout = 0;
	const char *script_exit_type = NULL;
	bool script_success;
	const char *reason = NULL;
	int reason_code;

	if (thread->type == THREAD_CHILD_TIMEOUT) {
		pid = THREAD_CHILD_PID(thread);

		if (vscript->state == SCRIPT_STATE_RUNNING) {
			vscript->state = SCRIPT_STATE_REQUESTING_TERMINATION;
#ifdef _SCRIPT_DEBUG_
			if (do_script_debug)
				log_message(LOG_INFO, "Sending TERM to %d", pid);
#endif
			sig_num = SIGTERM;
			timeout = 2;
		} else if (vscript->state == SCRIPT_STATE_REQUESTING_TERMINATION) {
			vscript->state = SCRIPT_STATE_FORCING_TERMINATION;
			sig_num = SIGKILL;
#ifdef _SCRIPT_DEBUG_
			if (do_script_debug)
				log_message(LOG_INFO, "Sending KILL 2 to %d", pid);
#endif
			timeout = 2;
		} else if (vscript->state == SCRIPT_STATE_FORCING_TERMINATION) {
			log_message(LOG_INFO, "Script %s child (PID %d) failed to terminate after kill", vscript->sname, pid);
			sig_num = SIGKILL;
			timeout = 10;	/* Give it longer to terminate */
#ifdef _SCRIPT_DEBUG_
			if (do_script_debug)
				log_message(LOG_INFO, "Sending KILL 10 to %d", pid);
#endif
		}
#ifdef _SCRIPT_DEBUG_
		else if (do_script_debug)
			log_message(LOG_INFO, "script state %u for pid %d", vscript->state, pid);
#endif

		/* Kill it off. */
		if (timeout) {
			/* If kill returns an error, we can't kill the process since either the process has terminated,
			 * or we don't have permission. If we can't kill it, there is no point trying again. */
			if (kill(-pid, sig_num)) {
				if (errno == ESRCH) {
					/* The process does not exist, and we should
					 * have reaped its exit status, otherwise it
					 * would exist as a zombie process. */
					log_message(LOG_INFO, "Script %s child (PID %d) lost", vscript->sname, THREAD_CHILD_PID(thread));
#if defined _SCRIPT_DEBUG_ && defined THREAD_DUMP
					if (do_script_debug)
						dump_thread_data(thread->master, NULL);
#endif
					vscript->state = SCRIPT_STATE_IDLE;
					timeout = 0;
				} else {
					log_message(LOG_INFO, "kill -%d of process %s(%d) with new state %u failed with errno %d", sig_num, vscript->script.args[0], pid, vscript->state, errno);
					timeout = 1000;
				}
			}
		} else if (vscript->state != SCRIPT_STATE_IDLE) {
			log_message(LOG_INFO, "Script %s child thread pid %d timeout with unknown script state %u", vscript->sname, pid, vscript->state);
			timeout = 10;	/* We need some timeout */
		}

		if (timeout)
			thread_add_child(thread->master, vrrp_script_child_thread, vscript, pid, timeout * TIMER_HZ);

		return;
	}

	wait_status = THREAD_CHILD_STATUS(thread);

	if (WIFEXITED(wait_status)) {
		int status = WEXITSTATUS(wait_status);

#ifdef _SCRIPT_DEBUG_
		if (do_script_debug)
			log_message(LOG_INFO, "pid %d exited with status %d", THREAD_CHILD_PID(thread), status);
#endif

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
#ifdef _SCRIPT_DEBUG_
		if (do_script_debug)
			log_message(LOG_INFO, "pid %d exited due to signal %d (%s)", THREAD_CHILD_PID(thread), WTERMSIG(wait_status), strsignal(WTERMSIG(wait_status)));
#endif

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
#ifdef _SCRIPT_DEBUG_
	else if (do_script_debug)
		log_message(LOG_INFO, "wait for pid %d exited with exit code 0x%x", THREAD_CHILD_PID(thread), (unsigned)wait_status);
#endif

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
}

/* Delayed ARP/NA thread */
static int
vrrp_arpna_send(vrrp_t *vrrp, list_head_t *l, timeval_t *n)
{
	ip_address_t *ip_addr;
	interface_t *ifp;

	list_for_each_entry(ip_addr, l, e_list) {
		if (!ip_addr->garp_gna_pending)
			continue;

		if (!ip_addr->set) {
			ip_addr->garp_gna_pending = false;
			continue;
		}

		ifp = IF_BASE_IFP(ip_addr->ifp);

		/* This should never happen */
		if (!ifp->garp_delay) {
			ip_addr->garp_gna_pending = false;
			continue;
		}

		/* IPv4 handling */
		if (!IP_IS6(ip_addr)) {
			if (timercmp(&time_now, &ifp->garp_delay->garp_next_time, >=)) {
				send_gratuitous_arp_immediate(ifp, ip_addr);
				ip_addr->garp_gna_pending = false;
			} else {
				vrrp->garp_pending = true;
				if (timercmp(&ifp->garp_delay->garp_next_time, n, <))
					*n = ifp->garp_delay->garp_next_time;
			}
			continue;
		}

		/* IPv6 handling */
		if (timercmp(&time_now, &ifp->garp_delay->gna_next_time, >=)) {
			ndisc_send_unsolicited_na_immediate(ifp, ip_addr);
			ip_addr->garp_gna_pending = false;
		} else {
			vrrp->gna_pending = true;
			if (timercmp(&ifp->garp_delay->gna_next_time, n, <))
				*n = ifp->garp_delay->gna_next_time;
		}
	}

	return 0;
}

void
vrrp_arp_thread(thread_ref_t thread)
{
	vrrp_t *vrrp;
	timeval_t next_time = {
		.tv_sec = INT_MAX	/* We're never going to delay this long - I hope! */
	};

	set_time_now();

	list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
		if (!vrrp->garp_pending && !vrrp->gna_pending)
			continue;

		vrrp->garp_pending = false;
		vrrp->gna_pending = false;

		if (vrrp->state != VRRP_STATE_MAST || !vrrp->vipset)
			continue;

		vrrp_arpna_send(vrrp, &vrrp->vip, &next_time);
		vrrp_arpna_send(vrrp, &vrrp->evip, &next_time);
	}

	if (next_time.tv_sec != INT_MAX) {
		/* Register next timer tracker */
		garp_next_time = next_time;
		garp_thread = thread_add_timer(thread->master, vrrp_arp_thread, NULL,
					       timer_long(timer_sub_now(next_time)));
	} else
		garp_thread = NULL;
}

#ifdef _WITH_DUMP_THREADS_
void
dump_threads(void)
{
	FILE *fp;
	char time_buf[26];
	vrrp_t *vrrp;
	const char *file_name;

	file_name = make_file_name(KA_TMP_DIR "/thread_dump.dat",
					"vrrp",
					global_data->network_namespace,
					global_data->instance_name);
	fp = fopen_safe(file_name, "a");
	FREE_CONST(file_name);

	set_time_now();
	ctime_r(&time_now.tv_sec, time_buf);

	fprintf(fp, "\n%.19s.%6.6ld: Thread dump\n", time_buf, time_now.tv_usec);

	dump_thread_data(master, fp);

	fprintf(fp, "alloc = %lu\n", master->alloc);

	fprintf(fp, "\n");
	list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
		ctime_r(&vrrp->sands.tv_sec, time_buf);
		fprintf(fp, "VRRP instance %s, sands %.19s.%6.6ld, status %s\n", vrrp->iname, time_buf, vrrp->sands.tv_usec,
				vrrp->state == VRRP_STATE_INIT ? "INIT" :
				vrrp->state == VRRP_STATE_BACK ? "BACKUP" :
				vrrp->state == VRRP_STATE_MAST ? "MASTER" :
				vrrp->state == VRRP_STATE_FAULT ? "FAULT" :
				vrrp->state == VRRP_STATE_STOP ? "STOP" : "unknown");
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
