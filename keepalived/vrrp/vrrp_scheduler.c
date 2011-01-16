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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include "vrrp_scheduler.h"
#include "vrrp_ipsecah.h"
#include "vrrp_if.h"
#include "vrrp.h"
#include "vrrp_sync.h"
#include "vrrp_notify.h"
#include "vrrp_netlink.h"
#include "vrrp_data.h"
#include "vrrp_index.h"
#include "ipvswrapper.h"
#include "memory.h"
#include "notify.h"
#include "list.h"
#include "logger.h"
#include "main.h"
#include "smtp.h"
#include "signals.h"

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
static void vrrp_backup(vrrp_rt *, char *, int);
static void vrrp_leave_master(vrrp_rt *, char *, int);
static void vrrp_leave_fault(vrrp_rt *, char *, int);
static void vrrp_become_master(vrrp_rt *, char *, int);

static void vrrp_goto_master(vrrp_rt *);
static void vrrp_master(vrrp_rt *);
static void vrrp_fault(vrrp_rt *);

static int vrrp_update_priority(thread_t * thread);
static int vrrp_script_child_timeout_thread(thread_t * thread);
static int vrrp_script_child_thread(thread_t * thread);
static int vrrp_script_thread(thread_t * thread);

struct {
	void (*read) (vrrp_rt *, char *, int);
	void (*read_to) (vrrp_rt *);
} VRRP_FSM[VRRP_MAX_FSM_STATE + 1] =
{
/*    Stream Read Handlers      |    Stream Read_to handlers   *
 *------------------------------+------------------------------*/
	{NULL, 				NULL},
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
struct {
	void (*handler) (vrrp_rt *);
} VRRP_TSM[VRRP_MAX_TSM_STATE + 1][VRRP_MAX_TSM_STATE + 1] =
{
  { {NULL}, {NULL},                      {NULL},             {NULL}            },
  { {NULL}, {vrrp_sync_master_election}, {vrrp_sync_master}, {vrrp_sync_fault} },
  { {NULL}, {vrrp_sync_backup},          {vrrp_sync_master}, {vrrp_sync_fault} },
  { {NULL}, {vrrp_sync_backup},          {vrrp_sync_master}, {vrrp_sync_fault} }
};

/* SMTP alert notifier */
static void
vrrp_smtp_notifier(vrrp_rt * vrrp)
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
static void vrrp_log_int_down(vrrp_rt *vrrp)
{
	if (!IF_ISUP(vrrp->ifp))
		log_message(LOG_INFO, "Kernel is reporting: interface %s DOWN",
		       IF_NAME(vrrp->ifp));
	if (!LIST_ISEMPTY(vrrp->track_ifp))
		vrrp_log_tracked_down(vrrp->track_ifp);
}

static void vrrp_log_int_up(vrrp_rt *vrrp)
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
	vrrp_rt *vrrp;
	vrrp_sgroup *vgroup;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		/* In case of VRRP SYNC, we have to carefully check that we are
		 * not running floating priorities on any VRRP instance.
		 */
		if (vrrp->sync) {
			element e;
			tracked_sc *sc;
			tracked_if *tip;
			int warning = 0;

			if (!LIST_ISEMPTY(vrrp->track_ifp)) {
				for (e = LIST_HEAD(vrrp->track_ifp); e; ELEMENT_NEXT(e)) {
					tip = ELEMENT_DATA(e);
					if (tip->weight) {
						tip->weight = 0;
						warning++;
					}
				}
			}

			if (!LIST_ISEMPTY(vrrp->track_script)) {
				for (e = LIST_HEAD(vrrp->track_script); e;
				     ELEMENT_NEXT(e)) {
					sc = ELEMENT_DATA(e);
					if (sc->weight) {
						sc->scr->inuse--;
						warning++;
					}
				}
			}

			if (warning > 0) {
				log_message(LOG_INFO, "VRRP_Instance(%s) : ignoring "
						 "tracked script with weights due to SYNC group",
				       vrrp->iname);
			}
		} else {
			/* Register new priority update thread */
			thread_add_timer(master, vrrp_update_priority,
					 vrrp, vrrp->adver_int);
		}

		if (vrrp->base_priority == VRRP_PRIO_OWNER ||
		    vrrp->wantstate == VRRP_STATE_MAST) {
#ifdef _HAVE_IPVS_SYNCD_
			/* Check if sync daemon handling is needed */
			if (vrrp->lvs_syncd_if)
				ipvs_syncd_cmd(IPVS_STARTDAEMON,
					       vrrp->lvs_syncd_if, IPVS_MASTER,
					       vrrp->vrid);
#endif
			vrrp->state = VRRP_STATE_GOTO_MASTER;
		} else {
			vrrp->ms_down_timer = 3 * vrrp->adver_int
			    + VRRP_TIMER_SKEW(vrrp);
#ifdef _HAVE_IPVS_SYNCD_
			/* Check if sync daemon handling is needed */
			if (vrrp->lvs_syncd_if)
				ipvs_syncd_cmd(IPVS_STARTDAEMON,
					       vrrp->lvs_syncd_if, IPVS_BACKUP,
					       vrrp->vrid);
#endif
			log_message(LOG_INFO, "VRRP_Instance(%s) Entering BACKUP STATE",
			       vrrp->iname);

			/* Set BACKUP state */
			vrrp_restore_interface(vrrp, 0);
			vrrp->state = VRRP_STATE_BACK;
			vrrp_smtp_notifier(vrrp);
			notify_instance_exec(vrrp, VRRP_STATE_BACK);

			/* Init group if needed  */
			if ((vgroup = vrrp->sync)) {
				if (GROUP_STATE(vgroup) != VRRP_STATE_BACK) {
					vgroup->state = VRRP_STATE_BACK;
					vrrp_sync_smtp_notifier(vgroup);
					notify_group_exec(vgroup, VRRP_STATE_BACK);
				}
			}
		}
	}
}

static void
vrrp_init_sands(list l)
{
	vrrp_rt *vrrp;
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
	vrrp_script *vscript;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vscript = ELEMENT_DATA(e);
		if (vscript->inuse == 0)
			vscript->result = VRRP_SCRIPT_STATUS_DISABLED;

		if (vscript->result == VRRP_SCRIPT_STATUS_INIT) {
			vscript->result = vscript->rise - 1; /* one success is enough */
			thread_add_event(master, vrrp_script_thread, vscript, vscript->interval);
		} else if (vscript->result == VRRP_SCRIPT_STATUS_INIT_GOOD) {
			vscript->result = vscript->rise; /* one failure is enough */
			thread_add_event(master, vrrp_script_thread, vscript, vscript->interval);
		}
	}
}

/* Timer functions */
static TIMEVAL
vrrp_compute_timer(const int fd)
{
	vrrp_rt *vrrp;
	element e;
	list l = &vrrp_data->vrrp_index_fd[fd%1024 + 1];
	TIMEVAL timer;

	/* Multiple instances on the same interface */
	TIMER_RESET(timer);
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (timer_cmp(vrrp->sands, timer) < 0 ||
		    TIMER_ISNULL(timer))
			timer = timer_dup(vrrp->sands);
	}

	return timer;
}

static long
vrrp_timer_fd(const int fd)
{
	TIMEVAL timer, vrrp_timer;
	long vrrp_long;

	timer = vrrp_compute_timer(fd);
	vrrp_timer = timer_sub(timer, time_now);
	vrrp_long = TIMER_LONG(vrrp_timer);

	return (vrrp_long < 0) ? TIMER_MAX_SEC : vrrp_long;
}

static int
vrrp_timer_vrid_timeout(const int fd)
{
	vrrp_rt *vrrp;
	element e;
	list l = &vrrp_data->vrrp_index_fd[fd%1024 + 1];
	TIMEVAL timer;
	int vrid = 0;

	/* Multiple instances on the same interface */
	TIMER_RESET(timer);
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (timer_cmp(vrrp->sands, timer) < 0 ||
		    TIMER_ISNULL(timer)) {
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
	TIMEVAL timer;
	long vrrp_timer = 0;
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
			thread_add_timer(master, vrrp_read_dispatcher_thread,
					 sock, vrrp_timer);
		else
			thread_add_read(master, vrrp_read_dispatcher_thread,
					sock, sock->fd_in, vrrp_timer);
	}
}

/* VRRP dispatcher functions */
static int
already_exist_sock(list l, sa_family_t family, int proto, int ifindex)
{
	sock_t *sock;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		sock = ELEMENT_DATA(e);
		if ((sock->family == family) &&
		    (sock->proto == proto)	 &&
		    (sock->ifindex == ifindex))
			return 1;
	}
	return 0;
}

void
alloc_sock(sa_family_t family, list l, int proto, int ifindex)
{
	sock_t *new;

	new = (sock_t *) MALLOC(sizeof (sock_t));
	new->family = family;
	new->proto = proto;
	new->ifindex = ifindex;

	list_add(l, new);
}

static void
vrrp_create_sockpool(list l)
{
	vrrp_rt *vrrp;
	list p = vrrp_data->vrrp;
	element e;
	int ifindex;
	int proto;

	for (e = LIST_HEAD(p); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		ifindex = IF_INDEX(vrrp->ifp);
		if (vrrp->auth_type == VRRP_AUTH_AH)
			proto = IPPROTO_IPSEC_AH;
		else
			proto = IPPROTO_VRRP;

		/* add the vrrp element if not exist */
		if (!already_exist_sock(l, vrrp->family, proto, ifindex))
			alloc_sock(vrrp->family, l, proto, ifindex);
	}
}

static void
vrrp_open_sockpool(list l)
{
	sock_t *sock;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		sock = ELEMENT_DATA(e);
		sock->fd_in = open_vrrp_socket(sock->family, sock->proto,
						   sock->ifindex);
		if (sock->fd_in == -1)
			sock->fd_out = -1;
		else
			sock->fd_out = open_vrrp_send_socket(sock->family, sock->proto,
								 sock->ifindex);
	}
}

static void
vrrp_set_fds(list l)
{
	sock_t *sock;
	vrrp_rt *vrrp;
	list p = vrrp_data->vrrp;
	element e_sock;
	element e_vrrp;
	int proto;

	for (e_sock = LIST_HEAD(l); e_sock; ELEMENT_NEXT(e_sock)) {
		sock = ELEMENT_DATA(e_sock);
		for (e_vrrp = LIST_HEAD(p); e_vrrp; ELEMENT_NEXT(e_vrrp)) {
			vrrp = ELEMENT_DATA(e_vrrp);
			if (vrrp->auth_type == VRRP_AUTH_AH)
				proto = IPPROTO_IPSEC_AH;
			else
				proto = IPPROTO_VRRP;

			if ((sock->ifindex == IF_INDEX(vrrp->ifp)) &&
			    (sock->proto == proto)) {
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
vrrp_dispatcher_init(thread_t * thread)
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
	if (debug & 32)
		dump_list(vrrp_data->vrrp_socket_pool);
	return 1;
}

void
vrrp_dispatcher_release(vrrp_conf_data *conf_data)
{
	free_list(conf_data->vrrp_socket_pool);
}

static void
vrrp_backup(vrrp_rt * vrrp, char *buffer, int len)
{
	struct iphdr *iph;
	ipsec_ah *ah;

	if (vrrp->family == AF_INET) {
		iph = (struct iphdr *) buffer;

		if (iph->protocol == IPPROTO_IPSEC_AH) {
			ah = (ipsec_ah *) (buffer + sizeof (struct iphdr));
			if (ntohl(ah->seq_number) >= vrrp->ipsecah_counter->seq_number)
				vrrp->ipsecah_counter->cycle = 0;
		}
	}

	vrrp_state_backup(vrrp, buffer, len);
}

static void
vrrp_become_master(vrrp_rt * vrrp, char *buffer, int len)
{
	struct iphdr *iph;
	ipsec_ah *ah;

	if (vrrp->family == AF_INET) {
		iph = (struct iphdr *) buffer;

		/*
		 * If we are in IPSEC AH mode, we must be sync
		 * with the remote IPSEC AH VRRP instance counter.
		 */
		if (iph->protocol == IPPROTO_IPSEC_AH) {
			log_message(LOG_INFO, "VRRP_Instance(%s) IPSEC-AH : seq_num sync",
			       vrrp->iname);
			ah = (ipsec_ah *) (buffer + sizeof (struct iphdr));
			vrrp->ipsecah_counter->seq_number = ntohl(ah->seq_number) + 1;
			vrrp->ipsecah_counter->cycle = 0;
		}
	}

	/* Then jump to master state */
	vrrp->wantstate = VRRP_STATE_MAST;
	vrrp_state_goto_master(vrrp);
}

static void
vrrp_leave_master(vrrp_rt * vrrp, char *buffer, int len)
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

static void
vrrp_ah_sync(vrrp_rt *vrrp)
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

static void
vrrp_leave_fault(vrrp_rt * vrrp, char *buffer, int len)
{
	if (!VRRP_ISUP(vrrp))
		return;

	if (vrrp_state_fault_rx(vrrp, buffer, len)) {
		if (vrrp->sync) {
			if (vrrp_sync_leave_fault(vrrp)) {
				log_message(LOG_INFO,
				       "VRRP_Instance(%s) prio is higher than received advert",
				       vrrp->iname);
				vrrp_become_master(vrrp, buffer, len);
			}
		} else {
			log_message(LOG_INFO,
			       "VRRP_Instance(%s) prio is higher than received advert",
			       vrrp->iname);
			vrrp_become_master(vrrp, buffer, len);
		}
	} else {
		if (vrrp->sync) {
			if (vrrp_sync_leave_fault(vrrp)) {
				log_message(LOG_INFO, "VRRP_Instance(%s) Entering BACKUP STATE",
				       vrrp->iname);
				vrrp->state = VRRP_STATE_BACK;
				vrrp_smtp_notifier(vrrp);
				notify_instance_exec(vrrp, VRRP_STATE_BACK);
			}
		} else {
			log_message(LOG_INFO, "VRRP_Instance(%s) Entering BACKUP STATE",
			       vrrp->iname);
			vrrp->state = VRRP_STATE_BACK;
			vrrp_smtp_notifier(vrrp);
			notify_instance_exec(vrrp, VRRP_STATE_BACK);
		}
	}
}

static void
vrrp_goto_master(vrrp_rt * vrrp)
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
	} else {
		/* If becoming MASTER in IPSEC AH AUTH, we reset the anti-replay */
		if (vrrp->ipsecah_counter->cycle) {
			vrrp->ipsecah_counter->cycle = 0;
			vrrp->ipsecah_counter->seq_number = 0;
		}

		/* handle master state transition */
		vrrp->wantstate = VRRP_STATE_MAST;
		vrrp_state_goto_master(vrrp);
	}
}

/* Delayed gratuitous ARP thread */
int
vrrp_gratuitous_arp_thread(thread_t * thread)
{
	vrrp_rt *vrrp = THREAD_ARG(thread);

	/* Simply broadcast the gratuitous ARP */
	vrrp_send_link_update(vrrp);

	return 0;
}

/* Update VRRP effective priority based on multiple checkers.
 * This is a thread which is executed every adver_int.
 */
static int
vrrp_update_priority(thread_t * thread)
{
	vrrp_rt *vrrp = THREAD_ARG(thread);
	int prio_offset, new_prio;

	/* compute prio_offset right here */
	prio_offset = 0;

	/* Now we will sum the weights of all interfaces which are tracked. */
	if (!vrrp->sync && !LIST_ISEMPTY(vrrp->track_ifp))
		 prio_offset += vrrp_tracked_weight(vrrp->track_ifp);

	/* Now we will sum the weights of all scripts which are tracked. */
	if (!vrrp->sync && !LIST_ISEMPTY(vrrp->track_script))
		prio_offset += vrrp_script_weight(vrrp->track_script);

	if (vrrp->base_priority == VRRP_PRIO_OWNER) {
		/* we will not run a PRIO_OWNER into a non-PRIO_OWNER */
		vrrp->effective_priority = VRRP_PRIO_OWNER;
	} else {
		/* WARNING! we must compute new_prio on a signed int in order
		   to detect overflows and avoid wrapping. */
		new_prio = vrrp->base_priority + prio_offset;
		if (new_prio < 1)
			new_prio = 1;
		else if (new_prio > 254)
			new_prio = 254;
		vrrp->effective_priority = new_prio;
	}

	/* Register next priority update thread */
	thread_add_timer(master, vrrp_update_priority, vrrp, vrrp->adver_int);
	return 0;
}

static void
vrrp_master(vrrp_rt * vrrp)
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
	    vrrp->ipsecah_counter->cycle) {
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
		 * register a gratuitous arp thread delayed to 5 secs.
		 */
		if (vrrp_state_master_tx(vrrp, 0)) {
			thread_add_timer(master, vrrp_gratuitous_arp_thread,
					 vrrp,
					 (vrrp->garp_delay) ?
						vrrp->garp_delay : VRRP_GARP_DELAY);
			vrrp_smtp_notifier(vrrp);
		}
	}
}

static void
vrrp_fault(vrrp_rt * vrrp)
{
	vrrp_sgroup *vgroup = vrrp->sync;

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

	/*
	 * We force the IPSEC AH seq_number sync
	 * to be done in read advert handler.
	 * So we ignore this timeouted state until remote
	 * VRRP MASTER send its advert for the concerned
	 * instance.
	 */
	if (vrrp->auth_type == VRRP_AUTH_AH) {
		vrrp_ah_sync(vrrp);
	} else {
		/* Otherwise, we transit to init state */
		if (vrrp->init_state == VRRP_STATE_BACK) {
			vrrp->state = VRRP_STATE_BACK;
			notify_instance_exec(vrrp, VRRP_STATE_BACK);
		} else {
			vrrp_goto_master(vrrp);
		}
	}
}

/* Handle dispatcher read timeout */
static int
vrrp_dispatcher_read_to(int fd)
{
	vrrp_rt *vrrp;
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
	return vrrp->fd_in;
}

/* Handle dispatcher read packet */
static int
vrrp_dispatcher_read(sock_t * sock)
{
	vrrp_rt *vrrp;
	vrrp_pkt *hd;
	int len = 0, prev_state = 0, proto = 0;
	uint32_t saddr;

	/* Clean the read buffer */
	memset(vrrp_buffer, 0, VRRP_PACKET_TEMP_LEN);

	/* read & affect received buffer */
	len = read(sock->fd_in, vrrp_buffer, VRRP_PACKET_TEMP_LEN);
	hd = vrrp_get_header(sock->family, vrrp_buffer, &proto, &saddr);

	/* Searching for matching instance */
	vrrp = vrrp_index_lookup(hd->vrid, sock->fd_in);

	/* If no instance found => ignore the advert */
	if (!vrrp)
		return sock->fd_in;

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
int
vrrp_read_dispatcher_thread(thread_t * thread)
{
	long vrrp_timer = 0;
	sock_t *sock;
	int fd;

	/* Fetch thread arg */
	sock = THREAD_ARG(thread);

	/* Dispatcher state handler */
	if (thread->type == THREAD_READ_TIMEOUT || sock->fd_in == -1)
		fd = vrrp_dispatcher_read_to(sock->fd_in);
	else
		fd = vrrp_dispatcher_read(sock);

	/* register next dispatcher thread */
	vrrp_timer = vrrp_timer_fd(fd);
	if (fd == -1)
		thread_add_timer(thread->master, vrrp_read_dispatcher_thread,
				 sock, vrrp_timer);
	else
		thread_add_read(thread->master, vrrp_read_dispatcher_thread,
				sock, fd, vrrp_timer);

	return 0;
}

/* Script tracking threads */
static int
vrrp_script_thread(thread_t * thread)
{
	vrrp_script *vscript = THREAD_ARG(thread);
	int status, ret;
	pid_t pid;

	/* Register next timer tracker */
	thread_add_timer(thread->master, vrrp_script_thread, vscript,
			 vscript->interval);

	/* Daemonization to not degrade our scheduling timer */
	pid = fork();

	/* In case of fork is error. */
	if (pid < 0) {
		log_message(LOG_INFO, "Failed fork process");
		return -1;
	}

	/* In case of this is parent process */
	if (pid) {
		long timeout;
		timeout = vscript->interval;
		thread_add_child(thread->master, vrrp_script_child_thread,
				 vscript, pid, timeout);
		return 0;
	}

	/* Child part */
	signal_handler_destroy();
	closeall(0);
	open("/dev/null", O_RDWR);
	ret = dup(0);
	ret = dup(0);

	status = system_call(vscript->script);

	if (status < 0 || !WIFEXITED(status))
		status = 0; /* Script errors aren't server errors */
	else
		status = WEXITSTATUS(status);

	exit(status);
}

static int
vrrp_script_child_thread(thread_t * thread)
{
	int wait_status;
	vrrp_script *vscript = THREAD_ARG(thread);

	if (thread->type == THREAD_CHILD_TIMEOUT) {
		pid_t pid;

		pid = THREAD_CHILD_PID(thread);

		/* The child hasn't responded. Kill it off. */
		if (vscript->result > vscript->rise) {
			vscript->result--;
		} else {
			if (vscript->result == vscript->rise)
				log_message(LOG_INFO, "VRRP_Script(%s) timed out", vscript->sname);
			vscript->result = 0;
		}
		kill(pid, SIGTERM);
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

	return 0;
}

static int
vrrp_script_child_timeout_thread(thread_t * thread)
{
	pid_t pid;

	if (thread->type != THREAD_CHILD_TIMEOUT)
		return 0;

	/* OK, it still hasn't exited. Now really kill it off. */
	pid = THREAD_CHILD_PID(thread);
	if (kill(pid, SIGKILL) < 0) {
		/* Its possible it finished while we're handing this */
		if (errno != ESRCH)
			DBG("kill error: %s", strerror(errno));
		return 0;
	}

	log_message(LOG_WARNING, "Process [%d] didn't respond to SIGTERM", pid);
	waitpid(pid, NULL, 0);

	return 0;
}
