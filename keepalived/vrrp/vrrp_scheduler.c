/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Sheduling framework for vrrp code.
 *
 * Version:     $Id: vrrp_scheduler.c,v 0.7.1 2002/09/17 22:03:31 acassen Exp $
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

#include "vrrp_scheduler.h"
#include "vrrp_ipsecah.h"
#include "vrrp_if.h"
#include "vrrp.h"
#include "vrrp_sync.h"
#include "vrrp_notify.h"
#include "ipvswrapper.h"
#include "memory.h"
#include "list.h"
#include "data.h"
#include "smtp.h"

extern thread_master *master;
extern data *conf_data;

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
  { {NULL}, {vrrp_sync_backup},          {NULL},             {vrrp_sync_fault} },
  { {NULL}, {NULL},                      {NULL},             {vrrp_sync_fault} }
};


/* SMTP alert notifier */
static void
vrrp_smtp_notifier(vrrp_rt * vrrp)
{
	if (vrrp->smtp_alert) {
		if (vrrp->state == VRRP_STATE_MAST)
			smtp_alert(master, NULL, vrrp,
				   "Entering MASTER state",
				   "=> VRRP Instance is now owning VRRP VIPs <=\n\n");
		if (vrrp->state == VRRP_STATE_BACK)
			smtp_alert(master, NULL, vrrp,
				   "Entering BACKUP state",
				   "=> VRRP Instance is nolonger owning VRRP VIPs <=\n\n");
	}
}

/*
 * Initialize state handling
 * --rfc2338.6.4.1
 */
static void
vrrp_init_state(list l)
{
	vrrp_rt *vrrp;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		if (vrrp->priority == VRRP_PRIO_OWNER ||
		    vrrp->wantstate == VRRP_STATE_MAST) {
#ifdef _HAVE_IPVS_SYNCD_
			/* Check if sync daemon handling is needed */
			if (vrrp->lvs_syncd_if)
				ipvs_syncd_cmd(IPVS_STARTDAEMON,
					       vrrp->lvs_syncd_if, IPVS_MASTER);
#endif
			vrrp->state = VRRP_STATE_GOTO_MASTER;
		} else {
			vrrp->ms_down_timer = 3 * vrrp->adver_int
			    + VRRP_TIMER_SKEW(vrrp);
#ifdef _HAVE_IPVS_SYNCD_
			/* Check if sync daemon handling is needed */
			if (vrrp->lvs_syncd_if)
				ipvs_syncd_cmd(IPVS_STARTDAEMON,
					       vrrp->lvs_syncd_if, IPVS_BACKUP);
#endif
			syslog(LOG_INFO, "VRRP_Instance(%s) Entering BACKUP STATE",
			       vrrp->iname);
			vrrp->state = VRRP_STATE_BACK;
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

/* Timer functions */
static TIMEVAL
vrrp_compute_timer(const int fd)
{
	vrrp_rt *vrrp;
	TIMEVAL timer;
	element e;
	list l = conf_data->vrrp;

	/* clean the memory */
	TIMER_RESET(timer);

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (vrrp->fd == fd) {
			if (timer_cmp(vrrp->sands, timer) < 0 ||
			    TIMER_ISNULL(timer))
				timer = timer_dup(vrrp->sands);
		}
	}

	return timer;
}

static long
vrrp_timer_fd(const int fd)
{
	TIMEVAL timer, vrrp_timer, now;

	timer = vrrp_compute_timer(fd);
	now = timer_now();
	vrrp_timer = timer_sub(timer, now);

	return (vrrp_timer.tv_sec * TIMER_HZ + vrrp_timer.tv_usec);
}

static int
vrrp_timer_vrid_timeout(const int fd)
{
	vrrp_rt *vrrp;
	list l = conf_data->vrrp;
	element e;
	TIMEVAL vrrp_timer;
	int vrid = 0;

	/* clean the memory */
	memset(&vrrp_timer, 0, sizeof (struct timeval));
	vrrp_timer = vrrp_compute_timer(fd);

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (timer_cmp(vrrp->sands, vrrp_timer) == 0)
			vrid = vrrp->vrid;
	}
	return vrid;
}

/* Thread functions */
static void
vrrp_register_workers(list l)
{
	sock *sock;
	TIMEVAL timer;
	long vrrp_timer = 0;
	element e;

	/* Init compute timer */
	memset(&timer, 0, sizeof (struct timeval));

	/* Init the VRRP instances state */
	vrrp_init_state(conf_data->vrrp);

	/* Init VRRP instances sands */
	vrrp_init_sands(conf_data->vrrp);

	/* Register VRRP workers threads */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		sock = ELEMENT_DATA(e);
		/* jump to asynchronous handling */
		vrrp_timer = vrrp_timer_fd(sock->fd);

		/* Register a timer thread if interface is shut */
		if (sock->fd == -1)
			thread_add_timer(master, vrrp_read_dispatcher_thread,
					 (int *)THREAD_TIMER, vrrp_timer);
		else
			thread_add_read(master, vrrp_read_dispatcher_thread,
					NULL, sock->fd, vrrp_timer);
	}
}

/* VRRP dispatcher functions */
static int
already_exist_sock(list l, int ifindex, int proto)
{
	sock *sock;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		sock = ELEMENT_DATA(e);
		if ((sock->ifindex == ifindex) && (sock->proto == proto))
			return 1;
	}
	return 0;
}

/* sockpool list primitives */
void
free_sock(void *data)
{
	FREE(data);
}

void
dump_sock(void *data)
{
#ifdef _DEBUG_
	sock *sock = data;
	DBG("sockpool -> ifindex(%d), proto(%d), fd(%d)",
	    sock->ifindex, sock->proto, sock->fd);
#endif
}

void
alloc_sock(list l, int ifindex, int proto)
{
	sock *new;

	new = (sock *) MALLOC(sizeof (sock));
	new->ifindex = ifindex;
	new->proto = proto;

	list_add(l, new);
}

static void
vrrp_create_sockpool(list l)
{
	vrrp_rt *vrrp;
	list p = conf_data->vrrp;
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
		if (!already_exist_sock(l, ifindex, proto))
			alloc_sock(l, ifindex, proto);
	}
}

static void
vrrp_open_sockpool(list l)
{
	sock *sock;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		sock = ELEMENT_DATA(e);
		sock->fd = open_vrrp_socket(sock->proto, sock->ifindex);
	}
}

static void
vrrp_set_fds(list l)
{
	sock *sock;
	vrrp_rt *vrrp;
	list p = conf_data->vrrp;
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
			    (sock->proto == proto))
				vrrp->fd = sock->fd;
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
vrrp_dispatcher_init(thread * thread)
{
	list pool;

	/* allocate the sockpool */
	pool = alloc_list(free_sock, dump_sock);

	/* create the VRRP socket pool list */
	vrrp_create_sockpool(pool);

	/* open the VRRP socket pool */
	vrrp_open_sockpool(pool);

	/* set VRRP instance fds to sockpool */
	vrrp_set_fds(pool);

	/* register read dispatcher worker thread */
	vrrp_register_workers(pool);

	/* cleanup the temp socket pool */
	dump_list(pool);
	free_list(pool);

	return 1;
}

static vrrp_rt *
vrrp_search_instance(const int vrid)
{
	vrrp_rt *vrrp;
	list l = conf_data->vrrp;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (vrrp->vrid == vrid)
			return vrrp;
	}
	return NULL;
}

static void
vrrp_backup(vrrp_rt * vrrp, char *vrrp_buffer, int len)
{
	struct iphdr *iph = (struct iphdr *) vrrp_buffer;
	ipsec_ah *ah;

	if (iph->protocol == IPPROTO_IPSEC_AH) {
		ah = (ipsec_ah *) (vrrp_buffer + sizeof (struct iphdr));
		if (ah->seq_number >= vrrp->ipsecah_counter->seq_number) {
			vrrp->ipsecah_counter->seq_number = ah->seq_number + 10;
			vrrp->ipsecah_counter->cycle = 0;
		}
	}

	vrrp_state_backup(vrrp, vrrp_buffer, len);
}

static void
vrrp_become_master(vrrp_rt * vrrp, char *vrrp_buffer, int len)
{
	struct iphdr *iph = (struct iphdr *) vrrp_buffer;
	ipsec_ah *ah;

	/*
	 * If we are in IPSEC AH mode, we must be sync
	 * with the remote IPSEC AH VRRP instance counter.
	 */
	if (iph->protocol == IPPROTO_IPSEC_AH) {
		syslog(LOG_INFO, "VRRP_Instance(%s) AH seq_num sync",
		       vrrp->iname);
		ah = (ipsec_ah *) (vrrp_buffer + sizeof (struct iphdr));
		vrrp->ipsecah_counter->seq_number = ah->seq_number + 5;
		vrrp->ipsecah_counter->cycle = 0;
	}

	/* Then jump to master state */
	vrrp->wantstate = VRRP_STATE_MAST;
	vrrp_state_goto_master(vrrp);
}

static void
vrrp_leave_master(vrrp_rt * vrrp, char *vrrp_buffer, int len)
{
	if (!IF_ISUP(vrrp->ifp)) {
		syslog(LOG_INFO, "Kernel is reporting: interface %s DOWN",
		       IF_NAME(vrrp->ifp));
		vrrp->wantstate = VRRP_STATE_GOTO_FAULT;
		vrrp_state_leave_master(vrrp);
	} else if (vrrp_state_master_rx(vrrp, vrrp_buffer, len)) {
		vrrp_state_leave_master(vrrp);
		vrrp_smtp_notifier(vrrp);
	}
}

static void
vrrp_leave_fault(vrrp_rt * vrrp, char *vrrp_buffer, int len)
{
	if (vrrp_state_fault_rx(vrrp, vrrp_buffer, len)) {
		if (vrrp->sync) {
			if (vrrp_sync_leave_fault(vrrp)) {
				syslog(LOG_INFO,
				       "VRRP_Instance(%s) prio is higher than received advert",
				       vrrp->iname);
				vrrp_become_master(vrrp, vrrp_buffer, len);
			}
		} else {
			syslog(LOG_INFO,
			       "VRRP_Instance(%s) prio is higher than received advert",
			       vrrp->iname);
			vrrp_become_master(vrrp, vrrp_buffer, len);
		}
	} else {
		if (vrrp->sync) {
			if (vrrp_sync_leave_fault(vrrp)) {
				syslog(LOG_INFO, "VRRP_Instance(%s) Entering BACKUP STATE",
				       vrrp->iname);
				vrrp->state = VRRP_STATE_BACK;
				vrrp_smtp_notifier(vrrp);
			}
		} else {
			syslog(LOG_INFO, "VRRP_Instance(%s) Entering BACKUP STATE",
			       vrrp->iname);
			vrrp->state = VRRP_STATE_BACK;
			vrrp_smtp_notifier(vrrp);
		}
	}
}

static void
vrrp_goto_master(vrrp_rt * vrrp)
{
	if (!IF_ISUP(vrrp->ifp)) {
		syslog(LOG_INFO, "Kernel is reporting: interface %s DOWN",
		       IF_NAME(vrrp->ifp));
		syslog(LOG_INFO, "VRRP_Instance(%s) Now in FAULT state",
		       vrrp->iname);
		vrrp->state = VRRP_STATE_FAULT;
		vrrp->ms_down_timer =
		    3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
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
vrrp_gratuitous_arp_thread(thread * thread)
{
	vrrp_rt *vrrp = THREAD_ARG(thread);

	/* Simply broadcast the gratuitous ARP */
	vrrp_send_gratuitous_arp(vrrp);

	return 0;
}

static void
vrrp_master(vrrp_rt * vrrp)
{
	/* Check if interface we are running on is UP */
	if (vrrp->wantstate != VRRP_STATE_GOTO_FAULT) {
		if (!IF_ISUP(vrrp->ifp)) {
			syslog(LOG_INFO,
			       "Kernel is reporting: interface %s DOWN",
			       IF_NAME(vrrp->ifp));
			vrrp->wantstate = VRRP_STATE_GOTO_FAULT;
		}
	}

	/* Then perform the state transition */
	if (vrrp->wantstate == VRRP_STATE_GOTO_FAULT ||
	    vrrp->wantstate == VRRP_STATE_BACK ||
	    vrrp->ipsecah_counter->cycle) {
		vrrp->ms_down_timer =
		    3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);

		/* handle backup state transition */
		vrrp_state_leave_master(vrrp);

		if (vrrp->state == VRRP_STATE_BACK)
			syslog(LOG_INFO,
			       "VRRP_Instance(%s) Now in BACKUP state",
			       vrrp->iname);
		if (vrrp->state == VRRP_STATE_FAULT)
			syslog(LOG_INFO, "VRRP_Instance(%s) Now in FAULT state",
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
		if (vrrp_sync_group_up(vgroup)) {
			if (vgroup->state == VRRP_STATE_FAULT) {
				syslog(LOG_INFO,
				       "VRRP_Group(%s) Leaving FAULT state",
				       GROUP_NAME(vgroup));
				notify_group_exec(vgroup, vrrp->init_state);
				vgroup->state = vrrp->init_state;
			}
		} else
			return;
	} else if (IF_ISUP(vrrp->ifp))
		syslog(LOG_INFO, "Kernel is reporting: interface %s UP",
		       IF_NAME(vrrp->ifp));
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
		/*
		 * Transition to BACKUP state for AH
		 * seq number synchronization.
		 */
		syslog(LOG_INFO,
		       "VRRP_Instance(%s) in FAULT state jump to AH sync",
		       vrrp->iname);
		vrrp->wantstate = VRRP_STATE_BACK;
		vrrp_state_leave_master(vrrp);
	} else {
		/* Otherwise, we transit to init state */
		if (vrrp->init_state == VRRP_STATE_BACK)
			vrrp->state = VRRP_STATE_BACK;
		else
			vrrp_goto_master(vrrp);
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
	vrrp = vrrp_search_instance(vrid);

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
	return vrrp->fd;
}

/* Handle dispatcher read packet */
static int
vrrp_dispatcher_read(int fd)
{
	vrrp_rt *vrrp;
	char *vrrp_buffer;
	struct iphdr *iph;
	vrrp_pkt *hd;
	int len = 0;
	int prev_state = 0;

	/* allocate & clean the read buffer */
	vrrp_buffer = (char *) MALLOC(VRRP_PACKET_TEMP_LEN);

	/* read & affect received buffer */
	len = read(fd, vrrp_buffer, VRRP_PACKET_TEMP_LEN);
	iph = (struct iphdr *) vrrp_buffer;

	/* GCC bug : Workaround */
	hd = (vrrp_pkt *) ((char *) iph + (iph->ihl << 2));
	if (iph->protocol == IPPROTO_IPSEC_AH)
		hd = (vrrp_pkt *) ((char *) hd + vrrp_ipsecah_len());
	/* GCC bug : end */

	/* Searching for matching instance */
	vrrp = vrrp_search_instance(hd->vrid);

	/* If no instance found => ignore the advert */
	if (!vrrp) {
		FREE(vrrp_buffer);
		return fd;
	}

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

	/* cleanup the room */
	FREE(vrrp_buffer);
	return fd;
}

/* Our read packet dispatcher */
int
vrrp_read_dispatcher_thread(thread * thread)
{
	long vrrp_timer = 0;
	int fd;

	/* Dispatcher state handler */
	if (thread->type == THREAD_READ_TIMEOUT)
		fd = vrrp_dispatcher_read_to(thread->u.fd);
	else if (thread->arg) {
		fd = vrrp_dispatcher_read_to(-1);
	} else
		fd = vrrp_dispatcher_read(thread->u.fd);

	/* register next dispatcher thread */
	vrrp_timer = vrrp_timer_fd(fd);
	TIMER_MICRO_ADJUST(vrrp_timer);
	if (fd == -1)
		thread_add_timer(thread->master, vrrp_read_dispatcher_thread,
				 (int *)THREAD_TIMER, vrrp_timer);
	else
		thread_add_read(thread->master, vrrp_read_dispatcher_thread,
				NULL, fd, vrrp_timer);

	return 0;
}

/* Register VRRP thread */
extern int reload;
void
register_vrrp_thread(void)
{
	/* Init the packet dispatcher */
	if (!LIST_ISEMPTY(conf_data->vrrp))
		thread_add_event(master, vrrp_dispatcher_init, NULL,
				 VRRP_DISPATCHER);
}
