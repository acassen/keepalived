/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Sheduling framework for vrrp code.
 *
 * Version:     $Id: vrrp_scheduler.c,v 0.5.3 2002/02/24 23:50:11 acassen Exp $
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
#include "vrrp.h"
#include "memory.h"
#include "list.h"

extern thread_master *master;
extern data *conf_data;

/*
 * Initialize state handling
 * --rfc2338.6.4.1
 */
static void vrrp_init_state(list l)
{
  vrrp_instance *vrrp;
  element e;

  for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
    vrrp = ELEMENT_DATA(e);

    if (vrrp->vsrv->priority == VRRP_PRIO_OWNER ||
        vrrp->vsrv->wantstate == VRRP_STATE_MAST) {
      vrrp->vsrv->state = VRRP_STATE_GOTO_MASTER;
    } else {
      vrrp->vsrv->ms_down_timer = 3 * vrrp->vsrv->adver_int
                                      + VRRP_TIMER_SKEW(vrrp->vsrv);
      vrrp->vsrv->state = VRRP_STATE_BACK;
    }
  }
}

static void vrrp_init_instance_sands(vrrp_instance *vrrp)
{
  TIMEVAL timer;

  timer = timer_now();

  if (vrrp->vsrv->state == VRRP_STATE_BACK) {
    vrrp->vsrv->sands.tv_sec = timer.tv_sec +
                               vrrp->vsrv->ms_down_timer / TIMER_HZ;
    vrrp->vsrv->sands.tv_usec = timer.tv_usec +
                                vrrp->vsrv->ms_down_timer % TIMER_HZ;
  }
  if (vrrp->vsrv->state == VRRP_STATE_GOTO_MASTER ||
      vrrp->vsrv->state == VRRP_STATE_MAST) {
    vrrp->vsrv->sands.tv_sec = timer.tv_sec +
                               vrrp->vsrv->adver_int / TIMER_HZ;
    vrrp->vsrv->sands.tv_usec = timer.tv_usec;
  }
}

static void vrrp_init_sands(list l)
{
  vrrp_instance *vrrp;
  element e;

  for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
    vrrp = ELEMENT_DATA(e);
    vrrp_init_instance_sands(vrrp);
  }
}

/* Timer functions */
static TIMEVAL vrrp_compute_timer(const int fd)
{
  vrrp_instance *vrrp;
  TIMEVAL timer;
  element e;
  list l = conf_data->vrrp;

  /* clean the memory */
  TIMER_RESET(timer);

  for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
    vrrp = ELEMENT_DATA(e);
    if (vrrp->vsrv->fd == fd) {
      if (timer_cmp(vrrp->vsrv->sands, timer) < 0 ||
          TIMER_ISNULL(timer))
        timer = timer_dup(vrrp->vsrv->sands);
    }
  }

  return timer;
}

static long vrrp_timer_fd(const int fd)
{
  TIMEVAL timer, vrrp_timer, now;

  timer = vrrp_compute_timer(fd);
  now = timer_now();
  vrrp_timer = timer_sub(timer, now);
//  vrrp_timer = timer_sub_now(timer);

  return (vrrp_timer.tv_sec*TIMER_HZ + vrrp_timer.tv_usec);
}

static int vrrp_timer_vrid_timeout(const int fd)
{
  vrrp_instance *vrrp;
  list l = conf_data->vrrp;
  element e;
  TIMEVAL vrrp_timer;
  int vrid = 0;

  /* clean the memory */
  memset(&vrrp_timer, 0, sizeof(struct timeval));
  vrrp_timer = vrrp_compute_timer(fd);

  for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
    vrrp = ELEMENT_DATA(e);
    if (timer_cmp(vrrp->vsrv->sands, vrrp_timer) == 0)
      vrid = vrrp->vsrv->vrid;
  }
  return vrid;
}

/* Simple dump function
static void vrrp_timer_dump(vrrp_instance *vrrp)
{
  vrrp_instance *ptr = vrrp;
  TIMEVAL timer_now;
  TIMEVAL timer;
  long vrrp_timer = 0;

  memset(&timer, 0, sizeof(struct timeval));

  while (vrrp) {
    timer = timer_sub_now(vrrp->vsrv->sands);
    vrrp_timer = timer.tv_sec * TIMER_HZ + timer.tv_usec;
    syslog(LOG_DEBUG, "Timer(vrid,value) : (%d,%d)", vrrp->vsrv->vrid, vrrp_timer);

    vrrp = (vrrp_instance *)vrrp->next;
  }
  vrrp = ptr;
}
*/

/* Thread functions */
static void vrrp_register_workers(list l)
{
  sock *sock;
  TIMEVAL timer;
  long vrrp_timer = 0;
  element e;

  /* Init compute timer */
  memset(&timer, 0, sizeof(struct timeval));

  /* Init the VRRP instances state */
  vrrp_init_state(conf_data->vrrp);

  /* Init VRRP instances sands */
  vrrp_init_sands(conf_data->vrrp);

  /* Register VRRP workers threads */
  for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
    sock = ELEMENT_DATA(e);
    /* jump to asynchronous handling */
    vrrp_timer = vrrp_timer_fd(sock->fd);
    thread_add_read(master, vrrp_read_dispatcher_thread
                          , NULL
                          , sock->fd
                          , vrrp_timer);
  }
}

/* VRRP dispatcher functions */
static int already_exist_sock(list l, int ifindex, int proto)
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
void free_sock(void *data)
{
  FREE(data);
}
void dump_sock(void *data)
{
  sock *sock = data;
  syslog(LOG_DEBUG, "sockpool -> ifindex(%d), proto(%d), fd(%d)"
                  , sock->ifindex
                  , sock->proto
                  , sock->fd);
}
void alloc_sock(list l, int ifindex, int proto)
{
  sock *new;

  new = (sock *)MALLOC(sizeof(sock));
  new->ifindex = ifindex;
  new->proto   = proto;

  list_add(l, new);
}

static void vrrp_create_sockpool(list l)
{
  vrrp_instance *vrrp;
  list p = conf_data->vrrp;
  element e;
  int ifindex;
  int proto;

  for (e = LIST_HEAD(p); e; ELEMENT_NEXT(e)) {
    vrrp = ELEMENT_DATA(e);
    ifindex = ifname_to_idx(vrrp->vsrv->vif->ifname);
    if (vrrp->vsrv->vif->auth_type == VRRP_AUTH_AH)
      proto = IPPROTO_IPSEC_AH;
    else
      proto = IPPROTO_VRRP;

    /* add the vrrp element if not exist */
    if (!already_exist_sock(l, ifindex, proto))
      alloc_sock(l, ifindex, proto);
  }
}

static void vrrp_open_sockpool(list l)
{
  sock *sock;
  element e;

  for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
    sock = ELEMENT_DATA(e);
    sock->fd = open_vrrp_socket(sock->proto, sock->ifindex);
  }
}

static void vrrp_set_fds(list l)
{
  sock *sock;
  vrrp_instance *vrrp;
  list p = conf_data->vrrp;
  element e_sock;
  element e_vrrp;
  int proto;

  for (e_sock = LIST_HEAD(l); e_sock; ELEMENT_NEXT(e_sock)) {
    sock = ELEMENT_DATA(e_sock);
    for (e_vrrp = LIST_HEAD(p); e_vrrp; ELEMENT_NEXT(e_vrrp)) {
      vrrp = ELEMENT_DATA(e_vrrp);
      if (vrrp->vsrv->vif->auth_type == VRRP_AUTH_AH)
        proto = IPPROTO_IPSEC_AH;
      else
        proto = IPPROTO_VRRP;

      if ((sock->ifindex == ifname_to_idx(vrrp->vsrv->vif->ifname)) &&
          (sock->proto == proto))
        vrrp->vsrv->fd = sock->fd;
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
int vrrp_dispatcher_init(thread *thread)
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

  return 0;
}

static vrrp_instance *vrrp_search_instance_isync(char *isync)
{
  vrrp_instance *vrrp;
  list l = conf_data->vrrp;
  element e;

  for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
    vrrp = ELEMENT_DATA(e);
    if (strcmp(vrrp->iname, isync) == 0)
      return vrrp;
  }
  return NULL;
}

static vrrp_instance *vrrp_search_instance(const int vrid)
{
  vrrp_instance *vrrp;
  list l = conf_data->vrrp;
  element e;

  for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
    vrrp = ELEMENT_DATA(e);
    if (vrrp->vsrv->vrid == vrid)
      return vrrp;
  }
  return NULL;
}

static void vrrp_handle_backup(vrrp_instance *instance
                               , char *vrrp_buffer
                               , int len)
{
  vrrp_state_backup(instance, vrrp_buffer, len);
}

static void vrrp_handle_become_master(vrrp_instance *instance
                                     , char *vrrp_buffer
                                     , int len)
{
  vrrp_rt *vsrv = instance->vsrv;
  struct iphdr *iph = (struct iphdr *)vrrp_buffer;
  ipsec_ah *ah;

  /*
   * If we are in IPSEC AH mode, we must be sync
   * with the remote IPSEC AH VRRP instance counter.
   */
  if (iph->protocol == IPPROTO_IPSEC_AH) {
    ah = (ipsec_ah *)(vrrp_buffer + sizeof(struct iphdr));
    vsrv->ipsecah_counter->seq_number = ah->seq_number + 1;
    vsrv->ipsecah_counter->cycle = 0;
  }
}

static void vrrp_handle_leave_master(vrrp_instance *instance
                                     , char *vrrp_buffer
                                     , int len)
{
  if (vrrp_state_master_rx(instance, vrrp_buffer, len)) {
    syslog(LOG_INFO, "VRRP_Instance(%s) Received higher prio advert"
                   , instance->iname);
    vrrp_state_leave_master(instance);
  }
}

static int vrrp_handle_state(vrrp_instance *instance
                             , char *vrrp_buffer
                             , int len)
{
  int previous_state;

  previous_state = instance->vsrv->state;

  switch (instance->vsrv->state) {
    case VRRP_STATE_BACK:
      vrrp_handle_backup(instance, vrrp_buffer, len);
      break;
    case VRRP_STATE_GOTO_MASTER:
      vrrp_handle_become_master(instance, vrrp_buffer, len);
      break;
    case VRRP_STATE_MAST:
      vrrp_handle_leave_master(instance, vrrp_buffer, len);
      break;
  }

  return previous_state;
}

static void vrrp_handle_goto_master(vrrp_instance *instance)
{
  vrrp_rt *vsrv = instance->vsrv;

  /* If becoming MASTER in IPSEC AH AUTH, we reset the anti-replay */
  if (vsrv->ipsecah_counter->cycle) {
    vsrv->ipsecah_counter->cycle = 0;
    vsrv->ipsecah_counter->seq_number = 0;
  }

  vsrv->state = VRRP_STATE_BACK;
  vsrv->wantstate = VRRP_STATE_MAST;

  /* handle master state transition */
  vrrp_state_goto_master(instance);
}

static void vrrp_handle_master(vrrp_instance *instance)
{
  vrrp_rt *vsrv = instance->vsrv;

  if (vsrv->wantstate == VRRP_STATE_BACK ||
      vsrv->ipsecah_counter->cycle) {
    vsrv->ms_down_timer = 3 * vsrv->adver_int + VRRP_TIMER_SKEW(vsrv);

    /* handle backup state transition */
    vsrv->state = VRRP_STATE_BACK;
    vrrp_state_leave_master(instance);

    syslog(LOG_INFO, "VRRP_Instance(%s) Becoming BACKUP"
                   , instance->iname);
  } else {
    /* send the VRRP advert */
    vrrp_state_master_tx(instance, 0);
  }
}

static int vrrp_handle_state_timeout(vrrp_instance *instance)
{
  int previous_state;

  previous_state = instance->vsrv->state;

  switch (instance->vsrv->state) {
    case VRRP_STATE_BACK:
      vrrp_handle_goto_master(instance);
      break;
    case VRRP_STATE_GOTO_MASTER:
      vrrp_handle_goto_master(instance);
      break;
    case VRRP_STATE_MAST:
      vrrp_handle_master(instance);
      break;
    case VRRP_STATE_FAULT:
      vrrp_handle_master(instance);
      break;
  }

  return previous_state;
}

/* Our read packet dispatcher */
int vrrp_read_dispatcher_thread(thread *thread)
{
  vrrp_instance *vrrp_isync;
  vrrp_instance *vrrp_instance;
  long vrrp_timer = 0;
  char *vrrp_buffer;
  struct iphdr *iph;
  vrrp_pkt *hd;
  int len = 0;
  int vrid = 0;
  int previous_state = 0;

  if (thread->type == THREAD_READ_TIMEOUT) {

    /* Searching for matching instance */
    vrid = vrrp_timer_vrid_timeout(thread->u.fd);
    vrrp_instance = vrrp_search_instance(vrid);

    previous_state = vrrp_handle_state_timeout(vrrp_instance);

    /* handle master instance synchronization */
    if (previous_state == VRRP_STATE_BACK && vrrp_instance->isync) {
      vrrp_isync = vrrp_search_instance_isync(vrrp_instance->isync);

      if (vrrp_isync->vsrv->state == VRRP_STATE_BACK) {
        syslog(LOG_INFO, "VRRP_Instance(%s) must be sync with %s"
                        , vrrp_instance->iname
                        , vrrp_isync->iname);

        /* Send the higher priority advert */
        syslog(LOG_INFO, "VRRP_Instance(%s) sending OWNER advert"
                        , vrrp_isync->iname);
        vrrp_state_master_tx(vrrp_isync, VRRP_PRIO_OWNER);
      } else {
        /* Otherwise, we simply update remotes arp tables */
        syslog(LOG_INFO, "VRRP_Instance(%s) gratuitous arp on %s"
                       , vrrp_isync->iname
                       , vrrp_isync->vsrv->vif->ifname);
        vrrp_isync->vsrv->state = VRRP_STATE_MAST;
        vrrp_send_gratuitous_arp(vrrp_isync);
      }
    }

    /*
     * We are sure the instance exist. So we can
     * compute new sands timer safely.
     */
    vrrp_init_instance_sands(vrrp_instance);

  } else {

    /* allocate & clean the read buffer */
    vrrp_buffer = (char *)MALLOC(VRRP_PACKET_TEMP_LEN);

    /* read & affect received buffer */
    len = read(thread->u.fd, vrrp_buffer, VRRP_PACKET_TEMP_LEN);
    iph = (struct iphdr *)vrrp_buffer;

    /* GCC bug : Workaround */
    hd = (vrrp_pkt *) ((char *)iph + (iph->ihl << 2));
    if (iph->protocol == IPPROTO_IPSEC_AH)
      hd = (vrrp_pkt *) ((char *)hd + vrrp_ipsecah_len());
    /* GCC bug : end */

    /* Searching for matching instance */
    vrrp_instance = vrrp_search_instance(hd->vrid);

    if (vrrp_instance) {

      previous_state = vrrp_handle_state(vrrp_instance, vrrp_buffer, len);

      /* handle backup instance synchronization */
      if (previous_state == VRRP_STATE_MAST && 
          vrrp_instance->vsrv->state == VRRP_STATE_BACK &&
          vrrp_instance->isync) {
        vrrp_isync = vrrp_search_instance_isync(vrrp_instance->isync);

        /* synchronized instance probably failed */
        if (vrrp_isync->vsrv->state == VRRP_STATE_MAST &&
            vrrp_isync->vsrv->init_state == VRRP_STATE_MAST) {
          syslog(LOG_INFO, "VRRP_Instance(%s) transition to FAULT state"
                         , vrrp_instance->iname);
          vrrp_isync->vsrv->state = VRRP_STATE_FAULT;
        } else if (vrrp_isync->vsrv->state == VRRP_STATE_MAST) {
          syslog(LOG_INFO, "VRRP_Instance(%s) must be sync with %s"
                         , vrrp_instance->iname
                         , vrrp_isync->iname);

          /* Transition to BACKUP state */
          vrrp_isync->vsrv->wantstate = VRRP_STATE_BACK;
        }
      }

      /*
       * Refresh sands only if found matching instance.
       * Otherwize the packet is simply ignored...
       *
       * FIXME: Add a dropping packet framework to not
       *        degrade the instance timer during dropping.
       */
      vrrp_init_instance_sands(vrrp_instance);
    }

    /* cleanup the room */
    FREE(vrrp_buffer);

  }

  /* register next dispatcher thread */
  vrrp_timer = vrrp_timer_fd(thread->u.fd);
  thread_add_read(thread->master, vrrp_read_dispatcher_thread
                                , NULL
                                , thread->u.fd
                                , vrrp_timer);
  return 0;
}

/* Register VRRP thread */
void register_vrrp_thread(void)
{
  if (!LIST_ISEMPTY(conf_data->vrrp))
    thread_add_event(master, vrrp_dispatcher_init
                           , NULL
                           , VRRP_DISPATCHER);
}
