/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Sheduling framework for vrrp code.
 *
 * Version:     $Id: vrrp_scheduler.c,v 0.5.5 2002/04/10 02:34:23 acassen Exp $
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
#include "vrrp_netlink.h"
#include "vrrp_if.h"
#include "vrrp.h"
#include "ipvswrapper.h"
#include "memory.h"
#include "list.h"
#include "data.h"

extern thread_master *master;
extern data *conf_data;

/*
 * Initialize state handling
 * --rfc2338.6.4.1
 */
static void vrrp_init_state(list l)
{
  vrrp_rt *vrrp;
  element e;

  for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
    vrrp = ELEMENT_DATA(e);

    if (vrrp->priority == VRRP_PRIO_OWNER ||
        vrrp->wantstate == VRRP_STATE_MAST) {
      vrrp->state = VRRP_STATE_GOTO_MASTER;
    } else {
      vrrp->ms_down_timer = 3 * vrrp->adver_int
                              + VRRP_TIMER_SKEW(vrrp);
      /* Check if sync daemon handling is needed */
      if (vrrp->lvs_syncd_if)
        ipvs_syncd_cmd(IPVS_STARTDAEMON, vrrp->lvs_syncd_if
                                       , IPVS_BACKUP);
      vrrp->state = VRRP_STATE_BACK;
    }
  }
}

static void vrrp_init_instance_sands(vrrp_rt *vrrp)
{
  TIMEVAL timer;

  timer = timer_now();

  if (vrrp->state == VRRP_STATE_BACK ||
      vrrp->state == VRRP_STATE_FAULT) {
    vrrp->sands.tv_sec = timer.tv_sec +
                         vrrp->ms_down_timer / TIMER_HZ;
    vrrp->sands.tv_usec = timer.tv_usec +
                          vrrp->ms_down_timer % TIMER_HZ;
  }
  if (vrrp->state == VRRP_STATE_GOTO_MASTER     ||
      vrrp->state == VRRP_STATE_GOTO_DUMMY_MAST ||
      vrrp->state == VRRP_STATE_MAST            ||
      vrrp->state == VRRP_STATE_DUMMY_MAST      ||
      vrrp->state == VRRP_STATE_GOTO_FAULT) {
    vrrp->sands.tv_sec = timer.tv_sec +
                         vrrp->adver_int / TIMER_HZ;
    vrrp->sands.tv_usec = timer.tv_usec;
  }
}

static void vrrp_init_sands(list l)
{
  vrrp_rt *vrrp;
  element e;

  for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
    vrrp = ELEMENT_DATA(e);
    vrrp_init_instance_sands(vrrp);
  }
}

/* Timer functions */
static TIMEVAL vrrp_compute_timer(const int fd)
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
  vrrp_rt *vrrp;
  list l = conf_data->vrrp;
  element e;
  TIMEVAL vrrp_timer;
  int vrid = 0;

  /* clean the memory */
  memset(&vrrp_timer, 0, sizeof(struct timeval));
  vrrp_timer = vrrp_compute_timer(fd);

  for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
    vrrp = ELEMENT_DATA(e);
    if (timer_cmp(vrrp->sands, vrrp_timer) == 0)
      vrid = vrrp->vrid;
  }
  return vrid;
}

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

static int vrrp_open_sockpool(list l)
{
  sock *sock;
  element e;

  for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
    sock = ELEMENT_DATA(e);
    sock->fd = open_vrrp_socket(sock->proto, sock->ifindex);
    if (sock->fd == -1)
      return -1;
  }
  return 1;
}

static void vrrp_set_fds(list l)
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
int vrrp_dispatcher_init(thread *thread)
{
  list pool;
  int ret = 0;

  /* allocate the sockpool */
  pool = alloc_list(free_sock, dump_sock);

  /* create the VRRP socket pool list */
  vrrp_create_sockpool(pool);

  /* open the VRRP socket pool */
  ret = vrrp_open_sockpool(pool);
  if (ret < 0) {
    syslog(LOG_INFO, "Something is wrong with your hardware configuration");
    free_list(pool);
    thread_add_terminate_event(thread->master);
    return -1;
  }

  /* set VRRP instance fds to sockpool */
  vrrp_set_fds(pool);

  /* register read dispatcher worker thread */
  vrrp_register_workers(pool);

  /* cleanup the temp socket pool */
  dump_list(pool);
  free_list(pool);

  return 1;
}

static vrrp_rt *vrrp_search_instance_isync(char *isync)
{
  vrrp_rt *vrrp;
  list l = conf_data->vrrp;
  element e;

  for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
    vrrp = ELEMENT_DATA(e);
    if (strcmp(vrrp->iname, isync) == 0)
      return vrrp;
  }
  return NULL;
}

static vrrp_rt *vrrp_search_instance(const int vrid)
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

static void vrrp_handle_backup(vrrp_rt *vrrp
                               , char *vrrp_buffer
                               , int len)
{
  struct iphdr *iph = (struct iphdr *)vrrp_buffer;
  ipsec_ah *ah;

  if (iph->protocol == IPPROTO_IPSEC_AH) {
    ah = (ipsec_ah *)(vrrp_buffer + sizeof(struct iphdr));
    if (ah->seq_number >= vrrp->ipsecah_counter->seq_number) {
      vrrp->ipsecah_counter->seq_number = ah->seq_number + 10;
      vrrp->ipsecah_counter->cycle = 0;
    }
  }

  vrrp_state_backup(vrrp, vrrp_buffer, len);
}

static void vrrp_handle_become_master(vrrp_rt *vrrp
                                     , char *vrrp_buffer
                                     , int len)
{
  struct iphdr *iph = (struct iphdr *)vrrp_buffer;
  ipsec_ah *ah;

  /*
   * If we are in IPSEC AH mode, we must be sync
   * with the remote IPSEC AH VRRP instance counter.
   */
  if (iph->protocol == IPPROTO_IPSEC_AH) {
    syslog(LOG_INFO, "VRRP_Instance(%s) AH seq_num sync"
                   , vrrp->iname);
    ah = (ipsec_ah *)(vrrp_buffer + sizeof(struct iphdr));
    vrrp->ipsecah_counter->seq_number = ah->seq_number + 5;
    vrrp->ipsecah_counter->cycle = 0;
  }

  /* Then jump to master state */
  vrrp->wantstate = VRRP_STATE_MAST;
  vrrp_state_goto_master(vrrp);
}

static void vrrp_handle_leave_master(vrrp_rt *vrrp
                                     , char *vrrp_buffer
                                     , int len)
{
  if (!IF_ISUP(vrrp->ifp)) {
    syslog(LOG_INFO, "Kernel is reporting: interface %s DOWN"
                   , IF_NAME(vrrp->ifp));
    vrrp->wantstate = VRRP_STATE_GOTO_FAULT;
  } else if (vrrp_state_master_rx(vrrp, vrrp_buffer, len))
    vrrp->wantstate = VRRP_STATE_BACK;

  vrrp_state_leave_master(vrrp);
}

static void vrrp_handle_leave_fault(vrrp_rt *vrrp
                                    , char *vrrp_buffer
                                    , int len)
{
  vrrp_rt *vrrp_isync;

  if (vrrp_state_fault_rx(vrrp, vrrp_buffer, len)) {
    if (vrrp->isync) {
      vrrp_isync = vrrp_search_instance_isync(vrrp->isync);

      if (vrrp_isync->state != VRRP_STATE_FAULT ||
          (vrrp_isync->state == VRRP_STATE_FAULT &&
           IF_ISUP(vrrp_isync->ifp))) {
        syslog(LOG_INFO, "VRRP_Instance(%s) prio is higher than received advert"
                       , vrrp->iname);
        vrrp_handle_become_master(vrrp, vrrp_buffer, len);
      }
    } else {
      syslog(LOG_INFO, "VRRP_Instance(%s) prio is higher than received advert"
                     , vrrp->iname);
      vrrp_handle_become_master(vrrp, vrrp_buffer, len);
    }
  } else {
    vrrp->state = VRRP_STATE_BACK;
  }
}

static void vrrp_handle_leave_dummy_master(vrrp_rt *vrrp
                                           , char *vrrp_buffer
                                           , int len)
{
  vrrp_rt *vrrp_isync;

  if (vrrp->isync) {
    vrrp_isync = vrrp_search_instance_isync(vrrp->isync);

    if (vrrp_isync->state == VRRP_STATE_FAULT &&
        vrrp->wantstate   == VRRP_STATE_GOTO_DUMMY_MAST) {
      vrrp->wantstate = VRRP_STATE_DUMMY_MAST;
      syslog(LOG_INFO, "VRRP_Instance(%s) leaving DUMMY MASTER state"
                      , vrrp->iname);
      vrrp_state_leave_master(vrrp);
    }

    if (vrrp_isync->state != VRRP_STATE_FAULT) {
      switch (vrrp_isync->state) {
        case VRRP_STATE_BACK:
          vrrp->state = VRRP_STATE_BACK;
          break;
        case VRRP_STATE_MAST:
          vrrp_handle_become_master(vrrp, vrrp_buffer, len);
          break;
      }
    }
  }
}

static int vrrp_handle_state(vrrp_rt *vrrp
                             , char *vrrp_buffer
                             , int len)
{
  int previous_state;

  previous_state = vrrp->state;

  switch (vrrp->state) {
    case VRRP_STATE_BACK:
      vrrp_handle_backup(vrrp, vrrp_buffer, len);
      break;
    case VRRP_STATE_GOTO_MASTER:
      vrrp_handle_become_master(vrrp, vrrp_buffer, len);
      break;
    case VRRP_STATE_DUMMY_MAST:
//      vrrp_handle_leave_dummy_master(vrrp, vrrp_buffer, len);
      break;
    case VRRP_STATE_MAST:
      vrrp_handle_leave_master(vrrp, vrrp_buffer, len);
      break;
    case VRRP_STATE_FAULT:
      vrrp_handle_leave_fault(vrrp, vrrp_buffer, len);
      break;
  }

  return previous_state;
}

static void vrrp_handle_goto_master(vrrp_rt *vrrp)
{
//  if (!IF_ISUP(vrrp->ifp)) {
//    syslog(LOG_INFO, "Kernel is reporting: interface %s DOWN"
//                   , IF_NAME(vrrp->ifp));
//    vrrp->state = VRRP_STATE_FAULT;
//  } else {
    /* If becoming MASTER in IPSEC AH AUTH, we reset the anti-replay */
    if (vrrp->ipsecah_counter->cycle) {
      vrrp->ipsecah_counter->cycle      = 0;
      vrrp->ipsecah_counter->seq_number = 0;
    }

    if (vrrp->wantstate != VRRP_STATE_GOTO_DUMMY_MAST)
      vrrp->wantstate = VRRP_STATE_MAST;

    /* handle master state transition */
    vrrp_state_goto_master(vrrp);
//  }
}

static void vrrp_handle_master(vrrp_rt *vrrp)
{
  /* Check if interface we are running on is UP */
  if (vrrp->wantstate != VRRP_STATE_GOTO_FAULT) {
    if (!IF_ISUP(vrrp->ifp)) {
      syslog(LOG_INFO, "Kernel is reporting: interface %s DOWN"
                     , IF_NAME(vrrp->ifp));
      vrrp->wantstate = VRRP_STATE_GOTO_FAULT;
    }
  }

  /* Then perform the state transition */
  if (vrrp->wantstate == VRRP_STATE_GOTO_FAULT ||
      vrrp->wantstate == VRRP_STATE_BACK       ||
      vrrp->ipsecah_counter->cycle) {
    vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);

    /* handle backup state transition */
    vrrp_state_leave_master(vrrp);

    if (vrrp->state == VRRP_STATE_BACK)
      syslog(LOG_INFO, "VRRP_Instance(%s) Now in BACKUP state"
                     , vrrp->iname);
    if (vrrp->state == VRRP_STATE_FAULT)
      syslog(LOG_INFO, "VRRP_Instance(%s) Now in FAULT state"
                     , vrrp->iname);
  } else if (vrrp->state == VRRP_STATE_MAST) {
    /* send the VRRP advert */
    vrrp_state_master_tx(vrrp, 0);
  }
}

static void vrrp_handle_fault(vrrp_rt *vrrp)
{
  if (IF_ISUP(vrrp->ifp)) {
    syslog(LOG_INFO, "Kernel is reporting: interface %s UP"
                   , IF_NAME(vrrp->ifp));
    /* refresh the multicast fd */
    new_vrrp_socket(vrrp);

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
      syslog(LOG_INFO, "VRRP_Instance(%s) in FAULT state jump to AH sync"
                     , vrrp->iname);
      vrrp->wantstate = VRRP_STATE_BACK;
      vrrp_state_leave_master(vrrp);
    } else {
      /* Otherwise, we transit to init state */
      if (vrrp->init_state == VRRP_STATE_BACK)
        vrrp->state = VRRP_STATE_BACK;
      else
        vrrp_handle_goto_master(vrrp);
    }
  }
}

static void vrrp_handle_dummy_master(vrrp_rt *vrrp)
{
  /* Check if interface we are running on is UP */
  if (!IF_ISUP(vrrp->ifp))
    vrrp->wantstate = VRRP_STATE_GOTO_FAULT;

  if (vrrp->wantstate == VRRP_STATE_GOTO_FAULT) {
    vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);

    /* handle backup state transition */
    vrrp_state_leave_master(vrrp);
  } else {
    /* send the VRRP advert */
    vrrp_state_master_tx(vrrp, 0);
  }
}

static int vrrp_handle_state_timeout(vrrp_rt *vrrp)
{
  int previous_state;

  previous_state = vrrp->state;

  switch (vrrp->state) {
    case VRRP_STATE_BACK:
      vrrp_handle_goto_master(vrrp);
      break;
    case VRRP_STATE_GOTO_MASTER:
      vrrp_handle_goto_master(vrrp);
      break;
    case VRRP_STATE_DUMMY_MAST:
      vrrp_handle_dummy_master(vrrp);
      break;
    case VRRP_STATE_MAST:
      vrrp_handle_master(vrrp);
      break;
    case VRRP_STATE_FAULT:
      vrrp_handle_fault(vrrp);
      break;
  }

  return previous_state;
}

/* Handle dispatcher read timeout */
static int vrrp_dispatcher_read_to(int fd)
{
  vrrp_rt *vrrp;
  vrrp_rt *vrrp_isync;
  int vrid = 0;
  int previous_state = 0;

  /* Searching for matching instance */
  vrid = vrrp_timer_vrid_timeout(fd);
  vrrp = vrrp_search_instance(vrid);

  previous_state = vrrp_handle_state_timeout(vrrp);

  /* handle master instance synchronization */
  if (previous_state == VRRP_STATE_BACK && 
      vrrp->state    == VRRP_STATE_MAST &&
      vrrp->isync) {
    vrrp_isync = vrrp_search_instance_isync(vrrp->isync);

    if (vrrp_isync->state == VRRP_STATE_BACK) {
      syslog(LOG_INFO, "VRRP_Instance(%s) must be sync with %s"
                      , vrrp->iname
                      , vrrp_isync->iname);

      /* Send the higher priority advert */
      syslog(LOG_INFO, "VRRP_Instance(%s) sending OWNER advert"
                     , vrrp_isync->iname);
      vrrp_state_master_tx(vrrp_isync, VRRP_PRIO_OWNER);
    } else {
      /* Otherwise, we simply update remotes arp caches */
      vrrp_isync->state = VRRP_STATE_MAST;
      vrrp_send_gratuitous_arp(vrrp_isync);
    }
  }

  /* handle synchronization in FAULT state */
  if (previous_state == VRRP_STATE_MAST  &&
      vrrp->state    == VRRP_STATE_FAULT && 
      vrrp->isync) {
    vrrp_isync = vrrp_search_instance_isync(vrrp->isync);

    if (vrrp_isync->state == VRRP_STATE_MAST) {
      /*
       * We force sync instance to backup mode.
       * This reduce instance takeover to less than ms_down_timer.
       * => by default ms_down_timer is set to 3secs.
       * => Takeover will be less than 3secs !
       */
      //vrrp_isync->wantstate = VRRP_STATE_BACK;
      vrrp_isync->wantstate = VRRP_STATE_GOTO_FAULT;
    }
  }

  /*
   * Break a MASTER/BACKUP state loop after sync instance
   * FAULT state transition.
   * => We doesn't receive remote MASTER adverts.
   * => Emulate a DUMMY master to break the loop.
   */
  if (previous_state == VRRP_STATE_MAST &&
      vrrp->state    == VRRP_STATE_BACK && 
      vrrp->isync) {
    vrrp_isync = vrrp_search_instance_isync(vrrp->isync);

    if (vrrp_isync->state == VRRP_STATE_FAULT) {
      syslog(LOG_INFO, "VRRP_Instance(%s) Transition to DUMMY MASTER"
                     , vrrp->iname);
      vrrp->wantstate = VRRP_STATE_GOTO_DUMMY_MAST;
    }
  }

  /* previous state symetry */
  if (vrrp->state == VRRP_STATE_DUMMY_MAST &&
      vrrp->isync) {
    vrrp_isync = vrrp_search_instance_isync(vrrp->isync);

    if (vrrp_isync->state == VRRP_STATE_MAST)
      vrrp->state = VRRP_STATE_MAST;
  }

  /*
   * We are sure the instance exist. So we can
   * compute new sands timer safely.
   */
  vrrp_init_instance_sands(vrrp);
  return vrrp->fd;
}

/* Handle dispatcher read packet */
static int vrrp_dispatcher_read(int fd)
{
  vrrp_rt *vrrp;
  vrrp_rt *vrrp_isync;
  char *vrrp_buffer;
  struct iphdr *iph;
  vrrp_pkt *hd;
  int len = 0;
  int previous_state = 0;

  /* allocate & clean the read buffer */
  vrrp_buffer = (char *)MALLOC(VRRP_PACKET_TEMP_LEN);

  /* read & affect received buffer */
  len = read(fd, vrrp_buffer, VRRP_PACKET_TEMP_LEN);
  iph = (struct iphdr *)vrrp_buffer;

  /* GCC bug : Workaround */
  hd = (vrrp_pkt *) ((char *)iph + (iph->ihl << 2));
  if (iph->protocol == IPPROTO_IPSEC_AH)
    hd = (vrrp_pkt *) ((char *)hd + vrrp_ipsecah_len());
  /* GCC bug : end */

  /* Searching for matching instance */
  vrrp = vrrp_search_instance(hd->vrid);

  /* If no instance found => ignore the advert */
  if (!vrrp) {
    FREE(vrrp_buffer);
    return fd;
  }

  previous_state = vrrp_handle_state(vrrp, vrrp_buffer, len);

  /* handle backup instance synchronization */
  if (previous_state == VRRP_STATE_MAST && 
      vrrp->state    == VRRP_STATE_BACK &&
      vrrp->isync) {
    vrrp_isync = vrrp_search_instance_isync(vrrp->isync);

    if (vrrp_isync->state == VRRP_STATE_MAST) {
      syslog(LOG_INFO, "VRRP_Instance(%s) must be sync with %s"
                     , vrrp->iname
                     , vrrp_isync->iname);

      /* Transition to BACKUP state */
      vrrp_isync->wantstate = VRRP_STATE_BACK;
    }
  }

  /*
   * Refresh sands only if found matching instance.
   * Otherwize the packet is simply ignored...
   *
   * FIXME: Add a dropping packet framework to not
   *        degrade the instance timer during dropping.
   */
  vrrp_init_instance_sands(vrrp);

  /* cleanup the room */
  FREE(vrrp_buffer);

  return fd;
}

/* Our read packet dispatcher */
int vrrp_read_dispatcher_thread(thread *thread)
{
  long vrrp_timer = 0;
  int fd;

  /* Dispatcher state handler */
  if (thread->type == THREAD_READ_TIMEOUT)
    fd = vrrp_dispatcher_read_to(thread->u.fd);
  else
    fd = vrrp_dispatcher_read(thread->u.fd);

  /* register next dispatcher thread */
  vrrp_timer = vrrp_timer_fd(fd);
  thread_add_read(thread->master, vrrp_read_dispatcher_thread
                                , NULL
                                , fd
                                , vrrp_timer);
  return 0;
}

/* Register VRRP thread */
void register_vrrp_thread(void)
{
  /* Init the packet dispatcher */
  if (!LIST_ISEMPTY(conf_data->vrrp))
    thread_add_event(master, vrrp_dispatcher_init
                           , NULL
                           , VRRP_DISPATCHER);
}
