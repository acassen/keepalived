/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Sheduling framework for vrrp code.
 *
 * Version:     $Id: vrrp_scheduler.c,v 0.4.9 2001/12/10 10:52:33 acassen Exp $
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

/*
 * Initialize state handling
 * --rfc2338.6.4.1
 */
static void vrrp_init_state(vrrp_instance *instance)
{
  vrrp_instance *vrrpptr = instance;

  while (instance) {
    if (instance->vsrv->priority == VRRP_PRIO_OWNER ||
        instance->vsrv->wantstate == VRRP_STATE_MAST) {
      instance->vsrv->state = VRRP_STATE_GOTO_MASTER;
    } else {
      instance->vsrv->ms_down_timer = 3 * instance->vsrv->adver_int
                                      + VRRP_TIMER_SKEW(instance->vsrv);
      instance->vsrv->state = VRRP_STATE_BACK;
    }

    instance = (vrrp_instance *)instance->next;
  }
  instance = vrrpptr;
}

static void vrrp_init_instance_sands(vrrp_instance *instance)
{
  struct timeval timer_now;

  gettimeofday(&timer_now, NULL);

  if (instance->vsrv->state == VRRP_STATE_BACK) {
    instance->vsrv->sands.tv_sec = timer_now.tv_sec +
                                   instance->vsrv->ms_down_timer / VRRP_TIMER_HZ;
    instance->vsrv->sands.tv_usec = timer_now.tv_usec +
                                    instance->vsrv->ms_down_timer % VRRP_TIMER_HZ;
  }
  if (instance->vsrv->state == VRRP_STATE_GOTO_MASTER ||
      instance->vsrv->state == VRRP_STATE_MAST) {
    instance->vsrv->sands.tv_sec = timer_now.tv_sec +
                                   instance->vsrv->adver_int / VRRP_TIMER_HZ;
    instance->vsrv->sands.tv_usec = timer_now.tv_usec;
  }
}

static void vrrp_init_sands(vrrp_instance *instance)
{
  vrrp_instance *vrrpptr = instance;

  while (instance) {
    vrrp_init_instance_sands(instance);

    instance = (vrrp_instance *)instance->next;
  }
  instance = vrrpptr;
}

/* Timer functions */
static TIMEVAL vrrp_compute_timer(const int fd, vrrp_instance *vrrp)
{
  vrrp_instance *ptr = vrrp;
  TIMEVAL timer;

  /* clean the memory */
  memset(&timer, 0, sizeof(struct timeval));

  while (vrrp) {
    if (vrrp->vsrv->fd == fd) {
      if (thread_timer_cmp(vrrp->vsrv->sands, timer) < 0 ||
          (timer.tv_sec == 0 && timer.tv_usec == 0)) {
        timer.tv_sec = vrrp->vsrv->sands.tv_sec;
        timer.tv_usec = vrrp->vsrv->sands.tv_usec;
      }
    }

    vrrp = (vrrp_instance *)vrrp->next;
  }
  vrrp = ptr;

  return timer;
}

static TIMEVAL vrrp_timer_delta(TIMEVAL timer)
{
  TIMEVAL timer_now;

  /* init timer */
  memset(&timer_now, 0, sizeof(struct timeval));
  gettimeofday(&timer_now, NULL);

  return(thread_timer_sub(timer, timer_now));
}

static long vrrp_timer_fd(const int fd, vrrp_instance *instance)
{
  TIMEVAL timer;
  long vrrp_timer = 0;

  timer = vrrp_compute_timer(fd, instance);
  timer = vrrp_timer_delta(timer);
  vrrp_timer = timer.tv_sec * VRRP_TIMER_HZ + timer.tv_usec;

  return vrrp_timer;
}

static int vrrp_timer_vrid_timeout(const int fd, vrrp_instance *vrrp)
{
  vrrp_instance *ptr = vrrp;
  TIMEVAL vrrp_timer;
  int vrid = 0;

  /* clean the memory */
  memset(&vrrp_timer, 0, sizeof(struct timeval));
  vrrp_timer = vrrp_compute_timer(fd, vrrp);

  while (vrrp) {
    if (thread_timer_cmp(vrrp->vsrv->sands, vrrp_timer) == 0)
      vrid = vrrp->vsrv->vrid;

    vrrp = (vrrp_instance *)vrrp->next;
  }
  vrrp = ptr;

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
  memset(&timer_now, 0, sizeof(struct timeval));
  gettimeofday(&timer_now, NULL);

  while (vrrp) {
    timer = thread_timer_sub(vrrp->vsrv->sands, timer_now);
    vrrp_timer = timer.tv_sec * VRRP_TIMER_HZ + timer.tv_usec;
    syslog(LOG_DEBUG, "Timer(vrid,value) : (%d,%d)", vrrp->vsrv->vrid, vrrp_timer);

    vrrp = (vrrp_instance *)vrrp->next;
  }
  vrrp = ptr;
}
*/

/* Thread functions */
static void vrrp_register_workers(thread_master *master
                                  , vrrp_instance *instance
                                  , sockpool *pool)
{
  sockpool *poolptr = pool;
  TIMEVAL timer;
  long vrrp_timer = 0;

  /* init compute timer */
  memset(&timer, 0, sizeof(struct timeval));

  /* Init the VRRP instances state */
  vrrp_init_state(instance);

  /* Init VRRP instances sands */
  vrrp_init_sands(instance);

  while (pool) {
    /* jump to asynchronous handling */
    vrrp_timer = vrrp_timer_fd(pool->fd, instance);
    thread_add_read(master, vrrp_read_dispatcher_thread,
                    instance, pool->fd, vrrp_timer);

    pool = (sockpool *)pool->next;
  }
  pool = poolptr;
}

/* VRRP dispatcher functions */
static int already_exist_sock(sockpool *lstptr, int ifindex, int proto)
{
  sockpool *ptrpool = lstptr;

  while (lstptr) {
    if ((lstptr->ifindex == ifindex) && (lstptr->proto == proto)) {
      lstptr = ptrpool;
      return 1;
    }
    lstptr = (sockpool *)lstptr->next;
  }
  lstptr = ptrpool;
  return 0;
}

static sockpool *add_sock(sockpool *lstsock, sockpool *sock)
{
  sockpool *ptrpool = lstsock;

  if (lstsock) {
    while (lstsock->next) lstsock = (sockpool *)lstsock->next;
    lstsock->next = (struct sockpool *)sock;
    return ptrpool;
  } else {
    lstsock = sock;
    return lstsock;
  }
}

static sockpool *remove_sock(sockpool *pool)
{
  sockpool *t;

  t = (sockpool *)pool->next;
  FREE(pool);
  return t;
}

static void clear_sockpool(sockpool *pool)
{
  while (pool)
    pool = remove_sock(pool);
}

static sockpool *vrrp_create_sockpool(vrrp_instance *instance, sockpool *pool)
{
  vrrp_instance *ptr = instance;
  sockpool *sock;
  int ifindex;
  int proto;

  while (instance) {
    ifindex = ifname_to_idx(instance->vsrv->vif->ifname);
    if (instance->vsrv->vif->auth_type == VRRP_AUTH_AH)
      proto = IPPROTO_IPSEC_AH;
    else
      proto = IPPROTO_VRRP;

    if (!already_exist_sock(pool, ifindex, proto)) {
      /* allocate & clean the new struct */
      sock = (sockpool *)MALLOC(sizeof(sockpool));

      /* fill in the new sock structure */
      sock->ifindex = ifindex;
      sock->proto = proto;
      pool = add_sock(pool, sock);
    }

    instance = (vrrp_instance *)instance->next;
  }

  instance = ptr;
  return pool;
}

static void vrrp_open_sockpool(sockpool *pool)
{
  sockpool *ptr = pool;

  while (pool) {
    pool->fd = open_vrrp_socket(pool->proto, pool->ifindex);
    syslog(LOG_DEBUG, "sockpool -> ifindex %d, proto %d, fd %d",
                      pool->ifindex, pool->proto, pool->fd);
    pool = (sockpool *)pool->next;
  }
  pool = ptr;
}

static void vrrp_set_fds(vrrp_instance *instance, sockpool *pool)
{
  sockpool *ptr = pool;
  vrrp_instance *ptrvrrp = instance;
  int proto;

  while (pool) {
    while (instance) {
      if (instance->vsrv->vif->auth_type == VRRP_AUTH_AH)
        proto = IPPROTO_IPSEC_AH;
      else
        proto = IPPROTO_VRRP;

      if ((pool->ifindex == ifname_to_idx(instance->vsrv->vif->ifname)) &&
          (pool->proto == proto))
        instance->vsrv->fd = pool->fd;

      instance = (vrrp_instance *)instance->next;
    }
    instance = ptrvrrp;

    pool = (sockpool *)pool->next;
  }
  pool = ptr;
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
int vrrp_dispatcher_init_thread(thread *thread)
{
  vrrp_instance *instance = THREAD_ARG(thread);
  sockpool *pool;

  /* init */
  pool = NULL;

  /* create the VRRP socket pool list */
  pool = vrrp_create_sockpool(instance, pool);

  /* open the VRRP socket pool */
  vrrp_open_sockpool(pool);

  /* set VRRP instance fds to sockpool */
  vrrp_set_fds(instance, pool);

  /* register read dispatcher worker thread */
  vrrp_register_workers(thread->master, instance, pool);

  /* cleanup the temp socket pool */
  clear_sockpool(pool);

  return 0;
}

static vrrp_instance *vrrp_search_instance_isync(char *isync, vrrp_instance *instance)
{
  while (instance) {
    if (strcmp(instance->iname, isync) == 0) /* FIXME: handle buffer overflow */
      return instance;
    instance = (vrrp_instance *)instance->next;
  }

  return NULL;
}

static vrrp_instance *vrrp_search_instance(const int vrid, vrrp_instance *instance)
{
  while (instance) {
    if (instance->vsrv->vrid == vrid)
      return instance;
    instance = (vrrp_instance *)instance->next;
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
  vrrp_instance *instance = THREAD_ARG(thread);
  vrrp_instance *ptr = instance;
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
    vrid = vrrp_timer_vrid_timeout(thread->u.fd, instance);
    vrrp_instance = vrrp_search_instance(vrid, instance);
    instance = ptr;

// syslog(LOG_DEBUG, "Dispatcher timeout on (fd,vrid) : (%d,%d)", thread->u.fd, vrid);

    previous_state = vrrp_handle_state_timeout(vrrp_instance);

    /* handle master instance synchronization */
    if (previous_state == VRRP_STATE_BACK && 
        strlen(vrrp_instance->isync) > 0) {
      vrrp_isync = vrrp_search_instance_isync(vrrp_instance->isync, instance);
      instance = ptr;

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

    if (iph->protocol == IPPROTO_IPSEC_AH)
      hd = (vrrp_pkt *)((char *)iph + (iph->ihl<<2) + vrrp_ipsecah_len());
    else
      hd = (vrrp_pkt *)((char *)iph + (iph->ihl<<2));

    /* Searching for matching instance */
    vrrp_instance = vrrp_search_instance(hd->vrid, instance);
    instance = ptr;

    if (vrrp_instance) {

//syslog(LOG_DEBUG, "VRRP packet received: on fd:%d", thread->u.fd);

      previous_state = vrrp_handle_state(vrrp_instance, vrrp_buffer, len);

      /* handle backup instance synchronization */
      if (previous_state == VRRP_STATE_MAST && 
          vrrp_instance->vsrv->state == VRRP_STATE_BACK &&
          strlen(vrrp_instance->isync) > 0) {
        vrrp_isync = vrrp_search_instance_isync(vrrp_instance->isync, instance);
        instance = ptr;

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
  vrrp_timer = vrrp_timer_fd(thread->u.fd, instance);
  thread_add_read(thread->master, vrrp_read_dispatcher_thread,
                  instance, thread->u.fd, vrrp_timer);

//syslog(LOG_DEBUG, "VRRP new timer: %lu on fd:%d", vrrp_timer, thread->u.fd);

  return 0;
}
