/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Scheduling framework. This code is highly inspired from
 *              the thread management routine (thread.c) present in the 
 *              very nice zebra project (http://www.zebra.org).
 *
 * Version:     $Id: scheduler.c,v 0.4.1 2001/09/14 00:37:56 acassen Exp $
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

#include "scheduler.h"

/* Make thread master. */
struct thread_master *
thread_make_master ()
{
  struct thread_master *new;

  new = (struct thread_master *)malloc(sizeof (struct thread_master));
  memset(new,0,sizeof(struct thread_master));

  return new;
}

/* Make a new http thread arg */
struct http_thread_arg *
thread_http_checker_arg_new()
{
  struct http_thread_arg *new;

  /* Allocate & prepare the thread argument structure */
  new = (struct http_thread_arg *)malloc(sizeof (struct http_thread_arg));
  memset(new, 0, sizeof(struct http_thread_arg));

  return new;
}

/* Make a new global thread arg */
struct thread_arg *
thread_arg_new(configuration_data *root,
               virtualserver *vserver,
               realserver *rserver)
{
  struct thread_arg *new;

  /* Allocate & prepare the thread argument structure */
  new = (struct thread_arg *)malloc(sizeof (struct thread_arg));
  memset(new, 0, sizeof(struct thread_arg));

  /* Assign structure elements */
  new->root = root;
  new->vs = vserver;
  new->svr = rserver;
  new->checker_arg = NULL;

  return new;
}

/* Add a new thread to the list. */
static void
thread_list_add (struct thread_list *list, struct thread *thread)
{
  thread->next = NULL;
  thread->prev = list->tail;
  if (list->tail)
    list->tail->next = thread;
  else
    list->head = thread;
  list->tail = thread;
  list->count++;
}

/* Add a new thread to the list. */
void
thread_list_add_before (struct thread_list *list, 
			struct thread *point, 
			struct thread *thread)
{
  thread->next = point;
  thread->prev = point->prev;
  if (point->prev)
    point->prev->next = thread;
  else
    list->head = thread;
  point->prev = thread;
  list->count++;
}

/* timer compare */
static int
thread_timer_cmp (struct timeval a, struct timeval b)
{
  if (a.tv_sec > b.tv_sec) 
    return 1;
  if (a.tv_sec < b.tv_sec)
    return -1;
  if (a.tv_usec > b.tv_usec)
    return 1;
  if (a.tv_usec < b.tv_usec)
    return -1;
  return 0;
}

/* Add a thread in the list sorted by timeval */
void
thread_list_add_timeval(struct thread_list *list, struct thread *thread)
{
  struct thread *tt;

  for (tt = list->head; tt; tt = tt->next)
    if (thread_timer_cmp (thread->sands, tt->sands) <= 0)
      break;

  if (tt)
    thread_list_add_before (list, tt, thread);
  else
    thread_list_add (list, thread);
}

/* Delete a thread from the list. */
struct thread *
thread_list_delete (struct thread_list *list, struct thread *thread)
{
  if (thread->next)
    thread->next->prev = thread->prev;
  else
    list->tail = thread->prev;
  if (thread->prev)
    thread->prev->next = thread->next;
  else
    list->head = thread->next;
  thread->next = thread->prev = NULL;
  list->count--;
  return thread;
}

/* Free all unused thread. */
static void
thread_clean_unuse (struct thread_master *m)
{
  struct thread *thread;

  thread = m->unuse.head;
  while (thread) {
    struct thread *t;

    t = thread;
    thread = t->next;

    thread_list_delete (&m->unuse, t);

    /* FIXME : Need to add thread_arg memory cleanup */

    /* free the thread */
    free(t);
    m->alloc--;
  }
}

/* Move thread to unuse list. */
static void
thread_add_unuse (struct thread_master *m, struct thread *thread)
{
  assert (m != NULL);
  assert (thread->next == NULL);
  assert (thread->prev == NULL);
  assert (thread->type == THREAD_UNUSED);
  thread_list_add (&m->unuse, thread);
}

/* Move list element to unuse queue */
void
thread_destroy_list(struct thread_master *m, struct thread_list thread_list)
{
  struct thread *thread;

  thread = thread_list.head;

  while (thread) {
    struct thread *t;

    t = thread;
    thread = t->next;

    thread_list_delete (&thread_list, t);
    t->type = THREAD_UNUSED;
    thread_add_unuse (m, t);
  }
}

/* Stop thread scheduler. */
void
thread_destroy_master (struct thread_master *m)
{
  thread_destroy_list(m,m->read);
  thread_destroy_list(m,m->write);
  thread_destroy_list(m,m->timer);
  thread_destroy_list(m,m->event);
  thread_destroy_list(m,m->ready);

  thread_clean_unuse (m);
  free(m);
}

/* Delete top of the list and return it. */
struct thread *
thread_trim_head (struct thread_list *list)
{
  if (list->head)
    return thread_list_delete (list, list->head);
  return NULL;
}

/* Make new thread. */
struct thread *
thread_new (struct thread_master *m)
{
  struct thread *new;

  /* If one thread is already allocated return it */
  if (m->unuse.head) {
    new = thread_trim_head(&m->unuse);
    memset(new,0,sizeof(struct thread));
    return new;
  }

  new = (struct thread *)malloc(sizeof(struct thread));
  memset(new,0,sizeof(struct thread));
  m->alloc++;
  return new;
}

/* Add new read thread. */
struct thread *
thread_add_read (struct thread_master *m, 
		 int (*func)(struct thread *),
		 void *arg,
		 int fd,
                 long timer)
{
  struct thread *thread;
  struct timeval timer_now;

  assert (m != NULL);

  if (FD_ISSET (fd, &m->readfd)) {
    syslog(LOG_WARNING, "There is already read fd [%d]", fd);
    return NULL;
  }

  thread = thread_new (m);
  thread->type = THREAD_READ;
  thread->id = 0;
  thread->master = m;
  thread->func = func;
  thread->arg = arg;
  FD_SET (fd, &m->readfd);
  thread->u.fd = fd;

  /* Compute read timeout value */
  gettimeofday(&timer_now, NULL);
  if (timer >= TIMER_MAX_SEC) {
    timer_now.tv_sec  += timer / TIMER_SEC_MICRO;
    timer_now.tv_usec += timer % TIMER_SEC_MICRO;
  } else
    timer_now.tv_sec += timer;

  thread->sands = timer_now;

  /* Sort the thread. */
  thread_list_add_timeval(&m->read, thread); 

  return thread;
}

/* Add new write thread. */
struct thread *
thread_add_write (struct thread_master *m,
		 int (*func)(struct thread *),
		 void *arg,
		 int fd,
                 long timer)
{
  struct thread *thread;
  struct timeval timer_now;

  assert (m != NULL);

  if (FD_ISSET (fd, &m->writefd)) {
    syslog(LOG_WARNING, "There is already write fd [%d]", fd);
    return NULL;
  }

  thread = thread_new (m);
  thread->type = THREAD_WRITE;
  thread->id = 0;
  thread->master = m;
  thread->func = func;
  thread->arg = arg;
  FD_SET (fd, &m->writefd);
  thread->u.fd = fd;

  /* Compute write timeout value */
  gettimeofday(&timer_now,NULL);
  if (timer >= TIMER_MAX_SEC) {
    timer_now.tv_sec  += timer / TIMER_SEC_MICRO;
    timer_now.tv_usec += timer % TIMER_SEC_MICRO;
  } else
    timer_now.tv_sec += timer;

  thread->sands = timer_now;

  /* Sort the thread. */
  thread_list_add_timeval(&m->write, thread); 

  return thread;
}

/* Add timer event thread. */
struct thread *
thread_add_timer (struct thread_master *m,
		  int (*func)(struct thread *),
		  void *arg,
		  long timer)
{
  struct timeval timer_now;
  struct thread *thread;

  assert (m != NULL);

  thread = thread_new (m);
  thread->type = THREAD_TIMER;
  thread->id = 0;
  thread->master = m;
  thread->func = func;
  thread->arg = arg;

  /* Do we need jitter here? */
  gettimeofday (&timer_now, NULL);
  if (timer >= TIMER_MAX_SEC) {
    timer_now.tv_sec  += timer / TIMER_SEC_MICRO;
    timer_now.tv_usec += timer % TIMER_SEC_MICRO;
  } else
    timer_now.tv_sec += timer;

  thread->sands = timer_now;

  /* Sort by timeval. */
  thread_list_add_timeval(&m->timer, thread); 

  return thread;
}

/* Add simple event thread. */
struct thread *
thread_add_event (struct thread_master *m,
		  int (*func)(struct thread *), 
		  void *arg,
		  int val)
{
  struct thread *thread;

  assert (m != NULL);

  thread = thread_new (m);
  thread->type = THREAD_EVENT;
  thread->id = 0;
  thread->master = m;
  thread->func = func;
  thread->arg = arg;
  thread->u.val = val;
  thread_list_add (&m->event, thread);

  return thread;
}

/* Add simple event thread. */
struct thread *
thread_add_terminate_event (struct thread_master *m)
{
  struct thread *thread;

  assert (m != NULL);

  thread = thread_new (m);
  thread->type = THREAD_TERMINATE;
  thread->id = 0;
  thread->master = m;
  thread->func = NULL;
  thread->arg = NULL;
  thread->u.val = 0;
  thread_list_add (&m->event, thread);

  return thread;
}

/* Cancel thread from scheduler. */
void
thread_cancel (struct thread *thread)
{
  switch (thread->type) {
    case THREAD_READ:
      assert (FD_ISSET (thread->u.fd, &thread->master->readfd));
      FD_CLR (thread->u.fd, &thread->master->readfd);
      thread_list_delete (&thread->master->read, thread);
      break;
    case THREAD_WRITE:
      assert (FD_ISSET (thread->u.fd, &thread->master->writefd));
      FD_CLR (thread->u.fd, &thread->master->writefd);
      thread_list_delete (&thread->master->write, thread);
      break;
    case THREAD_TIMER:
      thread_list_delete (&thread->master->timer, thread);
      break;
    case THREAD_EVENT:
      thread_list_delete (&thread->master->event, thread);
      break;
    case THREAD_READY:
      thread_list_delete (&thread->master->ready, thread);
      break;
    default:
      break;
  }

  thread->type = THREAD_UNUSED;
  thread_add_unuse (thread->master, thread);
}

/* Delete all events which has argument value arg. */
void
thread_cancel_event (struct thread_master *m, void *arg)
{
  struct thread *thread;

  thread = m->event.head;
  while (thread) {
    struct thread *t;

    t = thread;
    thread = t->next;

    if (t->arg == arg) {
      thread_list_delete (&m->event, t);
      t->type = THREAD_UNUSED;
      thread_add_unuse (m, t);
    }
  }
}

/* timer sub */
struct timeval
thread_timer_sub (struct timeval a, struct timeval b)
{
  struct timeval ret;

  ret.tv_usec = a.tv_usec - b.tv_usec;
  ret.tv_sec = a.tv_sec - b.tv_sec;

  if (ret.tv_usec < 0) {
    ret.tv_usec += TIMER_SEC_MICRO;
    ret.tv_sec--;
  }

  return ret;
}

static int thread_timer_null(struct timeval timer)
{
  if (timer.tv_sec == 0 && timer.tv_usec == 0)
    return 1;
  else
    return 0;
}

/* Compute the wait timer. Take care of timeouted fd */
struct timeval *
thread_compute_timer(struct thread_master *m, struct timeval *timer_wait)
{
  struct timeval timer_now;
  struct timeval timer_min;

  timer_min.tv_sec = 0;
  timer_min.tv_usec = 0;
  gettimeofday (&timer_now, NULL);

  if (m->timer.head)
    timer_min = m->timer.head->sands;

  if (m->write.head) {
    if (!thread_timer_null(timer_min)) {
      if (thread_timer_cmp(m->write.head->sands, timer_min) <= 0)
          timer_min = m->write.head->sands;
    } else
      timer_min = m->write.head->sands;
  }

  if (m->read.head) {
    if (!thread_timer_null(timer_min)) {
      if (thread_timer_cmp(m->read.head->sands, timer_min) <= 0)
          timer_min = m->read.head->sands;
    } else
      timer_min = m->read.head->sands;
  }

  if (!thread_timer_null(timer_min)) {
    timer_min = thread_timer_sub (timer_min, timer_now);
    if (timer_min.tv_sec < 0) {
      timer_min.tv_sec = 0;
      timer_min.tv_usec = 10;
    }
    timer_wait->tv_sec = timer_min.tv_sec;
    timer_wait->tv_usec = timer_min.tv_usec;
  } else
    timer_wait = NULL;

  return timer_wait;
}

/* Fetch next ready thread. */
struct thread *
thread_fetch (struct thread_master *m, struct thread *fetch)
{
  int ret;
  struct thread *thread;
  fd_set readfd;
  fd_set writefd;
  fd_set exceptfd;
  struct timeval timer_now;
  struct timeval *timer_wait;

  assert (m != NULL);

  /* Timer allocation */
  timer_wait = (struct timeval *)malloc(sizeof(struct timeval));
  memset(timer_wait,0,sizeof(struct timeval));

retry:  /* When thread can't fetch try to find next thread again. */

  /* If there is event process it first. */
  while ((thread = thread_trim_head (&m->event))) {
    *fetch = *thread;
    free(timer_wait);

    /* If daemon hanging event is received return NULL pointer */ 
    if (thread->type == THREAD_TERMINATE) {
      thread->type = THREAD_UNUSED;
      thread_add_unuse (m, thread);
      return NULL;
    }
    thread->type = THREAD_UNUSED;
    thread_add_unuse (m, thread);
    return fetch;
  }

  /* If there is ready threads process them */
  while ((thread = thread_trim_head (&m->ready))) {
    *fetch = *thread;
    thread->type = THREAD_UNUSED;
    thread_add_unuse (m, thread);
    free(timer_wait);
    return fetch;
  }

  /* Calculate select wait timer. Take care of timeouted fd */
  timer_wait = thread_compute_timer(m, timer_wait);

  /* Call select function. */
  readfd = m->readfd;
  writefd = m->writefd;
  exceptfd = m->exceptfd;

  ret = select (FD_SETSIZE, &readfd, &writefd, &exceptfd, timer_wait);
  if (ret < 0) {
    if (errno != EINTR) {
      /* Real error. */
#ifdef DEBUG
      syslog(LOG_DEBUG, "select error: %s", strerror (errno));
#endif
      assert (0);
    }
    /* Signal is coming. */
    goto retry;
  }

  /* Read thead. */
  gettimeofday (&timer_now, NULL);
  thread = m->read.head;

  while (thread) {
    struct thread *t;
      
    t = thread;
    thread = t->next;

    if (FD_ISSET (t->u.fd, &readfd)) {
      assert (FD_ISSET (t->u.fd, &m->readfd));
      FD_CLR(t->u.fd, &m->readfd);
      thread_list_delete (&m->read, t);
      thread_list_add (&m->ready, t);
      t->type = THREAD_READY;
    } else {
      if (thread_timer_cmp(timer_now, t->sands) >= 0) {
        FD_CLR(t->u.fd, &m->readfd);
        thread_list_delete (&m->read, t);
        thread_list_add (&m->ready, t);
        t->type = THREAD_READ_TIMEOUT;
      }
    }
  }

  /* Write thead. */
  gettimeofday (&timer_now, NULL);
  thread = m->write.head;

  while (thread) {
    struct thread *t;

    t = thread;
    thread = t->next;

    if (FD_ISSET (t->u.fd, &writefd)) {
      assert (FD_ISSET (t->u.fd, &writefd));
      FD_CLR(t->u.fd, &m->writefd);
      thread_list_delete (&m->write, t);
      thread_list_add (&m->ready, t);
      t->type = THREAD_READY;
    } else {
      if (thread_timer_cmp(timer_now, t->sands) >= 0) {
        FD_CLR(t->u.fd, &m->writefd);
        thread_list_delete (&m->write, t);
        thread_list_add (&m->ready, t);
        t->type = THREAD_WRITE_TIMEOUT;
      }
    }
  }
  /* Exception thead. */
  /*...*/

  /* Timer update. */
  gettimeofday (&timer_now, NULL);

  thread = m->timer.head;
  while (thread) {
    struct thread *t;

    t = thread;
    thread = t->next;

    if (thread_timer_cmp (timer_now, t->sands) >= 0) {
      thread_list_delete (&m->timer, t);
      thread_list_add (&m->ready, t);
      t->type = THREAD_READY;
    }
  }

  /* Return one event. */
  thread = thread_trim_head (&m->ready);

  /* There is no ready thread. */
  if (!thread)
    goto retry;

  *fetch = *thread;
  thread->type = THREAD_UNUSED;
  thread_add_unuse (m, thread);
  
  free(timer_wait);
  return fetch;
}

/* Make unique thread id for non pthread version of thread manager. */
unsigned long int
thread_get_id ()
{
  static unsigned long int counter = 0;
  return ++counter;
}

/* Call thread ! */
void
thread_call (struct thread *thread)
{
  thread->id = thread_get_id ();
  (*thread->func) (thread);
}

/* Register worker thread. One per realserver of each virtualserver */
void
register_vs_worker_thread(struct thread_master *master, 
                          configuration_data *root,
                          virtualserver *lstptr)
{
  realserver *pointersvr;
  struct thread_arg *thread_arg;

  pointersvr = lstptr->svr;

  while (lstptr->svr) {

    switch (lstptr->svr->method->type) {
      case TCP_CHECK_ID:
        thread_arg = thread_arg_new(root, lstptr, lstptr->svr);
        thread_add_timer(master, tcp_connect_thread, thread_arg,
                         thread_arg->vs->delay_loop);
        break;
      case HTTP_GET_ID:
        thread_arg = thread_arg_new(root, lstptr, lstptr->svr);
        thread_arg->checker_arg = (struct http_thread_arg *)thread_http_checker_arg_new();
        thread_add_timer(master, http_connect_thread, thread_arg,
                         thread_arg->vs->delay_loop);
        break;
      case SSL_GET_ID:
        break;
      case LDAP_GET_ID:
        break;
      default:
        break;
    }

    lstptr->svr = (realserver *)lstptr->svr->next;
  }

  lstptr->svr = pointersvr;
}

/* Register each virtualserver realservers worker thread */
void
register_worker_thread(struct thread_master *master, configuration_data *lstptr)
{
  virtualserver *pointervs;
  vrrp_instance *pointervrrp;

  /* register VRRP specifics threads */
  pointervrrp = lstptr->vrrp;
  while (lstptr->vrrp) {
    thread_add_event(master, vrrp_state_init_thread, lstptr->vrrp, VRRP_STATE_INIT);

    lstptr->vrrp = (vrrp_instance *)lstptr->vrrp->next;
  }
  lstptr->vrrp = pointervrrp;

  /* register VS specifics threads */
  pointervs = lstptr->lvstopology;
  while (lstptr->lvstopology) {
    register_vs_worker_thread(master, lstptr, lstptr->lvstopology);

    lstptr->lvstopology = (virtualserver *)lstptr->lvstopology->next;
  }
  lstptr->lvstopology = pointervs;
}
