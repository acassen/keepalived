/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Checkers arguments structures definitions.
 *
 * Version:     $Id: check_api.h,v 0.5.8 2002/05/21 16:09:46 acassen Exp $
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

#ifndef _CHECK_API_H
#define _CHECK_API_H

/* local includes */
#include "data.h"
#include "scheduler.h"

/* Checkers structure definition */
typedef struct _checker {
  void (*free)	(void *);
  void (*dump)	(void *);
  int (*launch)	(struct _thread *);
  virtual_server	*vs;	/* pointer to the checker thread virtualserver */
  real_server		*rs;	/* pointer to the checker thread realserver */
  void			*data;
} checker;

/* Checkers queue */
list checkers_queue;

/* utility macro */
#define CHECKER_ARG(X) ((X)->data)
#define CHECKER_DATA(X) (((checker *)X)->data)
#define CHECKER_GET() (CHECKER_DATA(LIST_TAIL_DATA(checkers_queue)))
#define CHECKER_VALUE_INT(X) (atoi(VECTOR_SLOT(X,1)))
#define CHECKER_VALUE_STRING(X) (set_value(X))
#define CHECKER_RIP(C)   (SVR_IP((C)->rs))
#define CHECKER_RPORT(C) (SVR_PORT((C)->rs))
#define CHECKER_VHOST(C) (VHOST((C)->vs))

/* Prototypes definition */
extern void init_checkers_queue(void);
extern void queue_checker(void (*free) (void *), void (*dump) (void *)
                                        , int (*launch) (struct _thread *)
                                        , void *data);
extern void dump_checkers_queue(void);
extern void free_checkers_queue(void);
extern void register_checkers_thread(void);
extern void install_checkers_keyword(void);

#endif
