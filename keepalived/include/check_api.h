/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Checkers arguments structures definitions.
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

#ifndef _CHECK_API_H
#define _CHECK_API_H

/* local includes */
#include "check_data.h"
#include "scheduler.h"

/* Checkers structure definition */
typedef struct _checker {
	void (*free_func) (void *);
	void (*dump_func) (void *);
	int (*launch) (struct _thread *);
	int (*plugin_launch) (void *);
	virtual_server *vs;	/* pointer to the checker thread virtualserver */
	real_server *rs;	/* pointer to the checker thread realserver */
	void *data;
	checker_id_t id;	/* Checker identifier */
	int enabled;		/* Activation flag */
} checker_t;

/* Checkers queue */
extern list checkers_queue;

/* utility macro */
#define CHECKER_ARG(X) ((X)->data)
#define CHECKER_DATA(X) (((checker_t *)X)->data)
#define CHECKER_GET() (CHECKER_DATA(LIST_TAIL_DATA(checkers_queue)))
#define CHECKER_VALUE_INT(X) (atoi(VECTOR_SLOT(X,1)))
#define CHECKER_VALUE_STRING(X) (set_value(X))
#define CHECKER_VHOST(C) (VHOST((C)->vs))
#define CHECKER_ENABLED(C) ((C)->enabled)
#define CHECKER_ENABLE(C)  ((C)->enabled = 1)
#define CHECKER_DISABLE(C) ((C)->enabled = 0)
#define CHECKER_HA_SUSPEND(C) ((C)->vs->ha_suspend)

/* Prototypes definition */
extern void init_checkers_queue(void);
extern void queue_checker(void (*free_func) (void *), void (*dump_func) (void *)
			  , int (*launch) (thread_t *)
			  , void *);
extern void dump_checkers_queue(void);
extern void free_checkers_queue(void);
extern void register_checkers_thread(void);
extern void install_checkers_keyword(void);
extern void update_checker_activity(sa_family_t, void *, int);
extern void checker_set_dst(struct sockaddr_storage *);
extern void checker_set_dst_port(struct sockaddr_storage *, uint16_t);

#endif
