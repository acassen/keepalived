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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _CHECK_API_H
#define _CHECK_API_H

#include "config.h"

/* global includes */
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>

/* local includes */
#include "list.h"
#include "check_data.h"
#include "vector.h"
#include "layer4.h"

/* Checkers structure definition */
typedef struct _checker {
	void				(*free_func) (struct _checker *);
	void				(*dump_func) (FILE *, const struct _checker *);
	thread_func_t			launch;
	bool				(*compare) (const struct _checker *, const struct _checker *);
	virtual_server_t		*vs;			/* pointer to the checker thread virtualserver */
	real_server_t			*rs;			/* pointer to the checker thread realserver */
	void				*data;
	bool				enabled;		/* Activation flag */
	bool				is_up;			/* Set if checker is up */
	bool				has_run;		/* Set if the checker has completed at least once */
	conn_opts_t			*co;			/* connection options */
	int				alpha;			/* Alpha mode enabled */
	unsigned long			delay_loop;		/* Interval between running checker */
	unsigned long			warmup;			/* max random timeout to start checker */
	unsigned			retry;			/* number of retries before failing */
	unsigned long			delay_before_retry;	/* interval between retries */
	unsigned			retry_it;		/* number of successive failures */
	unsigned			default_retry;		/* number of retries before failing */
	unsigned long			default_delay_before_retry; /* interval between retries */
	bool				log_all_failures;	/* Log all failures when checker up */
} checker_t;

/* Checkers queue */
extern list checkers_queue;

/* utility macro */
#define CHECKER_ARG(X) ((X)->data)
#define CHECKER_CO(X) (((checker_t *)X)->co)
#define CHECKER_DATA(X) (((checker_t *)X)->data)
#define CHECKER_GET_CURRENT() (LIST_TAIL_DATA(checkers_queue))
#define CHECKER_GET() (CHECKER_DATA(CHECKER_GET_CURRENT()))
#define CHECKER_GET_CO() (((checker_t *)CHECKER_GET_CURRENT())->co)
#define CHECKER_HA_SUSPEND(C) ((C)->vs->ha_suspend)
#define CHECKER_NEW_CO() ((conn_opts_t *) MALLOC(sizeof (conn_opts_t)))
#define FMT_CHK(C) FMT_RS((C)->rs, (C)->vs)

/* Prototypes definition */
extern void init_checkers_queue(void);
extern void free_vs_checkers(virtual_server_t *);
extern void dump_connection_opts(FILE *, const void *);
extern void dump_checker_opts(FILE *, const void *);
extern checker_t *queue_checker(void (*) (checker_t *), void (*) (FILE *, const checker_t *)
			  , thread_func_t
			  , bool (*) (const checker_t *, const checker_t *)
			  , void *
			  , conn_opts_t *
			  , bool);
extern void dequeue_new_checker(void);
extern bool check_conn_opts(conn_opts_t *);
extern bool compare_conn_opts(const conn_opts_t *, const conn_opts_t *) __attribute__ ((pure));
extern void dump_checkers_queue(FILE *);
extern void free_checkers_queue(void);
extern void register_checkers_thread(void);
extern void install_checkers_keyword(void);
extern void checker_set_dst_port(struct sockaddr_storage *, uint16_t);
extern void install_checker_common_keywords(bool);
extern void update_checker_activity(sa_family_t, void *, bool);

#endif
