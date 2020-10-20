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
#include "list_head.h"
#include "check_data.h"
#include "vector.h"
#include "layer4.h"

typedef enum _checker_type {
	CHECKER_MISC,
	CHECKER_TCP,
	CHECKER_UDP,
	CHECKER_DNS,
	CHECKER_HTTP,
	CHECKER_SSL,
	CHECKER_SMTP,
	CHECKER_BFD,
	CHECKER_PING,
	CHECKER_FILE
} checker_type_t;


/* Forward reference */
struct _checker;

typedef struct _checker_funcs {
	checker_type_t			type;
	void				(*free_func) (struct _checker *);
	void				(*dump_func) (FILE *, const struct _checker *);
	bool				(*compare) (const struct _checker *, struct _checker *);
	void				(*migrate) (struct _checker *, const struct _checker *);
} checker_funcs_t;

/* Checkers structure definition */
typedef struct _checker {
	const checker_funcs_t		*checker_funcs;
	thread_func_t			launch;
	virtual_server_t		*vs;			/* pointer to the checker thread virtualserver */
	real_server_t			*rs;			/* pointer to the checker thread realserver */
	void				*data;
	bool				enabled;		/* Activation flag */
	bool				is_up;			/* Set if checker is up */
	bool				has_run;		/* Set if the checker has completed at least once */
	int				cur_weight;		/* Current weight of checker */
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

	/* Linked list member */
	list_head_t			e_list;
} checker_t;

typedef struct _checker_ref {
	checker_t			*checker;

	/* Linked list member */
	list_head_t			e_list;
} checker_ref_t;

/* Checkers queue */
extern list_head_t checkers_queue;

/* utility macro */
#define CHECKER_ARG(X) ((X)->data)
#define CHECKER_CO(X) (((checker_t *)X)->co)
#define CHECKER_DATA(X) (((checker_t *)X)->data)
#define CHECKER_GET_CURRENT() (list_last_entry(&checkers_queue, checker_t, e_list))
#define CHECKER_GET() (CHECKER_DATA(CHECKER_GET_CURRENT()))
#define CHECKER_GET_CO() (((checker_t *)CHECKER_GET_CURRENT())->co)
#define CHECKER_HA_SUSPEND(C) ((C)->vs->ha_suspend)
#define CHECKER_NEW_CO() ((conn_opts_t *) MALLOC(sizeof (conn_opts_t)))
#define FMT_CHK(C) FMT_RS((C)->rs, (C)->vs)

#ifdef _CHECKER_DEBUG_
extern bool do_checker_debug;
#endif

/* Prototypes definition */
extern void free_checker(checker_t *);
extern void free_checker_list(list_head_t *);
extern void init_checkers_queue(void);
extern void free_vs_checkers(const virtual_server_t *);
extern void free_rs_checkers(const real_server_t *);
extern void dump_connection_opts(FILE *, const void *);
extern checker_t *queue_checker(const checker_funcs_t *
			  , thread_func_t
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
