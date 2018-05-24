/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        cfreader.c include file.
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

#ifndef _PARSER_H
#define _PARSER_H

/* system includes */
#include <sys/types.h>
#include <stdbool.h>

/* local includes */
#include "vector.h"

/* Global definitions */
#define KEEPALIVED_CONFIG_FILE "/etc/keepalived/keepalived.conf"

/* keyword definition */
typedef struct _keyword {
	const char *string;
	void (*handler) (vector_t *);
	vector_t *sub;
	void (*sub_close_handler) (void);
	bool active;
} keyword_t;

/* global vars exported */
extern vector_t *keywords;
extern char *config_id;

#ifdef _MEM_CHECK_
#define alloc_strvec(str)	(memcheck_log("alloc_strvec", str, (__FILE__), (char *)(__FUNCTION__), (__LINE__)), \
                                 alloc_strvec_r(str))
#else
#define alloc_strvec(str)	(alloc_strvec_r(str))
#endif

/* Prototypes */
extern void install_keyword_root(const char *, void (*handler) (vector_t *), bool);
extern void install_root_end_handler(void (*handler) (void));
extern void install_sublevel(void);
extern void install_sublevel_end(void);
extern void install_sublevel_end_handler(void (*handler) (void));
extern void install_keyword(const char *, void (*handler) (vector_t *));
extern vector_t *alloc_strvec_r(char *);
extern bool check_conf_file(const char*);
extern vector_t *read_value_block(vector_t *);
extern void alloc_value_block(void (*alloc_func) (vector_t *), const char *);
extern void *set_value(vector_t *);
extern unsigned long read_timer(vector_t *);
extern int check_true_false(char *);
extern void skip_block(bool);
extern void init_data(const char *, vector_t * (*init_keywords) (void));

#endif
