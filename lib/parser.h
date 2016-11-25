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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@linux-vs.org>
 */

#ifndef _PARSER_H
#define _PARSER_H

/* system includes */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>
#include <ctype.h>
#include <stdbool.h>

/* local includes */
#include "vector.h"

/* Global definitions */
#define KEEPALIVED_CONFIG_FILE "/etc/keepalived/keepalived.conf"
#define BOB  "{"
#define EOB  "}"
#define MAXBUF	1024

/* keyword definition */
typedef struct _keyword {
	const char *string;
	void (*handler) (vector_t *);
	vector_t *sub;
	void (*sub_close_handler) (void);
	bool active;
} keyword_t;

/* Reloading helpers */
#define SET_RELOAD      (reload = 1)
#define UNSET_RELOAD    (reload = 0)
#define RELOAD_DELAY    5

/* global vars exported */
extern vector_t *keywords;
extern bool reload;
extern char *config_id;

/* Prototypes */
extern void install_keyword_root(const char *, void (*handler) (vector_t *), bool);
extern void install_sublevel(void);
extern void install_sublevel_end(void);
extern void install_sublevel_end_handler(void (*handler) (void));
extern void install_keyword(const char *, void (*handler) (vector_t *));
extern vector_t *alloc_strvec(char *);
extern bool check_conf_file(const char*);
extern bool read_line(char *, size_t);
extern vector_t *read_value_block(vector_t *);
extern void alloc_value_block(void (*alloc_func) (vector_t *));
extern void *set_value(vector_t *);
extern int check_true_false(char *);
extern void skip_block(void);
extern void init_data(const char *, vector_t * (*init_keywords) (void));

#endif
