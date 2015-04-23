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

/* local includes */
#include "vector.h"

/* Global definitions */
#define CONF "/etc/keepalived/keepalived.conf"
#define EOB  "}"
#define MAXBUF	1024

/* ketword definition */
typedef struct _keyword {
	char *string;
	void (*handler) (vector_t *);
	vector_t *sub;
	void (*sub_close_handler) (void);
} keyword_t;

/* Reloading helpers */
#define SET_RELOAD      (reload = 1)
#define UNSET_RELOAD    (reload = 0)
#define RELOAD_DELAY    5

/* global vars exported */
extern vector_t *keywords;
extern FILE *current_stream;
extern int reload;

/* Prototypes */
extern void keyword_alloc(vector_t *, char *, void (*handler) (vector_t *));
extern void keyword_alloc_sub(vector_t *, char *, void (*handler) (vector_t *));
extern void install_keyword_root(char *, void (*handler) (vector_t *));
extern void install_sublevel(void);
extern void install_sublevel_end(void);
extern void install_sublevel_end_handler(void (*handler) (void));
extern void install_keyword(char *, void (*handler) (vector_t *));
extern void dump_keywords(vector_t *, int);
extern void free_keywords(vector_t *);
extern vector_t *alloc_strvec(char *);
extern int read_line(char *, int);
extern vector_t *read_value_block(void);
extern void alloc_value_block(vector_t *, void (*alloc_func) (vector_t *));
extern void *set_value(vector_t *);
extern void process_stream(vector_t *);
extern void init_data(char *, vector_t * (*init_keywords) (void));

#endif
