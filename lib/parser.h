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
#include <stdint.h>

/* local includes */
#include "vector.h"

/* Global definitions */
#define KEEPALIVED_CONFIG_FILE "/etc/keepalived/keepalived.conf"

/* Maximum config line length */
#define MAXBUF	1024

/* Maximum time read_timer can return */
#define TIMER_MAX (ULONG_MAX / TIMER_HZ)

/* Configuration test errors. These should be in decreasing order of severity */
typedef enum {
	CONFIG_OK,

	/* The following mean keepalived cannot run the config */
	CONFIG_FILE_NOT_FOUND,
	CONFIG_BAD_IF,
	CONFIG_FATAL,

	/* The following are configuration errors, but keepalived will still run */
	CONFIG_MULTIPLE_FILES,
	CONFIG_UNKNOWN_KEYWORD,
	CONFIG_UNEXPECTED_BOB,	/* '{' */
	CONFIG_MISSING_BOB,	/* '{' */
	CONFIG_UNMATCHED_QUOTE,
	CONFIG_MISSING_PARAMETER,
	CONFIG_INVALID_NUMBER,
	CONFIG_GENERAL_ERROR,

	/* The following is for script security not enabled when needed */
	CONFIG_SECURITY_ERROR,
} config_err_t;

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
extern const char *WHITE_SPACE;

#ifdef _MEM_CHECK_
#define alloc_strvec(str)	(memcheck_log("alloc_strvec", str, (__FILE__), (char *)(__FUNCTION__), (__LINE__)), \
                                 alloc_strvec_r(str))
#else
#define alloc_strvec(str)	(alloc_strvec_r(str))
#endif

/* Prototypes */
extern void report_config_error(config_err_t, const char *format, ...)
	__attribute__((format (printf, 2, 3)));
extern config_err_t get_config_status(void);
extern bool read_int(const char *, int *, int, int, bool);
extern bool read_unsigned(const char *, unsigned *, unsigned, unsigned, bool);
extern bool read_unsigned64(const char *, uint64_t *, uint64_t, uint64_t, bool);
extern bool read_double(const char *, double *, double, double, bool);
extern bool read_int_strvec(const vector_t *, size_t, int *, int, int, bool);
extern bool read_unsigned_strvec(const vector_t *, size_t, unsigned *, unsigned, unsigned, bool);
extern bool read_unsigned64_strvec(const vector_t *, size_t, uint64_t *, uint64_t, uint64_t, bool);
extern bool read_unsigned_base_strvec(const vector_t *, size_t, int, unsigned *, unsigned, unsigned, bool);
extern bool read_double_strvec(const vector_t *, size_t, double *, double, double, bool);
extern void install_keyword_root(const char *, void (*handler) (vector_t *), bool);
extern void install_root_end_handler(void (*handler) (void));
extern void install_sublevel(void);
extern void install_sublevel_end(void);
extern void install_sublevel_end_handler(void (*handler) (void));
extern void install_keyword(const char *, void (*handler) (vector_t *));
extern vector_t *alloc_strvec_quoted_escaped(char *);
extern vector_t *alloc_strvec_r(char *);
extern bool check_conf_file(const char*);
extern vector_t *read_value_block(vector_t *);
extern void alloc_value_block(void (*alloc_func) (vector_t *), const char *);
extern void *set_value(vector_t *);
extern bool read_timer(vector_t *, size_t, unsigned long *, unsigned long, unsigned long, bool);
extern int check_true_false(char *);
extern void skip_block(bool);
extern void init_data(const char *, vector_t * (*init_keywords) (void));

#endif
