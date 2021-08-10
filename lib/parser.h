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
#include <string.h>

/* local includes */
#include "vector.h"
#include "memory.h"

/* Global definitions */
#define KEEPALIVED_CONFIG_FILE	DEFAULT_CONFIG_FILE

/* Maximum config line length */
#define MAXBUF	1024

/* Maximum time read_timer can read - in micro-seconds */
#define TIMER_MAXIMUM (ULONG_MAX - 1)

/* Special values for parameters when we want to know they haven't been set */
#define	TIME_T_PARAMETER_UNSET	LONG_MAX
#define	PARAMETER_UNSET		UINT_MAX

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
	CONFIG_UNEXPECTED_EOB,	/* '}' */
	CONFIG_MISSING_EOB,	/* '}' */
	CONFIG_UNMATCHED_QUOTE,
	CONFIG_MISSING_PARAMETER,
	CONFIG_INVALID_NUMBER,
	CONFIG_GENERAL_ERROR,
	CONFIG_WARNING,
	CONFIG_DEPRECATED,

	/* The following is for script security not enabled when needed */
	CONFIG_SECURITY_ERROR,
} config_err_t;

/* keyword definition */
typedef struct _keyword {
	const char *string;
	void (*handler) (const vector_t *);
	vector_t *sub;
	void (*sub_close_handler) (void);
	bool active;
} keyword_t;

/* global vars exported */
extern vector_t *keywords;
extern const char *config_id;
extern const char *WHITE_SPACE;

#ifdef _PARSER_DEBUG_
extern bool do_parser_debug;
#endif
#ifdef _DUMP_KEYWORDS_
extern bool do_dump_keywords;
#endif
#ifndef _ONE_PROCESS_DEBUG_
extern const char *config_save_dir;
#endif


static inline const char * __attribute__((malloc))
set_value_r(const vector_t *strvec)
{
	return STRDUP(strvec_slot(strvec, 1));
}

#ifdef _MEM_CHECK_
#define alloc_strvec(str)	(memcheck_log("alloc_strvec", str, (__FILE__), (__func__), (__LINE__)), \
				 alloc_strvec_r(str))

#define set_value(str)		(memcheck_log("set_value", strvec_slot(str,1), (__FILE__), (__func__), (__LINE__)), \
				 set_value_r(str))
#else
#define alloc_strvec(str)	(alloc_strvec_r(str))
#define set_value(str)		(set_value_r(str))
#endif

/* Prototypes */
extern void report_config_error(config_err_t, const char *format, ...)
	__attribute__((format (printf, 2, 3)));
extern void use_disk_copy_for_config(const char *);
extern void clear_config_status(void);
extern config_err_t get_config_status(void) __attribute__ ((pure));
extern bool read_int(const char *, int *, int, int, bool);
extern bool read_unsigned(const char *, unsigned *, unsigned, unsigned, bool);
extern bool read_unsigned64(const char *, uint64_t *, uint64_t, uint64_t, bool);
extern bool read_decimal_unsigned(const char *, unsigned *, unsigned, unsigned, unsigned, bool);
extern bool read_int_strvec(const vector_t *, size_t, int *, int, int, bool);
extern bool read_unsigned_strvec(const vector_t *, size_t, unsigned *, unsigned, unsigned, bool);
extern bool read_unsigned64_strvec(const vector_t *, size_t, uint64_t *, uint64_t, uint64_t, bool);
extern bool read_unsigned_base_strvec(const vector_t *, size_t, int, unsigned *, unsigned, unsigned, bool);
extern bool read_decimal_unsigned_strvec(const vector_t *, size_t, unsigned *, unsigned, unsigned, unsigned, bool);
extern uint16_t read_hex_str(const char *, uint8_t **, uint8_t **);
extern void set_random_seed(unsigned int);
extern void install_keyword_root(const char *, void (*handler) (const vector_t *), bool);
extern void install_root_end_handler(void (*handler) (void));
extern void install_sublevel(void);
extern void install_sublevel_end(void);
extern void install_sublevel_end_handler(void (*handler) (void));
extern void install_keyword(const char *, void (*handler) (const vector_t *));
extern const vector_t *alloc_strvec_quoted_escaped(const char *);
extern vector_t *alloc_strvec_r(const char *);
extern bool check_conf_file(const char*);
extern const vector_t *read_value_block(const vector_t *);
extern void alloc_value_block(void (*alloc_func) (const vector_t *), const vector_t *);
extern bool read_timer(const vector_t *, size_t, unsigned long *, unsigned long, unsigned long, bool);
extern int check_true_false(const char *) __attribute__ ((pure));
extern void skip_block(bool);
extern void init_data(const char *, const vector_t * (*init_keywords) (void), bool);
extern int get_config_fd(void);
extern void set_config_fd(int);
void include_check_set(const vector_t *);
bool had_config_file_error(void) __attribute__((pure));
void separate_config_file(void);

#endif
