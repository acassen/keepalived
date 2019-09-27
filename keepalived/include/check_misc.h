/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_misc.c include file.
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *              Eric Jarman, <ehj38230@cmsu2.cmsu.edu>
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

#ifndef _CHECK_MISC_H
#define _CHECK_MISC_H

/* system includes */
#include <stdbool.h>
#include <sys/types.h>

/* user includes */
#include "notify.h"
#include "keepalived_magic.h"

/* Checker argument structure  */
typedef struct _misc_checker {
	notify_script_t		script;		/* The script details */
	unsigned long		timeout;
	bool			dynamic;	/* false: old-style, true: exit code from checker affects weight */
	script_state_t		state;		/* current state of script */
	unsigned		last_exit_code;	/* The last exit code of the script */
	timeval_t		last_ran;	/* Time script last ran */
} misc_checker_t;

/* Prototypes defs */
extern void clear_dynamic_misc_check_flag(void);
extern void install_misc_check_keyword(void);
extern int check_misc_script_security(magic_t);
#ifdef THREAD_DUMP
extern void register_check_misc_addresses(void);
#endif

#endif
