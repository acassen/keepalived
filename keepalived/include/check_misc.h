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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _CHECK_MISC_H
#define _CHECK_MISC_H

/* system includes */
#include <stdbool.h>
#include <sys/types.h>

/* user includes */
#include "notify.h"

/* Checker argument structure  */
typedef struct _misc_checker {
	notify_script_t		script;		/* The script details */
	unsigned long		timeout;
	int			dynamic;	/* 0: old-style, 1: exit code from checker affects weight */
	bool			forcing_termination; /* Set if we have sent the process a SIGTERM */
} misc_checker_t;

/* Prototypes defs */
extern void install_misc_check_keyword(void);
extern int check_misc_script_security(void);

#endif
