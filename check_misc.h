/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_misc.c include file.
 *
 * Version:     $Id: check_misc.h,v 0.3.8 2001/11/04 21:41:32 acassen Exp $
 *
 * Author:      Eric Jarman, <ehj38230@cmsu2.cmsu.edu>
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
 */

#ifndef _MISC_H
#define _MISC_H

/* system includes */
#include <stdlib.h>

/* local includes */
#include "cfreader.h"
#include "ipwrapper.h"
#include "scheduler.h"
#include "smtp.h"

/* Prototypes defs */
extern int misc_check_thread(struct thread *thread);

#endif
