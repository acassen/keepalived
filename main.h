/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Main program include file.
 *
 * Version:     $Id: main.h,v 0.3.8 2001/11/04 21:41:32 acassen Exp $
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
 */

#ifndef _MAIN_H
#define _MAIN_H

/* global includes */
#include <sys/stat.h>

/* local includes */
#include "utils.h"
#include "pidfile.h"
#include "cfreader.h"
#include "scheduler.h"
#include "ipwrapper.h"
#include "smtp.h"

/* global var */
struct thread_master *master;

/* Build version */
#define PROG    "keepalived"
#define VERSION "0.3.8 (04/11, 2001)"

#endif
