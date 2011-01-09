/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Main program include file.
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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

#ifndef _MAIN_H
#define _MAIN_H

/* global includes */
#include <sys/stat.h>
#include <sys/wait.h>
#include <popt.h>

/* local includes */
#include "daemon.h"
#include "memory.h"
#include "utils.h"
#include "pidfile.h"
#include "scheduler.h"
#include "parser.h"
#include "vrrp_daemon.h"
#include "check_daemon.h"
#include "global_data.h"

/* Global vars exported */
extern char *conf_file;		/* Configuration file */
extern int log_facility;	/* Optional logging facilities */
extern pid_t vrrp_child;	/* VRRP child process ID */
extern pid_t checkers_child;	/* Healthcheckers child process ID */
extern int daemon_mode;		/* VRRP/CHECK subsystem selection */
extern int linkwatch;		/* Use linkwatch kernel netlink reflection */

#endif
