/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Main program include file.
 *
 * Version:     $Id: main.h,v 1.1.4 2003/12/29 12:12:04 acassen Exp $
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
 * Copyright (C) 2001, 2002, 2003 Alexandre Cassen, <acassen@linux-vs.org>
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

/* global var */
thread_master *master = NULL;	/* Scheduling master thread */
char *conf_file = NULL;		/* Configuration file */
int log_facility = LOG_DAEMON;	/* Optional logging facilities */
int reload = 0;			/* Global reloading flag */
unsigned int debug;		/* Debugging flags */
pid_t vrrp_child = -1;		/* VRRP child process ID */
pid_t checkers_child = -1;	/* Healthcheckers child process ID */
long wdog_delay_vrrp = 0;	/* VRRP child polling delay */
long wdog_delay_check = 0;	/* Healthchecker child polling delay */
conf_data *data;		/* Global configuration data */
int daemon_mode = 0;		/* VRRP/CHECK subsystem selection */
int linkwatch = 0;		/* Use linkwatch kernel netlink reflection */

/* Build version */
#define LOG_FACILITY_MAX	7
#define PROG    "Keepalived"

#define VERSION_CODE 0x010104
#define DATE_CODE    0x1D0C03

#define KEEPALIVED_VERSION(version)	\
	(version >> 16) & 0xFF,		\
	(version >> 8) & 0xFF,		\
	version & 0xFF

#define VERSION_STRING PROG" v%d.%d.%d (%.2d/%.2d, 20%.2d)\n", \
		KEEPALIVED_VERSION(VERSION_CODE), \
		KEEPALIVED_VERSION(DATE_CODE)
#endif
