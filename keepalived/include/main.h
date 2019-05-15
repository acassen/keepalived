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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _MAIN_H
#define _MAIN_H

#include "config.h"

/* global includes */
#include <stdbool.h>
#include <sys/types.h>

/* State flags */
enum daemon_bits {
#ifdef _WITH_VRRP_
	DAEMON_VRRP,
#endif
#ifdef _WITH_LVS_
	DAEMON_CHECKERS,
#endif
#ifdef _WITH_BFD_
	DAEMON_BFD,
#endif
	RUN_ALL_CHILDREN,
};

/* Reloading helpers */
#define SET_RELOAD      (reload = 1)
#define UNSET_RELOAD    (reload = 0)

/* Global vars exported */
extern const char *version_string;	/* keepalived version */
extern unsigned long daemon_mode;	/* Which child processes are run */
extern const char *conf_file;		/* Configuration file */
extern int log_facility;		/* Optional logging facilities */
#ifdef _WITH_VRRP_
extern pid_t vrrp_child;		/* VRRP child process ID */
extern const char *vrrp_pidfile;	/* overrule default pidfile */
extern bool have_vrrp_instances;	/* vrrp instances configured */
#endif
#ifdef _WITH_LVS_
extern pid_t checkers_child;		/* Healthcheckers child process ID */
extern const char *checkers_pidfile;	/* overrule default pidfile */
extern bool have_virtual_servers;	/* virtual servers configured */
#endif
#ifdef _WITH_BFD_
extern pid_t bfd_child;			/* BFD child process ID */
extern const char *bfd_pidfile;		/* overrule default pidfile */
extern bool have_bfd_instances;		/* bfd instances configured */
#endif
extern bool reload;			/* Set during a reload */
extern const char *main_pidfile;	/* overrule default pidfile */
#ifdef _WITH_SNMP_
extern bool snmp_option;		/* Enable SNMP support */
extern const char *snmp_socket;		/* Socket to use for SNMP agent */
#endif
extern bool use_pid_dir;		/* pid files in /var/run/keepalived */
extern unsigned os_major;		/* Kernel version */
extern unsigned os_minor;
extern unsigned os_release;

extern void free_parent_mallocs_startup(bool);
extern void free_parent_mallocs_exit(void);
extern const char *make_syslog_ident(const char*);
#ifdef _WITH_VRRP_
extern bool running_vrrp(void) __attribute__ ((pure));
#endif
#ifdef _WITH_LVS_
extern bool running_checker(void) __attribute__ ((pure));
#endif

extern void stop_keepalived(void);
extern void initialise_debug_options(void);
extern int keepalived_main(int, char**); /* The "real" main function */

extern unsigned child_wait_time;
extern bool umask_cmdline;

#endif
