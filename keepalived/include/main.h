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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _MAIN_H
#define _MAIN_H

/* global includes */
#include <sys/stat.h>
#include <sys/wait.h>
#include <getopt.h>

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

/* State flags */
enum daemon_bits {
#ifdef _WITH_VRRP_
	DAEMON_VRRP,
#endif
#ifdef _WITH_LVS_
	DAEMON_CHECKERS,
#endif
};

/* Global vars exported */
extern const char *version_string;	/* keepalived version */
extern unsigned long daemon_mode;	/* Which child processes are run */
extern char *conf_file;			/* Configuration file */
extern int log_facility;		/* Optional logging facilities */
extern pid_t vrrp_child;		/* VRRP child process ID */
extern pid_t checkers_child;		/* Healthcheckers child process ID */
extern char *main_pidfile;		/* overrule default pidfile */
extern char *checkers_pidfile;		/* overrule default pidfile */
extern char *vrrp_pidfile;		/* overrule default pidfile */
#ifdef _WITH_SNMP_
extern bool snmp;			/* Enable SNMP support */
extern const char *snmp_socket;		/* Socket to use for SNMP agent */
#endif
#if HAVE_DECL_CLONE_NEWNET
extern char *network_namespace;		/* network namespace name */
extern bool namespace_with_ipsets;	/* override for namespaces with ipsets on Linux < 3.13 */
#endif
extern char *instance_name;		/* keepalived instance name */
extern bool use_pid_dir;		/* pid files in /var/run/keepalived */
extern size_t getpwnam_buf_len;		/* Buffer length needed for getpwnam_r/getgrnam_r */
extern uid_t default_script_uid;	/* Default user/group for script execution */
extern gid_t default_script_gid;
extern unsigned os_major;		/* Kernel version */
extern unsigned os_minor;
extern unsigned os_release;

extern void free_parent_mallocs_startup(bool);
extern void free_parent_mallocs_exit(void);
extern char *make_syslog_ident(const char*);

extern int keepalived_main(int, char**); /* The "real" main function */
#endif
