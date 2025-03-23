/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        pidfile.c include file.
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

#ifndef _PIDFILE_H
#define _PIDFILE_H

/* system include */
#include <stdbool.h>
#include <paths.h>

#include "utils.h"

/* lock pidfile */
#define KEEPALIVED_PID_DIR	RUNSTATEDIR "/" PACKAGE "/"
#define KEEPALIVED_PID_FILE	PACKAGE

#ifdef _WITH_VRRP_
#define VRRP_PID_FILE		"vrrp"
#endif
#ifdef _WITH_LVS_
#define CHECKERS_PID_FILE	"checkers"
#endif
#ifdef _WITH_BFD_
#define BFD_PID_FILE		"bfd"
#endif
#define	PID_EXTENSION		".pid"
#define	RELOAD_EXTENSION	".reload"

typedef struct pidfile {
	const char *	path;
	bool		free_path;
	int		fd;
} pidfile_t;

extern const char *pid_directory;

/* Prototypes */
extern void create_pid_dir(void);
extern void remove_pid_dir(void);
extern char *make_pidfile_name(const char *, const char *, const char *);
extern void pidfile_close(pidfile_t *, bool);
extern bool pidfile_write(pidfile_t *);
extern void pidfile_rm(pidfile_t *);
extern void close_other_pidfiles(void);
extern bool keepalived_running(unsigned long);

#endif
