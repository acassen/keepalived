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
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <syslog.h>
#include <stdbool.h>
#include <paths.h>

/* lock pidfile */
#ifdef GNU_STD_PATHS
#define PID_DIR			LOCAL_STATE_DIR "/run/"
#else
#define PID_DIR			_PATH_VARRUN
#endif
#define KEEPALIVED_PID_DIR	PID_DIR PACKAGE "/"
#define KEEPALIVED_PID_FILE	PACKAGE
#define VRRP_PID_FILE		"vrrp"
#define CHECKERS_PID_FILE	"checkers"
#define	PID_EXTENSION		".pid"

extern const char *pid_directory;

/* Prototypes */
extern void create_pid_dir(void);
extern void remove_pid_dir(void);
extern int pidfile_write(const char *, int);
extern void pidfile_rm(const char *);
extern bool keepalived_running(unsigned long);

#endif
