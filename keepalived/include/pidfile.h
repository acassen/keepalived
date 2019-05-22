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

/* lock pidfile */
#if defined PID_DIR_ROOT
#define	PID_DIR			PID_DIR_ROOT "/run/"
#elif defined GNU_STD_PATHS
#define PID_DIR			LOCAL_STATE_DIR "/run/"
#else
#define PID_DIR			_PATH_VARRUN
#endif

#define KEEPALIVED_PID_DIR	PID_DIR PACKAGE "/"
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

extern const char *pid_directory;

/* Prototypes */
extern void create_pid_dir(void);
extern void remove_pid_dir(void);
extern int pidfile_write(const char *, int);
extern void pidfile_rm(const char *);
extern bool keepalived_running(unsigned long);

#endif
