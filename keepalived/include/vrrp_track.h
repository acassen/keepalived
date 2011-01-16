/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_track.c include file.
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

#ifndef _VRRP_TRACK_H
#define _VRRP_TRACK_H

/* global includes */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <syslog.h>

/* local includes */
#include "vector.h"
#include "list.h"

/* Macro definition */
#define TRACK_ISUP(L)	(vrrp_tracked_up((L)))
#define SCRIPT_ISUP(L)	(vrrp_script_up((L)))

/* VRRP script tracking defaults */
#define VRRP_SCRIPT_DI 1       /* external script track interval (in sec) */
#define VRRP_SCRIPT_DW 0       /* external script default weight */

/* VRRP script tracking results.
 * The result is an integer between 0 and rise-1 to indicate a DOWN state,
 * or between rise-1 and rise+fall-1 to indicate an UP state. Upon failure,
 * we decrease result and set it to zero when we pass below rise. Upon
 * success, we increase result and set it to rise+fall-1 when we pass above
 * rise-1.
 */
#define VRRP_SCRIPT_STATUS_DISABLED  -3
#define VRRP_SCRIPT_STATUS_INIT_GOOD -2
#define VRRP_SCRIPT_STATUS_INIT      -1

/* external script we call to track local processes */
typedef struct _vrrp_script {
	char *sname;		/* instance name */
	char *script;		/* the command to be called */
	int interval;		/* interval between script calls */
	int weight;		/* weight associated to this script */
	int result;		/* result of last call to this script: 0..R-1 = KO, R..R+F-1 = OK */
	int inuse;		/* how many users have weight>0 ? */
	int rise;		/* R: how many successes before OK */
	int fall;		/* F: how many failures before KO */
} vrrp_script;

/* Tracked script structure definition */
typedef struct _tracked_sc {
	int weight;		/* tracking weight when non-zero */
	vrrp_script *scr;	/* script pointer, cannot be NULL */
} tracked_sc;

/* prototypes */
extern void dump_track(void *);
extern void alloc_track(list, vector);
extern void dump_track_script(void *);
extern void alloc_track_script(list, vector);
extern int vrrp_tracked_up(list);
extern void vrrp_log_tracked_down(list);
extern int vrrp_tracked_weight(list);
extern int vrrp_script_up(list);
extern int vrrp_script_weight(list);
extern vrrp_script* find_script_by_name(char *);

#endif
