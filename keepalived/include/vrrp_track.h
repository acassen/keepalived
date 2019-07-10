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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_TRACK_H
#define _VRRP_TRACK_H

/* global includes */
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

/* local includes */
#include "vector.h"
#include "list.h"
#include "vrrp_if.h"
#include "vrrp.h"
#include "notify.h"
#ifdef _WITH_BFD_
#include "bfd.h"
#endif
#ifdef _WITH_CN_PROC_
#include "rbtree.h"
#endif

/* VRRP script tracking defaults */
#define VRRP_SCRIPT_DI 1	/* external script track interval (in sec) */
#define VRRP_SCRIPT_DT 0	/* external script track timeout (in sec) */
#define VRRP_SCRIPT_DW 0	/* external script default weight */

/* VRRP script tracking results.
 * The result is an integer between 0 and rise-1 to indicate a DOWN state,
 * or between rise-1 and rise+fall-1 to indicate an UP state. Upon failure,
 * we decrease result and set it to zero when we pass below rise. Upon
 * success, we increase result and set it to rise+fall-1 when we pass above
 * rise-1.
 */

/* If a VRRP instance doesn't track it's own interface, we still
 * want the interface to have a reference to the VRRP instance,
 * but it needs to know the instance isn't tracking it. */
#define	VRRP_NOT_TRACK_IF	255

/* external script we call to track local processes */
typedef struct _vrrp_script {
	const char		*sname;		/* instance name */
	notify_script_t		script;		/* The script details */
	unsigned long		interval;	/* interval between script calls */
	unsigned long		timeout;	/* microseconds before script timeout */
	int			weight;		/* weight associated to this script */
	bool			weight_reverse;	/* which direction is the weight applied */
	int			result;		/* result of last call to this script: 0..R-1 = KO, R..R+F-1 = OK */
	int			rise;		/* R: how many successes before OK */
	int			fall;		/* F: how many failures before KO */
	list			tracking_vrrp;	/* List of tracking_vrrp_t for vrrp instances tracking this script */
	int			last_status;	/* Last status returned by script. Used to report changes */
	script_state_t		state;		/* current state of script */
	script_init_state_t	init_state;	/* current initialisation state of script */
	bool			insecure;	/* Set if script is run by root, but is non-root modifiable */
} vrrp_script_t;

/* Tracked script structure definition */
typedef struct _tracked_sc {
	vrrp_script_t		*scr;		/* script pointer, cannot be NULL */
	int			weight;		/* tracking weight when non-zero */
	bool			weight_reverse;	/* which direction is the weight applied */
} tracked_sc_t;

/* external file we read to track local processes */
typedef struct _vrrp_file {
	const char		*fname;		/* File name */
	const char		*file_path;	/* Path to file */
	const char		*file_part;	/* Pointer to start of filename without directories */
	int			weight;		/* Default weight */
	bool			weight_reverse;	/* which direction is the weight applied */
	int			wd;		/* Watch descriptor */
	list			tracking_vrrp;	/* List of tracking_vrrp_t for vrrp instances tracking this file */
	int			last_status;	/* Last status returned by file. Used to report changes */
} vrrp_tracked_file_t;

/* Tracked file structure definition */
typedef struct _tracked_file {
	vrrp_tracked_file_t	*file;		/* track file pointer, cannot be NULL */
	int			weight;		/* Multiplier for file value */
	bool			weight_reverse;	/* which direction is the weight applied */
} tracked_file_t;

#ifdef _WITH_CN_PROC_
typedef enum _param_match {
	PARAM_MATCH_NONE,
	PARAM_MATCH_EXACT,			/* All parameters must match */
	PARAM_MATCH_INITIAL,			/* Match initial complete parameters */
	PARAM_MATCH_PARTIAL,			/* Allow the last parameter to be a partial match */
} param_match_t;

/* process we track */
typedef struct _vrrp_process {
	const char		*pname;		/* Process name */
	const char		*process_path;	/* Path to process */
	const char		*process_params; /* NUL separated parameters */
	size_t			process_params_len; /* Total length of parameters, including NULs */
	param_match_t		param_match;	/* Full or partial match of parameters */
	int			weight;		/* Default weight */
	bool			weight_reverse;	/* which direction is the weight applied */
	unsigned		quorum;		/* Minimum number of process instances required */
	unsigned		quorum_max;	/* Maximum number of process instances required */
	int			fork_delay;	/* Delay before processing process fork */
	int			terminate_delay; /* Delay before processing process termination */
	bool			full_command;	/* Set if match against full command line */
	thread_ref_t		fork_timer_thread; /* For handling delay */
	thread_ref_t		terminate_timer_thread; /* For handling delay */
	list			tracking_vrrp;	/* List of tracking_vrrp_t for vrrp instances tracking this process */
	unsigned		num_cur_proc;
	bool			have_quorum;	/* Set if quorum is treated as achieved */
	unsigned		sav_num_cur_proc; /* Used if have ENOBUFS on netlink socket read */
} vrrp_tracked_process_t;

/* Tracked process structure definition */
typedef struct _tracked_process {
	vrrp_tracked_process_t	*process;	/* track process pointer, cannot be NULL */
	int			weight;		/* Multiplier for process value */
	bool			weight_reverse;	/* which direction is the weight applied */
} tracked_process_t;

/* A monitored process instance */
typedef struct _tracked_process_instance {
	pid_t			pid;
	rb_node_t		pid_tree;
	list			processes;	/* list of vrrp_tracked_process_t* */
} tracked_process_instance_t;
#endif

#ifdef _WITH_BFD_
/* external bfd we read to track forwarding to remote systems */
typedef struct _vrrp_bfd {
	char			bname[BFD_INAME_MAX];	/* bfd name */
	int			weight;		/* Default weight */
	bool			weight_reverse;	/* apply weight in opposite direction */
	list			tracking_vrrp;	/* List of tracking_vrrp_t for vrrp instances tracking this bfd */
	bool			bfd_up;		/* Last status returned by bfd. Used to report changes */
} vrrp_tracked_bfd_t;

/* Tracked bfd structure definition */
typedef struct _tracked_bfd {
	vrrp_tracked_bfd_t	*bfd;		/* track bfd pointer, cannot be NULL */
	int			weight;		/* Weight for bfd */
	bool			weight_reverse; /* which direction is the weight applied */
} tracked_bfd_t;
#endif

/* Forward references */
struct _vrrp_t;
struct _vrrp_sgroup;

typedef enum {
	TRACK_VRRP = 0x01,
	TRACK_IF = 0x02,
	TRACK_SG = 0x04,
	TRACK_ADDR = 0x08,
	TRACK_ROUTE = 0x10,
	TRACK_RULE = 0x20,
	TRACK_SADDR = 0x40,
	TRACK_SROUTE = 0x80,
	TRACK_SRULE = 0x100,
	TRACK_VRRP_DYNAMIC = 0x200,
} track_t;

/* List structure from scripts, files and interfaces to tracking vrrp */
typedef struct _tracking_vrrp {
	int			weight;		/* Tracking weight, or zero for down instance */
	int			weight_multiplier; /* Which direction is weight applied */
	struct _vrrp_t		*vrrp;		/* The vrrp instance */
	track_t			type;		/* Type of object being tracked */
} tracking_vrrp_t;

/* prototypes */
extern void dump_track_if(FILE *, const void *);
extern void free_track_if(void *);
extern void alloc_track_if(const char *, list, const vector_t *);
extern void dump_track_script(FILE *, const void *);
extern void free_track_script(void *);
extern void alloc_track_script(const char *, list, const vector_t *);
extern void dump_track_file(FILE *, const void *);
extern void free_track_file(void *);
extern void alloc_track_file(const char *, list, const vector_t *);
#ifdef _WITH_CN_PROC_
extern void dump_track_process(FILE *, const void *);
extern void free_track_process(void *);
extern void alloc_track_process(const char *, list, const vector_t *);
#endif
#ifdef _WITH_BFD_
extern vrrp_tracked_bfd_t *find_vrrp_tracked_bfd_by_name(const char *) __attribute__ ((pure));
extern void dump_vrrp_tracked_bfd(FILE *, const void *);
extern void free_vrrp_tracked_bfd(void *);
extern void alloc_track_bfd(const char *, list, const vector_t *);
#endif
extern vrrp_script_t *find_script_by_name(const char *) __attribute__ ((pure));
extern void update_script_priorities(vrrp_script_t *, bool);
extern void down_instance(struct _vrrp_t *);
extern void vrrp_set_effective_priority(struct _vrrp_t *);
extern void initialise_tracking_priorities(void);
extern void init_track_files(list);
extern void stop_track_files(void);
#ifdef _WITH_CN_PROC_
extern void process_update_track_process_status(vrrp_tracked_process_t *, bool);
#endif
#ifdef THREAD_DUMP
extern void register_vrrp_inotify_addresses(void);
#endif

#endif
