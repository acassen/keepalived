/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        notify.c include file.
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

#ifndef _NOTIFY_H
#define _NOTIFY_H

/* system includes */
#include <sys/types.h>
#include <stdbool.h>

/* application includes */
#include "scheduler.h"
#include "memory.h"
#include "vector.h"
#include "keepalived_magic.h"

/* Flags returned by check_script_secure() */
#define SC_INSECURE     0x01    /* Script is insecure */
#define SC_ISSCRIPT     0x02    /* It is a script */
#define SC_INHIBIT      0x04    /* Script needs inhibiting */
#define SC_NOTFOUND	0x08	/* Cannot find element of path */
#define SC_EXECUTABLE	0x10	/* The script is marked executable */
#define SC_EXECABLE	0x20	/* The script can be invoked via execve() */
#define SC_SYSTEM	0x40	/* The script can safely be executed via system() */

typedef enum {
	SCRIPT_STATE_IDLE,
	SCRIPT_STATE_RUNNING,
	SCRIPT_STATE_REQUESTING_TERMINATION,
	SCRIPT_STATE_FORCING_TERMINATION
} script_state_t;

typedef enum {
	SCRIPT_INIT_STATE_DONE,
	SCRIPT_INIT_STATE_INIT,
	SCRIPT_INIT_STATE_FAILED,
} script_init_state_t;

/* notify_script details */
typedef struct _notify_script {
	const char **args;	/* Script args - should be "char const * const *" */
	int	num_args;	/* Used for notify script when adding last 4 parameters */
	int	flags;
	uid_t	uid;		/* uid of user to execute script */
	gid_t	gid;		/* gid of group to execute script */
} notify_script_t;

/* notify_fifo details */
typedef struct _notify_fifo {
	const char *name;
	int	fd;
	uid_t	uid;		/* uid of user of fifo if create */
	gid_t	gid;		/* gid of group of fifo */
	bool	created_fifo;	/* We created the FIFO */
	notify_script_t *script; /* Script to run to process FIFO */
} notify_fifo_t;

static inline void
free_notify_script(notify_script_t **script)
{
	if (!*script)
		return;
	FREE_PTR((*script)->args);
	FREE_PTR(*script);
	*script = NULL;
}

/* Default user/group for script execution */
extern uid_t default_script_uid;
extern gid_t default_script_gid;

/* Script security enabled */
extern bool script_security;

/* prototypes */
extern const char *cmd_str_r(const notify_script_t *, char *, size_t);
extern const char *cmd_str(const notify_script_t *);
extern void notify_fifo_open(notify_fifo_t*, notify_fifo_t*, int (*)(thread_ref_t), const char *);
extern void notify_fifo_close(notify_fifo_t*, notify_fifo_t*);
extern int system_call_script(thread_master_t *, int (*)(thread_ref_t), void *, unsigned long, notify_script_t *);
extern int notify_exec(const notify_script_t *);
extern int child_killed_thread(thread_ref_t);
extern void script_killall(thread_master_t *, int, bool);
extern int check_script_secure(notify_script_t *, magic_t);
extern int check_notify_script_secure(notify_script_t **, magic_t);
extern bool set_default_script_user(const char *, const char *);
extern bool set_script_uid_gid(const vector_t *, unsigned, uid_t *, gid_t *);
extern void set_script_params_array(const vector_t *, notify_script_t *, unsigned);
extern notify_script_t* notify_script_init(int, const char *);
extern void add_script_param(notify_script_t *, const char *);
extern void notify_resource_release(void);
extern bool notify_script_compare(const notify_script_t *, const notify_script_t *) __attribute__ ((pure));
#ifdef THREAD_DUMP
extern void register_notify_addresses(void);
#endif

#endif
