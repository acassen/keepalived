/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        watchdog.c include file.
 *  
 * Version:     $Id: watchdog.h,v 1.1.4 2003/12/29 12:12:04 acassen Exp $
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

#ifndef _WATCHDOG_H
#define _WATCHDOG_H

/* local includes */
#include "scheduler.h"

/* watchdog data */
typedef struct _wdog_data {
	char *wdog_string;		/* motd wdog string */
	char *wdog_path;		/* unix domain socket */
	pid_t wdog_pid;			/* pid to monitor */
	int wdog_sd;			/* wdog socket descriptor */
	int (*wdog_start) (void);	/* respawn handler */
} wdog_data;

/* watchdog definition */
#define WATCHDOG_TIMER		30
#define WATCHDOG_DELAY		(5 * TIMER_HZ)
#define WATCHDOG_STRING		"hello"
#define WDOG_READ_BUFSIZ	32

/* Prototypes */
extern int wdog_init(char *path);
extern void wdog_close(int sd, char *path);
extern int wdog_boot_thread(thread *thread);

#endif
