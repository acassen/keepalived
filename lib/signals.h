/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        signals.c include file.
 *  
 * Version:     $Id: signals.h,v 1.1.15 2007/09/15 04:07:41 acassen Exp $
 *
 * Author:      Kevin Lindsay, <kevinl@netnation.com>
 *              Alexandre Cassen, <acassen@linux-vs.org>
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
 * Copyright (C) 2001-2007 Alexandre Cassen, <acassen@freebox.fr>
 */

#ifndef _SIGNALS_H
#define _SIGNALS_H

/* signals definition */
#define SIGNAL_SIGHUP	0x02
#define SIGNAL_SIGINT	0x04
#define SIGNAL_SIGTERM	0x08
#define SIGNAL_SIGCHLD	0x10

/* Prototypes */
extern int signal_pending(void);
extern void *signal_set(int signo, void (*func) (int));
extern void *signal_ignore(int signo);
extern void signal_noignore_sigchld(void);
extern void signal_handler_init(void);
extern void signal_run_callback(void);

#endif
