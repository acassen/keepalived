/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_tcp.c include file.
 *
 * Version:     $Id: check_tcp.h,v 0.3.7 2001/09/14 00:37:56 acassen Exp $
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
 */

#ifndef _TCP_H
#define _TCP_H

/* system includes */
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

/* local includes */
#include "cfreader.h"
#include "ipwrapper.h"
#include "scheduler.h"
#include "layer4.h"
#include "smtp.h"

/* Prototypes defs */
extern int tcp_connect_thread(struct thread *thread);

#endif
