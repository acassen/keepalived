/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_tcp.c include file.
 *
 * Version:     $Id: check_tcp.h,v 0.6.3 2002/06/18 21:39:17 acassen Exp $
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
#include "scheduler.h"

/* Checker argument structure  */
typedef struct _tcp_checker {
  uint16_t connection_port;
  int connection_to;
} tcp_checker;

/* Prototypes defs */
extern void install_tcp_check_keyword(void);

#endif
