/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        layer4.c include file.
 *
 * Version:     $Id: layer4.h,v 0.4.0 2001/08/24 00:35:19 acassen Exp $
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

#ifndef _LAYER4_H
#define _LAYER4_H

/* system includes */
#include <unistd.h>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>

/* local includes */
#include "cfreader.h"
#include "scheduler.h"
#include "check_http.h"

enum connect_result {
  connect_error,
  connect_success,
  connect_in_progress,
  connect_timeout
};

/* Prototypes defs */
extern enum connect_result
tcp_connect(int fd, uint32_t IP_DST, uint16_t PORT_DST);

extern enum connect_result
tcp_socket_state(int fd, struct thread *thread,
                         int (*func) (struct thread *));

extern void
tcp_connection_state(int fd, enum connect_result status,
                             struct thread *thread,
                             int (*func) (struct thread *));

#endif
