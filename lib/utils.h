/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        utils.h include file.
 *
 * Version:     $Id: utils.h,v 1.1.5 2004/01/25 23:14:31 acassen Exp $
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

#ifndef _UTILS_H
#define _UTILS_H

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <netdb.h>

/* Global debugging logging facilities */
#ifdef _DEBUG_
#define DBG(fmt, msg...) syslog(LOG_DEBUG, fmt, ## msg)
#else
#define DBG(fmt, msg...)
#endif

/* Prototypes defs */
extern void print_buffer(int count, char *buff);
extern char *inet_ntop2(uint32_t ip);
extern char *inet_ntoa2(uint32_t ip, char *buf);
extern uint8_t inet_stom(char *addr);
extern uint8_t inet_stor(char *addr);
extern int inet_ston(const char *addr, uint32_t * dst);
extern char *get_local_name(void);

#endif
