/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        sockaddr.h include file.
 *
 * Author:      Quentin Armitage <quentin@armitage.org.uk>
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
 * Copyright (C) 2020-2020 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _SOCKADDR_H
#define _SOCKADDR_H

#include "config.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

/* struct sockaddr_storage is 128 bytes, considerably larger than sockaddr_in6 (28 bytes).
 * Where we might have a large number of such sockaddrs, use a sockaddr_t */

typedef union {
#ifdef __SOCKADDR_COMMON
	__SOCKADDR_COMMON(ss_);
#else
	sa_family_t ss_family;
#endif
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
} sockaddr_t;

/* See sockstorage_equal() and inet_sockaddrcmp() and inet_inaddrcmp() */
static inline int
sockaddr_cmp(const struct sockaddr_storage *ss_a, const struct sockaddr_storage *ss_b)
{
	return memcmp(ss_a, ss_b, sizeof(*ss_a));
}
#endif
