/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        sockaddr.h include file.
 *
 * Author:      Quentin Armitage, <quentin@armitage.org.uk>
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
 * Copyright (C) 2021-2021 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _SOCKADDR_H
#define _SOCKADDR_H

#include "config.h"

#include <sys/socket.h>
#include <netinet/in.h>

/* If you want to use struct sockaddr_storage rather than struct sockaddr
 * use configure option --enable-sockaddr-storage
 * struct sockaddr_storage_t is much larger than we need, 128 bytes, versus
 * 28 bytes for the struct supporting just IPv4 and IPv6.
 */

#ifdef USE_SOCKADDR_STORAGE
typedef struct sockaddr_storage sockaddr_t;
#else
typedef struct {
	union {
		sa_family_t ss_family;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	};
} sockaddr_t;
#endif
#endif
