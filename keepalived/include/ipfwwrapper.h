/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        ipfwwrapper.c include file.
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
 * Copyright (C) 2001-2009 Alexandre Cassen, <acassen@freebox.fr>
 */

#ifndef _IPFWWRAPPER_H
#define _IPFWWRAPPER_H

/* system includes */
#include <errno.h>
#include <arpa/inet.h>

/* locale includes */
#include "../libipfwc/libipfwc.h"
#include "check_data.h"

/* local defs */
#define IPFW_ERROR   0
#define IPFW_SUCCESS 1

#define IP_FW_CMD_ADD 0x0001
#define IP_FW_CMD_DEL 0x0002

/* NAT netmask */
#define IPFW_SRC_NETMASK 0xffffffff

/* prototypes */
extern int ipfw_cmd(int cmd, virtual_server * vserver, real_server * rserver);

#endif
