/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_ci.c include file.
 *
 * Version:     $Id: check_ci.h,v 1.1.2 2003/09/08 01:18:41 acassen Exp $
 *
 * Authors:     Alexandre Cassen, <acassen@linux-vs.org>
 *              Aneesh Kumar K.V, <aneesh.kumar@digital.com>
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

#ifndef _CI_LINUX_H
#define _CI_LINUX_H

/* system includes */
#include <signal.h>
#include <pthread.h>
#include <linux/cluster.h>	/* Should change this to cluster.h alone */
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* local includes */
#include "scheduler.h"

#define CLUSTERTAB "/etc/clustertab"
#define BUFFSIZE 100
#define UP 1
#define DOWN 2
#define UNKNOWN_NODE 0

typedef struct nodenum_ip_map {
	uint32_t addr_ip;
} nodenum_ip_map_t;

/* Prototypes defs */
extern int initialize_nodemap(nodenum_ip_map_t * nodemap);
extern clusternode_t address_to_nodenum(uint32_t addr_ip);
extern int nodestatus(uint32_t addr_ip);
extern void install_ci_check_keyword(void);
extern int ci_check_thread(thread * thread);

#endif
