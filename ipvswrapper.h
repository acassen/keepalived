/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        ipvswrapper.c include file.
 *
 * Version:     $Id: ipvswrapper.c,v 0.3.5 2001/07/13 03:46:38 acassen Exp $
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

#ifndef _IPVSWRAPPER_H
#define _IPVSWRAPPER_H

/* system includes */
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <arpa/inet.h>
#include <asm/types.h>

#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <linux/ip_fw.h>
#include <linux/ip_masq.h>
#include <net/ip_masq.h>
#include <net/ip_vs.h>

/* locale includes */
#include "cfreader.h"

#define IPVS_ERROR   0
#define IPVS_SUCCESS 1

/* Return codes */
#define IPVSNOTDEFINED 0x0003
#define IPVSSVREXIST   0x0004
#define IPVSNODEST     0x0005

/* prototypes */
extern int parse_timeout(char *buf, unsigned *timeout);
extern int string_to_number(const char *s, int min, int max);
extern int ipvs_cmd(int cmd, virtualserver *vserver, realserver *rserver);

#endif
