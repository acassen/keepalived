/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        ipvswrapper.c include file.
 *  
 * Version:     $Id: keepalived.c,v 0.2.1 2000/12/09 $
 * 
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *              
 * Changes:     
 *              Alexandre Cassen      :       Initial release
 *              
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#ifndef IPVSWRAPPER_H
#define IPVSWRAPPER_H

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
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

#include "cfreader.h"

#define IPVS_ERROR   0
#define IPVS_SUCCESS 1

#define IPVS_CMD_DEL 0
#define IPVS_CMD_ADD 1

#define LOGBUFFER_LENGTH 100

/* prototypes */
int ipvs_pool_cmd(int cmd, virtualserver *vserver);

#endif
