/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        icmpcheck.c include file.
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

#ifndef ICMPCHECK_H
#define ICMPCHECK_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define ICMP_DATA "KeepAlive for LVS v1.0"

#define HDRBUFFSIZE (sizeof(struct icmphdr) + sizeof(struct iphdr))
#define BUFFSIZE (HDRBUFFSIZE + sizeof(ICMP_DATA))

#define DEFAULT_SELECT_TIME 10
#define ICMP_MINLEN 8
#define SIZE_ICMP_HDR ICMP_MINLEN

#define DELAY_TIME 1

#define LOGBUFFER_LENGTH 100

#define select_time (DEFAULT_SELECT_TIME * 100)

/* prototypes  */
int ICMP_CHECK(char dst_ip[16]);

#endif
