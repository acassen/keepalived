/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        httpget.c include file.
 *  
 * Version:     $Id: httpget.h,v 0.2.1 2000/12/09 $
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

#ifndef HTTPGET_H
#define HTTPGET_H

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <termios.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <md5.h>

#define SOCKET_ERROR   0
#define SOCKET_SUCCESS 1

#define MD5_BUFFER_LENGTH 32
#define GET_REQUEST_BUFFER_LENGTH 128
#define GET_BUFFER_LENGTH 2048
#define LOGBUFFER_LENGTH 100

/* prototypes */
int HTTP_GET(char *IP_SRC,char *IP_DST,char *PORT_DST,char *URL,char MDResult[0x40]);

#endif
