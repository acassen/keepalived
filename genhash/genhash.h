/* 
 * Soft:        Genhash compute MD5 digest from a HTTP get result. This
 *              program is use to compute hash value that you will add
 *              into the /etc/keepalived/keepalived.conf for the 
 *              HTTP_GET_CHECK.
 *
 * Part:        genhash.c include file.
 *  
 * Version:     $Id: keepalived.c,v 0.2.0 2000/12/09 $
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

#ifndef GENHASH_H
#define GENHASH_H

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
#include <linux/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <fcntl.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include "md5.h"

#define GETCMD "GET %s HTTP/1.0\r\n\r\n"

/* Socket Timeout */
#define SOCKET_TIMEOUT_READ    3
#define SOCKET_TIMEOUT_CONNECT 3

/* Sockets connection errors codes */
#define ERROR_SOCKET        0

/* Data buffer length description */
#define GET_BUFFER_LENGTH   180
#define RCV_BUFFER_LENGTH   1024

/* Build version */
#define PROG    "genhash"
#define VERSION "0.2.0 (12/09, 2000), Alexandre Cassen"

#endif
