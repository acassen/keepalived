/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        ipfwwrapper.c include file.
 *  
 * Version:     $Id: ipfwwrapper.h,v 0.2.7 2001/03/30 $
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

#ifndef IPFWWRAPPER_H
#define IPFWWRAPPER_H

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

#include "libipfwc/libipfwc.h"
#include "cfreader.h"
#include "ipfwwrappercmd.h"

#define IPFW_ERROR   0
#define IPFW_SUCCESS 1

#define IPFW_SRC_NETMASK "255.255.255.255"

#define LOGBUFFER_LENGTH 100

#endif
