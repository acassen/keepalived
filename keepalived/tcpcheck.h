/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        tcpcheck.c include file.
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

#ifndef CFREADER_H
#define CFREADER_H

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/time.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define SOCKET_ERROR   0
#define SOCKET_SUCCESS 1
#define STCP 1111

#define LOGBUFFER_LENGTH 100
#define SYNPACKET_LENGTH 1024
#define HOSTNAME_LENGTH  30

/* Structures used */
struct tcphdr_pseudo {
  unsigned int saddr;
  unsigned int daddr;
  unsigned char zero;
  unsigned char proto;
  unsigned short tcplen;
  struct tcphdr tcp;
};

/* prototypes */
int TCP_CHECK(char *IP_SRC, char *IP_DST, char *PORT_DST);

#endif
