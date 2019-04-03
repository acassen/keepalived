/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_udp.c include file.
 *
 * Author:      Jie Liu, <liujie165@huawei.com>
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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _CHECK_PING_H
#define _CHECK_PING_H

/* system includes */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>
#include "check_api.h"

#define SOCK_RECV_BUFF 128*1024 //128k
#define ICMP_BUFSIZE 128

/* function prototypes */
extern enum connect_result ping_it(int, conn_opts_t* );
extern enum connect_result recv_it(int);
extern enum connect_result ping6_it(int, conn_opts_t* );
extern enum connect_result recv6_it(int);


#endif
