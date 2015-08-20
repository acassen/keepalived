/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        utils.h include file.
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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@linux-vs.org>
 */

#ifndef _UTILS_H
#define _UTILS_H

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <netdb.h>

/* Global debugging logging facilities */
#ifdef _DEBUG_
#define DBG(fmt, msg...) syslog(LOG_DEBUG, fmt, ## msg)
#else
#define DBG(fmt, msg...)
#endif

#define STR(x)  #x

/* global vars exported */
extern unsigned long debug;

/* Prototypes defs */
extern void dump_buffer(char *, int);
extern u_short in_csum(u_short *, int, int, int *);
extern char *inet_ntop2(uint32_t);
extern char *inet_ntoa2(uint32_t, char *);
extern uint8_t inet_stom(char *);
extern uint8_t inet_stor(char *);
extern int domain_stosockaddr(char *, char *, struct sockaddr_storage *);
extern int inet_stosockaddr(char *, char *, struct sockaddr_storage *);
extern int inet_ip4tosockaddr(struct in_addr *, struct sockaddr_storage *);
extern int inet_ip6tosockaddr(struct in6_addr *, struct sockaddr_storage *);
extern int inet_ip6scopeid(uint32_t, struct sockaddr_storage *);
extern char *inet_sockaddrtos(struct sockaddr_storage *);
extern char *inet_sockaddrtos2(struct sockaddr_storage *, char *);
extern char *inet_sockaddrtopair(struct sockaddr_storage *addr);
extern uint16_t inet_sockaddrport(struct sockaddr_storage *);
extern uint32_t inet_sockaddrip4(struct sockaddr_storage *);
extern int inet_sockaddrip6(struct sockaddr_storage *, struct in6_addr *);
extern int inet_inaddrcmp(int, void *, void *);
extern int inet_sockaddrcmp(struct sockaddr_storage *, struct sockaddr_storage *);
extern int inet_ston(const char *, uint32_t *);
uint32_t inet_broadcast(uint32_t, uint32_t);
uint32_t inet_cidrtomask(uint8_t);
extern char *get_local_name(void);
extern int string_equal(const char *, const char *);
extern int fork_exec(char **argv);

#endif
