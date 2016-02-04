/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        ipvswrapper.c include file.
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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
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
#include <sys/wait.h>

#ifdef _WITH_LVS_
#ifdef _KRNL_2_4_
  #include "../libipvs-2.4/libipvs.h"
  #include <net/ip_vs.h>
#elif _KRNL_2_6_
  #include "../libipvs-2.6/ip_vs.h"
  #include "../libipvs-2.6/libipvs.h"
#endif
//  #include <net/ip_vs.h>
#endif

#ifndef IP_VS_TEMPLATE_TIMEOUT
#define IP_VS_TEMPLATE_TIMEOUT IPVS_SVC_PERSISTENT_TIMEOUT
#endif

/* locale includes */
#include "scheduler.h"
#include "check_data.h"

#define IPVS_ERROR	0
#define IPVS_SUCCESS	1
#define IPVS_CMD_DELAY	3

#ifdef _HAVE_IPVS_SYNCD_
#define IPVS_STARTDAEMON	IP_VS_SO_SET_STARTDAEMON
#define IPVS_STOPDAEMON		IP_VS_SO_SET_STOPDAEMON
#define IPVS_MASTER		IP_VS_STATE_MASTER
#define IPVS_BACKUP		IP_VS_STATE_BACKUP
#else
#define IPVS_STARTDAEMON	1
#define IPVS_STOPDAEMON		2
#define IPVS_MASTER		3
#define IPVS_BACKUP		4
#endif

/* Macro */
#define IPVS_ALIVE(X,Y,Z)	(((X) == IP_VS_SO_SET_ADD && !(Y)->alive)	|| \
				 ((X) == IP_VS_SO_SET_DEL && (Y)->alive)	|| \
				 ((X) == IP_VS_SO_SET_ADDDEST && !(Z)->alive)	|| \
				 ((X) == IP_VS_SO_SET_DELDEST && (Z)->alive)	|| \
				 (X) == IP_VS_SO_SET_EDITDEST			   \
				)

#define IPVS_SET_ALIVE(C,V)			\
do {						\
	if ((C) == IP_VS_SO_SET_ADD)		\
		SET_ALIVE((V));			\
	if ((C) == IP_VS_SO_SET_DEL)		\
		UNSET_ALIVE((V));		\
} while (0)

/* prototypes */
extern int ipvs_start(void);
extern void ipvs_stop(void);
extern virtual_server_group_t *ipvs_get_group_by_name(char *, list);
extern void ipvs_group_sync_entry(virtual_server_t *vs, virtual_server_group_entry_t *vsge);
extern void ipvs_group_remove_entry(virtual_server_t *, virtual_server_group_entry_t *);
extern int ipvs_cmd(int, virtual_server_t *, real_server_t *);
extern void ipvs_syncd_cmd(int, char *, int, int);
extern void ipvs_syncd_master(char *, int);
extern void ipvs_syncd_backup(char *, int);

#ifdef _KRNL_2_6_
/* Refresh statistics at most every 5 seconds */
#define STATS_REFRESH 5
extern void ipvs_update_stats(virtual_server_t * vs);
#endif

#endif
