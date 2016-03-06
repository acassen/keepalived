/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Dynamic data structure definition.
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

#ifndef _GLOBAL_DATA_H
#define _GLOBAL_DATA_H

/* system includes */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>

#ifdef HAVE_LINUX_NETFILTER_X_TABLES_H
#include <linux/netfilter/x_tables.h>
#else
#define	XT_EXTENSION_MAXNAMELEN 29
#endif

#ifdef _HAVE_LIBIPSET_
#include <libipset/linux_ip_set.h>
#endif

/* local includes */
#include "list.h"
#include "timer.h"

/* constants */
#define DEFAULT_SMTP_SERVER 0x7f000001
#define DEFAULT_SMTP_CONNECTION_TIMEOUT (30 * TIMER_HZ)

/* email link list */
typedef struct _email {
	char				*addr;
} email_t;

/* Configuration data root */
typedef struct _data {
	int				linkbeat_use_polling;
	char				*router_id;
	char				*email_from;
	struct sockaddr_storage		smtp_server;
	long				smtp_connection_to;
	list				email;
	struct sockaddr_storage		vrrp_mcast_group4;
	struct sockaddr_storage		vrrp_mcast_group6;
	int				vrrp_garp_delay;
	timeval_t			vrrp_garp_refresh;
	int				vrrp_garp_rep;
	int				vrrp_garp_refresh_rep;
	int				vrrp_version;            /* VRRP version (2 or 3) */
	char				vrrp_iptables_inchain[XT_EXTENSION_MAXNAMELEN];
	char				vrrp_iptables_outchain[XT_EXTENSION_MAXNAMELEN];
	int				block_ipv4;
	int				block_ipv6;
#ifdef _HAVE_LIBIPSET_
	int				using_ipsets;
	char				vrrp_ipset_address[IPSET_MAXNAMELEN];
	char				vrrp_ipset_address6[IPSET_MAXNAMELEN];
	char				vrrp_ipset_address_iface6[IPSET_MAXNAMELEN];
#endif
	char				vrrp_check_unicast_src;
	char				vrrp_skip_check_adv_addr;
	char				vrrp_strict;
#ifdef _WITH_SNMP_
	int				enable_traps;
	char				*snmp_socket;
	int				enable_snmp_keepalived;
	int				enable_snmp_rfcv2;
	int				enable_snmp_rfcv3;
	int				enable_snmp_checker;
#endif
} data_t;

/* Global vars exported */
extern data_t *global_data; /* Global configuration data */

/* Prototypes */
extern void alloc_email(char *);
extern data_t *alloc_global_data(void);
extern void init_global_data(data_t *);
extern void free_global_data(data_t *);
extern void dump_global_data(data_t *);

#endif
