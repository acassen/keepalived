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
#include <stdbool.h>
#include <sys/types.h>

#ifdef HAVE_LINUX_NETFILTER_X_TABLES_H
#include <linux/netfilter/x_tables.h>
#endif

#ifdef _HAVE_LIBIPSET_
#include <libipset/linux_ip_set.h>
#endif

/* local includes */
#include "list.h"
#include "timer.h"
#include "vrrp.h"
#ifdef _WITH_LVS_
#include "ipvswrapper.h"
#endif

#ifndef _HAVE_LIBIPTC_
#define	XT_EXTENSION_MAXNAMELEN		29
#endif

/* constants */
#define DEFAULT_SMTP_SERVER 0x7f000001
#define DEFAULT_SMTP_CONNECTION_TIMEOUT (30 * TIMER_HZ)

/* email link list */
typedef struct _email {
	char				*addr;
} email_t;

/* Configuration data root */
typedef struct _data {
	bool				linkbeat_use_polling;
	char				*router_id;
	char				*email_from;
	struct sockaddr_storage		smtp_server;
	char				*smtp_helo_name;
	unsigned long			smtp_connection_to;
	list				email;
	interface_t			*default_ifp;		/* Default interface for static addresses */
#ifdef _WITH_LVS_
	int				lvs_tcp_timeout;
	int				lvs_tcpfin_timeout;
	int				lvs_udp_timeout;
#ifdef _WITH_LVS_
	struct lvs_syncd_config		lvs_syncd;
#endif
	bool				lvs_flush;		/* flush any residual LVS config at startup */
#endif
#ifdef _WITH_VRRP_
	struct sockaddr_storage		vrrp_mcast_group4;
	struct sockaddr_storage		vrrp_mcast_group6;
	unsigned			vrrp_garp_delay;
	timeval_t			vrrp_garp_refresh;
	unsigned			vrrp_garp_rep;
	unsigned			vrrp_garp_refresh_rep;
	unsigned			vrrp_garp_lower_prio_delay;
	unsigned			vrrp_garp_lower_prio_rep;
	unsigned			vrrp_garp_interval;
	unsigned			vrrp_gna_interval;
	bool				vrrp_lower_prio_no_advert;
	int				vrrp_version;	/* VRRP version (2 or 3) */
	char				vrrp_iptables_inchain[XT_EXTENSION_MAXNAMELEN];
	char				vrrp_iptables_outchain[XT_EXTENSION_MAXNAMELEN];
	bool				block_ipv4;
	bool				block_ipv6;
#ifdef _HAVE_LIBIPSET_
	bool				using_ipsets;
	char				vrrp_ipset_address[IPSET_MAXNAMELEN];
	char				vrrp_ipset_address6[IPSET_MAXNAMELEN];
	char				vrrp_ipset_address_iface6[IPSET_MAXNAMELEN];
#endif
	bool				vrrp_check_unicast_src;
	bool				vrrp_skip_check_adv_addr;
	bool				vrrp_strict;
	char				vrrp_process_priority;
	bool				vrrp_no_swap;
#endif
#ifdef _WITH_LVS_
	char				checker_process_priority;
	bool				checker_no_swap;
#endif
#ifdef _WITH_SNMP_
	bool				enable_traps;
	char				*snmp_socket;
#ifdef _WITH_VRRP_
	bool				enable_snmp_keepalived;
	bool				enable_snmp_rfcv2;
	bool				enable_snmp_rfcv3;
#endif
#ifdef _WITH_LVS_
	bool				enable_snmp_checker;
#endif
#endif
#ifdef _WITH_DBUS_
	bool				enable_dbus;
#endif
	bool				script_security;
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
