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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _GLOBAL_DATA_H
#define _GLOBAL_DATA_H

#include "config.h"

/* system includes */
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sched.h>
#include <linux/netfilter/x_tables.h>

#ifdef _HAVE_LIBIPSET_
#include <linux/netfilter/ipset/ip_set.h>
#endif

#ifdef _WITH_NFTABLES_
#include <linux/netfilter/nf_tables.h>
#endif

#include <sys/resource.h>

/* local includes */
#include "list_head.h"
#include "vrrp_if.h"
#include "timer.h"
#ifdef _WITH_VRRP_
#include "vrrp.h"
#endif
#ifdef _WITH_LVS_
#include "ipvswrapper.h"
#include "libipvs.h"
#endif
#include "notify.h"

/* constants */
#define DEFAULT_SMTP_CONNECTION_TIMEOUT (30 * TIMER_HZ)

#ifdef _WITH_VRRP_
#define RX_BUFS_POLICY_MTU		0x01
#define RX_BUFS_POLICY_ADVERT		0x02
#define RX_BUFS_SIZE			0x04
#endif

#ifdef _WITH_LVS_
#define LVS_MAX_TIMEOUT			(86400*31)      /* 31 days */
#endif

/* email link list */
typedef struct _email {
	char				*addr;

	/* Linked list member */
	list_head_t			e_list;
} email_t;

#ifdef _WITH_LVS_
typedef enum {
	LVS_NO_FLUSH,
	LVS_FLUSH_FULL,
	LVS_FLUSH_VS
} lvs_flush_t;
#endif

/* Configuration data root */
typedef struct _data {
	const char			*process_name;
#ifdef _WITH_VRRP_
	const char			*vrrp_process_name;
#endif
#ifdef _WITH_LVS_
	const char			*lvs_process_name;
#endif
#ifdef _WITH_BFD_
	const char			*bfd_process_name;
#endif
	const char			*network_namespace;		/* network namespace name */
	const char			*network_namespace_ipvs;	/* network namespace name for ipvs */
	bool				namespace_with_ipsets;		/* override for namespaces with ipsets on Linux < 3.13 */
	const char			*local_name;
	const char			*instance_name;		/* keepalived instance name */
#ifdef _WITH_LINKBEAT_
	bool				linkbeat_use_polling;
#endif
	const char			*router_id;
	const char			*email_from;
	struct sockaddr_storage		smtp_server;
	const char			*smtp_helo_name;
	unsigned long			smtp_connection_to;
	list_head_t			email;
	int				smtp_alert;
	notify_script_t			*startup_script;
	unsigned			startup_script_timeout;
	notify_script_t			*shutdown_script;
	unsigned			shutdown_script_timeout;
#ifndef _ONE_PROCESS_DEBUG_
	const char			*reload_check_config;	/* log file name for validating new configuration before reloading */
	const char			*reload_time_file;
	bool				reload_repeat;
	time_t				reload_time;
	bool				reload_date_specified;
	const char			*reload_file;
#endif
	const char 			*config_directory;
	bool				data_use_instance;
#ifdef _WITH_VRRP_
	bool				dynamic_interfaces;
	bool				allow_if_changes;
	bool				no_email_faults;
	int				smtp_alert_vrrp;
	const char			*default_ifname;	/* Name of default interface */
	interface_t			*default_ifp;		/* Default interface for static addresses */
	bool				disable_local_igmp;
#endif
#ifdef _WITH_LVS_
	ipvs_timeout_t			lvs_timeouts;
	int				smtp_alert_checker;
	bool				checker_log_all_failures;
	struct lvs_syncd_config		lvs_syncd;
	bool				lvs_flush;		/* flush any residual LVS config at startup */
	lvs_flush_t			lvs_flush_on_stop;	/* flush any LVS config at shutdown */
#endif
	int				max_auto_priority;
	long				min_auto_priority_delay;
#ifdef _WITH_VRRP_
	struct sockaddr_in6		vrrp_mcast_group6 __attribute__((aligned(__alignof__(struct sockaddr_storage))));
	struct sockaddr_in		vrrp_mcast_group4 __attribute__((aligned(__alignof__(struct sockaddr_storage))));
	unsigned			vrrp_garp_delay;
	timeval_t			vrrp_garp_refresh;
	unsigned			vrrp_garp_rep;
	unsigned			vrrp_garp_refresh_rep;
	unsigned			vrrp_garp_lower_prio_delay;
	unsigned			vrrp_garp_lower_prio_rep;
	unsigned			vrrp_garp_interval;
	unsigned			vrrp_gna_interval;
#ifdef _HAVE_VRRP_VMAC_
	unsigned			vrrp_vmac_garp_intvl;
	bool				vrrp_vmac_garp_all_if;
#endif
	bool				vrrp_lower_prio_no_advert;
	bool				vrrp_higher_prio_send_advert;
	int				vrrp_version;		/* VRRP version (2 or 3) */
#ifdef _WITH_IPTABLES_
	const char			*vrrp_iptables_inchain;
	const char			*vrrp_iptables_outchain;
#ifdef _HAVE_LIBIPSET_
	unsigned			using_ipsets;
	const char			*vrrp_ipset_address;
	const char			*vrrp_ipset_address6;
	const char			*vrrp_ipset_address_iface6;
	const char			*vrrp_ipset_igmp;
	const char			*vrrp_ipset_mld;
#endif
#endif
#ifdef _WITH_NFTABLES_
	const char			*vrrp_nf_table_name;
	int				vrrp_nf_chain_priority;
	bool				vrrp_nf_ifindex;
#endif
	bool				vrrp_check_unicast_src;
	bool				vrrp_skip_check_adv_addr;
	bool				vrrp_strict;
	bool				have_vrrp_config;
	char				vrrp_process_priority;
	bool				vrrp_no_swap;
	unsigned			vrrp_realtime_priority;
	cpu_set_t			vrrp_cpu_mask;
	rlim_t				vrrp_rlimit_rt;
#endif
#ifdef _WITH_LVS_
	bool				have_checker_config;
	char				checker_process_priority;
	bool				checker_no_swap;
	unsigned			checker_realtime_priority;
	cpu_set_t			checker_cpu_mask;
	rlim_t				checker_rlimit_rt;
#ifdef _WITH_NFTABLES_
	const char			*ipvs_nf_table_name;
	int				ipvs_nf_chain_priority;
	uint32_t			ipvs_nftables_start_fwmark;
#endif
#endif
#ifdef _WITH_NFTABLES_
	bool				nf_counters;
#endif
#ifdef _WITH_BFD_
	bool				have_bfd_config;
	char				bfd_process_priority;
	bool				bfd_no_swap;
	unsigned			bfd_realtime_priority;
	cpu_set_t			bfd_cpu_mask;
	rlim_t				bfd_rlimit_rt;
#endif
	notify_fifo_t			notify_fifo;
#ifdef _WITH_VRRP_
	notify_fifo_t			vrrp_notify_fifo;
#endif
#ifdef _WITH_LVS_
	notify_fifo_t			lvs_notify_fifo;
#endif
#ifdef _WITH_VRRP_
	int				vrrp_notify_priority_changes;
#endif
#ifdef _WITH_SNMP_
	bool				enable_traps;
	const char			*snmp_socket;
#ifdef _WITH_VRRP_
#ifdef _WITH_SNMP_VRRP_
	bool				enable_snmp_vrrp;
#endif
#ifdef _WITH_SNMP_RFCV2_
	bool				enable_snmp_rfcv2;
#endif
#ifdef _WITH_SNMP_RFCV3_
	bool				enable_snmp_rfcv3;
#endif
#endif
#ifdef _WITH_LVS_
	bool				enable_snmp_checker;
#endif
#endif
#ifdef _WITH_DBUS_
	bool				enable_dbus;
	const char			*dbus_service_name;
#endif
#ifdef _WITH_VRRP_
	unsigned			vrrp_netlink_cmd_rcv_bufs;
	bool				vrrp_netlink_cmd_rcv_bufs_force;
	unsigned			vrrp_netlink_monitor_rcv_bufs;
	bool				vrrp_netlink_monitor_rcv_bufs_force;
#ifdef _WITH_TRACK_PROCESS_
	unsigned			process_monitor_rcv_bufs;
	bool				process_monitor_rcv_bufs_force;
#endif
#endif
#ifdef _WITH_LVS_
	unsigned			lvs_netlink_cmd_rcv_bufs;
	bool				lvs_netlink_cmd_rcv_bufs_force;
	unsigned			lvs_netlink_monitor_rcv_bufs;
	bool				lvs_netlink_monitor_rcv_bufs_force;
#endif
#ifdef _WITH_LVS_
	bool				rs_init_notifies;
	bool				no_checker_emails;
#endif
#ifdef _WITH_VRRP_
	int				vrrp_rx_bufs_policy;
	size_t				vrrp_rx_bufs_size;
	int				vrrp_rx_bufs_multiples;
	unsigned			vrrp_startup_delay;
	bool				log_unknown_vrids;
#ifdef _HAVE_VRRP_VMAC_
	const char			*vmac_prefix;
	const char			*vmac_addr_prefix;
#endif
#endif
} data_t;

/* Global vars exported */
extern data_t *global_data;	/* Global configuration data */
extern data_t *old_global_data;	/* Old global configuration data - used during reload */

/* Prototypes */
extern void alloc_email(const char *);
extern data_t *alloc_global_data(void);
extern void init_global_data(data_t *, data_t *, bool);
extern void free_global_data(data_t *);
extern FILE *open_dump_file(const char *) __attribute__((malloc));
extern void dump_global_data(FILE *, data_t *);

#endif
