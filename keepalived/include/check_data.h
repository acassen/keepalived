/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Healthcheckers dynamic data structure definition.
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

#ifndef _CHECK_DATA_H
#define _CHECK_DATA_H

#include "config.h"

/* system includes */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>


/* local includes */
#include "logger.h"
#include "ip_vs.h"
#include "list_head.h"
#include "vector.h"
#include "notify.h"
#include "utils.h"
#ifdef _WITH_BFD_
#include "check_bfd.h"
#endif
#ifdef _WITH_NFTABLES_
#include "logger.h"
#endif

/* Daemon dynamic data structure definition */
#define KEEPALIVED_DEFAULT_DELAY	(60 * TIMER_HZ)

#ifdef _WITH_NFTABLES_
/* Used for arrays of protocol entries */
typedef enum {
	TCP_INDEX,
	UDP_INDEX,
	SCTP_INDEX,
	PROTO_INDEX_MAX
} proto_index_t;
#endif

/* SSL specific data */
typedef struct _ssl_data {
	int				enable;
	int				strong_check;
	SSL_CTX				*ctx;
	const SSL_METHOD		*meth;
	const char			*password;
	const char			*cafile;
	const char			*certfile;
	const char			*keyfile;
} ssl_data_t;

/* Real Server definition */
typedef struct _real_server {
	struct sockaddr_storage		addr;
	int64_t				effective_weight;
	int64_t				peffective_weight; /* previous weight
							    * used for reloading */
	int				iweight;	/* Initial weight */
	unsigned			forwarding_method; /* NAT/TUN/DR */
#ifdef _HAVE_IPVS_TUN_TYPE_
	int				tun_type;	/* tunnel type */
	unsigned			tun_port;	/* tunnel port for gue tunnels */
#ifdef _HAVE_IPVS_TUN_CSUM_
	int				tun_flags;	/* tunnel checksum type for gue/gre tunnels */
#endif
#endif
#ifdef _WITH_SNMP_CHECKER_
	const char			*snmp_name;
#endif
	uint32_t			u_threshold;	/* Upper connection limit. */
	uint32_t			l_threshold;	/* Lower connection limit. */
	int				inhibit;	/* Set weight to 0 instead of removing
							 * the service from IPVS topology. */
	notify_script_t			*notify_up;	/* Script to launch when RS is added to LVS */
	notify_script_t			*notify_down;	/* Script to launch when RS is removed from LVS */
	int				alpha;		/* true if alpha mode is default. */
	unsigned int			connection_to;	/* connection time-out */
	unsigned long			delay_loop;	/* Interval between running checker */
	unsigned long			warmup;		/* max random timeout to start checker */
	unsigned			retry;		/* number of retries before failing */
	unsigned long			delay_before_retry; /* interval between retries */
	int				smtp_alert;	/* Send email on status change */

	bool				alive;
	unsigned			num_failed_checkers;/* Number of failed checkers */
	bool				set;		/* in the IPVS table */
	bool				reloaded;	/* active state was copied from old config while reloading */
	const char			*virtualhost;	/* Default virtualhost for HTTP and SSL health checkers */
#if defined(_WITH_SNMP_CHECKER_)
	/* Statistics */
	uint32_t			activeconns;	/* active connections */
	uint32_t			inactconns;	/* inactive connections */
	uint32_t			persistconns;	/* persistent connections */
#ifndef _WITH_LVS_64BIT_STATS_
	struct ip_vs_stats_user		stats;
#else
	struct ip_vs_stats64		stats;
#endif
#endif
	list_head_t			track_files;	/* tracked_file_monitor_t - Files whose value we monitor */
#ifdef _WITH_BFD_
	list_head_t			tracked_bfds;	/* cref_tracked_bfd_t */
#endif

	/* Linked list member */
	list_head_t			e_list;
} real_server_t;

/* Virtual Server group definition */
typedef struct _virtual_server_group_entry {
	bool				is_fwmark;
	union {
		struct {
			struct sockaddr_storage	addr;
			struct sockaddr_storage	addr_end;
			unsigned	tcp_alive;
			unsigned	udp_alive;
			unsigned	sctp_alive;
		};
		struct {
			uint32_t	vfwmark;
			uint16_t	fwm_family;
			unsigned	fwm4_alive;
			unsigned	fwm6_alive;
		};
	};
	bool				reloaded;

	/* Linked list member */
	list_head_t			e_list;
} virtual_server_group_entry_t;

typedef struct _virtual_server_group {
	char				*gname;
	list_head_t			addr_range;
	list_head_t			vfwmark;
	bool				have_ipv4;
	bool				have_ipv6;
	bool				fwmark_no_family;
#ifdef _WITH_NFTABLES_
	unsigned			auto_fwmark[PROTO_INDEX_MAX];
#endif

	/* Linked list member */
	list_head_t			e_list;
} virtual_server_group_t;

/* Virtual Server definition */
typedef struct _virtual_server {
	const char			*vsgname;
	virtual_server_group_t		*vsg;
	struct sockaddr_storage		addr;
	uint32_t			vfwmark;
	real_server_t			*s_svr;
	bool				s_svr_duplicates_rs;
	uint16_t			af;
	uint16_t			service_type;
	bool				ha_suspend;
	int				ha_suspend_addr_count;
	char				sched[IP_VS_SCHEDNAME_MAXLEN];
	uint32_t			flags;
	uint32_t			persistence_timeout;
	char				pe_name[IP_VS_PENAME_MAXLEN + 1];
	unsigned			forwarding_method;
#ifdef _HAVE_IPVS_TUN_TYPE_
	int				tun_type;	/* tunnel type */
	unsigned			tun_port;	/* tunnel port for gue tunnels */
#ifdef _HAVE_IPVS_TUN_CSUM_
	int				tun_flags;	/* tunnel checksum type for gue/gre tunnels */
#endif
#endif
#ifdef _WITH_SNMP_CHECKER_
	const char			*snmp_name;
#endif
	uint32_t			persistence_granularity;
	const char			*virtualhost;	/* Default virtualhost for HTTP and SSL healthcheckers
							   if not set on real servers */
	int				weight;
	list_head_t			rs;		/* real_server_t */
	unsigned			rs_cnt;		/* Number of real_server in list */
	int				alive;
	bool				alpha;		/* Set if alpha mode is default. */
	bool				omega;		/* Omega mode enabled. */
	bool				inhibit;	/* Set weight to 0 instead of removing
							 * the service from IPVS topology. */
	unsigned int			connection_to;	/* connection time-out */
	unsigned long			delay_loop;	/* Interval between running checker */
	unsigned long			warmup;		/* max random timeout to start checker */
	unsigned			retry;		/* number of retries before failing */
	unsigned long			delay_before_retry; /* interval between retries */
	notify_script_t			*notify_quorum_up;	/* A hook to call when the VS gains quorum. */
	notify_script_t			*notify_quorum_down;	/* A hook to call when the VS loses quorum. */
	unsigned			quorum;		/* Minimum live RSs to consider VS up. */
	unsigned			hysteresis;	/* up/down events "lag" WRT quorum. */
	int				smtp_alert;	/* Send email on status change */
	bool				quorum_state_up; /* Reflects result of the last transition done. */
	bool				reloaded;	/* quorum_state was copied from old config while reloading */
#if defined(_WITH_SNMP_CHECKER_)
	/* Statistics */
	time_t				lastupdated;
#ifndef _WITH_LVS_64BIT_STATS_
	struct ip_vs_stats_user		stats;
#else
	struct ip_vs_stats64		stats;
#endif
#endif
	/* Linked list member */
	list_head_t			e_list;
} virtual_server_t;

/* Configuration data root */
typedef struct _check_data {
	bool				ssl_required;
	ssl_data_t			*ssl;
	list_head_t			vs_group;	/* virtual_server_group_t */
	list_head_t			vs;		/* virtual_server_t */
	list_head_t			track_files;	/* tracked_file_t */
#ifdef _WITH_BFD_
	list_head_t			track_bfds;	/* checker_tracked_bfd_t */
#endif
	unsigned			num_checker_fd_required;
	unsigned			num_smtp_alert;
} check_data_t;

/* macro utility */
#define ISALIVE(S)		((S)->alive)
#define SET_ALIVE(S)		((S)->alive = true)
#define UNSET_ALIVE(S)		((S)->alive = false)
#define FMT_RS(R, V) (format_rs(R, V))
#define FMT_VS(V) (format_vs((V)))

#ifndef IP_VS_SVC_F_SCHED_MH_PORT
#define IP_VS_SVC_F_SCHED_MH_PORT IP_VS_SVC_F_SCHED_SH_PORT
#endif
#ifndef IP_VS_SVC_F_SCHED_MH_FALLBACK
#define IP_VS_SVC_F_SCHED_MH_FALLBACK IP_VS_SVC_F_SCHED_SH_FALLBACK
#endif

static inline int
real_weight(int64_t effective_weight)
{
	if (effective_weight < 0)
		return 0;
	if (effective_weight > IPVS_WEIGHT_LIMIT)
		return IPVS_WEIGHT_LIMIT;
	return effective_weight;
}

#ifdef _WITH_NFTABLES_
static inline proto_index_t
protocol_to_index(int proto)
{
	if (proto == IPPROTO_TCP)
		return TCP_INDEX;
	if (proto == IPPROTO_UDP)
		return UDP_INDEX;
	if (proto == IPPROTO_SCTP)
		return SCTP_INDEX;

	log_message(LOG_INFO, "Unknown protocol %d at %s:%d in %s", proto, __func__, __LINE__, __FILE__);

	return UDP_INDEX;
}
#endif

/* Global vars exported */
extern check_data_t *check_data;
extern check_data_t *old_check_data;

/* prototypes */
extern ssl_data_t *alloc_ssl(void) __attribute((malloc));
extern void free_ssl(void);
extern void alloc_vsg(const char *);
extern void free_vsg(virtual_server_group_t *);
extern void alloc_vsg_entry(const vector_t *);
extern void alloc_rs(const char *, const char *);
extern void free_rs(real_server_t *);
extern void alloc_vs(const char *, const char *);
extern void free_vs(virtual_server_t *);
extern void dump_tracking_rs(FILE *, const void *);
extern void alloc_ssvr(const char *, const char *);
#ifdef _WITH_BFD_
extern void free_checker_bfd(checker_tracked_bfd_t *);
#endif
extern check_data_t *alloc_check_data(void);
extern void free_check_data(check_data_t *);
extern void dump_data_check(FILE *);
extern const char *format_vs (const virtual_server_t *);
extern const char *format_vsge (const virtual_server_group_entry_t *);
extern const char *format_rs(const real_server_t *, const virtual_server_t *);
extern bool validate_check_config(void);

#endif
