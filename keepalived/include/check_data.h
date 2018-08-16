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

#ifdef _WITH_LVS_
  #include "ip_vs.h"
#endif

/* local includes */
#include "list.h"
#include "vector.h"
#include "notify.h"
#include "utils.h"

/* Daemon dynamic data structure definition */
#define KEEPALIVED_DEFAULT_DELAY	(60 * TIMER_HZ)

/* SSL specific data */
typedef struct _ssl_data {
	int				enable;
	int				strong_check;
	SSL_CTX				*ctx;
	const SSL_METHOD		*meth;
	char				*password;
	char				*cafile;
	char				*certfile;
	char				*keyfile;
} ssl_data_t;

/* Real Server definition */
typedef struct _real_server {
	struct sockaddr_storage		addr;
	int				weight;
	int				iweight;	/* Initial weight */
	int				pweight;	/* previous weight
							 * used for reloading */
	unsigned			forwarding_method; /* NAT/TUN/DR */
	uint32_t			u_threshold;   /* Upper connection limit. */
	uint32_t			l_threshold;   /* Lower connection limit. */
	int				inhibit;	/* Set weight to 0 instead of removing
							 * the service from IPVS topology.
							 */
	notify_script_t			*notify_up;	/* Script to launch when RS is added to LVS */
	notify_script_t			*notify_down;	/* Script to launch when RS is removed from LVS */
	int				alpha;		/* true if alpha mode is default. */
	unsigned long			delay_loop;	/* Interval between running checker */
	unsigned long			warmup;		/* max random timeout to start checker */
	unsigned			retry;		/* number of retries before failing */
	unsigned long			delay_before_retry; /* interval between retries */
	int				smtp_alert;	/* Send email on status change */

	bool				alive;
	unsigned			num_failed_checkers;/* Number of failed checkers */
	bool				set;		/* in the IPVS table */
	bool				reloaded;	/* active state was copied from old config while reloading */
	char				*virtualhost;	/* Default virtualhost for HTTP and SSL health checkers */
#if defined(_WITH_SNMP_CHECKER_) && defined(_WITH_LVS_)
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
#ifdef _WITH_BFD_
	list				tracked_bfds;	/* list of bfd_checker_t */
#endif
} real_server_t;

/* Virtual Server group definition */
typedef struct _virtual_server_group_entry {
	bool 				is_fwmark;
	union {
		struct {
			struct sockaddr_storage	addr;
			uint32_t	range;
			unsigned	tcp_alive;
			unsigned	udp_alive;
			unsigned	sctp_alive;
		};
		struct {
			uint32_t	vfwmark;
			unsigned	fwm4_alive;
			unsigned	fwm6_alive;
		};
	};
	bool				reloaded;
} virtual_server_group_entry_t;

typedef struct _virtual_server_group {
	char				*gname;
	list				addr_range;
	list				vfwmark;
} virtual_server_group_t;

/* Virtual Server definition */
typedef struct _virtual_server {
	char				*vsgname;
	virtual_server_group_t		*vsg;
	struct sockaddr_storage		addr;
	uint32_t			vfwmark;
	real_server_t			*s_svr;
	uint16_t			af;
	uint16_t			service_type;
	bool				ha_suspend;
	int				ha_suspend_addr_count;
#ifdef _WITH_LVS_
	char				sched[IP_VS_SCHEDNAME_MAXLEN];
	uint32_t			flags;
	uint32_t			persistence_timeout;
#ifdef _HAVE_PE_NAME_
	char				pe_name[IP_VS_PENAME_MAXLEN];
#endif
	unsigned			forwarding_method;
	uint32_t			persistence_granularity;
#endif
	char				*virtualhost;	/* Default virtualhost for HTTP and SSL healthcheckers
							   if not set on real servers */
	int				weight;
	list				rs;
	int				alive;
	bool				alpha;		/* Set if alpha mode is default. */
	bool				omega;		/* Omega mode enabled. */
	bool				inhibit;	/* Set weight to 0 instead of removing
							 * the service from IPVS topology. */
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
#if defined(_WITH_SNMP_CHECKER_) && defined(_WITH_LVS_)
	/* Statistics */
	time_t				lastupdated;
#ifndef _WITH_LVS_64BIT_STATS_
	struct ip_vs_stats_user		stats;
#else
	struct ip_vs_stats64		stats;
#endif
#endif
} virtual_server_t;

/* Configuration data root */
typedef struct _check_data {
	bool				ssl_required;
	ssl_data_t			*ssl;
	list				vs_group;
	list				vs;
#ifdef _WITH_BFD_
	list				track_bfds;	/* list of checker_tracked_bfd_t */
#endif
} check_data_t;

/* macro utility */
#define ISALIVE(S)		((S)->alive)
#define SET_ALIVE(S)		((S)->alive = true)
#define UNSET_ALIVE(S)		((S)->alive = false)
#define FMT_RS(R, V) (inet_sockaddrtotrio (&(R)->addr, (V)->service_type))
#define FMT_VS(V) (format_vs((V)))

#define VS_SCRIPT_ISEQ(XS,YS) \
	(!(XS) == !(YS) && \
	 (!(XS) || \
	  (!notify_script_compare((XS), (YS)) && \
	   (XS)->uid == (YS)->uid && \
	   (XS)->gid == (YS)->gid)))

#define VS_ISEQ(X,Y)	(sockstorage_equal(&(X)->addr,&(Y)->addr)			&&\
			 (X)->vfwmark		      == (Y)->vfwmark			&&\
			 (X)->af		      == (Y)->af			&&\
			 (X)->service_type	      == (Y)->service_type		&&\
			 (X)->forwarding_method       == (Y)->forwarding_method		&&\
			 (X)->persistence_granularity == (Y)->persistence_granularity	&&\
			 VS_SCRIPT_ISEQ((X)->notify_quorum_up, (Y)->notify_quorum_up)	&& \
			 VS_SCRIPT_ISEQ((X)->notify_quorum_down, (Y)->notify_quorum_down) && \
			 !strcmp((X)->sched, (Y)->sched)				&&\
			 (X)->persistence_timeout     == (Y)->persistence_timeout	&&\
			 !(X)->vsgname		      == !(Y)->vsgname			&& \
			 (!(X)->vsgname || !strcmp((X)->vsgname, (Y)->vsgname))		&& \
			 !(X)->virtualhost	      == !(Y)->virtualhost		&& \
			 (!(X)->virtualhost || !strcmp((X)->virtualhost, (Y)->virtualhost)))

#define VSGE_ISEQ(X,Y)	(sockstorage_equal(&(X)->addr,&(Y)->addr) &&	\
			 (X)->range     == (Y)->range &&		\
			 (X)->vfwmark   == (Y)->vfwmark)

#define RS_ISEQ(X,Y)	(sockstorage_equal(&(X)->addr,&(Y)->addr)			&& \
			 (X)->forwarding_method       == (Y)->forwarding_method		&& \
			 !(X)->virtualhost	      == !(Y)->virtualhost		&& \
			 (!(X)->virtualhost || !strcmp((X)->virtualhost, (Y)->virtualhost)))

#ifndef IP_VS_SVC_F_SCHED_MH_PORT
#define IP_VS_SVC_F_SCHED_MH_PORT IP_VS_SVC_F_SCHED_SH_PORT
#endif
#ifndef IP_VS_SVC_F_SCHED_MH_FALLBACK
#define IP_VS_SVC_F_SCHED_MH_FALLBACK IP_VS_SVC_F_SCHED_SH_FALLBACK
#endif

/* Global vars exported */
extern check_data_t *check_data;
extern check_data_t *old_check_data;

/* prototypes */
extern ssl_data_t *alloc_ssl(void);
extern void free_ssl(void);
extern void alloc_vsg(char *);
extern void alloc_vsg_entry(vector_t *);
extern void alloc_vs(char *, char *);
extern void alloc_rs(char *, char *);
extern void alloc_ssvr(char *, char *);
extern check_data_t *alloc_check_data(void);
extern void free_check_data(check_data_t *);
extern void dump_check_data(FILE *, check_data_t *);
extern char *format_vs (virtual_server_t *);
extern bool validate_check_config(void);

#endif
