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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _CHECK_DATA_H
#define _CHECK_DATA_H

/* system includes */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#ifdef _WITH_LVS_
  #ifdef _KRNL_2_4_
    #include <net/ip_vs.h>
  #elif _KRNL_2_6_
    #include "../libipvs-2.6/ip_vs.h"
  #endif
  #define SCHED_MAX_LENGTH IP_VS_SCHEDNAME_MAXLEN
#else
  #define SCHED_MAX_LENGTH   1
#endif

/* local includes */
#include "list.h"
#include "vector.h"
#include "timer.h"

/* Typedefs */
typedef unsigned int checker_id_t;

/* Daemon dynamic data structure definition */
#define MAX_TIMEOUT_LENGTH		5
#define KEEPALIVED_DEFAULT_DELAY	(60 * TIMER_HZ) 

/* SSL specific data */
typedef struct _ssl_data {
	int				enable;
	int				strong_check;
	SSL_CTX				*ctx;
	SSL_METHOD			*meth;
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
	int 				pweight;	/* previous weight
							 * used for reloading */
#ifdef _KRNL_2_6_
	uint32_t			u_threshold;   /* Upper connection limit. */
	uint32_t			l_threshold;   /* Lower connection limit. */
#endif
	int				inhibit;	/* Set weight to 0 instead of removing
							 * the service from IPVS topology.
							 */
	char				*notify_up;	/* Script to launch when RS is added to LVS */
	char				*notify_down;	/* Script to launch when RS is removed from LVS */
	int				alive;
	list				failed_checkers;/* List of failed checkers */
	int				set;		/* in the IPVS table */
	int				reloaded;	/* active state was copied from old config while reloading */
#if defined(_WITH_SNMP_) && defined(_KRNL_2_6_) && defined(_WITH_LVS_)
	/* Statistics */
	uint32_t			activeconns;	/* active connections */
	uint32_t			inactconns;	/* inactive connections */
	uint32_t			persistconns;	/* persistent connections */
	struct ip_vs_stats_user		stats;
#endif
} real_server_t;

/* Virtual Server group definition */
typedef struct _virtual_server_group_entry {
	struct sockaddr_storage		addr;
	uint8_t				range;
	uint32_t			vfwmark;
	int				alive;
	int				reloaded;
} virtual_server_group_entry_t;

typedef struct _virtual_server_group {
	char				*gname;
	list				addr_ip;
	list				range;
	list				vfwmark;
} virtual_server_group_t;

/* Virtual Server definition */
typedef struct _virtual_server {
	char				*vsgname;
	virtual_server_group_t		*vsg;
	struct sockaddr_storage		addr;
	real_server_t			*s_svr;
	uint32_t			vfwmark;
	uint16_t			af;
	uint16_t			service_type;
	long				delay_loop;
	int				ha_suspend;
	int				ops;
	char				sched[SCHED_MAX_LENGTH];
	char				timeout_persistence[MAX_TIMEOUT_LENGTH];
	unsigned			loadbalancing_kind;
	uint32_t			nat_mask;
	uint32_t			granularity_persistence;
	char				*virtualhost;
	list				rs;
	int				alive;
	unsigned			alpha;		/* Alpha mode enabled. */
	unsigned			omega;		/* Omega mode enabled. */
	char				*quorum_up;	/* A hook to call when the VS gains quorum. */
	char				*quorum_down;	/* A hook to call when the VS loses quorum. */
	long unsigned			quorum;		/* Minimum live RSs to consider VS up. */

	long unsigned			hysteresis;	/* up/down events "lag" WRT quorum. */
	unsigned			quorum_state;	/* Reflects result of the last transition done. */
	int				reloaded;	/* quorum_state was copied from old config while reloading */
#if defined(_WITH_SNMP_) && defined(_KRNL_2_6_) && defined(_WITH_LVS_)
	/* Statistics */
	time_t				lastupdated;
	struct ip_vs_stats_user		stats;
#endif
} virtual_server_t;

/* Configuration data root */
typedef struct _check_data {
	ssl_data_t			*ssl;
	list				vs_group;
	list				vs;
} check_data_t;

/* inline stuff */
static inline int __ip6_addr_equal(const struct in6_addr *a1,
				   const struct in6_addr *a2)
{
	return (((a1->s6_addr32[0] ^ a2->s6_addr32[0]) |
		 (a1->s6_addr32[1] ^ a2->s6_addr32[1]) |
		 (a1->s6_addr32[2] ^ a2->s6_addr32[2]) |
		 (a1->s6_addr32[3] ^ a2->s6_addr32[3])) == 0);
}

static inline int sockstorage_equal(const struct sockaddr_storage *s1,
				    const struct sockaddr_storage *s2)
{
	if (s1->ss_family != s2->ss_family)
		return 0;

	if (s1->ss_family == AF_INET6) {
		struct sockaddr_in6 *a1 = (struct sockaddr_in6 *) s1;
		struct sockaddr_in6 *a2 = (struct sockaddr_in6 *) s2;

//		if (IN6_ARE_ADDR_EQUAL(a1, a2) && (a1->sin6_port == a2->sin6_port))
		if (__ip6_addr_equal(&a1->sin6_addr, &a2->sin6_addr) &&
		    (a1->sin6_port == a2->sin6_port))
			return 1;
	} else if (s1->ss_family == AF_INET) {
		struct sockaddr_in *a1 = (struct sockaddr_in *) s1;
		struct sockaddr_in *a2 = (struct sockaddr_in *) s2;

		if ((a1->sin_addr.s_addr == a2->sin_addr.s_addr) &&
		    (a1->sin_port == a2->sin_port))
			return 1;
	} else if (s1->ss_family == AF_UNSPEC)
		return 1;

	return 0;
}

static inline int inaddr_equal(sa_family_t family, void *addr1, void *addr2)
{
	if (family == AF_INET6) {
		struct in6_addr *a1 = (struct in6_addr *) addr1;
		struct in6_addr *a2 = (struct in6_addr *) addr2;

		if (__ip6_addr_equal(a1, a2))
			return 1;
	} else if (family == AF_INET) {
		struct in_addr *a1 = (struct in_addr *) addr1;
		struct in_addr *a2 = (struct in_addr *) addr2;

		if (a1->s_addr == a2->s_addr)
			return 1;
	}

	return 0;
}

/* macro utility */
#define ISALIVE(S)	((S)->alive)
#define SET_ALIVE(S)	((S)->alive = 1)
#define UNSET_ALIVE(S)	((S)->alive = 0)
#define VHOST(V)	((V)->virtualhost)
#define FMT_RS(R) (inet_sockaddrtopair (&(R)->addr))
#define FMT_VS(V) (format_vs((V)))

#define VS_ISEQ(X,Y)	(sockstorage_equal(&(X)->addr,&(Y)->addr)			&&\
			 (X)->vfwmark                 == (Y)->vfwmark			&&\
			 (X)->af                      == (Y)->af                        &&\
			 (X)->service_type            == (Y)->service_type		&&\
			 (X)->loadbalancing_kind      == (Y)->loadbalancing_kind	&&\
			 (X)->nat_mask                == (Y)->nat_mask			&&\
			 (X)->granularity_persistence == (Y)->granularity_persistence	&&\
			 (  (!(X)->quorum_up && !(Y)->quorum_up) || \
			    ((X)->quorum_up && (Y)->quorum_up && !strcmp ((X)->quorum_up, (Y)->quorum_up)) \
			 ) &&\
			 !strcmp((X)->sched, (Y)->sched)				&&\
			 !strcmp((X)->timeout_persistence, (Y)->timeout_persistence)	&&\
			 (((X)->vsgname && (Y)->vsgname &&				\
			   !strcmp((X)->vsgname, (Y)->vsgname)) || 			\
			  (!(X)->vsgname && !(Y)->vsgname)))

#define VSGE_ISEQ(X,Y)	(sockstorage_equal(&(X)->addr,&(Y)->addr) &&	\
			 (X)->range     == (Y)->range &&		\
			 (X)->vfwmark   == (Y)->vfwmark)

#define RS_ISEQ(X,Y)	(sockstorage_equal(&(X)->addr,&(Y)->addr))

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
extern void alloc_group(char *);
extern void alloc_rsgroup(char *, char *);
extern void set_rsgroup(char *);
extern check_data_t *alloc_check_data(void);
extern void free_check_data(check_data_t *);
extern void dump_check_data(check_data_t *);
extern char *format_vs (virtual_server_t *);

#endif
