/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Dynamic data structure definition.
 *
 * Version:     $Id: data.h,v 1.0.2 2003/04/14 02:35:12 acassen Exp $
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
 */

#ifndef _DATA_H
#define _DATA_H

/* system includes */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#ifdef _WITH_LVS_
#ifdef _KRNL_2_2_
#include <linux/ip_masq.h>
#include <net/ip_masq.h>
#define SCHED_MAX_LENGTH IP_MASQ_TNAME_MAX
#else
#define SCHED_MAX_LENGTH IP_VS_SCHEDNAME_MAXLEN
#endif
#include <net/ip_vs.h>
#else
#define SCHED_MAX_LENGTH   1
#endif

/* local includes */
#include "list.h"
#include "vector.h"

/* Daemon dynamic data structure definition */
#define MAX_TIMEOUT_LENGTH	5
#define KEEPALIVED_DEFAULT_DELAY 60

/* SSL specific data */
typedef struct _ssl_data SSL_DATA;
typedef struct _ssl_data {
	int enable;
	int strong_check;
	SSL_CTX *ctx;
	SSL_METHOD *meth;
	char *password;
	char *cafile;
	char *certfile;
	char *keyfile;
} ssl_data;

/* Real Server definition */
typedef struct _real_server {
	uint32_t addr_ip;
	uint16_t addr_port;
	int weight;
	int inhibit;		/* Set weight to 0 instead of removing
				 * the service from IPVS topology.
				 */
	char *notify_up;	/* Script to launch when RS is added to LVS */
	char *notify_down;	/* Script to launch when RS is removed from LVS */
	int alive;
} real_server;

/* Virtual Server group definition */
typedef struct _virtual_server_group_entry {
	uint32_t addr_ip;
	uint8_t range;
	uint32_t vfwmark;
	uint16_t addr_port;
	int alive;
	int rsalive;
} virtual_server_group_entry;

typedef struct _virtual_server_group {
	char *gname;
	list addr_ip;
	list range;
	list vfwmark;
} virtual_server_group;

/* Virtual Server definition */
typedef struct _virtual_server {
	char *vsgname;
	uint32_t addr_ip;
	uint16_t addr_port;
	uint32_t vfwmark;
	uint16_t service_type;
	int delay_loop;
	int ha_suspend;
	char sched[SCHED_MAX_LENGTH];
	char timeout_persistence[MAX_TIMEOUT_LENGTH];
	unsigned loadbalancing_kind;
	uint32_t nat_mask;
	uint32_t granularity_persistence;
	char *virtualhost;
	real_server *s_svr;
	list rs;
	int alive;
} virtual_server;

/* email link list */
typedef struct _email {
	char *addr;
} email;

/* Configuration data root */
typedef struct _data {
	char *lvs_id;
	char *email_from;
	uint32_t smtp_server;
	int smtp_connection_to;
	SSL_DATA *ssl;
	list email;
	list static_routes;
	list vrrp_sync_group;
	list vrrp;
	list vs_group;
	list vs;
} data;

/* macro utility */
#define ISALIVE(S)	((S)->alive)
#define SET_ALIVE(S)	((S)->alive = 1)
#define UNSET_ALIVE(S)	((S)->alive = 0)
#define SET_RSALIVE(S)	((S)->rsalive = 1)
#define UNSET_RSALIVE(S)((S)->rsalive = 0)
#define SVR_IP(H)	((H)->addr_ip)
#define SVR_PORT(H)	((H)->addr_port)
#define VHOST(V)	((V)->virtualhost)

#define VS_ISEQ(X,Y)	((X)->addr_ip                 == (Y)->addr_ip &&		\
			 (X)->addr_port               == (Y)->addr_port &&		\
			 (X)->vfwmark                 == (Y)->vfwmark &&		\
			 (X)->service_type            == (Y)->service_type &&		\
			 (X)->loadbalancing_kind      == (Y)->loadbalancing_kind &&	\
			 (X)->nat_mask                == (Y)->nat_mask &&		\
			 (X)->granularity_persistence == (Y)->granularity_persistence &&\
			 !strcmp((X)->sched, (Y)->sched) &&				\
			 !strcmp((X)->timeout_persistence, (Y)->timeout_persistence) &&	\
			 !strcmp((X)->vsgname, (Y)->vsgname))

#define VSGE_ISEQ(X,Y)	((X)->addr_ip   == (Y)->addr_ip &&	\
			 (X)->range     == (Y)->range &&	\
			 (X)->vfwmark   == (Y)->vfwmark &&	\
			 (X)->addr_port == (Y)->addr_port)

#define RS_ISEQ(X,Y)	((X)->addr_ip   == (Y)->addr_ip &&	\
			 (X)->addr_port == (Y)->addr_port &&	\
			 (X)->weight    == (Y)->weight)

/* prototypes */
extern void alloc_email(char *addr);
extern SSL_DATA *alloc_ssl(void);
extern void free_ssl(void);
extern void alloc_sroute(vector strvec);
extern void alloc_vrrp_sync_group(char *gname);
extern void alloc_vrrp(char *iname);
extern void alloc_vrrp_vip(vector strvec);
extern void alloc_vrrp_evip(vector strvec);
extern void alloc_vrrp_vroute(vector strvec);
extern void alloc_vsg(char *gname);
extern void alloc_vsg_entry(vector strvec);
extern void alloc_vs(char *ip, char *port);
extern void alloc_rs(char *ip, char *port);
extern void alloc_ssvr(char *ip, char *port);
extern void alloc_group(char *name);
extern void alloc_rsgroup(char *ip, char *port);
extern void set_rsgroup(char *gname);

extern data *alloc_data(void);
extern void free_data(data * data);
extern void dump_data(data * data);

#endif
