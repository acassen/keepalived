/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Dynamic data structure definition.
 *
 * Version:     $Id: data.h,v 0.7.1 2002/09/17 22:03:31 acassen Exp $
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
	int alive;
} real_server;

/* Real server group list */
typedef struct _real_server_group {
	char *gname;
	list rs;
//  list vs;
} real_server_group;

/* Virtual Server definition */
typedef struct _virtual_server {
	uint32_t addr_ip;
	uint32_t vfwmark;
	uint16_t addr_port;
	uint16_t service_type;
	int delay_loop;
	char sched[SCHED_MAX_LENGTH];
	char timeout_persistence[MAX_TIMEOUT_LENGTH];
	unsigned loadbalancing_kind;
	uint32_t nat_mask;
	uint32_t granularity_persistence;
	char *virtualhost;
	real_server *s_svr;
	list rs;
	list rs_group;
	int last_rs_type;
#define RS		(1 << 0)
#define RS_GROUP	(1 << 1)
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
	list vrrp;
	list vrrp_sync_group;
	list vs;
	list group;
} data;

/* macro utility */
#define ISALIVE(S)	((S)->alive)
#define SET_ALIVE(S)	((S)->alive = 1)
#define UNSET_ALIVE(S)	((S)->alive = 0)
#define SVR_IP(H)	((H)->addr_ip)
#define SVR_PORT(H)	((H)->addr_port)
#define VHOST(V)	((V)->virtualhost)
#define LAST_RS_TYPE(V)	((V)->last_rs_type)

/* prototypes */
extern void alloc_email(char *addr);
extern SSL_DATA *alloc_ssl(void);
extern void free_ssl(void);
extern void alloc_vrrp_sync_group(char *gname);
extern void alloc_vrrp(char *iname);
extern void alloc_vrrp_vip(char *vip);
extern void alloc_vrrp_evip(char *vip);
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
