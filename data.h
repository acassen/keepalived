/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Dynamic data structure definition.
 *
 * Version:     $Id: data.h,v 0.5.7 2002/05/02 22:18:07 acassen Exp $
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

#ifdef _KRNL_2_2_
  #include <linux/ip_masq.h>
  #include <net/ip_masq.h>
  #define SCHED_MAX_LENGTH IP_MASQ_TNAME_MAX
#else
  #define SCHED_MAX_LENGTH IP_VS_SCHEDNAME_MAXLEN
#endif
#include <net/ip_vs.h>

/* local includes */
#include "list.h"

/* Daemon dynamic data structure definition */
#define MAX_TIMEOUT_LENGTH	5
#define KEEPALIVED_DEFAULT_DELAY 60

/* SSL specific data */
typedef struct _ssl_data SSL_DATA;
typedef struct _ssl_data {
  int		enable;
  int		strong_check;
  SSL_CTX	*ctx;
  SSL_METHOD	*meth;
  char		*password;
  char		*cafile;
  char		*certfile;
  char		*keyfile;
} ssl_data;

/* Real Server definition */
typedef struct _real_server {
  uint32_t	addr_ip;
  uint16_t	addr_port;
  int		weight;
  int		alive;
} real_server;

/* Virtual Server definition */
typedef struct _virtual_server {
  uint32_t		addr_ip;
  uint32_t		vfwmark;
  uint16_t		addr_port;
  uint16_t		service_type;
  int			delay_loop;
  char			sched[SCHED_MAX_LENGTH];
  unsigned		loadbalancing_kind;
  uint32_t		nat_mask;
  char			timeout_persistence[MAX_TIMEOUT_LENGTH];
  uint32_t		granularity_persistence;
  real_server		*s_svr;
  list			rs;
} virtual_server;

/* email link list */
typedef struct _email {
  char *addr;
} email;

/* Configuration data root */
typedef struct _data {
  char		*lvs_id;
  char		*email_from;
  uint32_t	smtp_server;
  int		smtp_connection_to;
  SSL_DATA	*ssl;
  list		email;
  list		vrrp;
  list		vs;
} data;

/* macro utility */
#define ISALIVE(R)   ((R)->alive)
#define SVR_IP(H)    ((H)->addr_ip)
#define SVR_PORT(H)  ((H)->addr_port)

/* prototypes */
extern void alloc_email(char *addr);
extern SSL_DATA *alloc_ssl(void);
extern void alloc_vrrp(char *iname);
extern void alloc_vrrp_vip(char *vip);
extern void alloc_vs(char *ip, char *port);
extern void alloc_rs(char *ip, char *port);
extern void alloc_ssvr(char *ip, char *port);

extern data *alloc_data(void);
extern void free_data(void);
extern void dump_data(void);

#endif
