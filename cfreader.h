/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        cfreader.c include file.
 *  
 * Version:     $Id: cfreader.h,v 0.4.0 2001/08/24 00:35:19 acassen Exp $
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


#ifndef _CFREADER_H
#define _CFREADER_H

/* system includes */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>
#include <arpa/inet.h>

#include <linux/ip_masq.h>

/* local includes */
#include "utils.h"
#include "vrrp.h"

#define CONFFILE "/etc/keepalived/keepalived.conf"

#define TEMP_BUFFER_LENGTH 100
#define MAX_EMAIL_LENGTH   45
#define MAX_LVSID_LENGTH   20
#define MAX_URL_LENGTH     110
#define DIGEST_LENGTH      32+1
#define MAX_TIMEOUT_LENGTH 5
#define MAX_INT_LENGTH     10

/* Keywords definition */
struct keyword {
  int key;
  char *word;
};

/* configuration file keyword definition */
#define KW_GLOBALDEFS	0
#define KW_VS		1
#define KW_SVR		2
#define KW_SSVR		3
#define KW_BEGINFLAG	4
#define KW_ENDFLAG	5
#define KW_DELAY	6
#define KW_EMAIL	7
#define KW_EMAILFROM	8
#define KW_LVSID	9
#define KW_SMTP		10
#define KW_STIMEOUT	11
#define KW_LBSCHED	12
#define KW_LBKIND	13
#define KW_NATMASK	14
#define KW_PTIMEOUT	15
#define KW_PROTOCOL	16
#define KW_WEIGHT	17
#define KW_URL		18
#define KW_URLPATH	19
#define KW_DIGEST	20
#define KW_CTIMEOUT	21
#define KW_NBGETRETRY	22
#define KW_DELAYRETRY	23

#define KW_ICMPCHECK	24
#define KW_TCPCHECK	25
#define KW_HTTPGET	26
#define KW_SSLGET	27
#define KW_LDAPGET	28

#define KW_VRRP		29
#define KW_VRRPINT	30
#define KW_VRRPVRID	31
#define KW_VRRPAUTH	32
#define KW_VRRPAUTHTYPE	33
#define KW_VRRPAUTHAH	34
#define KW_VRRPAUTHPWD	35
#define KW_VRRPAUTHPASS	36
#define KW_VRRPPRIO	37
#define KW_VRRPADVERT	38
#define KW_VRRPIPADD	39
#define KW_VRRPSYNC	40
#define KW_VRRPPREEMPT	41

#define KW_UNKNOWN	42

/* Structure definition  */
typedef struct _urls {
  char url[MAX_URL_LENGTH];
  char digest[DIGEST_LENGTH];

  struct urls *next;
} urls;

typedef struct _http_get_check {
  int nb_get_retry;
  int delay_before_retry;
  urls *check_urls;
} http_get_check;

typedef struct _keepalive_check {
  int type;
#define ICMP_CHECK_ID  (1 << 0)
#define TCP_CHECK_ID   (1 << 1)
#define HTTP_GET_ID    (1 << 2)
#define SSL_GET_ID     (1 << 3)
#define LDAP_GET_ID    (1 << 4)
  int connection_to;
  http_get_check *http_get;    /* FIXME : for new checker use union here */
} keepalive_check;

typedef struct _real_server {
  struct in_addr addr_ip;
  uint16_t addr_port;
  int weight;
  keepalive_check *method;
  int alive;

  struct realserver *next;
} realserver;

typedef struct _virtual_server {
  struct in_addr addr_ip;
  uint16_t addr_port;
  uint16_t service_type;
  int delay_loop;
  char sched[IP_MASQ_TNAME_MAX];
  unsigned loadbalancing_kind;
  struct in_addr nat_mask;
  char timeout_persistence[MAX_TIMEOUT_LENGTH];
  realserver *s_svr;
  realserver *svr;

  struct virtualserver *next;
} virtualserver;

typedef struct _vrrp_instance {
  char iname[MAX_INT_LENGTH];	/* Instance Name */
  char isync[MAX_INT_LENGTH];	/* Instance Name to synchronize with */
  vrrp_rt *vsrv;		/* VRRP data */

  struct vrrp_instance *next;
} vrrp_instance;

typedef struct _notification_email {
  char addr[MAX_EMAIL_LENGTH];

  struct notification_email *next;
} notification_email;

typedef struct _configuration_data {
  char lvs_id[MAX_LVSID_LENGTH];
  char email_from[MAX_EMAIL_LENGTH];
  struct in_addr smtp_server;
  int smtp_connection_to;
  notification_email *email;
  vrrp_instance *vrrp;

  virtualserver *lvstopology;
} configuration_data;

/* prototypes */
extern configuration_data * conf_reader();
extern void clear_conf(configuration_data * lstptr);
extern void clear_vrrp_instance(vrrp_instance *lstptr);
extern void dump_conf(configuration_data * lstptr);

#endif
