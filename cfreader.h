/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        cfreader.c include file.
 *  
 * Version:     $Id: cfreader.h,v 0.3.7 2001/09/14 00:37:56 acassen Exp $
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

#ifdef KERNEL_2_2
  #include <linux/ip_masq.h>
#else
  #include <net/ip_vs.h>
#endif

/* local includes */
#include "utils.h"

#define CONFFILE "/etc/keepalived/keepalived.conf"

/* locals defines */
#define TEMP_BUFFER_LENGTH 100
#define MAX_EMAIL_LENGTH   45
#define MAX_LVSID_LENGTH   20
#define MAX_URL_LENGTH     110
#define DIGEST_LENGTH      32+1
#define MAX_TIMEOUT_LENGTH 5

#ifdef KERNEL_2_2
  #define SCHED_MAX_LENGTH IP_MASQ_TNAME_MAX
#else
  #define SCHED_MAX_LENGTH IP_VS_SCHEDNAME_MAXLEN
#endif

/* Keywords definition */
struct keyword {
  int key;
  char *word;
};

/* configuration file keyword definition */
#define KW_GLOBALDEFS  (1 << 0)
#define KW_VS          (1 << 1)
#define KW_SVR         (1 << 2)
#define KW_SSVR        (1 << 3)
#define KW_BEGINFLAG   (1 << 4)
#define KW_ENDFLAG     (1 << 5)
#define KW_DELAY       (1 << 6)
#define KW_EMAIL       (1 << 7)
#define KW_EMAILFROM   (1 << 8)
#define KW_LVSID       (1 << 9)
#define KW_SMTP        (1 << 10)
#define KW_STIMEOUT    (1 << 11)
#define KW_LBSCHED     (1 << 12)
#define KW_LBKIND      (1 << 13)
#define KW_NATMASK     (1 << 14)
#define KW_PTIMEOUT    (1 << 15)
#define KW_PROTOCOL    (1 << 16)
#define KW_WEIGHT      (1 << 17)
#define KW_URL         (1 << 18)
#define KW_URLPATH     (1 << 19)
#define KW_DIGEST      (1 << 20)
#define KW_CTIMEOUT    (1 << 21)
#define KW_NBGETRETRY  (1 << 22)
#define KW_DELAYRETRY  (1 << 23)

#define KW_ICMPCHECK   (1 << 24)
#define KW_TCPCHECK    (1 << 25)
#define KW_HTTPGET     (1 << 26)
#define KW_SSLGET      (1 << 27)
#define KW_LDAPGET     (1 << 28)
#define KW_MISCCHECK   (1 << 29)
#define KW_MISCPATH    (1 << 30)

#define KW_UNKNOWN     (1 << 31)

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
#define MISC_CHECK_ID  (1 << 5)
  int connection_to;
  http_get_check *http_get;    /* FIXME : for new checker use union here */
  char *misc_check_path;
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
  char sched[SCHED_MAX_LENGTH];
  unsigned loadbalancing_kind;
  struct in_addr nat_mask;
  char timeout_persistence[MAX_TIMEOUT_LENGTH];
  realserver *s_svr;
  realserver *svr;

  struct virtualserver *next;
} virtualserver;

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

  virtualserver *lvstopology;
} configuration_data;

/* prototypes */
extern configuration_data * conf_reader();
extern void clear_conf(configuration_data * lstptr);
extern void dump_conf(configuration_data * lstptr);

#endif
