/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        cfreader.c include file.
 *  
 * Version:     $Id: cfreader.h,v 0.2.6 2001/03/01 $
 * 
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *              
 * Changes:     
 *              Alexandre Cassen : 2001/03/01 :
 *               <+> Adding keywords.
 *               <+> Change change the whole data structure.
 *               <+> Adding LVS ID & notification email for alertes.
 *
 *              Alexandre Cassen : Initial release : 2000/12/09
 *              
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#ifndef CFREADER_H
#define CFREADER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFFILE "keepalived.conf"

#define TEMPBUFFERLENGTH 100

/* Keywords definition */
#define GLOBALDEFS   "global_defs"
#define VS           "virtual_server"
#define SVR          "real_server"
#define BEGINFLAG    "{"
#define ENDFLAG      "}"
#define DELAY        "delay_loop"
#define EMAIL        "notification_email"
#define EMAILFROM    "notification_email_from"
#define LVSID        "lvs_id"
#define SMTP         "smtp_server"
#define LBSCHED      "lb_algo"
#define LBKIND       "lb_kind"
#define PTIMEOUT     "persistence_timeout"
#define PROTOCOL     "protocol"
#define WEIGHT       "weight"
#define URL          "url"
#define URLPATH      "path"
#define DIGEST       "digest"
#define CTIMEOUT     "connect_timeout"
#define NBGETRETRY   "nb_get_retry"
#define DELAYRETRY   "delay_before_retry"

#define ICMPCHECK    "ICMP_CHECK"
#define TCPCHECK     "TCP_CHECK"
#define HTTPGET      "HTTP_GET"
#define SSLGET       "SSL_GET"

/* Check method id */
#define ICMP_CHECK_ID  0x001
#define TCP_CHECK_ID   0x002
#define HTTP_GET_ID    0x003
#define SSL_GET_ID     0x004

/* Structure definition  */
typedef struct _tcp_vanilla_check {
  char connection_to[4+1];
} tcp_vanilla_check;

typedef struct _urls {
  char url[100+1];
  char digest[32+1];

  struct urls *next;
} urls;

typedef struct _http_get_check {
  char connection_to[4+1];
  char nb_get_retry[1+1];
  char delay_before_retry[4+1];
  urls *check_urls;
} http_get_check;

typedef struct _keepalive_check {
  int flag_type;
  http_get_check *http_get;
  tcp_vanilla_check *tcp_vanilla;
} keepalive_check;

typedef struct _real_server {
  char addr_ip[15+1];
  char addr_port[5+1];
  char weight[3+1];
  keepalive_check *method;
  int alive;

  struct realserver *next;
} realserver;

typedef struct _virtual_server {
  char addr_ip[15+1];
  char addr_port[5+1];
  char sched[5+1];
  char loadbalancing_kind[5+1];
  char timeout_persistence[4];
  char service_type[3+1];
  realserver *svr;

  struct virtualserver *next;
} virtualserver;

typedef struct _notification_email {
  char addr[40+1];

  struct notification_email *next;
} notification_email;

typedef struct _configuration_data {
  char delay_loop[4+1];
  char email_from[40+1];
  char smtp_server[15+1];
  char lvs_id[20+1];
  notification_email *email;

  virtualserver *lvstopology;
} configuration_data;

#endif
