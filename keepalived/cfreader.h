/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        cfreader.c include file.
 *  
 * Version:     $Id: keepalived.c,v 0.2.1 2000/12/09 $
 * 
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *              
 * Changes:     
 *              Alexandre Cassen      :       Initial release
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

#define DELAYWORD    "delay_loop"
#define VSWORD       "virtual_server"
#define SVRWORD      "real_server"
#define BEGINFLAG    "{"
#define ENDFLAG      "}"

/* Structure definition  */
typedef struct _real_server {
  char addr_ip[15+1];
  char addr_port[5+1];
  char keepalive_method[11+1];
  char keepalive_url[100+1];
  char keepalive_algo[10+1];
  char keepalive_result[32+1];
  char loadbalancing_kind[5+1];
  char weight[3+1];
  char service_type[3+1];
  int alive;

  struct realserver *next;
} realserver;

typedef struct _virtual_server {
  char addr_ip[15+1];
  char addr_port[5+1];
  char sched[5+1];
  char timeout_persistence[4];
  realserver *svr;

  struct virtualserver *next;
} virtualserver;


/* prototypes */
virtualserver * ConfReader(virtualserver *lst_vs, int delay_loop);
void ClearLst(virtualserver * lstptr);
void PrintLst(virtualserver * lstptr);

#endif
