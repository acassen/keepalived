/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        ipwrapper.c include file.
 *
 * Version:     $Id: ipwrapper.h,v 0.3.6 2001/08/23 23:02:51 acassen Exp $
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

#ifndef _IPWRAPPER_H
#define _IPWRAPPER_H

/* system includes */
#include <syslog.h>

/* locale includes */
#include "cfreader.h"
#include "smtp.h"

/* NAT netmask */
#define HOST_NETMASK   0xffffffff

/* firewall rules framework command */
#define IP_FW_CMD_ADD 0x0001
#define IP_FW_CMD_DEL 0x0002

/* UP & DOWN value */
#define UP   1
#define DOWN 0

/* prototypes */
extern void perform_svr_state(int alive, virtualserver *vserver, realserver *rserver);
extern int init_services(virtualserver *vserver);
extern int clear_services(virtualserver *vserver);

extern int ipvs_cmd(int cmd, virtualserver *vserver, realserver *rserver);
extern int ipfw_cmd(int cmd, virtualserver *vserver, realserver *rserver);

#endif
