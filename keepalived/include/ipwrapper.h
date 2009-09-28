/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        ipwrapper.c include file.
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
 * Copyright (C) 2001-2009 Alexandre Cassen, <acassen@freebox.fr>
 */

#ifndef _IPWRAPPER_H
#define _IPWRAPPER_H

/* system includes */
#include <syslog.h>

/* locale includes */
#include "check_data.h"
#include "smtp.h"

/* NAT netmask */
#define HOST_NETMASK   0xffffffff

/* firewall rules framework command */
#define IP_FW_CMD_ADD 0x0001
#define IP_FW_CMD_DEL 0x0002

/* UP & DOWN value */
#define UP   1
#define DOWN 0

/* LVS command set by kernel */
#ifdef _KRNL_2_2_
#define LVS_CMD_ADD		IP_MASQ_CMD_ADD
#define LVS_CMD_DEL		IP_MASQ_CMD_DEL
#define LVS_CMD_ADD_DEST	IP_MASQ_CMD_ADD_DEST
#define LVS_CMD_DEL_DEST	IP_MASQ_CMD_DEL_DEST
#define LVS_CMD_EDIT_DEST	IP_MASQ_CMD_SET_DEST
#else
#define LVS_CMD_ADD		IP_VS_SO_SET_ADD
#define LVS_CMD_DEL		IP_VS_SO_SET_DEL
#define LVS_CMD_ADD_DEST	IP_VS_SO_SET_ADDDEST
#define LVS_CMD_DEL_DEST	IP_VS_SO_SET_DELDEST
#define LVS_CMD_EDIT_DEST	IP_VS_SO_SET_EDITDEST
#endif

/* prototypes */
extern void perform_svr_state(int alive, virtual_server * vs, real_server * rs);
extern void update_svr_wgt(int weight, virtual_server * vs, real_server * rs);
extern int svr_checker_up(checker_id_t cid, real_server * rs);
extern void update_svr_checker_state(int alive, checker_id_t cid,
				     virtual_server * vs, real_server * rs);
extern int init_services(void);
extern int clear_services(void);
extern int clear_diff_services(void);

//extern int ipvs_cmd(int cmd, virtual_server * vserver, real_server * rserver);
extern int ipfw_cmd(int cmd, virtual_server * vserver, real_server * rserver);

#endif
