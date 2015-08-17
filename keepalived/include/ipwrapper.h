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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
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
#define LVS_CMD_ADD		IP_VS_SO_SET_ADD
#define LVS_CMD_DEL		IP_VS_SO_SET_DEL
#define LVS_CMD_ADD_DEST	IP_VS_SO_SET_ADDDEST
#define LVS_CMD_DEL_DEST	IP_VS_SO_SET_DELDEST
#define LVS_CMD_EDIT_DEST	IP_VS_SO_SET_EDITDEST

/* prototypes */
extern int perform_svr_state(int, virtual_server_t *, real_server_t *);
extern void update_svr_wgt(int, virtual_server_t *, real_server_t *, int);
extern int svr_checker_up(checker_id_t, real_server_t *);
extern void update_svr_checker_state(int, checker_id_t, virtual_server_t *, real_server_t *);
extern int init_services(void);
extern int clear_services(void);
extern int clear_diff_services(void);
extern void link_vsg_to_vs(void);

#endif
