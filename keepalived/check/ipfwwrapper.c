/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        IPFW Kernel wrapper. Use Rusty firewall manipulation
 *              library to add/remove server MASQ rules to the kernel 
 *              firewall framework.
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

#include "ipfwwrapper.h"
#include "utils.h"

int
ipfw_cmd(int cmd, virtual_server * vs, real_server * rs)
{
	struct ip_fwuser ctl;
	int ret = 1;

	/* Exit if NAT mask is not specified */
	if (!vs->nat_mask)
		return IPFW_SUCCESS;

	memset(&ctl, 0, sizeof (struct ip_fwuser));

	/* Create the firewall MASQ rule */
	strncpy(ctl.label, IP_FW_LABEL_MASQUERADE, IP_FW_MAX_LABEL_LENGTH);
	ctl.ipfw.fw_proto = vs->service_type;

	/* compute the source ip address */
	ctl.ipfw.fw_src.s_addr = SVR_IP(rs) & vs->nat_mask;
	ctl.ipfw.fw_smsk.s_addr = vs->nat_mask;

	ctl.ipfw.fw_spts[0] = ctl.ipfw.fw_spts[1] = htons(SVR_PORT(rs));
	ctl.ipfw.fw_dpts[0] = 0x0000;
	ctl.ipfw.fw_dpts[1] = 0xFFFF;
	ctl.ipfw.fw_tosand = 0xFF;
	ctl.ipfw.fw_tosxor = 0x00;

	if (cmd & IP_FW_CMD_ADD) {
		ipfwc_delete_entry(IP_FW_LABEL_FORWARD, &ctl);
		if (!(errno & EINVAL)) {
			DBG("ipfw_cmd : MASQ firewall rule [%s:%d] already exist.",
			    inet_ntop2(SVR_IP(rs)), ntohs(SVR_PORT(rs)));
		}
		ret &= ipfwc_insert_entry(IP_FW_LABEL_FORWARD, &ctl, 1);
	}

	if (cmd & IP_FW_CMD_DEL)
		ret &= ipfwc_delete_entry(IP_FW_LABEL_FORWARD, &ctl);

	if (!ret) {
		DBG("ipfw_cmd : firewall error (%s) processing [%s:%d] MASQ rule.",
		    strerror(errno), inet_ntop2(SVR_IP(rs)), ntohs(SVR_PORT(rs)));
		return IPFW_ERROR;
	}

	return IPFW_SUCCESS;
}
