/*
 * Soft:        Vrrpd is an implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Part:        vrrp_snmp.c program include file.
 *
 * Author:      Vincent Bernat <bernat@luffy.cx>
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

#ifndef _VRRP_SNMP_H
#define _VRRP_SNMP_H

#ifdef _WITH_SNMP_RFC_
#include "timer.h"
#endif

#ifdef _WITH_SNMP_RFCV2_
enum rfcv2_trap_auth_error_type {
	invalidAuthType = 1,
#ifdef _WITH_VRRP_AUTH_
	authTypeMismatch,
	authFailure
#endif
};
#endif

#ifdef _WITH_SNMP_RFCV3_
enum rfcv3_notify_proto_error_type {
	noError = 0,
	ipTtlError,
	versionError,
	checksumError,
	vrIdError
};

enum rfcv3_master_reason_type {
	VRRPV3_MASTER_REASON_NOT_MASTER = 0,
	VRRPV3_MASTER_REASON_PRIORITY,
	VRRPV3_MASTER_REASON_PREEMPTED,
	VRRPV3_MASTER_REASON_MASTER_NO_RESPONSE
};
#endif

#ifdef _WITH_SNMP_RFC_
/* Global vars */
extern timeval_t vrrp_start_time;
#endif

/* Prototypes */
extern void vrrp_snmp_agent_init(const char *);
extern void vrrp_snmp_agent_close(void);

#ifdef _WITH_SNMP_KEEPALIVED_
extern void vrrp_snmp_instance_trap(vrrp_t *);
extern void vrrp_snmp_group_trap(vrrp_sgroup_t *);
#endif

#ifdef _WITH_SNMP_RFCV2_
extern void vrrp_rfcv2_snmp_new_master_trap(vrrp_t *);
extern void vrrp_rfcv2_snmp_auth_err_trap(vrrp_t *, struct in_addr, enum rfcv2_trap_auth_error_type);
#endif
#ifdef _WITH_SNMP_RFCV3_
extern void vrrp_rfcv3_snmp_new_master_notify(vrrp_t *);
extern void vrrp_rfcv3_snmp_proto_err_notify(vrrp_t *);
#endif

#endif
