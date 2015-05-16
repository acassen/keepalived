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

#include "snmp.h"

/* VRRP SNMP defines */
#define VRRP_OID KEEPALIVED_OID, 2
#define VRRP_RFC_OID 1, 3, 6, 1, 2, 1, 68
#define VRRP_RFC_TRAP_OID VRRP_RFC_OID, 0

#define VRRP_SNMP_SCRIPT_NAME 3
#define VRRP_SNMP_SCRIPT_COMMAND 4
#define VRRP_SNMP_SCRIPT_INTERVAL 5
#define VRRP_SNMP_SCRIPT_WEIGHT 6
#define VRRP_SNMP_SCRIPT_RESULT 7
#define VRRP_SNMP_SCRIPT_RISE 8
#define VRRP_SNMP_SCRIPT_FALL 9
#define VRRP_SNMP_ADDRESS_ADDRESSTYPE 9
#define VRRP_SNMP_ADDRESS_VALUE 10
#define VRRP_SNMP_ADDRESS_BROADCAST 11
#define VRRP_SNMP_ADDRESS_MASK 12
#define VRRP_SNMP_ADDRESS_SCOPE 13
#define VRRP_SNMP_ADDRESS_IFINDEX 14
#define VRRP_SNMP_ADDRESS_IFNAME 15
#define VRRP_SNMP_ADDRESS_IFALIAS 16
#define VRRP_SNMP_ADDRESS_ISSET 17
#define VRRP_SNMP_ADDRESS_ISADVERTISED 18
#define VRRP_SNMP_ROUTE_ADDRESSTYPE 19
#define VRRP_SNMP_ROUTE_DESTINATION 20
#define VRRP_SNMP_ROUTE_DESTINATIONMASK 21
#define VRRP_SNMP_ROUTE_GATEWAY 22
#define VRRP_SNMP_ROUTE_SECONDARYGATEWAY 23
#define VRRP_SNMP_ROUTE_SOURCE 24
#define VRRP_SNMP_ROUTE_METRIC 25
#define VRRP_SNMP_ROUTE_SCOPE 26
#define VRRP_SNMP_ROUTE_TYPE 27
#define VRRP_SNMP_ROUTE_IFINDEX 28
#define VRRP_SNMP_ROUTE_IFNAME 29
#define VRRP_SNMP_ROUTE_ROUTINGTABLE 30
#define VRRP_SNMP_ROUTE_ISSET 31
#define VRRP_SNMP_SYNCGROUP_NAME 33
#define VRRP_SNMP_SYNCGROUP_STATE 34
#define VRRP_SNMP_SYNCGROUP_SMTPALERT 35
#define VRRP_SNMP_SYNCGROUP_NOTIFYEXEC 36
#define VRRP_SNMP_SYNCGROUP_SCRIPTMASTER 37
#define VRRP_SNMP_SYNCGROUP_SCRIPTBACKUP 38
#define VRRP_SNMP_SYNCGROUP_SCRIPTFAULT 39
#define VRRP_SNMP_SYNCGROUP_SCRIPT 40
#define VRRP_SNMP_SYNCGROUPMEMBER_INSTANCE 42
#define VRRP_SNMP_SYNCGROUPMEMBER_NAME 43
#define VRRP_SNMP_INSTANCE_NAME 45
#define VRRP_SNMP_INSTANCE_VIRTUALROUTERID 46
#define VRRP_SNMP_INSTANCE_STATE 47
#define VRRP_SNMP_INSTANCE_INITIALSTATE 48
#define VRRP_SNMP_INSTANCE_WANTEDSTATE 49
#define VRRP_SNMP_INSTANCE_BASEPRIORITY 50
#define VRRP_SNMP_INSTANCE_EFFECTIVEPRIORITY 51
#define VRRP_SNMP_INSTANCE_VIPSENABLED 52
#define VRRP_SNMP_INSTANCE_PRIMARYINTERFACE 53
#define VRRP_SNMP_INSTANCE_TRACKPRIMARYIF 54
#define VRRP_SNMP_INSTANCE_ADVERTISEMENTSINT 55
#define VRRP_SNMP_INSTANCE_PREEMPT 56
#define VRRP_SNMP_INSTANCE_PREEMPTDELAY 57
#define VRRP_SNMP_INSTANCE_AUTHTYPE 58
#define VRRP_SNMP_INSTANCE_USELVSSYNCDAEMON 59
#define VRRP_SNMP_INSTANCE_LVSSYNCINTERFACE 60
#define VRRP_SNMP_INSTANCE_SYNCGROUP 61
#define VRRP_SNMP_INSTANCE_GARPDELAY 62
#define VRRP_SNMP_INSTANCE_SMTPALERT 63
#define VRRP_SNMP_INSTANCE_NOTIFYEXEC 64
#define VRRP_SNMP_INSTANCE_SCRIPTMASTER 65
#define VRRP_SNMP_INSTANCE_SCRIPTBACKUP 66
#define VRRP_SNMP_INSTANCE_SCRIPTFAULT 67
#define VRRP_SNMP_INSTANCE_SCRIPTSTOP 68
#define VRRP_SNMP_INSTANCE_SCRIPT 69
#define VRRP_SNMP_INSTANCE_ACCEPT 70
#define VRRP_SNMP_TRACKEDINTERFACE_NAME 71
#define VRRP_SNMP_TRACKEDINTERFACE_WEIGHT 72
#define VRRP_SNMP_TRACKEDSCRIPT_NAME 74
#define VRRP_SNMP_TRACKEDSCRIPT_WEIGHT 75


#define HEADER_STATE_STATIC_ADDRESS 1
#define HEADER_STATE_VIRTUAL_ADDRESS 2
#define HEADER_STATE_EXCLUDED_VIRTUAL_ADDRESS 3
#define HEADER_STATE_STATIC_ROUTE 4
#define HEADER_STATE_VIRTUAL_ROUTE 5
#define HEADER_STATE_END 10


/* Prototypes */
extern void vrrp_snmp_agent_init(const char *);
extern void vrrp_snmp_agent_close(void);
extern void vrrp_snmp_instance_trap(vrrp_t *);
extern void vrrp_snmp_group_trap(vrrp_sgroup_t *);
extern void vrrp_rfc_snmp_new_master_trap(vrrp_t *);
#endif
