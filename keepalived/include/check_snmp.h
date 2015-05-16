/*
 * Soft:        Vrrpd is an implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Part:        check_snmp.c program include file.
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

#ifndef _CHECK_SNMP_H
#define _CHECK_SNMP_H

#include "snmp.h"

/* CHECK SNMP defines */
#define CHECK_OID KEEPALIVED_OID, 3

#define CHECK_SNMP_VSGROUPNAME 1
#define CHECK_SNMP_VSGROUPMEMBERTYPE 3
#define CHECK_SNMP_VSGROUPMEMBERFWMARK 4
#define CHECK_SNMP_VSGROUPMEMBERADDRTYPE 5
#define CHECK_SNMP_VSGROUPMEMBERADDRESS 6
#define CHECK_SNMP_VSGROUPMEMBERADDR1 7
#define CHECK_SNMP_VSGROUPMEMBERADDR2 8
#define CHECK_SNMP_VSGROUPMEMBERPORT 9
#define CHECK_SNMP_VSTYPE 10
#define CHECK_SNMP_VSNAMEGROUP 14
#define CHECK_SNMP_VSFWMARK 11
#define CHECK_SNMP_VSADDRTYPE 12
#define CHECK_SNMP_VSADDRESS 13
#define CHECK_SNMP_VSPORT 16
#define CHECK_SNMP_VSPROTOCOL 17
#define CHECK_SNMP_VSLOADBALANCINGALGO 18
#define CHECK_SNMP_VSLOADBALANCINGKIND 19
#define CHECK_SNMP_VSSTATUS 20
#define CHECK_SNMP_VSVIRTUALHOST 21
#define CHECK_SNMP_VSPERSIST 22
#define CHECK_SNMP_VSPERSISTTIMEOUT 23
#define CHECK_SNMP_VSPERSISTGRANULARITY 24
#define CHECK_SNMP_VSDELAYLOOP 25
#define CHECK_SNMP_VSHASUSPEND 26
#define CHECK_SNMP_VSALPHA 27
#define CHECK_SNMP_VSOMEGA 28
#define CHECK_SNMP_VSQUORUM 29
#define CHECK_SNMP_VSQUORUMSTATUS 30
#define CHECK_SNMP_VSQUORUMUP 31
#define CHECK_SNMP_VSQUORUMDOWN 32
#define CHECK_SNMP_VSHYSTERESIS 33
#define CHECK_SNMP_VSREALTOTAL 34
#define CHECK_SNMP_VSREALUP 35
#define CHECK_SNMP_VSSTATSCONNS 61
#define CHECK_SNMP_VSSTATSINPKTS 62
#define CHECK_SNMP_VSSTATSOUTPKTS 63
#define CHECK_SNMP_VSSTATSINBYTES 64
#define CHECK_SNMP_VSSTATSOUTBYTES 65
#define CHECK_SNMP_VSRATECPS 66
#define CHECK_SNMP_VSRATEINPPS 67
#define CHECK_SNMP_VSRATEOUTPPS 68
#define CHECK_SNMP_VSRATEINBPS 69
#define CHECK_SNMP_VSRATEOUTBPS 70
#define CHECK_SNMP_RSTYPE 36
#define CHECK_SNMP_RSADDRTYPE 37
#define CHECK_SNMP_RSADDRESS 38
#define CHECK_SNMP_RSPORT 39
#define CHECK_SNMP_RSSTATUS 40
#define CHECK_SNMP_RSWEIGHT 41
#define CHECK_SNMP_RSUPPERCONNECTIONLIMIT 42
#define CHECK_SNMP_RSLOWERCONNECTIONLIMIT 43
#define CHECK_SNMP_RSACTIONWHENDOWN 44
#define CHECK_SNMP_RSNOTIFYUP 45
#define CHECK_SNMP_RSNOTIFYDOWN 46
#define CHECK_SNMP_RSFAILEDCHECKS 47
#define CHECK_SNMP_RSSTATSCONNS 48
#define CHECK_SNMP_RSSTATSACTIVECONNS 49
#define CHECK_SNMP_RSSTATSINACTIVECONNS 50
#define CHECK_SNMP_RSSTATSPERSISTENTCONNS 51
#define CHECK_SNMP_RSSTATSINPKTS 52
#define CHECK_SNMP_RSSTATSOUTPKTS 53
#define CHECK_SNMP_RSSTATSINBYTES 54
#define CHECK_SNMP_RSSTATSOUTBYTES 55
#define CHECK_SNMP_RSRATECPS 56
#define CHECK_SNMP_RSRATEINPPS 57
#define CHECK_SNMP_RSRATEOUTPPS 58
#define CHECK_SNMP_RSRATEINBPS 59
#define CHECK_SNMP_RSRATEOUTBPS 60
#define CHECK_SNMP_VSOPS 71

#define STATE_VSGM_FWMARK 1
#define STATE_VSGM_ADDRESS 2
#define STATE_VSGM_RANGE 3
#define STATE_VSGM_END 4

#define STATE_RS_SORRY 1
#define STATE_RS_REGULAR_FIRST 2
#define STATE_RS_REGULAR_NEXT 3
#define STATE_RS_END 4

/* Macro */
#define RETURN_IP46ADDRESS(entity)					\
do {									\
  if (entity->addr.ss_family == AF_INET6) {				\
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&entity->addr;	\
    *var_len = 16;							\
    return (u_char *)&addr6->sin6_addr;					\
  } else {								\
    struct sockaddr_in *addr4 = (struct sockaddr_in *)&entity->addr;	\
    *var_len = 4;							\
    return (u_char *)&addr4->sin_addr;					\
  }									\
} while(0)


/* Prototypes */
extern void check_snmp_agent_init(const char *);
extern void check_snmp_agent_close(void);
extern void check_snmp_rs_trap(real_server_t *, virtual_server_t *);
extern void check_snmp_quorum_trap(virtual_server_t *);

#endif
