/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        SNMP agent
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

/*
 * To test this code, one can use the following:
 *
 * Build keepalived with SNMP support with one or more of the following options
     ./configure--enable-snmp-keepalived --enable-snmp-checker [or --enable-snmp to enable previous two options] \
		 --enable-snmp-rfcv2 --enable-snmp-rfcv3 [or --enable-snmp-rfc to enable previous two options]

 * Edit /etc/snmp/snmpd.conf to contain the following:
     rocommunity public
     rwcommunity private
     master agentx

     trapcommunity public
     trap2sink localhost:162

 * Edit /etc/snmp/snmptrapd.conf to uncomment the following line:
     authCommunity  log,execute,net public

 * Put the MIB definition files in a place that will be found:
     cp doc/[VK]*-MIB /usr/share/snmp/mibs
 *  or
     cp doc/[VK]*-MIB ~/.snmp/mibs

 * Run snmpd (in background)
     snmpd -LS0-6d

 * Run snmptrapd (in foreground)
     MIBS="+KEEPALIVED-MIB:VRRP-MIB:VRRPV3-MIB" snmptrapd -f -Lo
 *  or if MIB files copied to ~/.snmp/mibs
     MIBS="+KEEPALIVED-MIB:VRRP-MIB:VRRPV3-MIB" snmptrapd -f -M "+$HOME/.snmp/mibs" -Lo

 * Enable SNMP in config file, by adding some or all of the following, depending on which configure options were chosen
     enable_snmp_keepalived
     enable_snmp_checker
     enable_snmp_rfcv2
     enable_snmp_rfcv3
     enable_snmp_traps

 * Run keepalived. Some traps/notifications should be generated which will be displayed on the terminal running snmptrapd

 * To see the MIB trees, run
     MIBS="+KEEPALIVED-MIB" snmpwalk -v2c -c public localhost KEEPALIVED-MIB::keepalived
    or
     MIBS="+VRRP-MIB" snmpwalk -v2c -c public localhost VRRP-MIB::vrrpMIB
    or
     MIBS="+VRRPV3-MIB" snmpwalk -v2c -c public localhost VRRPV3-MIB::vrrpv3MIB
 *
 */

#include "vrrp.h"
#include "vrrp_snmp.h"
#include "vrrp_data.h"
#include "vrrp_track.h"
#include "vrrp_ipaddress.h"
#include "vrrp_iproute.h"
#include "vrrp_iprule.h"
#include "vrrp_vmac.h"
#include "config.h"
#include "vector.h"
#include "list.h"
#include "logger.h"
#include "global_data.h"
#include "bitops.h"
#include "main.h"

#include "snmp.h"

#ifdef _WITH_SNMP_KEEPALIVED_
/* VRRP SNMP defines */
#define VRRP_OID KEEPALIVED_OID, 2

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
#define VRRP_SNMP_RULE_DIRECTION 77
#define VRRP_SNMP_RULE_ADDRESSTYPE 78
#define VRRP_SNMP_RULE_ADDRESS 79
#define VRRP_SNMP_RULE_ADDRESSMASK 80
#define VRRP_SNMP_RULE_ROUTINGTABLE 81
#define VRRP_SNMP_RULE_ISSET 82


#define HEADER_STATE_STATIC_ADDRESS 1
#define HEADER_STATE_VIRTUAL_ADDRESS 2
#define HEADER_STATE_EXCLUDED_VIRTUAL_ADDRESS 3
#define HEADER_STATE_STATIC_ROUTE 4
#define HEADER_STATE_VIRTUAL_ROUTE 5
#define HEADER_STATE_STATIC_RULE 6
#define HEADER_STATE_VIRTUAL_RULE 7
#define HEADER_STATE_END 10

#endif

#ifdef _WITH_SNMP_RFCV2_
/* RFC SNMP defines */
#define VRRP_RFC_OID SNMP_OID_MIB2, 68
#define VRRP_RFC_TRAP_OID VRRP_RFC_OID, 0

/* Magic for RFC MIB functions */
enum rfcv2_snmp_node_magic {
	VRRP_RFC_SNMP_NODE_VER = 2,
	VRRP_RFC_SNMP_NOTIF_CNTL
};

enum rfcv2_snmp_oper_magic {
	VRRP_RFC_SNMP_OPER_VRID = 2,
	VRRP_RFC_SNMP_OPER_AUTH_KEY,
	VRRP_RFC_SNMP_OPER_ADVERT_INT,
	VRRP_RFC_SNMP_OPER_PREEMPT,
	VRRP_RFC_SNMP_OPER_VR_UPTIME,
	VRRP_RFC_SNMP_OPER_PROTO,
	VRRP_RFC_SNMP_OPER_ROW_STAT,
	VRRP_RFC_SNMP_OPER_VMAC,
	VRRP_RFC_SNMP_OPER_STATE,
	VRRP_RFC_SNMP_OPER_ADM_STATE,
	VRRP_RFC_SNMP_OPER_PRI,
	VRRP_RFC_SNMP_OPER_ADDR_CNT,
	VRRP_RFC_SNMP_OPER_MIP,
	VRRP_RFC_SNMP_OPER_PIP,
	VRRP_RFC_SNMP_OPER_AUTH_TYPE
};

enum rfcv2_snmp_assoc_ip_magic {
	VRRP_RFC_SNMP_ASSOC_IP_ADDR = 2,
	VRRP_RFC_SNMP_ASSOC_IP_ADDR_ROW
};

enum rfcv2_snmp_stats_err_magic {
	VRRP_RFC_SNMP_STATS_CHK_ERR = 2,
	VRRP_RFC_SNMP_STATS_VER_ERR,
	VRRP_RFC_SNMP_STATS_VRID_ERR
};

enum rfcv2_snmp_stats_magic {
	VRRP_RFC_SNMP_STATS_MASTER = 2,
	VRRP_RFC_SNMP_STATS_AUTH_INV,
	VRRP_RFC_SNMP_STATS_AUTH_MIS,
	VRRP_RFC_SNMP_STATS_PL_ERR,
	VRRP_RFC_SNMP_STATS_ADV_RCVD,
	VRRP_RFC_SNMP_STATS_ADV_INT_ERR,
	VRRP_RFC_SNMP_STATS_AUTH_FAIL,
	VRRP_RFC_SNMP_STATS_TTL_ERR,
	VRRP_RFC_SNMP_STATS_PRI_0_RCVD,
	VRRP_RFC_SNMP_STATS_PRI_0_SENT,
	VRRP_RFC_SNMP_STATS_INV_TYPE_RCVD,
	VRRP_RFC_SNMP_STATS_ADDR_LIST_ERR
};

/*
	VRRP_RFC_SNMP_CNFRM_MIB,
	VRRP_RFC_SNMP_GRP_OPER,
	VRRP_RFC_SNMP_GRP_STATS,
	VRRP_RFC_SNMP_GRP_TRAP,
	VRRP_RFC_SNMP_GRP_NOTIF
*/
#endif

#ifdef _WITH_SNMP_RFCV3_
/* RFC SNMP defines */
#define VRRP_RFCv3_OID SNMP_OID_MIB2, 207
#define VRRP_RFCv3_NOTIFY_OID VRRP_RFCv3_OID, 0

/* Magic for RFC MIB functions */
enum rfcv3_snmp_oper_magic {
	VRRP_RFCv3_SNMP_OPER_VRID,
	VRRP_RFCv3_SNMP_OPER_INET_ADDR_TYPE,
	VRRP_RFCv3_SNMP_OPER_MIP,
	VRRP_RFCv3_SNMP_OPER_PIP,
	VRRP_RFCv3_SNMP_OPER_VMAC,
	VRRP_RFCv3_SNMP_OPER_STATE,
	VRRP_RFCv3_SNMP_OPER_PRI,
	VRRP_RFCv3_SNMP_OPER_ADDR_CNT,
	VRRP_RFCv3_SNMP_OPER_ADVERT_INT,
	VRRP_RFCv3_SNMP_OPER_PREEMPT,
	VRRP_RFCv3_SNMP_OPER_ACCEPT,
	VRRP_RFCv3_SNMP_OPER_VR_UPTIME,
	VRRP_RFCv3_SNMP_OPER_ROW_STATUS
};

enum rfcv3_snmp_assoc_ip_magic {
	VRRP_RFCv3_SNMP_ASSOC_IP_ADDR = 2,
	VRRP_RFCv3_SNMP_ASSOC_IP_ADDR_ROW_STATUS
};

enum rfcv3_snmp_stats_err_magic {
	VRRP_RFCv3_SNMP_STATS_CHK_ERR = 2,
	VRRP_RFCv3_SNMP_STATS_VER_ERR,
	VRRP_RFCv3_SNMP_STATS_VRID_ERR,
	VRRP_RFCv3_SNMP_STATS_DISC_TIME
};

enum rfcv3_snmp_stats_magic {
	VRRP_RFCv3_SNMP_STATS_MASTER = 2,
	VRRP_RFCv3_SNMP_STATS_MASTER_REASON,
	VRRP_RFCv3_SNMP_STATS_ADV_RCVD,
	VRRP_RFCv3_SNMP_STATS_ADV_INT_ERR,
	VRRP_RFCv3_SNMP_STATS_TTL_ERR,
	VRRP_RFCv3_SNMP_STATS_PROTO_ERR_REASON,
	VRRP_RFCv3_SNMP_STATS_PRI_0_RCVD,
	VRRP_RFCv3_SNMP_STATS_PRI_0_SENT,
	VRRP_RFCv3_SNMP_STATS_INV_TYPE_RCVD,
	VRRP_RFCv3_SNMP_STATS_ADDR_LIST_ERR,
	VRRP_RFCv3_SNMP_STATS_PL_ERR,
	VRRP_RFCv3_SNMP_STATS_ROW_DISC_TIME,
	VRRP_RFCv3_SNMP_STATS_REFRESH_RATE
};

/*
	VRRP_RFCv3_SNMP_CNFRM_MIB,
	VRRP_RFCv3_SNMP_GRP_OPER,
	VRRP_RFCv3_SNMP_GRP_STATS,
	VRRP_RFCv3_SNMP_GRP_TRAP,
	VRRP_RFCv3_SNMP_GRP_NOTIF
*/
#endif

/* global variable */
#ifdef _WITH_SNMP_RFC_
timeval_t vrrp_start_time;
#endif


#ifdef _FOR_DEBUGGING_
static void
sprint_oid(char *str, oid* oid, int len)
{
	int offs = 0;
	int i;

	if (!len) {
		str[0] = '.';
		str[1] = 0;
		return;
	}

	for (i = 0; i < len; i++)
		offs += sprintf(str + offs, ".%lu", oid[i]);
}
#endif

#ifdef _WITH_SNMP_KEEPALIVED_
/* Convert VRRP state to SNMP state */
static unsigned long
vrrp_snmp_state(int state)
{
	return (state<VRRP_STATE_GOTO_MASTER)?state:4;
}

static u_char*
vrrp_snmp_script(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	vrrp_script_t *scr;

	if ((scr = (vrrp_script_t *)snmp_header_list_table(vp, name, length, exact,
							   var_len, write_method,
							   vrrp_data->vrrp_script)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_SCRIPT_NAME:
		*var_len = strlen(scr->sname);
		return (u_char *)scr->sname;
	case VRRP_SNMP_SCRIPT_COMMAND:
		*var_len = strlen(scr->script);
		return (u_char *)scr->script;
	case VRRP_SNMP_SCRIPT_INTERVAL:
		long_ret = scr->interval / TIMER_HZ;
		return (u_char *)&long_ret;
	case VRRP_SNMP_SCRIPT_WEIGHT:
		long_ret = scr->weight;
		return (u_char *)&long_ret;
	case VRRP_SNMP_SCRIPT_RESULT:
		switch (scr->result) {
		case VRRP_SCRIPT_STATUS_INIT:
			long_ret = 1; break;
		case VRRP_SCRIPT_STATUS_INIT_GOOD:
			long_ret = 4; break;
		case VRRP_SCRIPT_STATUS_DISABLED:
			long_ret = 0; break;
		default:
			long_ret = (scr->result >= scr->rise) ? 3 : 2;
		}
		return (u_char *)&long_ret;
	case VRRP_SNMP_SCRIPT_RISE:
		long_ret = scr->rise;
		return (u_char *)&long_ret;
	case VRRP_SNMP_SCRIPT_FALL:
		long_ret = scr->fall;
		return (u_char *)&long_ret;
	default:
		break;
	}
	return NULL;
}

/* Header function using a FSM. `state' is the initial state, either
   HEADER_STATE_STATIC_ADDRESS or HEADER_STATE_STATIC_ROUTE. We return
   the matching address or route. */
static void*
vrrp_header_ar_table(struct variable *vp, oid *name, size_t *length,
		     int exact, size_t *var_len, WriteMethod **write_method,
		     int *state)
{
	oid *target, current[2], best[2];
	int result, target_len;
	element e1 = NULL, e2;
	void *el, *bel = NULL;
	list l2;
	int curinstance = 0;
	int curstate, nextstate;

	if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
	}

	*write_method = 0;
	*var_len = sizeof(long);

	/* We search the best match: equal if exact, the lower OID in
	   the set of the OID strictly superior to the target
	   otherwise. */
	best[0] = best[1] = MAX_SUBID; /* Our best match */
	target = &name[vp->namelen];   /* Our target match */
	target_len = *length - vp->namelen;

	nextstate = *state;
	while (nextstate != HEADER_STATE_END) {
		curstate = nextstate;
		switch (curstate) {
		case HEADER_STATE_STATIC_ADDRESS:
			/* Try static addresses */
			l2 = vrrp_data->static_addresses;
			current[1] = 0;
			nextstate = HEADER_STATE_VIRTUAL_ADDRESS;
			break;
		case HEADER_STATE_VIRTUAL_ADDRESS:
			/* Try virtual addresses */
			if (LIST_ISEMPTY(vrrp_data->vrrp)) {
				nextstate = HEADER_STATE_END;
				continue;
			}
			curinstance++;
			if (e1 == NULL)
				e1 = LIST_HEAD(vrrp_data->vrrp);
			else {
				ELEMENT_NEXT(e1);
				if (!e1) {
					nextstate = HEADER_STATE_END;
					continue;
				}
			}
			l2 = ((vrrp_t *) ELEMENT_DATA(e1))->vip;
			current[1] = 0;
			nextstate = HEADER_STATE_EXCLUDED_VIRTUAL_ADDRESS;
			break;
		case HEADER_STATE_EXCLUDED_VIRTUAL_ADDRESS:
			/* Try excluded virtual addresses */
			l2 = ((vrrp_t *)ELEMENT_DATA(e1))->evip;
			nextstate = HEADER_STATE_VIRTUAL_ADDRESS;
			break;
		case HEADER_STATE_STATIC_ROUTE:
			/* Try static routes */
			l2 = vrrp_data->static_routes;
			current[1] = 0;
			nextstate = HEADER_STATE_VIRTUAL_ROUTE;
			break;
		case HEADER_STATE_VIRTUAL_ROUTE:
			/* Try virtual routes */
			if (LIST_ISEMPTY(vrrp_data->vrrp) ||
			    ((e1 != NULL) && (ELEMENT_NEXT(e1), !e1))) {
				nextstate = HEADER_STATE_END;
				continue;
			}
			curinstance++;
			if (e1 == NULL)
				e1 = LIST_HEAD(vrrp_data->vrrp);
			l2 = ((vrrp_t *)ELEMENT_DATA(e1))->vroutes;
			current[1] = 0;
			nextstate = HEADER_STATE_VIRTUAL_ROUTE;
			break;
		case HEADER_STATE_STATIC_RULE:
			/* Try static routes */
			l2 = vrrp_data->static_rules;
			current[1] = 0;
			nextstate = HEADER_STATE_VIRTUAL_RULE;
			break;
		case HEADER_STATE_VIRTUAL_RULE:
			/* Try virtual rules */
			if (LIST_ISEMPTY(vrrp_data->vrrp) ||
			    ((e1 != NULL) && (ELEMENT_NEXT(e1), !e1))) {
				nextstate = HEADER_STATE_END;
				continue;
			}
			curinstance++;
			if (e1 == NULL)
				e1 = LIST_HEAD(vrrp_data->vrrp);
			l2 = ((vrrp_t *)ELEMENT_DATA(e1))->vrules;
			current[1] = 0;
			nextstate = HEADER_STATE_VIRTUAL_RULE;
			break;
		default:
			return NULL; /* Big problem! */
		}
		if (target_len && (curinstance < target[0]))
			continue; /* Optimization: cannot be part of our set */
		if (LIST_ISEMPTY(l2)) continue;
		for (e2 = LIST_HEAD(l2); e2; ELEMENT_NEXT(e2)) {
			el = ELEMENT_DATA(e2);
			current[0] = curinstance;
			current[1]++;
			if ((result = snmp_oid_compare(current, 2, target,
						       target_len)) < 0)
				continue;
			if ((result == 0) && !exact)
				continue;
			if (result == 0) {
				return el;
			}
			if (snmp_oid_compare(current, 2, best, 2) < 0) {
				/* This is our best match */
				memcpy(best, current, sizeof(oid) * 2);
				bel = el;
				*state = curstate;
				/* Optimization: (e1,e2) is strictly
				   increasing, this is the lower
				   element of our target set. */
				nextstate = HEADER_STATE_END;
				break;
			}
		}
	}

	if (bel == NULL)
		/* No best match */
		return NULL;
	if (exact)
		/* No exact match */
		return NULL;
	/* Let's use our best match */
	memcpy(target, best, sizeof(oid) * 2);
	*length = vp->namelen + 2;
	return bel;
}

static u_char*
vrrp_snmp_address(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	ip_address_t *addr;
	int state = HEADER_STATE_STATIC_ADDRESS;

	if ((addr = (ip_address_t *)
	     vrrp_header_ar_table(vp, name, length, exact,
				  var_len, write_method,
				  &state)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_ADDRESS_ADDRESSTYPE:
		long_ret = (addr->ifa.ifa_family == AF_INET6)?2:1;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ADDRESS_VALUE:
		if (addr->ifa.ifa_family == AF_INET6) {
			*var_len = 16;
			return (u_char *)&addr->u.sin6_addr;
		} else {
			*var_len = 4;
			return (u_char *)&addr->u.sin.sin_addr;
		}
		break;
	case VRRP_SNMP_ADDRESS_BROADCAST:
		if (addr->ifa.ifa_family == AF_INET6) break;
		*var_len = 4;
		return (u_char *)&addr->u.sin.sin_brd;
	case VRRP_SNMP_ADDRESS_MASK:
		long_ret = addr->ifa.ifa_prefixlen;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ADDRESS_SCOPE:
		long_ret = snmp_scope(addr->ifa.ifa_scope);
		return (u_char *)&long_ret;
	case VRRP_SNMP_ADDRESS_IFINDEX:
		long_ret = addr->ifa.ifa_index;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ADDRESS_IFNAME:
		*var_len = strlen(addr->ifp->ifname);
		return (u_char *)addr->ifp->ifname;
	case VRRP_SNMP_ADDRESS_IFALIAS:
		if (addr->label) {
			*var_len = strlen(addr->label);
			return (u_char*)addr->label;
		}
		break;
	case VRRP_SNMP_ADDRESS_ISSET:
		long_ret = (addr->set)?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ADDRESS_ISADVERTISED:
		long_ret = (state == HEADER_STATE_VIRTUAL_ADDRESS)?1:2;
		return (u_char *)&long_ret;
	default:
		return NULL;
	}
	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_snmp_address(vp, name, length,
					 exact, var_len, write_method);
	return NULL;
}

static u_char*
vrrp_snmp_route(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	ip_route_t *route;
	int state = HEADER_STATE_STATIC_ROUTE;

	if ((route = (ip_route_t *)
	     vrrp_header_ar_table(vp, name, length, exact,
				  var_len, write_method,
				  &state)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_ROUTE_ADDRESSTYPE:
		long_ret = 1;	/* IPv4 only */
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_DESTINATION:
		if (route->dst) {
			if (route->dst->ifa.ifa_family == AF_INET6) {
				*var_len = 16;
				return (u_char *)&route->dst->u.sin6_addr;
			} else {
				*var_len = 4;
				return (u_char *)&route->dst->u.sin.sin_addr;
			}
		}
		break;
	case VRRP_SNMP_ROUTE_DESTINATIONMASK:
		long_ret = route->dmask;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_GATEWAY:
		if (route->gw) {
			if (route->gw->ifa.ifa_family == AF_INET6) {
				*var_len = 16;
				return (u_char *)&route->gw->u.sin6_addr;
			} else {
				*var_len = 4;
				return (u_char *)&route->gw->u.sin.sin_addr;
			}
		}
		break;
	case VRRP_SNMP_ROUTE_SECONDARYGATEWAY:
		if (route->gw2) {
			if (route->gw2->ifa.ifa_family == AF_INET6) {
				*var_len = 16;
				return (u_char *)&route->gw2->u.sin6_addr;
			} else {
				*var_len = 4;
				return (u_char *)&route->gw2->u.sin.sin_addr;
			}
		}
		break;
	case VRRP_SNMP_ROUTE_SOURCE:
		if (route->src) {
			if (route->src->ifa.ifa_family == AF_INET6) {
				*var_len = 16;
				return (u_char *)&route->src->u.sin6_addr;
			} else {
				*var_len = 4;
				return (u_char *)&route->src->u.sin.sin_addr;
			}
		}
		break;
	case VRRP_SNMP_ROUTE_METRIC:
		long_ret = route->metric;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_SCOPE:
		long_ret = snmp_scope(route->scope);
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_TYPE:
		if (route->blackhole)
			long_ret = 3;
		else if (route->gw2)
			long_ret = 2;
		else long_ret = 1;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_IFINDEX:
		if (!route->oif)
			break;
		long_ret = route->index;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_IFNAME:
		if (route->index) {
			*var_len = strlen(IF_NAME(if_get_by_ifindex(route->index)));
			return (u_char *)&IF_NAME(if_get_by_ifindex(route->index));
		}
		break;
	case VRRP_SNMP_ROUTE_ROUTINGTABLE:
		long_ret = route->table;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_ISSET:
		long_ret = (route->set)?1:2;
		return (u_char *)&long_ret;
	default:
		return NULL;
	}
	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_snmp_route(vp, name, length,
				       exact, var_len, write_method);
	return NULL;
}

static u_char*
vrrp_snmp_rule(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	ip_rule_t *rule;
	int state = HEADER_STATE_STATIC_RULE;
	char *dir_str;

	if ((rule = (ip_rule_t *)
	     vrrp_header_ar_table(vp, name, length, exact,
				  var_len, write_method,
				  &state)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_RULE_DIRECTION:
		dir_str = rule->dir == VRRP_RULE_FROM ? "from" : "to";
		*var_len = strlen(dir_str);
		return (u_char *)dir_str;
	case VRRP_SNMP_RULE_ADDRESSTYPE:
		long_ret = (rule->addr->ifa.ifa_family == AF_INET6)?2:1;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_ADDRESS:
		if (rule->addr->ifa.ifa_family == AF_INET6) {
			*var_len = 16;
			return (u_char *)&rule->addr->u.sin6_addr;
		} else {
			*var_len = 4;
			return (u_char *)&rule->addr->u.sin.sin_addr;
		}
		break;
	case VRRP_SNMP_RULE_ADDRESSMASK:
		long_ret = rule->mask;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_ROUTINGTABLE:
		long_ret = rule->table;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_ISSET:
		long_ret = (rule->set)?1:2;
		return (u_char *)&long_ret;
	default:
		return NULL;
	}
	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_snmp_rule(vp, name, length,
				       exact, var_len, write_method);
	return NULL;
}

static u_char*
vrrp_snmp_syncgroup(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	vrrp_sgroup_t *group;

	if ((group = (vrrp_sgroup_t *)
	     snmp_header_list_table(vp, name, length, exact,
				    var_len, write_method,
				    vrrp_data->vrrp_sync_group)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_SYNCGROUP_NAME:
		*var_len = strlen(group->gname);
		return (u_char *)group->gname;
	case VRRP_SNMP_SYNCGROUP_STATE:
		long_ret = vrrp_snmp_state(group->state);
		return (u_char *)&long_ret;
	case VRRP_SNMP_SYNCGROUP_SMTPALERT:
		long_ret = group->smtp_alert?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_SYNCGROUP_NOTIFYEXEC:
		long_ret = group->notify_exec?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_SYNCGROUP_SCRIPTMASTER:
		if (group->script_master) {
			*var_len = strlen(group->script_master);
			return (u_char *)group->script_master;
		}
		break;
	case VRRP_SNMP_SYNCGROUP_SCRIPTBACKUP:
		if (group->script_backup) {
			*var_len = strlen(group->script_backup);
			return (u_char *)group->script_backup;
		}
		break;
	case VRRP_SNMP_SYNCGROUP_SCRIPTFAULT:
		if (group->script_fault) {
			*var_len = strlen(group->script_fault);
			return (u_char *)group->script_fault;
		}
		break;
	case VRRP_SNMP_SYNCGROUP_SCRIPT:
		if (group->script) {
			*var_len = strlen(group->script);
			return (u_char *)group->script;
		}
		break;
	default:
		return NULL;
	}
	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_snmp_syncgroup(vp, name, length,
					   exact, var_len, write_method);
	return NULL;
}

static u_char*
vrrp_snmp_syncgroupmember(struct variable *vp, oid *name, size_t *length,
			  int exact, size_t *var_len, WriteMethod **write_method)
{
	oid *target, current[2], best[2];
	int result, target_len;
	int curgroup, curinstance;
	char *instance, *binstance = NULL;
	element e;
	vrrp_sgroup_t *group;

	if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
	}

	*write_method = 0;
	*var_len = sizeof(long);

	if (LIST_ISEMPTY(vrrp_data->vrrp_sync_group))
		return NULL;

	/* We search the best match: equal if exact, the lower OID in
	   the set of the OID strictly superior to the target
	   otherwise. */
	best[0] = best[1] = MAX_SUBID; /* Our best match */
	target = &name[vp->namelen];   /* Our target match */
	target_len = *length - vp->namelen;
	curgroup = 0;
	for (e = LIST_HEAD(vrrp_data->vrrp_sync_group); e; ELEMENT_NEXT(e)) {
		group = ELEMENT_DATA(e);
		curgroup++;
		if (target_len && (curgroup < target[0]))
			continue; /* Optimization: cannot be part of our set */
		if (binstance)
			break; /* Optimization: cannot be the lower
				  anymore, see break below */
		vector_foreach_slot(group->iname, instance, curinstance) {
			/* We build our current match */
			current[0] = curgroup;
			current[1] = curinstance + 1;
			/* And compare it to our target match */
			if ((result = snmp_oid_compare(current, 2, target,
						       target_len)) < 0)
				continue;
			if ((result == 0) && !exact)
				continue;
			if (result == 0) {
				/* Got an exact match and asked for it */
				*var_len = strlen(instance);
				return (u_char *)instance;
			}
			if (snmp_oid_compare(current, 2, best, 2) < 0) {
				/* This is our best match */
				memcpy(best, current, sizeof(oid) * 2);
				binstance = instance;
				/* (current[0],current[1]) are
				   strictly increasing, this is our
				   lower element of our set */
				break;
			}
		}
	}
	if (binstance == NULL)
		/* No best match */
		return NULL;
	if (exact)
		/* No exact match */
		return NULL;
	/* Let's use our best match */
	memcpy(target, best, sizeof(oid) * 2);
	*length = vp->namelen + 2;
	*var_len = strlen(binstance);
	return (u_char*)binstance;
}

static vrrp_t *
_get_instance(oid *name, size_t name_len)
{
	int instance;
	element e;
	vrrp_t *vrrp = NULL;

	if (name_len < 1) return NULL;
	instance = name[name_len - 1];
	if (LIST_ISEMPTY(vrrp_data->vrrp)) return NULL;
	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (--instance == 0) break;
	}
	return vrrp;
}

static int
vrrp_snmp_instance_accept(int action,
			  u_char *var_val, u_char var_val_type,
			  size_t var_val_len, u_char *statP,
			  oid *name, size_t name_len)
{
	vrrp_t *vrrp = NULL;

	switch (action) {
	case RESERVE1:
		/* Check that the proposed value is acceptable */
		if (var_val_type != ASN_INTEGER)
			return SNMP_ERR_WRONGTYPE;
		if (var_val_len > sizeof(long))
			return SNMP_ERR_WRONGLENGTH;
		switch ((long)(*var_val)) {
		case 1:		/* enable accept */
		case 2:		/* disable accept */
			break;
		default:
			return SNMP_ERR_WRONGVALUE;
		}
		break;
	case RESERVE2:	/* Check that we can find the instance.*/
	case COMMIT:
		/* Find the instance */
		vrrp = _get_instance(name, name_len);
		if (!vrrp)
			return SNMP_ERR_NOSUCHNAME;
		if (action == RESERVE2)
			break;
		/* Commit: change values. There is no way to fail. */
		switch ((long)(*var_val)) {
		case 1:
			log_message(LOG_INFO,
				    "VRRP_Instance(%s) accept mode enabled with SNMP",
				     vrrp->iname);
// TODO - What do we do about adding/removing iptables blocks?
// RFC6527 requires the instance to be down to change this
			vrrp->accept = 1;
			break;
		case 2:
			log_message(LOG_INFO,
				    "VRRP_Instance(%s) accept mode disabled with SNMP",
				    vrrp->iname);
			vrrp->accept = 0;
			break;
			}
		break;
		}
	return SNMP_ERR_NOERROR;
}

static int
vrrp_snmp_instance_priority(int action,
			    u_char *var_val, u_char var_val_type, size_t var_val_len,
			    u_char *statP, oid *name, size_t name_len)
{
	vrrp_t *vrrp = NULL;
	switch (action) {
	case RESERVE1:
		/* Check that the proposed priority is acceptable */
		if (var_val_type != ASN_INTEGER)
			return SNMP_ERR_WRONGTYPE;
		if (var_val_len > sizeof(long))
			return SNMP_ERR_WRONGLENGTH;
		if (VRRP_IS_BAD_PRIORITY((long)(*var_val)))
			return SNMP_ERR_WRONGVALUE;
		break;
	case RESERVE2:		/* Check that we can find the instance. We should. */
	case COMMIT:
		/* Find the instance */
		vrrp = _get_instance(name, name_len);
		if (!vrrp)
			return SNMP_ERR_NOSUCHNAME;
		if (action == RESERVE2)
			break;
		/* Commit: change values. There is no way to fail. */
		log_message(LOG_INFO,
			    "VRRP_Instance(%s) base priority changed from"
			    " %d to %ld via SNMP.",
			    vrrp->iname, vrrp->base_priority, (long)(*var_val));
		vrrp->base_priority = (long)(*var_val);
		/* If we the instance is not part of a sync group, the
		   effective priority will be recomputed by some
		   thread. Otherwise, we should set it equal to the
		   base priority. */
		if (vrrp->sync)
			vrrp->effective_priority = vrrp->base_priority;
//TODO - could affect accept
		break;
	}
	return SNMP_ERR_NOERROR;
}

static int
vrrp_snmp_instance_preempt(int action,
			   u_char *var_val, u_char var_val_type, size_t var_val_len,
			   u_char *statP, oid *name, size_t name_len)
{
	vrrp_t *vrrp = NULL;
	switch (action) {
	case RESERVE1:
		/* Check that the proposed value is acceptable */
		if (var_val_type != ASN_INTEGER)
			return SNMP_ERR_WRONGTYPE;
		if (var_val_len > sizeof(long))
			return SNMP_ERR_WRONGLENGTH;
		switch ((long)(*var_val)) {
		case 1:		/* enable preemption */
		case 2:		/* disable preemption */
			break;
		default:
			return SNMP_ERR_WRONGVALUE;
		}
		break;
	case RESERVE2:		/* Check that we can find the instance. We should. */
	case COMMIT:
		/* Find the instance */
		vrrp = _get_instance(name, name_len);
		if (!vrrp) return SNMP_ERR_NOSUCHNAME;
		if (action == RESERVE2)
			break;
		/* Commit: change values. There is no way to fail. */
		switch ((long)(*var_val)) {
		case 1:
			log_message(LOG_INFO,
				    "VRRP_Instance(%s) preemption enabled with SNMP",
				    vrrp->iname);
			vrrp->nopreempt = 0;
			break;
		case 2:
			log_message(LOG_INFO,
				    "VRRP_Instance(%s) preemption disabled with SNMP",
				    vrrp->iname);
			vrrp->nopreempt = 1;
			break;
		}
		break;
	}
	return SNMP_ERR_NOERROR;
}

static u_char*
vrrp_snmp_instance(struct variable *vp, oid *name, size_t *length,
		   int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	vrrp_t *rt;

	if ((rt = (vrrp_t *)snmp_header_list_table(vp, name, length, exact,
						    var_len, write_method,
						    vrrp_data->vrrp)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_INSTANCE_NAME:
		*var_len = strlen(rt->iname);
		return (u_char *)rt->iname;
	case VRRP_SNMP_INSTANCE_VIRTUALROUTERID:
		long_ret = rt->vrid;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_STATE:
		long_ret = vrrp_snmp_state(rt->state);
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_INITIALSTATE:
		long_ret = vrrp_snmp_state(rt->init_state);
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_WANTEDSTATE:
		long_ret = vrrp_snmp_state(rt->wantstate);
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_BASEPRIORITY:
		long_ret = rt->base_priority;
		*write_method = vrrp_snmp_instance_priority;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_EFFECTIVEPRIORITY:
		long_ret = rt->effective_priority;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_VIPSENABLED:
		long_ret = rt->vipset?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_PRIMARYINTERFACE:
		*var_len = strlen(rt->ifp->ifname);
		return (u_char *)&rt->ifp->ifname;
	case VRRP_SNMP_INSTANCE_TRACKPRIMARYIF:
		long_ret = rt->track_ifp?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_ADVERTISEMENTSINT:
		long_ret = (rt->version == VRRP_VERSION_2) ?
			    rt->adver_int / TIMER_HZ :
			    rt->adver_int / TIMER_CENTI_HZ;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_PREEMPT:
		long_ret = rt->nopreempt?2:1;
		*write_method = vrrp_snmp_instance_preempt;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_PREEMPTDELAY:
		long_ret = rt->preempt_delay / TIMER_HZ;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_AUTHTYPE:
		long_ret = 0;
		if (rt->version == VRRP_VERSION_2)
#ifdef _WITH_VRRP_AUTH_
			long_ret = rt->auth_type;
#endif
		return (u_char *)&long_ret;

	case VRRP_SNMP_INSTANCE_USELVSSYNCDAEMON:
		long_ret = (global_data->lvs_syncd_vrrp == rt)?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_LVSSYNCINTERFACE:
		if (global_data->lvs_syncd_vrrp == rt) {
			*var_len = strlen(global_data->lvs_syncd_if);
			return (u_char *)global_data->lvs_syncd_if;
		}
		break;
	case VRRP_SNMP_INSTANCE_SYNCGROUP:
		if (rt->sync) {
			*var_len = strlen(rt->sync->gname);
			return (u_char *)rt->sync->gname;
		}
		break;
	case VRRP_SNMP_INSTANCE_GARPDELAY:
		long_ret = rt->garp_delay / TIMER_HZ;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_SMTPALERT:
		long_ret = rt->smtp_alert?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_NOTIFYEXEC:
		long_ret = rt->notify_exec?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_SCRIPTMASTER:
		if (rt->script_master) {
			*var_len = strlen(rt->script_master);
			return (u_char *)rt->script_master;
		}
		break;
	case VRRP_SNMP_INSTANCE_SCRIPTBACKUP:
		if (rt->script_backup) {
			*var_len = strlen(rt->script_backup);
			return (u_char *)rt->script_backup;
		}
		break;
	case VRRP_SNMP_INSTANCE_SCRIPTFAULT:
		if (rt->script_fault) {
			*var_len = strlen(rt->script_fault);
			return (u_char *)rt->script_fault;
		}
		break;
	case VRRP_SNMP_INSTANCE_SCRIPTSTOP:
		if (rt->script_stop) {
			*var_len = strlen(rt->script_stop);
			return (u_char *)rt->script_stop;
		}
		break;
	case VRRP_SNMP_INSTANCE_SCRIPT:
		if (rt->script) {
			*var_len = strlen(rt->script);
			return (u_char *)rt->script;
		}
		break;
	case VRRP_SNMP_INSTANCE_ACCEPT:
		long_ret = 0;
		if (rt->version == VRRP_VERSION_3) {
			long_ret = rt->accept ? 1:2;
			*write_method = vrrp_snmp_instance_accept;
		}
		return (u_char *)&long_ret;
	default:
		return NULL;
	}
	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_snmp_instance(vp, name, length,
					  exact, var_len, write_method);
	return NULL;
}

static u_char*
vrrp_snmp_trackedinterface(struct variable *vp, oid *name, size_t *length,
			   int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	oid *target, current[2], best[2];
	int result, target_len;
	int curinstance;
	element e1, e2;
	vrrp_t *instance;
	tracked_if_t *ifp, *bifp = NULL;

	if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
	}

	*write_method = 0;
	*var_len = sizeof(long);

	if (LIST_ISEMPTY(vrrp_data->vrrp))
		return NULL;

	/* We search the best match: equal if exact, the lower OID in
	   the set of the OID strictly superior to the target
	   otherwise. */
	best[0] = best[1] = MAX_SUBID; /* Our best match */
	target = &name[vp->namelen];   /* Our target match */
	target_len = *length - vp->namelen;
	curinstance = 0;
	for (e1 = LIST_HEAD(vrrp_data->vrrp); e1; ELEMENT_NEXT(e1)) {
		instance = ELEMENT_DATA(e1);
		curinstance++;
		if (target_len && (curinstance < target[0]))
			continue; /* Optimization: cannot be part of our set */
		if (target_len && bifp && (curinstance > target[0] + 1))
			break; /* Optimization: cannot be the lower anymore */
		if (LIST_ISEMPTY(instance->track_ifp))
			continue;
		for (e2 = LIST_HEAD(instance->track_ifp); e2; ELEMENT_NEXT(e2)) {
			ifp = ELEMENT_DATA(e2);
			/* We build our current match */
			current[0] = curinstance;
			current[1] = ifp->ifp->ifindex;
			/* And compare it to our target match */
			if ((result = snmp_oid_compare(current, 2, target,
						       target_len)) < 0)
				continue;
			if ((result == 0) && !exact)
				continue;
			if (result == 0) {
				/* Got an exact match and asked for it */
				bifp = ifp;
				goto trackedinterface_found;
			}
			if (snmp_oid_compare(current, 2, best, 2) < 0) {
				/* This is our best match */
				memcpy(best, current, sizeof(oid) * 2);
				bifp = ifp;
			}
		}
	}
	if (bifp == NULL)
		/* No best match */
		return NULL;
	if (exact)
		/* No exact match */
		return NULL;
	/* Let's use our best match */
	memcpy(target, best, sizeof(oid) * 2);
	*length = vp->namelen + 2;
 trackedinterface_found:
	switch (vp->magic) {
	case VRRP_SNMP_TRACKEDINTERFACE_NAME:
		*var_len = strlen(bifp->ifp->ifname);
		return (u_char *)bifp->ifp->ifname;
	case VRRP_SNMP_TRACKEDINTERFACE_WEIGHT:
		long_ret = bifp->weight;
		return (u_char *)&long_ret;
	}
	return NULL;
}

static u_char*
vrrp_snmp_trackedscript(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	oid *target, current[2], best[2];
	int result, target_len;
	int curinstance, curscr;
	element e1, e2;
	vrrp_t *instance;
	tracked_sc_t *scr, *bscr = NULL;

	if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
	}

	*write_method = 0;
	*var_len = sizeof(long);

	if (LIST_ISEMPTY(vrrp_data->vrrp))
		return NULL;

	/* We search the best match: equal if exact, the lower OID in
	   the set of the OID strictly superior to the target
	   otherwise. */
	best[0] = best[1] = MAX_SUBID; /* Our best match */
	target = &name[vp->namelen];   /* Our target match */
	target_len = *length - vp->namelen;
	curinstance = 0;
	for (e1 = LIST_HEAD(vrrp_data->vrrp); e1; ELEMENT_NEXT(e1)) {
		instance = ELEMENT_DATA(e1);
		curinstance++;
		if (target_len && (curinstance < target[0]))
			continue; /* Optimization: cannot be part of our set */
		if (bscr)
			break; /* Optimization, see below */
		if (LIST_ISEMPTY(instance->track_script))
			continue;
		curscr = 0;
		for (e2 = LIST_HEAD(instance->track_script); e2; ELEMENT_NEXT(e2)) {
			scr = ELEMENT_DATA(e2);
			curscr++;
			/* We build our current match */
			current[0] = curinstance;
			current[1] = curscr;
			/* And compare it to our target match */
			if ((result = snmp_oid_compare(current, 2, target,
						       target_len)) < 0)
				continue;
			if ((result == 0) && !exact)
				continue;
			if (result == 0) {
				/* Got an exact match and asked for it */
				bscr = scr;
				goto trackedscript_found;
			}
			if (snmp_oid_compare(current, 2, best, 2) < 0) {
				/* This is our best match */
				memcpy(best, current, sizeof(oid) * 2);
				bscr = scr;
				/* (current[0],current[1]) are
				   strictly increasing, this is our
				   lower element of our set */
				break;
			}
		}
	}
	if (bscr == NULL)
		/* No best match */
		return NULL;
	if (exact)
		/* No exact match */
		return NULL;
	/* Let's use our best match */
	memcpy(target, best, sizeof(oid) * 2);
	*length = vp->namelen + 2;
 trackedscript_found:
	switch (vp->magic) {
	case VRRP_SNMP_TRACKEDSCRIPT_NAME:
		*var_len = strlen(bscr->scr->sname);
		return (u_char *)bscr->scr->sname;
	case VRRP_SNMP_TRACKEDSCRIPT_WEIGHT:
		long_ret = bscr->weight;
		return (u_char *)&long_ret;
	}
	return NULL;
}

static oid vrrp_oid[] = {VRRP_OID};
static struct variable8 vrrp_vars[] = {
	/* vrrpSyncGroupTable */
	{VRRP_SNMP_SYNCGROUP_NAME, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_syncgroup, 3, {1, 1, 2}},
	{VRRP_SNMP_SYNCGROUP_STATE, ASN_INTEGER, RONLY,
	 vrrp_snmp_syncgroup, 3, {1, 1, 3}},
	{VRRP_SNMP_SYNCGROUP_SMTPALERT, ASN_INTEGER, RONLY,
	 vrrp_snmp_syncgroup, 3, {1, 1, 4}},
	{VRRP_SNMP_SYNCGROUP_NOTIFYEXEC, ASN_INTEGER, RONLY,
	 vrrp_snmp_syncgroup, 3, {1, 1, 5}},
	{VRRP_SNMP_SYNCGROUP_SCRIPTMASTER, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_syncgroup, 3, {1, 1, 6}},
	{VRRP_SNMP_SYNCGROUP_SCRIPTBACKUP, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_syncgroup, 3, {1, 1, 7}},
	{VRRP_SNMP_SYNCGROUP_SCRIPTFAULT, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_syncgroup, 3, {1, 1, 8}},
	{VRRP_SNMP_SYNCGROUP_SCRIPT, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_syncgroup, 3, {1, 1, 9}},
	/* vrrpSyncGroupMemberTable */
	{VRRP_SNMP_SYNCGROUPMEMBER_NAME, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_syncgroupmember, 3, {2, 1, 2}},
	/* vrrpInstanceTable */
	{VRRP_SNMP_INSTANCE_NAME, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 2}},
	{VRRP_SNMP_INSTANCE_VIRTUALROUTERID, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 3}},
	{VRRP_SNMP_INSTANCE_STATE, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 4}},
	{VRRP_SNMP_INSTANCE_INITIALSTATE, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 5}},
	{VRRP_SNMP_INSTANCE_WANTEDSTATE, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 6}},
	{VRRP_SNMP_INSTANCE_BASEPRIORITY, ASN_INTEGER, RWRITE,
	 vrrp_snmp_instance, 3, {3, 1, 7}},
	{VRRP_SNMP_INSTANCE_EFFECTIVEPRIORITY, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 8}},
	{VRRP_SNMP_INSTANCE_VIPSENABLED, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 9}},
	{VRRP_SNMP_INSTANCE_PRIMARYINTERFACE, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 10}},
	{VRRP_SNMP_INSTANCE_TRACKPRIMARYIF, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 11}},
	{VRRP_SNMP_INSTANCE_ADVERTISEMENTSINT, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 12}},
	{VRRP_SNMP_INSTANCE_PREEMPT, ASN_INTEGER, RWRITE,
	 vrrp_snmp_instance, 3, {3, 1, 13}},
	{VRRP_SNMP_INSTANCE_PREEMPTDELAY, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 14}},
	{VRRP_SNMP_INSTANCE_AUTHTYPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 15}},
	{VRRP_SNMP_INSTANCE_USELVSSYNCDAEMON, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 16}},
	{VRRP_SNMP_INSTANCE_LVSSYNCINTERFACE, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 17}},
	{VRRP_SNMP_INSTANCE_SYNCGROUP, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 18}},
	{VRRP_SNMP_INSTANCE_GARPDELAY, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 19}},
	{VRRP_SNMP_INSTANCE_SMTPALERT, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 20}},
	{VRRP_SNMP_INSTANCE_NOTIFYEXEC, ASN_INTEGER, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 21}},
	{VRRP_SNMP_INSTANCE_SCRIPTMASTER, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 22}},
	{VRRP_SNMP_INSTANCE_SCRIPTBACKUP, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 23}},
	{VRRP_SNMP_INSTANCE_SCRIPTFAULT, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 24}},
	{VRRP_SNMP_INSTANCE_SCRIPTSTOP, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 25}},
	{VRRP_SNMP_INSTANCE_SCRIPT, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_instance, 3, {3, 1, 26}},
	{VRRP_SNMP_INSTANCE_ACCEPT, ASN_INTEGER, RWRITE,
	 vrrp_snmp_instance, 3, {3, 1, 27} },
	/* vrrpTrackedInterfaceTable */
	{VRRP_SNMP_TRACKEDINTERFACE_NAME, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_trackedinterface, 3, {4, 1, 1}},
	{VRRP_SNMP_TRACKEDINTERFACE_WEIGHT, ASN_INTEGER, RONLY,
	 vrrp_snmp_trackedinterface, 3, {4, 1, 2}},
	/* vrrpTrackedScriptTable */
	{VRRP_SNMP_TRACKEDSCRIPT_NAME, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_trackedscript, 3, {5, 1, 2}},
	{VRRP_SNMP_TRACKEDSCRIPT_WEIGHT, ASN_INTEGER, RONLY,
	 vrrp_snmp_trackedscript, 3, {5, 1, 3}},
	/* vrrpAddressTable */
	{VRRP_SNMP_ADDRESS_ADDRESSTYPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_address, 3, {6, 1, 2}},
	{VRRP_SNMP_ADDRESS_VALUE, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_address, 3, {6, 1, 3}},
	{VRRP_SNMP_ADDRESS_BROADCAST, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_address, 3, {6, 1, 4}},
	{VRRP_SNMP_ADDRESS_MASK, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_address, 3, {6, 1, 5}},
	{VRRP_SNMP_ADDRESS_SCOPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_address, 3, {6, 1, 6}},
	{VRRP_SNMP_ADDRESS_IFINDEX, ASN_INTEGER, RONLY,
	 vrrp_snmp_address, 3, {6, 1, 7}},
	{VRRP_SNMP_ADDRESS_IFNAME, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_address, 3, {6, 1, 8}},
	{VRRP_SNMP_ADDRESS_IFALIAS, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_address, 3, {6, 1, 9}},
	{VRRP_SNMP_ADDRESS_ISSET, ASN_INTEGER, RONLY,
	 vrrp_snmp_address, 3, {6, 1, 10}},
	{VRRP_SNMP_ADDRESS_ISADVERTISED, ASN_INTEGER, RONLY,
	 vrrp_snmp_address, 3, {6, 1, 11}},
	/* vrrpRouteTable */
	{VRRP_SNMP_ROUTE_ADDRESSTYPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 2}},
	{VRRP_SNMP_ROUTE_DESTINATION, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 3}},
	{VRRP_SNMP_ROUTE_DESTINATIONMASK, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 4}},
	{VRRP_SNMP_ROUTE_GATEWAY, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 5}},
	{VRRP_SNMP_ROUTE_SECONDARYGATEWAY, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 6}},
	{VRRP_SNMP_ROUTE_SOURCE, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 7}},
	{VRRP_SNMP_ROUTE_METRIC, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 8}},
	{VRRP_SNMP_ROUTE_SCOPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 9}},
	{VRRP_SNMP_ROUTE_TYPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 10}},
	{VRRP_SNMP_ROUTE_IFINDEX, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 11}},
	{VRRP_SNMP_ROUTE_IFNAME, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 12}},
	{VRRP_SNMP_ROUTE_ROUTINGTABLE, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 13}},
	{VRRP_SNMP_ROUTE_ISSET, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 14}},
	 /* vrrpRuleTable */
	{VRRP_SNMP_RULE_DIRECTION, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 2}},
	{VRRP_SNMP_RULE_ADDRESSTYPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 3}},
	{VRRP_SNMP_RULE_ADDRESS, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 4}},
	{VRRP_SNMP_RULE_ADDRESSMASK, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 5}},
	{VRRP_SNMP_RULE_ROUTINGTABLE, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 6}},
	{VRRP_SNMP_RULE_ISSET, ASN_INTEGER, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 7}},
	/* vrrpScriptTable */
	{VRRP_SNMP_SCRIPT_NAME, ASN_OCTET_STR, RONLY, vrrp_snmp_script, 3, {9, 1, 2}},
	{VRRP_SNMP_SCRIPT_COMMAND, ASN_OCTET_STR, RONLY, vrrp_snmp_script, 3, {9, 1, 3}},
	{VRRP_SNMP_SCRIPT_INTERVAL, ASN_INTEGER, RONLY, vrrp_snmp_script, 3, {9, 1, 4}},
	{VRRP_SNMP_SCRIPT_WEIGHT, ASN_INTEGER, RONLY, vrrp_snmp_script, 3, {9, 1, 5}},
	{VRRP_SNMP_SCRIPT_RESULT, ASN_INTEGER, RONLY, vrrp_snmp_script, 3, {9, 1, 6}},
	{VRRP_SNMP_SCRIPT_RISE, ASN_UNSIGNED, RONLY, vrrp_snmp_script, 3, {9, 1, 7}},
	{VRRP_SNMP_SCRIPT_FALL, ASN_UNSIGNED, RONLY, vrrp_snmp_script, 3, {9, 1, 8}},
};


void
vrrp_snmp_instance_trap(vrrp_t *vrrp)
{
	/* OID of the notification */
	oid notification_oid[] = { VRRP_OID, 10, 0, 2 };
	size_t notification_oid_len = OID_LENGTH(notification_oid);
	/* OID for snmpTrapOID.0 */
	oid objid_snmptrap[] = { SNMPTRAP_OID };
	size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);

	/* Other OID */
	oid name_oid[] = { VRRP_OID, 3, 1, 2 };
	size_t name_oid_len = OID_LENGTH(name_oid);
	oid state_oid[] = { VRRP_OID, 3, 1, 4 };
	size_t state_oid_len = OID_LENGTH(state_oid);
	oid initialstate_oid[] = { VRRP_OID, 3, 1, 5};
	size_t initialstate_oid_len = OID_LENGTH(initialstate_oid);
	oid routerId_oid[] = { KEEPALIVED_OID, 1, 2, 0 };
	size_t routerId_oid_len = OID_LENGTH(routerId_oid);

	netsnmp_variable_list *notification_vars = NULL;

	if (!global_data->enable_traps || !global_data->enable_snmp_keepalived)
		return;

	/* snmpTrapOID */
	snmp_varlist_add_variable(&notification_vars,
				  objid_snmptrap, objid_snmptrap_len,
				  ASN_OBJECT_ID,
				  (u_char *) notification_oid,
				  notification_oid_len * sizeof(oid));
	/* vrrpInstanceName */
	snmp_varlist_add_variable(&notification_vars,
				  name_oid, name_oid_len,
				  ASN_OCTET_STR,
				  (u_char *)vrrp->iname,
				  strlen(vrrp->iname));
	/* vrrpInstanceState */
	snmp_varlist_add_variable(&notification_vars,
				  state_oid, state_oid_len,
				  ASN_INTEGER,
				  (u_char *)&vrrp->state,
				  sizeof(vrrp->state));
	/* vrrpInstanceInitialState */
	snmp_varlist_add_variable(&notification_vars,
				  initialstate_oid, initialstate_oid_len,
				  ASN_INTEGER,
				  (u_char *)&vrrp->init_state,
				  sizeof(vrrp->init_state));

	/* routerId */
	snmp_varlist_add_variable(&notification_vars,
				  routerId_oid, routerId_oid_len,
				  ASN_OCTET_STR,
				  (u_char *)global_data->router_id,
				  strlen(global_data->router_id));

	log_message(LOG_INFO,
		    "VRRP_Instance(%s): Sending SNMP notification",
		    vrrp->iname);
	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
}

void
vrrp_snmp_group_trap(vrrp_sgroup_t *group)
{
	/* OID of the notification */
	oid notification_oid[] = { VRRP_OID, 10, 0, 1 };
	size_t notification_oid_len = OID_LENGTH(notification_oid);
	/* OID for snmpTrapOID.0 */
	oid objid_snmptrap[] = { SNMPTRAP_OID };
	size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);

	/* Other OID */
	oid name_oid[] = { VRRP_OID, 1, 1, 2 };
	size_t name_oid_len = OID_LENGTH(name_oid);
	oid state_oid[] = { VRRP_OID, 1, 1, 3 };
	size_t state_oid_len = OID_LENGTH(state_oid);
	oid routerId_oid[] = { KEEPALIVED_OID, 1, 2, 0 };
	size_t routerId_oid_len = OID_LENGTH(routerId_oid);

	netsnmp_variable_list *notification_vars = NULL;

	if (!global_data->enable_traps || !global_data->enable_snmp_keepalived)
		return;

	/* snmpTrapOID */
	snmp_varlist_add_variable(&notification_vars,
				  objid_snmptrap, objid_snmptrap_len,
				  ASN_OBJECT_ID,
				  (u_char *) notification_oid,
				  notification_oid_len * sizeof(oid));

	/* vrrpSyncGroupName */
	snmp_varlist_add_variable(&notification_vars,
				  name_oid, name_oid_len,
				  ASN_OCTET_STR,
				  (u_char *)group->gname,
				  strlen(group->gname));
	/* vrrpSyncGroupState */
	snmp_varlist_add_variable(&notification_vars,
				  state_oid, state_oid_len,
				  ASN_INTEGER,
				  (u_char *)&group->state,
				  sizeof(group->state));

	/* routerId */
	snmp_varlist_add_variable(&notification_vars,
				  routerId_oid, routerId_oid_len,
				  ASN_OCTET_STR,
				  (u_char *)global_data->router_id,
				  strlen(global_data->router_id));

	log_message(LOG_INFO,
		    "VRRP_Group(%s): Sending SNMP notification",
		    group->gname);
	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
}
#endif


#if defined _WITH_SNMP_RFC_
/* Convert VRRP state to RFC SNMP state */
static unsigned long
vrrp_snmp_rfc_state(int state)
{
	if (state <= VRRP_STATE_MAST)
		return state + 1;
	if (state == VRRP_STATE_FAULT ||
	    state == VRRP_STATE_GOTO_FAULT)
		return VRRP_STATE_INIT + 1;
	if (state == VRRP_STATE_GOTO_MASTER)
		return VRRP_STATE_BACK + 1;
	return VRRP_STATE_INIT + 1;
}
#endif

#ifdef _WITH_SNMP_RFCV2_
static bool
suitable_for_rfc2787(vrrp_t* vrrp)
{
	/* We mustn't return any VRRP instances that aren't version 2 */
	if (vrrp->version != VRRP_VERSION_2)
		return false;

	/* We have to skip VRRPv2 with IPv6 since it won't be understood */
	if (vrrp->family == AF_INET6)
		return false;

	/* We are expected to have at least one VIP */
	if (LIST_ISEMPTY(vrrp->vip))
		return false;

	return true;
}

static ip_address_t*
vrrp_rfcv2_header_ar_table(struct variable *vp, oid *name, size_t *length,
		     int exact, size_t *var_len, WriteMethod **write_method)
{
	element e, e2;
	ip_address_t *vip;
	vrrp_t *scr;
	ip_address_t *bel = NULL;
	oid * target, current[2], best[2];
	struct in_addr best_addr, target_addr, current_addr;
	int result, result2 = 0;
	size_t target_len;
	bool found_exact = false;
	bool found_better;

	*write_method = 0;
	*var_len = sizeof(unsigned long);

	if (LIST_ISEMPTY(vrrp_data->vrrp))
		return NULL;

	if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
	}

	/* We search the best match: equal if exact, the lower OID in
	   the set of the OID strictly superior to the target
	   otherwise. */
	best[0] = best[1] = MAX_SUBID; /* Our best match */
	best_addr.s_addr = 0xffffffff;
	target = &name[vp->namelen];   /* Our target match */
	target_len = *length - vp->namelen;
	if (target_len > 2 ) {
		target_len = 2;
		target_addr.s_addr = name[*length - 4] << 24 |
				     name[*length - 3] << 16 |
				     name[*length - 2] << 8 |
				     name[*length - 1];
	}
	else
		target_addr.s_addr = 0;

	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		scr = (vrrp_t *)ELEMENT_DATA(e);

		if (!suitable_for_rfc2787(scr))
			continue;

		current[0] = IF_BASE_INDEX(scr->ifp);
		current[1] = scr->vrid;

		if ((result = snmp_oid_compare(current, 2, target, target_len)) < 0)
			continue;

		if (exact) {
			if (result > 0)
				continue;
		}
		else {
			if ((result2 = snmp_oid_compare(current, 2, best, 2)) > 0)
				continue;
		}

		if (LIST_ISEMPTY(scr->vip)) {
			if (exact)
				return NULL;
			continue;
		}

		found_better = false;
		for (e2 = LIST_HEAD(scr->vip); e2; ELEMENT_NEXT(e2)) {
			vip = ELEMENT_DATA(e2);

			/* We need the address to be MSB first, for numerical comparison */
			current_addr.s_addr = htonl(vip->u.sin.sin_addr.s_addr);

			if (exact) {
				if (target_addr.s_addr == current_addr.s_addr) {
					memcpy(best, current, sizeof(best));
					best_addr = current_addr;
					bel = vip;
					found_exact = true;
					break;
				}

				continue;
			}

			if (result == 0 && target_len && current_addr.s_addr <= target_addr.s_addr)
				continue;
			if (result2 == 0 && current_addr.s_addr >= best_addr.s_addr)
				continue;

			memcpy(best, current, sizeof(best));
			best_addr = current_addr;
			bel = vip;
			result2 = 0;
			found_better = true;
		}

		if (found_exact)
			break;
		if (exact)
			return NULL;
		if (result == 0 && found_better)
			break;
	}

	if (bel == NULL)	/* No best match */
		return NULL;
	if (exact && !found_exact) /* No exact match */
		return NULL;

	/* Let's use our best match */
	memcpy(target, best, sizeof(best));
	*length = vp->namelen + 2;
	name[*length]   =  best_addr.s_addr >> 24;
	name[*length+1] = (best_addr.s_addr >> 16) & 0xff;
	name[*length+2] = (best_addr.s_addr >>  8) & 0xff;
	name[*length+3] = (best_addr.s_addr      ) & 0xff;
	*length += 4;

	return bel;
}

static u_char*
vrrp_rfcv2_snmp_node_info(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;

	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;

	if (vp->magic == VRRP_RFC_SNMP_NODE_VER) {
		long_ret = 2;
		return (u_char*)&long_ret;
	}

	if (vp->magic == VRRP_RFC_SNMP_NOTIF_CNTL) {
		long_ret = global_data->enable_traps ? 1 : 2 ;
		return (u_char*)&long_ret;
	}

	return NULL;
}

static vrrp_t*
snmp_rfcv2_header_list_table(struct variable *vp, oid *name, size_t *length,
		  int exact, size_t *var_len, WriteMethod **write_method)
{
	element e;
	vrrp_t *bel = NULL, *scr;
	oid * target, current[2], best[2];
	int result;
	size_t target_len;

	*write_method = 0;
	*var_len = sizeof (unsigned long);

	if (LIST_ISEMPTY(vrrp_data->vrrp))
		return NULL;

	if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
	}

	/* We search the best match: equal if exact, the lower OID in
	   the set of the OID strictly superior to the target
	   otherwise. */
	best[0] = best[1] = MAX_SUBID; /* Our best match */
	target = &name[vp->namelen];   /* Our target match */
	target_len = *length - vp->namelen;

	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		scr = (vrrp_t *)ELEMENT_DATA(e);

		if (!suitable_for_rfc2787(scr))
			continue;

		if (target_len && (IF_BASE_INDEX(scr->ifp) < target[0]))
			continue; /* Optimization: cannot be part of our set */

		current[0] = IF_BASE_INDEX(scr->ifp);
		current[1] = scr->vrid;
		if ((result = snmp_oid_compare(current, 2, target, target_len)) < 0)
			continue;
		if (result == 0) {
			if (!exact)
				continue;
			return scr;
		}

		if (snmp_oid_compare(current, 2, best, 2) < 0) {
			/* This is our best match */
			memcpy(best, current, sizeof(best));

			bel = scr;
		}
	}

	if (bel == NULL)
		/* No best match */
		return NULL;
	if (exact)
		/* No exact match */
		return NULL;
	/* Let's use our best match */
	memcpy(target, best, sizeof(best));
	*length = vp->namelen + 2;
	return bel;
}

static u_char*
vrrp_rfcv2_snmp_opertable(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	vrrp_t *rt;
	interface_t* ifp;
	timeval_t uptime;

	if ((rt = snmp_rfcv2_header_list_table(vp, name, length, exact,
					     var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_RFC_SNMP_OPER_VRID:
		long_ret = rt->vrid;
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_VMAC:
		*var_len = rt->ifp->hw_addr_len;
		return (u_char*)&rt->ifp->hw_addr;
	case VRRP_RFC_SNMP_OPER_STATE:
		long_ret = vrrp_snmp_rfc_state(rt->state);
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_ADM_STATE:
		/* If we implement write access, then this could be 2 for down */
		long_ret = 1;
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_PRI:
		long_ret = rt->base_priority;
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_ADDR_CNT:
		if (LIST_ISEMPTY(rt->vip))
			long_ret = 0;
		else
			long_ret = LIST_SIZE(rt->vip);
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_MIP:
		return (u_char*)&((struct sockaddr_in *)&rt->master_saddr)->sin_addr.s_addr;
	case VRRP_RFC_SNMP_OPER_PIP:
		if (rt->ifp->vmac)
			ifp = if_get_by_ifindex(rt->ifp->base_ifindex);
		else
			ifp = rt->ifp;
		return (u_char*)&ifp->sin_addr;
	case VRRP_RFC_SNMP_OPER_AUTH_TYPE:
#ifdef _WITH_VRRP_AUTH_
		long_ret = rt->auth_type + 1;
#else
		long_ret = 1;
#endif
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_AUTH_KEY:
		*var_len = 0;		// Not readable
		return NULL;
	case VRRP_RFC_SNMP_OPER_ADVERT_INT:
		long_ret = rt->adver_int / TIMER_HZ;
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_PREEMPT:
		long_ret =  1 + rt->nopreempt;
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_VR_UPTIME:
		if (rt->state == VRRP_STATE_BACK ||
		    rt->state == VRRP_STATE_MAST) {
			uptime = timer_sub(rt->stats->uptime, vrrp_start_time);
			long_ret = uptime.tv_sec * 100 + uptime.tv_usec / 10000;	// unit is centi-seconds
		}
		else
			long_ret = 0;
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_PROTO:
		long_ret = 1;	// IP
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_ROW_STAT:
		long_ret = 1;	// active - 1, notInService - 2, notReady - 3, createAndGo - 4, createAndWait - 5
		return (u_char*)&long_ret;
	}

	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_rfcv2_snmp_opertable(vp, name, length,
					  exact, var_len, write_method);

	return NULL;
}

static u_char*
vrrp_rfcv2_snmp_assoiptable(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	ip_address_t *addr;

	if (snmp_oid_compare(name, *length, vp->name, vp->namelen) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
		*var_len = 0;
		return NULL;
	}
	if ((addr = vrrp_rfcv2_header_ar_table(vp, name, length, exact,
				  var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_RFC_SNMP_ASSOC_IP_ADDR:
		return (u_char*)&addr->u.sin.sin_addr;
	case VRRP_RFC_SNMP_ASSOC_IP_ADDR_ROW:
		/* If we implement write access, then this could be 2 for down */
		long_ret = 1;
		return (u_char*)&long_ret;
	}

	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_rfcv2_snmp_assoiptable(vp, name, length,
					  exact, var_len, write_method);

	return NULL;
}

static u_char*
vrrp_rfcv2_snmp_stats(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret = 0;
	element e;
	vrrp_t *vrrp;

	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;

	if (vp->magic != VRRP_RFC_SNMP_STATS_CHK_ERR &&
	    vp->magic != VRRP_RFC_SNMP_STATS_VER_ERR &&
	    vp->magic != VRRP_RFC_SNMP_STATS_VRID_ERR)
		return NULL;

	if (LIST_ISEMPTY(vrrp_data->vrrp))
		return (u_char*)&long_ret;

	/* Work through all the vrrp instances that we can respond for */
	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		if (!suitable_for_rfc2787(vrrp))
			continue;

		switch (vp->magic) {
		case VRRP_RFC_SNMP_STATS_CHK_ERR:
			long_ret += vrrp->stats->chk_err;
			break;
		case VRRP_RFC_SNMP_STATS_VER_ERR:
			long_ret += vrrp->stats->vers_err;
			break;
		case VRRP_RFC_SNMP_STATS_VRID_ERR:
			long_ret += vrrp->stats->vrid_err;
			break;
		}
	}

	return (u_char *)&long_ret;
}
static u_char*
vrrp_rfcv2_snmp_statstable(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	vrrp_t *rt;

	if ((rt = snmp_rfcv2_header_list_table(vp, name, length, exact,
					     var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_RFC_SNMP_STATS_MASTER:
		long_ret = rt->stats->become_master;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_ADV_RCVD:
		long_ret = rt->stats->advert_rcvd;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_ADV_INT_ERR:
		long_ret = rt->stats->advert_interval_err;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_AUTH_FAIL:
		long_ret = rt->stats->auth_failure;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_TTL_ERR:
		long_ret = rt->stats->ip_ttl_err;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_PRI_0_RCVD:
		long_ret = rt->stats->pri_zero_rcvd;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_PRI_0_SENT:
		long_ret = rt->stats->pri_zero_sent;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_INV_TYPE_RCVD:
		long_ret = rt->stats->invalid_type_rcvd;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_ADDR_LIST_ERR:
		long_ret = rt->stats->addr_list_err;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_AUTH_INV:
		long_ret = rt->stats->invalid_authtype;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_AUTH_MIS:
		long_ret = rt->stats->authtype_mismatch;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_PL_ERR:
		long_ret = rt->stats->packet_len_err;
		return (u_char *)&long_ret;
	}

	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_rfcv2_snmp_statstable(vp, name, length,
					  exact, var_len, write_method);

	return NULL;
}

static oid vrrp_rfcv2_oid[] = {VRRP_RFC_OID};
static struct variable8 vrrp_rfcv2_vars[] = {
	{ VRRP_RFC_SNMP_NODE_VER, ASN_INTEGER, RONLY,
	  vrrp_rfcv2_snmp_node_info, 2, {1, 1}},
	{ VRRP_RFC_SNMP_NOTIF_CNTL, ASN_INTEGER, RONLY,
	  vrrp_rfcv2_snmp_node_info, 2, {1, 2}},
	/* vrrpOperTable */
	{ VRRP_RFC_SNMP_OPER_VRID, ASN_INTEGER, RONLY,
	  vrrp_rfcv2_snmp_opertable, 4, {1, 3, 1, 1}},
	{ VRRP_RFC_SNMP_OPER_VMAC, ASN_OCTET_STR, RONLY,
	  vrrp_rfcv2_snmp_opertable, 4, {1, 3, 1, 2}},
	{ VRRP_RFC_SNMP_OPER_STATE, ASN_INTEGER, RONLY,
	  vrrp_rfcv2_snmp_opertable, 4, {1, 3, 1, 3}},
	{ VRRP_RFC_SNMP_OPER_ADM_STATE, ASN_INTEGER, RONLY,
	  vrrp_rfcv2_snmp_opertable, 4, {1, 3, 1, 4}},
	{ VRRP_RFC_SNMP_OPER_PRI, ASN_INTEGER, RONLY,
	  vrrp_rfcv2_snmp_opertable, 4, {1, 3, 1, 5}},
	{ VRRP_RFC_SNMP_OPER_ADDR_CNT, ASN_INTEGER, RONLY,
	  vrrp_rfcv2_snmp_opertable, 4, {1, 3, 1, 6}},
	{ VRRP_RFC_SNMP_OPER_MIP, ASN_IPADDRESS, RONLY,
	  vrrp_rfcv2_snmp_opertable, 4, {1, 3, 1, 7}},
	{ VRRP_RFC_SNMP_OPER_PIP, ASN_IPADDRESS, RONLY,
	  vrrp_rfcv2_snmp_opertable, 4, {1, 3, 1, 8}},
	{ VRRP_RFC_SNMP_OPER_AUTH_TYPE, ASN_INTEGER, RONLY,
	  vrrp_rfcv2_snmp_opertable, 4, {1, 3, 1, 9}},
	{ VRRP_RFC_SNMP_OPER_AUTH_KEY, ASN_OCTET_STR, RONLY,
	  vrrp_rfcv2_snmp_opertable, 4, {1, 3, 1, 10}},
	{ VRRP_RFC_SNMP_OPER_ADVERT_INT, ASN_INTEGER, RONLY,
	  vrrp_rfcv2_snmp_opertable, 4, {1, 3, 1, 11}},
	{ VRRP_RFC_SNMP_OPER_PREEMPT, ASN_INTEGER, RONLY,
	  vrrp_rfcv2_snmp_opertable, 4, {1, 3, 1, 12}},
	{ VRRP_RFC_SNMP_OPER_VR_UPTIME, ASN_TIMETICKS, RONLY,
	  vrrp_rfcv2_snmp_opertable, 4, {1, 3, 1, 13}},
	{ VRRP_RFC_SNMP_OPER_PROTO, ASN_INTEGER, RONLY,
	  vrrp_rfcv2_snmp_opertable, 4, {1, 3, 1, 14}},
	{ VRRP_RFC_SNMP_OPER_ROW_STAT, ASN_INTEGER, RONLY,
	  vrrp_rfcv2_snmp_opertable, 4, {1, 3, 1, 15}},
	/* vrrpAssoIpAddrTable */
	{ VRRP_RFC_SNMP_ASSOC_IP_ADDR, ASN_IPADDRESS, RONLY,
	  vrrp_rfcv2_snmp_assoiptable, 4, {1, 4, 1, 1}},
	{ VRRP_RFC_SNMP_ASSOC_IP_ADDR_ROW, ASN_INTEGER, RONLY,
	  vrrp_rfcv2_snmp_assoiptable, 4, {1, 4, 1, 2}},
	/* vrrpRouterStats */
	{ VRRP_RFC_SNMP_STATS_CHK_ERR, ASN_COUNTER, RONLY,
	  vrrp_rfcv2_snmp_stats, 2, {2, 1}},
	{ VRRP_RFC_SNMP_STATS_VER_ERR, ASN_COUNTER, RONLY,
	  vrrp_rfcv2_snmp_stats, 2, {2, 2}},
	{ VRRP_RFC_SNMP_STATS_VRID_ERR, ASN_COUNTER, RONLY,
	  vrrp_rfcv2_snmp_stats, 2, {2, 3}},
	/* vrrpRouterStatsTable */
	{ VRRP_RFC_SNMP_STATS_MASTER, ASN_COUNTER, RONLY,
	  vrrp_rfcv2_snmp_statstable, 4, {2, 4, 1, 1}},
	{ VRRP_RFC_SNMP_STATS_ADV_RCVD, ASN_COUNTER, RONLY,
	  vrrp_rfcv2_snmp_statstable, 4, {2, 4, 1, 2}},
	{ VRRP_RFC_SNMP_STATS_ADV_INT_ERR, ASN_COUNTER, RONLY,
	  vrrp_rfcv2_snmp_statstable, 4, {2, 4, 1, 3}},
	{ VRRP_RFC_SNMP_STATS_AUTH_FAIL, ASN_COUNTER, RONLY,
	  vrrp_rfcv2_snmp_statstable, 4, {2, 4, 1, 4}},
	{ VRRP_RFC_SNMP_STATS_TTL_ERR, ASN_COUNTER, RONLY,
	  vrrp_rfcv2_snmp_statstable, 4, {2, 4, 1, 5}},
	{ VRRP_RFC_SNMP_STATS_PRI_0_RCVD, ASN_COUNTER, RONLY,
	  vrrp_rfcv2_snmp_statstable, 4, {2, 4, 1, 6}},
	{ VRRP_RFC_SNMP_STATS_PRI_0_SENT, ASN_COUNTER , RONLY,
	  vrrp_rfcv2_snmp_statstable, 4, {2, 4, 1, 7}},
	{ VRRP_RFC_SNMP_STATS_INV_TYPE_RCVD, ASN_COUNTER, RONLY,
	  vrrp_rfcv2_snmp_statstable, 4, {2, 4, 1, 8}},
	{ VRRP_RFC_SNMP_STATS_ADDR_LIST_ERR, ASN_COUNTER, RONLY,
	  vrrp_rfcv2_snmp_statstable, 4, {2, 4, 1, 9}},
	{ VRRP_RFC_SNMP_STATS_AUTH_INV, ASN_COUNTER, RONLY,
	  vrrp_rfcv2_snmp_statstable, 4, {2, 4, 1, 10}},
	{ VRRP_RFC_SNMP_STATS_AUTH_MIS, ASN_COUNTER, RONLY,
	  vrrp_rfcv2_snmp_statstable, 4, {2, 4, 1, 11}},
	{ VRRP_RFC_SNMP_STATS_PL_ERR, ASN_COUNTER, RONLY,
	  vrrp_rfcv2_snmp_statstable, 4, {2, 4, 1, 12}}
};

void
vrrp_rfcv2_snmp_new_master_trap(vrrp_t *vrrp)
{
	/* OID of the notification vrrpTrapNewMaster */
	oid notification_oid[] = { VRRP_RFC_TRAP_OID, 1 };
	size_t notification_oid_len = OID_LENGTH(notification_oid);
	/* OID for snmpTrapOID.0 */
	oid objid_snmptrap[] = { SNMPTRAP_OID };
	size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);
	/* OID for trap data vrrpOperMasterIPAddr */
	oid masterip_oid[] = { VRRP_RFC_OID, 1, 3, 1, 7, IF_BASE_INDEX(vrrp->ifp), vrrp->vrid };
	size_t masterip_oid_len = OID_LENGTH(masterip_oid);

	netsnmp_variable_list *notification_vars = NULL;

	if (!global_data->enable_traps || !global_data->enable_snmp_rfcv2)
		return;

	if (!suitable_for_rfc2787(vrrp))
		return;

	/* snmpTrapOID */
	snmp_varlist_add_variable(&notification_vars,
				  objid_snmptrap, objid_snmptrap_len,
				  ASN_OBJECT_ID,
				  (u_char *) notification_oid,
				  notification_oid_len * sizeof(oid));
	/* vrrpInstanceName */
	snmp_varlist_add_variable(&notification_vars,
				  masterip_oid, masterip_oid_len,
				  ASN_IPADDRESS,
				  (u_char *)&((struct sockaddr_in *)&vrrp->saddr)->sin_addr.s_addr,
				  sizeof(((struct sockaddr_in *)&vrrp->saddr)->sin_addr.s_addr));
	log_message(LOG_INFO, "VRRP_Instance(%s): Sending SNMP notification"
			      " vrrpTrapNewMaster"
			    , vrrp->iname);
	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
}

void
vrrp_rfcv2_snmp_auth_err_trap(vrrp_t *vrrp, struct in_addr src, enum rfcv2_trap_auth_error_type auth_err)
{
	/* OID of the notification vrrpTrapNewMaster */
	oid notification_oid[] = { VRRP_RFC_TRAP_OID, 2 };
	size_t notification_oid_len = OID_LENGTH(notification_oid);
	/* OID for snmpTrapOID.0 */
	oid objid_snmptrap[] = { SNMPTRAP_OID };
	size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);
	/* OID for trap data vrrpTrapPacketSrc */
	oid packet_src_oid[] = { VRRP_RFC_OID, 1, 5, IF_INDEX(vrrp->ifp), vrrp->vrid };
	size_t packet_src_oid_len = OID_LENGTH(packet_src_oid);
	/* OID for trap data vrrpTrapAuthErrorType */
	oid err_type_oid[] = { VRRP_RFC_OID, 1, 6, IF_INDEX(vrrp->ifp), vrrp->vrid };
	size_t err_type_oid_len = OID_LENGTH(err_type_oid);

	netsnmp_variable_list *notification_vars = NULL;

	if (!global_data->enable_traps || !global_data->enable_snmp_rfcv2)
		return;

	if (!suitable_for_rfc2787(vrrp))
		return;

	/* snmpTrapOID */
	snmp_varlist_add_variable(&notification_vars,
				  objid_snmptrap, objid_snmptrap_len,
				  ASN_OBJECT_ID,
				  (u_char *) notification_oid,
				  notification_oid_len * sizeof(oid));
	/* vrrpPacketSrc */
	snmp_varlist_add_variable(&notification_vars,
				  packet_src_oid, packet_src_oid_len,
				  ASN_IPADDRESS,
				  (u_char *)&src,
				  sizeof(src));
	/* vrrpAuthErrorType */
	snmp_varlist_add_variable(&notification_vars,
				  err_type_oid, err_type_oid_len,
				  ASN_INTEGER,
				  (u_char *)&auth_err,
				  sizeof(auth_err));
	log_message(LOG_INFO, "VRRP_Instance(%s): Sending SNMP notification"
			      " vrrpTrapAuthFailure"
			    , vrrp->iname);
	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
}
#endif

#ifdef _WITH_SNMP_RFCV3_

/* Enable returning detail of VRRP version 2 instances as well as version 3 instances */
#define SNMP_REPLY_V3_FOR_V2

/* For some reason net-snmp doesn't use a uint64_t for 64 bit counters, but rather uses
 * a struct, with the high word at the lower address, so we need to assign values according. */
static void inline
set_counter64 (struct counter64 *c64, uint64_t val)
{
	c64->high = val >> 32;
	c64->low = val & 0xffffffff;
}

static bool
suitable_for_rfc6527(vrrp_t* vrrp)
{
#ifndef SNMP_REPLY_V3_FOR_V2
	/* We mustn't return any VRRP instances that don't match version */
	if (vrrp->version != VRRP_VERSION_3)
		return false;
#endif

	/* We are expected to have at least one VIP */
	if (LIST_ISEMPTY(vrrp->vip))
		return false;

	return true;
}

static inline int
inet6_addr_compare(const struct in6_addr* l, const struct in6_addr* r)
{
	int i;
	uint32_t l1, r1;

	for (i = 0; i < sizeof(l->s6_addr32) / sizeof(l->s6_addr32[0]); i++)
	{
		l1 = htonl(l->s6_addr32[i]);
		r1 = htonl(r->s6_addr32[i]);
		if (l1 != r1)
			return ((l1 > r1) & 1) * 2 - 1;
	}

	return 0;
}

static ip_address_t*
vrrp_rfcv3_header_ar_table(struct variable *vp, oid *name, size_t *length,
		     int exact, size_t *var_len, WriteMethod **write_method)
{
	element e, e2;
	ip_address_t *vip;
	vrrp_t *scr;
	ip_address_t *bel = NULL;
	oid * target, current[3], best[3];
	struct in_addr target_addr, current_addr, best_addr;
	struct in6_addr target_addr6, current_addr6, best_addr6;
	int result, result2 = 0;
	size_t target_len;
	bool found_exact = false;
	bool found_better;
	int i;

	*write_method = 0;
	*var_len = sizeof(unsigned long);

	if (LIST_ISEMPTY(vrrp_data->vrrp))
		return NULL;

	if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
	}

	/* We search the best match: equal if exact, the lower OID in
	   the set of the OID strictly superior to the target
	   otherwise. */
	best[0] = best[1] = best[2] = MAX_SUBID; /* Our best match */
	best_addr.s_addr = 0xffffffff;
	memset(&best_addr6, 0xff, sizeof(best_addr6));
	target = &name[vp->namelen];   /* Our target match */
	target_len = *length - vp->namelen;
	target_addr.s_addr = 0;		/* Avoid compiler uninitialised warning */
	if (target_len == 3 + 1 + 4 ) {
		target_len = 3;
		target_addr.s_addr = name[*length - 4] << 24 |
				     name[*length - 3] << 16 |
				     name[*length - 2] << 8 |
				     name[*length - 1];
	}
	else if (target_len == 3 + 1 + 16) {
		target_len = 3;
		for (i = 0; i < 16; i++)
			target_addr6.s6_addr[i] = name[*length - 16 + i];
	}

	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		scr = (vrrp_t *)ELEMENT_DATA(e);

		if (!suitable_for_rfc6527(scr))
			continue;

		current[0] = IF_BASE_INDEX(scr->ifp);
		current[1] = scr->vrid;
		current[2] = scr->family == AF_INET ? 1 : 2;

		if ((result = snmp_oid_compare(current, 3, target, target_len)) < 0)
			continue;

		if (exact) {
			if (result != 0)
				continue;
		}
		else {
			if ((result2 = snmp_oid_compare(current, 3, best, 3)) > 0)
				continue;
		}

		if (LIST_ISEMPTY(scr->vip)) {
			if (exact)
				return NULL;
			continue;
		}

		found_better = false;
		for (e2 = LIST_HEAD(scr->vip); e2; ELEMENT_NEXT(e2)) {
			vip = ELEMENT_DATA(e2);

			if (scr->family == AF_INET) {
				current_addr.s_addr = htons(vip->u.sin.sin_addr.s_addr);

				if (exact) {
					if (target_addr.s_addr == current_addr.s_addr) {
						memcpy(best, current, sizeof(best));
						best_addr = current_addr;
						bel = vip;
						found_exact = true;
						break;
					}

					continue;
				}

				if (result == 0 && target_len && current_addr.s_addr <= target_addr.s_addr)
					continue;
				if (result2 == 0 && current_addr.s_addr >= best_addr.s_addr)
					continue;

				memcpy(best, current, sizeof(best));
				best_addr = current_addr;
				bel = vip;
				result2 = 0;
				found_better = true;
			}
			else
			{
				current_addr6 = vip->u.sin6_addr;

				if (exact) {
					if (inet6_addr_compare(&target_addr6, &current_addr6) == 0) {
						memcpy(best, current, sizeof(best));
						best_addr6 = current_addr6;
						bel = vip;
						found_exact = true;
						break;
					}

					continue;
				}
				if (result == 0 && target_len && inet6_addr_compare(&current_addr6, &target_addr6) <= 0)
					continue;
				if (result2 == 0 && inet6_addr_compare(&current_addr6, &best_addr6) >= 0)
					continue;

				memcpy(best, current, sizeof(best));
				best_addr6 = current_addr6;
				bel = vip;
				result2 = 0;
				found_better = true;
			}
		}

		if (found_exact)
			break;
		if (exact)
			return NULL;
		if (result == 0 && found_better)
			break;
	}

	if (bel == NULL)	/* No best match */
		return NULL;
	if (exact && !found_exact) /* No exact match */
		return NULL;

	/* Let's use our best match */
	memcpy(target, best, sizeof(best));
	*length = vp->namelen + 3;
	if (name[*length - 1] == 1) {
		name[*length] = sizeof(struct in_addr);
		*length += 1;
		name[*length  ] =  best_addr.s_addr >> 24;
		name[*length+1] = (best_addr.s_addr >> 16) & 0xff;
		name[*length+2] = (best_addr.s_addr >>  8) & 0xff;
		name[*length+3] = (best_addr.s_addr      ) & 0xff;
		*length += sizeof(struct in_addr);
	}
	else {
		name[*length] = sizeof(struct in6_addr);
		*length += 1;
		for (i = 0; i < sizeof(struct in6_addr); i++)
			name[*length + i] = best_addr6.s6_addr[i];
		*length += sizeof(struct in6_addr);
	}

	return bel;
}

static vrrp_t*
snmp_rfcv3_header_list_table(struct variable *vp, oid *name, size_t *length,
		  int exact, size_t *var_len, WriteMethod **write_method)
{
	element e;
	vrrp_t *bel = NULL, *scr;
	oid * target, current[3], best[3];
	int result;
	size_t target_len;

	*write_method = 0;
	*var_len = sizeof (unsigned long);

	if (LIST_ISEMPTY(vrrp_data->vrrp))
		return NULL;

	if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
	}

	/* We search the best match: equal if exact, the lower OID in
	   the set of the OID strictly superior to the target
	   otherwise. */
	best[0] = best[1] = best[2] = MAX_SUBID; /* Our best match */
	target = &name[vp->namelen];   /* Our target match */
	target_len = *length - vp->namelen;

	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		scr = (vrrp_t *)ELEMENT_DATA(e);

		if (!suitable_for_rfc6527(scr))
			continue;

		if (target_len && (IF_BASE_INDEX(scr->ifp) < target[0] ||
				   (IF_BASE_INDEX(scr->ifp) == target[0] &&
				    scr->vrid < target[1])))
			continue; /* Optimization: cannot be part of our set */

		current[0] = IF_BASE_INDEX(scr->ifp);
		current[1] = scr->vrid;
		current[2] = scr->family == AF_INET ? 1 : 2;
		if ((result = snmp_oid_compare(current, 3, target, target_len)) < 0)
			continue;
		if (result == 0) {
			if (!exact)
				continue;
			return scr;
		}

		if (snmp_oid_compare(current, 3, best, 3) < 0) {
			/* This is our best match */
			memcpy(best, current, sizeof(best));

			bel = scr;
		}
	}

	if (bel == NULL)
		/* No best match */
		return NULL;
	if (exact)
		/* No exact match */
		return NULL;
	/* Let's use our best match */
	memcpy(target, best, sizeof(best));
	*length = vp->namelen + 3;
	return bel;
}

static u_char*
vrrp_rfcv3_snmp_opertable(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	vrrp_t *rt;
	interface_t* ifp;
	timeval_t uptime;

	if ((rt = snmp_rfcv3_header_list_table(vp, name, length, exact,
					     var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_RFCv3_SNMP_OPER_VRID:
		long_ret = rt->vrid;
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_INET_ADDR_TYPE:
		long_ret = rt->family == AF_INET ? 1 : 2;
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_MIP:
		if (rt->state != VRRP_STATE_MAST) {
			if (rt->family == AF_INET) {
				*var_len = sizeof(struct in_addr);
				return (u_char*)&((struct sockaddr_in *)&rt->master_saddr)->sin_addr;
			}
			*var_len = sizeof(struct in6_addr);
			return (u_char*)&((struct sockaddr_in6 *)&rt->master_saddr)->sin6_addr;
		}
		/* Fall through. If we are master, we want to return the Primary IP address */
	case VRRP_RFCv3_SNMP_OPER_PIP:
		if (rt->ifp->vmac)
			ifp = if_get_by_ifindex(rt->ifp->base_ifindex);
		else
			ifp = rt->ifp;
		if (rt->family == AF_INET) {
			*var_len = sizeof(struct in_addr);
			return (u_char*)&ifp->sin_addr;
		}
		*var_len = sizeof(struct in6_addr);
		return (u_char*)&ifp->sin6_addr;
	case VRRP_RFCv3_SNMP_OPER_VMAC:
		*var_len = rt->ifp->hw_addr_len;
		return (u_char*)&rt->ifp->hw_addr;
	case VRRP_RFCv3_SNMP_OPER_STATE:
		long_ret = vrrp_snmp_rfc_state(rt->state);
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_PRI:
		long_ret = rt->base_priority;
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_ADDR_CNT:
		if (LIST_ISEMPTY(rt->vip))
			long_ret = 0;
		else
			long_ret = LIST_SIZE(rt->vip);
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_ADVERT_INT:
		long_ret = rt->adver_int / TIMER_CENTI_HZ;
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_PREEMPT:
		long_ret =  1 + rt->nopreempt;
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_ACCEPT:
		long_ret =  1 + rt->accept;
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_VR_UPTIME:
		if (rt->state == VRRP_STATE_BACK ||
		    rt->state == VRRP_STATE_MAST) {
			uptime = timer_sub(rt->stats->uptime, vrrp_start_time);
			long_ret = uptime.tv_sec * 100 + uptime.tv_usec / 10000;	// unit is centi-seconds
		}
		else
			long_ret = 0;
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_ROW_STATUS:
		long_ret = 1;	// active - 1, notInService - 2, notReady - 3, createAndGo - 4, createAndWait - 5
		return (u_char*)&long_ret;
	}

	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_rfcv3_snmp_opertable(vp, name, length,
					  exact, var_len, write_method);

	return NULL;
}

static u_char*
vrrp_rfcv3_snmp_assoiptable(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	ip_address_t *addr;

	if (snmp_oid_compare(name, *length, vp->name, vp->namelen) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
		*var_len = 0;
	}
	if ((addr = vrrp_rfcv3_header_ar_table(vp, name, length, exact,
				  var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_RFCv3_SNMP_ASSOC_IP_ADDR:
		if (addr->ifa.ifa_family == AF_INET) {
			*var_len = sizeof(struct in_addr);
			return (u_char*)&addr->u.sin.sin_addr;
		}
		*var_len = sizeof(struct in6_addr);
		return (u_char*)&addr->u.sin6_addr;
	case VRRP_RFCv3_SNMP_ASSOC_IP_ADDR_ROW_STATUS:
		/* If we implement write access, then this could be 2 for down */
		long_ret = 1;
		return (u_char*)&long_ret;
	}

	/* If we are here, we asked for a non existent data. Try the
	   next one.
	   NOTE: This never appears to be true, so could be removed.
	 */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_rfcv3_snmp_assoiptable(vp, name, length,
					  exact, var_len, write_method);

	return NULL;
}

static u_char*
vrrp_rfcv3_snmp_stats(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
	static struct counter64 c64;
	element e;
	vrrp_t *vrrp;
	uint64_t count;

	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;

	if (vp->magic != VRRP_RFCv3_SNMP_STATS_CHK_ERR &&
	    vp->magic != VRRP_RFCv3_SNMP_STATS_VER_ERR &&
	    vp->magic != VRRP_RFCv3_SNMP_STATS_VRID_ERR &&
	    vp->magic != VRRP_RFCv3_SNMP_STATS_DISC_TIME)
		return NULL;

	c64.high = c64.low = 0;
	*var_len = sizeof(c64);

	if (LIST_ISEMPTY(vrrp_data->vrrp))
		return (u_char*)&c64;

	count = 0;

	/* We don't do discontinuity time at the moment */
	if (vp->magic != VRRP_RFCv3_SNMP_STATS_ROW_DISC_TIME) {
		/* Work through all the vrrp instances that we can respond for */
		for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
			vrrp = ELEMENT_DATA(e);

			if (!suitable_for_rfc6527(vrrp))
				continue;

			switch (vp->magic) {
			case VRRP_RFCv3_SNMP_STATS_CHK_ERR:
				count += vrrp->stats->chk_err;
				break;
			case VRRP_RFCv3_SNMP_STATS_VER_ERR:
				count += vrrp->stats->vers_err;
				break;
			case VRRP_RFCv3_SNMP_STATS_VRID_ERR:
				count += vrrp->stats->vrid_err;
				break;
			}
		}
	}

	set_counter64(&c64, count);
	return (u_char *)&c64;
}

static u_char*
vrrp_rfcv3_snmp_statstable(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
	static uint32_t ret;
	static struct counter64 c64;
	vrrp_t *rt;

	if ((rt = snmp_rfcv3_header_list_table(vp, name, length, exact,
					     var_len, write_method)) == NULL)
		return NULL;

	*var_len = sizeof(c64);
	switch (vp->magic) {
	case VRRP_RFCv3_SNMP_STATS_MASTER:
		*var_len = sizeof(ret);
		ret = rt->stats->become_master;
		return (u_char *)&ret;
	case VRRP_RFCv3_SNMP_STATS_MASTER_REASON:
		if (rt->state != VRRP_STATE_MAST)
			ret = VRRPV3_MASTER_REASON_NOT_MASTER;
		else
			ret = rt->stats->master_reason;
		*var_len = sizeof(ret);
		return (u_char*)&ret;
	case VRRP_RFCv3_SNMP_STATS_ADV_RCVD:
		set_counter64(&c64, rt->stats->advert_rcvd);
		return (u_char *)&c64;
	case VRRP_RFCv3_SNMP_STATS_ADV_INT_ERR:
		set_counter64(&c64, rt->stats->advert_interval_err);
		return (u_char *)&c64;
	case VRRP_RFCv3_SNMP_STATS_TTL_ERR:
		set_counter64(&c64, rt->stats->ip_ttl_err);
		return (u_char *)&c64;
	case VRRP_RFCv3_SNMP_STATS_PROTO_ERR_REASON:
		*var_len = sizeof(ret);
		ret = rt->stats->proto_err_reason;
		return (u_char *)&ret;
	case VRRP_RFCv3_SNMP_STATS_PRI_0_RCVD:
		set_counter64(&c64, rt->stats->pri_zero_rcvd);
		return (u_char *)&c64;
	case VRRP_RFCv3_SNMP_STATS_PRI_0_SENT:
		set_counter64(&c64, rt->stats->pri_zero_sent);
		return (u_char *)&c64;
	case VRRP_RFCv3_SNMP_STATS_INV_TYPE_RCVD:
		set_counter64(&c64, rt->stats->invalid_type_rcvd);
		return (u_char *)&c64;
	case VRRP_RFCv3_SNMP_STATS_ADDR_LIST_ERR:
		set_counter64(&c64, rt->stats->addr_list_err);
		return (u_char *)&c64;
	case VRRP_RFCv3_SNMP_STATS_PL_ERR:
		set_counter64(&c64, rt->stats->packet_len_err);
		return (u_char *)&c64;
	case VRRP_RFCv3_SNMP_STATS_ROW_DISC_TIME:
		// We don't "do" discontinuities
		*var_len = sizeof(ret);
		ret = 0;
		return (u_char *)&ret;
	case VRRP_RFCv3_SNMP_STATS_REFRESH_RATE:
		*var_len = sizeof(ret);
		ret = rt->adver_int / TIMER_CENTI_HZ * 10;	/* milliseconds */
		return (u_char *)&ret;
	}

	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_rfcv3_snmp_statstable(vp, name, length,
					  exact, var_len, write_method);

	return NULL;
}

static oid vrrp_rfcv3_oid[] = {VRRP_RFCv3_OID};
static struct variable8 vrrp_rfcv3_vars[] = {
	/* vrrpOperTable */
	{ VRRP_RFCv3_SNMP_OPER_VRID, ASN_INTEGER, RONLY,
	  vrrp_rfcv3_snmp_opertable, 5, {1, 1, 1, 1, 1}},
	{ VRRP_RFCv3_SNMP_OPER_INET_ADDR_TYPE, ASN_INTEGER, RONLY,
	  vrrp_rfcv3_snmp_opertable, 5, {1, 1, 1, 1, 2}},
	{ VRRP_RFCv3_SNMP_OPER_MIP, ASN_OCTET_STR, RONLY,
	  vrrp_rfcv3_snmp_opertable, 5, {1, 1, 1, 1, 3}},
	{ VRRP_RFCv3_SNMP_OPER_PIP, ASN_OCTET_STR, RONLY,
	  vrrp_rfcv3_snmp_opertable, 5, {1, 1, 1, 1, 4}},
	{ VRRP_RFCv3_SNMP_OPER_VMAC, ASN_OCTET_STR, RONLY,
	  vrrp_rfcv3_snmp_opertable, 5, {1, 1, 1, 1, 5}},
	{ VRRP_RFCv3_SNMP_OPER_STATE, ASN_INTEGER, RONLY,
	  vrrp_rfcv3_snmp_opertable, 5, {1, 1, 1, 1, 6}},
	{ VRRP_RFCv3_SNMP_OPER_PRI, ASN_UNSIGNED, RONLY,
	  vrrp_rfcv3_snmp_opertable, 5, {1, 1, 1, 1, 7}},
	{ VRRP_RFCv3_SNMP_OPER_ADDR_CNT, ASN_INTEGER, RONLY,
	  vrrp_rfcv3_snmp_opertable, 5, {1, 1, 1, 1, 8}},
	{ VRRP_RFCv3_SNMP_OPER_ADVERT_INT, ASN_INTEGER, RONLY,
	  vrrp_rfcv3_snmp_opertable, 5, {1, 1, 1, 1, 9}},
	{ VRRP_RFCv3_SNMP_OPER_PREEMPT, ASN_INTEGER, RONLY,
	  vrrp_rfcv3_snmp_opertable, 5, {1, 1, 1, 1, 10}},
	{ VRRP_RFCv3_SNMP_OPER_ACCEPT, ASN_INTEGER, RONLY,
	  vrrp_rfcv3_snmp_opertable, 5, {1, 1, 1, 1, 11}},
	{ VRRP_RFCv3_SNMP_OPER_VR_UPTIME, ASN_TIMETICKS, RONLY,
	  vrrp_rfcv3_snmp_opertable, 5, {1, 1, 1, 1, 12}},
	{ VRRP_RFCv3_SNMP_OPER_ROW_STATUS, ASN_INTEGER, RONLY,
	  vrrp_rfcv3_snmp_opertable, 5, {1, 1, 1, 1, 13}},
	/* vrrpAssoIpAddrTable */
	{ VRRP_RFCv3_SNMP_ASSOC_IP_ADDR, ASN_OCTET_STR, RONLY,
	  vrrp_rfcv3_snmp_assoiptable, 5, {1, 1, 2, 1, 1}},
	{ VRRP_RFCv3_SNMP_ASSOC_IP_ADDR_ROW_STATUS, ASN_INTEGER, RONLY,
	  vrrp_rfcv3_snmp_assoiptable, 5, {1, 1, 2, 1, 2}},
	/* vrrpRouterStats */
	{ VRRP_RFCv3_SNMP_STATS_CHK_ERR, ASN_COUNTER64, RONLY,
	  vrrp_rfcv3_snmp_stats, 3, {1, 2, 1}},
	{ VRRP_RFCv3_SNMP_STATS_VER_ERR, ASN_COUNTER64, RONLY,
	  vrrp_rfcv3_snmp_stats, 3, {1, 2, 2}},
	{ VRRP_RFCv3_SNMP_STATS_VRID_ERR, ASN_COUNTER64, RONLY,
	  vrrp_rfcv3_snmp_stats, 3, {1, 2, 3}},
	{ VRRP_RFCv3_SNMP_STATS_DISC_TIME, ASN_TIMETICKS, RONLY,
	  vrrp_rfcv3_snmp_stats, 3, {1, 2, 4}},
	/* vrrpRouterStatsTable */
	{ VRRP_RFCv3_SNMP_STATS_MASTER, ASN_COUNTER, RONLY,
	  vrrp_rfcv3_snmp_statstable, 5, {1, 2, 5, 1, 1}},
	{ VRRP_RFCv3_SNMP_STATS_MASTER_REASON, ASN_INTEGER, RONLY,
	  vrrp_rfcv3_snmp_statstable, 5, {1, 2, 5, 1, 2}},
	{ VRRP_RFCv3_SNMP_STATS_ADV_RCVD, ASN_COUNTER64, RONLY,
	  vrrp_rfcv3_snmp_statstable, 5, {1, 2, 5, 1, 3}},
	{ VRRP_RFCv3_SNMP_STATS_ADV_INT_ERR, ASN_COUNTER64, RONLY,
	  vrrp_rfcv3_snmp_statstable, 5, {1, 2, 5, 1, 4}},
	{ VRRP_RFCv3_SNMP_STATS_TTL_ERR, ASN_COUNTER64, RONLY,
	  vrrp_rfcv3_snmp_statstable, 5, {1, 2, 5, 1, 5}},
	{ VRRP_RFCv3_SNMP_STATS_PROTO_ERR_REASON, ASN_INTEGER, RONLY,
	  vrrp_rfcv3_snmp_statstable, 5, {1, 2, 5, 1, 6}},
	{ VRRP_RFCv3_SNMP_STATS_PRI_0_RCVD, ASN_COUNTER64, RONLY,
	  vrrp_rfcv3_snmp_statstable, 5, {1, 2, 5, 1, 7}},
	{ VRRP_RFCv3_SNMP_STATS_PRI_0_SENT, ASN_COUNTER64 , RONLY,
	  vrrp_rfcv3_snmp_statstable, 5, {1, 2, 5, 1, 8}},
	{ VRRP_RFCv3_SNMP_STATS_INV_TYPE_RCVD, ASN_COUNTER64, RONLY,
	  vrrp_rfcv3_snmp_statstable, 5, {1, 2, 5, 1, 9}},
	{ VRRP_RFCv3_SNMP_STATS_ADDR_LIST_ERR, ASN_COUNTER64, RONLY,
	  vrrp_rfcv3_snmp_statstable, 5, {1, 2, 5, 1, 10}},
	{ VRRP_RFCv3_SNMP_STATS_PL_ERR, ASN_COUNTER64, RONLY,
	  vrrp_rfcv3_snmp_statstable, 5, {1, 2, 5, 1, 11}},
	{ VRRP_RFCv3_SNMP_STATS_ROW_DISC_TIME, ASN_TIMETICKS, RONLY,
	  vrrp_rfcv3_snmp_statstable, 5, {1, 2, 5, 1, 12}},
	{ VRRP_RFCv3_SNMP_STATS_REFRESH_RATE, ASN_UNSIGNED, RONLY,
	  vrrp_rfcv3_snmp_statstable, 5, {1, 2, 5, 1, 13}}
};

void
vrrp_rfcv3_snmp_new_master_notify(vrrp_t *vrrp)
{
	/* OID of the notification vrrpTrapNewMaster */
	oid notification_oid[] = { VRRP_RFCv3_NOTIFY_OID, 1 };
	size_t notification_oid_len = OID_LENGTH(notification_oid);
	/* OID for snmpNotifyOID.0 */
	oid objid_snmptrap[] = { SNMPTRAP_OID };
	size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);
	/* OID for trap data vrrpOperMasterIPAddr */
	oid masterip_oid[] = { VRRP_RFCv3_OID, 1, 1, 1, 1, 3, IF_BASE_INDEX(vrrp->ifp), vrrp->vrid, vrrp->family == AF_INET ? 1 : 2 };
	size_t masterip_oid_len = OID_LENGTH(masterip_oid);
	oid master_reason_oid[] = { VRRP_RFCv3_OID, 1, 2, 5, 1, 2, IF_BASE_INDEX(vrrp->ifp), vrrp->vrid, vrrp->family == AF_INET ? 1 : 2 };
	size_t master_reason_oid_len = OID_LENGTH(master_reason_oid);
	int	reason = vrrp->stats->master_reason;

	netsnmp_variable_list *notification_vars = NULL;

	if (!global_data->enable_traps || !global_data->enable_snmp_rfcv3)
		return;

	if (!suitable_for_rfc6527(vrrp))
		return;

	/* snmpTrapOID */
	snmp_varlist_add_variable(&notification_vars,
				  objid_snmptrap, objid_snmptrap_len,
				  ASN_OBJECT_ID,
				  (u_char *) notification_oid,
				  notification_oid_len * sizeof(oid));
	/* vrrpInstanceName */
	if (vrrp->family == AF_INET)
		snmp_varlist_add_variable(&notification_vars,
					  masterip_oid, masterip_oid_len,
					  ASN_OCTET_STR,
					  (u_char *)&((struct sockaddr_in *)&vrrp->saddr)->sin_addr.s_addr,
					  sizeof(((struct sockaddr_in *)&vrrp->saddr)->sin_addr.s_addr));
	else
		snmp_varlist_add_variable(&notification_vars,
					  masterip_oid, masterip_oid_len,
					  ASN_OCTET_STR,
					  (u_char *)&((struct sockaddr_in6 *)&vrrp->saddr)->sin6_addr,
					  sizeof(((struct sockaddr_in6 *)&vrrp->saddr)->sin6_addr));

	snmp_varlist_add_variable(&notification_vars,
				  master_reason_oid, master_reason_oid_len,
				  ASN_INTEGER,
				  (u_char *)&reason,
				  sizeof(reason));
	log_message(LOG_INFO, "VRRP_Instance(%s): Sending SNMP notification"
			      " vrrpv3NotifyNewMaster, reason %d"
			    , vrrp->iname, reason);
	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
}

void
vrrp_rfcv3_snmp_proto_err_notify(vrrp_t *vrrp)
{
	/* OID of the notification vrrpTrapNewMaster */
	oid notification_oid[] = { VRRP_RFCv3_NOTIFY_OID, 2 };
	size_t notification_oid_len = OID_LENGTH(notification_oid);
	/* OID for snmpTrapOID.0 */
	oid objid_snmptrap[] = { SNMPTRAP_OID };
	size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);
	/* OID for notify data vrrpTrapProtoErrorType */
	oid err_type_oid[] = { VRRP_RFCv3_OID, 1, 2, 5, 1, 6, IF_INDEX(vrrp->ifp), vrrp->vrid, vrrp->family == AF_INET ? 1 : 2 };
	size_t err_type_oid_len = OID_LENGTH(err_type_oid);

	netsnmp_variable_list *notification_vars = NULL;

	if (!global_data->enable_traps || !global_data->enable_snmp_rfcv3)
		return;

	if (!suitable_for_rfc6527(vrrp))
		return;

	/* snmpTrapOID */
	snmp_varlist_add_variable(&notification_vars,
				  objid_snmptrap, objid_snmptrap_len,
				  ASN_OBJECT_ID,
				  (u_char *) notification_oid,
				  notification_oid_len * sizeof(oid));
	/* vrrpProtoErrorType */
	snmp_varlist_add_variable(&notification_vars,
				  err_type_oid, err_type_oid_len,
				  ASN_INTEGER,
				  (u_char *)&vrrp->stats->proto_err_reason,
				  sizeof(vrrp->stats->proto_err_reason));
	log_message(LOG_INFO, "VRRP_Instance(%s): Sending SNMP notification"
			      " vrrpTrapProtoError"
			    , vrrp->iname);
	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
}
#endif

static bool
vrrp_handles_global_oid(void)
{
	if (global_data->enable_snmp_keepalived) {
		if (!__test_bit(DAEMON_CHECKERS, &daemon_mode) || !global_data->enable_snmp_checker)
			return true;
#ifndef _WITH_LVS_
		return true;
#endif
	}

	return false;
}

void
vrrp_snmp_agent_init(const char *snmp_socket)
{
	/* We let the check process handle the global OID if it is running and with snmp */
	snmp_agent_init(snmp_socket, vrrp_handles_global_oid());

#ifdef _WITH_SNMP_KEEPALIVED_
	if (global_data->enable_snmp_keepalived)
		snmp_register_mib(vrrp_oid, OID_LENGTH(vrrp_oid), "KEEPALIVED-VRRP",
				  (struct variable *)vrrp_vars,
				  sizeof(struct variable8),
				  sizeof(vrrp_vars)/sizeof(struct variable8));
#endif
#ifdef _WITH_SNMP_RFCV2_
	if (global_data->enable_snmp_rfcv2)
		snmp_register_mib(vrrp_rfcv2_oid, OID_LENGTH(vrrp_rfcv2_oid), "VRRP",
				  (struct variable *)vrrp_rfcv2_vars,
				  sizeof(struct variable8),
				  sizeof(vrrp_rfcv2_vars)/sizeof(struct variable8));
#endif
#ifdef _WITH_SNMP_RFCV3_
	if (global_data->enable_snmp_rfcv3)
		snmp_register_mib(vrrp_rfcv3_oid, OID_LENGTH(vrrp_rfcv3_oid), "VRRPV3",
				  (struct variable *)vrrp_rfcv3_vars,
				  sizeof(struct variable8),
				  sizeof(vrrp_rfcv3_vars)/sizeof(struct variable8));
#endif
}

void
vrrp_snmp_agent_close(void)
{
#ifdef _WITH_SNMP_KEEPALIVED_
	if (global_data->enable_snmp_keepalived)
		snmp_unregister_mib(vrrp_oid, OID_LENGTH(vrrp_oid));
#endif
#ifdef _WITH_SNMP_RFCV2_
	if (global_data->enable_snmp_rfcv2)
		snmp_unregister_mib(vrrp_rfcv2_oid, OID_LENGTH(vrrp_rfcv2_oid));
#endif
#ifdef _WITH_SNMP_RFCV3_
	if (global_data->enable_snmp_rfcv3)
		snmp_unregister_mib(vrrp_rfcv3_oid, OID_LENGTH(vrrp_rfcv3_oid));
#endif
	snmp_agent_close(vrrp_handles_global_oid());
}
