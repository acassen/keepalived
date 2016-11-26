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
     enable_snmp	(enables enable_snmp_keepalived and enable_snmp_checker)
     enable_snmp_keepalived
     enable_snmp_checker
     enable_snmp_rfc	(enables enable_snmp_rfcv2 enable_snmp_rfcv3)
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

#include "config.h"

#if HAVE_DECL_RTA_PREF
#include <linux/icmpv6.h>
#endif
#if HAVE_DECL_RTA_ENCAP
#include <linux/lwtunnel.h>
#endif

#include "vrrp.h"
#include "vrrp_snmp.h"
#include "vrrp_data.h"
#include "vrrp_track.h"
#include "vrrp_ipaddress.h"
#ifdef _HAVE_FIB_ROUTING_
#include "vrrp_iproute.h"
#include "vrrp_iprule.h"
#endif
#include "vrrp_scheduler.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_vmac.h"
#endif
#include "config.h"
#include "vector.h"
#include "list.h"
#include "logger.h"
#include "global_data.h"
#include "bitops.h"
#include "main.h"
#include "rttables.h"

#include "snmp.h"

#ifdef _WITH_SNMP_KEEPALIVED_
/* VRRP SNMP defines */
#define VRRP_OID KEEPALIVED_OID, 2

enum snmp_vrrp_magic {
	VRRP_SNMP_SCRIPT_NAME = 3,
	VRRP_SNMP_SCRIPT_COMMAND,
	VRRP_SNMP_SCRIPT_INTERVAL,
	VRRP_SNMP_SCRIPT_WEIGHT,
	VRRP_SNMP_SCRIPT_RESULT,
	VRRP_SNMP_SCRIPT_RISE,
	VRRP_SNMP_SCRIPT_FALL,
	VRRP_SNMP_ADDRESS_ADDRESSTYPE,
	VRRP_SNMP_ADDRESS_VALUE,
	VRRP_SNMP_ADDRESS_BROADCAST,
	VRRP_SNMP_ADDRESS_MASK,
	VRRP_SNMP_ADDRESS_SCOPE,
	VRRP_SNMP_ADDRESS_IFINDEX,
	VRRP_SNMP_ADDRESS_IFNAME,
	VRRP_SNMP_ADDRESS_IFALIAS,
	VRRP_SNMP_ADDRESS_ISSET,
	VRRP_SNMP_ADDRESS_ISADVERTISED,
	VRRP_SNMP_SYNCGROUP_NAME,
	VRRP_SNMP_SYNCGROUP_STATE,
	VRRP_SNMP_SYNCGROUP_SMTPALERT,
	VRRP_SNMP_SYNCGROUP_NOTIFYEXEC,
	VRRP_SNMP_SYNCGROUP_SCRIPTMASTER,
	VRRP_SNMP_SYNCGROUP_SCRIPTBACKUP,
	VRRP_SNMP_SYNCGROUP_SCRIPTFAULT,
	VRRP_SNMP_SYNCGROUP_SCRIPT,
	VRRP_SNMP_SYNCGROUPMEMBER_INSTANCE,
	VRRP_SNMP_SYNCGROUPMEMBER_NAME,
	VRRP_SNMP_INSTANCE_NAME,
	VRRP_SNMP_INSTANCE_VIRTUALROUTERID,
	VRRP_SNMP_INSTANCE_STATE,
	VRRP_SNMP_INSTANCE_INITIALSTATE,
	VRRP_SNMP_INSTANCE_WANTEDSTATE,
	VRRP_SNMP_INSTANCE_BASEPRIORITY,
	VRRP_SNMP_INSTANCE_EFFECTIVEPRIORITY,
	VRRP_SNMP_INSTANCE_VIPSENABLED,
	VRRP_SNMP_INSTANCE_PRIMARYINTERFACE,
	VRRP_SNMP_INSTANCE_TRACKPRIMARYIF,
	VRRP_SNMP_INSTANCE_ADVERTISEMENTSINT,
	VRRP_SNMP_INSTANCE_PREEMPT,
	VRRP_SNMP_INSTANCE_PREEMPTDELAY,
	VRRP_SNMP_INSTANCE_AUTHTYPE,
	VRRP_SNMP_INSTANCE_USELVSSYNCDAEMON,
	VRRP_SNMP_INSTANCE_LVSSYNCINTERFACE,
	VRRP_SNMP_INSTANCE_SYNCGROUP,
	VRRP_SNMP_INSTANCE_GARPDELAY,
	VRRP_SNMP_INSTANCE_SMTPALERT,
	VRRP_SNMP_INSTANCE_NOTIFYEXEC,
	VRRP_SNMP_INSTANCE_SCRIPTMASTER,
	VRRP_SNMP_INSTANCE_SCRIPTBACKUP,
	VRRP_SNMP_INSTANCE_SCRIPTFAULT,
	VRRP_SNMP_INSTANCE_SCRIPTSTOP,
	VRRP_SNMP_INSTANCE_SCRIPT,
	VRRP_SNMP_INSTANCE_ACCEPT,
	VRRP_SNMP_INSTANCE_PROMOTE_SECONDARIES,
	VRRP_SNMP_TRACKEDINTERFACE_NAME,
	VRRP_SNMP_TRACKEDINTERFACE_WEIGHT,
	VRRP_SNMP_TRACKEDSCRIPT_NAME,
	VRRP_SNMP_TRACKEDSCRIPT_WEIGHT,
};

#ifdef _HAVE_FIB_ROUTING_
enum snmp_rule_magic {
	VRRP_SNMP_RULE_DIRECTION = 2,
	VRRP_SNMP_RULE_ADDRESSTYPE,
	VRRP_SNMP_RULE_ADDRESS,
	VRRP_SNMP_RULE_ADDRESSMASK,
	VRRP_SNMP_RULE_ROUTINGTABLE,
	VRRP_SNMP_RULE_ISSET,
	VRRP_SNMP_RULE_INVERT,
	VRRP_SNMP_RULE_DESTINATIONADDRESSTYPE,
	VRRP_SNMP_RULE_DESTINATIONADDRESS,
	VRRP_SNMP_RULE_DESTINATIONADDRESSMASK,
	VRRP_SNMP_RULE_SOURCEADDRESSTYPE,
	VRRP_SNMP_RULE_SOURCEADDRESS,
	VRRP_SNMP_RULE_SOURCEADDRESSMASK,
	VRRP_SNMP_RULE_TOS,
	VRRP_SNMP_RULE_FWMARK,
	VRRP_SNMP_RULE_FWMASK,
	VRRP_SNMP_RULE_REALM_DST,
	VRRP_SNMP_RULE_REALM_SRC,
	VRRP_SNMP_RULE_ININTERFACE,
	VRRP_SNMP_RULE_OUTINTERFACE,
	VRRP_SNMP_RULE_TARGET,
	VRRP_SNMP_RULE_ACTION,
	VRRP_SNMP_RULE_TABLE_NO,
	VRRP_SNMP_RULE_PREFERENCE,
	VRRP_SNMP_RULE_SUPPRESSPREFIXLEN,
	VRRP_SNMP_RULE_SUPPRESSGROUP,
	VRRP_SNMP_RULE_TUNNELID_HIGH,
	VRRP_SNMP_RULE_TUNNELID_LOW,
};

enum snmp_route_magic {
	VRRP_SNMP_ROUTE_ADDRESSTYPE = 2,
	VRRP_SNMP_ROUTE_DESTINATION,
	VRRP_SNMP_ROUTE_DESTINATIONMASK,
	VRRP_SNMP_ROUTE_GATEWAY,
	VRRP_SNMP_ROUTE_SECONDARYGATEWAY,
	VRRP_SNMP_ROUTE_SOURCE,
	VRRP_SNMP_ROUTE_METRIC,
	VRRP_SNMP_ROUTE_SCOPE,
	VRRP_SNMP_ROUTE_TYPE,
	VRRP_SNMP_ROUTE_IFINDEX,
	VRRP_SNMP_ROUTE_IFNAME,
	VRRP_SNMP_ROUTE_ROUTINGTABLE,
	VRRP_SNMP_ROUTE_ISSET,
	VRRP_SNMP_ROUTE_FROM_ADDRESS,
	VRRP_SNMP_ROUTE_FROM_ADDRESS_MASK,
	VRRP_SNMP_ROUTE_TOS,
	VRRP_SNMP_ROUTE_PROTOCOL,
	VRRP_SNMP_ROUTE_ECN,
	VRRP_SNMP_ROUTE_QUICK_ACK,
	VRRP_SNMP_ROUTE_EXPIRES,
	VRRP_SNMP_ROUTE_MTU,
	VRRP_SNMP_ROUTE_MTU_LOCK,
	VRRP_SNMP_ROUTE_HOP_LIMIT,
	VRRP_SNMP_ROUTE_ADVMSS,
	VRRP_SNMP_ROUTE_ADVMSS_LOCK,
	VRRP_SNMP_ROUTE_RTT,
	VRRP_SNMP_ROUTE_RTT_LOCK,
	VRRP_SNMP_ROUTE_RTTVAR,
	VRRP_SNMP_ROUTE_RTTVAR_LOCK,
	VRRP_SNMP_ROUTE_REORDERING,
	VRRP_SNMP_ROUTE_REORDERING_LOCK,
	VRRP_SNMP_ROUTE_WINDOW,
	VRRP_SNMP_ROUTE_CWND,
	VRRP_SNMP_ROUTE_CWND_LOCK,
	VRRP_SNMP_ROUTE_SSTHRESH,
	VRRP_SNMP_ROUTE_SSTHRESH_LOCK,
	VRRP_SNMP_ROUTE_RTOMIN,
	VRRP_SNMP_ROUTE_RTOMIN_LOCK,
	VRRP_SNMP_ROUTE_INIT_CWND,
	VRRP_SNMP_ROUTE_INIT_RWND,
	VRRP_SNMP_ROUTE_CONG_CTL,
	VRRP_SNMP_ROUTE_PREF,
	VRRP_SNMP_ROUTE_REALM_DST,
	VRRP_SNMP_ROUTE_REALM_SRC,
	VRRP_SNMP_ROUTE_ENCAP_TYPE,
	VRRP_SNMP_ROUTE_ENCAP_MPLS_LABELS,
	VRRP_SNMP_ROUTE_ENCAP_ID,
	VRRP_SNMP_ROUTE_ENCAP_DST_ADDRESS,
	VRRP_SNMP_ROUTE_ENCAP_SRC_ADDRESS,
	VRRP_SNMP_ROUTE_ENCAP_TOS,
	VRRP_SNMP_ROUTE_ENCAP_TTL,
	VRRP_SNMP_ROUTE_ENCAP_FLAGS,
	VRRP_SNMP_ROUTE_ENCAP_ILA_LOCATOR,
};

enum snmp_next_hop_magic {
	VRRP_SNMP_ROUTE_NEXT_HOP_ADDRESS_TYPE = 2,
	VRRP_SNMP_ROUTE_NEXT_HOP_ADDRESS,
	VRRP_SNMP_ROUTE_NEXT_HOP_IF_INDEX,
	VRRP_SNMP_ROUTE_NEXT_HOP_IF_NAME,
	VRRP_SNMP_ROUTE_NEXT_HOP_WEIGHT,
	VRRP_SNMP_ROUTE_NEXT_HOP_ONLINK,
	VRRP_SNMP_ROUTE_NEXT_HOP_REALM_DST,
	VRRP_SNMP_ROUTE_NEXT_HOP_REALM_SRC,
	VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_TYPE,
	VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_MPLS_LABELS,
	VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_ID,
	VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_DST_ADDRESS,
	VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_SRC_ADDRESS,
	VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_TOS,
	VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_TTL,
	VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_FLAGS,
	VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_ILA_LOCATOR,
};
#endif

#define HEADER_STATE_STATIC_ADDRESS 1
#define HEADER_STATE_VIRTUAL_ADDRESS 2
#define HEADER_STATE_EXCLUDED_VIRTUAL_ADDRESS 3
#ifdef _HAVE_FIB_ROUTING_
#define HEADER_STATE_STATIC_ROUTE 4
#define HEADER_STATE_VIRTUAL_ROUTE 5
#define HEADER_STATE_STATIC_RULE 6
#define HEADER_STATE_VIRTUAL_RULE 7
#define HEADER_STATE_NEXT_HOP 11
#endif
#define HEADER_STATE_END 12

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

/* Static return value */
static longret_t long_ret;

/* global variable */
#ifdef _WITH_SNMP_RFC_
timeval_t vrrp_start_time;
#endif


/* For some reason net-snmp doesn't use a uint64_t for 64 bit counters, but rather uses
 * a struct, with the high word at the lower address, so we need to assign values according. */
inline static void
set_counter64 (struct counter64 *c64, uint64_t val)
{
	c64->high = val >> 32;
	c64->low = val & 0xffffffff;
}

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
static int
vrrp_snmp_state(int state)
{
	return state < VRRP_STATE_GOTO_MASTER ? state : 4;
}

static u_char*
vrrp_snmp_script(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
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
		long_ret.u = scr->interval / TIMER_HZ;
		return (u_char *)&long_ret;
	case VRRP_SNMP_SCRIPT_WEIGHT:
		long_ret.s = scr->weight;
		return (u_char *)&long_ret;
	case VRRP_SNMP_SCRIPT_RESULT:
		switch (scr->result) {
		case VRRP_SCRIPT_STATUS_INIT:
			long_ret.u = 1; break;
		case VRRP_SCRIPT_STATUS_INIT_GOOD:
			long_ret.u = 4; break;
		case VRRP_SCRIPT_STATUS_INIT_FAILED:
			long_ret.u = 5; break;
		case VRRP_SCRIPT_STATUS_DISABLED:
			long_ret.u = 0; break;
		default:
			long_ret.u = (scr->result >= scr->rise) ? 3 : 2;
		}
		return (u_char *)&long_ret;
	case VRRP_SNMP_SCRIPT_RISE:
		long_ret.s = scr->rise;
		return (u_char *)&long_ret;
	case VRRP_SNMP_SCRIPT_FALL:
		long_ret.s = scr->fall;
		return (u_char *)&long_ret;
	default:
		break;
	}
	return NULL;
}

/* Header function using a FSM. `state' is the initial state, either
   HEADER_STATE_STATIC_ADDRESS, HEADER_STATE_STATIC_ROUTE or
   HEADER_STATE_STATIC_RULE. We return the matching address, route or rule. */
static void*
vrrp_header_ar_table(struct variable *vp, oid *name, size_t *length,
		     int exact, size_t *var_len, WriteMethod **write_method,
		     int *state)
{
	oid *target, current[2], best[2];
	int result;
	size_t target_len;
	element e1 = NULL, e2;
	void *el, *bel = NULL;
	list l2;
	unsigned curinstance = 0;
	int curstate, nextstate;

	if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
	}

	*write_method = 0;
	*var_len = sizeof(unsigned long);

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
#ifdef _HAVE_FIB_ROUTING_
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
#endif
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
	*length = (unsigned)vp->namelen + 2;

	return bel;
}

#ifdef _HAVE_FIB_ROUTING_
#define MAX_PTR ((void*)((char *)NULL - 1))
static nexthop_t*
vrrp_header_nh_table(struct variable *vp, oid *name, size_t *length,
		     int exact, size_t *var_len, WriteMethod **write_method)
{
	oid *target;
	int result;
	size_t target_len;
	element e1, e2, e3;
	list l2, l3;
	oid curinstance[3];
	bool same;

	if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
	}

	*write_method = 0;
	*var_len = sizeof(unsigned long);

	/* We search the best match: equal if exact, the lower OID in
	   the set of the OID strictly superior to the target
	   otherwise. */
	target = &name[vp->namelen];   /* Our target match */
	target_len = *length - vp->namelen;
	if (exact && !target_len)
		return NULL;

	for (e1 = MAX_PTR, curinstance[0] = 0; e1; e1 = ((e1 == MAX_PTR) ? (LIST_ISEMPTY(vrrp_data->vrrp) ? NULL : LIST_HEAD(vrrp_data->vrrp)) : e1->next), curinstance[0]++) {
		if (exact && curinstance[0] > target[0])
			return NULL;
		if (target_len && curinstance[0] < target[0])
			continue;
		same = (target_len && curinstance[0] == target[0]);
		l2 = (e1 == MAX_PTR) ? vrrp_data->static_routes : ((vrrp_t *)ELEMENT_DATA(e1))->vroutes;
		if (LIST_ISEMPTY(l2))
			continue;
		for (e2 = LIST_HEAD(l2), curinstance[1] = 1; e2; ELEMENT_NEXT(e2), curinstance[1]++) {
			if (exact && curinstance[1] > target[1])
				return NULL;
			if (same && curinstance[1] < target[1])
				continue;
			same = (same && curinstance[1] == target[1]);
			l3 = ((ip_route_t *)ELEMENT_DATA(e2))->nhs;
			if (LIST_ISEMPTY(l3))
				continue;
			for (e3 = LIST_HEAD(l3), curinstance[2] = 1; e3; ELEMENT_NEXT(e3), curinstance[2]++) {
				if (exact && target_len && curinstance[2] > target[2])
					return NULL;
				if (same && curinstance[2] < target[2])
					continue;

				if (target_len && !exact && curinstance[0] == target[0] && curinstance[1] == target[1] && curinstance[2] == target[2])
					continue;

				memcpy(target, curinstance, sizeof(oid) * 3);
				*length = (unsigned)vp->namelen + 3;

				return ELEMENT_DATA(e3);
			}
		}
	}
	return NULL;
}
#endif

static u_char*
vrrp_snmp_address(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	ip_address_t *addr;
	int state = HEADER_STATE_STATIC_ADDRESS;

	if ((addr = (ip_address_t *)
	     vrrp_header_ar_table(vp, name, length, exact,
				  var_len, write_method,
				  &state)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_ADDRESS_ADDRESSTYPE:
		long_ret.u = (addr->ifa.ifa_family == AF_INET6)?2:1;
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
		long_ret.u = addr->ifa.ifa_prefixlen;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ADDRESS_SCOPE:
		long_ret.u = snmp_scope(addr->ifa.ifa_scope);
		return (u_char *)&long_ret;
	case VRRP_SNMP_ADDRESS_IFINDEX:
		long_ret.u = addr->ifa.ifa_index;
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
		long_ret.u = (addr->set)?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ADDRESS_ISADVERTISED:
		long_ret.u = (state == HEADER_STATE_VIRTUAL_ADDRESS)?1:2;
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

#ifdef _HAVE_FIB_ROUTING_
static u_char*
vrrp_snmp_route(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	ip_route_t *route;
	int state = HEADER_STATE_STATIC_ROUTE;

	if ((route = (ip_route_t *)
	     vrrp_header_ar_table(vp, name, length, exact,
				  var_len, write_method,
				  &state)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_ROUTE_ADDRESSTYPE:
		long_ret.u = AF_INET;	/* IPv4 only */
		if (route->dst)
			long_ret.u = route->dst->ifa.ifa_family;
		else if (route->src)
			long_ret.u = route->src->ifa.ifa_family;
		else if (route->pref_src)
			long_ret.u = route->pref_src->ifa.ifa_family;
		if (long_ret.u == AF_INET6)
			long_ret.u = 2;
		else
			long_ret.u = 1;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_DESTINATION:
		if (!route->dst)
			break;
		if (route->dst->ifa.ifa_family == AF_INET6) {
			*var_len = 16;
			return (u_char *)&route->dst->u.sin6_addr;
		}
		*var_len = 4;
		return (u_char *)&route->dst->u.sin.sin_addr;
	case VRRP_SNMP_ROUTE_DESTINATIONMASK:
		if (!route->dst)
			break;
		long_ret.u = route->dst->ifa.ifa_prefixlen;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_GATEWAY:
		if (!route->via)
			break;
		if (route->via->ifa.ifa_family == AF_INET6) {
			*var_len = 16;
			return (u_char *)&route->via->u.sin6_addr;
		}
		*var_len = 4;
		return (u_char *)&route->via->u.sin.sin_addr;
	case VRRP_SNMP_ROUTE_SECONDARYGATEWAY:
		if (LIST_ISEMPTY(route->nhs) || LIST_SIZE(route->nhs) != 1)
			break;
		nexthop_t *gw2 = LIST_HEAD(route->nhs)->data;
#if HAVE_DECL_RTA_ENCAP
		if (gw2->encap.type != LWTUNNEL_ENCAP_NONE)
			break;
#endif
		if (gw2->addr->ifa.ifa_family == AF_INET6) {
			*var_len = 16;
			return (u_char *)&gw2->addr->u.sin6_addr;
		}
		*var_len = 4;
		return (u_char *)&gw2->addr->u.sin.sin_addr;
	case VRRP_SNMP_ROUTE_SOURCE:
		if (!route->pref_src)
			break;
		if (route->pref_src->ifa.ifa_family == AF_INET6) {
			*var_len = 16;
			return (u_char *)&route->pref_src->u.sin6_addr;
		}
		*var_len = 4;
		return (u_char *)&route->pref_src->u.sin.sin_addr;
	case VRRP_SNMP_ROUTE_METRIC:
		long_ret.u = route->metric;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_SCOPE:
		long_ret.u = snmp_scope(route->scope);
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_TYPE:
		if (!LIST_ISEMPTY(route->nhs))
			long_ret.u = 2;
		else if (route->type == RTN_BLACKHOLE)
			long_ret.u = 3;
		else if (route->type == RTN_ANYCAST)
			long_ret.u = 4;
		else if (route->type == RTN_MULTICAST)
			long_ret.u = 5;
		else if (route->type == RTN_BROADCAST)
			long_ret.u = 6;
		else if (route->type == RTN_UNREACHABLE)
			long_ret.u = 7;
		else if (route->type == RTN_PROHIBIT)
			long_ret.u = 8;
		else if (route->type == RTN_THROW)
			long_ret.u = 9;
		else if (route->type == RTN_NAT)
			long_ret.u = 10;
		else if (route->type == RTN_XRESOLVE)
			long_ret.u = 11;
		else
			long_ret.u = 1;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_IFINDEX:
		if (!route->oif)
			break;
		long_ret.u = route->oif->ifindex;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_IFNAME:
		if (!route->oif)
			break;
		*var_len = strlen(IF_NAME(route->oif));
		return (u_char *)&IF_NAME(route->oif);
	case VRRP_SNMP_ROUTE_ROUTINGTABLE:
		long_ret.u = route->table;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_ISSET:
		long_ret.u = (route->set)?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_FROM_ADDRESS:
		if (!route->src)
			break;
		if (route->src->ifa.ifa_family == AF_INET6) {
			*var_len = 16;
			return (u_char *)&route->src->u.sin6_addr;
		} else {
			*var_len = 4;
			return (u_char *)&route->src->u.sin.sin_addr;
		}
	case VRRP_SNMP_ROUTE_FROM_ADDRESS_MASK:
		if (!route->src)
			break;
		long_ret.u = route->src->ifa.ifa_prefixlen;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_TOS:
		if (!(route->mask & IPROUTE_BIT_DSFIELD))
			break;
		long_ret.u = route->tos;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_PROTOCOL:
		if (!(route->mask & IPROUTE_BIT_PROTOCOL))
			break;
		long_ret.s = route->protocol + 1;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_ECN:
		long_ret.s = 2 - !!(route->features & RTAX_FEATURE_ECN);
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_QUICK_ACK:
		long_ret.u = 2 - !!(route->mask & IPROUTE_BIT_QUICKACK);
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_EXPIRES:
#if !HAVE_DECL_RTA_EXPIRES
		break;
#else
		if (!(route->mask & IPROUTE_BIT_EXPIRES))
			break;
		long_ret.u = route->expires;
		return (u_char *)&long_ret;
#endif
	case VRRP_SNMP_ROUTE_MTU:
		if (!(route->mask & IPROUTE_BIT_MTU))
			break;
		long_ret.u = route->mtu;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_MTU_LOCK:
		if (!(route->mask & IPROUTE_BIT_MTU))
			break;
		long_ret.u = 2 - !!(route->lock & (1<<RTAX_MTU));
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_HOP_LIMIT:
		if (!(route->mask & IPROUTE_BIT_HOPLIMIT))
			break;
		long_ret.u = route->hoplimit;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_ADVMSS:
		if (!(route->mask & IPROUTE_BIT_HOPLIMIT))
			break;
		long_ret.u = route->advmss;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_ADVMSS_LOCK:
		if (!(route->mask & IPROUTE_BIT_ADVMSS))
			break;
		long_ret.u = 2 - !!(route->lock & (1<<RTAX_ADVMSS));
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_RTT:
		if (!(route->mask & IPROUTE_BIT_RTT))
			break;
		long_ret.u = route->rtt / 8;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_RTT_LOCK:
		if (!(route->mask & IPROUTE_BIT_RTT))
			break;
		long_ret.u = 2 - !!(route->lock & (1<<RTAX_RTT));
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_RTTVAR:
		if (!(route->mask & IPROUTE_BIT_RTTVAR))
			break;
		long_ret.u = route->rttvar / 4;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_RTTVAR_LOCK:
		if (!(route->mask & IPROUTE_BIT_RTTVAR))
			break;
		long_ret.u = 2 - !!(route->lock & (1<<RTAX_RTTVAR));
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_REORDERING:
		if (!(route->mask & IPROUTE_BIT_REORDERING))
			break;
		long_ret.u = route->reordering;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_REORDERING_LOCK:
		if (!(route->mask & IPROUTE_BIT_REORDERING))
			break;
		long_ret.u = 2 - !!(route->lock & (1<<RTAX_REORDERING));
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_WINDOW:
		if (!(route->mask & IPROUTE_BIT_WINDOW))
			break;
		long_ret.u = route->window;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_CWND:
		if (!(route->mask & IPROUTE_BIT_CWND))
			break;
		long_ret.u = route->cwnd;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_CWND_LOCK:
		if (!(route->mask & IPROUTE_BIT_CWND))
			break;
		long_ret.u = 2 - !!(route->lock & (1<<RTAX_CWND));
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_SSTHRESH:
		if (!(route->mask & IPROUTE_BIT_SSTHRESH))
			break;
		long_ret.u = route->ssthresh;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_SSTHRESH_LOCK:
		if (!(route->mask & IPROUTE_BIT_SSTHRESH))
			break;
		long_ret.u = 2 - !!(route->lock & (1<<RTAX_SSTHRESH));
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_RTOMIN:
		if (!(route->mask & IPROUTE_BIT_RTO_MIN))
			break;
		long_ret.u = route->rto_min;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_RTOMIN_LOCK:
		if (!(route->mask & IPROUTE_BIT_RTO_MIN))
			break;
		long_ret.u = 2 - !!(route->lock & (1<<RTAX_RTO_MIN));
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_INIT_CWND:
		if (!(route->mask & IPROUTE_BIT_INITCWND))
			break;
		long_ret.u = route->initcwnd;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_INIT_RWND:
		if (!(route->mask & IPROUTE_BIT_INITRWND))
			break;
		long_ret.u = route->initrwnd;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_CONG_CTL:
#if !HAVE_DECL_RTAX_CC_ALGO
		break;
#else
		if (!route->congctl)
			break;
		*var_len = strlen(route->congctl);
		return (u_char *)route->congctl;
#endif
	case VRRP_SNMP_ROUTE_PREF:
#if !HAVE_DECL_RTA_PREF
		break;
#else
		if (!(route->mask & IPROUTE_BIT_PREF))
			break;
		long_ret.u = 
			route->pref == ICMPV6_ROUTER_PREF_LOW ? 1 :
			route->pref == ICMPV6_ROUTER_PREF_MEDIUM ? 2 :
			route->pref == ICMPV6_ROUTER_PREF_HIGH ? 3 : 0;
		return (u_char *)&long_ret;
#endif
	case VRRP_SNMP_ROUTE_REALM_DST:
		if (!route->realms)
			break;
		long_ret.u = route->realms & 0xFFFF;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_REALM_SRC:
		if (!(route->realms & 0xFFFF0000))
			break;
		long_ret.u = route->realms >> 16;
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

#if HAVE_DECL_RTA_ENCAP
static u_char*
vrrp_snmp_encap(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	static char labels[11*MAX_MPLS_LABELS];
	char *op;
	ip_route_t *route;
	nexthop_t *nh;
	encap_t *encap;
	int state = HEADER_STATE_STATIC_ROUTE;
	unsigned i;
	static struct counter64 c64;

	if (vp->name[vp->namelen - 3] == 7) {
		if ((route = (ip_route_t *)vrrp_header_ar_table(vp, name, length, exact,
					  var_len, write_method,
					  &state)) == NULL)
			return NULL;
		encap = &route->encap;
	}
	else {
		if ((nh = vrrp_header_nh_table(vp, name, length, exact,
					  var_len, write_method)) == NULL)
			return NULL;
		encap = &nh->encap;
	}

// TODO - enable this to work for main route or next hop - following in a separate function callable by both
	if (encap->type != LWTUNNEL_ENCAP_NONE) {
		if (vp->magic == VRRP_SNMP_ROUTE_ENCAP_TYPE) {
			long_ret.s = encap->type + 1;
			return (u_char *)&long_ret;
		}

		if (encap->type == LWTUNNEL_ENCAP_MPLS) {
			if (vp->magic == VRRP_SNMP_ROUTE_ENCAP_MPLS_LABELS) {
				op = labels;
				for (i = 0; i < encap->mpls.num_labels; i++)
					op += snprintf(op, (size_t)(labels + sizeof(labels) - op), "%s%u", i ? "/" : "", encap->mpls.addr[i].entry);
				*var_len = strlen(labels);
				return (u_char *)labels;
			}
		}
		else if (encap->type == LWTUNNEL_ENCAP_IP ||
			 encap->type == LWTUNNEL_ENCAP_IP6) {
			switch(vp->magic) {
			case VRRP_SNMP_ROUTE_ENCAP_ID:
				if (!(encap->flags & IPROUTE_BIT_ENCAP_ID))
					break;
				*var_len = sizeof(c64);
				set_counter64 (&c64, encap->ip.id);
				return (u_char *)&c64;
			case VRRP_SNMP_ROUTE_ENCAP_DST_ADDRESS:
				if (!encap->ip.dst)
					break;
				if (encap->ip.dst->ifa.ifa_family == AF_INET6) {
					*var_len = sizeof(encap->ip.dst->u.sin6_addr);
					return (u_char *)&encap->ip.dst->u.sin6_addr;
				}
				*var_len = sizeof(encap->ip.dst->u.sin.sin_addr.s_addr);
				return (u_char *)&encap->ip.dst->u.sin.sin_addr.s_addr;
			case VRRP_SNMP_ROUTE_ENCAP_SRC_ADDRESS:
				if (!encap->ip.src)
					break;
				if (encap->ip.src->ifa.ifa_family == AF_INET6) {
					*var_len = sizeof(encap->ip.src->u.sin6_addr);
					return (u_char *)&encap->ip.src->u.sin6_addr;
				}
				*var_len = sizeof(encap->ip.src->u.sin.sin_addr.s_addr);
				return (u_char *)&encap->ip.src->u.sin.sin_addr.s_addr;
			case VRRP_SNMP_ROUTE_ENCAP_TOS:
				if (!(encap->flags & IPROUTE_BIT_ENCAP_DSFIELD))
					break;
				long_ret.u = encap->ip.tos;
				return (u_char *)&long_ret;
			case VRRP_SNMP_ROUTE_ENCAP_TTL:
				if (!(encap->flags & IPROUTE_BIT_ENCAP_TTL))
					break;
				long_ret.u = encap->ip.ttl;
				return (u_char *)&long_ret;
			case VRRP_SNMP_ROUTE_ENCAP_FLAGS:
				if (!(encap->flags & IPROUTE_BIT_ENCAP_FLAGS))
					break;
				long_ret.u = encap->ip.flags;
				return (u_char *)&long_ret;
			}
		}
		else if (encap->type == LWTUNNEL_ENCAP_ILA) {
			if (vp->magic == VRRP_SNMP_ROUTE_ENCAP_ILA_LOCATOR) {
				*var_len = sizeof(c64);
				set_counter64 (&c64, encap->ila.locator);
				return (u_char *)&c64;
			}
		}
	}

	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_snmp_encap(vp, name, length,
				       exact, var_len, write_method);
	return NULL;
}
#endif

static u_char*
vrrp_snmp_next_hop(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	nexthop_t *nh;

	if ((nh = vrrp_header_nh_table(vp, name, length, exact,
				  var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_ROUTE_NEXT_HOP_ADDRESS_TYPE:
		if (!nh->addr)
			break;
		long_ret.u = (nh->addr->ifa.ifa_family == AF_INET6) ? 2 : 1;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_NEXT_HOP_ADDRESS:
		if (!nh->addr)
			break;
		if (nh->addr->ifa.ifa_family == AF_INET6) {
			*var_len = 16;
			return (u_char *)&nh->addr->u.sin6_addr;
		}
		*var_len = 4;
		return (u_char *)&nh->addr->u.sin.sin_addr;
	case VRRP_SNMP_ROUTE_NEXT_HOP_IF_INDEX:
		if (!nh->ifp)
			break;
		long_ret.u = nh->ifp->ifindex;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_NEXT_HOP_IF_NAME:
		if (!nh->ifp)
			break;
		*var_len = strlen(nh->ifp->ifname);
		return (u_char *)&nh->ifp->ifname;
	case VRRP_SNMP_ROUTE_NEXT_HOP_WEIGHT:
		 if (!(nh->mask & IPROUTE_BIT_WEIGHT))
			break;
		long_ret.s = nh->weight + 1;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_NEXT_HOP_ONLINK:
		long_ret.u = 2 - !!(nh->flags & RTNH_F_ONLINK);
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_NEXT_HOP_REALM_DST:
		if (!nh->realms)
			break;
		long_ret.u = nh->realms & 0xFFFF;
	case VRRP_SNMP_ROUTE_NEXT_HOP_REALM_SRC:
		if (!(nh->realms & 0xFFFF0000))
			break;
		long_ret.u = nh->realms >> 16;
		return (u_char *)&long_ret;
	default:
		break;
	}

	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return vrrp_snmp_next_hop(vp, name, length,
				       exact, var_len, write_method);
	return NULL;
}

static u_char*
vrrp_snmp_rule(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	ip_rule_t *rule;
	int state = HEADER_STATE_STATIC_RULE;
	const char *str;
	ip_address_t *addr;

	if ((rule = (ip_rule_t *)
	     vrrp_header_ar_table(vp, name, length, exact,
				  var_len, write_method,
				  &state)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_SNMP_RULE_DIRECTION:	/* obsolete */
		str = rule->to_addr ? rule->from_addr ? "both" : "to" : rule->from_addr ? "from" : "";
		*var_len = strlen(str);
		return (u_char *)str;
	case VRRP_SNMP_RULE_ADDRESSTYPE:	/* obsolete */
		addr = rule->to_addr ? rule->to_addr : rule->from_addr;
		if (!addr)
			break;
		long_ret.u = addr->ifa.ifa_family == AF_INET6 ? 2 : 1;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_ADDRESS:	/* obsolete */
		addr = rule->to_addr ? rule->to_addr : rule->from_addr;
		if (!addr)
			break;
		if (addr->ifa.ifa_family == AF_INET6) {
			*var_len = sizeof(addr->u.sin6_addr);
			return (u_char *)&addr->u.sin6_addr;
		}
		*var_len = sizeof(addr->u.sin.sin_addr);
		return (u_char *)&addr->u.sin.sin_addr;
	case VRRP_SNMP_RULE_ADDRESSMASK:	/* obsolete */
		addr = rule->to_addr ? rule->to_addr : rule->from_addr;
		if (!addr)
			break;
		long_ret.u = addr->ifa.ifa_prefixlen;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_ROUTINGTABLE:
		if (rule->action != FR_ACT_TO_TBL)
			break;
		long_ret.u = rule->table;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_ISSET:
		long_ret.u = (rule->set)?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_INVERT:
		long_ret.s = 2 - rule->invert;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_DESTINATIONADDRESSTYPE:
		if (!rule->to_addr)
			break;
		long_ret.u = (rule->to_addr->ifa.ifa_family == AF_INET6) ? 2 : 1;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_DESTINATIONADDRESS:
		if (!rule->to_addr)
			break;
		if (rule->to_addr->ifa.ifa_family == AF_INET6) {
			*var_len = sizeof(rule->to_addr->u.sin6_addr);
			return (u_char *)&rule->to_addr->u.sin6_addr;
		}
		*var_len = sizeof(rule->to_addr->u.sin.sin_addr);
		return (u_char *)&rule->to_addr->u.sin.sin_addr;
	case VRRP_SNMP_RULE_DESTINATIONADDRESSMASK:
		if (!rule->to_addr)
			break;
		long_ret.u = rule->to_addr->ifa.ifa_prefixlen;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_SOURCEADDRESSTYPE:
		if (!rule->from_addr)
			break;
		long_ret.u = (rule->from_addr->ifa.ifa_family == AF_INET6) ? 2 : 1;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_SOURCEADDRESS:
		if (!rule->from_addr)
			break;
		if (rule->from_addr->ifa.ifa_family == AF_INET6) {
			*var_len = sizeof(rule->from_addr->u.sin6_addr);
			return (u_char *)&rule->from_addr->u.sin6_addr;
		}
		*var_len = sizeof(rule->from_addr->u.sin.sin_addr);
		return (u_char *)&rule->from_addr->u.sin.sin_addr;
	case VRRP_SNMP_RULE_SOURCEADDRESSMASK:
		if (!rule->from_addr)
			break;
		long_ret.u = rule->from_addr->ifa.ifa_prefixlen;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_TOS:
		if (rule->mask & IPRULE_BIT_DSFIELD)
			long_ret.u = rule->tos;
		else
			break;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_FWMARK:
		if (rule->mask & IPRULE_BIT_FWMARK)
			long_ret.u = rule->fwmark;
		else
			break;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_FWMASK:
		if (rule->mask & IPRULE_BIT_FWMASK)
			long_ret.u = rule->fwmask;
		else
			break;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_REALM_DST:
		if (!rule->realms)
			break;
		long_ret.u = rule->realms & 0xFFFF;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_REALM_SRC:
		if (!(rule->realms & 0xFFFF0000))
			break;
		long_ret.u = rule->realms >> 16;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_ININTERFACE:
		if (!rule->iif)
			break;
		*var_len = strlen(rule->iif->ifname);
		return (u_char *)rule->iif->ifname;
	case VRRP_SNMP_RULE_OUTINTERFACE:
		if (!rule->oif)
			break;
		*var_len = strlen(rule->oif->ifname);
		return (u_char *)rule->oif->ifname;
	case VRRP_SNMP_RULE_TARGET:
		if (!(rule->action == FR_ACT_GOTO))
			break;
		long_ret.u = rule->goto_target;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_ACTION:
		long_ret.u = rule->action;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_TABLE_NO:
		if (rule->action != FR_ACT_TO_TBL)
			break;
		long_ret.u = rule->table;
		return (u_char *)&long_ret;
	case VRRP_SNMP_RULE_PREFERENCE:
		if (!rule->priority)
			break;
		long_ret.u = rule->priority;
		return (u_char *)&long_ret;
#if HAVE_DECL_FRA_SUPPRESS_PREFIXLEN
	case VRRP_SNMP_RULE_SUPPRESSPREFIXLEN:
		if (rule->mask & IPRULE_BIT_SUP_PREFIXLEN)
			long_ret.u = rule->suppress_prefix_len;
		else
#endif
			break;
		return (u_char *)&long_ret;
#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
	case VRRP_SNMP_RULE_SUPPRESSGROUP:
		if (rule->mask & IPRULE_BIT_SUP_GROUP) {
			str = get_rttables_group(rule->suppress_group);
			*var_len = strlen(str);
		}
		else
#endif
			break;
		return (u_char *)str;
#if HAVE_DECL_FRA_TUN_ID
	case VRRP_SNMP_RULE_TUNNELID_HIGH:
		if (rule->tunnel_id)
			long_ret.u = rule->tunnel_id >> 32;
		else
#endif
			break;
		return (u_char *)&long_ret;
#if HAVE_DECL_FRA_TUN_ID
	case VRRP_SNMP_RULE_TUNNELID_LOW:
		if (rule->tunnel_id)
			long_ret.u = rule->tunnel_id & 0xffffffff;
		else
#endif
			break;
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
#endif	// _HAVE_FIB_ROUTING_

static u_char*
vrrp_snmp_syncgroup(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
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
		long_ret.s = vrrp_snmp_state(group->state);
		return (u_char *)&long_ret;
	case VRRP_SNMP_SYNCGROUP_SMTPALERT:
		long_ret.u = group->smtp_alert?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_SYNCGROUP_NOTIFYEXEC:
		long_ret.u = group->notify_exec?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_SYNCGROUP_SCRIPTMASTER:
		if (group->script_master) {
			*var_len = strlen(group->script_master->name);
			return (u_char *)group->script_master->name;
		}
		break;
	case VRRP_SNMP_SYNCGROUP_SCRIPTBACKUP:
		if (group->script_backup) {
			*var_len = strlen(group->script_backup->name);
			return (u_char *)group->script_backup->name;
		}
		break;
	case VRRP_SNMP_SYNCGROUP_SCRIPTFAULT:
		if (group->script_fault) {
			*var_len = strlen(group->script_fault->name);
			return (u_char *)group->script_fault->name;
		}
		break;
	case VRRP_SNMP_SYNCGROUP_SCRIPT:
		if (group->script) {
			*var_len = strlen(group->script->name);
			return (u_char *)group->script->name;
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
	int result;
	size_t target_len;
	unsigned curgroup, curinstance;
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
	*length = (unsigned)vp->namelen + 2;
	*var_len = strlen(binstance);
	return (u_char*)binstance;
}

static vrrp_t *
_get_instance(oid *name, size_t name_len)
{
	oid instance;
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
			  size_t var_val_len, __attribute__((unused)) u_char *statP,
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
// TODO - We must check that we are not address owner (especially if disabling)
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
// RFC6527 requires the instance to be down to change this - can't find now where it says that
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
			    __attribute__((unused)) u_char *statP, oid *name, size_t name_len)
{
	vrrp_t *vrrp = NULL;
	switch (action) {
	case RESERVE1:
		/* Check that the proposed priority is acceptable */
		if (var_val_type != ASN_INTEGER)
			return SNMP_ERR_WRONGTYPE;
		if (var_val_len > sizeof(long))
			return SNMP_ERR_WRONGLENGTH;
		if (*var_val == 0)
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
			    " %u to %u via SNMP.",
			    vrrp->iname, vrrp->base_priority, *var_val);
		vrrp->base_priority = *var_val;
		/* If we the instance is not part of a sync group, the
		   effective priority will be recomputed by some
		   thread. Otherwise, we should set it equal to the
		   base priority. */
		if (vrrp->sync)
			vrrp_set_effective_priority(vrrp, vrrp->base_priority);
//TODO - could affect accept
		break;
	}
	return SNMP_ERR_NOERROR;
}

static int
vrrp_snmp_instance_preempt(int action,
			   u_char *var_val, u_char var_val_type, size_t var_val_len,
			   __attribute__((unused)) u_char *statP, oid *name, size_t name_len)
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
		long_ret.u = rt->vrid;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_STATE:
		long_ret.s = vrrp_snmp_state(rt->state);
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_INITIALSTATE:
		long_ret.s = vrrp_snmp_state(rt->init_state);
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_WANTEDSTATE:
		long_ret.s = vrrp_snmp_state(rt->wantstate);
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_BASEPRIORITY:
		long_ret.u = rt->base_priority;
		*write_method = vrrp_snmp_instance_priority;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_EFFECTIVEPRIORITY:
		long_ret.u = rt->effective_priority;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_VIPSENABLED:
		long_ret.u = rt->vipset?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_PRIMARYINTERFACE:
		*var_len = strlen(rt->ifp->ifname);
		return (u_char *)&rt->ifp->ifname;
	case VRRP_SNMP_INSTANCE_TRACKPRIMARYIF:
		long_ret.u = rt->track_ifp?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_ADVERTISEMENTSINT:
		long_ret.u = (rt->version == VRRP_VERSION_2) ?
			    rt->adver_int / TIMER_HZ :
			    rt->adver_int / TIMER_CENTI_HZ;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_PREEMPT:
		long_ret.u = rt->nopreempt?2:1;
		*write_method = vrrp_snmp_instance_preempt;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_PREEMPTDELAY:
		long_ret.u = rt->preempt_delay / TIMER_HZ;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_AUTHTYPE:
		long_ret.u = 0;
		if (rt->version == VRRP_VERSION_2)
#ifdef _WITH_VRRP_AUTH_
			long_ret.u = rt->auth_type;
#endif
		return (u_char *)&long_ret;
#ifdef _WITH_LVS_
	case VRRP_SNMP_INSTANCE_USELVSSYNCDAEMON:
		long_ret.u = (global_data->lvs_syncd.vrrp == rt)?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_LVSSYNCINTERFACE:
		if (global_data->lvs_syncd.vrrp == rt) {
			*var_len = strlen(global_data->lvs_syncd.ifname);
			return (u_char *)global_data->lvs_syncd.ifname;
		}
		break;
#endif
	case VRRP_SNMP_INSTANCE_SYNCGROUP:
		if (rt->sync) {
			*var_len = strlen(rt->sync->gname);
			return (u_char *)rt->sync->gname;
		}
		break;
	case VRRP_SNMP_INSTANCE_GARPDELAY:
		long_ret.u = rt->garp_delay / TIMER_HZ;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_SMTPALERT:
		long_ret.u = rt->smtp_alert?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_NOTIFYEXEC:
		long_ret.u = rt->notify_exec?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_SCRIPTMASTER:
		if (rt->script_master) {
			*var_len = strlen(rt->script_master->name);
			return (u_char *)rt->script_master->name;
		}
		break;
	case VRRP_SNMP_INSTANCE_SCRIPTBACKUP:
		if (rt->script_backup) {
			*var_len = strlen(rt->script_backup->name);
			return (u_char *)rt->script_backup->name;
		}
		break;
	case VRRP_SNMP_INSTANCE_SCRIPTFAULT:
		if (rt->script_fault) {
			*var_len = strlen(rt->script_fault->name);
			return (u_char *)rt->script_fault->name;
		}
		break;
	case VRRP_SNMP_INSTANCE_SCRIPTSTOP:
		if (rt->script_stop) {
			*var_len = strlen(rt->script_stop->name);
			return (u_char *)rt->script_stop->name;
		}
		break;
	case VRRP_SNMP_INSTANCE_SCRIPT:
		if (rt->script) {
			*var_len = strlen(rt->script->name);
			return (u_char *)rt->script->name;
		}
		break;
	case VRRP_SNMP_INSTANCE_ACCEPT:
		long_ret.u = 0;
		if (rt->version == VRRP_VERSION_3) {
			long_ret.u = rt->accept ? 1:2;
			*write_method = vrrp_snmp_instance_accept;
		}
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_PROMOTE_SECONDARIES:
		long_ret.u = rt->promote_secondaries ? 1:2;
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
	oid *target, current[2], best[2];
	int result;
	size_t target_len;
	unsigned curinstance;
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
	*length = (unsigned)vp->namelen + 2;
 trackedinterface_found:
	switch (vp->magic) {
	case VRRP_SNMP_TRACKEDINTERFACE_NAME:
		*var_len = strlen(bifp->ifp->ifname);
		return (u_char *)bifp->ifp->ifname;
	case VRRP_SNMP_TRACKEDINTERFACE_WEIGHT:
		long_ret.s = bifp->weight;
		return (u_char *)&long_ret;
	}
	return NULL;
}

static u_char*
vrrp_snmp_trackedscript(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
	oid *target, current[2], best[2];
	int result;
	size_t target_len;
	unsigned curinstance, curscr;
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
	*length = (unsigned)vp->namelen + 2;
 trackedscript_found:
	switch (vp->magic) {
	case VRRP_SNMP_TRACKEDSCRIPT_NAME:
		*var_len = strlen(bscr->scr->sname);
		return (u_char *)bscr->scr->sname;
	case VRRP_SNMP_TRACKEDSCRIPT_WEIGHT:
		long_ret.s = bscr->weight;
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
	{VRRP_SNMP_INSTANCE_PROMOTE_SECONDARIES, ASN_INTEGER, RWRITE,
	 vrrp_snmp_instance, 3, {3, 1, 28} },
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

#ifdef _HAVE_FIB_ROUTING_
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
	{VRRP_SNMP_ROUTE_FROM_ADDRESS, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 15}},
	{VRRP_SNMP_ROUTE_FROM_ADDRESS_MASK, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 16}},
	{VRRP_SNMP_ROUTE_TOS, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 17}},
	{VRRP_SNMP_ROUTE_PROTOCOL, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 18}},
	{VRRP_SNMP_ROUTE_ECN, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 19}},
	{VRRP_SNMP_ROUTE_QUICK_ACK, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 20}},
	{VRRP_SNMP_ROUTE_EXPIRES, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 21}},
	{VRRP_SNMP_ROUTE_MTU, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 22}},
	{VRRP_SNMP_ROUTE_MTU_LOCK, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 23}},
	{VRRP_SNMP_ROUTE_HOP_LIMIT, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 24}},
	{VRRP_SNMP_ROUTE_ADVMSS, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 25}},
	{VRRP_SNMP_ROUTE_ADVMSS_LOCK, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 26}},
	{VRRP_SNMP_ROUTE_RTT, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 27}},
	{VRRP_SNMP_ROUTE_RTT_LOCK, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 28}},
	{VRRP_SNMP_ROUTE_RTTVAR, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 29}},
	{VRRP_SNMP_ROUTE_RTTVAR_LOCK, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 30}},
	{VRRP_SNMP_ROUTE_REORDERING, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 31}},
	{VRRP_SNMP_ROUTE_REORDERING_LOCK, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 32}},
	{VRRP_SNMP_ROUTE_WINDOW, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 33}},
	{VRRP_SNMP_ROUTE_CWND, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 34}},
	{VRRP_SNMP_ROUTE_CWND_LOCK, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 35}},
	{VRRP_SNMP_ROUTE_SSTHRESH, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 36}},
	{VRRP_SNMP_ROUTE_SSTHRESH_LOCK, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 37}},
	{VRRP_SNMP_ROUTE_RTOMIN, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 38}},
	{VRRP_SNMP_ROUTE_RTOMIN_LOCK, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 39}},
	{VRRP_SNMP_ROUTE_INIT_CWND, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 40}},
	{VRRP_SNMP_ROUTE_INIT_RWND, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 41}},
	{VRRP_SNMP_ROUTE_CONG_CTL, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 42}},
	{VRRP_SNMP_ROUTE_PREF, ASN_INTEGER, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 43}},
	{VRRP_SNMP_ROUTE_REALM_DST, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 44}},
	{VRRP_SNMP_ROUTE_REALM_SRC, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_route, 3, {7, 1, 45}},
#if HAVE_DECL_RTA_ENCAP
	{VRRP_SNMP_ROUTE_ENCAP_TYPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_encap, 3, {7, 1, 46}},
	{VRRP_SNMP_ROUTE_ENCAP_MPLS_LABELS, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_encap, 3, {7, 1, 47}},
	{VRRP_SNMP_ROUTE_ENCAP_ID, ASN_COUNTER64, RONLY,
	 vrrp_snmp_encap, 3, {7, 1, 48}},
	{VRRP_SNMP_ROUTE_ENCAP_DST_ADDRESS, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_encap, 3, {7, 1, 49}},
	{VRRP_SNMP_ROUTE_ENCAP_SRC_ADDRESS, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_encap, 3, {7, 1, 50}},
	{VRRP_SNMP_ROUTE_ENCAP_TOS, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_encap, 3, {7, 1, 51}},
	{VRRP_SNMP_ROUTE_ENCAP_TTL, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_encap, 3, {7, 1, 52}},
	{VRRP_SNMP_ROUTE_ENCAP_FLAGS, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_encap, 3, {7, 1, 53}},
	{VRRP_SNMP_ROUTE_ENCAP_ILA_LOCATOR, ASN_COUNTER64, RONLY,
	 vrrp_snmp_encap, 3, {7, 1, 54}},
#endif

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
	{VRRP_SNMP_RULE_INVERT, ASN_INTEGER, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 8}},
	{VRRP_SNMP_RULE_DESTINATIONADDRESSTYPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 9}},
	{VRRP_SNMP_RULE_DESTINATIONADDRESS, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 10}},
	{VRRP_SNMP_RULE_DESTINATIONADDRESSMASK, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 11}},
	{VRRP_SNMP_RULE_SOURCEADDRESSTYPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 12}},
	{VRRP_SNMP_RULE_SOURCEADDRESS, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 13}},
	{VRRP_SNMP_RULE_SOURCEADDRESSMASK, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 14}},
	{VRRP_SNMP_RULE_TOS, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 15}},
	{VRRP_SNMP_RULE_FWMARK, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 16}},
	{VRRP_SNMP_RULE_FWMASK, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 17}},
	{VRRP_SNMP_RULE_REALM_DST, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 18}},
	{VRRP_SNMP_RULE_REALM_SRC, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 19}},
	{VRRP_SNMP_RULE_ININTERFACE, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 20}},
	{VRRP_SNMP_RULE_OUTINTERFACE, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 21}},
	{VRRP_SNMP_RULE_TARGET, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 22}},
	{VRRP_SNMP_RULE_ACTION, ASN_INTEGER, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 23}},
	{VRRP_SNMP_RULE_TABLE_NO, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 24}},
	{VRRP_SNMP_RULE_PREFERENCE, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 25}},
	{VRRP_SNMP_RULE_SUPPRESSPREFIXLEN, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 26}},
	{VRRP_SNMP_RULE_SUPPRESSGROUP, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 27}},
	{VRRP_SNMP_RULE_TUNNELID_HIGH, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 28}},
	{VRRP_SNMP_RULE_TUNNELID_LOW, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_rule, 3, {8, 1, 29}},
#endif

	/* vrrpScriptTable */
	{VRRP_SNMP_SCRIPT_NAME, ASN_OCTET_STR, RONLY, vrrp_snmp_script, 3, {9, 1, 2}},
	{VRRP_SNMP_SCRIPT_COMMAND, ASN_OCTET_STR, RONLY, vrrp_snmp_script, 3, {9, 1, 3}},
	{VRRP_SNMP_SCRIPT_INTERVAL, ASN_INTEGER, RONLY, vrrp_snmp_script, 3, {9, 1, 4}},
	{VRRP_SNMP_SCRIPT_WEIGHT, ASN_INTEGER, RONLY, vrrp_snmp_script, 3, {9, 1, 5}},
	{VRRP_SNMP_SCRIPT_RESULT, ASN_INTEGER, RONLY, vrrp_snmp_script, 3, {9, 1, 6}},
	{VRRP_SNMP_SCRIPT_RISE, ASN_UNSIGNED, RONLY, vrrp_snmp_script, 3, {9, 1, 7}},
	{VRRP_SNMP_SCRIPT_FALL, ASN_UNSIGNED, RONLY, vrrp_snmp_script, 3, {9, 1, 8}},

#ifdef _HAVE_FIB_ROUTING_
	/* vrrpRouteNextHopTable */
	{VRRP_SNMP_ROUTE_NEXT_HOP_ADDRESS_TYPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_next_hop, 3, {11, 1, 2}},
	{VRRP_SNMP_ROUTE_NEXT_HOP_ADDRESS, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_next_hop, 3, {11, 1, 3}},
	{VRRP_SNMP_ROUTE_NEXT_HOP_IF_INDEX, ASN_INTEGER, RONLY,
	 vrrp_snmp_next_hop, 3, {11, 1, 4}},
	{VRRP_SNMP_ROUTE_NEXT_HOP_IF_NAME, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_next_hop, 3, {11, 1, 5}},
	{VRRP_SNMP_ROUTE_NEXT_HOP_WEIGHT, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_next_hop, 3, {11, 1, 6}},
	{VRRP_SNMP_ROUTE_NEXT_HOP_ONLINK, ASN_INTEGER, RONLY,
	 vrrp_snmp_next_hop, 3, {11, 1, 7}},
	{VRRP_SNMP_ROUTE_NEXT_HOP_REALM_DST, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_next_hop, 3, {11, 1, 8}},
	{VRRP_SNMP_ROUTE_NEXT_HOP_REALM_SRC, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_next_hop, 3, {11, 1, 9}},
#if HAVE_DECL_RTA_ENCAP
	{VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_TYPE, ASN_INTEGER, RONLY,
	 vrrp_snmp_encap, 3, {11, 1, 10}},
	{VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_MPLS_LABELS, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_encap, 3, {11, 1, 11}},
	{VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_ID, ASN_COUNTER64, RONLY,
	 vrrp_snmp_encap, 3, {11, 1, 12}},
	{VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_DST_ADDRESS, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_encap, 3, {11, 1, 13}},
	{VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_SRC_ADDRESS, ASN_OCTET_STR, RONLY,
	 vrrp_snmp_encap, 3, {11, 1, 14}},
	{VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_TOS, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_encap, 3, {11, 1, 15}},
	{VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_TTL, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_encap, 3, {11, 1, 16}},
	{VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_FLAGS, ASN_UNSIGNED, RONLY,
	 vrrp_snmp_encap, 3, {11, 1, 17}},
	{VRRP_SNMP_ROUTE_NEXT_HOP_ENCAP_ILA_LOCATOR, ASN_COUNTER64, RONLY,
	 vrrp_snmp_encap, 3, {11, 1, 18}},
#endif
#endif
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
static int
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
		target_addr.s_addr = (in_addr_t)(name[*length - 4] << 24 |
						 name[*length - 3] << 16 |
						 name[*length - 2] << 8 |
						 name[*length - 1]);
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
	*length = (unsigned)vp->namelen + 2;
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

	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;

	if (vp->magic == VRRP_RFC_SNMP_NODE_VER) {
		long_ret.u = 2;
		return (u_char*)&long_ret;
	}

	if (vp->magic == VRRP_RFC_SNMP_NOTIF_CNTL) {
		long_ret.u = global_data->enable_traps ? 1 : 2 ;
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
	*length = (unsigned)vp->namelen + 2;
	return bel;
}

static u_char*
vrrp_rfcv2_snmp_opertable(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
	vrrp_t *rt;
	interface_t* ifp;
	timeval_t uptime;

	if ((rt = snmp_rfcv2_header_list_table(vp, name, length, exact,
					     var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_RFC_SNMP_OPER_VRID:
		long_ret.u = rt->vrid;
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_VMAC:
		*var_len = rt->ifp->hw_addr_len;
		return (u_char*)&rt->ifp->hw_addr;
	case VRRP_RFC_SNMP_OPER_STATE:
		long_ret.s = vrrp_snmp_rfc_state(rt->state);
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_ADM_STATE:
		/* If we implement write access, then this could be 2 for down */
		long_ret.u = 1;
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_PRI:
		long_ret.u = rt->base_priority;
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_ADDR_CNT:
		if (LIST_ISEMPTY(rt->vip))
			long_ret.u = 0;
		else
			long_ret.u = LIST_SIZE(rt->vip);
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_MIP:
		return (u_char*)&((struct sockaddr_in *)&rt->master_saddr)->sin_addr.s_addr;
	case VRRP_RFC_SNMP_OPER_PIP:
#ifdef _HAVE_VRRP_VMAC_
		if (rt->ifp->vmac)
			ifp = if_get_by_ifindex(rt->ifp->base_ifindex);
		else
#endif
			ifp = rt->ifp;
		return (u_char*)&ifp->sin_addr;
	case VRRP_RFC_SNMP_OPER_AUTH_TYPE:
#ifdef _WITH_VRRP_AUTH_
		long_ret.s = rt->auth_type + 1;
#else
		long_ret.s = 1;
#endif
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_AUTH_KEY:
		*var_len = 0;		// Not readable
		return NULL;
	case VRRP_RFC_SNMP_OPER_ADVERT_INT:
		long_ret.u = rt->adver_int / TIMER_HZ;
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_PREEMPT:
		long_ret.s =  1 + rt->nopreempt;
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_VR_UPTIME:
		if (rt->state == VRRP_STATE_BACK ||
		    rt->state == VRRP_STATE_MAST) {
			uptime = timer_sub(rt->stats->uptime, vrrp_start_time);
			long_ret.s = uptime.tv_sec * 100 + uptime.tv_usec / 10000;	// unit is centi-seconds
		}
		else
			long_ret.u = 0;
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_PROTO:
		long_ret.u = 1;	// IP
		return (u_char*)&long_ret;
	case VRRP_RFC_SNMP_OPER_ROW_STAT:
		long_ret.u = 1;	// active - 1, notInService - 2, notReady - 3, createAndGo - 4, createAndWait - 5
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
		long_ret.u = 1;
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
	element e;
	vrrp_t *vrrp;

	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;

	if (vp->magic != VRRP_RFC_SNMP_STATS_CHK_ERR &&
	    vp->magic != VRRP_RFC_SNMP_STATS_VER_ERR &&
	    vp->magic != VRRP_RFC_SNMP_STATS_VRID_ERR)
		return NULL;

	long_ret.u = 0;

	if (LIST_ISEMPTY(vrrp_data->vrrp))
		return (u_char*)&long_ret;

	/* Work through all the vrrp instances that we can respond for */
	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		if (!suitable_for_rfc2787(vrrp))
			continue;

		switch (vp->magic) {
		case VRRP_RFC_SNMP_STATS_CHK_ERR:
			long_ret.u += vrrp->stats->chk_err;
			break;
		case VRRP_RFC_SNMP_STATS_VER_ERR:
			long_ret.u += vrrp->stats->vers_err;
			break;
		case VRRP_RFC_SNMP_STATS_VRID_ERR:
			long_ret.u += vrrp->stats->vrid_err;
			break;
		}
	}

	return (u_char *)&long_ret;
}
static u_char*
vrrp_rfcv2_snmp_statstable(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
	vrrp_t *rt;

	if ((rt = snmp_rfcv2_header_list_table(vp, name, length, exact,
					     var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_RFC_SNMP_STATS_MASTER:
		long_ret.u = rt->stats->become_master;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_ADV_RCVD:
		long_ret.u = rt->stats->advert_rcvd;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_ADV_INT_ERR:
		long_ret.u = rt->stats->advert_interval_err;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_AUTH_FAIL:
		long_ret.u = rt->stats->auth_failure;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_TTL_ERR:
		long_ret.u = rt->stats->ip_ttl_err;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_PRI_0_RCVD:
		long_ret.u = rt->stats->pri_zero_rcvd;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_PRI_0_SENT:
		long_ret.u = rt->stats->pri_zero_sent;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_INV_TYPE_RCVD:
		long_ret.u = rt->stats->invalid_type_rcvd;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_ADDR_LIST_ERR:
		long_ret.u = rt->stats->addr_list_err;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_AUTH_INV:
		long_ret.u = rt->stats->invalid_authtype;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_AUTH_MIS:
		long_ret.u = rt->stats->authtype_mismatch;
		return (u_char *)&long_ret;
	case VRRP_RFC_SNMP_STATS_PL_ERR:
		long_ret.u = rt->stats->packet_len_err;
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

static bool
suitable_for_rfc6527(vrrp_t* vrrp)
{
#ifndef _SNMP_REPLY_V3_FOR_V2_
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
	size_t i;
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
	size_t i;

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
		target_addr.s_addr = (in_addr_t)(name[*length - 4] << 24 |
						 name[*length - 3] << 16 |
						 name[*length - 2] << 8 |
						 name[*length - 1]);
	}
	else if (target_len == 3 + 1 + 16) {
		target_len = 3;
		for (i = 0; i < 16; i++)
			target_addr6.s6_addr[i] = (uint8_t)name[*length - 16 + i];
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
	*length = (unsigned)vp->namelen + 3;
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
	*length = (unsigned)vp->namelen + 3;
	return bel;
}

static u_char*
vrrp_rfcv3_snmp_opertable(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
	vrrp_t *rt;
	interface_t* ifp;
	timeval_t uptime;

	if ((rt = snmp_rfcv3_header_list_table(vp, name, length, exact,
					     var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case VRRP_RFCv3_SNMP_OPER_VRID:
		long_ret.u = rt->vrid;
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_INET_ADDR_TYPE:
		long_ret.u = rt->family == AF_INET ? 1 : 2;
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
#ifdef _HAVE_VRRP_VMAC_
		if (rt->ifp->vmac)
			ifp = if_get_by_ifindex(rt->ifp->base_ifindex);
		else
#endif
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
		long_ret.s = vrrp_snmp_rfc_state(rt->state);
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_PRI:
		long_ret.u = rt->base_priority;
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_ADDR_CNT:
		if (LIST_ISEMPTY(rt->vip))
			long_ret.u = 0;
		else
			long_ret.u = LIST_SIZE(rt->vip);
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_ADVERT_INT:
		long_ret.u = rt->adver_int / TIMER_CENTI_HZ;
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_PREEMPT:
		long_ret.s =  1 + rt->nopreempt;
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_ACCEPT:
		long_ret.u =  1 + rt->accept;
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_VR_UPTIME:
		if (rt->state == VRRP_STATE_BACK ||
		    rt->state == VRRP_STATE_MAST) {
			uptime = timer_sub(rt->stats->uptime, vrrp_start_time);
			long_ret.s = uptime.tv_sec * 100 + uptime.tv_usec / 10000;	// unit is centi-seconds
		}
		else
			long_ret.s = 0;
		return (u_char*)&long_ret;
	case VRRP_RFCv3_SNMP_OPER_ROW_STATUS:
		long_ret.u = 1;	// active - 1, notInService - 2, notReady - 3, createAndGo - 4, createAndWait - 5
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
		long_ret.u = 1;
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
	static uint32_t ret;
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
	if (vp->magic == VRRP_RFCv3_SNMP_STATS_DISC_TIME) {
		// We don't "do" discontinuities
		*var_len = sizeof(ret);
		ret = 0;
		return (u_char *)&ret;
	}

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
	uint32_t reason = vrrp->stats->master_reason;

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
#ifdef _WITH_LVS_
		if (!__test_bit(DAEMON_CHECKERS, &daemon_mode) || !global_data->enable_snmp_checker)
			return true;
#else
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
