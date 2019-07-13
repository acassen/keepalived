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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <stdint.h>

#include "check_snmp.h"
#include "ipwrapper.h"
#include "global_data.h"
#include "snmp.h"
#include "utils.h"
#include "parser.h"

/* CHECK SNMP defines */
#define CHECK_OID KEEPALIVED_OID, 3

enum check_snmp_vsgroup_magic {
	CHECK_SNMP_VSGROUPNAME = 2
};

enum check_snmp_vsgroupmember_magic {
	CHECK_SNMP_VSGROUPMEMBERTYPE = 2,
	CHECK_SNMP_VSGROUPMEMBERFWMARK,
	CHECK_SNMP_VSGROUPMEMBERADDRTYPE,
	CHECK_SNMP_VSGROUPMEMBERADDRESS,
	CHECK_SNMP_VSGROUPMEMBERADDR1,
	CHECK_SNMP_VSGROUPMEMBERADDR2,
	CHECK_SNMP_VSGROUPMEMBERPORT
};

enum check_snmp_virtualserver_magic {
	CHECK_SNMP_VSTYPE = 2,
	CHECK_SNMP_VSNAMEGROUP,
	CHECK_SNMP_VSFWMARK,
	CHECK_SNMP_VSADDRTYPE,
	CHECK_SNMP_VSADDRESS,
	CHECK_SNMP_VSPORT,
	CHECK_SNMP_VSPROTOCOL,
	CHECK_SNMP_VSLOADBALANCINGALGO,
	CHECK_SNMP_VSLOADBALANCINGKIND,
	CHECK_SNMP_VSSTATUS,
	CHECK_SNMP_VSVIRTUALHOST,
	CHECK_SNMP_VSPERSIST,
	CHECK_SNMP_VSPERSISTTIMEOUT,
	CHECK_SNMP_VSPERSISTGRANULARITY,
	CHECK_SNMP_VSPERSISTGRANULARITY6,
	CHECK_SNMP_VSDELAYLOOP,
	CHECK_SNMP_VSHASUSPEND,
	CHECK_SNMP_VSOPS,
	CHECK_SNMP_VSALPHA,
	CHECK_SNMP_VSOMEGA,
	CHECK_SNMP_VSQUORUM,
	CHECK_SNMP_VSQUORUMSTATUS,
	CHECK_SNMP_VSQUORUMUP,
	CHECK_SNMP_VSQUORUMDOWN,
	CHECK_SNMP_VSHYSTERESIS,
	CHECK_SNMP_VSREALTOTAL,
	CHECK_SNMP_VSREALUP,
	CHECK_SNMP_VSSTATSCONNS,
	CHECK_SNMP_VSSTATSINPKTS,
	CHECK_SNMP_VSSTATSOUTPKTS,
	CHECK_SNMP_VSSTATSINBYTES,
	CHECK_SNMP_VSSTATSOUTBYTES,
	CHECK_SNMP_VSRATECPS,
	CHECK_SNMP_VSRATEINPPS,
	CHECK_SNMP_VSRATEOUTPPS,
	CHECK_SNMP_VSRATEINBPS,
	CHECK_SNMP_VSRATEOUTBPS,
#ifdef _WITH_LVS_64BIT_STATS_
	CHECK_SNMP_VSSTATSCONNS64,
	CHECK_SNMP_VSSTATSINPKTS64,
	CHECK_SNMP_VSSTATSOUTPKTS64,
	CHECK_SNMP_VSRATECPSLOW,
	CHECK_SNMP_VSRATECPSHIGH,
	CHECK_SNMP_VSRATEINPPSLOW,
	CHECK_SNMP_VSRATEINPPSHIGH,
	CHECK_SNMP_VSRATEOUTPPSLOW,
	CHECK_SNMP_VSRATEOUTPPSHIGH,
	CHECK_SNMP_VSRATEINBPSLOW,
	CHECK_SNMP_VSRATEINBPSHIGH,
	CHECK_SNMP_VSRATEOUTBPSLOW,
	CHECK_SNMP_VSRATEOUTBPSHIGH,
#endif
	CHECK_SNMP_VSHASHED,
	CHECK_SNMP_VSSHFALLBACK,
	CHECK_SNMP_VSSHPORT,
	CHECK_SNMP_VSMHFALLBACK,
	CHECK_SNMP_VSMHPORT,
	CHECK_SNMP_VSSCHED3,
	CHECK_SNMP_VSACTIONWHENDOWN,
	CHECK_SNMP_VSRETRY,
	CHECK_SNMP_VSDELAYBEFORERETRY,
	CHECK_SNMP_VSWARMUP,
	CHECK_SNMP_VSWEIGHT,
	CHECK_SNMP_VSSMTPALERT,
	CHECK_SNMP_VSDELAYLOOPUSEC,
	CHECK_SNMP_VSDELAYBEFORERETRYUSEC,
	CHECK_SNMP_VSWARMUPUSEC,
	CHECK_SNMP_VSCONNTIMEOUTUSEC,
	CHECK_SNMP_VSTUNNELTYPE,
#ifdef _HAVE_IPVS_TUN_TYPE_
	CHECK_SNMP_VSTUNNELPORT,
#ifdef _HAVE_IPVS_TUN_CSUM_
	CHECK_SNMP_VSTUNNELCSUM,
#endif
#endif
};

enum check_snmp_realserver_magic {
	CHECK_SNMP_RSTYPE,
	CHECK_SNMP_RSADDRTYPE,
	CHECK_SNMP_RSADDRESS,
	CHECK_SNMP_RSPORT,
	CHECK_SNMP_RSSTATUS,
	CHECK_SNMP_RSWEIGHT,
	CHECK_SNMP_RSUPPERCONNECTIONLIMIT,
	CHECK_SNMP_RSLOWERCONNECTIONLIMIT,
	CHECK_SNMP_RSACTIONWHENDOWN,
	CHECK_SNMP_RSNOTIFYUP,
	CHECK_SNMP_RSNOTIFYDOWN,
	CHECK_SNMP_RSFAILEDCHECKS,
	CHECK_SNMP_RSSTATSCONNS,
	CHECK_SNMP_RSSTATSACTIVECONNS,
	CHECK_SNMP_RSSTATSINACTIVECONNS,
	CHECK_SNMP_RSSTATSPERSISTENTCONNS,
	CHECK_SNMP_RSSTATSINPKTS,
	CHECK_SNMP_RSSTATSOUTPKTS,
	CHECK_SNMP_RSSTATSINBYTES,
	CHECK_SNMP_RSSTATSOUTBYTES,
	CHECK_SNMP_RSRATECPS,
	CHECK_SNMP_RSRATEINPPS,
	CHECK_SNMP_RSRATEOUTPPS,
	CHECK_SNMP_RSRATEINBPS,
	CHECK_SNMP_RSRATEOUTBPS,
#ifdef _WITH_LVS_64BIT_STATS_
	CHECK_SNMP_RSSTATSCONNS64,
	CHECK_SNMP_RSSTATSINPKTS64,
	CHECK_SNMP_RSSTATSOUTPKTS64,
	CHECK_SNMP_RSRATECPSLOW,
	CHECK_SNMP_RSRATECPSHIGH,
	CHECK_SNMP_RSRATEINPPSLOW,
	CHECK_SNMP_RSRATEINPPSHIGH,
	CHECK_SNMP_RSRATEOUTPPSLOW,
	CHECK_SNMP_RSRATEOUTPPSHIGH,
	CHECK_SNMP_RSRATEINBPSLOW,
	CHECK_SNMP_RSRATEINBPSHIGH,
	CHECK_SNMP_RSRATEOUTBPSLOW,
	CHECK_SNMP_RSRATEOUTBPSHIGH,
#endif
	CHECK_SNMP_RSLOADBALANCINGKIND,
	CHECK_SNMP_RSVIRTUALHOST,
	CHECK_SNMP_RSALPHA,
	CHECK_SNMP_RSRETRY,
	CHECK_SNMP_RSDELAYBEFORERETRY,
	CHECK_SNMP_RSWARMUP,
	CHECK_SNMP_RSDELAYLOOP,
	CHECK_SNMP_RSSMTPALERT,
	CHECK_SNMP_RSDELAYBEFORERETRYUSEC,
	CHECK_SNMP_RSWARMUPUSEC,
	CHECK_SNMP_RSDELAYLOOPUSEC,
	CHECK_SNMP_RSCONNTIMEOUTUSEC,
	CHECK_SNMP_RSTUNNELTYPE,
#ifdef _HAVE_IPVS_TUN_TYPE_
	CHECK_SNMP_RSTUNNELPORT,
#ifdef _HAVE_IPVS_TUN_CSUM_
	CHECK_SNMP_RSTUNNELCSUM,
#endif
#endif
};

#define STATE_VSGM_FWMARK 1
#define STATE_VSGM_ADDRESS_RANGE 2
#define STATE_VSGM_END 3

#define STATE_RS_SORRY 1
#define STATE_RS_REGULAR_FIRST 2
#define STATE_RS_REGULAR_NEXT 3
#define STATE_RS_END 4

#ifdef _WITH_VRRP_
enum check_snmp_lvs_sync_daemon {
	CHECK_SNMP_LVSSYNCDAEMONENABLED,
	CHECK_SNMP_LVSSYNCDAEMONINTERFACE,
	CHECK_SNMP_LVSSYNCDAEMONVRRPINSTANCE,
	CHECK_SNMP_LVSSYNCDAEMONSYNCID,
#ifdef _HAVE_IPVS_SYNCD_ATTRIBUTES_
	CHECK_SNMP_LVSSYNCDAEMONMAXLEN,
	CHECK_SNMP_LVSSYNCDAEMONPORT,
	CHECK_SNMP_LVSSYNCDAEMONTTL,
	CHECK_SNMP_LVSSYNCDAEMONMCASTGROUPADDRTYPE,
	CHECK_SNMP_LVSSYNCDAEMONMCASTGROUPADDRVALUE,
#endif
};
#endif

enum check_snmp_lvs_timeouts {
	CHECK_SNMP_LVSTIMEOUTTCP,
	CHECK_SNMP_LVSTIMEOUTTCPFIN,
	CHECK_SNMP_LVSTIMEOUTUDP,
};

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

/* Static return value */
static longret_t long_ret;
static char buf[MAXBUF];

static u_char*
check_snmp_vsgroup(struct variable *vp, oid *name, size_t *length,
		   int exact, size_t *var_len, WriteMethod **write_method)
{
	virtual_server_group_t *g;

	if ((g = (virtual_server_group_t *)
	     snmp_header_list_table(vp, name, length, exact,
				    var_len, write_method,
				    check_data->vs_group)) == NULL)
		return NULL;

	switch (vp->magic) {
	case CHECK_SNMP_VSGROUPNAME:
		*var_len = strlen(g->gname);
		return (u_char *)g->gname;
	default:
		break;
	}
	return NULL;
}

static u_char*
check_snmp_vsgroupmember(struct variable *vp, oid *name, size_t *length,
			 int exact, size_t *var_len, WriteMethod **write_method)
{
	static uint32_t ip;
	static struct in6_addr ip6;
	oid *target, current[2], best[2];
	int result;
	size_t target_len;
	unsigned curgroup = 0, curentry;
	element e1, e2;
	virtual_server_group_t *group;
	virtual_server_group_entry_t *e, *be = NULL;
	int state;
	list l;


	if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
	}

	*write_method = 0;
	*var_len = sizeof(long);

	if (LIST_ISEMPTY(check_data->vs_group))
		return NULL;

	/* We search the best match: equal if exact, the lower OID in
	   the set of the OID strictly superior to the target
	   otherwise. */
	best[0] = best[1] = MAX_SUBID; /* Our best match */
	target = &name[vp->namelen];   /* Our target match */
	target_len = *length - vp->namelen;
	LIST_FOREACH(check_data->vs_group, group, e1) {
		curgroup++;
		curentry = 0;
		if (target_len && (curgroup < target[0]))
			continue; /* Optimization: cannot be part of our set */
		state = STATE_VSGM_FWMARK;
		while (state < STATE_VSGM_END) {
			switch (state) {
			case STATE_VSGM_FWMARK:
				l = group->vfwmark;
				break;
			case STATE_VSGM_ADDRESS_RANGE:
				l = group->addr_range;
				break;
			default:
				/* Dunno? */
				return NULL;
			}
			state++;
			LIST_FOREACH(l, e, e2) {
				curentry++;
				/* We build our current match */
				current[0] = curgroup;
				current[1] = curentry;
				/* And compare it to our target match */
				if ((result = snmp_oid_compare(current, 2, target,
							       target_len)) < 0)
					continue;
				if ((result == 0) && !exact)
					continue;
				if (result == 0) {
					/* Got an exact match and asked for it */
					be = e;
					goto vsgmember_found;
				}
				if (snmp_oid_compare(current, 2, best, 2) < 0) {
					/* This is our best match */
					memcpy(best, current, sizeof(oid) * 2);
					be = e;
					goto vsgmember_be_found;
				}
			}
		}
	}

	/* Nothing found */
	return NULL;

 vsgmember_be_found:
	/* Let's use our best match */
	memcpy(target, best, sizeof(oid) * 2);
	*length = (unsigned)vp->namelen + 2;
 vsgmember_found:
	switch (vp->magic) {
	case CHECK_SNMP_VSGROUPMEMBERTYPE:
		if (be->is_fwmark)
			long_ret.u = 1;
		else if (be->range)
			long_ret.u = 3;
		else
			long_ret.u = 2;
		return (u_char *)&long_ret;
	case CHECK_SNMP_VSGROUPMEMBERFWMARK:
		if (!be->is_fwmark) break;
		long_ret.u = be->vfwmark;
		return (u_char *)&long_ret;
	case CHECK_SNMP_VSGROUPMEMBERADDRTYPE:
		if (be->is_fwmark) break;
		long_ret.u = (be->addr.ss_family == AF_INET6) ? 2:1;
		return (u_char *)&long_ret;
	case CHECK_SNMP_VSGROUPMEMBERADDRESS:
		if (be->is_fwmark || be->range) break;
		RETURN_IP46ADDRESS(be);
		break;
	case CHECK_SNMP_VSGROUPMEMBERADDR1:
		if (be->is_fwmark || !be->range) break;
		RETURN_IP46ADDRESS(be);
		break;
	case CHECK_SNMP_VSGROUPMEMBERADDR2:
		if (!be->range || be->is_fwmark) break;
		if (be->addr.ss_family == AF_INET6) {
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&be->addr;
			*var_len = 16;
			memcpy(&ip6, &addr6->sin6_addr, sizeof(ip6));
			ip6.s6_addr16[7] = htons(ntohs(ip6.s6_addr16[7]) + be->range);
			return (u_char *)&ip6;
		} else {
			struct sockaddr_in *addr4 = (struct sockaddr_in *)&be->addr;
			*var_len = 4;
			ip = *(uint32_t *)&addr4->sin_addr;
			ip += htonl(be->range);
			return (u_char *)&ip;
		}
		break;
	case CHECK_SNMP_VSGROUPMEMBERPORT:
		if (be->is_fwmark) break;
		long_ret.u = htons(inet_sockaddrport(&be->addr));
		return (u_char *)&long_ret;
	default:
		return NULL;
	}
	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return check_snmp_vsgroupmember(vp, name, length,
						exact, var_len, write_method);
	return NULL;
}

static u_char*
check_snmp_virtualserver(struct variable *vp, oid *name, size_t *length,
			 int exact, size_t *var_len, WriteMethod **write_method)
{
	static struct counter64 counter64_ret;
	virtual_server_t *v;
	element e;
	snmp_ret_t ret;

	if ((v = (virtual_server_t *)
	     snmp_header_list_table(vp, name, length, exact,
				    var_len, write_method,
				    check_data->vs)) == NULL)
		return NULL;

	switch (vp->magic) {
	case CHECK_SNMP_VSTYPE:
		if (v->vsg)
			long_ret.u = 3;
		else if (v->vfwmark)
			long_ret.u = 1;
		else
			long_ret.u = 2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSNAMEGROUP:
		if (!v->vsg) break;
		ret.cp = v->vsgname;
		*var_len = strlen(ret.cp);
		return ret.p;
	case CHECK_SNMP_VSFWMARK:
		if (!v->vfwmark) break;
		long_ret.u = v->vfwmark;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSADDRTYPE:
		long_ret.u = (v->af == AF_INET6) ? 2:1;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSADDRESS:
		if (v->vfwmark || v->vsg) break;
		RETURN_IP46ADDRESS(v);
		break;
	case CHECK_SNMP_VSPORT:
		if (v->vfwmark || v->vsg) break;
		long_ret.u = htons(inet_sockaddrport(&v->addr));
		return (u_char *)&long_ret;
	case CHECK_SNMP_VSPROTOCOL:
		if (v->vfwmark) break;
		long_ret.u = (v->service_type == IPPROTO_TCP) ? 1 :
			     (v->service_type == IPPROTO_UDP) ? 2 :
			     (v->service_type == IPPROTO_SCTP) ? 3 : 4;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSLOADBALANCINGALGO:
		if (!strcmp(v->sched, "rr"))
			long_ret.u = 1;
		else if (!strcmp(v->sched, "wrr"))
			long_ret.u = 2;
		else if (!strcmp(v->sched, "lc"))
			long_ret.u = 3;
		else if (!strcmp(v->sched, "wlc"))
			long_ret.u = 4;
		else if (!strcmp(v->sched, "lblc"))
			long_ret.u = 5;
		else if (!strcmp(v->sched, "lblcr"))
			long_ret.u = 6;
		else if (!strcmp(v->sched, "dh"))
			long_ret.u = 7;
		else if (!strcmp(v->sched, "sh"))
			long_ret.u = 8;
		else if (!strcmp(v->sched, "sed"))
			long_ret.u = 9;
		else if (!strcmp(v->sched, "nq"))
			long_ret.u = 10;
		else if (!strcmp(v->sched, "fo"))
			long_ret.u = 11;
		else if (!strcmp(v->sched, "ovf"))
			long_ret.u = 12;
		else if (!strcmp(v->sched, "mh"))
			long_ret.u = 13;
		else
			long_ret.u = 99;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSLOADBALANCINGKIND:
		long_ret.u = 0;
		switch (v->forwarding_method) {
		case IP_VS_CONN_F_MASQ:
			long_ret.u = 1;
			break;
		case IP_VS_CONN_F_DROUTE:
			long_ret.u = 2;
			break;
		case IP_VS_CONN_F_TUNNEL:
			long_ret.u = 3;
			break;
		}
		if (!long_ret.u) break;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSSTATUS:
		long_ret.u = v->alive?1:2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSVIRTUALHOST:
		if (!v->virtualhost) break;
		*var_len = strlen(v->virtualhost);
		ret.cp = v->virtualhost;
		return ret.p;
	case CHECK_SNMP_VSPERSIST:
		long_ret.u = (v->persistence_timeout)?1:2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSPERSISTTIMEOUT:
		if (!v->persistence_timeout) break;
		long_ret.u = v->persistence_timeout;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSPERSISTGRANULARITY:
		if (!v->persistence_granularity || v->addr.ss_family == AF_INET6) break;
		*var_len = sizeof(v->persistence_granularity);
		return (u_char*)&v->persistence_granularity;
	case CHECK_SNMP_VSPERSISTGRANULARITY6:
		if (!v->persistence_granularity || v->addr.ss_family == AF_INET) break;
		*var_len = sizeof(v->persistence_granularity);
		return (u_char*)&v->persistence_granularity;
	case CHECK_SNMP_VSDELAYLOOP:
		long_ret.u = v->delay_loop/TIMER_HZ;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSHASUSPEND:
		long_ret.u = v->ha_suspend?1:2;
		return (u_char*)&long_ret;
#ifdef IP_VS_SVC_F_ONEPACKET
	case CHECK_SNMP_VSOPS:
		long_ret.u = v->flags & IP_VS_SVC_F_ONEPACKET?1:2;
		return (u_char*)&long_ret;
#endif
	case CHECK_SNMP_VSALPHA:
		long_ret.u = v->alpha?1:2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSOMEGA:
		long_ret.u = v->omega?1:2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSQUORUM:
		long_ret.u = v->quorum;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSQUORUMSTATUS:
		long_ret.u = v->quorum_state_up ? 1 : 2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSQUORUMUP:
		if (!v->notify_quorum_up) break;
		cmd_str_r(v->notify_quorum_up, buf, sizeof(buf));
		*var_len = strlen(buf);
		return (u_char*)buf;
	case CHECK_SNMP_VSQUORUMDOWN:
		if (!v->notify_quorum_down) break;
		cmd_str_r(v->notify_quorum_down, buf, sizeof(buf));
		*var_len = strlen(buf);
		return (u_char*)buf;
	case CHECK_SNMP_VSHYSTERESIS:
		long_ret.u = v->hysteresis;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSREALTOTAL:
		if (LIST_ISEMPTY(v->rs))
			long_ret.u = 0;
		else
			long_ret.u = LIST_SIZE(v->rs);
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSREALUP:
		long_ret.u = 0;
		if (!LIST_ISEMPTY(v->rs))
			for (e = LIST_HEAD(v->rs); e; ELEMENT_NEXT(e))
				if (((real_server_t *)ELEMENT_DATA(e))->alive)
					long_ret.u++;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSSTATSCONNS:
		ipvs_update_stats(v);
		long_ret.u = v->stats.conns;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSSTATSINPKTS:
		ipvs_update_stats(v);
		long_ret.u = v->stats.inpkts;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSSTATSOUTPKTS:
		ipvs_update_stats(v);
		long_ret.u = v->stats.outpkts;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSSTATSINBYTES:
		ipvs_update_stats(v);
		counter64_ret.low = v->stats.inbytes & 0xffffffff;
		counter64_ret.high = v->stats.inbytes >> 32;
		*var_len = sizeof(struct counter64);
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_VSSTATSOUTBYTES:
		ipvs_update_stats(v);
		counter64_ret.low = v->stats.outbytes & 0xffffffff;
		counter64_ret.high = v->stats.outbytes >> 32;
		*var_len = sizeof(struct counter64);
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_VSRATECPS:
		ipvs_update_stats(v);
		long_ret.u = v->stats.cps;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSRATEINPPS:
		ipvs_update_stats(v);
		long_ret.u = v->stats.inpps;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSRATEOUTPPS:
		ipvs_update_stats(v);
		long_ret.u = v->stats.outpps;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSRATEINBPS:
		ipvs_update_stats(v);
		long_ret.u = v->stats.inbps;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSRATEOUTBPS:
		ipvs_update_stats(v);
		long_ret.u = v->stats.outbps;
		return (u_char*)&long_ret;
#ifdef _WITH_LVS_64BIT_STATS_
	case CHECK_SNMP_VSSTATSCONNS64:
		ipvs_update_stats(v);
		counter64_ret.low = v->stats.conns & 0xffffffff;
		counter64_ret.high = v->stats.conns >> 32;
		*var_len = sizeof(struct counter64);
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_VSSTATSINPKTS64:
		ipvs_update_stats(v);
		counter64_ret.low = v->stats.inpkts & 0xffffffff;
		counter64_ret.high = v->stats.inpkts >> 32;
		*var_len = sizeof(struct counter64);
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_VSSTATSOUTPKTS64:
		ipvs_update_stats(v);
		counter64_ret.low = v->stats.outpkts & 0xffffffff;
		counter64_ret.high = v->stats.outpkts >> 32;
		*var_len = sizeof(struct counter64);
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_VSRATECPSLOW:
		ipvs_update_stats(v);
		long_ret.u = v->stats.cps & 0xffffffff;
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_VSRATECPSHIGH:
		ipvs_update_stats(v);
		long_ret.u = v->stats.cps >> 32;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSRATEINPPSLOW:
		ipvs_update_stats(v);
		long_ret.u = v->stats.inpps & 0xffffffff;
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_VSRATEINPPSHIGH:
		ipvs_update_stats(v);
		long_ret.u = v->stats.inpps >> 32;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSRATEOUTPPSLOW:
		ipvs_update_stats(v);
		long_ret.u = v->stats.outpps & 0xffffffff;
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_VSRATEOUTPPSHIGH:
		ipvs_update_stats(v);
		long_ret.u = v->stats.outpps >> 32;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSRATEINBPSLOW:
		ipvs_update_stats(v);
		long_ret.u = v->stats.inbps & 0xffffffff;
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_VSRATEINBPSHIGH:
		ipvs_update_stats(v);
		long_ret.u = v->stats.inbps >> 32;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSRATEOUTBPSLOW:
		ipvs_update_stats(v);
		long_ret.u = v->stats.outbps & 0xffffffff;
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_VSRATEOUTBPSHIGH:
		ipvs_update_stats(v);
		long_ret.u = v->stats.outbps >> 32;
		return (u_char*)&long_ret;
#endif
#ifdef IP_VS_SVC_F_SCHED1
	case CHECK_SNMP_VSHASHED:
		long_ret.u = v->flags & IP_VS_SVC_F_HASHED ? 1 : 2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSSHFALLBACK:
		long_ret.u = v->flags & IP_VS_SVC_F_SCHED_SH_FALLBACK ? 1 : 2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSSHPORT:
		long_ret.u = v->flags & IP_VS_SVC_F_SCHED_SH_PORT ? 1 : 2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSMHFALLBACK:
		long_ret.u = v->flags & IP_VS_SVC_F_SCHED_MH_FALLBACK ? 1 : 2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSMHPORT:
		long_ret.u = v->flags & IP_VS_SVC_F_SCHED_MH_PORT ? 1 : 2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSSCHED3:
		long_ret.u = v->flags & IP_VS_SVC_F_SCHED3 ? 1 : 2;
		return (u_char*)&long_ret;
#endif
	case CHECK_SNMP_VSACTIONWHENDOWN:
		long_ret.u = v->inhibit?2:1;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSRETRY:
		long_ret.u = v->retry == UINT_MAX ? 0 : v->retry;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSDELAYBEFORERETRY:
		long_ret.u = v->delay_before_retry == ULONG_MAX ? 0 : v->delay_before_retry / TIMER_HZ;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSWARMUP:
		long_ret.u = v->warmup == ULONG_MAX ? 0 : v->warmup / TIMER_HZ;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSWEIGHT:
		long_ret.s = v->weight;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSSMTPALERT:
		long_ret.u = v->smtp_alert?1:2;
		return (u_char *)&long_ret;
	case CHECK_SNMP_VSDELAYLOOPUSEC:
		long_ret.u = v->delay_loop;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSDELAYBEFORERETRYUSEC:
		long_ret.u = v->delay_before_retry == ULONG_MAX ? 0 : v->delay_before_retry;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSWARMUPUSEC:
		long_ret.u = v->warmup == ULONG_MAX ? 0 : v->warmup;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSCONNTIMEOUTUSEC:
		long_ret.u = v->connection_to;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSTUNNELTYPE:
		if (v->forwarding_method != IP_VS_CONN_F_TUNNEL)
			break;
#ifndef _HAVE_IPVS_TUN_TYPE_
		long_ret.u = 1;		/* IPIP */
#else
		long_ret.u = v->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_IPIP ? 1
			   : v->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_GUE ? 2
#ifdef _HAVE_IPVS_TUN_GRE_
			   : v->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_GRE ? 3
#endif
			   : 0;
#endif
		return (u_char*)&long_ret;
#ifdef _HAVE_IPVS_TUN_TYPE_
	case CHECK_SNMP_VSTUNNELPORT:
		if (v->forwarding_method != IP_VS_CONN_F_TUNNEL ||
		    v->tun_type != IP_VS_CONN_F_TUNNEL_TYPE_GUE)
			break;
		long_ret.u = ntohs(v->tun_port);
		return (u_char*)&long_ret;
#ifdef _HAVE_IPVS_TUN_CSUM_
	case CHECK_SNMP_VSTUNNELCSUM:
		if (v->forwarding_method != IP_VS_CONN_F_TUNNEL ||
		    v->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_IPIP)
			break;
		long_ret.u = v->tun_flags == IP_VS_TUNNEL_ENCAP_FLAG_NOCSUM ? 1
			   : v->tun_flags == IP_VS_TUNNEL_ENCAP_FLAG_CSUM ? 2
			   : v->tun_flags == IP_VS_TUNNEL_ENCAP_FLAG_REMCSUM ? 3
			   : 0;
		return (u_char*)&long_ret;
#endif
#endif
	default:
		return NULL;
	}
	if (!exact && (name[*length-1] < MAX_SUBID))
		return check_snmp_virtualserver(vp, name, length,
						exact, var_len, write_method);
	return NULL;
}

static int
check_snmp_realserver_weight(int action,
			     u_char *var_val, u_char var_val_type, size_t var_val_len,
			     __attribute__((unused)) u_char *statP, oid *name, size_t name_len)
{
	element e1, e2;
	virtual_server_t *vs = NULL;
	real_server_t *rs = NULL;
	oid ivs, irs;
	switch (action) {
	case RESERVE1:
		/* Check that the proposed value is acceptable */
		if (var_val_type != ASN_INTEGER)
			return SNMP_ERR_WRONGTYPE;
		if (var_val_len > sizeof(long))
			return SNMP_ERR_WRONGLENGTH;
		break;
	case RESERVE2:		/* Check that we can find the instance. We should. */
	case COMMIT:
		/* Find the instance */
		if (name_len < 2) return SNMP_ERR_NOSUCHNAME;
		irs = name[name_len - 1];
		ivs = name[name_len - 2];
		if (LIST_ISEMPTY(check_data->vs)) return SNMP_ERR_NOSUCHNAME;
		for (e1 = LIST_HEAD(check_data->vs); e1; ELEMENT_NEXT(e1)) {
			vs = ELEMENT_DATA(e1);
			if (--ivs == 0) {
				if (vs->s_svr) {
					/* We don't want to set weight
					   of sorry server */
					rs = NULL;
					if (--irs == 0) break;
				}
				for (e2 = LIST_HEAD(vs->rs); e2; ELEMENT_NEXT(e2)) {
					rs = ELEMENT_DATA(e2);
					if (--irs == 0) break;
				}
				break;
			}
		}
		/* Did not find a RS or this is a sorry server (this
		   should not happen) */
		if (!rs) return SNMP_ERR_NOSUCHNAME;
		if (action == RESERVE2)
			break;
		/* Commit: change values. There is no way to fail. */
		update_svr_wgt((unsigned)(*var_val), vs, rs, true);
		break;
	}
	return SNMP_ERR_NOERROR;
}

static u_char*
check_snmp_realserver(struct variable *vp, oid *name, size_t *length,
		      int exact, size_t *var_len, WriteMethod **write_method)
{
	static struct counter64 counter64_ret;
	oid *target, current[2], best[2];
	int result;
	size_t target_len;
	unsigned curvirtual = 0, curreal;
	real_server_t *e = NULL, *be = NULL;
	element e1, e2 = NULL;
	virtual_server_t *vs, *bvs = NULL;
	int state;
	int type, btype;
	snmp_ret_t ret;

	if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
	}

	*write_method = 0;
	*var_len = sizeof(long);

	if (LIST_ISEMPTY(check_data->vs))
		return NULL;

	/* We search the best match: equal if exact, the lower OID in
	   the set of the OID strictly superior to the target
	   otherwise. */
	best[0] = best[1] = MAX_SUBID; /* Our best match */
	target = &name[vp->namelen];   /* Our target match */
	target_len = *length - vp->namelen;
	for (e1 = LIST_HEAD(check_data->vs); e1; ELEMENT_NEXT(e1)) {
		vs = ELEMENT_DATA(e1);
		curvirtual++;
		curreal = 0;
		if (target_len && (curvirtual < target[0]))
			continue; /* Optimization: cannot be part of our set */
		if (be)
			break; /* Optimization: cannot be the lower anymore */
		state = STATE_RS_SORRY;
		while (state != STATE_RS_END) {
			switch (state) {
			case STATE_RS_SORRY:
				e = vs->s_svr;
				type = state++;
				break;
			case STATE_RS_REGULAR_FIRST:
				e2 = LIST_HEAD(vs->rs);
				if (!e2) {
					e = NULL;
					state = STATE_RS_END;
					break;
				}
				e = ELEMENT_DATA(e2);
				type = state++;
				break;
			case STATE_RS_REGULAR_NEXT:
				type = state;
				ELEMENT_NEXT(e2);
				if (!e2) {
					e = NULL;
					state++;
					break;
				}
				e = ELEMENT_DATA(e2);
				break;
			default:
				/* Dunno? */
				return NULL;
			}
			if (!e)
				continue;
			curreal++;
			/* We build our current match */
			current[0] = curvirtual;
			current[1] = curreal;
			/* And compare it to our target match */
			if ((result = snmp_oid_compare(current, 2, target,
						       target_len)) < 0)
				continue;
			if (result == 0) {
				if (!exact)
					continue;

				/* Got an exact match and asked for it */
				be = e;
				bvs = vs;
				btype = type;
				goto real_found;
			}
			if (snmp_oid_compare(current, 2, best, 2) < 0) {
				/* This is our best match */
				memcpy(best, current, sizeof(oid) * 2);
				be = e;
				bvs = vs;
				btype = type;
				goto real_be_found;
			}
		}
	}
	if (be == NULL)
		/* No best match */
		return NULL;
	if (exact)
		/* No exact match */
		return NULL;

 real_be_found:
	/* Let's use our best match */
	memcpy(target, best, sizeof(oid) * 2);
	*length = (unsigned)vp->namelen + 2;

 real_found:
	switch (vp->magic) {
	case CHECK_SNMP_RSTYPE:
		long_ret.u = (btype == STATE_RS_SORRY)?2:1;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSADDRTYPE:
		long_ret.u = (be->addr.ss_family == AF_INET6) ? 2:1;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSADDRESS:
		RETURN_IP46ADDRESS(be);
		break;
	case CHECK_SNMP_RSPORT:
		long_ret.u = htons(inet_sockaddrport(&be->addr));
		return (u_char *)&long_ret;
	case CHECK_SNMP_RSLOADBALANCINGKIND:
		long_ret.u = 0;
		switch (be->forwarding_method) {
		case IP_VS_CONN_F_MASQ:
			long_ret.u = 1;
			break;
		case IP_VS_CONN_F_DROUTE:
			long_ret.u = 2;
			break;
		case IP_VS_CONN_F_TUNNEL:
			long_ret.u = 3;
			break;
		}
		if (!long_ret.u) break;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSSTATUS:
		if (btype == STATE_RS_SORRY) break;
		long_ret.u = be->alive?1:2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSWEIGHT:
		if (btype == STATE_RS_SORRY) break;
		long_ret.s = be->weight;
		*write_method = check_snmp_realserver_weight;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSUPPERCONNECTIONLIMIT:
		if (btype == STATE_RS_SORRY) break;
		if (!be->u_threshold) break;
		long_ret.u = be->u_threshold;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSLOWERCONNECTIONLIMIT:
		if (btype == STATE_RS_SORRY) break;
		if (!be->l_threshold) break;
		long_ret.u = be->l_threshold;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSACTIONWHENDOWN:
		if (btype == STATE_RS_SORRY) break;
		long_ret.u = be->inhibit?2:1;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSNOTIFYUP:
		if (btype == STATE_RS_SORRY) break;
		if (!be->notify_up) break;
		cmd_str_r(be->notify_up, buf, sizeof(buf));
		*var_len = strlen(buf);
		return (u_char*)buf;
	case CHECK_SNMP_RSNOTIFYDOWN:
		if (btype == STATE_RS_SORRY) break;
		if (!be->notify_down) break;
		cmd_str_r(be->notify_down, buf, sizeof(buf));
		*var_len = strlen(buf);
		return (u_char*)buf;
	case CHECK_SNMP_RSVIRTUALHOST:
		if (!be->virtualhost) break;
		*var_len = strlen(be->virtualhost);
		ret.cp = be->virtualhost;
		return ret.p;
	case CHECK_SNMP_RSFAILEDCHECKS:
		if (btype == STATE_RS_SORRY) break;
		long_ret.u = be->num_failed_checkers;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSSTATSCONNS:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.conns;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSSTATSACTIVECONNS:
		ipvs_update_stats(bvs);
		long_ret.u = be->activeconns;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSSTATSINACTIVECONNS:
		ipvs_update_stats(bvs);
		long_ret.u = be->inactconns;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSSTATSPERSISTENTCONNS:
		ipvs_update_stats(bvs);
		long_ret.u = be->persistconns;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSSTATSINPKTS:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.inpkts;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSSTATSOUTPKTS:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.outpkts;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSSTATSINBYTES:
		ipvs_update_stats(bvs);
		counter64_ret.low = be->stats.inbytes & 0xffffffff;
		counter64_ret.high = be->stats.inbytes >> 32;
		*var_len = sizeof(struct counter64);
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_RSSTATSOUTBYTES:
		ipvs_update_stats(bvs);
		counter64_ret.low = be->stats.outbytes & 0xffffffff;
		counter64_ret.high = be->stats.outbytes >> 32;
		*var_len = sizeof(struct counter64);
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_RSRATECPS:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.cps;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSRATEINPPS:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.inpps;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSRATEOUTPPS:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.outpps;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSRATEINBPS:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.inbps;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSRATEOUTBPS:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.outbps;
		return (u_char*)&long_ret;
#ifdef _WITH_LVS_64BIT_STATS_
	case CHECK_SNMP_RSSTATSCONNS64:
		ipvs_update_stats(bvs);
		counter64_ret.low = be->stats.conns & 0xffffffff;
		counter64_ret.high = be->stats.conns >> 32;
		*var_len = sizeof(struct counter64);
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_RSSTATSINPKTS64:
		ipvs_update_stats(bvs);
		counter64_ret.low = be->stats.inpkts & 0xffffffff;
		counter64_ret.high = be->stats.inpkts >> 32;
		*var_len = sizeof(struct counter64);
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_RSSTATSOUTPKTS64:
		ipvs_update_stats(bvs);
		counter64_ret.low = be->stats.outpkts & 0xffffffff;
		counter64_ret.high = be->stats.outpkts >> 32;
		*var_len = sizeof(struct counter64);
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_RSRATECPSLOW:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.cps & 0xffffffff;
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_RSRATECPSHIGH:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.cps >> 32;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSRATEINPPSLOW:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.inpps & 0xffffffff;
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_RSRATEINPPSHIGH:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.inpps >> 32;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSRATEOUTPPSLOW:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.outpps & 0xffffffff;
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_RSRATEOUTPPSHIGH:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.outpps >> 32;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSRATEINBPSLOW:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.inbps & 0xffffffff;
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_RSRATEINBPSHIGH:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.inbps >> 32;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSRATEOUTBPSLOW:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.outbps & 0xffffffff;
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_RSRATEOUTBPSHIGH:
		ipvs_update_stats(bvs);
		long_ret.u = be->stats.outbps >> 32;
		return (u_char*)&long_ret;
#endif
	case CHECK_SNMP_RSALPHA:
		long_ret.u = be->alpha?1:2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSRETRY:
		long_ret.u = be->retry == UINT_MAX ? 0 : be->retry;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSDELAYBEFORERETRY:
		long_ret.u = be->delay_before_retry == ULONG_MAX ? 0 : be->delay_before_retry / TIMER_HZ;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSWARMUP:
		long_ret.u = be->warmup == ULONG_MAX ? 0 : be->warmup / TIMER_HZ;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSDELAYLOOP:
		long_ret.u = be->delay_loop == ULONG_MAX ? 0 : be->delay_loop / TIMER_HZ;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSSMTPALERT:
		long_ret.u = be->smtp_alert?1:2;
		return (u_char *)&long_ret;
	case CHECK_SNMP_RSDELAYBEFORERETRYUSEC:
		long_ret.u = be->delay_before_retry == ULONG_MAX ? 0 : be->delay_before_retry;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSWARMUPUSEC:
		long_ret.u = be->warmup == ULONG_MAX ? 0 : be->warmup;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSDELAYLOOPUSEC:
		long_ret.u = be->delay_loop == ULONG_MAX ? 0 : be->delay_loop;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSCONNTIMEOUTUSEC:
		long_ret.u = be->connection_to;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSTUNNELTYPE:
		if (be->forwarding_method != IP_VS_CONN_F_TUNNEL)
			break;
#ifndef _HAVE_IPVS_TUN_TYPE_
		long_ret.u = 1;		/* IPIP */
#else
		long_ret.u = be->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_IPIP ? 1
			   : be->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_GUE ? 2
#ifdef _HAVE_IPVS_TUN_GRE_
			   : be->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_GRE ? 3
#endif
			   : 0;
#endif
		return (u_char*)&long_ret;
#ifdef _HAVE_IPVS_TUN_TYPE_
	case CHECK_SNMP_RSTUNNELPORT:
		if (be->forwarding_method != IP_VS_CONN_F_TUNNEL ||
		    be->tun_type != IP_VS_CONN_F_TUNNEL_TYPE_GUE)
			break;
		long_ret.u = ntohs(be->tun_port);
		return (u_char*)&long_ret;
#ifdef _HAVE_IPVS_TUN_CSUM_
	case CHECK_SNMP_RSTUNNELCSUM:
		if (be->forwarding_method != IP_VS_CONN_F_TUNNEL ||
		    be->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_IPIP)
			break;
		long_ret.u = be->tun_flags == IP_VS_TUNNEL_ENCAP_FLAG_NOCSUM ? 1
			   : be->tun_flags == IP_VS_TUNNEL_ENCAP_FLAG_CSUM ? 2
			   : be->tun_flags == IP_VS_TUNNEL_ENCAP_FLAG_REMCSUM ? 3
			   : 0;
		return (u_char*)&long_ret;
#endif
#endif
	default:
		return NULL;
	}
	/* If we are here, we asked for a non existent data. Try the
	   next one. */
	if (!exact && (name[*length-1] < MAX_SUBID))
		return check_snmp_realserver(vp, name, length,
					     exact, var_len, write_method);
	return NULL;
}

#ifdef _WITH_VRRP_
static u_char*
check_snmp_lvs_sync_daemon(struct variable *vp, oid *name, size_t *length,
				 int exact, size_t *var_len, WriteMethod **write_method)
{
	snmp_ret_t ret;

	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;

	switch (vp->magic) {
	case CHECK_SNMP_LVSSYNCDAEMONENABLED:
		long_ret.u = global_data->lvs_syncd.syncid != PARAMETER_UNSET ? 1 : 2;
		return (u_char *)&long_ret;
	case CHECK_SNMP_LVSSYNCDAEMONINTERFACE:
		if (global_data->lvs_syncd.syncid == PARAMETER_UNSET)
			return NULL;
		*var_len = strlen(global_data->lvs_syncd.ifname);
		ret.cp = global_data->lvs_syncd.ifname;
		return ret.p;
	case CHECK_SNMP_LVSSYNCDAEMONVRRPINSTANCE:
		if (global_data->lvs_syncd.syncid == PARAMETER_UNSET)
			return NULL;
		*var_len = strlen(global_data->lvs_syncd.vrrp_name);
		ret.cp = global_data->lvs_syncd.vrrp_name;
		return ret.p;
	case CHECK_SNMP_LVSSYNCDAEMONSYNCID:
		if (global_data->lvs_syncd.syncid == PARAMETER_UNSET)
			return NULL;
		long_ret.u = global_data->lvs_syncd.syncid;
		return (u_char *)&long_ret;
#ifdef _HAVE_IPVS_SYNCD_ATTRIBUTES_
	case CHECK_SNMP_LVSSYNCDAEMONMAXLEN:
		if (global_data->lvs_syncd.syncid == PARAMETER_UNSET)
			return NULL;
		long_ret.u = global_data->lvs_syncd.sync_maxlen;
		return (u_char *)&long_ret;
	case CHECK_SNMP_LVSSYNCDAEMONPORT:
		if (global_data->lvs_syncd.syncid == PARAMETER_UNSET)
			return NULL;
		long_ret.u = global_data->lvs_syncd.mcast_port;
		return (u_char *)&long_ret;
	case CHECK_SNMP_LVSSYNCDAEMONTTL:
		if (global_data->lvs_syncd.syncid == PARAMETER_UNSET)
			return NULL;
		long_ret.u = global_data->lvs_syncd.mcast_ttl;
		return (u_char *)&long_ret;
	case CHECK_SNMP_LVSSYNCDAEMONMCASTGROUPADDRTYPE:
		if (global_data->lvs_syncd.syncid == PARAMETER_UNSET)
			return NULL;
		long_ret.u = (global_data->lvs_syncd.mcast_group.ss_family == AF_INET6) ? 2:1;
		return (u_char *)&long_ret;
	case CHECK_SNMP_LVSSYNCDAEMONMCASTGROUPADDRVALUE:
		if (global_data->lvs_syncd.syncid == PARAMETER_UNSET)
			return NULL;
		if (global_data->lvs_syncd.mcast_group.ss_family == AF_INET6) {
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&global_data->lvs_syncd.mcast_group;
			*var_len = 16;
			return (u_char *)&addr6->sin6_addr;
		} else {
			struct sockaddr_in *addr4 = (struct sockaddr_in *)&global_data->lvs_syncd.mcast_group;
			*var_len = 4;
			return (u_char *)&addr4->sin_addr;
		}
#endif
	}
	return NULL;
}
#endif

static u_char*
check_snmp_lvs_timeouts(struct variable *vp, oid *name, size_t *length,
				 int exact, size_t *var_len, WriteMethod **write_method)
{
	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;

	switch (vp->magic) {
	case CHECK_SNMP_LVSTIMEOUTTCP:
		if (!global_data->lvs_tcp_timeout)
			return NULL;
		long_ret.s = global_data->lvs_tcp_timeout;
		return (u_char *)&long_ret;
	case CHECK_SNMP_LVSTIMEOUTTCPFIN:
		if (!global_data->lvs_tcpfin_timeout)
			return NULL;
		long_ret.s = global_data->lvs_tcpfin_timeout;
		return (u_char *)&long_ret;
	case CHECK_SNMP_LVSTIMEOUTUDP:
		if (!global_data->lvs_udp_timeout)
			return NULL;
		long_ret.s = global_data->lvs_udp_timeout;
		return (u_char *)&long_ret;
	}
	return NULL;
}

static oid check_oid[] = {CHECK_OID};
static struct variable8 check_vars[] = {
	/* virtualServerGroupTable */
	{CHECK_SNMP_VSGROUPNAME, ASN_OCTET_STR, RONLY,
	 check_snmp_vsgroup, 3, {1, 1, 2}},
	/* virtualServerGroupMemberTable */
	{CHECK_SNMP_VSGROUPMEMBERTYPE, ASN_INTEGER, RONLY,
	 check_snmp_vsgroupmember, 3, {2, 1, 2}},
	{CHECK_SNMP_VSGROUPMEMBERFWMARK, ASN_UNSIGNED, RONLY,
	 check_snmp_vsgroupmember, 3, {2, 1, 3}},
	{CHECK_SNMP_VSGROUPMEMBERADDRTYPE, ASN_INTEGER, RONLY,
	 check_snmp_vsgroupmember, 3, {2, 1, 4}},
	{CHECK_SNMP_VSGROUPMEMBERADDRESS, ASN_OCTET_STR, RONLY,
	 check_snmp_vsgroupmember, 3, {2, 1, 5}},
	{CHECK_SNMP_VSGROUPMEMBERADDR1, ASN_OCTET_STR, RONLY,
	 check_snmp_vsgroupmember, 3, {2, 1, 6}},
	{CHECK_SNMP_VSGROUPMEMBERADDR2, ASN_OCTET_STR, RONLY,
	 check_snmp_vsgroupmember, 3, {2, 1, 7}},
	{CHECK_SNMP_VSGROUPMEMBERPORT, ASN_UNSIGNED, RONLY,
	 check_snmp_vsgroupmember, 3, {2, 1, 8}},
	/* virtualServerTable */
	{CHECK_SNMP_VSTYPE, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 2}},
	{CHECK_SNMP_VSNAMEGROUP, ASN_OCTET_STR, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 3}},
	{CHECK_SNMP_VSFWMARK, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 4}},
	{CHECK_SNMP_VSADDRTYPE, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 5}},
	{CHECK_SNMP_VSADDRESS, ASN_OCTET_STR, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 6}},
	{CHECK_SNMP_VSPORT, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 7}},
	{CHECK_SNMP_VSPROTOCOL, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 8}},
	{CHECK_SNMP_VSLOADBALANCINGALGO, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 9}},
	{CHECK_SNMP_VSLOADBALANCINGKIND, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 10}},
	{CHECK_SNMP_VSSTATUS, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 11}},
	{CHECK_SNMP_VSVIRTUALHOST, ASN_OCTET_STR, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 12}},
	{CHECK_SNMP_VSPERSIST, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 13}},
	{CHECK_SNMP_VSPERSISTTIMEOUT, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 14}},
	{CHECK_SNMP_VSPERSISTGRANULARITY, ASN_OCTET_STR, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 15}},
	{CHECK_SNMP_VSDELAYLOOP, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 16}},
	{CHECK_SNMP_VSHASUSPEND, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 17}},
	{CHECK_SNMP_VSOPS, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 37}},
	{CHECK_SNMP_VSALPHA, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 18}},
	{CHECK_SNMP_VSOMEGA, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 19}},
	{CHECK_SNMP_VSREALTOTAL, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 20}},
	{CHECK_SNMP_VSREALUP, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 21}},
	{CHECK_SNMP_VSQUORUM, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 22}},
	{CHECK_SNMP_VSQUORUMSTATUS, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 23}},
	{CHECK_SNMP_VSQUORUMUP, ASN_OCTET_STR, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 24}},
	{CHECK_SNMP_VSQUORUMDOWN, ASN_OCTET_STR, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 25}},
	{CHECK_SNMP_VSHYSTERESIS, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 26}},
	{CHECK_SNMP_VSSTATSCONNS, ASN_GAUGE, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 27}},
	{CHECK_SNMP_VSSTATSINPKTS, ASN_COUNTER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 28}},
	{CHECK_SNMP_VSSTATSOUTPKTS, ASN_COUNTER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 29}},
	{CHECK_SNMP_VSSTATSINBYTES, ASN_COUNTER64, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 30}},
	{CHECK_SNMP_VSSTATSOUTBYTES, ASN_COUNTER64, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 31}},
	{CHECK_SNMP_VSRATECPS, ASN_GAUGE, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 32}},
	{CHECK_SNMP_VSRATEINPPS, ASN_GAUGE, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 33}},
	{CHECK_SNMP_VSRATEOUTPPS, ASN_GAUGE, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 34}},
	{CHECK_SNMP_VSRATEINBPS, ASN_GAUGE, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 35}},
	{CHECK_SNMP_VSRATEOUTBPS, ASN_GAUGE, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 36}},
#ifdef _WITH_LVS_64BIT_STATS_
	{CHECK_SNMP_VSSTATSCONNS64, ASN_COUNTER64, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 38}},
	{CHECK_SNMP_VSSTATSINPKTS64, ASN_COUNTER64, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 39}},
	{CHECK_SNMP_VSSTATSOUTPKTS64, ASN_COUNTER64, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 40}},
	{CHECK_SNMP_VSRATECPSLOW, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 41}},
	{CHECK_SNMP_VSRATECPSHIGH, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 42}},
	{CHECK_SNMP_VSRATEINPPSLOW, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 43}},
	{CHECK_SNMP_VSRATEINPPSHIGH, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 44}},
	{CHECK_SNMP_VSRATEOUTPPSLOW, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 45}},
	{CHECK_SNMP_VSRATEOUTPPSHIGH, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 46}},
	{CHECK_SNMP_VSRATEINBPSLOW, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 47}},
	{CHECK_SNMP_VSRATEINBPSHIGH, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 48}},
	{CHECK_SNMP_VSRATEOUTBPSLOW, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 49}},
	{CHECK_SNMP_VSRATEOUTBPSHIGH, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 50}},
#endif
	{CHECK_SNMP_VSPERSISTGRANULARITY6, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 51}},
	{CHECK_SNMP_VSHASHED, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 52}},
	{CHECK_SNMP_VSSHFALLBACK, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 53}},
	{CHECK_SNMP_VSSHPORT, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 54}},
	{CHECK_SNMP_VSSCHED3, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 55}},
	{CHECK_SNMP_VSACTIONWHENDOWN, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 56}},
	{CHECK_SNMP_VSRETRY, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 57}},
	{CHECK_SNMP_VSDELAYBEFORERETRY, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 58}},
	{CHECK_SNMP_VSWARMUP, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 59}},
	{CHECK_SNMP_VSWEIGHT, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 60}},
	{CHECK_SNMP_VSSMTPALERT, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 61}},
	{CHECK_SNMP_VSMHFALLBACK, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 62}},
	{CHECK_SNMP_VSMHPORT, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 63}},
	{CHECK_SNMP_VSDELAYLOOPUSEC, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 64}},
	{CHECK_SNMP_VSDELAYBEFORERETRYUSEC, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 65}},
	{CHECK_SNMP_VSWARMUPUSEC, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 66}},
	{CHECK_SNMP_VSCONNTIMEOUTUSEC, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 67}},
	{CHECK_SNMP_VSTUNNELTYPE, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 68}},
#ifdef _HAVE_IPSV_TUN_TYPE_
	{CHECK_SNMP_VSTUNNELPORT, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 69}},
#endif
#ifdef _HAVE_IPVS_TUN_CSUM_
	{CHECK_SNMP_VSTUNNELCSUM, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 70}},
#endif

	/* realServerTable */
	{CHECK_SNMP_RSTYPE, ASN_INTEGER, RONLY,
	 check_snmp_realserver, 3, {4, 1, 2}},
	{CHECK_SNMP_RSADDRTYPE, ASN_INTEGER, RONLY,
	 check_snmp_realserver, 3, {4, 1, 3}},
	{CHECK_SNMP_RSADDRESS, ASN_OCTET_STR, RONLY,
	 check_snmp_realserver, 3, {4, 1, 4}},
	{CHECK_SNMP_RSPORT, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 5}},
	{CHECK_SNMP_RSSTATUS, ASN_INTEGER, RONLY,
	 check_snmp_realserver, 3, {4, 1, 6}},
	{CHECK_SNMP_RSWEIGHT, ASN_INTEGER, RWRITE,
	 check_snmp_realserver, 3, {4, 1, 7}},
	{CHECK_SNMP_RSUPPERCONNECTIONLIMIT, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 8}},
	{CHECK_SNMP_RSLOWERCONNECTIONLIMIT, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 9}},
	{CHECK_SNMP_RSACTIONWHENDOWN, ASN_INTEGER, RONLY,
	 check_snmp_realserver, 3, {4, 1, 10}},
	{CHECK_SNMP_RSNOTIFYUP, ASN_OCTET_STR, RONLY,
	 check_snmp_realserver, 3, {4, 1, 11}},
	{CHECK_SNMP_RSNOTIFYDOWN, ASN_OCTET_STR, RONLY,
	 check_snmp_realserver, 3, {4, 1, 12}},
	{CHECK_SNMP_RSFAILEDCHECKS, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 13}},
	{CHECK_SNMP_RSSTATSCONNS, ASN_GAUGE, RONLY,
	 check_snmp_realserver, 3, {4, 1, 14}},
	{CHECK_SNMP_RSSTATSACTIVECONNS, ASN_GAUGE, RONLY,
	 check_snmp_realserver, 3, {4, 1, 15}},
	{CHECK_SNMP_RSSTATSINACTIVECONNS, ASN_GAUGE, RONLY,
	 check_snmp_realserver, 3, {4, 1, 16}},
	{CHECK_SNMP_RSSTATSPERSISTENTCONNS, ASN_GAUGE, RONLY,
	 check_snmp_realserver, 3, {4, 1, 17}},
	{CHECK_SNMP_RSSTATSINPKTS, ASN_COUNTER, RONLY,
	 check_snmp_realserver, 3, {4, 1, 18}},
	{CHECK_SNMP_RSSTATSOUTPKTS, ASN_COUNTER, RONLY,
	 check_snmp_realserver, 3, {4, 1, 19}},
	{CHECK_SNMP_RSSTATSINBYTES, ASN_COUNTER64, RONLY,
	 check_snmp_realserver, 3, {4, 1, 20}},
	{CHECK_SNMP_RSSTATSOUTBYTES, ASN_COUNTER64, RONLY,
	 check_snmp_realserver, 3, {4, 1, 21}},
	{CHECK_SNMP_RSRATECPS, ASN_GAUGE, RONLY,
	 check_snmp_realserver, 3, {4, 1, 22}},
	{CHECK_SNMP_RSRATEINPPS, ASN_GAUGE, RONLY,
	 check_snmp_realserver, 3, {4, 1, 23}},
	{CHECK_SNMP_RSRATEOUTPPS, ASN_GAUGE, RONLY,
	 check_snmp_realserver, 3, {4, 1, 24}},
	{CHECK_SNMP_RSRATEINBPS, ASN_GAUGE, RONLY,
	 check_snmp_realserver, 3, {4, 1, 25}},
	{CHECK_SNMP_RSRATEOUTBPS, ASN_GAUGE, RONLY,
	 check_snmp_realserver, 3, {4, 1, 26}},
#ifdef _WITH_LVS_64BIT_STATS_
	{CHECK_SNMP_RSSTATSCONNS64, ASN_COUNTER64, RONLY,
	 check_snmp_realserver, 3, {4, 1, 27}},
	{CHECK_SNMP_RSSTATSINPKTS64, ASN_COUNTER64, RONLY,
	 check_snmp_realserver, 3, {4, 1, 28}},
	{CHECK_SNMP_RSSTATSOUTPKTS64, ASN_COUNTER64, RONLY,
	 check_snmp_realserver, 3, {4, 1, 29}},
	{CHECK_SNMP_RSRATECPSLOW, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 30}},
	{CHECK_SNMP_RSRATECPSHIGH, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 31}},
	{CHECK_SNMP_RSRATEINPPSLOW, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 32}},
	{CHECK_SNMP_RSRATEINPPSHIGH, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 33}},
	{CHECK_SNMP_RSRATEOUTPPSLOW, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 34}},
	{CHECK_SNMP_RSRATEOUTPPSHIGH, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 35}},
	{CHECK_SNMP_RSRATEINBPSLOW, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 36}},
	{CHECK_SNMP_RSRATEINBPSHIGH, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 37}},
	{CHECK_SNMP_RSRATEOUTBPSLOW, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 38}},
	{CHECK_SNMP_RSRATEOUTBPSHIGH, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 39}},
#endif
	{CHECK_SNMP_RSLOADBALANCINGKIND, ASN_INTEGER, RONLY,
	 check_snmp_realserver, 3, {4, 1, 40}},
	{CHECK_SNMP_RSVIRTUALHOST, ASN_OCTET_STR, RONLY,
	 check_snmp_realserver, 3, {4, 1, 41}},
	{CHECK_SNMP_RSALPHA, ASN_INTEGER, RONLY,
	 check_snmp_realserver, 3, {4, 1, 42}},
	{CHECK_SNMP_RSRETRY, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 43}},
	{CHECK_SNMP_RSDELAYBEFORERETRY, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 44}},
	{CHECK_SNMP_RSWARMUP, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 45}},
	{CHECK_SNMP_RSDELAYLOOP, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 46}},
	{CHECK_SNMP_RSSMTPALERT, ASN_INTEGER, RONLY,
	 check_snmp_realserver, 3, {4, 1, 47}},
	{CHECK_SNMP_RSDELAYBEFORERETRYUSEC, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 48}},
	{CHECK_SNMP_RSWARMUPUSEC, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 49}},
	{CHECK_SNMP_RSDELAYLOOPUSEC, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 50}},
	{CHECK_SNMP_RSCONNTIMEOUTUSEC, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 51}},
	{CHECK_SNMP_RSTUNNELTYPE, ASN_INTEGER, RONLY,
	 check_snmp_realserver, 3, {4, 1, 52}},
#ifdef _HAVE_IPSV_TUN_TYPE_
	{CHECK_SNMP_RSTUNNELPORT, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 53}},
#endif
#ifdef _HAVE_IPVS_TUN_CSUM_
	{CHECK_SNMP_RSTUNNELCSUM, ASN_INTEGER, RONLY,
	 check_snmp_realserver, 3, {4, 1, 54}},
#endif

#ifdef _WITH_VRRP_
	/* LVS sync daemon configuration */
	{CHECK_SNMP_LVSSYNCDAEMONENABLED, ASN_INTEGER, RONLY,
	 check_snmp_lvs_sync_daemon, 2, {6, 1}},
	{CHECK_SNMP_LVSSYNCDAEMONINTERFACE, ASN_OCTET_STR, RONLY,
	 check_snmp_lvs_sync_daemon, 2, {6, 2}},
	{CHECK_SNMP_LVSSYNCDAEMONVRRPINSTANCE, ASN_OCTET_STR, RONLY,
	 check_snmp_lvs_sync_daemon, 2, {6, 3}},
	{CHECK_SNMP_LVSSYNCDAEMONSYNCID, ASN_INTEGER, RONLY,
	 check_snmp_lvs_sync_daemon, 2, {6, 4}},
#ifdef _HAVE_IPVS_SYNCD_ATTRIBUTES_
	{CHECK_SNMP_LVSSYNCDAEMONMAXLEN, ASN_INTEGER, RONLY,
	 check_snmp_lvs_sync_daemon, 2, {6, 5}},
	{CHECK_SNMP_LVSSYNCDAEMONPORT, ASN_INTEGER, RONLY,
	 check_snmp_lvs_sync_daemon, 2, {6, 6}},
	{CHECK_SNMP_LVSSYNCDAEMONTTL, ASN_INTEGER, RONLY,
	 check_snmp_lvs_sync_daemon, 2, {6, 7}},
	{CHECK_SNMP_LVSSYNCDAEMONMCASTGROUPADDRTYPE, ASN_INTEGER, RONLY,
	 check_snmp_lvs_sync_daemon, 2, {6, 8}},
	{CHECK_SNMP_LVSSYNCDAEMONMCASTGROUPADDRVALUE, ASN_OCTET_STR, RONLY,
	 check_snmp_lvs_sync_daemon, 2, {6, 9}},
#endif
#endif
	/* LVS timeouts */
	{CHECK_SNMP_LVSTIMEOUTTCP, ASN_INTEGER, RONLY,
	 check_snmp_lvs_timeouts, 2, {7, 1}},
	{CHECK_SNMP_LVSTIMEOUTTCPFIN, ASN_INTEGER, RONLY,
	 check_snmp_lvs_timeouts, 2, {7, 2}},
	{CHECK_SNMP_LVSTIMEOUTUDP, ASN_INTEGER, RONLY,
	 check_snmp_lvs_timeouts, 2, {7, 3}},
};

void
check_snmp_agent_init(const char *snmp_socket)
{
	if (snmp_running)
		return;

	/* We handle the global oid if we are running SNMP */
	snmp_agent_init(snmp_socket, true);
	snmp_register_mib(check_oid, OID_LENGTH(check_oid), "Healthchecker",
			  (struct variable *)check_vars,
			  sizeof(struct variable8),
			  sizeof(check_vars)/sizeof(struct variable8));
}

void
check_snmp_agent_close(void)
{
	if (!snmp_running)
		return;

	snmp_unregister_mib(check_oid, OID_LENGTH(check_oid));
	snmp_agent_close(true);
}

void
check_snmp_rs_trap(real_server_t *rs, virtual_server_t *vs, bool stopping)
{
	element e;
	snmp_ret_t ptr_conv;

	/* OID of the notification */
	oid notification_oid[] = { CHECK_OID, 5, 0, 1 };
	size_t notification_oid_len = OID_LENGTH(notification_oid);
	/* OID for snmpTrapOID.0 */
	oid objid_snmptrap[] = { SNMPTRAP_OID };
	size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);

	/* Other OID */
	oid addrtype_oid[] = { CHECK_OID, 4, 1, 3 };
	size_t addrtype_oid_len = OID_LENGTH(addrtype_oid);
	static unsigned long addrtype = 1;
	oid address_oid[] = { CHECK_OID, 4, 1, 4 };
	size_t address_oid_len = OID_LENGTH(address_oid);
	oid port_oid[] = { CHECK_OID, 4, 1, 5 };
	size_t port_oid_len = OID_LENGTH(port_oid);
	static unsigned long port;
	oid status_oid[] = { CHECK_OID, 4, 1, 6 };
	size_t status_oid_len = OID_LENGTH(status_oid);
	static unsigned long status;
	oid vstype_oid[] = { CHECK_OID, 3, 1, 2 };
	size_t vstype_oid_len = OID_LENGTH(vstype_oid);
	static unsigned long vstype;
	oid vsgroupname_oid[] = { CHECK_OID, 3, 1, 3 };
	size_t vsgroupname_oid_len = OID_LENGTH(vsgroupname_oid);
	oid vsfwmark_oid[] = { CHECK_OID, 3, 1, 4 };
	size_t vsfwmark_oid_len = OID_LENGTH(vsfwmark_oid);
	static unsigned long vsfwmark;
	oid vsaddrtype_oid[] = {CHECK_OID, 3, 1, 5 };
	size_t vsaddrtype_oid_len = OID_LENGTH(vsaddrtype_oid);
	oid vsaddress_oid[] = {CHECK_OID, 3, 1, 6 };
	size_t vsaddress_oid_len = OID_LENGTH(vsaddress_oid);
	oid vsport_oid[] = {CHECK_OID, 3, 1, 7 };
	size_t vsport_oid_len = OID_LENGTH(vsport_oid);
	static unsigned long vsport;
	oid vsprotocol_oid[] = {CHECK_OID, 3, 1, 8 };
	size_t vsprotocol_oid_len = OID_LENGTH(vsprotocol_oid);
	static unsigned long vsprotocol;
	oid realup_oid[] = {CHECK_OID, 3, 1, 21 };
	size_t realup_oid_len = OID_LENGTH(realup_oid);
	static unsigned long realup;
	oid realtotal_oid[] = {CHECK_OID, 3, 1, 20 };
	size_t realtotal_oid_len = OID_LENGTH(realtotal_oid);
	static unsigned long realtotal;
	oid quorumstatus_oid[] = {CHECK_OID, 3, 1, 23 };
	size_t quorumstatus_oid_len = OID_LENGTH(quorumstatus_oid);
	static unsigned long quorumstatus;
	oid quorum_oid[] = {CHECK_OID, 3, 1, 22 };
	size_t quorum_oid_len = OID_LENGTH(quorum_oid);
	static unsigned long quorum;
	oid routerId_oid[] = { KEEPALIVED_OID, 1, 2, 0 };
	size_t routerId_oid_len = OID_LENGTH(routerId_oid);

	netsnmp_variable_list *notification_vars = NULL;

	if (!global_data->enable_traps) return;

	if (!rs)
		notification_oid[notification_oid_len - 1] = 2;

	/* Initialize data */
	realtotal = LIST_SIZE(vs->rs);
	realup = 0;
	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e))
		if (((real_server_t *)ELEMENT_DATA(e))->alive)
			realup++;

	/* snmpTrapOID */
	snmp_varlist_add_variable(&notification_vars,
				  objid_snmptrap, objid_snmptrap_len,
				  ASN_OBJECT_ID,
				  (u_char *) notification_oid,
				  notification_oid_len * sizeof(oid));
	if (rs) {
		/* realServerAddrType */
		addrtype = (rs->addr.ss_family == AF_INET6)?2:1;
		snmp_varlist_add_variable(&notification_vars,
					  addrtype_oid, addrtype_oid_len,
					  ASN_INTEGER,
					  (u_char *)&addrtype,
					  sizeof(addrtype));
		/* realServerAddress */
		snmp_varlist_add_variable(&notification_vars,
					  address_oid, address_oid_len,
					  ASN_OCTET_STR,
					  (rs->addr.ss_family == AF_INET6)?
					  ((u_char *)&((struct sockaddr_in6 *)&rs->addr)->sin6_addr):
					  ((u_char *)&((struct sockaddr_in *)&rs->addr)->sin_addr),
					  (rs->addr.ss_family == AF_INET6)?16:4);
		/* realServerPort */
		port = htons(inet_sockaddrport(&rs->addr));
		snmp_varlist_add_variable(&notification_vars,
					  port_oid, port_oid_len,
					  ASN_UNSIGNED,
					  (u_char *)&port,
					  sizeof(port));
		/* realServerStatus */
		status = rs->alive?1:2;
		snmp_varlist_add_variable(&notification_vars,
					  status_oid, status_oid_len,
					  ASN_INTEGER,
					  (u_char *)&status,
					  sizeof(status));
	}

	/* virtualServerType */
	if (vs->vsgname)
		vstype = 3;
	else if (vs->vfwmark)
		vstype = 1;
	else
		vstype = 2;
	snmp_varlist_add_variable(&notification_vars,
				  vstype_oid, vstype_oid_len,
				  ASN_INTEGER,
				  (u_char *)&vstype,
				  sizeof(vstype));
	if (vs->vsgname) {
		/* virtualServerNameOfGroup */
		snmp_varlist_add_variable(&notification_vars,
					  vsgroupname_oid, vsgroupname_oid_len,
					  ASN_OCTET_STR,
					  (const u_char *)vs->vsgname,
					  strlen(vs->vsgname));
	} else if (vs->vfwmark) {
		vsfwmark = vs->vfwmark;
		snmp_varlist_add_variable(&notification_vars,
					  vsfwmark_oid, vsfwmark_oid_len,
					  ASN_UNSIGNED,
					  (u_char *)&vsfwmark,
					  sizeof(vsfwmark));
	} else {
		addrtype = (vs->addr.ss_family == AF_INET6)?2:1;
		snmp_varlist_add_variable(&notification_vars,
					  vsaddrtype_oid, vsaddrtype_oid_len,
					  ASN_INTEGER,
					  (u_char *)&addrtype,
					  sizeof(addrtype));
		snmp_varlist_add_variable(&notification_vars,
					  vsaddress_oid, vsaddress_oid_len,
					  ASN_OCTET_STR,
					  (vs->addr.ss_family == AF_INET6)?
					  ((u_char *)&((struct sockaddr_in6 *)&vs->addr)->sin6_addr):
					  ((u_char *)&((struct sockaddr_in *)&vs->addr)->sin_addr),
					  (vs->addr.ss_family == AF_INET6)?16:4);
		vsport = htons(inet_sockaddrport(&vs->addr));
		snmp_varlist_add_variable(&notification_vars,
					  vsport_oid, vsport_oid_len,
					  ASN_UNSIGNED,
					  (u_char *)&vsport,
					  sizeof(vsport));
	}
	vsprotocol = (vs->service_type == IPPROTO_TCP)?1:2;
	snmp_varlist_add_variable(&notification_vars,
				  vsprotocol_oid, vsprotocol_oid_len,
				  ASN_INTEGER,
				  (u_char *)&vsprotocol,
				  sizeof(vsprotocol));
	if (!rs) {
		quorumstatus = stopping ? 3 : vs->quorum_state_up ? 1 : 2;
		snmp_varlist_add_variable(&notification_vars,
					  quorumstatus_oid, quorumstatus_oid_len,
					  ASN_INTEGER,
					  (u_char *)&quorumstatus,
					  sizeof(quorumstatus));
		quorum = vs->quorum;
		snmp_varlist_add_variable(&notification_vars,
					  quorum_oid, quorum_oid_len,
					  ASN_UNSIGNED,
					  (u_char *)&quorum,
					  sizeof(quorum));
	}
	snmp_varlist_add_variable(&notification_vars,
				  realup_oid, realup_oid_len,
				  ASN_UNSIGNED,
				  (u_char *)&realup,
				  sizeof(realup));
	snmp_varlist_add_variable(&notification_vars,
				  realtotal_oid, realtotal_oid_len,
				  ASN_UNSIGNED,
				  (u_char *)&realtotal,
				  sizeof(realtotal));

	/* routerId */
	ptr_conv.cp = global_data->router_id,
	snmp_varlist_add_variable(&notification_vars,
				  routerId_oid, routerId_oid_len,
				  ASN_OCTET_STR,
				  ptr_conv.p,
				  strlen(global_data->router_id));

	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
}

void
check_snmp_quorum_trap(virtual_server_t *vs, bool stopping)
{
	check_snmp_rs_trap(NULL, vs, stopping);
}
