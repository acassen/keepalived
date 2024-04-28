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
	/* See below for VSRATECPS64 64 bit counters for rates */
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
	CHECK_SNMP_VSNAME,
	CHECK_SNMP_VSQUORUMUPPATH,
	CHECK_SNMP_VSQUORUMDOWNPATH,
#ifdef _WITH_LVS_64BIT_STATS_
	CHECK_SNMP_VSRATECPS64,
	CHECK_SNMP_VSRATEINPPS64,
	CHECK_SNMP_VSRATEOUTPPS64,
	CHECK_SNMP_VSRATEINBPS64,
	CHECK_SNMP_VSRATEOUTBPS64,
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
	/* See below for RSRATECPS64 etc 64 bit counters for rates */
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
	CHECK_SNMP_RSNAME,
	CHECK_SNMP_RSNOTIFYUPPATH,
	CHECK_SNMP_RSNOTIFYDOWNPATH,
#ifdef _WITH_LVS_64BIT_STATS_
	CHECK_SNMP_RSRATECPS64,
	CHECK_SNMP_RSRATEINPPS64,
	CHECK_SNMP_RSRATEOUTPPS64,
	CHECK_SNMP_RSRATEINBPS64,
	CHECK_SNMP_RSRATEOUTBPS64,
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
#define RETURN_IP46ADDRESS(entity)						\
do {										\
  if (entity->addr.ss_family == AF_INET6) {					\
    struct sockaddr_in6 *addr6 = PTR_CAST(struct sockaddr_in6, &entity->addr);	\
    *var_len = sizeof(struct in6_addr);						\
    return PTR_CAST(u_char, &addr6->sin6_addr);					\
  } else {									\
    struct sockaddr_in *addr4 = PTR_CAST(struct sockaddr_in, &entity->addr);	\
    *var_len = sizeof(struct in_addr);						\
    return PTR_CAST(u_char, &addr4->sin_addr);					\
  }										\
} while(0)

/* Static return values */
static longret_t long_ret;
static char buf[MAXBUF];
static struct counter64 counter64_ret;

static u_char*
check_snmp_vsgroup(struct variable *vp, oid *name, size_t *length,
		   int exact, size_t *var_len, WriteMethod **write_method)
{
	virtual_server_group_t *g;
	list_head_t *e;

	if ((e = snmp_header_list_head_table(vp, name, length, exact,
					 var_len, write_method,
					 &check_data->vs_group)) == NULL)
		return NULL;

	g = list_entry(e, virtual_server_group_t, e_list);

	switch (vp->magic) {
	case CHECK_SNMP_VSGROUPNAME:
		*var_len = strlen(g->gname);
		return PTR_CAST(u_char, g->gname);
	default:
		break;
	}
	return NULL;
}

static u_char*
check_snmp_vsgroupmember(struct variable *vp, oid *name, size_t *length,
			 int exact, size_t *var_len, WriteMethod **write_method)
{
	oid *target;
	oid current[2] = { 0 };
	int result;
	size_t target_len;
	virtual_server_group_t *group;
	virtual_server_group_entry_t *vsge;
	int state;
	list_head_t *l;


	if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
	}

	*write_method = 0;
	*var_len = sizeof(long);

	if (list_empty(&check_data->vs_group))
		return NULL;

	/* We search the best match: equal if exact, the lower OID in
	   the set of the OID strictly superior to the target
	   otherwise. */
	target = &name[vp->namelen];   /* Our target match */
	target_len = *length - vp->namelen;
	list_for_each_entry(group, &check_data->vs_group, e_list) {
		current[0]++;
		current[1] = 0;
		if (target_len && (current[0] < target[0]))
			continue; /* Optimization: cannot be part of our set */
		state = list_empty(&group->vfwmark) ? STATE_VSGM_ADDRESS_RANGE : STATE_VSGM_FWMARK;
		while (state < STATE_VSGM_END) {
			switch (state) {
			case STATE_VSGM_FWMARK:
				l = &group->vfwmark;
				break;
			case STATE_VSGM_ADDRESS_RANGE:
				l = &group->addr_range;
				break;
			default:
				/* Dunno? */
				return NULL;
			}
			state++;
			list_for_each_entry(vsge, l, e_list) {
				current[1]++;
				/* And compare it to our target match */
				if ((result = snmp_oid_compare(current, 2, target,
							       target_len)) < 0)
					continue;
				if (result == 0) {
					if (!exact)
						continue;

					/* Got an exact match and asked for it */
				} else {
					/* This is our best match */
					target[0] = current[0];
					target[1] = current[1];
					*length = (unsigned)vp->namelen + 2;
				}
				goto vsgmember_found;
			}
		}
	}

	/* Nothing found */
	return NULL;

 vsgmember_found:
	switch (vp->magic) {
	case CHECK_SNMP_VSGROUPMEMBERTYPE:
		if (vsge->is_fwmark)
			long_ret.u = 1;
		else if (inet_sockaddrcmp(&vsge->addr, &vsge->addr_end))
			long_ret.u = 3;
		else
			long_ret.u = 2;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSGROUPMEMBERFWMARK:
		if (!vsge->is_fwmark) break;
		long_ret.u = vsge->vfwmark;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSGROUPMEMBERADDRTYPE:
		if (vsge->is_fwmark) break;
		long_ret.u = SNMP_InetAddressType(vsge->addr.ss_family);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSGROUPMEMBERADDRESS:
		if (vsge->is_fwmark || inet_sockaddrcmp(&vsge->addr, &vsge->addr_end)) break;
		RETURN_IP46ADDRESS(vsge);
		break;
	case CHECK_SNMP_VSGROUPMEMBERADDR1:
		if (vsge->is_fwmark || !inet_sockaddrcmp(&vsge->addr, &vsge->addr_end)) break;
		RETURN_IP46ADDRESS(vsge);
		break;
	case CHECK_SNMP_VSGROUPMEMBERADDR2:
		if (!inet_sockaddrcmp(&vsge->addr, &vsge->addr_end) || vsge->is_fwmark) break;
		if (vsge->addr.ss_family == AF_INET6) {
			struct sockaddr_in6 *addr6 = PTR_CAST(struct sockaddr_in6, &vsge->addr_end);
			*var_len = sizeof(addr6->sin6_addr);
			return PTR_CAST(u_char, &addr6->sin6_addr);
		} else {
			struct sockaddr_in *addr4 = PTR_CAST(struct sockaddr_in, &vsge->addr_end);
			*var_len = sizeof(addr4->sin_addr);
			return PTR_CAST(u_char, &addr4->sin_addr);
		}
		break;
	case CHECK_SNMP_VSGROUPMEMBERPORT:
		if (vsge->is_fwmark) break;
		long_ret.u = htons(inet_sockaddrport(&vsge->addr));
		return PTR_CAST(u_char, &long_ret);
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

static u_char *
check_snmp_virtualserver(struct variable *vp, oid *name, size_t *length,
			 int exact, size_t *var_len, WriteMethod **write_method)
{
	virtual_server_t *vs;
	real_server_t *rs;
	snmp_ret_t ret;
	list_head_t *e;

	if ((e = snmp_header_list_head_table(vp, name, length, exact,
					 var_len, write_method,
					 &check_data->vs)) == NULL)
		return NULL;

	vs = list_entry(e, virtual_server_t, e_list);

	switch (vp->magic) {
	case CHECK_SNMP_VSTYPE:
		if (vs->vsg)
			long_ret.u = 3;
		else if (vs->vfwmark)
			long_ret.u = 1;
		else
			long_ret.u = 2;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSNAMEGROUP:
		if (!vs->vsg) break;
		ret.cp = vs->vsgname;
		*var_len = strlen(ret.cp);
		return ret.p;
	case CHECK_SNMP_VSFWMARK:
		if (!vs->vfwmark) break;
		long_ret.u = vs->vfwmark;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSADDRTYPE:
		long_ret.u = SNMP_InetAddressType(vs->af);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSADDRESS:
		if (vs->vfwmark || vs->vsg) break;
		RETURN_IP46ADDRESS(vs);
		break;
	case CHECK_SNMP_VSPORT:
		if (vs->vfwmark || vs->vsg) break;
		long_ret.u = htons(inet_sockaddrport(&vs->addr));
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSPROTOCOL:
		if (vs->vfwmark) break;
		long_ret.u = (vs->service_type == IPPROTO_TCP) ? 1 :
			     (vs->service_type == IPPROTO_UDP) ? 2 :
			     (vs->service_type == IPPROTO_SCTP) ? 3 : 4;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSLOADBALANCINGALGO:
		if (!strcmp(vs->sched, "rr"))
			long_ret.u = 1;
		else if (!strcmp(vs->sched, "wrr"))
			long_ret.u = 2;
		else if (!strcmp(vs->sched, "lc"))
			long_ret.u = 3;
		else if (!strcmp(vs->sched, "wlc"))
			long_ret.u = 4;
		else if (!strcmp(vs->sched, "lblc"))
			long_ret.u = 5;
		else if (!strcmp(vs->sched, "lblcr"))
			long_ret.u = 6;
		else if (!strcmp(vs->sched, "dh"))
			long_ret.u = 7;
		else if (!strcmp(vs->sched, "sh"))
			long_ret.u = 8;
		else if (!strcmp(vs->sched, "sed"))
			long_ret.u = 9;
		else if (!strcmp(vs->sched, "nq"))
			long_ret.u = 10;
		else if (!strcmp(vs->sched, "fo"))
			long_ret.u = 11;
		else if (!strcmp(vs->sched, "ovf"))
			long_ret.u = 12;
		else if (!strcmp(vs->sched, "mh"))
			long_ret.u = 13;
		else if (!strcmp(vs->sched, "twos"))
			long_ret.u = 14;
		else
			long_ret.u = 99;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSLOADBALANCINGKIND:
		long_ret.u = 0;
		switch (vs->forwarding_method) {
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
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSSTATUS:
		long_ret.u = SNMP_TruthValue(vs->alive);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSVIRTUALHOST:
		if (!vs->virtualhost) break;
		*var_len = strlen(vs->virtualhost);
		ret.cp = vs->virtualhost;
		return ret.p;
	case CHECK_SNMP_VSPERSIST:
		long_ret.u = SNMP_TruthValue(vs->persistence_timeout);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSPERSISTTIMEOUT:
		if (!vs->persistence_timeout) break;
		long_ret.u = vs->persistence_timeout;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSPERSISTGRANULARITY:
		if (vs->addr.ss_family == AF_INET6) break;
		*var_len = sizeof(vs->persistence_granularity);
		return PTR_CAST(u_char, &vs->persistence_granularity);
	case CHECK_SNMP_VSPERSISTGRANULARITY6:
		if (vs->addr.ss_family == AF_INET) break;
		*var_len = sizeof(vs->persistence_granularity);
		return PTR_CAST(u_char, &vs->persistence_granularity);
	case CHECK_SNMP_VSDELAYLOOP:
		long_ret.u = vs->delay_loop/TIMER_HZ;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSHASUSPEND:
		long_ret.u = SNMP_TruthValue(vs->ha_suspend);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSOPS:
		long_ret.u = SNMP_TruthValue(vs->flags & IP_VS_SVC_F_ONEPACKET);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSALPHA:
		long_ret.u = SNMP_TruthValue(vs->alpha);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSOMEGA:
		long_ret.u = SNMP_TruthValue(vs->omega);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSQUORUM:
		long_ret.u = vs->quorum;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSQUORUMSTATUS:
		long_ret.u = SNMP_TruthValue(vs->quorum_state_up);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSQUORUMUP:
		if (!vs->notify_quorum_up) break;
		cmd_str_r(vs->notify_quorum_up, buf, sizeof(buf));
		*var_len = strlen(buf);
		return PTR_CAST(u_char, buf);
	case CHECK_SNMP_VSQUORUMDOWN:
		if (!vs->notify_quorum_down) break;
		cmd_str_r(vs->notify_quorum_down, buf, sizeof(buf));
		*var_len = strlen(buf);
		return PTR_CAST(u_char, buf);
	case CHECK_SNMP_VSHYSTERESIS:
		long_ret.u = vs->hysteresis;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSREALTOTAL:
		long_ret.u = vs->rs_cnt;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSREALUP:
		long_ret.u = 0;
		list_for_each_entry(rs, &vs->rs, e_list)
			if (rs->alive)
				long_ret.u++;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSSTATSCONNS:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.conns;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSSTATSINPKTS:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.inpkts;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSSTATSOUTPKTS:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.outpkts;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSSTATSINBYTES:
		ipvs_vs_update_stats(vs);
		counter64_ret.low = vs->stats.inbytes & 0xffffffff;
		counter64_ret.high = vs->stats.inbytes >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	case CHECK_SNMP_VSSTATSOUTBYTES:
		ipvs_vs_update_stats(vs);
		counter64_ret.low = vs->stats.outbytes & 0xffffffff;
		counter64_ret.high = vs->stats.outbytes >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	case CHECK_SNMP_VSRATECPS:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.cps;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSRATEINPPS:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.inpps;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSRATEOUTPPS:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.outpps;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSRATEINBPS:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.inbps;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSRATEOUTBPS:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.outbps;
		return PTR_CAST(u_char, &long_ret);
#ifdef _WITH_LVS_64BIT_STATS_
	case CHECK_SNMP_VSSTATSCONNS64:
		ipvs_vs_update_stats(vs);
		counter64_ret.low = vs->stats.conns & 0xffffffff;
		counter64_ret.high = vs->stats.conns >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	case CHECK_SNMP_VSSTATSINPKTS64:
		ipvs_vs_update_stats(vs);
		counter64_ret.low = vs->stats.inpkts & 0xffffffff;
		counter64_ret.high = vs->stats.inpkts >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	case CHECK_SNMP_VSSTATSOUTPKTS64:
		ipvs_vs_update_stats(vs);
		counter64_ret.low = vs->stats.outpkts & 0xffffffff;
		counter64_ret.high = vs->stats.outpkts >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	/* See below for VSRATECPS64 etc 64 bit counters for rates */
	case CHECK_SNMP_VSRATECPSLOW:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.cps & 0xffffffff;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSRATECPSHIGH:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.cps >> 32;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSRATEINPPSLOW:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.inpps & 0xffffffff;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSRATEINPPSHIGH:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.inpps >> 32;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSRATEOUTPPSLOW:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.outpps & 0xffffffff;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSRATEOUTPPSHIGH:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.outpps >> 32;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSRATEINBPSLOW:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.inbps & 0xffffffff;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSRATEINBPSHIGH:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.inbps >> 32;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSRATEOUTBPSLOW:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.outbps & 0xffffffff;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSRATEOUTBPSHIGH:
		ipvs_vs_update_stats(vs);
		long_ret.u = vs->stats.outbps >> 32;
		return PTR_CAST(u_char, &long_ret);
#endif
#ifdef IP_VS_SVC_F_SCHED1
	case CHECK_SNMP_VSHASHED:
		long_ret.u = SNMP_TruthValue(vs->flags & IP_VS_SVC_F_HASHED);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSSHFALLBACK:
		long_ret.u = SNMP_TruthValue(vs->flags & IP_VS_SVC_F_SCHED_SH_FALLBACK);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSSHPORT:
		long_ret.u = SNMP_TruthValue(vs->flags & IP_VS_SVC_F_SCHED_SH_PORT);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSMHFALLBACK:
		long_ret.u = SNMP_TruthValue(vs->flags & IP_VS_SVC_F_SCHED_MH_FALLBACK);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSMHPORT:
		long_ret.u = SNMP_TruthValue(vs->flags & IP_VS_SVC_F_SCHED_MH_PORT);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSSCHED3:
		long_ret.u = SNMP_TruthValue(vs->flags & IP_VS_SVC_F_SCHED3);
		return PTR_CAST(u_char, &long_ret);
#endif
	case CHECK_SNMP_VSACTIONWHENDOWN:
		long_ret.u = SNMP_TruthValue(!vs->inhibit);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSRETRY:
		long_ret.u = vs->retry == UINT_MAX ? 0 : vs->retry;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSDELAYBEFORERETRY:
		long_ret.u = vs->delay_before_retry == ULONG_MAX ? 0 : vs->delay_before_retry / TIMER_HZ;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSWARMUP:
		long_ret.u = vs->warmup == ULONG_MAX ? 0 : vs->warmup / TIMER_HZ;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSWEIGHT:
		long_ret.s = vs->weight;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSSMTPALERT:
		long_ret.u = SNMP_TruthValue(vs->smtp_alert);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSDELAYLOOPUSEC:
		long_ret.u = vs->delay_loop;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSDELAYBEFORERETRYUSEC:
		long_ret.u = vs->delay_before_retry == ULONG_MAX ? 0 : vs->delay_before_retry;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSWARMUPUSEC:
		long_ret.u = vs->warmup == ULONG_MAX ? 0 : vs->warmup;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSCONNTIMEOUTUSEC:
		long_ret.u = vs->connection_to;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_VSTUNNELTYPE:
		if (vs->forwarding_method != IP_VS_CONN_F_TUNNEL)
			break;
#ifndef _HAVE_IPVS_TUN_TYPE_
		long_ret.u = 1;		/* IPIP */
#else
		long_ret.u = vs->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_IPIP ? 1
			   : vs->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_GUE ? 2
#ifdef _HAVE_IPVS_TUN_GRE_
			   : vs->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_GRE ? 3
#endif
			   : 0;
#endif
		return PTR_CAST(u_char, &long_ret);
#ifdef _HAVE_IPVS_TUN_TYPE_
	case CHECK_SNMP_VSTUNNELPORT:
		if (vs->forwarding_method != IP_VS_CONN_F_TUNNEL ||
		    vs->tun_type != IP_VS_CONN_F_TUNNEL_TYPE_GUE)
			break;
		long_ret.u = ntohs(vs->tun_port);
		return PTR_CAST(u_char, &long_ret);
#ifdef _HAVE_IPVS_TUN_CSUM_
	case CHECK_SNMP_VSTUNNELCSUM:
		if (vs->forwarding_method != IP_VS_CONN_F_TUNNEL ||
		    vs->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_IPIP)
			break;
		long_ret.u = vs->tun_flags == IP_VS_TUNNEL_ENCAP_FLAG_NOCSUM ? 1
			   : vs->tun_flags == IP_VS_TUNNEL_ENCAP_FLAG_CSUM ? 2
			   : vs->tun_flags == IP_VS_TUNNEL_ENCAP_FLAG_REMCSUM ? 3
			   : 0;
		return PTR_CAST(u_char, &long_ret);
#endif
#endif
	case CHECK_SNMP_VSNAME:
		if (!vs->snmp_name) break;
		*var_len = strlen(vs->snmp_name);
		ret.cp = vs->snmp_name;
		return ret.p;
	case CHECK_SNMP_VSQUORUMUPPATH:
		if (!vs->notify_quorum_up) break;
		ret.cp = vs->notify_quorum_up->path ? vs->notify_quorum_up->path : vs->notify_quorum_up->args[0] ;
		*var_len = strlen(ret.cp);
		return ret.p;
	case CHECK_SNMP_VSQUORUMDOWNPATH:
		if (!vs->notify_quorum_down) break;
		ret.cp = vs->notify_quorum_down->path ? vs->notify_quorum_down->path : vs->notify_quorum_down->args[0];
		*var_len = strlen(ret.cp);
		return ret.p;
#ifdef _WITH_LVS_64BIT_STATS_
	case CHECK_SNMP_VSRATECPS64:
		ipvs_vs_update_stats(vs);
		counter64_ret.low = vs->stats.cps & 0xffffffff;
		counter64_ret.high = vs->stats.cps >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	case CHECK_SNMP_VSRATEINPPS64:
		ipvs_vs_update_stats(vs);
		counter64_ret.low = vs->stats.inpps & 0xffffffff;
		counter64_ret.high = vs->stats.inpps >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	case CHECK_SNMP_VSRATEOUTPPS64:
		ipvs_vs_update_stats(vs);
		counter64_ret.low = vs->stats.outpps & 0xffffffff;
		counter64_ret.high = vs->stats.outpps >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	case CHECK_SNMP_VSRATEINBPS64:
		ipvs_vs_update_stats(vs);
		counter64_ret.low = vs->stats.inbps & 0xffffffff;
		counter64_ret.high = vs->stats.inbps >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	case CHECK_SNMP_VSRATEOUTBPS64:
		ipvs_vs_update_stats(vs);
		counter64_ret.low = vs->stats.outbps & 0xffffffff;
		counter64_ret.high = vs->stats.outbps >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
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
		if (list_empty(&check_data->vs))
			return SNMP_ERR_NOSUCHNAME;
		list_for_each_entry(vs, &check_data->vs, e_list) {
			if (--ivs == 0) {
				if (vs->s_svr) {
					/* We don't want to set weight
					   of sorry server */
					rs = NULL;
					if (--irs == 0) break;
				}
				list_for_each_entry(rs, &vs->rs, e_list) {
					if (--irs == 0)
						break;
				}
				break;
			}
		}

		/* Did not find a RS or this is a sorry server (this
		   should not happen) */
		if (!rs)
			return SNMP_ERR_NOSUCHNAME;
		if (action == RESERVE2)
			break;

		/* Commit: change values. There is no way to fail. */
		update_svr_wgt((unsigned)(*var_val), vs, rs, true);
		break;
	}
	return SNMP_ERR_NOERROR;
}

static u_char *
check_snmp_realserver(struct variable *vp, oid *name, size_t *length,
		      int exact, size_t *var_len, WriteMethod **write_method)
{
	oid *target;
	oid current[2] = { 0 };
	int result;
	size_t target_len;
	real_server_t *rs;
	virtual_server_t *vs;
	int state;
	int type;
	snmp_ret_t ret;

	if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
	}

	*write_method = 0;
	*var_len = sizeof(long);

	if (list_empty(&check_data->vs))
		return NULL;

	/* We search the best match: equal if exact, the lower OID in
	   the set of the OID strictly superior to the target
	   otherwise. */
	target = &name[vp->namelen];   /* Our target match */
	target_len = *length - vp->namelen;

	list_for_each_entry(vs, &check_data->vs, e_list) {
		current[0]++;
		current[1] = 0;
		if (target_len && (current[0] < target[0]))
			continue; /* Optimization: cannot be part of our set */
		state = vs->s_svr ? STATE_RS_SORRY : STATE_RS_REGULAR_FIRST;
		while (state != STATE_RS_END) {
			switch (state) {
			case STATE_RS_SORRY:
				rs = vs->s_svr;
				type = STATE_RS_SORRY;
				state = STATE_RS_REGULAR_FIRST;
				break;
			case STATE_RS_REGULAR_FIRST:
				if (list_empty(&vs->rs)) {
					rs = NULL;
					state = STATE_RS_END;
					break;
				}
				rs = list_first_entry(&vs->rs, real_server_t, e_list);
				type = STATE_RS_REGULAR_FIRST;
				state = STATE_RS_REGULAR_NEXT;
				break;
			case STATE_RS_REGULAR_NEXT:
				type = STATE_RS_REGULAR_NEXT;
				if (list_is_last(&rs->e_list, &vs->rs)) {
					rs = NULL;
					state = STATE_RS_END;
					break;
				}
				rs = list_entry(rs->e_list.next, real_server_t, e_list);
				break;
			default:
				/* Dunno? */
				return NULL;
			}
			if (!rs)
				continue;

			current[1]++;

			/* And compare it to our target match */
			if ((result = snmp_oid_compare(current, 2, target,
						       target_len)) < 0)
				continue;
			if (result == 0) {
				/* Got an exact match. Were we asked for it? */
				if (!exact)
					continue;
			} else {
				target[0] = current[0];
				target[1] = current[1];
				*length = (unsigned)vp->namelen + 2;
			}

			break;
		}

		if (rs)
			break;
	}

	if (rs == NULL) {
		/* No match */
		return NULL;
	}

	switch (vp->magic) {
	case CHECK_SNMP_RSTYPE:
		long_ret.u = SNMP_TruthValue(type != STATE_RS_SORRY);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSADDRTYPE:
		long_ret.u = SNMP_InetAddressType(rs->addr.ss_family);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSADDRESS:
		RETURN_IP46ADDRESS(rs);
		break;
	case CHECK_SNMP_RSPORT:
		long_ret.u = htons(inet_sockaddrport(&rs->addr));
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSLOADBALANCINGKIND:
		switch (rs->forwarding_method) {
		case IP_VS_CONN_F_MASQ:
			long_ret.u = 1;
			break;
		case IP_VS_CONN_F_DROUTE:
			long_ret.u = 2;
			break;
		case IP_VS_CONN_F_TUNNEL:
			long_ret.u = 3;
			break;
		default:
			long_ret.u = 0;
			break;
		}
		if (!long_ret.u) break;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSSTATUS:
		if (type == STATE_RS_SORRY) break;
		long_ret.u = SNMP_TruthValue(rs->alive);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSWEIGHT:
		if (type == STATE_RS_SORRY) break;
		long_ret.s = real_weight(rs->effective_weight);
		*write_method = check_snmp_realserver_weight;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSUPPERCONNECTIONLIMIT:
		if (type == STATE_RS_SORRY) break;
		if (!rs->u_threshold) break;
		long_ret.u = rs->u_threshold;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSLOWERCONNECTIONLIMIT:
		if (type == STATE_RS_SORRY) break;
		if (!rs->l_threshold) break;
		long_ret.u = rs->l_threshold;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSACTIONWHENDOWN:
		if (type == STATE_RS_SORRY) break;
		long_ret.u = SNMP_TruthValue(!rs->inhibit);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSNOTIFYUP:
		if (type == STATE_RS_SORRY) break;
		if (!rs->notify_up) break;
		cmd_str_r(rs->notify_up, buf, sizeof(buf));
		*var_len = strlen(buf);
		return PTR_CAST(u_char, buf);
	case CHECK_SNMP_RSNOTIFYDOWN:
		if (type == STATE_RS_SORRY) break;
		if (!rs->notify_down) break;
		cmd_str_r(rs->notify_down, buf, sizeof(buf));
		*var_len = strlen(buf);
		return PTR_CAST(u_char, buf);
	case CHECK_SNMP_RSVIRTUALHOST:
		if (!rs->virtualhost) break;
		*var_len = strlen(rs->virtualhost);
		ret.cp = rs->virtualhost;
		return ret.p;
	case CHECK_SNMP_RSFAILEDCHECKS:
		if (type == STATE_RS_SORRY) break;
		long_ret.u = rs->num_failed_checkers;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSSTATSCONNS:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.conns;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSSTATSACTIVECONNS:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->activeconns;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSSTATSINACTIVECONNS:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->inactconns;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSSTATSPERSISTENTCONNS:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->persistconns;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSSTATSINPKTS:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.inpkts;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSSTATSOUTPKTS:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.outpkts;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSSTATSINBYTES:
		ipvs_rs_update_stats(vs);
		counter64_ret.low = rs->stats.inbytes & 0xffffffff;
		counter64_ret.high = rs->stats.inbytes >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	case CHECK_SNMP_RSSTATSOUTBYTES:
		ipvs_rs_update_stats(vs);
		counter64_ret.low = rs->stats.outbytes & 0xffffffff;
		counter64_ret.high = rs->stats.outbytes >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	case CHECK_SNMP_RSRATECPS:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.cps;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSRATEINPPS:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.inpps;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSRATEOUTPPS:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.outpps;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSRATEINBPS:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.inbps;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSRATEOUTBPS:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.outbps;
		return PTR_CAST(u_char, &long_ret);
#ifdef _WITH_LVS_64BIT_STATS_
	case CHECK_SNMP_RSSTATSCONNS64:
		ipvs_rs_update_stats(vs);
		counter64_ret.low = rs->stats.conns & 0xffffffff;
		counter64_ret.high = rs->stats.conns >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	case CHECK_SNMP_RSSTATSINPKTS64:
		ipvs_rs_update_stats(vs);
		counter64_ret.low = rs->stats.inpkts & 0xffffffff;
		counter64_ret.high = rs->stats.inpkts >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	case CHECK_SNMP_RSSTATSOUTPKTS64:
		ipvs_rs_update_stats(vs);
		counter64_ret.low = rs->stats.outpkts & 0xffffffff;
		counter64_ret.high = rs->stats.outpkts >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	/* See below for RSRATECPS64 etc 64 bit counters for rates */
	case CHECK_SNMP_RSRATECPSLOW:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.cps & 0xffffffff;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSRATECPSHIGH:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.cps >> 32;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSRATEINPPSLOW:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.inpps & 0xffffffff;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSRATEINPPSHIGH:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.inpps >> 32;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSRATEOUTPPSLOW:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.outpps & 0xffffffff;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSRATEOUTPPSHIGH:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.outpps >> 32;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSRATEINBPSLOW:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.inbps & 0xffffffff;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSRATEINBPSHIGH:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.inbps >> 32;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSRATEOUTBPSLOW:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.outbps & 0xffffffff;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSRATEOUTBPSHIGH:
		ipvs_rs_update_stats(vs);
		long_ret.u = rs->stats.outbps >> 32;
		return PTR_CAST(u_char, &long_ret);
#endif
	case CHECK_SNMP_RSALPHA:
		long_ret.u = SNMP_TruthValue(rs->alpha);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSRETRY:
		long_ret.u = rs->retry == UINT_MAX ? 0 : rs->retry;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSDELAYBEFORERETRY:
		long_ret.u = rs->delay_before_retry == ULONG_MAX ? 0 : rs->delay_before_retry / TIMER_HZ;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSWARMUP:
		long_ret.u = rs->warmup == ULONG_MAX ? 0 : rs->warmup / TIMER_HZ;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSDELAYLOOP:
		long_ret.u = rs->delay_loop == ULONG_MAX ? 0 : rs->delay_loop / TIMER_HZ;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSSMTPALERT:
		long_ret.u = SNMP_TruthValue(rs->smtp_alert);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSDELAYBEFORERETRYUSEC:
		long_ret.u = rs->delay_before_retry == ULONG_MAX ? 0 : rs->delay_before_retry;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSWARMUPUSEC:
		long_ret.u = rs->warmup == ULONG_MAX ? 0 : rs->warmup;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSDELAYLOOPUSEC:
		long_ret.u = rs->delay_loop == ULONG_MAX ? 0 : rs->delay_loop;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSCONNTIMEOUTUSEC:
		long_ret.u = rs->connection_to;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_RSTUNNELTYPE:
		if (rs->forwarding_method != IP_VS_CONN_F_TUNNEL)
			break;
#ifndef _HAVE_IPVS_TUN_TYPE_
		long_ret.u = 1;		/* IPIP */
#else
		long_ret.u = rs->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_IPIP ? 1
			   : rs->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_GUE ? 2
#ifdef _HAVE_IPVS_TUN_GRE_
			   : rs->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_GRE ? 3
#endif
			   : 0;
#endif
		return PTR_CAST(u_char, &long_ret);
#ifdef _HAVE_IPVS_TUN_TYPE_
	case CHECK_SNMP_RSTUNNELPORT:
		if (rs->forwarding_method != IP_VS_CONN_F_TUNNEL ||
		    rs->tun_type != IP_VS_CONN_F_TUNNEL_TYPE_GUE)
			break;
		long_ret.u = ntohs(rs->tun_port);
		return PTR_CAST(u_char, &long_ret);
#ifdef _HAVE_IPVS_TUN_CSUM_
	case CHECK_SNMP_RSTUNNELCSUM:
		if (rs->forwarding_method != IP_VS_CONN_F_TUNNEL ||
		    rs->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_IPIP)
			break;
		long_ret.u = rs->tun_flags == IP_VS_TUNNEL_ENCAP_FLAG_NOCSUM ? 1
			   : rs->tun_flags == IP_VS_TUNNEL_ENCAP_FLAG_CSUM ? 2
			   : rs->tun_flags == IP_VS_TUNNEL_ENCAP_FLAG_REMCSUM ? 3
			   : 0;
		return PTR_CAST(u_char, &long_ret);
#endif
#endif
	case CHECK_SNMP_RSNAME:
		if (!rs->snmp_name) break;
		*var_len = strlen(rs->snmp_name);
		ret.cp = rs->snmp_name;
		return ret.p;
	case CHECK_SNMP_RSNOTIFYUPPATH:
		if (type == STATE_RS_SORRY) break;
		if (!rs->notify_up) break;
		ret.cp = rs->notify_up->path ? rs->notify_up->path : rs->notify_up->args[0];
		*var_len = strlen(ret.cp);
		return ret.p;
	case CHECK_SNMP_RSNOTIFYDOWNPATH:
		if (type == STATE_RS_SORRY) break;
		if (!rs->notify_down) break;
		ret.cp = rs->notify_down->path ? rs->notify_down->path : rs->notify_down->args[0];
		*var_len = strlen(ret.cp);
		return ret.p;
#ifdef _WITH_LVS_64BIT_STATS_
	case CHECK_SNMP_RSRATECPS64:
		ipvs_rs_update_stats(vs);
		counter64_ret.low = rs->stats.cps & 0xffffffff;
		counter64_ret.high = rs->stats.cps >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	case CHECK_SNMP_RSRATEINPPS64:
		ipvs_rs_update_stats(vs);
		counter64_ret.low = rs->stats.inpps & 0xffffffff;
		counter64_ret.high = rs->stats.inpps >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	case CHECK_SNMP_RSRATEOUTPPS64:
		ipvs_rs_update_stats(vs);
		counter64_ret.low = rs->stats.outpps & 0xffffffff;
		counter64_ret.high = rs->stats.outpps >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	case CHECK_SNMP_RSRATEINBPS64:
		ipvs_rs_update_stats(vs);
		counter64_ret.low = rs->stats.inbps & 0xffffffff;
		counter64_ret.high = rs->stats.inbps >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
	case CHECK_SNMP_RSRATEOUTBPS64:
		ipvs_rs_update_stats(vs);
		counter64_ret.low = rs->stats.outbps & 0xffffffff;
		counter64_ret.high = rs->stats.outbps >> 32;
		*var_len = sizeof(struct counter64);
		return PTR_CAST(u_char, &counter64_ret);
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
		long_ret.u = SNMP_TruthValue(global_data->lvs_syncd.ifname);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_LVSSYNCDAEMONINTERFACE:
		if (!global_data->lvs_syncd.ifname)
			return NULL;
		*var_len = strlen(global_data->lvs_syncd.ifname);
		ret.cp = global_data->lvs_syncd.ifname;
		return ret.p;
	case CHECK_SNMP_LVSSYNCDAEMONVRRPINSTANCE:
		if (!global_data->lvs_syncd.ifname ||
		    !global_data->lvs_syncd.vrrp_name)
			return NULL;
		*var_len = strlen(global_data->lvs_syncd.vrrp_name);
		ret.cp = global_data->lvs_syncd.vrrp_name;
		return ret.p;
	case CHECK_SNMP_LVSSYNCDAEMONSYNCID:
		if (!global_data->lvs_syncd.ifname)
			return NULL;
		long_ret.u = global_data->lvs_syncd.syncid;
		return PTR_CAST(u_char, &long_ret);
#ifdef _HAVE_IPVS_SYNCD_ATTRIBUTES_
	case CHECK_SNMP_LVSSYNCDAEMONMAXLEN:
		if (!global_data->lvs_syncd.ifname)
			return NULL;
		long_ret.u = global_data->lvs_syncd.sync_maxlen;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_LVSSYNCDAEMONPORT:
		if (!global_data->lvs_syncd.ifname)
			return NULL;
		long_ret.u = global_data->lvs_syncd.mcast_port;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_LVSSYNCDAEMONTTL:
		if (!global_data->lvs_syncd.ifname)
			return NULL;
		long_ret.u = global_data->lvs_syncd.mcast_ttl;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_LVSSYNCDAEMONMCASTGROUPADDRTYPE:
		if (!global_data->lvs_syncd.ifname ||
		    global_data->lvs_syncd.mcast_group.ss_family == AF_UNSPEC)
			return NULL;
		long_ret.u = SNMP_InetAddressType(global_data->lvs_syncd.mcast_group.ss_family);
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_LVSSYNCDAEMONMCASTGROUPADDRVALUE:
		if (!global_data->lvs_syncd.ifname ||
		    global_data->lvs_syncd.mcast_group.ss_family == AF_UNSPEC)
			return NULL;
		if (global_data->lvs_syncd.mcast_group.ss_family == AF_INET6) {
			struct sockaddr_in6 *addr6 = PTR_CAST(struct sockaddr_in6, &global_data->lvs_syncd.mcast_group);
			*var_len = sizeof(addr6->sin6_addr);
			return PTR_CAST(u_char, &addr6->sin6_addr);
		} else {
			struct sockaddr_in *addr4 = PTR_CAST(struct sockaddr_in, &global_data->lvs_syncd.mcast_group);
			*var_len = sizeof(addr4->sin_addr);
			return PTR_CAST(u_char, &addr4->sin_addr);
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
		if (!global_data->lvs_timeouts.tcp_timeout)
			return NULL;
		long_ret.s = global_data->lvs_timeouts.tcp_timeout;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_LVSTIMEOUTTCPFIN:
		if (!global_data->lvs_timeouts.tcp_fin_timeout)
			return NULL;
		long_ret.s = global_data->lvs_timeouts.tcp_fin_timeout;
		return PTR_CAST(u_char, &long_ret);
	case CHECK_SNMP_LVSTIMEOUTUDP:
		if (!global_data->lvs_timeouts.udp_timeout)
			return NULL;
		long_ret.s = global_data->lvs_timeouts.udp_timeout;
		return PTR_CAST(u_char, &long_ret);
	}
	return NULL;
}

static oid check_oid[] = {CHECK_OID};
static struct variable3 check_vars[] = {
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
	/* See below for VSRATECPS64 etc 64 bit counters for rates */
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
#ifdef _HAVE_IPVS_TUN_TYPE_
	{CHECK_SNMP_VSTUNNELPORT, ASN_UNSIGNED, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 69}},
#endif
#ifdef _HAVE_IPVS_TUN_CSUM_
	{CHECK_SNMP_VSTUNNELCSUM, ASN_INTEGER, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 70}},
#endif
	{CHECK_SNMP_VSNAME, ASN_OCTET_STR, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 71}},
	{CHECK_SNMP_VSQUORUMUPPATH, ASN_OCTET_STR, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 72}},
	{CHECK_SNMP_VSQUORUMDOWNPATH, ASN_OCTET_STR, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 73}},
#ifdef _WITH_LVS_64BIT_STATS_
	{CHECK_SNMP_VSRATECPS64, ASN_COUNTER64, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 74}},
	{CHECK_SNMP_VSRATEINPPS64, ASN_COUNTER64, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 75}},
	{CHECK_SNMP_VSRATEOUTPPS64, ASN_COUNTER64, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 76}},
	{CHECK_SNMP_VSRATEINBPS64, ASN_COUNTER64, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 77}},
	{CHECK_SNMP_VSRATEOUTBPS64, ASN_COUNTER64, RONLY,
	 check_snmp_virtualserver, 3, {3, 1, 78}},
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
	/* See below for RSRATECPS64 64 bit counters for rates */
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
#ifdef _HAVE_IPVS_TUN_TYPE_
	{CHECK_SNMP_RSTUNNELPORT, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 53}},
#endif
#ifdef _HAVE_IPVS_TUN_CSUM_
	{CHECK_SNMP_RSTUNNELCSUM, ASN_INTEGER, RONLY,
	 check_snmp_realserver, 3, {4, 1, 54}},
#endif
	{CHECK_SNMP_RSNAME, ASN_OCTET_STR, RONLY,
	 check_snmp_realserver, 3, {4, 1, 55}},
	{CHECK_SNMP_RSNOTIFYUPPATH, ASN_OCTET_STR, RONLY,
	 check_snmp_realserver, 3, {4, 1, 56}},
	{CHECK_SNMP_RSNOTIFYDOWNPATH, ASN_OCTET_STR, RONLY,
	 check_snmp_realserver, 3, {4, 1, 57}},
#ifdef _WITH_LVS_64BIT_STATS_
	{CHECK_SNMP_RSRATECPS64, ASN_COUNTER64, RONLY,
	 check_snmp_realserver, 3, {4, 1, 58}},
	{CHECK_SNMP_RSRATEINPPS64, ASN_COUNTER64, RONLY,
	 check_snmp_realserver, 3, {4, 1, 59}},
	{CHECK_SNMP_RSRATEOUTPPS64, ASN_COUNTER64, RONLY,
	 check_snmp_realserver, 3, {4, 1, 60}},
	{CHECK_SNMP_RSRATEINBPS64, ASN_COUNTER64, RONLY,
	 check_snmp_realserver, 3, {4, 1, 61}},
	{CHECK_SNMP_RSRATEOUTBPS64, ASN_COUNTER64, RONLY,
	 check_snmp_realserver, 3, {4, 1, 62}},
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
			  PTR_CAST(struct variable, check_vars),
			  sizeof(check_vars[0]),
			  sizeof(check_vars)/sizeof(check_vars[0]));
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
	real_server_t *r;
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
	realtotal = vs->rs_cnt;
	realup = 0;
	list_for_each_entry(r, &vs->rs, e_list)
		if (r->alive)
			realup++;

	/* snmpTrapOID */
	snmp_varlist_add_variable(&notification_vars,
				  objid_snmptrap, objid_snmptrap_len,
				  ASN_OBJECT_ID,
				  PTR_CAST(u_char, notification_oid),
				  notification_oid_len * sizeof(oid));
	if (rs) {
		/* realServerAddrType */
		addrtype = SNMP_InetAddressType(rs->addr.ss_family);
		snmp_varlist_add_variable(&notification_vars,
					  addrtype_oid, addrtype_oid_len,
					  ASN_INTEGER,
					  PTR_CAST(u_char, &addrtype),
					  sizeof(addrtype));
		/* realServerAddress */
		snmp_varlist_add_variable(&notification_vars,
					  address_oid, address_oid_len,
					  ASN_OCTET_STR,
					  (rs->addr.ss_family == AF_INET6)?
					  	PTR_CAST2(u_char, struct sockaddr_in6, &rs->addr, sin6_addr):
					  	PTR_CAST2(u_char, struct sockaddr_in, &rs->addr, sin_addr),
					  (rs->addr.ss_family == AF_INET6) ? 16 : 4);
		/* realServerPort */
		port = htons(inet_sockaddrport(&rs->addr));
		snmp_varlist_add_variable(&notification_vars,
					  port_oid, port_oid_len,
					  ASN_UNSIGNED,
					  PTR_CAST(u_char, &port),
					  sizeof(port));
		/* realServerStatus */
		status = SNMP_TruthValue(rs->alive);
		snmp_varlist_add_variable(&notification_vars,
					  status_oid, status_oid_len,
					  ASN_INTEGER,
					  PTR_CAST(u_char, &status),
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
				  PTR_CAST(u_char, &vstype),
				  sizeof(vstype));
	if (vs->vsgname) {
		/* virtualServerNameOfGroup */
		snmp_varlist_add_variable(&notification_vars,
					  vsgroupname_oid, vsgroupname_oid_len,
					  ASN_OCTET_STR,
					  PTR_CAST_CONST(u_char, vs->vsgname),
					  strlen(vs->vsgname));
	} else if (vs->vfwmark) {
		vsfwmark = vs->vfwmark;
		snmp_varlist_add_variable(&notification_vars,
					  vsfwmark_oid, vsfwmark_oid_len,
					  ASN_UNSIGNED,
					  PTR_CAST(u_char, &vsfwmark),
					  sizeof(vsfwmark));
	} else {
		addrtype = SNMP_InetAddressType(vs->addr.ss_family);
		snmp_varlist_add_variable(&notification_vars,
					  vsaddrtype_oid, vsaddrtype_oid_len,
					  ASN_INTEGER,
					  PTR_CAST(u_char, &addrtype),
					  sizeof(addrtype));
		snmp_varlist_add_variable(&notification_vars,
					  vsaddress_oid, vsaddress_oid_len,
					  ASN_OCTET_STR,
					  (vs->addr.ss_family == AF_INET6) ?
						PTR_CAST2(u_char, struct sockaddr_in6, &vs->addr, sin6_addr) :
					  	PTR_CAST2(u_char, struct sockaddr_in, &vs->addr, sin_addr),
					  (vs->addr.ss_family == AF_INET6) ? 16 : 4);
		vsport = htons(inet_sockaddrport(&vs->addr));
		snmp_varlist_add_variable(&notification_vars,
					  vsport_oid, vsport_oid_len,
					  ASN_UNSIGNED,
					  PTR_CAST(u_char, &vsport),
					  sizeof(vsport));
	}
	vsprotocol = SNMP_TruthValue(vs->service_type == IPPROTO_TCP);
	snmp_varlist_add_variable(&notification_vars,
				  vsprotocol_oid, vsprotocol_oid_len,
				  ASN_INTEGER,
				  PTR_CAST(u_char, &vsprotocol),
				  sizeof(vsprotocol));
	if (!rs) {
		quorumstatus = stopping ? 3 : vs->quorum_state_up ? 1 : 2;
		snmp_varlist_add_variable(&notification_vars,
					  quorumstatus_oid, quorumstatus_oid_len,
					  ASN_INTEGER,
					  PTR_CAST(u_char, &quorumstatus),
					  sizeof(quorumstatus));
		quorum = vs->quorum;
		snmp_varlist_add_variable(&notification_vars,
					  quorum_oid, quorum_oid_len,
					  ASN_UNSIGNED,
					  PTR_CAST(u_char, &quorum),
					  sizeof(quorum));
	}
	snmp_varlist_add_variable(&notification_vars,
				  realup_oid, realup_oid_len,
				  ASN_UNSIGNED,
				  PTR_CAST(u_char, &realup),
				  sizeof(realup));
	snmp_varlist_add_variable(&notification_vars,
				  realtotal_oid, realtotal_oid_len,
				  ASN_UNSIGNED,
				  PTR_CAST(u_char, &realtotal),
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
