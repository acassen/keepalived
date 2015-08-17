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

#include "check_data.h"
#include "check_snmp.h"
#include "list.h"
#include "ipvswrapper.h"
#include "ipwrapper.h"
#include "global_data.h"

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
	static unsigned long long_ret;
	static uint32_t ip;
	static struct in6_addr ip6;
        oid *target, current[2], best[2];
        int result, target_len;
	int curgroup = 0, curentry;
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
	for (e1 = LIST_HEAD(check_data->vs_group); e1; ELEMENT_NEXT(e1)) {
		group = ELEMENT_DATA(e1);
		curgroup++;
		curentry = 0;
		if (target_len && (curgroup < target[0]))
			continue; /* Optimization: cannot be part of our set */
		if (be)
			break; /* Optimization: cannot be the lower anymore */
		state = STATE_VSGM_FWMARK;
		while (state != STATE_VSGM_END) {
			switch (state) {
			case STATE_VSGM_FWMARK:
				l = group->vfwmark;
				break;
			case STATE_VSGM_ADDRESS:
				l = group->addr_ip;
				break;
			case STATE_VSGM_RANGE:
				l = group->range;
				break;
			default:
				/* Dunno? */
				return NULL;
			}
			state++;
			if (LIST_ISEMPTY(l))
				continue;
			for (e2 = LIST_HEAD(l); e2; ELEMENT_NEXT(e2)) {
				e = ELEMENT_DATA(e2);
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
	if (be == NULL)
		/* No best match */
		return NULL;
	if (exact)
		/* No exact match */
		return NULL;
 vsgmember_be_found:
	/* Let's use our best match */
        memcpy(target, best, sizeof(oid) * 2);
        *length = vp->namelen + 2;
 vsgmember_found:
	switch (vp->magic) {
	case CHECK_SNMP_VSGROUPMEMBERTYPE:
		if (be->vfwmark)
			long_ret = 1;
		else if (be->range)
			long_ret = 3;
		else
			long_ret = 2;
		return (u_char *)&long_ret;
	case CHECK_SNMP_VSGROUPMEMBERFWMARK:
		if (!be->vfwmark) break;
		long_ret = be->vfwmark;
		return (u_char *)&long_ret;
	case CHECK_SNMP_VSGROUPMEMBERADDRTYPE:
		if (be->vfwmark) break;
		long_ret = (be->addr.ss_family == AF_INET6) ? 2:1;
		return (u_char *)&long_ret;
	case CHECK_SNMP_VSGROUPMEMBERADDRESS:
		if (be->vfwmark || be->range) break;
		RETURN_IP46ADDRESS(be);
		break;
	case CHECK_SNMP_VSGROUPMEMBERADDR1:
		if (!be->range) break;
		RETURN_IP46ADDRESS(be);
		break;
	case CHECK_SNMP_VSGROUPMEMBERADDR2:
		if (!be->range) break;
		if (be->addr.ss_family == AF_INET6) {
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&be->addr;
			*var_len = 16;
			memcpy(&ip6, &addr6->sin6_addr, sizeof(ip6));
			ip6.s6_addr32[3] &= htonl(0xFFFFFF00);
			ip6.s6_addr32[3] += htonl(be->range);
			return (u_char *)&ip6;
		} else {
			struct sockaddr_in *addr4 = (struct sockaddr_in *)&be->addr;
			*var_len = 4;
			ip = (*(u_int32_t *)&addr4->sin_addr) & htonl(0xFFFFFF00);
			ip += htonl(be->range);
			return (u_char *)&ip;
		}
		break;
	case CHECK_SNMP_VSGROUPMEMBERPORT:
		if (be->vfwmark) break;
		long_ret = htons(inet_sockaddrport(&be->addr));
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
	static unsigned long long_ret;
#ifdef _KRNL_2_6_
	static U64 counter64_ret;
#endif
	virtual_server_t *v;
	element e;

	if ((v = (virtual_server_t *)
	     snmp_header_list_table(vp, name, length, exact,
				    var_len, write_method,
				    check_data->vs)) == NULL)
		return NULL;

	switch (vp->magic) {
	case CHECK_SNMP_VSTYPE:
		if (v->vsgname)
			long_ret = 3;
		else if (v->vfwmark)
			long_ret = 1;
		else
			long_ret = 2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSNAMEGROUP:
		if (!v->vsgname) break;
		*var_len = strlen(v->vsgname);
		return (u_char*)v->vsgname;
	case CHECK_SNMP_VSFWMARK:
		if (!v->vfwmark) break;
		long_ret = v->vfwmark;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSADDRTYPE:
		if (v->vfwmark || v->vsgname) break;
		long_ret = (v->addr.ss_family == AF_INET6) ? 2:1;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSADDRESS:
		if (v->vfwmark || v->vsgname) break;
		RETURN_IP46ADDRESS(v);
		break;
	case CHECK_SNMP_VSPORT:
		if (v->vfwmark || v->vsgname) break;
		long_ret = htons(inet_sockaddrport(&v->addr));
		return (u_char *)&long_ret;
	case CHECK_SNMP_VSPROTOCOL:
		long_ret = (v->service_type == IPPROTO_TCP)?1:2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSLOADBALANCINGALGO:
		if (strncmp(v->sched, "rr", SCHED_MAX_LENGTH) == 0)
			long_ret = 1;
		else if (strncmp(v->sched, "wrr", SCHED_MAX_LENGTH) == 0)
			long_ret = 2;
		else if (strncmp(v->sched, "lc", SCHED_MAX_LENGTH) == 0)
			long_ret = 3;
		else if (strncmp(v->sched, "wlc", SCHED_MAX_LENGTH) == 0)
			long_ret = 4;
		else if (strncmp(v->sched, "lblc", SCHED_MAX_LENGTH) == 0)
			long_ret = 5;
		else if (strncmp(v->sched, "lblcr", SCHED_MAX_LENGTH) == 0)
			long_ret = 6;
		else if (strncmp(v->sched, "dh", SCHED_MAX_LENGTH) == 0)
			long_ret = 7;
		else if (strncmp(v->sched, "sh", SCHED_MAX_LENGTH) == 0)
			long_ret = 8;
		else if (strncmp(v->sched, "sed", SCHED_MAX_LENGTH) == 0)
			long_ret = 9;
		else if (strncmp(v->sched, "nq", SCHED_MAX_LENGTH) == 0)
			long_ret = 10;
		else long_ret = 99;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSLOADBALANCINGKIND:
		long_ret = 0;
		switch (v->loadbalancing_kind) {
#ifdef _WITH_LVS_
#ifdef _KRNL_2_2_
		case 0:
			long_ret = 1;
			break;
		case IP_MASQ_F_VS_DROUTE:
			long_ret = 2;
			break;
		case IP_MASQ_F_VS_TUNNEL:
			long_ret = 3;
			break;
#else
		case IP_VS_CONN_F_MASQ:
			long_ret = 1;
			break;
		case IP_VS_CONN_F_DROUTE:
			long_ret = 2;
			break;
		case IP_VS_CONN_F_TUNNEL:
			long_ret = 3;
			break;
#endif
#endif
		}
		if (!long_ret) break;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSSTATUS:
		long_ret = v->alive?1:2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSVIRTUALHOST:
		if (!v->virtualhost) break;
		*var_len = strlen(v->virtualhost);
		return (u_char*)v->virtualhost;
	case CHECK_SNMP_VSPERSIST:
		long_ret = (atol(v->timeout_persistence) > 0)?1:2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSPERSISTTIMEOUT:
		if (atol(v->timeout_persistence) <= 0) break;
		long_ret = atol(v->timeout_persistence);
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSPERSISTGRANULARITY:
		if (atol(v->timeout_persistence) <= 0) break;
		if (!v->granularity_persistence) break;
		*var_len = 4;
		return (u_char*)&v->granularity_persistence;
	case CHECK_SNMP_VSDELAYLOOP:
		if (v->delay_loop >= TIMER_MAX_SEC)
			long_ret = v->delay_loop/TIMER_HZ;
		else
			long_ret = v->delay_loop;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSHASUSPEND:
		long_ret = v->ha_suspend?1:2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSOPS:
		long_ret = v->ops?1:2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSALPHA:
		long_ret = v->alpha?1:2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSOMEGA:
		long_ret = v->omega?1:2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSQUORUM:
		long_ret = v->quorum;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSQUORUMSTATUS:
		long_ret = v->quorum_state?1:2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSQUORUMUP:
		if (!v->quorum_up) break;
		*var_len = strlen(v->quorum_up);
		return (u_char*)v->quorum_up;
	case CHECK_SNMP_VSQUORUMDOWN:
		if (!v->quorum_down) break;
		*var_len = strlen(v->quorum_down);
		return (u_char*)v->quorum_down;
	case CHECK_SNMP_VSHYSTERESIS:
		long_ret = v->hysteresis;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSREALTOTAL:
		if (LIST_ISEMPTY(v->rs))
			long_ret = 0;
		else
			long_ret = LIST_SIZE(v->rs);
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSREALUP:
		long_ret = 0;
		if (!LIST_ISEMPTY(v->rs))
			for (e = LIST_HEAD(v->rs); e; ELEMENT_NEXT(e))
				if (((real_server_t *)ELEMENT_DATA(e))->alive)
					long_ret++;
		return (u_char*)&long_ret;
#if defined(_KRNL_2_6_) && defined(_WITH_LVS_)
	case CHECK_SNMP_VSSTATSCONNS:
		ipvs_update_stats(v);
		long_ret = v->stats.conns;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSSTATSINPKTS:
		ipvs_update_stats(v);
		long_ret = v->stats.inpkts;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSSTATSOUTPKTS:
		ipvs_update_stats(v);
		long_ret = v->stats.outpkts;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSSTATSINBYTES:
		ipvs_update_stats(v);
		counter64_ret.low = v->stats.inbytes & 0xffffffff;
		counter64_ret.high = v->stats.inbytes >> 32;
		*var_len = sizeof(U64);
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_VSSTATSOUTBYTES:
		ipvs_update_stats(v);
		counter64_ret.low = v->stats.outbytes & 0xffffffff;
		counter64_ret.high = v->stats.outbytes >> 32;
		*var_len = sizeof(U64);
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_VSRATECPS:
		ipvs_update_stats(v);
		long_ret = v->stats.cps;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSRATEINPPS:
		ipvs_update_stats(v);
		long_ret = v->stats.inpps;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSRATEOUTPPS:
		ipvs_update_stats(v);
		long_ret = v->stats.outpps;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSRATEINBPS:
		ipvs_update_stats(v);
		long_ret = v->stats.inbps;
		return (u_char*)&long_ret;
	case CHECK_SNMP_VSRATEOUTBPS:
		ipvs_update_stats(v);
		long_ret = v->stats.outbps;
		return (u_char*)&long_ret;
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
			     u_char *statP, oid *name, size_t name_len)
{
	element e1, e2;
	virtual_server_t *vs = NULL;
	real_server_t *rs = NULL;
	int ivs, irs;
	switch (action) {
	case RESERVE1:
		/* Check that the proposed value is acceptable */
		if (var_val_type != ASN_INTEGER)
			return SNMP_ERR_WRONGTYPE;
		if (var_val_len > sizeof(long))
			return SNMP_ERR_WRONGLENGTH;
		if ((long)(*var_val) < 0)
			return SNMP_ERR_WRONGVALUE;
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
				if (LIST_ISEMPTY(vs->rs)) return SNMP_ERR_NOSUCHNAME;
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
		update_svr_wgt((long)(*var_val), vs, rs, 1);
		break;
	}
	return SNMP_ERR_NOERROR;
}

static u_char*
check_snmp_realserver(struct variable *vp, oid *name, size_t *length,
		      int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
#ifdef _KRNL_2_6_
	static U64 counter64_ret;
#endif
        oid *target, current[2], best[2];
        int result, target_len;
	int curvirtual = 0, curreal;
	real_server_t *e = NULL, *be = NULL;
	element e1, e2 = NULL;
	virtual_server_t *vs, *bvs = NULL;
	int state;
	int type, btype;

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
				if (LIST_ISEMPTY(vs->rs)) {
					e = NULL;
					state = STATE_RS_END;
					break;
				}
				e2 = LIST_HEAD(vs->rs);
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
			if ((result == 0) && !exact)
				continue;
			if (result == 0) {
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
        *length = vp->namelen + 2;
 real_found:
	switch (vp->magic) {
	case CHECK_SNMP_RSTYPE:
		long_ret = (btype == STATE_RS_SORRY)?2:1;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSADDRTYPE:
		long_ret = (be->addr.ss_family == AF_INET6) ? 2:1;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSADDRESS:
		RETURN_IP46ADDRESS(be);
		break;
	case CHECK_SNMP_RSPORT:
		long_ret = htons(inet_sockaddrport(&be->addr));
		return (u_char *)&long_ret;
	case CHECK_SNMP_RSSTATUS:
		if (btype == STATE_RS_SORRY) break;
		long_ret = be->alive?1:2;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSWEIGHT:
		if (btype == STATE_RS_SORRY) break;
		long_ret = be->weight;
		*write_method = check_snmp_realserver_weight;
		return (u_char*)&long_ret;
#ifdef _KRNL_2_6_
	case CHECK_SNMP_RSUPPERCONNECTIONLIMIT:
		if (btype == STATE_RS_SORRY) break;
		if (!be->u_threshold) break;
		long_ret = be->u_threshold;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSLOWERCONNECTIONLIMIT:
		if (btype == STATE_RS_SORRY) break;
		if (!be->l_threshold) break;
		long_ret = be->l_threshold;
		return (u_char*)&long_ret;
#endif
	case CHECK_SNMP_RSACTIONWHENDOWN:
		if (btype == STATE_RS_SORRY) break;
		long_ret = be->inhibit?2:1;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSNOTIFYUP:
		if (btype == STATE_RS_SORRY) break;
		if (!be->notify_up) break;
		*var_len = strlen(be->notify_up);
		return (u_char*)be->notify_up;
	case CHECK_SNMP_RSNOTIFYDOWN:
		if (btype == STATE_RS_SORRY) break;
		if (!be->notify_down) break;
		*var_len = strlen(be->notify_down);
		return (u_char*)be->notify_down;
	case CHECK_SNMP_RSFAILEDCHECKS:
		if (btype == STATE_RS_SORRY) break;
		if (LIST_ISEMPTY(be->failed_checkers))
			long_ret = 0;
		else
			long_ret = LIST_SIZE(be->failed_checkers);
		return (u_char*)&long_ret;
#if defined(_KRNL_2_6_) && defined(_WITH_LVS_)
	case CHECK_SNMP_RSSTATSCONNS:
		ipvs_update_stats(bvs);
		long_ret = be->stats.conns;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSSTATSACTIVECONNS:
		ipvs_update_stats(bvs);
		long_ret = be->activeconns;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSSTATSINACTIVECONNS:
		ipvs_update_stats(bvs);
		long_ret = be->inactconns;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSSTATSPERSISTENTCONNS:
		ipvs_update_stats(bvs);
		long_ret = be->persistconns;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSSTATSINPKTS:
		ipvs_update_stats(bvs);
		long_ret = be->stats.inpkts;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSSTATSOUTPKTS:
		ipvs_update_stats(bvs);
		long_ret = be->stats.outpkts;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSSTATSINBYTES:
		ipvs_update_stats(bvs);
		counter64_ret.low = be->stats.inbytes & 0xffffffff;
		counter64_ret.high = be->stats.inbytes >> 32;
		*var_len = sizeof(U64);
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_RSSTATSOUTBYTES:
		ipvs_update_stats(bvs);
		counter64_ret.low = be->stats.outbytes & 0xffffffff;
		counter64_ret.high = be->stats.outbytes >> 32;
		*var_len = sizeof(U64);
		return (u_char*)&counter64_ret;
	case CHECK_SNMP_RSRATECPS:
		ipvs_update_stats(bvs);
		long_ret = be->stats.cps;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSRATEINPPS:
		ipvs_update_stats(bvs);
		long_ret = be->stats.inpps;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSRATEOUTPPS:
		ipvs_update_stats(bvs);
		long_ret = be->stats.outpps;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSRATEINBPS:
		ipvs_update_stats(bvs);
		long_ret = be->stats.inbps;
		return (u_char*)&long_ret;
	case CHECK_SNMP_RSRATEOUTBPS:
		ipvs_update_stats(bvs);
		long_ret = be->stats.outbps;
		return (u_char*)&long_ret;
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
#if defined(_KRNL_2_6_) && defined(_WITH_LVS_)
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
#ifdef _KRNL_2_6_
	{CHECK_SNMP_RSUPPERCONNECTIONLIMIT, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 8}},
	{CHECK_SNMP_RSLOWERCONNECTIONLIMIT, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 9}},
#endif
	{CHECK_SNMP_RSACTIONWHENDOWN, ASN_INTEGER, RONLY,
	 check_snmp_realserver, 3, {4, 1, 10}},
	{CHECK_SNMP_RSNOTIFYUP, ASN_OCTET_STR, RONLY,
	 check_snmp_realserver, 3, {4, 1, 11}},
	{CHECK_SNMP_RSNOTIFYDOWN, ASN_OCTET_STR, RONLY,
	 check_snmp_realserver, 3, {4, 1, 12}},
	{CHECK_SNMP_RSFAILEDCHECKS, ASN_UNSIGNED, RONLY,
	 check_snmp_realserver, 3, {4, 1, 13}},
#if defined(_KRNL_2_6_) && defined(_WITH_LVS_)
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
#endif
};

void
check_snmp_agent_init(const char *snmp_socket)
{
	snmp_agent_init(snmp_socket);
	snmp_register_mib(check_oid, OID_LENGTH(check_oid), "Healthchecker",
			  (struct variable *)check_vars,
			  sizeof(struct variable8),
			  sizeof(check_vars)/sizeof(struct variable8));
}

void
check_snmp_agent_close()
{
	snmp_agent_close(check_oid, OID_LENGTH(check_oid), "Healthchecker");
}

void
check_snmp_rs_trap(real_server_t *rs, virtual_server_t *vs)
{
	element e;

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
	if (LIST_ISEMPTY(vs->rs))
		realtotal = 0;
	else
		realtotal = LIST_SIZE(vs->rs);
	realup = 0;
	if (!LIST_ISEMPTY(vs->rs))
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
					  (u_char *)vs->vsgname,
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
		quorumstatus = vs->quorum_state?1:2;
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
	snmp_varlist_add_variable(&notification_vars,
				  routerId_oid, routerId_oid_len,
				  ASN_OCTET_STR,
				  (u_char *)global_data->router_id,
				  strlen(global_data->router_id));

	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
}

void
check_snmp_quorum_trap(virtual_server_t *vs)
{
	check_snmp_rs_trap(NULL, vs);
}
