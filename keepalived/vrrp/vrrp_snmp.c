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

#include "vrrp.h"
#include "vrrp_snmp.h"
#include "vrrp_data.h"
#include "vrrp_track.h"
#include "vrrp_ipaddress.h"
#include "vrrp_iproute.h"
#include "config.h"
#include "vector.h"
#include "list.h"
#include "logger.h"
#include "global_data.h"


/* Magic for RFC MIB functions */
#define VRRP_RFC_SNMP_NODE_VER            2
#define VRRP_RFC_SNMP_NOTIF_CNTL          3
#define VRRP_RFC_SNMP_OPER_IF_IDX         4
#define VRRP_RFC_SNMP_OPER_VRID           5
#define VRRP_RFC_SNMP_OPER_AUTH_KEY       6
#define VRRP_RFC_SNMP_OPER_ADVERT_INT     7
#define VRRP_RFC_SNMP_OPER_PREEMPT        8
#define VRRP_RFC_SNMP_OPER_VR_UPTIME      9
#define VRRP_RFC_SNMP_OPER_PROTO          10
#define VRRP_RFC_SNMP_OPER_ROW_STAT       11
#define VRRP_RFC_SNMP_OPER_VMAC           12
#define VRRP_RFC_SNMP_OPER_STATE          13
#define VRRP_RFC_SNMP_OPER_ADM_STATE      14
#define VRRP_RFC_SNMP_OPER_PRI            15
#define VRRP_RFC_SNMP_OPER_ADDR_CNT       16
#define VRRP_RFC_SNMP_OPER_MIP            17
#define VRRP_RFC_SNMP_OPER_PIP            18
#define VRRP_RFC_SNMP_OPER_AUTH_TYPE      19
#define VRRP_RFC_SNMP_OPER_TRAP_SRC       20
#define VRRP_RFC_SNMP_OPER_TRAP_AUTH_ERR  21
#define VRRP_RFC_SNMP_ASSOC_IP_ADDR       22
#define VRRP_RFC_SNMP_ASSOC_IP_ADDR_ROW   23
#define VRRP_RFC_SNMP_STATS_CHK_ERR       24
#define VRRP_RFC_SNMP_STATS_VER_ERR       26
#define VRRP_RFC_SNMP_STATS_VRID_ERR      27
#define VRRP_RFC_SNMP_STATS_MASTER        28
#define VRRP_RFC_SNMP_STATS_AUTH_INV      29
#define VRRP_RFC_SNMP_STATS_AUTH_MIS      30
#define VRRP_RFC_SNMP_STATS_PL_ERR        31
#define VRRP_RFC_SNMP_STATS_ADV_RCVD      32
#define VRRP_RFC_SNMP_STATS_ADV_INT_ERR   33
#define VRRP_RFC_SNMP_STATS_AUTH_FAIL     35
#define VRRP_RFC_SNMP_STATS_TTL_ERR       36
#define VRRP_RFC_SNMP_STATS_PRI_0_RCVD    37
#define VRRP_RFC_SNMP_STATS_PRI_0_SENT    38
#define VRRP_RFC_SNMP_STATS_INV_TYPE_RCVD 39
#define VRRP_RFC_SNMP_STATS_ADDR_LIST_ERR 40
#define VRRP_RFC_SNMP_CNFRM_MIB           41
#define VRRP_RFC_SNMP_GRP_OPER            42
#define VRRP_RFC_SNMP_GRP_STATS           43
#define VRRP_RFC_SNMP_GRP_TRAP            44
#define VRRP_RFC_SNMP_GRP_NOTIF           45

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
		*var_len = 4;
		return (u_char *)&route->dst;
	case VRRP_SNMP_ROUTE_DESTINATIONMASK:
		long_ret = route->dmask;
		return (u_char *)&long_ret;
	case VRRP_SNMP_ROUTE_GATEWAY:
		*var_len = 4;
		return (u_char *)&route->gw;
	case VRRP_SNMP_ROUTE_SECONDARYGATEWAY:
		if (route->gw2) {
			*var_len = 4;
			return (u_char *)&route->gw2;
		}
		break;
	case VRRP_SNMP_ROUTE_SOURCE:
		*var_len = 4;
		return (u_char *)&route->src;
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
		case 2:         /* disable accept */
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
			vrrp->accept = 0;
			break;
		case 2:
			log_message(LOG_INFO,
				    "VRRP_Instance(%s) accept mode disabled with SNMP",
				    vrrp->iname);
			vrrp->accept = 1;
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
			    (rt->adver_int * 100) / TIMER_HZ;
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
			long_ret = rt->auth_type;
		return (u_char *)&long_ret;

	case VRRP_SNMP_INSTANCE_USELVSSYNCDAEMON:
		long_ret = (rt->lvs_syncd_if)?1:2;
		return (u_char *)&long_ret;
	case VRRP_SNMP_INSTANCE_LVSSYNCINTERFACE:
		if (rt->lvs_syncd_if) {
			*var_len = strlen(rt->lvs_syncd_if);
			return (u_char *)rt->lvs_syncd_if;
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

static u_char*
vrrp_rfc_snmp_node_info(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
         return NULL;
}

static u_char*
vrrp_rfc_snmp_opertable(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
         return NULL;
}

static u_char*
vrrp_rfc_snmp_assoiptable(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
         return NULL;
}

static u_char*
vrrp_rfc_snmp_statstable(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
         return NULL;
}


static oid vrrp_rfc_oid[] = {VRRP_RFC_OID};
static struct variable8 vrrp_rfc_vars[] = {
        { VRRP_RFC_SNMP_NODE_VER, ASN_INTEGER, RONLY,
	  vrrp_rfc_snmp_node_info, 2, {1, 1}},
        { VRRP_RFC_SNMP_NOTIF_CNTL, ASN_INTEGER, RONLY,
	  vrrp_rfc_snmp_node_info, 2, {1, 2}},
	/* vrrpOperTable */
	{ VRRP_RFC_SNMP_OPER_IF_IDX, ASN_INTEGER, RONLY,
	  vrrp_rfc_snmp_opertable, 3, {1, 3, 1}},
        { VRRP_RFC_SNMP_OPER_VRID, ASN_INTEGER, RONLY,
	  vrrp_rfc_snmp_opertable, 4, {1, 3, 1, 1}},
        { VRRP_RFC_SNMP_OPER_VMAC, ASN_OCTET_STR, RONLY,
	  vrrp_rfc_snmp_opertable, 4, {1, 3, 1, 2}},
        { VRRP_RFC_SNMP_OPER_STATE, ASN_INTEGER, RONLY,
	  vrrp_rfc_snmp_opertable, 4, {1, 3, 1, 3}},
        { VRRP_RFC_SNMP_OPER_ADM_STATE, ASN_INTEGER, RONLY,
	  vrrp_rfc_snmp_opertable, 4, {1, 3, 1, 4}},
        { VRRP_RFC_SNMP_OPER_PRI, ASN_INTEGER, RONLY,
	  vrrp_rfc_snmp_opertable, 4, {1, 3, 1, 5}},
        { VRRP_RFC_SNMP_OPER_ADDR_CNT, ASN_INTEGER, RONLY,
	  vrrp_rfc_snmp_opertable, 4, {1, 3, 1, 6}},
        { VRRP_RFC_SNMP_OPER_MIP, ASN_IPADDRESS, RONLY,
	  vrrp_rfc_snmp_opertable, 4, {1, 3, 1, 7}},
        { VRRP_RFC_SNMP_OPER_PIP, ASN_IPADDRESS, RONLY,
	  vrrp_rfc_snmp_opertable, 4, {1, 3, 1, 8}},
        { VRRP_RFC_SNMP_OPER_AUTH_TYPE, ASN_INTEGER, RONLY,
	  vrrp_rfc_snmp_opertable, 4, {1, 3, 1, 9}},
        { VRRP_RFC_SNMP_OPER_AUTH_KEY, ASN_OCTET_STR, RONLY,
	  vrrp_rfc_snmp_opertable, 4, {1, 3, 1, 10}},
        { VRRP_RFC_SNMP_OPER_ADVERT_INT, ASN_INTEGER, RONLY,
	  vrrp_rfc_snmp_opertable, 4, {1, 3, 1, 11}},
        { VRRP_RFC_SNMP_OPER_PREEMPT, ASN_INTEGER, RONLY,
	  vrrp_rfc_snmp_opertable, 4, {1, 3, 1, 12}},
        { VRRP_RFC_SNMP_OPER_VR_UPTIME, ASN_TIMETICKS, RONLY,
	  vrrp_rfc_snmp_opertable, 4, {1, 3, 1, 13}},
        { VRRP_RFC_SNMP_OPER_PROTO, ASN_INTEGER, RONLY,
	  vrrp_rfc_snmp_opertable, 4, {1, 3, 1, 14}},
        { VRRP_RFC_SNMP_OPER_ROW_STAT, ASN_INTEGER, RONLY,
	  vrrp_rfc_snmp_opertable, 4, {1, 3, 1, 15}},
	/* vrrpAssoIpAddrTable */
        { VRRP_RFC_SNMP_ASSOC_IP_ADDR, ASN_IPADDRESS, RONLY,
	  vrrp_rfc_snmp_assoiptable, 4, {1, 4, 1, 1}},
        { VRRP_RFC_SNMP_ASSOC_IP_ADDR_ROW, ASN_INTEGER, RONLY,
	  vrrp_rfc_snmp_assoiptable, 4, {1, 4, 1, 2}},
	/* vrrpRouterStatsTable */
        { VRRP_RFC_SNMP_STATS_CHK_ERR, ASN_COUNTER, RONLY,
	  vrrp_rfc_snmp_statstable, 4, {2, 1}},
        { VRRP_RFC_SNMP_STATS_VER_ERR, ASN_COUNTER, RONLY,
	  vrrp_rfc_snmp_statstable, 2, {2, 2}},
        { VRRP_RFC_SNMP_STATS_VRID_ERR, ASN_COUNTER, RONLY,
	  vrrp_rfc_snmp_statstable, 2, {2, 3}},
        { VRRP_RFC_SNMP_STATS_MASTER, ASN_COUNTER, RONLY,
	  vrrp_rfc_snmp_statstable, 4, {2, 4, 1, 1}},
        { VRRP_RFC_SNMP_STATS_ADV_RCVD, ASN_COUNTER, RONLY,
	  vrrp_rfc_snmp_statstable, 4, {2, 4, 1, 2}},
        { VRRP_RFC_SNMP_STATS_ADV_INT_ERR, ASN_COUNTER, RONLY,
	  vrrp_rfc_snmp_statstable, 4, {2, 4, 1, 3}},
        { VRRP_RFC_SNMP_STATS_AUTH_FAIL, ASN_COUNTER, RONLY,
	  vrrp_rfc_snmp_statstable, 4, {2, 4, 1, 4}},
        { VRRP_RFC_SNMP_STATS_TTL_ERR, ASN_COUNTER, RONLY,
	  vrrp_rfc_snmp_statstable, 4, {2, 4, 1, 5}},
        { VRRP_RFC_SNMP_STATS_PRI_0_RCVD, ASN_COUNTER, RONLY,
	  vrrp_rfc_snmp_statstable, 4, {2, 4, 1, 6}},
        { VRRP_RFC_SNMP_STATS_PRI_0_SENT, ASN_COUNTER , RONLY,
	  vrrp_rfc_snmp_statstable, 4, {2, 4, 1, 7}},
        { VRRP_RFC_SNMP_STATS_INV_TYPE_RCVD, ASN_COUNTER, RONLY,
	  vrrp_rfc_snmp_statstable, 4, {2, 4, 1, 8}},
        { VRRP_RFC_SNMP_STATS_ADDR_LIST_ERR, ASN_COUNTER, RONLY,
	  vrrp_rfc_snmp_statstable, 4, {2, 4, 1, 9}},
        { VRRP_RFC_SNMP_STATS_AUTH_INV, ASN_COUNTER, RONLY,
	  vrrp_rfc_snmp_statstable, 4, {2, 4, 1, 10}},
        { VRRP_RFC_SNMP_STATS_AUTH_MIS, ASN_COUNTER, RONLY,
	  vrrp_rfc_snmp_statstable, 4, {2, 4, 1, 11}},
        { VRRP_RFC_SNMP_STATS_PL_ERR, ASN_COUNTER, RONLY,
	  vrrp_rfc_snmp_statstable, 4, {2, 4, 1, 12}}
};

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
	/* vrrpScriptTable */
	{VRRP_SNMP_SCRIPT_NAME, ASN_OCTET_STR, RONLY, vrrp_snmp_script, 3, {8, 1, 2}},
	{VRRP_SNMP_SCRIPT_COMMAND, ASN_OCTET_STR, RONLY, vrrp_snmp_script, 3, {8, 1, 3}},
	{VRRP_SNMP_SCRIPT_INTERVAL, ASN_INTEGER, RONLY, vrrp_snmp_script, 3, {8, 1, 4}},
	{VRRP_SNMP_SCRIPT_WEIGHT, ASN_INTEGER, RONLY, vrrp_snmp_script, 3, {8, 1, 5}},
	{VRRP_SNMP_SCRIPT_RESULT, ASN_INTEGER, RONLY, vrrp_snmp_script, 3, {8, 1, 6}},
	{VRRP_SNMP_SCRIPT_RISE, ASN_UNSIGNED, RONLY, vrrp_snmp_script, 3, {8, 1, 7}},
	{VRRP_SNMP_SCRIPT_FALL, ASN_UNSIGNED, RONLY, vrrp_snmp_script, 3, {8, 1, 8}},
};

void
vrrp_snmp_agent_init(const char *snmp_socket)
{
	snmp_agent_init(snmp_socket);
	snmp_register_mib(vrrp_oid, OID_LENGTH(vrrp_oid), "KEEPALIVED-VRRP",
			  (struct variable *)vrrp_vars,
			  sizeof(struct variable8),
			  sizeof(vrrp_vars)/sizeof(struct variable8));
	snmp_register_mib(vrrp_rfc_oid, OID_LENGTH(vrrp_rfc_oid), "VRRP",
			  (struct variable *)vrrp_rfc_vars,
			  sizeof(struct variable8),
			  sizeof(vrrp_rfc_vars)/sizeof(struct variable8));
}

void
vrrp_snmp_agent_close(void)
{
	snmp_agent_close(vrrp_oid, OID_LENGTH(vrrp_oid), "KEEPALIVED-VRRP");
	snmp_agent_close(vrrp_rfc_oid, OID_LENGTH(vrrp_rfc_oid), "VRRP");
}

void
vrrp_rfc_snmp_new_master_trap(vrrp_t *vrrp)
{

	/* OID of the notification vrrpTrapNewMaster */
	oid notification_oid[] = { VRRP_RFC_TRAP_OID, 1 };
	size_t notification_oid_len = OID_LENGTH(notification_oid);
	/* OID for snmpTrapOID.0 */
	oid objid_snmptrap[] = { SNMPTRAP_OID };
	size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);
	/* OID for trap data vrrpOperMasterIPAddr */
	oid masterip_oid[] = { VRRP_RFC_OID, 1, 3, 1, 7, IF_INDEX(vrrp->ifp), vrrp->vrid };
	size_t masterip_oid_len = OID_LENGTH(masterip_oid);

	netsnmp_variable_list *notification_vars = NULL;

	if (!global_data->enable_traps) return;

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
				  (u_char *)&vrrp->saddr,
				  sizeof(vrrp->saddr));
	log_message(LOG_INFO, "VRRP_Instance(%s): Sending SNMP notification"
			      " vrrpTrapNewMaster"
			    , vrrp->iname);
	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
}

void
vrrp_snmp_instance_trap(vrrp_t *vrrp)
{
	/* OID of the notification */
	oid notification_oid[] = { VRRP_OID, 9, 0, 2 };
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

        static unsigned long state;
	static unsigned long istate;

	if (!global_data->enable_traps) return;

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
	state = vrrp_snmp_state(vrrp->state);
	snmp_varlist_add_variable(&notification_vars,
				  state_oid, state_oid_len,
				  ASN_INTEGER,
				  (u_char *)&state,
				  sizeof(state));
	/* vrrpInstanceInitialState */
	istate = vrrp_snmp_state(vrrp->init_state);
	snmp_varlist_add_variable(&notification_vars,
				  initialstate_oid, initialstate_oid_len,
				  ASN_INTEGER,
				  (u_char *)&istate,
				  sizeof(istate));

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
	oid notification_oid[] = { VRRP_OID, 9, 0, 1 };
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

        static unsigned long state;

	if (!global_data->enable_traps) return;

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
	state = vrrp_snmp_state(group->state);
	snmp_varlist_add_variable(&notification_vars,
				  state_oid, state_oid_len,
				  ASN_INTEGER,
				  (u_char *)&state,
				  sizeof(state));

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
