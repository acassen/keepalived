/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Manipulation functions for IPVS & IPFW wrappers.
 *
 * Version:     $id: ipwrapper.c,v 0.7.6 2002/11/20 21:34:18 acassen Exp $
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
 */

#include "ipwrapper.h"
#include "utils.h"

/* extern global vars */
extern data *conf_data;
extern data *old_data;

/* Remove a realserver IPVS rule */
static int
clear_service_rs(virtual_server * vs, list l)
{
	element e;
	real_server *rs;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (ISALIVE(rs))
			if (!ipvs_cmd(LVS_CMD_DEL_DEST, vs, rs))
				return 0;
#ifdef _KRNL_2_2_
		/* if we have a /32 mask, we create one nat rules per
		 * realserver.
		 */
		if (vs->nat_mask == HOST_NETMASK)
			if (!ipfw_cmd(IP_FW_CMD_DEL, vs, rs))
				return 0;
#endif
	}
	return 1;
}

/* Remove a virtualserver IPVS rule */
static int
clear_service_vs(virtual_server * vs)
{
	element e;
	real_server_group *group;

	/* Processing real server queue */
	if (!LIST_ISEMPTY(vs->rs)) {
		if (vs->s_svr) {
			if (ISALIVE(vs->s_svr))
				if (!ipvs_cmd(LVS_CMD_DEL_DEST, vs, vs->s_svr))
					return 0;
		} else if (!clear_service_rs(vs, vs->rs))
			return 0;
	}

	/* Processing real server group queue */
	if (!LIST_ISEMPTY(vs->rs_group)) {
		for (e = LIST_HEAD(vs->rs_group); e; ELEMENT_NEXT(e)) {
			group = ELEMENT_DATA(e);
			if (!clear_service_rs(vs, group->rs))
				return 0;
		}
	}

	if (!ipvs_cmd(LVS_CMD_DEL, vs, NULL))
		return 0;
	return 1;
}

/* IPVS cleaner processing */
int
clear_services(void)
{
	element e;
	list l = conf_data->vs;
	virtual_server *vs;
	real_server *rs;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);
		rs = ELEMENT_DATA(LIST_HEAD(vs->rs));
		if (!clear_service_vs(vs))
			return 0;
#ifdef _KRNL_2_2_
		if (vs->nat_mask != HOST_NETMASK)
			if (!ipfw_cmd(IP_FW_CMD_DEL, vs, rs))
				return 0;
#endif
	}
	return 1;
}

/* Set a realserver IPVS rules */
static int
init_service_rs(virtual_server * vs, list l)
{
	element e;
	real_server *rs;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (!ISALIVE(rs)) {
			if (!ipvs_cmd(LVS_CMD_ADD_DEST, vs, rs))
				return 0;
			else
				SET_ALIVE(rs);
		}
#ifdef _KRNL_2_2_
		/* if we have a /32 mask, we create one nat rules per
		 * realserver.
		 */
		if (vs->nat_mask == HOST_NETMASK)
			if (!ipfw_cmd(IP_FW_CMD_ADD, vs, rs))
				return 0;
#endif
	}
	return 1;
}

/* Set a virtualserver IPVS rules */
static int
init_service_vs(virtual_server * vs)
{
	element e;
	real_server_group *group;

	/* Init the VS root */
	if (!ISALIVE(vs)) {
		if (!ipvs_cmd(LVS_CMD_ADD, vs, NULL))
			return 0;
		else
			SET_ALIVE(vs);
	}

	/* Processing real server queue */
	if (!LIST_ISEMPTY(vs->rs))
		if (!init_service_rs(vs, vs->rs))
			return 0;

	/* Processing real server group queue */
	if (!LIST_ISEMPTY(vs->rs_group)) {
		for (e = LIST_HEAD(vs->rs_group); e; ELEMENT_NEXT(e)) {
			group = ELEMENT_DATA(e);
			if (!init_service_rs(vs, group->rs))
				return 0;
		}
	}
	return 1;
}

/* Set IPVS rules */
int
init_services(void)
{
	element e;
	list l = conf_data->vs;
	virtual_server *vs;
	real_server *rs;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);
		rs = ELEMENT_DATA(LIST_HEAD(vs->rs));
		if (!init_service_vs(vs))
			return 0;
#ifdef _KRNL_2_2_
		/* work if all realserver ip address are in the
		 * same network (it is assumed).
		 */
		if (vs->nat_mask != HOST_NETMASK)
			if (!ipfw_cmd(IP_FW_CMD_ADD, vs, rs))
				return 0;
#endif
	}
	return 1;
}

/* Check if all rs for a specific vs are down */
int
all_realservers_down(virtual_server * vs)
{
	element e;
	real_server *svr;

	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		svr = ELEMENT_DATA(e);
		if (ISALIVE(svr))
			return 0;
	}
	return 1;
}

/* manipulate add/remove rs according to alive state */
void
perform_svr_state(int alive, virtual_server * vs, real_server * rs)
{
	char rsip[16], vsip[16];

	if (!ISALIVE(rs) && alive) {

		/* adding a server to the vs pool, if sorry server is flagged alive,
		 * we remove it from the vs pool.
		 */
		if (vs->s_svr) {
			if (ISALIVE(vs->s_svr)) {
				syslog(LOG_INFO,
				       "Removing sorry server [%s:%d] from VS [%s:%d]",
				       inet_ntoa2(SVR_IP(vs->s_svr), rsip)
				       , ntohs(SVR_PORT(vs->s_svr))
				       , inet_ntoa2(SVR_IP(vs), vsip)
				       , ntohs(SVR_PORT(vs)));

				vs->s_svr->alive = 0;
				ipvs_cmd(LVS_CMD_DEL_DEST, vs, vs->s_svr);
#ifdef _KRNL_2_2_
				ipfw_cmd(IP_FW_CMD_DEL, vs, vs->s_svr);
#endif
			}
		}

		rs->alive = alive;
		syslog(LOG_INFO, "%s service [%s:%d] to VS [%s:%d]",
		       (rs->inhibit) ? "Enabling" : "Adding"
		       , inet_ntoa2(SVR_IP(rs), rsip)
		       , ntohs(SVR_PORT(rs))
		       , inet_ntoa2(SVR_IP(vs), vsip)
		       , ntohs(SVR_PORT(vs)));
		ipvs_cmd(LVS_CMD_ADD_DEST, vs, rs);
#ifdef _KRNL_2_2_
		if (vs->nat_mask == HOST_NETMASK)
			ipfw_cmd(IP_FW_CMD_ADD, vs, rs);
#endif

	} else {

		rs->alive = alive;
		syslog(LOG_INFO, "%s service [%s:%d] from VS [%s:%d]",
		       (rs->inhibit) ? "Disabling" : "Removing"
		       , inet_ntoa2(SVR_IP(rs), rsip)
		       , ntohs(SVR_PORT(rs))
		       , inet_ntoa2(SVR_IP(vs), vsip)
		       , ntohs(SVR_PORT(vs)));

		/* server is down, it is removed from the LVS realserver pool */
		ipvs_cmd(LVS_CMD_DEL_DEST, vs, rs);

#ifdef _KRNL_2_2_
		if (vs->nat_mask == HOST_NETMASK)
			ipfw_cmd(IP_FW_CMD_DEL, vs, rs);
#endif

		/* if all the realserver pool is down, we add sorry server */
		if (vs->s_svr && all_realservers_down(vs)) {
			syslog(LOG_INFO,
			       "Adding sorry server [%s:%d] to VS [%s:%d]",
			       inet_ntoa2(SVR_IP(vs->s_svr), rsip)
			       , ntohs(SVR_PORT(vs->s_svr))
			       , inet_ntoa2(SVR_IP(vs), vsip)
			       , ntohs(SVR_PORT(vs)));

			/* the sorry server is now up in the pool, we flag it alive */
			vs->s_svr->alive = 1;
			ipvs_cmd(LVS_CMD_ADD_DEST, vs, vs->s_svr);

#ifdef _KRNL_2_2_
			ipfw_cmd(IP_FW_CMD_ADD, vs, vs->s_svr);
#endif
		}

	}
}

/* Check if rs1 = rs2 */
static int
rs_iseq(real_server * rs1, real_server * rs2)
{
	if (rs1->addr_ip == rs2->addr_ip &&
	    rs1->addr_port == rs2->addr_port &&
	    rs1->weight == rs2->weight)
		return 1;
	return 0;
}

/* Check if vs1 = vs2 */
static int
vs_iseq(virtual_server * vs1, virtual_server * vs2)
{
	if (vs1->addr_ip == vs2->addr_ip &&
	    vs1->vfwmark == vs2->vfwmark &&
	    vs1->addr_port == vs2->addr_port &&
	    vs1->service_type == vs2->service_type &&
	    !strcmp(vs1->sched, vs2->sched) &&
	    !strcmp(vs1->timeout_persistence, vs2->timeout_persistence) &&
	    vs1->loadbalancing_kind == vs2->loadbalancing_kind &&
	    vs1->nat_mask == vs2->nat_mask &&
	    vs1->granularity_persistence == vs2->granularity_persistence)
		return 1;
	return 0;
}

/* Check if a vs exist in new data */
static int
vs_exist(virtual_server * old_vs)
{
	element e;
	list l = conf_data->vs;
	virtual_server *vs;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);
		if (vs_iseq(old_vs, vs)) {
			/*
			 * We reflect the previous alive
			 * flag value to not try to set
			 * already set IPVS rule.
			 */
			vs->alive = old_vs->alive;
			return 1;
		}
	}

	return 0;
}

/* Check if rs is in new vs data */
static int
rs_exist(real_server * old_rs, list l)
{
	element e;
	real_server *rs;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (rs_iseq(rs, old_rs)) {
			/*
			 * We reflect the previous alive
			 * flag value to not try to set
			 * already set IPVS rule.
			 */
			rs->alive = old_rs->alive;
			return 1;
		}
	}

	return 0;
}

/* get rs list for a specific vs */
static list
get_rs_list(virtual_server * vs)
{
	element e;
	list l = conf_data->vs;
	virtual_server *vsrv;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsrv = ELEMENT_DATA(e);
		if (vs_iseq(vs, vsrv))
			return vsrv->rs;
	}

	/* most of the time never reached */
	return NULL;
}

/* Clear the diff rs of the old vs */
static int
clear_diff_rs(virtual_server * old_vs)
{
	element e;
	list l = old_vs->rs;
	list new = get_rs_list(old_vs);
	real_server *rs;
	char rsip[16], vsip[16];

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (!rs_exist(rs, new) && (ISALIVE(rs) || rs->inhibit)) {
			/* Reset inhibit flag to delete inhibit entries */
			syslog(LOG_INFO, "service [%s:%d] no longer exist"
			       , inet_ntoa2(SVR_IP(rs), rsip)
			       , ntohs(SVR_PORT(rs)));
			syslog(LOG_INFO, "Removing service [%s:%d] from VS [%s:%d]"
			       , inet_ntoa2(SVR_IP(rs), rsip)
			       , ntohs(SVR_PORT(rs))
			       , inet_ntoa2(SVR_IP(old_vs), vsip)
			       , ntohs(SVR_PORT(old_vs)));
			rs->inhibit = 0;
			if (!ipvs_cmd(LVS_CMD_DEL_DEST, old_vs, rs))
				return 0;
		} else if (!ISALIVE(rs) && rs->inhibit) {
			/*
			 * We duplicate here just for optimization. We
			 * don t want to call rs_exist() 2 times.
			 */
			rs->inhibit = 0;
			if (!ipvs_cmd(LVS_CMD_DEL_DEST, old_vs, rs))
				return 0;
		}
	}

	return 1;
}

/* When reloading configuration, remove negative diff entries */
int
clear_diff_services(void)
{
	element e;
	list l = old_data->vs;
	virtual_server *vs;

	/* Remove diff entries from previous IPVS rules */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);

		/*
		 * Try to find this vs into the new conf data
		 * reloaded.
		 */
		if (!vs_exist(vs)) {
			if (!clear_service_vs(vs))
				return 0;
		} else {
			/* If vs exist, perform rs pool diff */
			if (!clear_diff_rs(vs))
				return 0;
			if (vs->s_svr)
				if (ISALIVE(vs->s_svr))
					if (!ipvs_cmd(LVS_CMD_DEL_DEST, vs,
						      vs->s_svr))
						return 0;
		}
	}

	return 1;
}
