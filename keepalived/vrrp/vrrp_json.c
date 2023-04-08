/*
 * Soft:        Vrrpd is an implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Part:        Output running VRRP state information in JSON format
 *
 * Author:	Alexandre Cassen, <acassen@gmail.com>
 *		Damien Clabaut, <Damien.Clabaut@corp.ovh.com>
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
 * Copyright (C) 2001-2019 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"
#include "vrrp_json.h"

#include <errno.h>
#include <stdio.h>

#include "vrrp.h"
#include "vrrp_track.h"
#include "list_head.h"
#include "vrrp_data.h"
#include "vrrp_ipaddress.h"
#include "vrrp_iproute.h"
#include "vrrp_iprule.h"
#include "logger.h"
#include "timer.h"
#include "utils.h"
#include "global_data.h"
#include "rttables.h"
#include "json_writer.h"

static inline double
timeval_to_double(const timeval_t *t)
{
	/* The casts are necessary to avoid conversion warnings */
	return t->tv_sec + t->tv_usec / TIMER_HZ_DOUBLE;
}

static int
vrrp_json_script_dump(json_writer_t *wr, const char *prop, notify_script_t *script)
{
	if (!script)
		return -1;

	jsonw_string_field(wr, prop, cmd_str(script));
	return 0;
}

static int
vrrp_json_ip_dump(json_writer_t *wr, list_head_t *e)
{
	char peer[INET6_ADDRSTRLEN + 4];
	ip_address_t *ipaddr = list_entry(e, ip_address_t, e_list);

	if (ipaddr->ifa.ifa_family == AF_UNSPEC)
		return -1;

	jsonw_start_object(wr);

	jsonw_string_field(wr, "ip", ipaddresstos(NULL, ipaddr));
	if (!IP_IS6(ipaddr) && ipaddr->u.sin.sin_brd.s_addr)
		jsonw_string_field(wr, "brd", inet_ntop2(ipaddr->u.sin.sin_brd.s_addr));
	jsonw_string_field(wr, "dev", IF_NAME(ipaddr->ifp));
#ifdef _HAVE_VRRP_VMAC_
	if (ipaddr->ifp != ipaddr->ifp->base_ifp)
		jsonw_string_field(wr, "base_ifp", ipaddr->ifp->base_ifp->ifname);
	if (ipaddr->use_vmac)
		jsonw_bool_field(wr, "use_vmac", true);
#endif
	jsonw_string_field(wr, "scope", get_rttables_scope(ipaddr->ifa.ifa_scope));
	if (ipaddr->label)
		jsonw_string_field(wr, "label", ipaddr->label);
	if (ipaddr->have_peer) {
                inet_ntop(ipaddr->ifa.ifa_family, &ipaddr->peer, peer, sizeof(peer));
                jsonw_string_field(wr, "peer", peer);
                jsonw_uint_field(wr, "peer_prefixlen", ipaddr->ifa.ifa_prefixlen);
	}
	if (ipaddr->flags & IFA_F_HOMEADDRESS)
		jsonw_bool_field(wr, "home", true);
	if (ipaddr->flagmask & IFA_F_NODAD)
		jsonw_bool_field(wr, "no_dad", true);
#ifdef IFA_F_MANAGETEMPADDR
	if (ipaddr->flags & IFA_F_MANAGETEMPADDR)
		jsonw_bool_field(wr, "mng_tmp_addr", true);
#endif
#ifdef IFA_F_NOPREFIXROUTE
	if (ipaddr->flags & IFA_F_NOPREFIXROUTE)
		jsonw_bool_field(wr, "no_prefix_route", true);
#endif
#ifdef IFA_F_MCAUTOJOIN
	if (ipaddr->flags & IFA_F_MCAUTOJOIN)
		jsonw_bool_field(wr, "auto_join", true);
#endif
	if (ipaddr->dont_track)
		jsonw_bool_field(wr, "dont_track", true);
	if (ipaddr->track_group)
		jsonw_bool_field(wr, "track_group", true);
	if (IP_IS6(ipaddr)) {
		if (ipaddr->preferred_lft == 0)
			jsonw_string_field(wr, "preferred_lft", "deprecated");
		else if (ipaddr->preferred_lft == INFINITY_LIFE_TIME)
			jsonw_string_field(wr, "preferred_lft", "forever");
		else
			jsonw_uint_field(wr, "preferred_lft", ipaddr->preferred_lft);
	}
	if (ipaddr->set)
		jsonw_bool_field(wr, "set", true);
#ifdef _WITH_IPTABLES_
	if (ipaddr->iptable_rule_set)
		jsonw_bool_field(wr, "iptable_set", true);
#endif
#ifdef _WITH_NFTABLES_
	if (ipaddr->iptable_rule_set)
		jsonw_bool_field(wr, "nftable_set", true);
#endif

	jsonw_end_object(wr);
	return 0;
}

static int
vrrp_json_vroute_dump(json_writer_t *wr, list_head_t *e)
{
	ip_route_t *iproute = list_entry(e, ip_route_t, e_list);
	char buf[256];

	format_iproute(iproute, buf, sizeof(buf));
	jsonw_string(wr, buf);
	return 0;
}

static int
vrrp_json_vrule_dump(json_writer_t *wr, list_head_t *e)
{
	ip_rule_t *iprule = list_entry(e, ip_rule_t, e_list);
	char buf[256];

	format_iprule(iprule, buf, sizeof(buf));
	jsonw_string(wr, buf);
	return 0;
}

static int
vrrp_json_track_ifp_dump(json_writer_t *wr, list_head_t *e)
{
	tracked_if_t *tip = list_entry(e, tracked_if_t, e_list);
	interface_t *ifp = tip->ifp;

	jsonw_string(wr, ifp->ifname);
	return 0;
}

static int
vrrp_json_track_script_dump(json_writer_t *wr, list_head_t *e)
{
	tracked_sc_t *tsc = list_entry(e, tracked_sc_t, e_list);
	vrrp_script_t *vscript = tsc->scr;

	jsonw_string(wr, vscript->sname);
	return 0;
}

#ifdef _WITH_TRACK_PROCESS_
static int
vrrp_json_track_process_dump(json_writer_t *wr, list_head_t *e)
{
	tracked_process_t *tpr = list_entry(e, tracked_process_t, e_list);
	vrrp_tracked_process_t *vprocess = tpr->process;

	jsonw_string(wr, vprocess->pname);
	return 0;
}
#endif

static int
vrrp_json_array_dump(json_writer_t *wr, const char *prop, list_head_t *l,
		     int (*func) (json_writer_t *, list_head_t *))
{
	list_head_t *e;

	if (list_empty(l))
		return -1;

	jsonw_name(wr, prop);
	jsonw_start_array(wr);
	list_for_each(e, l)
		(*func) (wr, e);
	jsonw_end_array(wr);
	return 0;
}

#if defined _WITH_VRRP_AUTH_
static int
vrrp_json_auth_dump(json_writer_t *wr, const char *prop, vrrp_t *vrrp)
{
	char buf[sizeof(vrrp->auth_data) + 1];

	if (!vrrp->auth_type)
		return -1;

	memcpy(buf, vrrp->auth_data, sizeof(vrrp->auth_data));
	buf[sizeof(vrrp->auth_data)] = 0;
	jsonw_string_field(wr, prop, buf);
	return 0;
}
#endif

static int
vrrp_json_data_dump(json_writer_t *wr, vrrp_t *vrrp)
{
	/* data object */
	jsonw_name(wr, "data");
	jsonw_start_object(wr);

	/* Global instance related */
	jsonw_string_field(wr, "iname", vrrp->iname);
	jsonw_uint_field(wr, "dont_track_primary", __test_bit(VRRP_FLAG_DONT_TRACK_PRIMARY, &vrrp->flags));
	jsonw_uint_field(wr, "skip_check_adv_addr", __test_bit(VRRP_FLAG_SKIP_CHECK_ADV_ADDR, &vrrp->flags));
	jsonw_uint_field(wr, "strict_mode", vrrp->strict_mode);
#ifdef _HAVE_VRRP_VMAC_
	jsonw_string_field(wr, "vmac_ifname", vrrp->vmac_ifname);
#endif
	if (vrrp->ifp)
		jsonw_string_field(wr, "ifp_ifname", vrrp->ifp->ifname);
	jsonw_uint_field(wr, "master_priority", vrrp->master_priority);
	jsonw_float_field_fmt(wr, "last_transition", "%f", timeval_to_double(&vrrp->last_transition));
	jsonw_float_field(wr, "garp_delay", vrrp->garp_delay / TIMER_HZ_DOUBLE);
	jsonw_uint_field(wr, "garp_refresh", vrrp->garp_refresh.tv_sec);
	jsonw_uint_field(wr, "garp_rep", vrrp->garp_rep);
	jsonw_uint_field(wr, "garp_refresh_rep", vrrp->garp_refresh_rep);
	jsonw_uint_field(wr, "garp_lower_prio_delay", vrrp->garp_lower_prio_delay / TIMER_HZ);
	jsonw_uint_field(wr, "garp_lower_prio_rep", vrrp->garp_lower_prio_rep);
	jsonw_uint_field(wr, "lower_prio_no_advert", vrrp->lower_prio_no_advert);
	jsonw_uint_field(wr, "higher_prio_send_advert", vrrp->higher_prio_send_advert);
	jsonw_uint_field(wr, "vrid", vrrp->vrid);
	jsonw_uint_field(wr, "base_priority", vrrp->base_priority);
	jsonw_uint_field(wr, "effective_priority", vrrp->effective_priority);
	jsonw_bool_field(wr, "vipset", vrrp->vipset);
	jsonw_bool_field(wr, "promote_secondaries", __test_bit(VRRP_FLAG_PROMOTE_SECONDARIES, &vrrp->flags));
	jsonw_float_field(wr, "adver_int", vrrp->adver_int / TIMER_HZ_DOUBLE);
	jsonw_float_field(wr, "master_adver_int", vrrp->master_adver_int / TIMER_HZ_DOUBLE);
#ifdef _WITH_FIREWALL_
	jsonw_uint_field(wr, "accept", vrrp->accept);
#endif
	jsonw_bool_field(wr, "nopreempt", __test_bit(VRRP_FLAG_NOPREEMPT, &vrrp->flags));
	jsonw_uint_field(wr, "preempt_delay", vrrp->preempt_delay / TIMER_HZ);
	jsonw_uint_field(wr, "state", vrrp->state);
	jsonw_uint_field(wr, "wantstate", vrrp->wantstate);
	jsonw_uint_field(wr, "version", vrrp->version);
	jsonw_bool_field(wr, "smtp_alert", vrrp->smtp_alert);
	jsonw_bool_field(wr, "notify_deleted", vrrp->notify_deleted);

	/* Script related */
	vrrp_json_script_dump(wr, "script_backup", vrrp->script_backup);
	vrrp_json_script_dump(wr, "script_master", vrrp->script_master);
	vrrp_json_script_dump(wr, "script_fault", vrrp->script_fault);
	vrrp_json_script_dump(wr, "script_stop", vrrp->script_stop);
	vrrp_json_script_dump(wr, "script_deleted", vrrp->script_deleted);
	vrrp_json_script_dump(wr, "script", vrrp->script);
	vrrp_json_script_dump(wr, "script_master_rx_lower_pri"
				, vrrp->script_master_rx_lower_pri);

	/* Virtual related */
	vrrp_json_array_dump(wr, "vips", &vrrp->vip, vrrp_json_ip_dump);
	vrrp_json_array_dump(wr, "evips", &vrrp->evip, vrrp_json_ip_dump);
	vrrp_json_array_dump(wr, "vroutes", &vrrp->vroutes, vrrp_json_vroute_dump);
	vrrp_json_array_dump(wr, "vrules", &vrrp->vrules, vrrp_json_vrule_dump);

	/* Tracking related */
	vrrp_json_array_dump(wr, "track_ifp", &vrrp->track_ifp, vrrp_json_track_ifp_dump);
	vrrp_json_array_dump(wr, "track_script", &vrrp->track_script, vrrp_json_track_script_dump);
#ifdef _WITH_TRACK_PROCESS_
	vrrp_json_array_dump(wr, "track_process", &vrrp->track_process, vrrp_json_track_process_dump);
#endif

#ifdef _WITH_VRRP_AUTH_
	jsonw_uint_field(wr, "auth_type", vrrp->auth_type);
	vrrp_json_auth_dump(wr, "auth_data", vrrp);
#endif

	jsonw_end_object(wr);
	return 0;
}

static int
vrrp_json_stats_dump(json_writer_t *wr, vrrp_t *vrrp)
{
	vrrp_stats *stats = vrrp->stats;

	if (!stats)
		return -1;

	/* data object */
	jsonw_name(wr, "stats");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "advert_rcvd", stats->advert_rcvd);
	jsonw_uint_field(wr, "advert_sent", stats->advert_sent);
	jsonw_uint_field(wr, "become_master", stats->become_master);
	jsonw_uint_field(wr, "release_master", stats->release_master);
	jsonw_uint_field(wr, "packet_len_err", stats->packet_len_err);
	jsonw_uint_field(wr, "advert_interval_err", stats->advert_interval_err);
	jsonw_uint_field(wr, "ip_ttl_err", stats->ip_ttl_err);
	jsonw_uint_field(wr, "invalid_type_rcvd", stats->invalid_type_rcvd);
	jsonw_uint_field(wr, "addr_list_err", stats->addr_list_err);
	jsonw_uint_field(wr, "invalid_authtype", stats->invalid_authtype);
#ifdef _WITH_VRRP_AUTH_
	jsonw_uint_field(wr, "authtype_mismatch", stats->authtype_mismatch);
	jsonw_uint_field(wr, "auth_failure", stats->auth_failure);
#endif
	jsonw_uint_field(wr, "pri_zero_rcvd", stats->pri_zero_rcvd);
	jsonw_uint_field(wr, "pri_zero_sent", stats->pri_zero_sent);
	jsonw_end_object(wr);
	return 0;
}

static int
vrrp_json_vscript_dump(json_writer_t *wr, list_head_t *e)
{
	vrrp_script_t *vscript = list_entry(e, vrrp_script_t, e_list);

	jsonw_start_object(wr);

	jsonw_string_field(wr, "script_name", vscript->sname);
	jsonw_string_field(wr, "script", cmd_str(&vscript->script));
	jsonw_uint_field(wr, "interval", vscript->interval / TIMER_HZ);
	jsonw_uint_field(wr, "timeout", vscript->timeout / TIMER_HZ);
	jsonw_int_field(wr, "weight", vscript->weight);
	jsonw_bool_field(wr, "reverse", vscript->weight_reverse);
	jsonw_int_field(wr, "rise", vscript->rise);
	jsonw_int_field(wr, "fall", vscript->fall);
	jsonw_uint_field(wr, "uid", vscript->script.uid);
	jsonw_uint_field(wr, "gid", vscript->script.gid);
	jsonw_string_field(wr, "init_state",
		vscript->init_state == SCRIPT_INIT_STATE_INIT ? "init":
		vscript->init_state == SCRIPT_INIT_STATE_FAILED ? "failed" :
		vscript->init_state == SCRIPT_INIT_STATE_INIT_RELOAD ? "reload" :
		"unknown"
	);
	jsonw_int_field(wr, "status",
		vscript->result >= vscript->rise ? 1 :
		0
	);
	jsonw_string_field(wr, "state",
		vscript->state == SCRIPT_STATE_IDLE ? "idle" :
		vscript->state == SCRIPT_STATE_RUNNING ? "running" :
		vscript->state == SCRIPT_STATE_REQUESTING_TERMINATION ? "requesting_termination" :
		vscript->state == SCRIPT_STATE_FORCING_TERMINATION ? "forcing_termination" :
		"unknown"
	);

	jsonw_end_object(wr);

	return 0;
}

static int
vrrp_json_vscripts_dump(json_writer_t *wr)
{
	vrrp_json_array_dump(wr, "track_script", &vrrp_data->vrrp_script, vrrp_json_vscript_dump);

	return 0;
}

#ifdef _WITH_TRACK_PROCESS_
static int
vrrp_json_vprocess_dump(json_writer_t *wr, list_head_t *e)
{
	vrrp_tracked_process_t *vprocess = list_entry(e, vrrp_tracked_process_t, e_list);
	char *params, *p;

	jsonw_start_object(wr);

	jsonw_string_field(wr, "process", vprocess->pname);
	if (vprocess->process_params) {
		params = MALLOC(vprocess->process_params_len);
		memcpy(params, vprocess->process_params, vprocess->process_params_len);
		p = params;
		for (p = strchr(params, '\0'); p < params + vprocess->process_params_len - 1; p = strchr(params + 1, '\0'))
			*p = ' ';
		jsonw_string_field(wr, "parameters", params);
		FREE(params);
	}
	jsonw_string_field(wr, "param_match",
		vprocess->param_match == PARAM_MATCH_NONE ? "none" :
		vprocess->param_match == PARAM_MATCH_EXACT ? "exact" :
		vprocess->param_match == PARAM_MATCH_PARTIAL ? "partial" :
		vprocess->param_match == PARAM_MATCH_INITIAL ? "initial" :
		"unknown");
	jsonw_uint_field(wr, "min_processes", vprocess->quorum);
	if (vprocess->quorum_max < UINT_MAX)
		jsonw_uint_field(wr, "max_processes", vprocess->quorum_max);
	jsonw_uint_field(wr, "current_processes", vprocess->num_cur_proc);
	jsonw_bool_field(wr, "have_quorum", vprocess->have_quorum);
	jsonw_int_field(wr, "weight", vprocess->weight_reverse ? -(int)vprocess->weight : vprocess->weight);
	jsonw_float_field(wr, "terminate_delay", (double)vprocess->terminate_delay / TIMER_HZ);
	jsonw_float_field(wr, "fork_delay", (double)vprocess->fork_delay / TIMER_HZ);
	jsonw_bool_field(wr, "fork_delay_timer_running", vprocess->fork_timer_thread);
	jsonw_bool_field(wr, "terminate_delay_timer_running", vprocess->terminate_timer_thread);
	jsonw_bool_field(wr, "full_command", vprocess->full_command);

	jsonw_end_object(wr);

	return 0;
}

static int
vrrp_json_vprocesses_dump(json_writer_t *wr)
{
	vrrp_json_array_dump(wr, "track_process", &vrrp_data->vrrp_track_processes, vrrp_json_vprocess_dump);

	return 0;
}
#endif

/*
 *	Split dump function for future purpose
 *	this offer generic integration for mapping
 *	socket fd to a FILE stream.
 */
static int
vrrp_json_dump(FILE *fp)
{
	json_writer_t *wr;
	vrrp_t *vrrp;

	wr = jsonw_new(fp);

	if (global_data->json_version == JSON_VERSION_V2) {
		jsonw_start_object(wr);
		jsonw_name(wr, "vrrp");
	}

	jsonw_start_array(wr);

	list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
		jsonw_start_object(wr);
		vrrp_json_data_dump(wr, vrrp);
		vrrp_json_stats_dump(wr, vrrp);
		jsonw_end_object(wr);
	}

	jsonw_end_array(wr);

	if (global_data->json_version == JSON_VERSION_V2) {
		if (!list_empty(&vrrp_data->vrrp_script))
			vrrp_json_vscripts_dump(wr);
#ifdef _WITH_TRACK_PROCESS_
		if (!list_empty(&vrrp_data->vrrp_track_processes))
			vrrp_json_vprocesses_dump(wr);
#endif

		jsonw_end_object(wr);
	}

	jsonw_destroy(&wr);
	return 0;
}

void
vrrp_print_json(void)
{
	FILE *fp;
	const char *filename;

	if (list_empty(&vrrp_data->vrrp))
		return;

	filename = make_tmp_filename("keepalived.json");
	fp = fopen_safe(filename, "w");
	if (fp) {
		vrrp_json_dump(fp);
		fclose(fp);
	} else
		log_message(LOG_INFO, "Can't open %s/keepalived.json (%d: %m)", tmp_dir, errno);

	FREE_CONST(filename);
}
