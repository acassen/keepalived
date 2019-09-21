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
#include "list.h"
#include "vrrp_data.h"
#include "vrrp_ipaddress.h"
#include "vrrp_iproute.h"
#include "vrrp_iprule.h"
#include "logger.h"
#include "timer.h"
#include "utils.h"
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
vrrp_json_ip_dump(json_writer_t *wr, void *data)
{
	ip_address_t *ipaddr = data;
	char buf[256];

	format_ipaddress(ipaddr, buf, sizeof(buf));
	jsonw_string(wr, buf);
	return 0;
}

#ifdef _HAVE_FIB_ROUTING_
static int
vrrp_json_vroute_dump(json_writer_t *wr, void *data)
{
	ip_route_t *iproute = data;
	char buf[256];

	format_iproute(iproute, buf, sizeof(buf));
	jsonw_string(wr, buf);
	return 0;
}

static int
vrrp_json_vrule_dump(json_writer_t *wr, void *data)
{
	ip_rule_t *iprule = data;
	char buf[256];

	format_iprule(iprule, buf, sizeof(buf));
	jsonw_string(wr, buf);
	return 0;
}
#endif

static int
vrrp_json_track_ifp_dump(json_writer_t *wr, void *data)
{
	tracked_if_t *tip = data;
	interface_t *ifp = tip->ifp;

	jsonw_string(wr, ifp->ifname);
	return 0;
}

static int
vrrp_json_track_script_dump(json_writer_t *wr, void *data)
{
	tracked_sc_t *tsc = data;
	vrrp_script_t *vscript = tsc->scr;

	jsonw_string(wr, cmd_str(&vscript->script));
	return 0;
}

static int
vrrp_json_array_dump(json_writer_t *wr, const char *prop, list l,
		     int (*func) (json_writer_t *, void *))
{
	void *data;
	element e;

	if (LIST_ISEMPTY(l))
		return -1;

	jsonw_name(wr, prop);
	jsonw_start_array(wr);
	LIST_FOREACH(l, data, e) {
		(*func) (wr, data);
	}
	jsonw_end_array(wr);
	return 0;
}

static int
vrrp_json_auth_dump(json_writer_t *wr, const char *prop, vrrp_t *vrrp)
{
	char buf[256];

	if (!vrrp->auth_type)
		return -1;

	memcpy(buf, vrrp->auth_data, sizeof(vrrp->auth_data));
	buf[sizeof(vrrp->auth_data)] = 0;
	jsonw_string_field(wr, prop, buf);
	return 0;
}

static int
vrrp_json_data_dump(json_writer_t *wr, vrrp_t *vrrp)
{
	/* data object */
	jsonw_name(wr, "data");
	jsonw_start_object(wr);

	/* Global instance related */
	jsonw_string_field(wr, "iname", vrrp->iname);
	jsonw_uint_field(wr, "dont_track_primary", vrrp->dont_track_primary);
	jsonw_uint_field(wr, "skip_check_adv_addr", vrrp->skip_check_adv_addr);
	jsonw_uint_field(wr, "strict_mode", vrrp->strict_mode);
#ifdef _HAVE_VRRP_VMAC_
	jsonw_string_field(wr, "vmac_ifname", vrrp->vmac_ifname);
#endif
	jsonw_string_field(wr, "ifp_ifname", vrrp->ifp->ifname);
	jsonw_uint_field(wr, "master_priority", vrrp->master_priority);
	jsonw_float_field_fmt(wr, "last_transition", "%f", timeval_to_double(&vrrp->last_transition));
	jsonw_float_field(wr, "garp_delay", vrrp->garp_delay / TIMER_HZ_FLOAT);
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
	jsonw_bool_field(wr, "promote_secondaries", vrrp->promote_secondaries);
	jsonw_float_field(wr, "adver_int", vrrp->adver_int / TIMER_HZ_FLOAT);
	jsonw_float_field(wr, "master_adver_int", vrrp->master_adver_int / TIMER_HZ_FLOAT);
#ifdef _WITH_FIREWALL_
	jsonw_uint_field(wr, "accept", vrrp->accept);
#endif
	jsonw_bool_field(wr, "nopreempt", vrrp->nopreempt);
	jsonw_uint_field(wr, "preempt_delay", vrrp->preempt_delay / TIMER_HZ);
	jsonw_uint_field(wr, "state", vrrp->state);
	jsonw_uint_field(wr, "wantstate", vrrp->wantstate);
	jsonw_uint_field(wr, "version", vrrp->version);
	jsonw_bool_field(wr, "smtp_alert", vrrp->smtp_alert);

	/* Script related */
	vrrp_json_script_dump(wr, "script_backup", vrrp->script_backup);
	vrrp_json_script_dump(wr, "script_master", vrrp->script_master);
	vrrp_json_script_dump(wr, "script_fault", vrrp->script_fault);
	vrrp_json_script_dump(wr, "script_stop", vrrp->script_stop);
	vrrp_json_script_dump(wr, "script", vrrp->script);
	vrrp_json_script_dump(wr, "script_master_rx_lower_pri"
				, vrrp->script_master_rx_lower_pri);

	/* Virtual related */
	vrrp_json_array_dump(wr, "vips", vrrp->vip, vrrp_json_ip_dump);
	vrrp_json_array_dump(wr, "evips", vrrp->evip, vrrp_json_ip_dump);
#ifdef _HAVE_FIB_ROUTING_
	vrrp_json_array_dump(wr, "vroutes", vrrp->vroutes, vrrp_json_vroute_dump);
	vrrp_json_array_dump(wr, "vrules", vrrp->vrules, vrrp_json_vrule_dump);
#endif

	/* Tracking related */
	vrrp_json_array_dump(wr, "track_ifp", vrrp->track_ifp, vrrp_json_track_ifp_dump);
	vrrp_json_array_dump(wr, "track_script", vrrp->track_script, vrrp_json_track_script_dump);

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
	element e;

	wr = jsonw_new(fp);
	jsonw_start_array(wr);

	LIST_FOREACH(vrrp_data->vrrp, vrrp, e) {
		jsonw_start_object(wr);
		vrrp_json_data_dump(wr, vrrp);
		vrrp_json_stats_dump(wr, vrrp);
		jsonw_end_object(wr);
	}

	jsonw_end_array(wr);
	jsonw_destroy(&wr);
	return 0;
}

void
vrrp_print_json(void)
{
	FILE *fp;

	if (LIST_ISEMPTY(vrrp_data->vrrp))
		return;

	fp = fopen_safe("/tmp/keepalived.json", "w");
	if (!fp) {
		log_message(LOG_INFO, "Can't open /tmp/keepalived.json (%d: %m)", errno);
		return;
	}

	vrrp_json_dump(fp);
	fclose(fp);
}
