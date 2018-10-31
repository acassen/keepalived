/*
 * Soft:        Vrrpd is an implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Part:        Output running VRRP state information in JSON format
 *
 * Author:      Damien Clabaut, <Damien.Clabaut@corp.ovh.com>
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
 * Copyright (C) 2017 Damien Clabaut, <Damien.Clabaut@corp.ovh.com>
 * Copyright (C) 2017-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"
#include "vrrp_json.h"

#include <errno.h>
#include <stdio.h>
#include <json.h>

#include "vrrp.h"
#include "vrrp_track.h"
#include "list.h"
#include "vrrp_data.h"
#include "vrrp_iproute.h"
#include "vrrp_iprule.h"
#include "logger.h"
#include "timer.h"
#include "utils.h"

static inline double
timeval_to_double(const timeval_t *t)
{
	/* The casts are necessary to avoid conversion warnings */
	return (double)t->tv_sec + (double)t->tv_usec / TIMER_HZ_FLOAT;
}

void
vrrp_print_json(void)
{
	FILE *file;
	element e;
	struct json_object *array;

	if (LIST_ISEMPTY(vrrp_data->vrrp))
		return;

	file = fopen_safe("/tmp/keepalived.json", "w");
	if (!file) {
		log_message(LOG_INFO, "Can't open /tmp/keepalived.json (%d: %s)",
			errno, strerror(errno));
		return;
	}

	array = json_object_new_array();

	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		struct json_object *instance_json, *json_stats, *json_data,
			*vips, *evips, *track_ifp, *track_script;
#ifdef _HAVE_FIB_ROUTING_
		struct json_object *vroutes, *vrules;
#endif
		element f;

		vrrp_t *vrrp = ELEMENT_DATA(e);
		instance_json = json_object_new_object();
		json_stats = json_object_new_object();
		json_data = json_object_new_object();
		vips = json_object_new_array();
		evips = json_object_new_array();
		track_ifp = json_object_new_array();
		track_script = json_object_new_array();
#ifdef _HAVE_FIB_ROUTING_
		vroutes = json_object_new_array();
		vrules = json_object_new_array();
#endif

		// Dump data to json
		json_object_object_add(json_data, "iname",
			json_object_new_string(vrrp->iname));
		json_object_object_add(json_data, "dont_track_primary",
			json_object_new_int(vrrp->dont_track_primary));
		json_object_object_add(json_data, "skip_check_adv_addr",
			json_object_new_int(vrrp->skip_check_adv_addr));
		json_object_object_add(json_data, "strict_mode",
			json_object_new_int((int)vrrp->strict_mode));
#ifdef _HAVE_VRRP_VMAC_
		json_object_object_add(json_data, "vmac_ifname",
			json_object_new_string(vrrp->vmac_ifname));
#endif
		// Tracked interfaces are stored in a list
		if (!LIST_ISEMPTY(vrrp->track_ifp)) {
			for (f = LIST_HEAD(vrrp->track_ifp); f; ELEMENT_NEXT(f)) {
				interface_t *ifp = ELEMENT_DATA(f);
				json_object_array_add(track_ifp,
					json_object_new_string(ifp->ifname));
			}
		}
		json_object_object_add(json_data, "track_ifp", track_ifp);

		// Tracked scripts also
		if (!LIST_ISEMPTY(vrrp->track_script)) {
			for (f = LIST_HEAD(vrrp->track_script); f; ELEMENT_NEXT(f)) {
				tracked_sc_t *tsc = ELEMENT_DATA(f);
				vrrp_script_t *vscript = tsc->scr;
				json_object_array_add(track_script,
					json_object_new_string(cmd_str(&vscript->script)));
			}
		}
		json_object_object_add(json_data, "track_script", track_script);

		json_object_object_add(json_data, "ifp_ifname",
			json_object_new_string(vrrp->ifp->ifname));
		json_object_object_add(json_data, "master_priority",
			json_object_new_int(vrrp->master_priority));
		json_object_object_add(json_data, "last_transition",
			json_object_new_double(timeval_to_double(&vrrp->last_transition)));
		json_object_object_add(json_data, "garp_delay",
			json_object_new_double(vrrp->garp_delay / TIMER_HZ_FLOAT));
		json_object_object_add(json_data, "garp_refresh",
			json_object_new_int((int)vrrp->garp_refresh.tv_sec));
		json_object_object_add(json_data, "garp_rep",
			json_object_new_int((int)vrrp->garp_rep));
		json_object_object_add(json_data, "garp_refresh_rep",
			json_object_new_int((int)vrrp->garp_refresh_rep));
		json_object_object_add(json_data, "garp_lower_prio_delay",
			json_object_new_int((int)(vrrp->garp_lower_prio_delay / TIMER_HZ)));
		json_object_object_add(json_data, "garp_lower_prio_rep",
			json_object_new_int((int)vrrp->garp_lower_prio_rep));
		json_object_object_add(json_data, "lower_prio_no_advert",
			json_object_new_int((int)vrrp->lower_prio_no_advert));
		json_object_object_add(json_data, "higher_prio_send_advert",
			json_object_new_int((int)vrrp->higher_prio_send_advert));
		json_object_object_add(json_data, "vrid",
			json_object_new_int(vrrp->vrid));
		json_object_object_add(json_data, "base_priority",
			json_object_new_int(vrrp->base_priority));
		json_object_object_add(json_data, "effective_priority",
			json_object_new_int(vrrp->effective_priority));
		json_object_object_add(json_data, "vipset",
			json_object_new_boolean(vrrp->vipset));

		//Virtual IPs are stored in a list
		if (!LIST_ISEMPTY(vrrp->vip)) {
			for (f = LIST_HEAD(vrrp->vip); f; ELEMENT_NEXT(f)) {
				ip_address_t *vip = ELEMENT_DATA(f);
				char ipaddr[INET6_ADDRSTRLEN];
				inet_ntop(vrrp->family, &(vip->u.sin.sin_addr.s_addr),
					ipaddr, INET6_ADDRSTRLEN);
				json_object_array_add(vips,
					json_object_new_string(ipaddr));
			}
		}
		json_object_object_add(json_data, "vips", vips);

		//External VIPs are also stored in a list
		if (!LIST_ISEMPTY(vrrp->evip)) {
			for (f = LIST_HEAD(vrrp->evip); f; ELEMENT_NEXT(f)) {
				ip_address_t *evip = ELEMENT_DATA(f);
				char ipaddr[INET6_ADDRSTRLEN];
				inet_ntop(vrrp->family, &(evip->u.sin.sin_addr.s_addr),
					ipaddr, INET6_ADDRSTRLEN);
				json_object_array_add(evips,
					json_object_new_string(ipaddr));
			}
		}
		json_object_object_add(json_data, "evips", evips);

		json_object_object_add(json_data, "promote_secondaries",
			json_object_new_boolean(vrrp->promote_secondaries));

#ifdef _HAVE_FIB_ROUTING_
		// Dump vroutes
		if (!LIST_ISEMPTY(vrrp->vroutes)) {
			for (f = LIST_HEAD(vrrp->vroutes); f; ELEMENT_NEXT(f)) {
				ip_route_t *route = ELEMENT_DATA(f);
				char *buf = MALLOC(ROUTE_BUF_SIZE);
				format_iproute(route, buf, ROUTE_BUF_SIZE);
				json_object_array_add(vroutes,
					json_object_new_string(buf));
			}
		}
		json_object_object_add(json_data, "vroutes", vroutes);

		// Dump vrules
		if (!LIST_ISEMPTY(vrrp->vrules)) {
			for (f = LIST_HEAD(vrrp->vrules); f; ELEMENT_NEXT(f)) {
				ip_rule_t *rule = ELEMENT_DATA(f);
				char *buf = MALLOC(RULE_BUF_SIZE);
				format_iprule(rule, buf, RULE_BUF_SIZE);
				json_object_array_add(vrules,
					json_object_new_string(buf));
			}
		}
		json_object_object_add(json_data, "vrules", vrules);
#endif

		json_object_object_add(json_data, "adver_int",
			json_object_new_double(vrrp->adver_int / TIMER_HZ_FLOAT));
		json_object_object_add(json_data, "master_adver_int",
			json_object_new_double(vrrp->master_adver_int / TIMER_HZ_FLOAT));
		json_object_object_add(json_data, "accept",
			json_object_new_int((int)vrrp->accept));
		json_object_object_add(json_data, "nopreempt",
			json_object_new_boolean(vrrp->nopreempt));
		json_object_object_add(json_data, "preempt_delay",
			json_object_new_int((int)(vrrp->preempt_delay / TIMER_HZ)));
		json_object_object_add(json_data, "state",
			json_object_new_int(vrrp->state));
		json_object_object_add(json_data, "wantstate",
			json_object_new_int(vrrp->wantstate));
		json_object_object_add(json_data, "version",
			json_object_new_int(vrrp->version));
		if (vrrp->script_backup)
			json_object_object_add(json_data, "script_backup",
				json_object_new_string(cmd_str(vrrp->script_backup)));
		if (vrrp->script_master)
			json_object_object_add(json_data, "script_master",
				json_object_new_string(cmd_str(vrrp->script_master)));
		if (vrrp->script_fault)
			json_object_object_add(json_data, "script_fault",
				json_object_new_string(cmd_str(vrrp->script_fault)));
		if (vrrp->script_stop)
			json_object_object_add(json_data, "script_stop",
				json_object_new_string(cmd_str(vrrp->script_stop)));
		if (vrrp->script)
			json_object_object_add(json_data, "script",
				json_object_new_string(cmd_str(vrrp->script)));
		if (vrrp->script_master_rx_lower_pri)
			json_object_object_add(json_data, "script_master_rx_lower_pri",
				json_object_new_string(cmd_str(vrrp->script_master_rx_lower_pri)));
		json_object_object_add(json_data, "smtp_alert",
			json_object_new_boolean(vrrp->smtp_alert));
#ifdef _WITH_VRRP_AUTH_
		if (vrrp->auth_type) {
			json_object_object_add(json_data, "auth_type",
				json_object_new_int(vrrp->auth_type));

			if (vrrp->auth_type != VRRP_AUTH_AH) {
				char auth_data[sizeof(vrrp->auth_data) + 1];
				memcpy(auth_data, vrrp->auth_data, sizeof(vrrp->auth_data));
				auth_data[sizeof(vrrp->auth_data)] = '\0';
				json_object_object_add(json_data, "auth_data",
					json_object_new_string(auth_data));
			}
		}
		else
			json_object_object_add(json_data, "auth_type",
				json_object_new_int(0));
#endif

		// Dump stats to json
		json_object_object_add(json_stats, "advert_rcvd",
			json_object_new_int64((int64_t)vrrp->stats->advert_rcvd));
		json_object_object_add(json_stats, "advert_sent",
			json_object_new_int64(vrrp->stats->advert_sent));
		json_object_object_add(json_stats, "become_master",
			json_object_new_int64(vrrp->stats->become_master));
		json_object_object_add(json_stats, "release_master",
			json_object_new_int64(vrrp->stats->release_master));
		json_object_object_add(json_stats, "packet_len_err",
			json_object_new_int64((int64_t)vrrp->stats->packet_len_err));
		json_object_object_add(json_stats, "advert_interval_err",
			json_object_new_int64((int64_t)vrrp->stats->advert_interval_err));
		json_object_object_add(json_stats, "ip_ttl_err",
			json_object_new_int64((int64_t)vrrp->stats->ip_ttl_err));
		json_object_object_add(json_stats, "invalid_type_rcvd",
			json_object_new_int64((int64_t)vrrp->stats->invalid_type_rcvd));
		json_object_object_add(json_stats, "addr_list_err",
			json_object_new_int64((int64_t)vrrp->stats->addr_list_err));
		json_object_object_add(json_stats, "invalid_authtype",
			json_object_new_int64(vrrp->stats->invalid_authtype));
#ifdef _WITH_VRRP_AUTH_
		json_object_object_add(json_stats, "authtype_mismatch",
			json_object_new_int64(vrrp->stats->authtype_mismatch));
		json_object_object_add(json_stats, "auth_failure",
			json_object_new_int64(vrrp->stats->auth_failure));
#endif
		json_object_object_add(json_stats, "pri_zero_rcvd",
			json_object_new_int64((int64_t)vrrp->stats->pri_zero_rcvd));
		json_object_object_add(json_stats, "pri_zero_sent",
			json_object_new_int64((int64_t)vrrp->stats->pri_zero_sent));

		// Add both json_data and json_stats to main instance_json
		json_object_object_add(instance_json, "data", json_data);
		json_object_object_add(instance_json, "stats", json_stats);

		// Add instance_json to main array
		json_object_array_add(array, instance_json);

	}
	fprintf(file, "%s", json_object_to_json_string(array));
	fclose(file);
}
