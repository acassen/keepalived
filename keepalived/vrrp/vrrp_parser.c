/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Configuration file parser/reader. Place into the dynamic
 *              data structure representation the conf file representing
 *              the loadbalanced server pool.
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
 *
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <net/if_arp.h>
#include <sys/types.h>
#include <sys/stat.h>
//#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <net/if.h>

#include "vrrp_parser.h"
#include "logger.h"
#include "parser.h"
#include "bitops.h"
#include "utils.h"

#include "main.h"
#include "global_data.h"
#include "global_parser.h"

#include "vrrp_data.h"
#include "vrrp_ipaddress.h"
#include "vrrp_sync.h"
#include "vrrp_track.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_vmac.h"
#endif
#include "vrrp_static_track.h"

#ifdef _WITH_LVS_
#include "check_parser.h"
#endif
#ifdef _WITH_BFD_
#include "bfd_parser.h"
#endif

/* Used for initialising track files */
static enum {
	TRACK_FILE_NO_INIT,
	TRACK_FILE_CREATE,
	TRACK_FILE_INIT,
} track_file_init;
static int track_file_init_value;

static bool script_user_set;
static bool remove_script;

/* track groups for static items */
static void
static_track_group_handler(vector_t *strvec)
{
	element e;
	static_track_group_t *tg;
	char* gname;

	if (!strvec)
		return;

	if (vector_count(strvec) != 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "track_group must have a name - skipping");
		skip_block(true);
		return;
	}

	gname = strvec_slot(strvec, 1);

	/* check group doesn't already exist */
	LIST_FOREACH(vrrp_data->static_track_groups, tg, e) {
		if (!strcmp(gname,tg->gname)) {
			report_config_error(CONFIG_GENERAL_ERROR, "track_group %s already defined", gname);
			skip_block(true);
			return;
		}
	}

	alloc_static_track_group(gname);
}

static void
static_track_group_group_handler(vector_t *strvec)
{
	static_track_group_t *tgroup = LIST_TAIL_DATA(vrrp_data->static_track_groups);

	if (tgroup->iname) {
		report_config_error(CONFIG_GENERAL_ERROR, "Group list already specified for sync group %s", tgroup->gname);
		skip_block(true);
		return;
	}

	tgroup->iname = read_value_block(strvec);

	if (!tgroup->iname)
		report_config_error(CONFIG_GENERAL_ERROR, "Warning - track group %s has empty group block", tgroup->gname);
}

/* Static addresses handler */
static void
static_addresses_handler(vector_t *strvec)
{
	global_data->have_vrrp_config = true;

	if (!strvec)
		return;

	alloc_value_block(alloc_saddress, vector_slot(strvec, 0));
}

#ifdef _HAVE_FIB_ROUTING_
/* Static routes handler */
static void
static_routes_handler(vector_t *strvec)
{
	global_data->have_vrrp_config = true;

	if (!strvec)
		return;

	alloc_value_block(alloc_sroute, vector_slot(strvec, 0));
}

/* Static rules handler */
static void
static_rules_handler(vector_t *strvec)
{
	global_data->have_vrrp_config = true;

	if (!strvec)
		return;

	alloc_value_block(alloc_srule, vector_slot(strvec, 0));
}
#endif

/* VRRP handlers */
static void
vrrp_sync_group_handler(vector_t *strvec)
{
	list l;
	element e;
	vrrp_sgroup_t *sg;
	char* gname;

	if (!strvec)
		return;

	if (vector_count(strvec) != 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp_sync_group must have a name - skipping");
		skip_block(true);
		return;
	}

	gname = strvec_slot(strvec, 1);

	/* check group doesn't already exist */
	if (!LIST_ISEMPTY(vrrp_data->vrrp_sync_group)) {
		l = vrrp_data->vrrp_sync_group;
		for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
			sg = ELEMENT_DATA(e);
			if (!strcmp(gname,sg->gname)) {
				report_config_error(CONFIG_GENERAL_ERROR, "vrrp sync group %s already defined", gname);
				skip_block(true);
				return;
			}
		}
	}

	alloc_vrrp_sync_group(gname);
}

static void
vrrp_group_handler(vector_t *strvec)
{
	vrrp_sgroup_t *vgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);

	if (vgroup->iname) {
		report_config_error(CONFIG_GENERAL_ERROR, "Group list already specified for sync group %s", vgroup->gname);
		skip_block(true);
		return;
	}

	vgroup->iname = read_value_block(strvec);

	if (!vgroup->iname)
		report_config_error(CONFIG_GENERAL_ERROR, "Warning - sync group %s has empty group block", vgroup->gname);
}

static void
vrrp_group_track_if_handler(vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_group_track_if, vector_slot(strvec, 0));
}

static void
vrrp_group_track_scr_handler(vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_group_track_script, vector_slot(strvec, 0));
}

static void
vrrp_group_track_file_handler(vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_group_track_file, vector_slot(strvec, 0));
}

#if defined _WITH_BFD_
static void
vrrp_group_track_bfd_handler(vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_group_track_bfd, vector_slot(strvec, 0));
}
#endif

static inline notify_script_t*
set_vrrp_notify_script(__attribute__((unused)) vector_t *strvec, int extra_params)
{
	return notify_script_init(extra_params, "notify");
}

static void
vrrp_gnotify_backup_handler(vector_t *strvec)
{
	vrrp_sgroup_t *vgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);
	if (vgroup->script_backup) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp group %s: notify_backup script already specified - ignoring %s", vgroup->gname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vgroup->script_backup = set_vrrp_notify_script(strvec, 0);
	vgroup->notify_exec = true;
}
static void
vrrp_gnotify_master_handler(vector_t *strvec)
{
	vrrp_sgroup_t *vgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);
	if (vgroup->script_master) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp group %s: notify_master script already specified - ignoring %s", vgroup->gname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vgroup->script_master = set_vrrp_notify_script(strvec, 0);
	vgroup->notify_exec = true;
}
static void
vrrp_gnotify_fault_handler(vector_t *strvec)
{
	vrrp_sgroup_t *vgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);
	if (vgroup->script_fault) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp group %s: notify_fault script already specified - ignoring %s", vgroup->gname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vgroup->script_fault = set_vrrp_notify_script(strvec, 0);
	vgroup->notify_exec = true;
}
static void
vrrp_gnotify_stop_handler(vector_t *strvec)
{
	vrrp_sgroup_t *vgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);
	if (vgroup->script_stop) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp group %s: notify_stop script already specified - ignoring %s", vgroup->gname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vgroup->script_stop = set_vrrp_notify_script(strvec, 0);
	vgroup->notify_exec = true;
}
static void
vrrp_gnotify_handler(vector_t *strvec)
{
	vrrp_sgroup_t *vgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);
	if (vgroup->script) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp group %s: notify script already specified - ignoring %s", vgroup->gname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vgroup->script = set_vrrp_notify_script(strvec, 4);
	vgroup->notify_exec = true;
}
static void
vrrp_gsmtp_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_sgroup_t *vgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res == -1) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid vrrp_group smtp_alert parameter %s", FMT_STR_VSLOT(strvec, 1));
			return;
		}
	}
	vgroup->smtp_alert = res;
}
static void
vrrp_gglobal_tracking_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_sgroup_t *vgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);

	report_config_error(CONFIG_GENERAL_ERROR, "(%s) global_tracking is deprecated. Use track_interface/script/file on the sync group", vgroup->gname);
	vgroup->sgroup_tracking_weight = true;
}
static void
vrrp_sg_tracking_weight_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_sgroup_t *vgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);
	vgroup->sgroup_tracking_weight = true;
}
static void
vrrp_handler(vector_t *strvec)
{
	list l;
	element e;
	vrrp_t *vrrp;
	char *iname;

	global_data->have_vrrp_config = true;

	if (!strvec)
		return;

	if (vector_count(strvec) != 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp_instance must have a name");
		skip_block(true);
		return;
	}

	iname = strvec_slot(strvec,1);

	/* Make sure the vrrp instance doesn't already exist */
	if (!LIST_ISEMPTY(vrrp_data->vrrp)) {
		l = vrrp_data->vrrp;
		for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
			vrrp = ELEMENT_DATA(e);
			if (!strcmp(iname,vrrp->iname)) {
				report_config_error(CONFIG_GENERAL_ERROR, "vrrp instance %s already defined", iname );
				skip_block(true);
				return;
			}
		}
	}

	alloc_vrrp(iname);
}
#ifdef _HAVE_VRRP_VMAC_
static void
vrrp_vmac_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	interface_t *ifp;

	__set_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags);

	if (vector_size(strvec) >= 2) {
		if (strlen(strvec_slot(strvec, 1)) >= IFNAMSIZ) {
			report_config_error(CONFIG_GENERAL_ERROR, "VMAC interface name '%s' too long - ignoring", FMT_STR_VSLOT(strvec, 1));
			return;
		}

		strcpy(vrrp->vmac_ifname, strvec_slot(strvec, 1));

		/* Check if the interface exists and is a macvlan we can use */
		if ((ifp = if_get_by_ifname(vrrp->vmac_ifname, IF_NO_CREATE)) &&
		    ifp->vmac_type != MACVLAN_MODE_PRIVATE) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) interface %s already exists and is not a private macvlan; ignoring vmac if_name", vrrp->iname, vrrp->vmac_ifname);
			vrrp->vmac_ifname[0] = '\0';
		}
	}
}
static void
vrrp_vmac_xmit_base_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	__set_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags);
}
#endif
static void
vrrp_unicast_peer_handler(vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_unicast_peer, vector_slot(strvec, 0));
}
#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
static void
vrrp_unicast_chksum_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (vector_size(strvec) >= 2) {
		if (!strcmp(strvec_slot(strvec, 1), "never"))
			vrrp->unicast_chksum_compat = CHKSUM_COMPATIBILITY_NEVER;
		else
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) Unknown old_unicast_chksum mode %s - ignoring", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
	}
	else
		vrrp->unicast_chksum_compat = CHKSUM_COMPATIBILITY_CONFIG;
}
#endif
static void
vrrp_native_ipv6_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (vrrp->family == AF_INET) {
		report_config_error(CONFIG_GENERAL_ERROR,"(%s) Cannot specify native_ipv6 with IPv4 addresses", vrrp->iname);
		return;
	}

	vrrp->family = AF_INET6;
	vrrp->version = VRRP_VERSION_3;
}
static void
vrrp_state_handler(vector_t *strvec)
{
	char *str = strvec_slot(strvec, 1);
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!strcmp(str, "MASTER"))
		vrrp->wantstate = VRRP_STATE_MAST;
	else if (!strcmp(str, "BACKUP"))
	{
		if (vrrp->wantstate == VRRP_STATE_MAST)
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) state previously set as MASTER - ignoring BACKUP", vrrp->iname);
		else
			vrrp->wantstate = VRRP_STATE_BACK;
	}
	else {
		report_config_error(CONFIG_GENERAL_ERROR,"(%s) unknown state '%s', defaulting to BACKUP", vrrp->iname, str);
		vrrp->wantstate = VRRP_STATE_BACK;
	}
}
static void
vrrp_int_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	char *name = strvec_slot(strvec, 1);

	if (strlen(name) >= IFNAMSIZ) {
		report_config_error(CONFIG_GENERAL_ERROR, "Interface name '%s' too long - ignoring", name);
		return;
	}

	vrrp->ifp = if_get_by_ifname(name, IF_CREATE_IF_DYNAMIC);
	if (!vrrp->ifp)
		report_config_error(CONFIG_GENERAL_ERROR, "WARNING - interface %s for vrrp_instance %s doesn't exist", name, vrrp->iname);
	else if (vrrp->ifp->hw_type == ARPHRD_LOOPBACK) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) cannot use a loopback interface (%s) for vrrp - ignoring", vrrp->iname, vrrp->ifp->ifname);
		vrrp->ifp = NULL;
	}

#ifdef _HAVE_VRRP_VMAC_
	vrrp->configured_ifp = vrrp->ifp;
#endif
}
static void
vrrp_linkbeat_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	vrrp->linkbeat_use_polling = true;
}
static void
vrrp_track_if_handler(vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_track_if, vector_slot(strvec, 0));
}
static void
vrrp_track_scr_handler(vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_track_script, vector_slot(strvec, 0));
}
static void
vrrp_track_file_handler(vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_track_file, vector_slot(strvec, 0));
}
static void
vrrp_dont_track_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	vrrp->dont_track_primary = true;
}
#ifdef _WITH_BFD_
static void
vrrp_track_bfd_handler(vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_track_bfd, vector_slot(strvec, 0));
}
#endif
static void
vrrp_srcip_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	struct sockaddr_storage *saddr = &vrrp->saddr;

	if (inet_stosockaddr(strvec_slot(strvec, 1), NULL, saddr)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: VRRP instance[%s] malformed"
				     " src address[%s]. Skipping..."
				   , vrrp->iname, FMT_STR_VSLOT(strvec, 1));
		return;
	}

	vrrp->saddr_from_config = true;

	if (vrrp->family == AF_UNSPEC)
		vrrp->family = saddr->ss_family;
	else if (saddr->ss_family != vrrp->family) {
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: VRRP instance[%s] and src address"
				     "[%s] MUST be of the same family !!! Skipping..."
				   , vrrp->iname, FMT_STR_VSLOT(strvec, 1));
		saddr->ss_family = AF_UNSPEC;
		vrrp->saddr_from_config = false;
	}
}
static void
vrrp_track_srcip_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	vrrp->track_saddr = true;
}
static void
vrrp_vrid_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	unsigned vrid;

	if (!read_unsigned_strvec(strvec, 1, &vrid, 1, 255, false)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): VRID '%s' not valid - must be between 1 & 255", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
		return;
	}

	vrrp->vrid = (uint8_t)vrid;
}
static void
vrrp_prio_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	unsigned base_priority;

	if (!read_unsigned_strvec(strvec, 1, &base_priority, 1, VRRP_PRIO_OWNER, false)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) Priority not valid! must be between 1 & %d. Using default %d", vrrp->iname, VRRP_PRIO_OWNER, VRRP_PRIO_DFL);
		vrrp->base_priority = VRRP_PRIO_DFL;
	}
	else
		vrrp->base_priority = (uint8_t)base_priority;
}
static void
vrrp_adv_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	double adver_int;
	bool res;

	res = read_double_strvec(strvec, 1, &adver_int, 0.01, 255.0, true);

	/* Simple check - just positive */
	if (!res || adver_int <= 0)
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) Advert interval (%s) not valid! Must be > 0 - ignoring", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
	else
		vrrp->adver_int = (unsigned)(adver_int * TIMER_HZ);
}
static void
vrrp_debug_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	unsigned debug;

	if (!read_unsigned_strvec(strvec, 1, &debug, 0, 4, true))
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) Debug value '%s' not valid; must be between 0-4", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
	else
		vrrp->debug = debug;
}
static void
vrrp_skip_check_adv_addr_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	int res;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res >= 0)
			vrrp->skip_check_adv_addr = (bool)res;
		else
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) invalid skip_check_adv_addr %s specified", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
	} else {
		/* Defaults to true */
		vrrp->skip_check_adv_addr = true;
	}
}
static void
vrrp_strict_mode_handler(vector_t *strvec)
{
	int res;

	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res >= 0)
			vrrp->strict_mode = (bool)res;
		else
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) invalid strict_mode %s specified", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
	} else {
		/* Defaults to true */
		vrrp->strict_mode = true;
	}
}
static void
vrrp_nopreempt_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	vrrp->nopreempt = 1;
}
static void	/* backwards compatibility */
vrrp_preempt_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	vrrp->nopreempt = 0;
}
static void
vrrp_preempt_delay_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	double preempt_delay;

	if (!read_double_strvec(strvec, 1, &preempt_delay, 0, TIMER_MAX_SEC, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) Preempt_delay not valid! must be between 0-%d", vrrp->iname, TIMER_MAX_SEC);
		vrrp->preempt_delay = 0;
	}
	else
		vrrp->preempt_delay = (unsigned long)(preempt_delay * TIMER_HZ);
}
static void
vrrp_notify_backup_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	if (vrrp->script_backup) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) notify_backup script already specified - ignoring %s", vrrp->iname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vrrp->script_backup = set_vrrp_notify_script(strvec, 0);
	vrrp->notify_exec = true;
}
static void
vrrp_notify_master_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	if (vrrp->script_master) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) notify_master script already specified - ignoring %s", vrrp->iname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vrrp->script_master = set_vrrp_notify_script(strvec, 0);
	vrrp->notify_exec = true;
}
static void
vrrp_notify_fault_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	if (vrrp->script_fault) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) notify_fault script already specified - ignoring %s", vrrp->iname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vrrp->script_fault = set_vrrp_notify_script(strvec, 0);
	vrrp->notify_exec = true;
}
static void
vrrp_notify_stop_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	if (vrrp->script_stop) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) notify_stop script already specified - ignoring %s", vrrp->iname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vrrp->script_stop = set_vrrp_notify_script(strvec, 0);
	vrrp->notify_exec = true;
}
static void
vrrp_notify_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	if (vrrp->script) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) notify script already specified - ignoring %s", vrrp->iname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vrrp->script = set_vrrp_notify_script(strvec, 4);
	vrrp->notify_exec = true;
}
static void
vrrp_notify_master_rx_lower_pri(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	if (vrrp->script_master_rx_lower_pri) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) notify_master_rx_lower_pri script already specified - ignoring %s", vrrp->iname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vrrp->script_master_rx_lower_pri = set_vrrp_notify_script(strvec, 0);
	vrrp->notify_exec = true;
}
static void
vrrp_smtp_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res == -1) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid vrrp_instance smtp_alert parameter %s", FMT_STR_VSLOT(strvec, 1));
			return;
		}
	}
	vrrp->smtp_alert = res;
}
#ifdef _WITH_LVS_
static void
vrrp_lvs_syncd_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	report_config_error(CONFIG_GENERAL_ERROR, "(%s) Specifying lvs_sync_daemon_interface against a vrrp is deprecated.", vrrp->iname);  /* Deprecated after v1.2.19 */
	report_config_error(CONFIG_GENERAL_ERROR, "      %*sPlease use global lvs_sync_daemon", (int)strlen(vrrp->iname) - 2, "");

	if (global_data->lvs_syncd.ifname) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) lvs_sync_daemon_interface has already been specified as %s - ignoring", vrrp->iname, global_data->lvs_syncd.ifname);
		return;
	}

	global_data->lvs_syncd.ifname = set_value(strvec);
	global_data->lvs_syncd.vrrp = vrrp;
}
#endif
static void
vrrp_garp_delay_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	unsigned delay;

	if (!read_unsigned_strvec(strvec, 1, &delay, 0, UINT_MAX / TIMER_HZ, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): garp_master_delay '%s' invalid - ignoring", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
		return;
	}

	vrrp->garp_delay = delay * TIMER_HZ;
}
static void
vrrp_garp_refresh_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	unsigned refresh;

	if (!read_unsigned_strvec(strvec, 1, &refresh, 0, UINT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): Invalid garp_master_refresh '%s' - ignoring", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
		vrrp->garp_refresh.tv_sec = 0;
	}
	else
		vrrp->garp_refresh.tv_sec = refresh;
	vrrp->garp_refresh.tv_usec = 0;
}
static void
vrrp_garp_rep_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	unsigned repeats;

	/* The min value should be 1, but allow 0 to maintain backward compatibility
	 * with pre v2.0.7 */
	if (!read_unsigned_strvec(strvec, 1, &repeats, 0, UINT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): garp_master_repeat '%s' invalid - ignoring", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
		return;
	}

	if (repeats == 0) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): garp_master_repeat must be greater than 0, setting to 1", vrrp->iname);
		repeats = 1;
	}

	vrrp->garp_rep = repeats;
}
static void
vrrp_garp_refresh_rep_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	unsigned repeats;

	/* The min value should be 1, but allow 0 to maintain backward compatibility
	 * with pre v2.0.7 */
	if (!read_unsigned_strvec(strvec, 1, &repeats, 0, UINT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): garp_master_refresh_repeat '%s' invalid - ignoring", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
		return;
	}

	if (repeats == 0) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): garp_master_refresh_repeat must be greater than 0, setting to 1", vrrp->iname);
		repeats = 1;
	}

	vrrp->garp_refresh_rep = repeats;
}

static void
vrrp_garp_lower_prio_delay_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	unsigned delay;

	if (!read_unsigned_strvec(strvec, 1, &delay, 0, UINT_MAX / TIMER_HZ, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): garp_lower_prio_delay '%s' invalid - ignoring", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
		return;
	}

	vrrp->garp_lower_prio_delay = delay * TIMER_HZ;
}
static void
vrrp_garp_lower_prio_rep_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	unsigned garp_lower_prio_rep;

	if (!read_unsigned_strvec(strvec, 1, &garp_lower_prio_rep, 0, INT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): Invalid garp_lower_prio_repeat '%s'", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
		return;
	}

	vrrp->garp_lower_prio_rep = garp_lower_prio_rep;
}
static void
vrrp_lower_prio_no_advert_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	int res;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res >= 0)
			vrrp->lower_prio_no_advert = (unsigned)res;
		else
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) invalid lower_prio_no_advert %s specified", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
	} else {
		/* Defaults to true */
		vrrp->lower_prio_no_advert = true;
	}
}

static void
vrrp_higher_prio_send_advert_handler(vector_t *strvec)
{
	int res;
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res >= 0)
			vrrp->higher_prio_send_advert = (unsigned)res;
		else
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) invalid higher_prio_send_advert %s specified", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
	} else {
		/* Defaults to true */
		vrrp->higher_prio_send_advert = true;
	}
}


static void
kernel_rx_buf_size_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	unsigned rx_buf_size;

	if (vector_size(strvec) == 2 &&
	    read_unsigned_strvec(strvec, 1, &rx_buf_size, 0, UINT_MAX, false)) {
		vrrp->kernel_rx_buf_size = rx_buf_size;
		return;
	}

	report_config_error(CONFIG_GENERAL_ERROR, "(%s) invalid kernel_rx_buf_size specified", vrrp->iname);
}

#if defined _WITH_VRRP_AUTH_
static void
vrrp_auth_type_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	char *str = strvec_slot(strvec, 1);

	if (!strcmp(str, "AH"))
		vrrp->auth_type = VRRP_AUTH_AH;
	else if (!strcmp(str, "PASS"))
		vrrp->auth_type = VRRP_AUTH_PASS;
	else
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown authentication type '%s'", vrrp->iname, str);
}
static void
vrrp_auth_pass_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	char *str = strvec_slot(strvec, 1);
	size_t max_size = sizeof (vrrp->auth_data);
	size_t str_len = strlen(str);

	if (str_len > max_size) {
		str_len = max_size;
		report_config_error(CONFIG_GENERAL_ERROR,
			    "Truncating auth_pass to %zu characters", max_size);
	}

	memset(vrrp->auth_data, 0, max_size);
	memcpy(vrrp->auth_data, str, str_len);
}
#endif
static void
vrrp_vip_handler(vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_vip, vector_slot(strvec, 0));
}
static void
vrrp_evip_handler(vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_evip, vector_slot(strvec, 0));
}
static void
vrrp_promote_secondaries_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	vrrp->promote_secondaries = true;
}
#ifdef _HAVE_FIB_ROUTING_
static void
vrrp_vroutes_handler(vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_vroute, vector_slot(strvec, 0));
}
static void
vrrp_vrules_handler(vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_vrule, vector_slot(strvec, 0));
}
#endif
static void
vrrp_script_handler(vector_t *strvec)
{
	if (!strvec)
		return;

	alloc_vrrp_script(strvec_slot(strvec, 1));
	script_user_set = false;
	remove_script = false;
}
static void
vrrp_vscript_script_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);
	vector_t *strvec_qe;

	/* We need to allow quoted and escaped strings for the script and parameters */
	strvec_qe = alloc_strvec_quoted_escaped(NULL);

	set_script_params_array(strvec_qe, &vscript->script, 0);
	free_strvec(strvec_qe);
}
static void
vrrp_vscript_interval_handler(vector_t *strvec)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);
	unsigned interval;

	/* The min value should be 1, but allow 0 to maintain backward compatibility
	 * with pre v2.0.7 */
	if (!read_unsigned_strvec(strvec, 1, &interval, 0, UINT_MAX / TIMER_HZ, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): vrrp script interval '%s' must be between 1 and %u - ignoring", vscript->sname, FMT_STR_VSLOT(strvec, 1), UINT_MAX / TIMER_HZ);
		return;
	}

	if (interval == 0) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): vrrp script interval must be greater than 0, setting to 1", vscript->sname);
		interval = 1;
	}

	vscript->interval = interval * TIMER_HZ;
}
static void
vrrp_vscript_timeout_handler(vector_t *strvec)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);
	unsigned timeout;

	/* The min value should be 1, but allow 0 to maintain backward compatibility
	 * with pre v2.0.7 */
	if (!read_unsigned_strvec(strvec, 1, &timeout, 0, UINT_MAX / TIMER_HZ, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): vrrp script timeout '%s' invalid - ignoring", vscript->sname, FMT_STR_VSLOT(strvec, 1));
		return;
	}

	if (timeout == 0) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): vrrp script timeout must be greater than 0, setting to 1", vscript->sname);
		timeout = 1;
	}

	vscript->timeout = timeout * TIMER_HZ;
}
static void
vrrp_vscript_weight_handler(vector_t *strvec)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);
	int weight;

	if (!read_int_strvec(strvec, 1, &weight, -253, 253, true))
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp_script %s weight %s must be in [-253, 253]", vscript->sname, FMT_STR_VSLOT(strvec, 1));
	vscript->weight = weight;
}
static void
vrrp_vscript_rise_handler(vector_t *strvec)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);
	unsigned rise;

	if (!read_unsigned_strvec(strvec, 1, &rise, 1, INT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): vrrp script rise value '%s' invalid, defaulting to 1", vscript->sname, FMT_STR_VSLOT(strvec, 1));
		vscript->rise = 1;
	}
	else
		vscript->rise = rise;
}
static void
vrrp_vscript_fall_handler(vector_t *strvec)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);
	unsigned fall;

	if (!read_unsigned_strvec(strvec, 1, &fall, 1, INT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): vrrp script fall value '%s' invalid, defaulting to 1", vscript->sname, FMT_STR_VSLOT(strvec, 1));
		vscript->fall = 1;
	}
	else
		vscript->fall = fall;
}
static void
vrrp_vscript_user_handler(vector_t *strvec)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);

	if (set_script_uid_gid(strvec, 1, &vscript->script.uid, &vscript->script.gid)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Unable to set uid/gid for script %s", cmd_str(&vscript->script));
		remove_script = true;
	}
	else {
		remove_script = false;
		script_user_set = true;
	}
}
static void
vrrp_vscript_end_handler(void)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);

	if (!vscript->script.args || !vscript->script.args[0]) {
		report_config_error(CONFIG_GENERAL_ERROR, "No script set for vrrp_script %s - removing", vscript->sname);
		remove_script = true;
	}
	else if (!remove_script) {
		if (script_user_set)
			return;

		if (set_default_script_user(NULL, NULL)) {
			report_config_error(CONFIG_GENERAL_ERROR, "Unable to set default user for vrrp script %s - removing", vscript->sname);
			remove_script = true;
		}
	}

	if (remove_script) {
		free_list_element(vrrp_data->vrrp_script, vrrp_data->vrrp_script->tail);
		return;
	}

	vscript->script.uid = default_script_uid;
	vscript->script.gid = default_script_gid;
}
static void
vrrp_tfile_handler(vector_t *strvec)
{
	if (!strvec)
		return;

	alloc_vrrp_file(strvec_slot(strvec, 1));

	track_file_init = TRACK_FILE_NO_INIT;
}
static void
vrrp_tfile_file_handler(vector_t *strvec)
{
	vrrp_tracked_file_t *tfile = LIST_TAIL_DATA(vrrp_data->vrrp_track_files);
	if (tfile->file_path) {
		report_config_error(CONFIG_GENERAL_ERROR, "File already set for track file %s - ignoring %s", tfile->fname, FMT_STR_VSLOT(strvec, 1));
		return;
	}
	tfile->file_path = set_value(strvec);
}
static void
vrrp_tfile_weight_handler(vector_t *strvec)
{
	int weight;
	vrrp_tracked_file_t *tfile = LIST_TAIL_DATA(vrrp_data->vrrp_track_files);

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "No weight specified for track file %s - ignoring", tfile->fname);
		return;
	}
	if (tfile->weight != 1) {
		report_config_error(CONFIG_GENERAL_ERROR, "Weight already set for track file %s - ignoring %s", tfile->fname, FMT_STR_VSLOT(strvec, 1));
		return;
	}

	if (!read_int_strvec(strvec, 1, &weight, -254, 254, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Weight (%s) for vrrp_track_file %s must be between "
				 "[-254..254] inclusive. Ignoring...", FMT_STR_VSLOT(strvec, 1), tfile->fname);
		weight = 1;
	}

	tfile->weight = weight;
}
static void
vrrp_tfile_init_handler(vector_t *strvec)
{
	unsigned i;
	char *word;
	vrrp_tracked_file_t *tfile = LIST_TAIL_DATA(vrrp_data->vrrp_track_files);
	int value;

	track_file_init = TRACK_FILE_CREATE;
	track_file_init_value = 0;

	for (i = 1; i < vector_size(strvec); i++) {
		word = strvec_slot(strvec, i);
		word += strspn(word, WHITE_SPACE);
		if (isdigit(word[0]) || word[0] == '-') {
			if (!read_int_strvec(strvec, i, &value, INT_MIN, INT_MAX, false)) {
				/* It is not a valid integer */
				report_config_error(CONFIG_GENERAL_ERROR, "Track file %s init value %s is invalid", tfile->fname, word);
				value = 0;
			}
			else if (value < -254 || value > 254)
				report_config_error(CONFIG_GENERAL_ERROR, "Track file %s init value %d is outside sensible range [%d, %d]", tfile->fname, value, -254, 254);
			track_file_init_value = value;
		}
		else if (!strcmp(word, "overwrite"))
			track_file_init = TRACK_FILE_INIT;
		else
			report_config_error(CONFIG_GENERAL_ERROR, "Unknown track file init option %s", word);
	}
}
static void
vrrp_tfile_end_handler(void)
{
	vrrp_tracked_file_t *tfile = LIST_TAIL_DATA(vrrp_data->vrrp_track_files);
	struct stat statb;
	FILE *tf;
	int ret;

	if (!tfile->file_path) {
		report_config_error(CONFIG_GENERAL_ERROR, "No file set for track_file %s - removing", tfile->fname);
		free_list_element(vrrp_data->vrrp_track_files, vrrp_data->vrrp_track_files->tail);
		return;
	}

	if (track_file_init == TRACK_FILE_NO_INIT)
		return;

	ret = stat(tfile->file_path, &statb);
	if (!ret) {
		if (track_file_init == TRACK_FILE_CREATE) {
			/* The file exists */
			return;
		}
		if ((statb.st_mode & S_IFMT) != S_IFREG) {
			/* It is not a regular file */
			report_config_error(CONFIG_GENERAL_ERROR, "Cannot initialise track file %s - it is not a regular file", tfile->fname);
			return;
		}

		/* Don't overwrite a file on reload */
		if (reload)
			return;
	}

	if (!__test_bit(CONFIG_TEST_BIT, &debug)) {
		/* Write the value to the file */
		if ((tf = fopen(tfile->file_path, "w"))) {
			fprintf(tf, "%d\n", track_file_init_value);
			fclose(tf);
		}
		else
			report_config_error(CONFIG_GENERAL_ERROR, "Unable to initialise track file %s", tfile->fname);
	}
}
static void
vrrp_vscript_init_fail_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);
	vscript->init_state = SCRIPT_INIT_STATE_FAILED;
}
static void
vrrp_version_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	int version;

	if (!read_int_strvec(strvec, 1, &version, 2, 3, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): Version must be either 2 or 3", vrrp->iname);
		return;
	}

	if ((vrrp->version && vrrp->version != version) ||
	    (version == VRRP_VERSION_2 && vrrp->family == AF_INET6)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) vrrp_version %d conflicts with configured or deduced version %d; ignoring.", vrrp->iname, version, vrrp->version);
		return;
	}

	vrrp->version = version;
}

static void
vrrp_accept_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	vrrp->accept = true;
}

static void
vrrp_no_accept_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	vrrp->accept = false;
}

static void
garp_group_handler(vector_t *strvec)
{
	if (!strvec)
		return;

	alloc_garp_delay();
}
static void
garp_group_garp_interval_handler(vector_t *strvec)
{
	garp_delay_t *delay = LIST_TAIL_DATA(garp_delay);
	double val;

	if (!read_double_strvec(strvec, 1, &val, 0, INT_MAX / 1000000, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "garp_group garp_interval '%s' invalid", FMT_STR_VSLOT(strvec, 1));
		return;
	}

	delay->garp_interval.tv_sec = (time_t)val;
	delay->garp_interval.tv_usec = (suseconds_t)((val - delay->garp_interval.tv_sec) * 1000000);
	delay->have_garp_interval = true;

	if (delay->garp_interval.tv_sec >= 1)
		log_message(LOG_INFO, "The garp_interval is very large - %s seconds", FMT_STR_VSLOT(strvec,1));
}
static void
garp_group_gna_interval_handler(vector_t *strvec)
{
	garp_delay_t *delay = LIST_TAIL_DATA(garp_delay);
	double val;

	if (!read_double_strvec(strvec, 1, &val, 0, INT_MAX / 1000000, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "garp_group gna_interval '%s' invalid", FMT_STR_VSLOT(strvec, 1));
		return;
	}

	delay->gna_interval.tv_sec = (time_t)val;
	delay->gna_interval.tv_usec = (suseconds_t)((val - delay->gna_interval.tv_sec) * 1000000);
	delay->have_gna_interval = true;

	if (delay->gna_interval.tv_sec >= 1)
		log_message(LOG_INFO, "The gna_interval is very large - %s seconds", FMT_STR_VSLOT(strvec,1));
}
static void
garp_group_interface_handler(vector_t *strvec)
{
	interface_t *ifp = if_get_by_ifname(strvec_slot(strvec, 1), IF_CREATE_IF_DYNAMIC);
	if (!ifp) {
		report_config_error(CONFIG_GENERAL_ERROR, "WARNING - interface %s specified for garp_group doesn't exist", FMT_STR_VSLOT(strvec, 1));
		return;
	}

	if (ifp->garp_delay) {
		report_config_error(CONFIG_GENERAL_ERROR, "garp_group already specified for %s - ignoring", FMT_STR_VSLOT(strvec, 1));
		return;
	}

#ifdef _HAVE_VRRP_VMAC_
	/* We cannot have a group on a vmac interface */
	if (ifp->vmac_type) {
		report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify garp_delay on a vmac (%s) - ignoring", ifp->ifname);
		return;
	}
#endif
	ifp->garp_delay = LIST_TAIL_DATA(garp_delay);
}
static void
garp_group_interfaces_handler(vector_t *strvec)
{
	garp_delay_t *delay = LIST_TAIL_DATA(garp_delay);
	interface_t *ifp;
	vector_t *interface_vec = read_value_block(strvec);
	size_t i;
	garp_delay_t *gd;
	element e;

	/* Handle the interfaces block being empty */
	if (!interface_vec) {
		report_config_error(CONFIG_GENERAL_ERROR, "Warning - empty garp_group interfaces block");
		return;
	}

	/* First set the next aggregation group number */
	delay->aggregation_group = 1;
	for (e = LIST_HEAD(garp_delay); e; ELEMENT_NEXT(e)) {
		gd = ELEMENT_DATA(e);
		if (gd->aggregation_group && gd != delay)
			delay->aggregation_group++;
	}

	for (i = 0; i < vector_size(interface_vec); i++) {
		ifp = if_get_by_ifname(vector_slot(interface_vec, i), IF_CREATE_IF_DYNAMIC);
		if (!ifp) {
			if (global_data->dynamic_interfaces)
				log_message(LOG_INFO, "WARNING - interface %s specified for garp_group doesn't exist", FMT_STR_VSLOT(strvec, i));
			else
				report_config_error(CONFIG_GENERAL_ERROR, "WARNING - interface %s specified for garp_group doesn't exist", FMT_STR_VSLOT(strvec, i));
			continue;
		}

		if (ifp->garp_delay) {
			report_config_error(CONFIG_GENERAL_ERROR, "garp_group already specified for %s - ignoring", FMT_STR_VSLOT(strvec, 1));
			continue;
		}

#ifdef _HAVE_VRRP_VMAC_
		if (ifp->vmac_type) {
			report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify garp_delay on a vmac (%s) - ignoring", ifp->ifname);
			continue;
		}
#endif
		ifp->garp_delay = delay;
	}

	free_strvec(interface_vec);
}
static void
garp_group_end_handler(void)
{
	garp_delay_t *delay = LIST_TAIL_DATA(garp_delay);
	element e, next;
	interface_t *ifp;

	if (!delay->have_garp_interval && !delay->have_gna_interval) {
		report_config_error(CONFIG_GENERAL_ERROR, "garp group %d does not have any delay set - removing", delay->aggregation_group);

		/* Remove the garp_delay from any interfaces that are using it */
		LIST_FOREACH_NEXT(get_if_list(), ifp, e, next) {
			if (ifp->garp_delay == delay)
				ifp->garp_delay = NULL;
		}

		free_list_element(garp_delay, garp_delay->tail);
	}
}

void
init_vrrp_keywords(bool active)
{
	/* Static addresses/routes/rules */
	install_keyword_root("track_group", &static_track_group_handler, active);
	install_keyword("group", &static_track_group_group_handler);
	install_keyword_root("static_ipaddress", &static_addresses_handler, active);
#ifdef _HAVE_FIB_ROUTING_
	install_keyword_root("static_routes", &static_routes_handler, active);
	install_keyword_root("static_rules", &static_rules_handler, active);
#endif

	/* Sync group declarations */
	install_keyword_root("vrrp_sync_group", &vrrp_sync_group_handler, active);
	install_keyword("group", &vrrp_group_handler);
	install_keyword("track_interface", &vrrp_group_track_if_handler);
	install_keyword("track_script", &vrrp_group_track_scr_handler);
	install_keyword("track_file", &vrrp_group_track_file_handler);
#ifdef _WITH_BFD_
	install_keyword("track_bfd", &vrrp_group_track_bfd_handler);
#endif
	install_keyword("notify_backup", &vrrp_gnotify_backup_handler);
	install_keyword("notify_master", &vrrp_gnotify_master_handler);
	install_keyword("notify_fault", &vrrp_gnotify_fault_handler);
	install_keyword("notify_stop", &vrrp_gnotify_stop_handler);
	install_keyword("notify", &vrrp_gnotify_handler);
	install_keyword("smtp_alert", &vrrp_gsmtp_handler);
	install_keyword("global_tracking", &vrrp_gglobal_tracking_handler);
	install_keyword("sync_group_tracking_weight", &vrrp_sg_tracking_weight_handler);

	install_keyword_root("garp_group", &garp_group_handler, active);
	install_keyword("garp_interval", &garp_group_garp_interval_handler);
	install_keyword("gna_interval", &garp_group_gna_interval_handler);
	install_keyword("interface", &garp_group_interface_handler);
	install_keyword("interfaces", &garp_group_interfaces_handler);
	install_sublevel_end_handler(&garp_group_end_handler);

	/* VRRP Instance mapping */
	install_keyword_root("vrrp_instance", &vrrp_handler, active);
#ifdef _HAVE_VRRP_VMAC_
	install_keyword("use_vmac", &vrrp_vmac_handler);
	install_keyword("vmac_xmit_base", &vrrp_vmac_xmit_base_handler);
#endif
	install_keyword("unicast_peer", &vrrp_unicast_peer_handler);
#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
	install_keyword("old_unicast_checksum", &vrrp_unicast_chksum_handler);
#endif
	install_keyword("native_ipv6", &vrrp_native_ipv6_handler);
	install_keyword("state", &vrrp_state_handler);
	install_keyword("interface", &vrrp_int_handler);
	install_keyword("dont_track_primary", &vrrp_dont_track_handler);
	install_keyword("track_interface", &vrrp_track_if_handler);
	install_keyword("track_script", &vrrp_track_scr_handler);
	install_keyword("track_file", &vrrp_track_file_handler);
#ifdef _WITH_BFD_
	install_keyword("track_bfd", &vrrp_track_bfd_handler);
#endif
	install_keyword("mcast_src_ip", &vrrp_srcip_handler);
	install_keyword("unicast_src_ip", &vrrp_srcip_handler);
	install_keyword("track_src_ip", &vrrp_track_srcip_handler);
	install_keyword("virtual_router_id", &vrrp_vrid_handler);
	install_keyword("version", &vrrp_version_handler);
	install_keyword("priority", &vrrp_prio_handler);
	install_keyword("advert_int", &vrrp_adv_handler);
	install_keyword("virtual_ipaddress", &vrrp_vip_handler);
	install_keyword("virtual_ipaddress_excluded", &vrrp_evip_handler);
	install_keyword("promote_secondaries", &vrrp_promote_secondaries_handler);
	install_keyword("linkbeat_use_polling", &vrrp_linkbeat_handler);
#ifdef _HAVE_FIB_ROUTING_
	install_keyword("virtual_routes", &vrrp_vroutes_handler);
	install_keyword("virtual_rules", &vrrp_vrules_handler);
#endif
	install_keyword("accept", &vrrp_accept_handler);
	install_keyword("no_accept", &vrrp_no_accept_handler);
	install_keyword("skip_check_adv_addr", &vrrp_skip_check_adv_addr_handler);
	install_keyword("strict_mode", &vrrp_strict_mode_handler);
	install_keyword("preempt", &vrrp_preempt_handler);
	install_keyword("nopreempt", &vrrp_nopreempt_handler);
	install_keyword("preempt_delay", &vrrp_preempt_delay_handler);
	install_keyword("debug", &vrrp_debug_handler);
	install_keyword("notify_backup", &vrrp_notify_backup_handler);
	install_keyword("notify_master", &vrrp_notify_master_handler);
	install_keyword("notify_fault", &vrrp_notify_fault_handler);
	install_keyword("notify_stop", &vrrp_notify_stop_handler);
	install_keyword("notify", &vrrp_notify_handler);
	install_keyword("notify_master_rx_lower_pri", vrrp_notify_master_rx_lower_pri);
	install_keyword("smtp_alert", &vrrp_smtp_handler);
#ifdef _WITH_LVS_
	install_keyword("lvs_sync_daemon_interface", &vrrp_lvs_syncd_handler);
#endif
	install_keyword("garp_master_delay", &vrrp_garp_delay_handler);
	install_keyword("garp_master_refresh", &vrrp_garp_refresh_handler);
	install_keyword("garp_master_repeat", &vrrp_garp_rep_handler);
	install_keyword("garp_master_refresh_repeat", &vrrp_garp_refresh_rep_handler);
	install_keyword("garp_lower_prio_delay", &vrrp_garp_lower_prio_delay_handler);
	install_keyword("garp_lower_prio_repeat", &vrrp_garp_lower_prio_rep_handler);
	install_keyword("lower_prio_no_advert", &vrrp_lower_prio_no_advert_handler);
	install_keyword("higher_prio_send_advert", &vrrp_higher_prio_send_advert_handler);
	install_keyword("kernel_rx_buf_size", &kernel_rx_buf_size_handler);
#if defined _WITH_VRRP_AUTH_
	install_keyword("authentication", NULL);
	install_sublevel();
	install_keyword("auth_type", &vrrp_auth_type_handler);
	install_keyword("auth_pass", &vrrp_auth_pass_handler);
	install_sublevel_end();
#endif
	install_keyword_root("vrrp_script", &vrrp_script_handler, active);
	install_keyword("script", &vrrp_vscript_script_handler);
	install_keyword("interval", &vrrp_vscript_interval_handler);
	install_keyword("timeout", &vrrp_vscript_timeout_handler);
	install_keyword("weight", &vrrp_vscript_weight_handler);
	install_keyword("rise", &vrrp_vscript_rise_handler);
	install_keyword("fall", &vrrp_vscript_fall_handler);
	install_keyword("user", &vrrp_vscript_user_handler);
	install_keyword("init_fail", &vrrp_vscript_init_fail_handler);
	install_sublevel_end_handler(&vrrp_vscript_end_handler);

	/* Track file declarations */
	install_keyword_root("vrrp_track_file", &vrrp_tfile_handler, active);
	install_keyword("file", &vrrp_tfile_file_handler);
	install_keyword("weight", &vrrp_tfile_weight_handler);
	install_keyword("init_file", &vrrp_tfile_init_handler);
	install_sublevel_end_handler(&vrrp_tfile_end_handler);
}

vector_t *
vrrp_init_keywords(void)
{
	/* global definitions mapping */
	init_global_keywords(reload);

	init_vrrp_keywords(true);
#ifdef _WITH_LVS_
	init_check_keywords(false);
#endif
#ifdef _WITH_BFD_
	init_bfd_keywords(true);
#endif

	return keywords;
}
