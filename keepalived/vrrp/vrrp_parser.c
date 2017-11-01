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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
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

#include "vrrp_parser.h"
#include "logger.h"
#include "parser.h"
#include "bitops.h"
#include "utils.h"

#include "main.h"
#include "global_data.h"
#include "global_parser.h"

#include "vrrp_data.h"
#include "vrrp_index.h"
#include "vrrp_ipaddress.h"
#include "vrrp_sync.h"
#include "vrrp_track.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_vmac.h"
#endif

#ifdef _WITH_LVS_
#include "check_parser.h"
#endif

/* Used for initialising track files */
static enum {
	TRACK_FILE_NO_INIT,
	TRACK_FILE_CREATE,
	TRACK_FILE_INIT,
} track_file_init;
static long track_file_init_weight;

static bool script_user_set;
static bool remove_script;

/* Static addresses handler */
static void
static_addresses_handler(__attribute__((unused)) vector_t *strvec)
{
	alloc_value_block(alloc_saddress);
}

#ifdef _HAVE_FIB_ROUTING_
/* Static routes handler */
static void
static_routes_handler(__attribute__((unused)) vector_t *strvec)
{
	alloc_value_block(alloc_sroute);
}

/* Static rules handler */
static void
static_rules_handler(__attribute__((unused)) vector_t *strvec)
{
	alloc_value_block(alloc_srule);
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

	if (vector_count(strvec) != 2) {
		log_message(LOG_INFO, "vrrp_sync_group must have a name - skipping");
		skip_block();
		return;
	}

	gname = strvec_slot(strvec, 1);

	/* check group doesn't already exist */
	if (!LIST_ISEMPTY(vrrp_data->vrrp_sync_group)) {
		l = vrrp_data->vrrp_sync_group;
		for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
			sg = ELEMENT_DATA(e);
			if (!strcmp(gname,sg->gname)) {
				log_message(LOG_INFO, "vrrp sync group %s already defined", gname);
				skip_block();
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
		log_message(LOG_INFO, "Group list already specified for sync group %s", vgroup->gname);
		skip_block();
		return;
	}

	vgroup->iname = read_value_block(strvec);
}

static void
vrrp_group_track_if_handler(__attribute__((unused)) vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_group_track_if);
}

static void
vrrp_group_track_scr_handler(__attribute__((unused)) vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_group_track_script);
}

static void
vrrp_group_track_file_handler(__attribute__((unused)) vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_group_track_file);
}

static inline notify_script_t*
set_vrrp_notify_script(vector_t *strvec, bool with_params)
{
	return notify_script_init(strvec, with_params, "notify");
}

static void
vrrp_gnotify_backup_handler(vector_t *strvec)
{
	vrrp_sgroup_t *vgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);
	if (vgroup->script_backup) {
		log_message(LOG_INFO, "vrrp group %s: notify_backup script already specified - ignoring %s", vgroup->gname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vgroup->script_backup = set_vrrp_notify_script(strvec, true);
	vgroup->notify_exec = true;
}
static void
vrrp_gnotify_master_handler(vector_t *strvec)
{
	vrrp_sgroup_t *vgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);
	if (vgroup->script_master) {
		log_message(LOG_INFO, "vrrp group %s: notify_master script already specified - ignoring %s", vgroup->gname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vgroup->script_master = set_vrrp_notify_script(strvec, true);
	vgroup->notify_exec = true;
}
static void
vrrp_gnotify_fault_handler(vector_t *strvec)
{
	vrrp_sgroup_t *vgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);
	if (vgroup->script_fault) {
		log_message(LOG_INFO, "vrrp group %s: notify_fault script already specified - ignoring %s", vgroup->gname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vgroup->script_fault = set_vrrp_notify_script(strvec, true);
	vgroup->notify_exec = true;
}
static void
vrrp_gnotify_handler(vector_t *strvec)
{
	vrrp_sgroup_t *vgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);
	if (vgroup->script) {
		log_message(LOG_INFO, "vrrp group %s: notify script already specified - ignoring %s", vgroup->gname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vgroup->script = set_vrrp_notify_script(strvec, false);
	vgroup->notify_exec = true;
}
static void
vrrp_gsmtp_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_sgroup_t *vgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);
	vgroup->smtp_alert = true;
}
static void
vrrp_gglobal_tracking_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_sgroup_t *vgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);

	log_message(LOG_INFO, "(%s) global_tracking is deprecated. Use track_interface/script/file on the sync group", vgroup->gname);
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

	if (vector_count(strvec) != 2) {
		log_message(LOG_INFO, "vrrp_instance must have a name");
		skip_block();
		return;
	}

	iname = strvec_slot(strvec,1);

	/* Make sure the vrrp instance doesn't already exist */
	if (!LIST_ISEMPTY(vrrp_data->vrrp)) {
		l = vrrp_data->vrrp;
		for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
			vrrp = ELEMENT_DATA(e);
			if (!strcmp(iname,vrrp->iname)) {
				log_message(LOG_INFO, "vrrp instance %s already defined", iname );
				skip_block();
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
		strncpy(vrrp->vmac_ifname, strvec_slot(strvec, 1), IFNAMSIZ - 1);

		/* Check if the interface exists and is a macvlan we can use */
		if ((ifp = if_get_by_ifname(vrrp->vmac_ifname, IF_NO_CREATE)) &&
		    !ifp->vmac) {
			log_message(LOG_INFO, "(%s) interface %s already exists and is not a private macvlan; ignoring vmac if_name", vrrp->iname, vrrp->vmac_ifname);
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
vrrp_unicast_peer_handler(__attribute__((unused)) vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_unicast_peer);
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
			log_message(LOG_INFO, "(%s) Unknown old_unicast_chksum mode %s - ignoring", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
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
		log_message(LOG_INFO,"(%s) Cannot specify native_ipv6 with IPv4 addresses", vrrp->iname);
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
		vrrp->init_state = VRRP_STATE_MAST;
	else if (!strcmp(str, "BACKUP"))
	{
		if (vrrp->init_state == VRRP_STATE_MAST)
			log_message(LOG_INFO, "(%s) state previously set as MASTER - ignoring BACKUP", vrrp->iname);
		else
			vrrp->init_state = VRRP_STATE_BACK;
	}
	else {
		log_message(LOG_INFO,"(%s) unknown state '%s', defaulting to BACKUP", vrrp->iname, str);
		vrrp->init_state = VRRP_STATE_BACK;
	}
}
static void
vrrp_int_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	char *name = strvec_slot(strvec, 1);

	vrrp->ifp = if_get_by_ifname(name, IF_CREATE_IF_DYNAMIC);
	if (!vrrp->ifp)
		log_message(LOG_INFO, "WARNING - interface %s for vrrp_instance %s doesn't exist", name, vrrp->iname);
	else if (vrrp->ifp->hw_type == ARPHRD_LOOPBACK) {
		log_message(LOG_INFO, "(%s) cannot use a loopback interface (%s) for vrrp - ignoring", vrrp->iname, vrrp->ifp->ifname);
		vrrp->ifp = NULL;
	}
}
static void
vrrp_linkbeat_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	vrrp->linkbeat_use_polling = true;
}
static void
vrrp_track_if_handler(__attribute__((unused)) vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_track_if);
}
static void
vrrp_track_scr_handler(__attribute__((unused)) vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_track_script);
}
static void
vrrp_track_file_handler(__attribute__((unused)) vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_track_file);
}
static void
vrrp_dont_track_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	vrrp->dont_track_primary = true;
}
static void
vrrp_srcip_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	struct sockaddr_storage *saddr = &vrrp->saddr;
	int ret;

	ret = inet_stosockaddr(strvec_slot(strvec, 1), 0, saddr);
	if (ret < 0) {
		log_message(LOG_ERR, "Configuration error: VRRP instance[%s] malformed"
				     " src address[%s]. Skipping..."
				   , vrrp->iname, FMT_STR_VSLOT(strvec, 1));
		return;
	}

	vrrp->saddr_from_config = true;

	if (vrrp->family == AF_UNSPEC)
		vrrp->family = saddr->ss_family;
	else if (saddr->ss_family != vrrp->family) {
		log_message(LOG_ERR, "Configuration error: VRRP instance[%s] and src address"
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
	char *end_ptr;
	unsigned long vrid = strtoul(strvec_slot(strvec, 1),&end_ptr, 10);

	if (*end_ptr || VRRP_IS_BAD_VID(vrid)) {
		log_message(LOG_INFO, "VRRP Error : VRID not valid - must be between 1 & 255. reconfigure !");
		return;
	}

	vrrp->vrid = (uint8_t)vrid;
}
static void
vrrp_prio_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	char *endptr;
	unsigned long base_priority = strtoul(strvec_slot(strvec, 1), &endptr, 10);

	if (*endptr || VRRP_IS_BAD_PRIORITY(base_priority)) {
		log_message(LOG_INFO, "(%s) Priority not valid! must be between 1 & 255. Reconfigure !", vrrp->iname);
		log_message(LOG_INFO, "%*sUsing default value : %d", (int)strlen(vrrp->iname) + 4, "", VRRP_PRIO_DFL);

		vrrp->base_priority = VRRP_PRIO_DFL;
	}
	else
		vrrp->base_priority = (uint8_t)base_priority;
}
static void
vrrp_adv_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	int adver_int = (int)(atof(strvec_slot(strvec, 1)) * TIMER_HZ);

	/* Simple check - just positive */
	if (adver_int <= 0)
		log_message(LOG_INFO, "(%s) Advert interval (%s) not valid! Must be > 0 - ignoring", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
	else
		vrrp->adver_int = (unsigned)adver_int;
}
static void
vrrp_debug_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	vrrp->debug = atoi(strvec_slot(strvec, 1));

	if (VRRP_IS_BAD_DEBUG_INT(vrrp->debug)) {
		log_message(LOG_INFO, "(%s) Debug value not valid! must be between 0-4", vrrp->iname);
		vrrp->debug = 0;
	}
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
			log_message(LOG_INFO, "(%s) invalid skip_check_adv_addr %s specified", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
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
			log_message(LOG_INFO, "(%s) invalid strict_mode %s specified", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
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
	unsigned long preempt_delay = (unsigned long)(atof(vector_slot(strvec, 1)) * TIMER_HZ);

	if (preempt_delay > TIMER_MAX_SEC * TIMER_HZ) {
		log_message(LOG_INFO, "(%s) Preempt_delay not valid! must be between 0-%d", vrrp->iname, TIMER_MAX_SEC);
		vrrp->preempt_delay = 0;
	}
	else
		vrrp->preempt_delay = preempt_delay;
}
static void
vrrp_notify_backup_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	if (vrrp->script_backup) {
		log_message(LOG_INFO, "(%s) notify_backup script already specified - ignoring %s", vrrp->iname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vrrp->script_backup = set_vrrp_notify_script(strvec, true);
	vrrp->notify_exec = true;
}
static void
vrrp_notify_master_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	if (vrrp->script_master) {
		log_message(LOG_INFO, "(%s) notify_master script already specified - ignoring %s", vrrp->iname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vrrp->script_master = set_vrrp_notify_script(strvec, true);
	vrrp->notify_exec = true;
}
static void
vrrp_notify_fault_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	if (vrrp->script_fault) {
		log_message(LOG_INFO, "(%s) notify_fault script already specified - ignoring %s", vrrp->iname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vrrp->script_fault = set_vrrp_notify_script(strvec, true);
	vrrp->notify_exec = true;
}
static void
vrrp_notify_stop_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	if (vrrp->script_stop) {
		log_message(LOG_INFO, "(%s) notify_stop script already specified - ignoring %s", vrrp->iname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vrrp->script_stop = set_vrrp_notify_script(strvec, true);
	vrrp->notify_exec = true;
}
static void
vrrp_notify_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	if (vrrp->script) {
		log_message(LOG_INFO, "(%s) notify script already specified - ignoring %s", vrrp->iname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vrrp->script = set_vrrp_notify_script(strvec, false);
	vrrp->notify_exec = true;
}
static void
vrrp_smtp_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	vrrp->smtp_alert = true;
}
#ifdef _WITH_LVS_
static void
vrrp_lvs_syncd_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	log_message(LOG_INFO, "(%s) Specifying lvs_sync_daemon_interface against a vrrp is deprecated.", vrrp->iname);  /* Deprecated after v1.2.19 */
	log_message(LOG_INFO, "      %*sPlease use global lvs_sync_daemon", (int)strlen(vrrp->iname) - 2, "");

	if (global_data->lvs_syncd.ifname) {
		log_message(LOG_INFO, "(%s) lvs_sync_daemon_interface has already been specified as %s - ignoring", vrrp->iname, global_data->lvs_syncd.ifname);
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
	vrrp->garp_delay = (unsigned)strtoul(strvec_slot(strvec, 1), NULL, 10) * TIMER_HZ;
	if (vrrp->garp_delay < TIMER_HZ)
		vrrp->garp_delay = TIMER_HZ;
}
static void
vrrp_garp_refresh_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	vrrp->garp_refresh.tv_sec = atoi(strvec_slot(strvec, 1));
	vrrp->garp_refresh.tv_usec = 0;
}
static void
vrrp_garp_rep_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	vrrp->garp_rep = (unsigned)strtoul(strvec_slot(strvec, 1), NULL, 10);
	if (vrrp->garp_rep < 1)
		vrrp->garp_rep = 1;
}
static void
vrrp_garp_refresh_rep_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	vrrp->garp_refresh_rep = (unsigned)strtoul(strvec_slot(strvec, 1), NULL, 10);
	if (vrrp->garp_refresh_rep < 1)
		vrrp->garp_refresh_rep = 1;
}

static void
vrrp_garp_lower_prio_delay_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	vrrp->garp_lower_prio_delay = (unsigned)strtoul(strvec_slot(strvec, 1), NULL, 10) * TIMER_HZ;
}
static void
vrrp_garp_lower_prio_rep_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	int garp_lower_prio_rep = atoi(strvec_slot(strvec, 1));

	/* Allow 0 GARP messages to be sent */
	if (garp_lower_prio_rep < 0)
		vrrp->garp_lower_prio_rep = 0;
	else
		vrrp->garp_lower_prio_rep = (unsigned)garp_lower_prio_rep;
}
static void
vrrp_lower_prio_no_advert_handler(vector_t *strvec)
{
	int res;

	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res >= 0)
			vrrp->lower_prio_no_advert = (unsigned)res;
		else
			log_message(LOG_INFO, "(%s) invalid lower_prio_no_advert %s specified", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
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
			log_message(LOG_INFO, "(%s) invalid higher_prio_send_advert %s specified", vrrp->iname, FMT_STR_VSLOT(strvec, 1));
	} else {
		/* Defaults to true */
		vrrp->higher_prio_send_advert = true;
	}
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
		log_message(LOG_INFO, "(%s) unknown authentication type '%s'", vrrp->iname, str);
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
		log_message(LOG_INFO,
			    "Truncating auth_pass to %zu characters", max_size);
	}

	memset(vrrp->auth_data, 0, max_size);
	memcpy(vrrp->auth_data, str, str_len);
}
#endif
static void
vrrp_vip_handler(__attribute__((unused)) vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_vip);
}
static void
vrrp_evip_handler(__attribute__((unused)) vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_evip);
}
static void
vrrp_promote_secondaries_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	vrrp->promote_secondaries = true;
}
#ifdef _HAVE_FIB_ROUTING_
static void
vrrp_vroutes_handler(__attribute__((unused)) vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_vroute);
}
static void
vrrp_vrules_handler(__attribute__((unused)) vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_vrule);
}
#endif
static void
vrrp_script_handler(vector_t *strvec)
{
	alloc_vrrp_script(strvec_slot(strvec, 1));
	script_user_set = false;
	remove_script = false;
}
static void
vrrp_vscript_script_handler(vector_t *strvec)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);
	vscript->script.args = set_script_params_array(strvec, true);
	vscript->script.cmd_str = set_value(strvec);
}
static void
vrrp_vscript_interval_handler(vector_t *strvec)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);
	vscript->interval = (unsigned)(strtoul(strvec_slot(strvec, 1), NULL, 10) * TIMER_HZ);
	if (vscript->interval < TIMER_HZ)
		vscript->interval = TIMER_HZ;
}
static void
vrrp_vscript_timeout_handler(vector_t *strvec)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);
	vscript->timeout = strtoul(strvec_slot(strvec, 1), NULL, 10) * TIMER_HZ;
	if (vscript->timeout < TIMER_HZ)
		vscript->timeout = TIMER_HZ;
}
static void
vrrp_vscript_weight_handler(vector_t *strvec)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);
	vscript->weight = atoi(strvec_slot(strvec, 1));
}
static void
vrrp_vscript_rise_handler(vector_t *strvec)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);
	vscript->rise = atoi(strvec_slot(strvec, 1));
	if (vscript->rise < 1)
		vscript->rise = 1;
}
static void
vrrp_vscript_fall_handler(vector_t *strvec)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);
	vscript->fall = atoi(strvec_slot(strvec, 1));
	if (vscript->fall < 1)
		vscript->fall = 1;
}
static void
vrrp_vscript_user_handler(vector_t *strvec)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);
	if (set_script_uid_gid(strvec, 1, &vscript->script.uid, &vscript->script.gid)) {
		log_message(LOG_INFO, "Unable to set uid/gid for script %s", vscript->script.cmd_str);
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
		log_message(LOG_INFO, "No script set for vrrp_script %s - removing", vscript->sname);
		remove_script = true;
	}
	else if (!remove_script) {
		if (script_user_set)
			return;

		if (set_default_script_user(NULL, NULL)) {
			log_message(LOG_INFO, "Unable to set default user for vrrp script %s - removing", vscript->sname);
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
	alloc_vrrp_file(strvec_slot(strvec, 1));

	track_file_init = TRACK_FILE_NO_INIT;
}
static void
vrrp_tfile_file_handler(vector_t *strvec)
{
	vrrp_tracked_file_t *tfile = LIST_TAIL_DATA(vrrp_data->vrrp_track_files);
	if (tfile->file_path) {
		log_message(LOG_INFO, "File already set for track file %s - ignoring %s", tfile->fname, FMT_STR_VSLOT(strvec, 1));
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
		log_message(LOG_INFO, "No weight specified for track file %s - ignoring", tfile->fname);
		return;
	}
	if (tfile->weight != 1) {
		log_message(LOG_INFO, "Weight already set for track file %s - ignoring %s", tfile->fname, FMT_STR_VSLOT(strvec, 1));
		return;
	}

	weight = atoi(strvec_slot(strvec, 1));
	if (weight < -254 || weight > 254) {
		log_message(LOG_INFO, "Weight for %s must be between "
				 "[-254..254] inclusive. Ignoring...", tfile->fname);
		weight = 1;
	}

	tfile->weight = weight;
}
static void
vrrp_tfile_init_handler(vector_t *strvec)
{
	unsigned i;
	char *word;
	char *endptr;
	vrrp_tracked_file_t *tfile = LIST_TAIL_DATA(vrrp_data->vrrp_track_files);

	track_file_init = TRACK_FILE_CREATE;
	track_file_init_weight = 0;

	for (i = 1; i < vector_size(strvec); i++) {
		word = strvec_slot(strvec, i);
		if (isdigit(word[0])) {
			track_file_init_weight = strtol(word, &endptr, 0);
			if (*endptr) {
				/* It is not a valid integer */
				log_message(LOG_INFO, "Track file %s init weight %s is invalid", tfile->fname, word);
				track_file_init_weight = 0;
			}
		}
		else if (!strcmp(word, "overwrite"))
			track_file_init = TRACK_FILE_INIT;
		else
			log_message(LOG_INFO, "Unknown track file init option %s", word);
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
		log_message(LOG_INFO, "No file set for track_file %s - removing", tfile->fname);
		free_list_element(vrrp_data->vrrp_track_files, vrrp_data->vrrp_track_files->tail);
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
			log_message(LOG_INFO, "Cannot initialise track file %s - it is not a regular file", tfile->fname);
			return;
		}
	}

	/* Write the value to the file */
	if ((tf = fopen(tfile->file_path, "w"))) {
		fprintf(tf, "%ld\n", track_file_init_weight);
		fclose(tf);
	}
	else
		log_message(LOG_INFO, "Unable to initialise track file %s", tfile->fname);
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
	uint8_t version = (uint8_t)strtoul(strvec_slot(strvec, 1), NULL, 10);

	if (VRRP_IS_BAD_VERSION(version)) {
		log_message(LOG_INFO, "VRRP Error : Version not valid !");
		log_message(LOG_INFO, "             must be between either 2 or 3. reconfigure !");
		return;
	}

	if ((vrrp->version && vrrp->version != version) ||
	    (version == VRRP_VERSION_2 && vrrp->family == AF_INET6)) {
		log_message(LOG_INFO, "(%s) vrrp_version conflicts with configured or deduced version; ignoring.", vrrp->iname);
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
garp_group_handler(__attribute__((unused)) vector_t *strvec)
{
	alloc_garp_delay();
}
static void
garp_group_garp_interval_handler(vector_t *strvec)
{
	garp_delay_t *delay = LIST_TAIL_DATA(garp_delay);

	delay->garp_interval.tv_usec = (useconds_t)atof(strvec_slot(strvec, 1)) * 1000000;
	delay->garp_interval.tv_sec = delay->garp_interval.tv_usec / 1000000;
	delay->garp_interval.tv_usec %= 1000000;
	delay->have_garp_interval = true;

	if (delay->garp_interval.tv_sec >= 1)
		log_message(LOG_INFO, "The garp_interval is very large - %s seconds", FMT_STR_VSLOT(strvec,1));
}
static void
garp_group_gna_interval_handler(vector_t *strvec)
{
	garp_delay_t *delay = LIST_TAIL_DATA(garp_delay);

	delay->gna_interval.tv_usec = (suseconds_t)(atof(strvec_slot(strvec, 1)) * 1000000);
	delay->gna_interval.tv_sec = delay->gna_interval.tv_usec / 1000000;
	delay->gna_interval.tv_usec %= 1000000;
	delay->have_gna_interval = true;

	if (delay->gna_interval.tv_sec >= 1)
		log_message(LOG_INFO, "The gna_interval is very large - %s seconds", FMT_STR_VSLOT(strvec,1));
}
static void
garp_group_interface_handler(vector_t *strvec)
{
	interface_t *ifp = if_get_by_ifname(strvec_slot(strvec, 1), IF_CREATE_IF_DYNAMIC);
	if (!ifp) {
		log_message(LOG_INFO, "WARNING - interface %s specified for garp_group doesn't exist", ifp->ifname);
		return;
	}

	if (ifp->garp_delay) {
		log_message(LOG_INFO, "garp_group already specified for %s - ignoring", FMT_STR_VSLOT(strvec, 1));
		return;
	}

#ifdef _HAVE_VRRP_VMAC_
	/* We cannot have a group on a vmac interface */
	if (ifp->vmac) {
		log_message(LOG_INFO, "Cannot specify garp_delay on a vmac (%s) - ignoring", ifp->ifname);
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
			log_message(LOG_INFO, "WARNING - interface %s specified for garp_group doesn't exist", ifp->ifname);
			continue;
		}

		if (ifp->garp_delay) {
			log_message(LOG_INFO, "garp_group already specified for %s - ignoring", FMT_STR_VSLOT(strvec, 1));
			continue;
		}

#ifdef _HAVE_VRRP_VMAC_
		if (ifp->vmac) {
			log_message(LOG_INFO, "Cannot specify garp_delay on a vmac (%s) - ignoring", ifp->ifname);
			continue;
		}
#endif
		ifp->garp_delay = delay;
	}

	free_strvec(interface_vec);
}

void
init_vrrp_keywords(bool active)
{
	/* Static routes mapping */
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
	install_keyword("notify_backup", &vrrp_gnotify_backup_handler);
	install_keyword("notify_master", &vrrp_gnotify_master_handler);
	install_keyword("notify_fault", &vrrp_gnotify_fault_handler);
	install_keyword("notify", &vrrp_gnotify_handler);
	install_keyword("smtp_alert", &vrrp_gsmtp_handler);
	install_keyword("global_tracking", &vrrp_gglobal_tracking_handler);
	install_keyword("sync_group_tracking_weight", &vrrp_sg_tracking_weight_handler);

	install_keyword_root("garp_group", &garp_group_handler, active);
	install_keyword("garp_interval", &garp_group_garp_interval_handler);
	install_keyword("gna_interval", &garp_group_gna_interval_handler);
	install_keyword("interface", &garp_group_interface_handler);
	install_keyword("interfaces", &garp_group_interfaces_handler);

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
	init_global_keywords(true);

	init_vrrp_keywords(true);
#ifdef _WITH_LVS_
	init_check_keywords(false);
#endif

	return keywords;
}
