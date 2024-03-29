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

#include "rttables.h"

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
#include "track_file.h"
#ifdef _WITH_TRACK_PROCESS_
#include "track_process.h"
#endif

enum process_delay {
	PROCESS_DELAY,
	PROCESS_TERMINATE_DELAY,
	PROCESS_FORK_DELAY,
};

static bool script_user_set;
static bool remove_script;

static static_track_group_t *current_stg;
vrrp_sgroup_t *current_vsyncg;
static garp_delay_t *current_ggd;
vrrp_t *current_vrrp;
static vrrp_script_t *current_vscr;
#ifdef _WITH_TRACK_PROCESS_
static vrrp_tracked_process_t *current_tp;
#endif


/* track groups for static items */
static void
static_track_group_handler(const vector_t *strvec)
{
	static_track_group_t *tg;
	const char *gname;

	if (!strvec)
		return;

	if (vector_count(strvec) != 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "track_group must have a name - skipping");
		skip_block(true);
		return;
	}

	gname = strvec_slot(strvec, 1);

	/* check group doesn't already exist */
	list_for_each_entry(tg, &vrrp_data->static_track_groups, e_list) {
		if (!strcmp(gname,tg->gname)) {
			report_config_error(CONFIG_GENERAL_ERROR, "track_group %s already defined"
								, gname);
			skip_block(true);
			return;
		}
	}

	current_stg = alloc_static_track_group(gname);
}

static void
static_track_group_group_handler(const vector_t *strvec)
{
	if (current_stg->iname) {
		report_config_error(CONFIG_GENERAL_ERROR, "Group list already specified for sync group %s", current_stg->gname);
		skip_block(true);
		return;
	}

	current_stg->iname = read_value_block(strvec);

	if (!current_stg->iname)
		report_config_error(CONFIG_GENERAL_ERROR, "Warning - track group %s has empty group block", current_stg->gname);
}

static void
static_track_group_end_handler(void)
{
	if (!current_stg->iname) {
		report_config_error(CONFIG_GENERAL_ERROR, "Static track group %s has no members - removing", current_stg->gname);
		free_static_track_group(current_stg);
		return;
	}

	list_add_tail(&current_stg->e_list, &vrrp_data->static_track_groups);
}

/* Static addresses handler */
static void
static_addresses_handler(const vector_t *strvec)
{
	global_data->have_vrrp_config = true;

	if (!strvec)
		return;

	alloc_value_block(alloc_saddress, strvec);
}

/* Static routes handler */
static void
static_routes_handler(const vector_t *strvec)
{
	global_data->have_vrrp_config = true;

	if (!strvec)
		return;

	alloc_value_block(alloc_sroute, strvec);
}

/* Static rules handler */
static void
static_rules_handler(const vector_t *strvec)
{
	global_data->have_vrrp_config = true;

	if (!strvec)
		return;

	alloc_value_block(alloc_srule, strvec);
}

#ifdef _WITH_LINKBEAT_
static void
alloc_linkbeat_interface(const vector_t *strvec)
{
	interface_t *ifp;
	int lb_type = 0;

	if (!(ifp = if_get_by_ifname(vector_slot(strvec, 0), global_data->dynamic_interfaces))) {
		report_config_error(CONFIG_FATAL, "unknown interface %s specified for linkbeat interface", strvec_slot(strvec, 0));
		return;
	}

#ifdef _HAVE_VRRP_VMAC_
	/* netlink messages work for vmacs */
	if (IS_MAC_IP_VLAN(ifp)) {
		log_message(LOG_INFO, "(%s): linkbeat not supported for vmacs since netlink works", ifp->ifname);
		return;
	}
#endif

	if (vector_size(strvec) > 1) {
		if (!strcmp(strvec_slot(strvec, 1), "MII"))
			lb_type = LB_MII;
		else if (!strcmp(strvec_slot(strvec, 1), "ETHTOOL"))
			lb_type = LB_ETHTOOL;
		else if (!strcmp(strvec_slot(strvec, 1), "IOCTL"))
			lb_type = LB_IOCTL;

		if (!lb_type || vector_size(strvec) > 2)
			report_config_error(CONFIG_GENERAL_ERROR, "extra characters %s in linkbeat interface", strvec_slot(strvec, 1));
	}

	ifp->linkbeat_use_polling = true;
	ifp->lb_type = lb_type;
}

static void
linkbeat_interfaces_handler(const vector_t *strvec)
{
	if (!strvec)
		return;
	alloc_value_block(alloc_linkbeat_interface, strvec);
}
#endif

/* VRRP handlers */
static void
vrrp_sync_group_handler(const vector_t *strvec)
{
	vrrp_sgroup_t *sgroup;
	const char *gname;

	if (!strvec)
		return;

	if (vector_count(strvec) != 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp_sync_group must have a name - skipping");
		skip_block(true);
		return;
	}

	gname = strvec_slot(strvec, 1);

	/* check group doesn't already exist */
	list_for_each_entry(sgroup, &vrrp_data->vrrp_sync_group, e_list) {
		if (!strcmp(gname, sgroup->gname)) {
			report_config_error(CONFIG_GENERAL_ERROR, "vrrp sync group %s already defined", gname);
			skip_block(true);
			return;
		}
	}

	current_vsyncg = alloc_vrrp_sync_group(gname);
}

static void
vrrp_group_handler(const vector_t *strvec)
{
	if (current_vsyncg->iname) {
		report_config_error(CONFIG_GENERAL_ERROR, "Group list already specified for sync group %s"
							, current_vsyncg->gname);
		skip_block(true);
		return;
	}

	current_vsyncg->iname = read_value_block(strvec);

	if (!current_vsyncg->iname)
		report_config_error(CONFIG_GENERAL_ERROR, "Warning - sync group %s has empty group block"
							, current_vsyncg->gname);
}

static void
vrrp_group_track_if_handler(const vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_group_track_if, strvec);
}

static void
vrrp_group_track_scr_handler(const vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_group_track_script, strvec);
}

static void
vrrp_group_track_file_handler(const vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_group_track_file, strvec);
}

#ifdef _WITH_TRACK_PROCESS_
static void
vrrp_group_track_process_handler(const vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_group_track_process, strvec);
}
#endif

#if defined _WITH_BFD_
static void
vrrp_group_track_bfd_handler(const vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_group_track_bfd, strvec);
}
#endif

static void
vrrp_sync_group_end_handler(void)
{
	if (!current_vsyncg->iname) {
		report_config_error(CONFIG_GENERAL_ERROR, "Sync group %s has no members - removing"
							, current_vsyncg->gname);
		free_sync_group(current_vsyncg);
		return;
	}

	list_add_tail(&current_vsyncg->e_list, &vrrp_data->vrrp_sync_group);
}

static inline notify_script_t*
set_vrrp_notify_script(__attribute__((unused)) const vector_t *strvec, int extra_params)
{
	return notify_script_init(extra_params, "notify");
}

static void
vrrp_gnotify_backup_handler(const vector_t *strvec)
{
	if (current_vsyncg->script_backup) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp group %s: notify_backup script already specified - ignoring %s", current_vsyncg->gname, strvec_slot(strvec,1));
		return;
	}
	current_vsyncg->script_backup = set_vrrp_notify_script(strvec, 0);
	current_vsyncg->notify_exec = true;
}
static void
vrrp_gnotify_master_handler(const vector_t *strvec)
{
	if (current_vsyncg->script_master) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp group %s: notify_master script already specified - ignoring %s", current_vsyncg->gname, strvec_slot(strvec,1));
		return;
	}
	current_vsyncg->script_master = set_vrrp_notify_script(strvec, 0);
	current_vsyncg->notify_exec = true;
}
static void
vrrp_gnotify_fault_handler(const vector_t *strvec)
{
	if (current_vsyncg->script_fault) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp group %s: notify_fault script already specified - ignoring %s", current_vsyncg->gname, strvec_slot(strvec,1));
		return;
	}
	current_vsyncg->script_fault = set_vrrp_notify_script(strvec, 0);
	current_vsyncg->notify_exec = true;
}
static void
vrrp_gnotify_stop_handler(const vector_t *strvec)
{
	if (current_vsyncg->script_stop) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp group %s: notify_stop script already specified - ignoring %s", current_vsyncg->gname, strvec_slot(strvec,1));
		return;
	}
	current_vsyncg->script_stop = set_vrrp_notify_script(strvec, 0);
	current_vsyncg->notify_exec = true;
}
static void
vrrp_gnotify_handler(const vector_t *strvec)
{
	if (current_vsyncg->script) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp group %s: notify script already specified - ignoring %s", current_vsyncg->gname, strvec_slot(strvec,1));
		return;
	}
	current_vsyncg->script = set_vrrp_notify_script(strvec, 4);
	current_vsyncg->notify_exec = true;
}
static void
vrrp_gsmtp_handler(__attribute__((unused)) const vector_t *strvec)
{
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res == -1) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid vrrp_group smtp_alert parameter %s", strvec_slot(strvec, 1));
			return;
		}
	}
	current_vsyncg->smtp_alert = res;
	vrrp_data->num_smtp_alert++;
}
static void
vrrp_gglobal_tracking_handler(__attribute__((unused)) const vector_t *strvec)
{
	report_config_error(CONFIG_GENERAL_ERROR, "(%s) global_tracking is deprecated. Use track_interface/script/file on the sync group", current_vsyncg->gname);
	current_vsyncg->sgroup_tracking_weight = true;
}
static void
vrrp_sg_tracking_weight_handler(__attribute__((unused)) const vector_t *strvec)
{
	current_vsyncg->sgroup_tracking_weight = true;
}
static void
vrrp_sg_notify_priority_changes_handler(const vector_t *strvec)
{
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) Invalid value '%s' for sync group notify_priority_changes specified", current_vsyncg->gname, strvec_slot(strvec, 1));
			return;
		}
	}

	current_vsyncg->notify_priority_changes = res;
}
static void
vrrp_handler(const vector_t *strvec)
{
	vrrp_t *vrrp;
	const char *iname;

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
	list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
		if (!strcmp(iname, vrrp->iname)) {
			report_config_error(CONFIG_GENERAL_ERROR, "vrrp instance %s already defined", iname);
			skip_block(true);
			return;
		}
	}

	current_vrrp = alloc_vrrp(iname);
}
static void
vrrp_end_handler(void)
{
#ifdef _HAVE_VRRP_VMAC_
	if (__test_bit(VRRP_FLAG_UNICAST_CONFIGURED, &current_vrrp->flags) &&
	    (__test_bit(VRRP_VMAC_BIT, &current_vrrp->flags)
#ifdef _HAVE_VRRP_IPVLAN_
	     || (__test_bit(VRRP_IPVLAN_BIT, &current_vrrp->flags))
#endif
							   )) {
		if (!current_vrrp->ifp) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s): Cannot use VMAC/ipvlan with unicast and no interface - clearing use_vmac", current_vrrp->iname);
			__clear_bit(VRRP_VMAC_BIT, &current_vrrp->flags);
#ifdef _HAVE_VRRP_IPVLAN_
			__clear_bit(VRRP_IPVLAN_BIT, &current_vrrp->flags);
#endif
			current_vrrp->vmac_ifname[0] = '\0';
		} else if (!__test_bit(VRRP_VMAC_XMITBASE_BIT, &current_vrrp->flags)) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) unicast with use_vmac requires vmac_xmit_base - setting", current_vrrp->iname);
			__set_bit(VRRP_VMAC_XMITBASE_BIT, &current_vrrp->flags);
		}
	}
#endif

	if (list_empty(&current_vrrp->unicast_peer) && current_vrrp->ttl != -1) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): Cannot use unicast_ttl without unicast peers - resetting", current_vrrp->iname);
		current_vrrp->ttl = 0;
	}

	if (!current_vrrp->ifp)
		__clear_bit(VRRP_FLAG_LINKBEAT_USE_POLLING, &current_vrrp->flags);

	list_add_tail(&current_vrrp->e_list, &vrrp_data->vrrp);
}

#ifdef _HAVE_VRRP_VMAC_
/* The following function is copied from kernel net/core/dev.c */
static bool __attribute__ ((pure))
dev_name_valid(const char *name)
{
	if (*name == '\0')
		return false;
	if (strnlen(name, IFNAMSIZ) == IFNAMSIZ)
		return false;
	if (!strcmp(name, ".") || !strcmp(name, ".."))
		return false;

	while (*name) {
		if (*name == '/' || *name == ':' || isspace(*name))
			return false;
		name++;
	}
	return true;
}

static void
vrrp_vmac_handler(const vector_t *strvec)
{
	interface_t *ifp;
	const char *name;
	vrrp_t *ovrrp;
	unsigned i;
	unsigned j;
	bool had_error;
	unsigned long byte_val;
	const char *p;
	char *endptr;

	__set_bit(VRRP_VMAC_BIT, &current_vrrp->flags);

	/* Ifname and MAC address can be specified */
	for (i = 1; i < vector_size(strvec); i++) {
		if (strchr(strvec_slot(strvec, i), ':')) {
			/* It's a MAC address - interface names cannot include a ':' */
			if (__test_bit(VRRP_VMAC_MAC_SPECIFIED, &current_vrrp->flags)) {
				report_config_error(CONFIG_GENERAL_ERROR, "VMAC interface address already specified");
				continue;
			}
			p = strvec_slot(strvec, i);
			if (p[strspn(p, "0123456789ABCDEFabcdef:")]) {
				report_config_error(CONFIG_GENERAL_ERROR, "VMAC invalid MAC address %s", p);
				continue;
			}

			for (j = 0, had_error = false; j < ETH_ALEN; j++) {
				errno = 0;
				byte_val = strtoul(p, &endptr, 16);
				if (errno || endptr - p > 2 || endptr == p) {
					had_error = true;
					break;
				}

				if (*endptr != ':' && (*endptr || j < ETH_ALEN - 2)) {
					had_error = true;
					break;
				}
				current_vrrp->ll_addr[j] = (u_char)byte_val;
				if (j == ETH_ALEN - 2 &&
				    (!*endptr || (*endptr == ':' && !*(endptr+1)))) {
					__set_bit(VRRP_VMAC_MAC_USE_VRID, &current_vrrp->flags);
					break;
				}
				p = endptr + 1;
				if (!*p && j < ETH_ALEN - 1) {
					/* Not enough octets specified */
					had_error = true;
					break;
				}
			}
			if (had_error)
				report_config_error(CONFIG_GENERAL_ERROR, "VMAC invalid MAC address %s - ignored", strvec_slot(strvec, i));
			else if (current_vrrp->ll_addr[0] & 0x01)
				report_config_error(CONFIG_GENERAL_ERROR, "VMAC MAC address is multicast %s - ignoring", strvec_slot(strvec, i));
			else if (!memcmp(ll_addr, current_vrrp->ll_addr, ETH_ALEN - 2) && (current_vrrp->ll_addr[ETH_ALEN - 2] == 0x01 || current_vrrp->ll_addr[ETH_ALEN - 2] == 0x02))
				report_config_error(CONFIG_GENERAL_ERROR, "VMAC MAC address not allowed to be RFC5798 address (%s) - ignoring", strvec_slot(strvec, i));
			else
				__set_bit(VRRP_VMAC_MAC_SPECIFIED, &current_vrrp->flags);

			continue;
		}

		if (!strcmp(strvec_slot(strvec, i), "netlink_notify_msg")) {
			__set_bit(VRRP_VMAC_NETLINK_NOTIFY, &current_vrrp->flags);
			continue;
		}

#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
		if (!strcmp(strvec_slot(strvec, i), "group")) {
			uint32_t group;
			if (!find_rttables_group(strvec_slot(strvec, ++i), &group)) {
				report_config_error(CONFIG_GENERAL_ERROR, "VMAC group %s not found", strvec_slot(strvec, i));
				continue;
			}
			__set_bit(VRRP_VMAC_GROUP, &current_vrrp->flags);
			current_vrrp->vmac_group = group;
			continue;
		}
#endif

		if (!strcmp(strvec_slot(strvec, i), "name")) {
			/* Skip over "name" */
			i++;
		}

		if (current_vrrp->vmac_ifname[0]) {
			report_config_error(CONFIG_GENERAL_ERROR, "VMAC interface name already specified");
			continue;
		}

		name = strvec_slot(strvec, i);

		if (!dev_name_valid(name)) {
			report_config_error(CONFIG_GENERAL_ERROR, "VMAC interface name '%s' too long or invalid characters - ignoring", name);
			continue;
		}

		/* Check another vrrp instance isn't using this name */
		list_for_each_entry(ovrrp, &vrrp_data->vrrp, e_list) {
			if (!strcmp(name, ovrrp->vmac_ifname)) {
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) VRRP instance %s is already using %s - ignoring name", current_vrrp->iname, ovrrp->iname, name);
				name = NULL;
				break;
			}
		}

		if (!name)
			continue;

		strcpy(current_vrrp->vmac_ifname, name);

		/* Check if the interface exists and is a macvlan we can use */
		if ((ifp = if_get_by_ifname(current_vrrp->vmac_ifname, IF_NO_CREATE)) &&
		    (ifp->if_type != IF_TYPE_MACVLAN ||
		     ifp->vmac_type != MACVLAN_MODE_PRIVATE)) {
			/* ??? also check ADDR_GEN_MODE and VRF enslavement matches parent */
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) interface %s already exists and is not a private macvlan; ignoring vmac if_name", current_vrrp->iname, current_vrrp->vmac_ifname);
			current_vrrp->vmac_ifname[0] = '\0';
		}
	}
}

static void
vrrp_vmac_addr_handler(__attribute__((unused)) const vector_t *strvec)
{
	__set_bit(VRRP_VMAC_ADDR_BIT, &current_vrrp->flags);
}
static void
vrrp_vmac_xmit_base_handler(__attribute__((unused)) const vector_t *strvec)
{
	__set_bit(VRRP_VMAC_XMITBASE_BIT, &current_vrrp->flags);
}
#endif
#ifdef _HAVE_VRRP_IPVLAN_
static void
vrrp_ipvlan_handler(const vector_t *strvec)
{
	vrrp_t *ovrrp;
	interface_t *ifp;
	bool had_flags = false;
	ip_address_t addr = {0};
	size_t i;
	const char *ifname;

	if (__test_bit(VRRP_IPVLAN_BIT, &current_vrrp->flags)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) use_ipvlan already specified", current_vrrp->iname);
		return;
	}

	__set_bit(VRRP_IPVLAN_BIT, &current_vrrp->flags);

	for (i = 1; i < vector_size(strvec); i++) {
		if (!strcmp(strvec_slot(strvec, i), "bridge")) {
			if (had_flags)
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) ipvlan type already specified - ignoring '%s'", current_vrrp->iname, strvec_slot(strvec, i));
			else {
				current_vrrp->ipvlan_type = 0;
				had_flags = true;
			}

			continue;
		}

		if (!strcmp(strvec_slot(strvec, i), "private")) {
			if (had_flags)
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) ipvlan type already specified - ignoring '%s'", current_vrrp->iname, strvec_slot(strvec, i));
			else {
#ifdef IPVLAN_F_PRIVATE
				current_vrrp->ipvlan_type = IPVLAN_F_PRIVATE;
#else
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) kernel doesn't support ipvlan type %s", current_vrrp->iname, strvec_slot(strvec, i));
#endif
				had_flags = true;
			}

			continue;
		}

		if (!strcmp(strvec_slot(strvec, i), "vepa")) {
			if (had_flags)
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) ipvlan type already specified - ignoring '%s'", current_vrrp->iname, strvec_slot(strvec, i));
			else {
#ifdef IPVLAN_F_VEPA
				current_vrrp->ipvlan_type = IPVLAN_F_VEPA;
#else
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) kernel doesn't support ipvlan type %s", current_vrrp->iname, strvec_slot(strvec, i));
#endif
				had_flags = true;
			}

			continue;
		}

#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
		if (!strcmp(strvec_slot(strvec, i), "group")) {
			uint32_t group;
			if (!find_rttables_group(strvec_slot(strvec, ++i), &group)) {
				report_config_error(CONFIG_GENERAL_ERROR, "ipvlan group %s not found", strvec_slot(strvec, i));
				continue;
			}
			__set_bit(VRRP_VMAC_GROUP, &current_vrrp->flags);
			current_vrrp->vmac_group = group;
			continue;
		}
#endif

		if (!strcmp(strvec_slot(strvec, i), "name")) {
			i++;
		} else if (check_valid_ipaddress(strvec_slot(strvec, i), true)) {
			parse_ipaddress(&addr, strvec_slot(strvec, i), true);
			if (current_vrrp->ipvlan_addr) {
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) ipvlan address already specified - ignoring '%s'", current_vrrp->iname, strvec_slot(strvec, i));
				continue;
			}

			if (current_vrrp->family == AF_UNSPEC)
				current_vrrp->family = addr.ifa.ifa_family;
			else if (addr.ifa.ifa_family != current_vrrp->family) {
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) ipvlan address"
						     "[%s] MUST match vrrp instance family !!! Skipping..."
						   , current_vrrp->iname, strvec_slot(strvec, i));
				continue;
			}

			current_vrrp->ipvlan_addr = MALLOC(sizeof(*current_vrrp->ipvlan_addr));
			*current_vrrp->ipvlan_addr = addr;

			/* We also want to use this address as the source address */
			if (current_vrrp->saddr.ss_family == AF_UNSPEC) {
				current_vrrp->saddr.ss_family = current_vrrp->ipvlan_addr->ifa.ifa_family;
				if (current_vrrp->saddr.ss_family == AF_INET)
					PTR_CAST(struct sockaddr_in, &current_vrrp->saddr)->sin_addr = current_vrrp->ipvlan_addr->u.sin.sin_addr;
				else
					PTR_CAST(struct sockaddr_in6, &current_vrrp->saddr)->sin6_addr = current_vrrp->ipvlan_addr->u.sin6_addr;
				__set_bit(VRRP_FLAG_SADDR_FROM_CONFIG, &current_vrrp->flags);
			}

			continue;
		}

		if (current_vrrp->vmac_ifname[0]) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) IPVLAN interface already specified - ignoring '%s'", current_vrrp->iname, strvec_slot(strvec, i));
			continue;
		}

		ifname = strvec_slot(strvec, i);
		if (strlen(ifname) >= IFNAMSIZ) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) IPVLAN interface name '%s' too long - ignoring", current_vrrp->iname, ifname);
			continue;
		}

		/* Check another vrrp instance isn't using this name */
		list_for_each_entry(ovrrp, &vrrp_data->vrrp, e_list) {
			if (!strcmp(ifname, ovrrp->vmac_ifname)) {
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) VRRP instance %s is already using %s - ignoring name", current_vrrp->iname, ovrrp->iname, ifname);
				ifname = NULL;
				break;
			}
		}

		if (!ifname)
			continue;

		strcpy(current_vrrp->vmac_ifname, ifname);

		/* Check if the interface exists and is ipvlan we can use
		   ??? also check ADDR_GEN_MODE and VRF enslavement matches parent */
		if ((ifp = if_get_by_ifname(current_vrrp->vmac_ifname, IF_NO_CREATE)) &&
		    (ifp->if_type != IF_TYPE_IPVLAN ||
		     ifp->vmac_type != IPVLAN_MODE_L2)) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) interface %s already exists and is not an l2 ipvlan; ignoring ipvlan if_name", current_vrrp->iname, current_vrrp->vmac_ifname);
			current_vrrp->vmac_ifname[0] = '\0';
		}
	}
}
#endif
static void
vrrp_unicast_peer_handler(const vector_t *strvec)
{
	__set_bit(VRRP_FLAG_UNICAST_CONFIGURED, &current_vrrp->flags);

	alloc_value_block(alloc_vrrp_unicast_peer, strvec);
}

static void
vrrp_unicast_fault_no_peer(__attribute__((unused)) const vector_t *strvec)
{
	__set_bit(VRRP_FLAG_UNICAST_CONFIGURED, &current_vrrp->flags);
	__set_bit(VRRP_FLAG_UNICAST_FAULT_NO_PEERS, &current_vrrp->flags);
}

static void
vrrp_check_unicast_src_handler(__attribute__((unused)) const vector_t *strvec)
{
	__set_bit(VRRP_FLAG_UNICAST_CONFIGURED, &current_vrrp->flags);

	__set_bit(VRRP_FLAG_CHECK_UNICAST_SRC, &current_vrrp->flags);
}
#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
static void
vrrp_unicast_chksum_handler(const vector_t *strvec)
{
	__set_bit(VRRP_FLAG_UNICAST_CONFIGURED, &current_vrrp->flags);

	if (vector_size(strvec) >= 2) {
		if (!strcmp(strvec_slot(strvec, 1), "never"))
			current_vrrp->unicast_chksum_compat = CHKSUM_COMPATIBILITY_NEVER;
		else
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) Unknown old_unicast_chksum mode %s - ignoring", current_vrrp->iname, strvec_slot(strvec, 1));
	}
	else
		current_vrrp->unicast_chksum_compat = CHKSUM_COMPATIBILITY_CONFIG;
}
#endif
static void
vrrp_native_ipv6_handler(__attribute__((unused)) const vector_t *strvec)
{
	if (current_vrrp->family == AF_INET) {
		report_config_error(CONFIG_GENERAL_ERROR,"(%s) Cannot specify native_ipv6 with IPv4 addresses", current_vrrp->iname);
		return;
	}

	current_vrrp->family = AF_INET6;
	current_vrrp->version = VRRP_VERSION_3;
}
static void
vrrp_state_handler(const vector_t *strvec)
{
	const char *str = strvec_slot(strvec, 1);

	if (!strcmp(str, "MASTER"))
		current_vrrp->wantstate = VRRP_STATE_MAST;
	else if (!strcmp(str, "BACKUP"))
	{
		if (current_vrrp->wantstate == VRRP_STATE_MAST)
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) state previously set as MASTER - ignoring BACKUP", current_vrrp->iname);
		else
			current_vrrp->wantstate = VRRP_STATE_BACK;
	}
	else {
		report_config_error(CONFIG_GENERAL_ERROR,"(%s) unknown state '%s', defaulting to BACKUP", current_vrrp->iname, str);
		current_vrrp->wantstate = VRRP_STATE_BACK;
	}
}
static void
vrrp_int_handler(const vector_t *strvec)
{
	const char *name = strvec_slot(strvec, 1);

	if (strlen(name) >= IFNAMSIZ) {
		report_config_error(CONFIG_GENERAL_ERROR, "Interface name '%s' too long - ignoring", name);
		return;
	}

	current_vrrp->ifp = if_get_by_ifname(name, IF_CREATE_IF_DYNAMIC);
	if (!current_vrrp->ifp)
		report_config_error(CONFIG_GENERAL_ERROR, "WARNING - interface %s for vrrp_instance %s doesn't exist", name, current_vrrp->iname);
	else if (current_vrrp->ifp->hw_type == ARPHRD_LOOPBACK) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) cannot use a loopback interface (%s) for vrrp - ignoring", current_vrrp->iname, current_vrrp->ifp->ifname);
		current_vrrp->ifp = NULL;
	}

#ifdef _HAVE_VRRP_VMAC_
	current_vrrp->configured_ifp = current_vrrp->ifp;
#endif
}

#ifdef _HAVE_VRF_
static void
vrrp_vrf_handler(const vector_t *strvec)
{
	const char *name = strvec_slot(strvec, 1);

	if (strlen(name) >= IFNAMSIZ) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) VRF interface name '%s' too long - ignoring", current_vrrp->iname, name);
		return;
	}

	if (current_vrrp->ifp) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) Cannot specify VRF interface and interface - ignoring", current_vrrp->iname);
		return;
	}

	if (current_vrrp->vrf_ifp) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) VRF interface already specified as '%s' - ignoring", current_vrrp->iname, current_vrrp->vrf_ifp->ifname);
		return;
	}

	current_vrrp->vrf_ifp = if_get_by_ifname(name, IF_CREATE_IF_DYNAMIC);
	if (!current_vrrp->vrf_ifp)
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) WARNING - VRF interface %s doesn't exist", current_vrrp->iname, name);
	else if (current_vrrp->vrf_ifp->hw_type == ARPHRD_LOOPBACK) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) cannot use a loopback interface (%s) for VRF - ignoring", current_vrrp->iname, name);
		current_vrrp->vrf_ifp = NULL;
	}
}
#endif

#ifdef _WITH_LINKBEAT_
static void
vrrp_linkbeat_handler(__attribute__((unused)) const vector_t *strvec)
{
	__set_bit(VRRP_FLAG_LINKBEAT_USE_POLLING, &current_vrrp->flags);
	report_config_error(CONFIG_GENERAL_ERROR, "(%s) 'linkbeat_use_polling' in vrrp instance deprecated - use linkbeat_interfaces block", current_vrrp->iname);
}
#endif
static void
v3_checksum_as_v2(__attribute__((unused)) const vector_t *strvec)
{
	int res;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res >= 0) {
			if (res)
				__set_bit(VRRP_FLAG_V3_CHECKSUM_AS_V2, &current_vrrp->flags);
			else
				__clear_bit(VRRP_FLAG_V3_CHECKSUM_AS_V2, &current_vrrp->flags);
		} else
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) invalid v3_checksum_as_v2 %s specified", current_vrrp->iname, strvec_slot(strvec, 1));
	} else {
		/* Defaults to true if specified */
		__set_bit(VRRP_FLAG_V3_CHECKSUM_AS_V2, &current_vrrp->flags);
	}
}
static void
vrrp_track_if_handler(const vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_track_if, strvec);
}
static void
vrrp_track_scr_handler(const vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_track_script, strvec);
}
static void
vrrp_track_file_handler(const vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_track_file, strvec);
}
#ifdef _WITH_TRACK_PROCESS_
static void
vrrp_track_process_handler(const vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_track_process, strvec);
}
#endif
static void
vrrp_dont_track_handler(__attribute__((unused)) const vector_t *strvec)
{
	__set_bit(VRRP_FLAG_DONT_TRACK_PRIMARY, &current_vrrp->flags);
}
#ifdef _WITH_BFD_
static void
vrrp_track_bfd_handler(const vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_track_bfd, strvec);
}
#endif
static void
vrrp_srcip_handler(const vector_t *strvec)
{
	sockaddr_t *saddr = &current_vrrp->saddr;

	if (inet_stosockaddr(strvec_slot(strvec, 1), NULL, saddr)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: VRRP instance[%s] malformed"
				     " src address[%s]. Skipping..."
				   , current_vrrp->iname, strvec_slot(strvec, 1));
		return;
	}

	__set_bit(VRRP_FLAG_SADDR_FROM_CONFIG, &current_vrrp->flags);

	if (current_vrrp->family == AF_UNSPEC)
		current_vrrp->family = saddr->ss_family;
	else if (saddr->ss_family != current_vrrp->family) {
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: VRRP instance[%s] and src address"
				     "[%s] MUST be of the same family !!! Skipping..."
				   , current_vrrp->iname, strvec_slot(strvec, 1));
		saddr->ss_family = AF_UNSPEC;
		__clear_bit(VRRP_FLAG_SADDR_FROM_CONFIG, &current_vrrp->flags);
	}
}

static void
vrrp_unicast_srcip_handler(const vector_t *strvec)
{
	__set_bit(VRRP_FLAG_UNICAST_CONFIGURED, &current_vrrp->flags);

	vrrp_srcip_handler(strvec);
}

static void
vrrp_mcast_dstip_handler(const vector_t *strvec)
{
	if (inet_stosockaddr(strvec_slot(strvec, 1), NULL, &current_vrrp->mcast_daddr)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) malformed"
				     " mcast dest address %s. Skipping..."
				   , current_vrrp->iname, strvec_slot(strvec, 1));
		return;
	}

	if (current_vrrp->family == AF_UNSPEC)
		current_vrrp->family = current_vrrp->mcast_daddr.ss_family;
	else if (current_vrrp->mcast_daddr.ss_family != current_vrrp->family) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) mcast dest address"
				     " %s MUST match VRRP instance family. Skipping..."
				   , current_vrrp->iname, strvec_slot(strvec, 1));
		current_vrrp->mcast_daddr.ss_family = AF_UNSPEC;
	}

	if ((current_vrrp->mcast_daddr.ss_family == AF_INET && !IN_MULTICAST(htonl(PTR_CAST(struct sockaddr_in, &current_vrrp->mcast_daddr)->sin_addr.s_addr))) ||
	    (current_vrrp->mcast_daddr.ss_family == AF_INET6 && !IN6_IS_ADDR_MC_LINKLOCAL(&PTR_CAST(struct sockaddr_in6, &current_vrrp->mcast_daddr)->sin6_addr))) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) mcast_dst_ip %s not%s multicast. Skipping..."
				   , current_vrrp->iname, strvec_slot(strvec, 1), current_vrrp->mcast_daddr.ss_family == AF_INET6 ? " link-local" : "");
		current_vrrp->mcast_daddr.ss_family = AF_UNSPEC;
	}
}

static void
vrrp_track_srcip_handler(__attribute__((unused)) const vector_t *strvec)
{
	__set_bit(VRRP_FLAG_TRACK_SADDR, &current_vrrp->flags);
}
static void
vrrp_vrid_handler(const vector_t *strvec)
{
	unsigned vrid;

	if (!read_unsigned_strvec(strvec, 1, &vrid, 1, 255, false)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): VRID '%s' not valid - must be between 1 & 255", current_vrrp->iname, strvec_slot(strvec, 1));
		return;
	}

	current_vrrp->vrid = (uint8_t)vrid;
}
static void
vrrp_ttl_handler(const vector_t *strvec)
{
	unsigned ttl;

	if (!read_unsigned_strvec(strvec, 1, &ttl, 0, 255, false)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): TTL '%s' not valid - must be between 0 & 255", current_vrrp->iname, strvec_slot(strvec, 1));
		return;
	}

	current_vrrp->ttl = (uint8_t)ttl;
}
static void
vrrp_prio_handler(const vector_t *strvec)
{
	unsigned base_priority;

	if (!read_unsigned_strvec(strvec, 1, &base_priority, 1, VRRP_PRIO_OWNER, false)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) Priority not valid! must be between 1 & %d. Using default %d", current_vrrp->iname, VRRP_PRIO_OWNER, VRRP_PRIO_DFL);
		current_vrrp->base_priority = VRRP_PRIO_DFL;
	}
	else
		current_vrrp->base_priority = (uint8_t)base_priority;
}
static void
vrrp_adv_handler(const vector_t *strvec)
{
	unsigned adver_int;
	bool res;

	res = read_decimal_unsigned_strvec(strvec, 1, &adver_int, TIMER_HZ / 100, 255 * TIMER_HZ, TIMER_HZ_DIGITS, true);

	/* Simple check - just positive */
	if (!res || adver_int <= 0)
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) Advert interval (%s) not valid! Must be > 0 - ignoring", current_vrrp->iname, strvec_slot(strvec, 1));
	else
		current_vrrp->adver_int = adver_int;
}
static void
vrrp_debug_handler(const vector_t *strvec)
{
	unsigned debug_val;

	if (!read_unsigned_strvec(strvec, 1, &debug_val, 0, 4, true))
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) Debug value '%s' not valid; must be between 0-4", current_vrrp->iname, strvec_slot(strvec, 1));
	else
		current_vrrp->debug = debug_val;
}
static void
vrrp_skip_check_adv_addr_handler(const vector_t *strvec)
{
	int res;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res >= 0)
			__set_bit(VRRP_FLAG_SKIP_CHECK_ADV_ADDR, &current_vrrp->flags);
		else
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) invalid skip_check_adv_addr %s specified", current_vrrp->iname, strvec_slot(strvec, 1));
	} else {
		/* Defaults to true */
		__set_bit(VRRP_FLAG_SKIP_CHECK_ADV_ADDR, &current_vrrp->flags);
	}
}
static void
vrrp_strict_mode_handler(const vector_t *strvec)
{
	int res;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res >= 0)
			current_vrrp->strict_mode = (bool)res;
		else
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) invalid strict_mode %s specified", current_vrrp->iname, strvec_slot(strvec, 1));
	} else {
		/* Defaults to true */
		current_vrrp->strict_mode = true;
	}
}
static void
vrrp_nopreempt_handler(__attribute__((unused)) const vector_t *strvec)
{
	__set_bit(VRRP_FLAG_NOPREEMPT, &current_vrrp->flags);
}
static void	/* backwards compatibility */
vrrp_preempt_handler(__attribute__((unused)) const vector_t *strvec)
{
	__clear_bit(VRRP_FLAG_NOPREEMPT, &current_vrrp->flags);
}
static void
vrrp_preempt_delay_handler(const vector_t *strvec)
{
	unsigned preempt_delay;

	if (!read_decimal_unsigned_strvec(strvec, 1, &preempt_delay, 0, TIMER_MAX_SEC * TIMER_HZ, TIMER_HZ_DIGITS, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) Preempt_delay not valid! must be between 0-%u", current_vrrp->iname, TIMER_MAX_SEC);
		current_vrrp->preempt_delay = 0;
	}
	else
		current_vrrp->preempt_delay = preempt_delay;
}
static void
vrrp_notify_backup_handler(const vector_t *strvec)
{
	if (current_vrrp->script_backup) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) notify_backup script already specified - ignoring %s", current_vrrp->iname, strvec_slot(strvec,1));
		return;
	}
	current_vrrp->script_backup = set_vrrp_notify_script(strvec, 0);
	current_vrrp->notify_exec = true;
}
static void
vrrp_notify_master_handler(const vector_t *strvec)
{
	if (current_vrrp->script_master) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) notify_master script already specified - ignoring %s", current_vrrp->iname, strvec_slot(strvec,1));
		return;
	}
	current_vrrp->script_master = set_vrrp_notify_script(strvec, 0);
	current_vrrp->notify_exec = true;
}
static void
vrrp_notify_fault_handler(const vector_t *strvec)
{
	if (current_vrrp->script_fault) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) notify_fault script already specified - ignoring %s", current_vrrp->iname, strvec_slot(strvec,1));
		return;
	}
	current_vrrp->script_fault = set_vrrp_notify_script(strvec, 0);
	current_vrrp->notify_exec = true;
}
static void
vrrp_notify_stop_handler(const vector_t *strvec)
{
	if (current_vrrp->script_stop) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) notify_stop script already specified - ignoring %s", current_vrrp->iname, strvec_slot(strvec,1));
		return;
	}
	current_vrrp->script_stop = set_vrrp_notify_script(strvec, 0);
	current_vrrp->notify_exec = true;
}
static void
vrrp_notify_deleted_handler(const vector_t *strvec)
{
	if (current_vrrp->notify_deleted) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) notify_deleted already specified - ignoring %s", current_vrrp->iname, vector_size(strvec) > 1 ? strvec_slot(strvec,1) : "");
		return;
	}

	if (vector_size(strvec) > 1) {
		current_vrrp->script_deleted = set_vrrp_notify_script(strvec, 0);
		current_vrrp->notify_exec = true;
	}
	current_vrrp->notify_deleted = true;
}
static void
vrrp_notify_handler(const vector_t *strvec)
{
	if (current_vrrp->script) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) notify script already specified - ignoring %s", current_vrrp->iname, strvec_slot(strvec,1));
		return;
	}
	current_vrrp->script = set_vrrp_notify_script(strvec, 4);
	current_vrrp->notify_exec = true;
}
static void
vrrp_notify_master_rx_lower_pri(const vector_t *strvec)
{
	if (current_vrrp->script_master_rx_lower_pri) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) notify_master_rx_lower_pri script already specified - ignoring %s", current_vrrp->iname, strvec_slot(strvec,1));
		return;
	}
	current_vrrp->script_master_rx_lower_pri = set_vrrp_notify_script(strvec, 0);
	current_vrrp->notify_exec = true;
}
static void
vrrp_smtp_handler(__attribute__((unused)) const vector_t *strvec)
{
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res == -1) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid vrrp_instance smtp_alert parameter %s", strvec_slot(strvec, 1));
			return;
		}
	}
	current_vrrp->smtp_alert = res;
	vrrp_data->num_smtp_alert++;
}
static void
vrrp_notify_priority_changes_handler(const vector_t *strvec)
{
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) Invalid value '%s' for notify_priority_changes specified", current_vrrp->iname, strvec_slot(strvec, 1));
			return;
		}
	}

	current_vrrp->notify_priority_changes = res;
}
#ifdef _WITH_LVS_
static void
vrrp_lvs_syncd_handler(const vector_t *strvec)
{
	report_config_error(CONFIG_GENERAL_ERROR, "(%s) Specifying lvs_sync_daemon_interface against a vrrp is deprecated.", current_vrrp->iname);  /* Deprecated after v1.2.19 */
	report_config_error(CONFIG_GENERAL_ERROR, "      %*sPlease use global lvs_sync_daemon", (int)strlen(current_vrrp->iname) - 2, "");

	if (global_data->lvs_syncd.ifname) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) lvs_sync_daemon_interface has already been specified as %s - ignoring", current_vrrp->iname, global_data->lvs_syncd.ifname);
		return;
	}

	global_data->lvs_syncd.ifname = set_value(strvec);
	global_data->lvs_syncd.vrrp = current_vrrp;
}
#endif
static void
vrrp_garp_delay_handler(const vector_t *strvec)
{
	unsigned delay;

	if (!read_unsigned_strvec(strvec, 1, &delay, 0, UINT_MAX / TIMER_HZ, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): garp_master_delay '%s' invalid - ignoring", current_vrrp->iname, strvec_slot(strvec, 1));
		return;
	}

	current_vrrp->garp_delay = delay * TIMER_HZ;
}
static void
vrrp_garp_refresh_handler(const vector_t *strvec)
{
	unsigned refresh;

	if (!read_unsigned_strvec(strvec, 1, &refresh, 0, UINT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): Invalid garp_master_refresh '%s' - ignoring", current_vrrp->iname, strvec_slot(strvec, 1));
		current_vrrp->garp_refresh.tv_sec = 0;
	}
	else
		current_vrrp->garp_refresh.tv_sec = refresh;
	current_vrrp->garp_refresh.tv_usec = 0;
}
static void
vrrp_garp_rep_handler(const vector_t *strvec)
{
	unsigned repeats;

	/* The min value should be 1, but allow 0 to maintain backward compatibility
	 * with pre v2.0.7 */
	if (!read_unsigned_strvec(strvec, 1, &repeats, 0, UINT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): garp_master_repeat '%s' invalid - ignoring", current_vrrp->iname, strvec_slot(strvec, 1));
		return;
	}

	if (repeats == 0) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): garp_master_repeat must be greater than 0, setting to 1", current_vrrp->iname);
		repeats = 1;
	}

	current_vrrp->garp_rep = repeats;
}
static void
vrrp_garp_refresh_rep_handler(const vector_t *strvec)
{
	unsigned repeats;

	/* The min value should be 1, but allow 0 to maintain backward compatibility
	 * with pre v2.0.7 */
	if (!read_unsigned_strvec(strvec, 1, &repeats, 0, UINT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): garp_master_refresh_repeat '%s' invalid - ignoring", current_vrrp->iname, strvec_slot(strvec, 1));
		return;
	}

	if (repeats == 0) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): garp_master_refresh_repeat must be greater than 0, setting to 1", current_vrrp->iname);
		repeats = 1;
	}

	current_vrrp->garp_refresh_rep = repeats;
}

static void
vrrp_garp_lower_prio_delay_handler(const vector_t *strvec)
{
	unsigned delay;

	if (!read_unsigned_strvec(strvec, 1, &delay, 0, UINT_MAX / TIMER_HZ, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): garp_lower_prio_delay '%s' invalid - ignoring", current_vrrp->iname, strvec_slot(strvec, 1));
		return;
	}

	current_vrrp->garp_lower_prio_delay = delay * TIMER_HZ;
}
static void
vrrp_garp_lower_prio_rep_handler(const vector_t *strvec)
{
	unsigned garp_lower_prio_rep;

	if (!read_unsigned_strvec(strvec, 1, &garp_lower_prio_rep, 0, INT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): Invalid garp_lower_prio_repeat '%s'", current_vrrp->iname, strvec_slot(strvec, 1));
		return;
	}

	current_vrrp->garp_lower_prio_rep = garp_lower_prio_rep;
}
static void
vrrp_down_timer_adverts_handler(const vector_t *strvec)
{
	unsigned down_timer_adverts;

	if (!read_unsigned_strvec(strvec, 1, &down_timer_adverts, 1, 100, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): Invalid down_timer_adverts [1:100] '%s'", current_vrrp->iname, strvec_slot(strvec, 1));
		return;
	}

	current_vrrp->down_timer_adverts = down_timer_adverts;
}
static void
vrrp_timer_expired_backup_handler(const vector_t *strvec)
{
	unsigned other_priority = VRRP_PRIO_OWNER - 1;	/* default to shortest duration for another instance to take over */

	if (vector_size(strvec) >= 2) {
		if (!read_unsigned_strvec(strvec, 1, &other_priority, 1, VRRP_PRIO_OWNER - 1, false)) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) timer_expired _backup highest_other_priority not valid! must be between 1 & %d", current_vrrp->iname, VRRP_PRIO_OWNER - 1);
			return;
		}
	}

	current_vrrp->highest_other_priority = (uint8_t)other_priority;
}
#ifdef _HAVE_VRRP_VMAC_
static void
vrrp_garp_extra_if_handler(const vector_t *strvec)
{
	unsigned delay = UINT_MAX;
	unsigned index;
	const char *cmd_name = strvec_slot(strvec, 0);

	if (!strcmp(cmd_name, "vmac_garp_intvl")) {
		/* Deprecated after v2.2.2 */
		report_config_error(CONFIG_DEPRECATED, "Keyword \"vmac_garp_intvl\" is deprecated - please use \"garp_extra_if\"");
	}

	for (index = 1; index < vector_size(strvec); index++) {
		if (!strcmp(strvec_slot(strvec, index), "all"))
			__set_bit(VRRP_FLAG_VMAC_GARP_ALL_IF, &current_vrrp->flags);
		else if (!read_unsigned_strvec(strvec, index, &delay, 0, 86400, true)) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s): %s '%s' invalid - ignoring", current_vrrp->iname, cmd_name, strvec_slot(strvec, index));
			return;
		}
	}

	if (delay == UINT_MAX) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): %s specified without time - ignoring", current_vrrp->iname, cmd_name);
		return;
	}

	current_vrrp->vmac_garp_intvl.tv_sec = delay;
	current_vrrp->vmac_garp_intvl.tv_usec = 0;
}
#endif
static void
vrrp_lower_prio_no_advert_handler(const vector_t *strvec)
{
	int res;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res >= 0)
			current_vrrp->lower_prio_no_advert = (unsigned)res;
		else
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) invalid lower_prio_no_advert %s specified", current_vrrp->iname, strvec_slot(strvec, 1));
	} else {
		/* Defaults to true */
		current_vrrp->lower_prio_no_advert = true;
	}
}

static void
vrrp_higher_prio_send_advert_handler(const vector_t *strvec)
{
	int res;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res >= 0)
			current_vrrp->higher_prio_send_advert = (unsigned)res;
		else
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) invalid higher_prio_send_advert %s specified", current_vrrp->iname, strvec_slot(strvec, 1));
	} else {
		/* Defaults to true */
		current_vrrp->higher_prio_send_advert = true;
	}
}


static void
kernel_rx_buf_size_handler(const vector_t *strvec)
{
	unsigned rx_buf_size;

	if (vector_size(strvec) == 2 &&
	    read_unsigned_strvec(strvec, 1, &rx_buf_size, 0, UINT_MAX, false)) {
		current_vrrp->kernel_rx_buf_size = rx_buf_size;
		return;
	}

	report_config_error(CONFIG_GENERAL_ERROR, "(%s) invalid kernel_rx_buf_size specified", current_vrrp->iname);
}

#if defined _WITH_VRRP_AUTH_
static void
vrrp_auth_type_handler(const vector_t *strvec)
{
	const char *str = strvec_slot(strvec, 1);

	if (!strcmp(str, "AH"))
		current_vrrp->auth_type = VRRP_AUTH_AH;
	else if (!strcmp(str, "PASS"))
		current_vrrp->auth_type = VRRP_AUTH_PASS;
	else
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown authentication type '%s'", current_vrrp->iname, str);
}
static void
vrrp_auth_pass_handler(const vector_t *strvec)
{
	const char *str = strvec_slot(strvec, 1);
	size_t max_size = sizeof (current_vrrp->auth_data);
	size_t str_len = strlen(str);

	if (str_len > max_size) {
		str_len = max_size;
		report_config_error(CONFIG_GENERAL_ERROR,
			    "Truncating auth_pass to %zu characters", max_size);
	}

	memset(current_vrrp->auth_data, 0, max_size);
	memcpy(current_vrrp->auth_data, str, str_len);
}
#endif
static void
vrrp_vip_handler(const vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_vip, strvec);
}
static void
vrrp_evip_handler(const vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_evip, strvec);
}
static void
vrrp_no_vip_handler(__attribute__((unused)) const vector_t *strvec)
{
	__set_bit(VRRP_FLAG_ALLOW_NO_VIPS, &current_vrrp->flags);
}
static void
vrrp_promote_secondaries_handler(__attribute__((unused)) const vector_t *strvec)
{
	__set_bit(VRRP_FLAG_PROMOTE_SECONDARIES, &current_vrrp->flags);
}
static void
vrrp_vroutes_handler(const vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_vroute, strvec);
}
static void
vrrp_vrules_handler(const vector_t *strvec)
{
	alloc_value_block(alloc_vrrp_vrule, strvec);
}
static void
vrrp_script_handler(const vector_t *strvec)
{
	if (!strvec)
		return;

	current_vscr = alloc_vrrp_script(strvec_slot(strvec, 1));
	script_user_set = false;
	remove_script = false;
}
static void
vrrp_vscript_script_handler(__attribute__((unused)) const vector_t *strvec)
{
	const vector_t *strvec_qe;

	/* We need to allow quoted and escaped strings for the script and parameters */
	strvec_qe = alloc_strvec_quoted_escaped(NULL);

	set_script_params_array(strvec_qe, &current_vscr->script, 0);
	free_strvec(strvec_qe);
}
static void
vrrp_vscript_interval_handler(const vector_t *strvec)
{
	unsigned interval;

	/* The min value should be 1, but allow 0 to maintain backward compatibility
	 * with pre v2.0.7 */
	if (!read_unsigned_strvec(strvec, 1, &interval, 0, UINT_MAX / TIMER_HZ, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): vrrp script interval '%s' must be between 1 and %u - ignoring", current_vscr->sname, strvec_slot(strvec, 1), UINT_MAX / TIMER_HZ);
		return;
	}

	if (interval == 0) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): vrrp script interval must be greater than 0, setting to 1", current_vscr->sname);
		interval = 1;
	}

	current_vscr->interval = interval * TIMER_HZ;
}
static void
vrrp_vscript_timeout_handler(const vector_t *strvec)
{
	unsigned timeout;

	/* The min value should be 1, but allow 0 to maintain backward compatibility
	 * with pre v2.0.7 */
	if (!read_unsigned_strvec(strvec, 1, &timeout, 0, UINT_MAX / TIMER_HZ, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): vrrp script timeout '%s' invalid - ignoring", current_vscr->sname, strvec_slot(strvec, 1));
		return;
	}

	if (timeout == 0) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): vrrp script timeout must be greater than 0, setting to 1", current_vscr->sname);
		timeout = 1;
	}

	current_vscr->timeout = timeout * TIMER_HZ;
}
static void
vrrp_vscript_weight_handler(const vector_t *strvec)
{
	int weight;

	if (!read_int_strvec(strvec, 1, &weight, -253, 253, true))
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp_script %s weight %s must be in [-253, 253]", current_vscr->sname, strvec_slot(strvec, 1));
	current_vscr->weight = weight;

	if (vector_size(strvec) >= 3) {
		if (!strcmp(strvec_slot(strvec, 2), "reverse"))
			current_vscr->weight_reverse = true;
		else
			report_config_error(CONFIG_GENERAL_ERROR, "vrrp_script %s unknown weight option %s", current_vscr->sname, strvec_slot(strvec, 2));
	}
}
static void
vrrp_vscript_rise_handler(const vector_t *strvec)
{
	unsigned rise;

	if (!read_unsigned_strvec(strvec, 1, &rise, 1, INT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): vrrp script rise value '%s' invalid, defaulting to 1", current_vscr->sname, strvec_slot(strvec, 1));
		current_vscr->rise = 1;
	}
	else
		current_vscr->rise = rise;
}
static void
vrrp_vscript_fall_handler(const vector_t *strvec)
{
	unsigned fall;

	if (!read_unsigned_strvec(strvec, 1, &fall, 1, INT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): vrrp script fall value '%s' invalid, defaulting to 1", current_vscr->sname, strvec_slot(strvec, 1));
		current_vscr->fall = 1;
	}
	else
		current_vscr->fall = fall;
}
static void
vrrp_vscript_user_handler(const vector_t *strvec)
{
	if (set_script_uid_gid(strvec, 1, &current_vscr->script.uid, &current_vscr->script.gid)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Unable to set uid/gid for script %s"
							, cmd_str(&current_vscr->script));
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
	if (!current_vscr->script.args || !current_vscr->script.args[0]) {
		report_config_error(CONFIG_GENERAL_ERROR, "No script set for vrrp_script %s - removing"
							, current_vscr->sname);
		remove_script = true;
	}
	else if (!remove_script && !script_user_set) {
		if (get_default_script_user(&current_vscr->script.uid, &current_vscr->script.gid)) {
			report_config_error(CONFIG_GENERAL_ERROR, "Unable to set default user for vrrp"
								  " script %s - removing"
								, current_vscr->sname);
			remove_script = true;
		}
	}

	if (remove_script) {
		free_vscript(current_vscr);
		return;
	}

	list_add_tail(&current_vscr->e_list, &vrrp_data->vrrp_script);
}

#ifdef _WITH_TRACK_PROCESS_
static void
vrrp_tprocess_handler(const vector_t *strvec)
{
	if (!strvec)
		return;

	if (proc_events_not_supported)
		report_config_error(CONFIG_GENERAL_ERROR, "no kernel support for track_process (CONFIG_PROC_EVENTS)");

	current_tp = alloc_vrrp_process(strvec_slot(strvec, 1));
}
static void
vrrp_tprocess_process_handler(const vector_t *strvec)
{
	size_t len = 0;
	size_t i;
	char *p;

	if (current_tp->process_path) {
		report_config_error(CONFIG_GENERAL_ERROR, "Process already set for track process %s"
							   " - ignoring %s"
							, current_tp->pname, strvec_slot(strvec, 1));
		return;
	}

	current_tp->process_path = set_value(strvec);

	if (vector_size(strvec) > 2) {
		for (i = 2; i < vector_size(strvec); i++)
			len += strlen(strvec_slot(strvec, i)) + 1;

		current_tp->process_params = p = MALLOC(len);
		current_tp->process_params_len = len;
		for (i = 2; i < vector_size(strvec); i++) {
			strcpy(p, strvec_slot(strvec, i));
			p += strlen(strvec_slot(strvec, i)) + 1;
		}

		if (current_tp->param_match == PARAM_MATCH_NONE)
			current_tp->param_match = PARAM_MATCH_EXACT;

		current_tp->full_command = true;
	}

	len += strlen(current_tp->process_path) + 1;
	if (len > vrrp_data->vrrp_max_process_name_len)
		vrrp_data->vrrp_max_process_name_len = len;
}
static void
vrrp_tprocess_match_handler(const vector_t *strvec)
{
	if (vector_size(strvec) == 1) {
		current_tp->param_match = PARAM_MATCH_EXACT;
		current_tp->full_command = true;
	} else if (!strcmp(strvec_slot(strvec, 1), "initial")) {
		current_tp->param_match = PARAM_MATCH_INITIAL;
		current_tp->full_command = true;
	} else if (!strcmp(strvec_slot(strvec, 1), "partial")) {
		current_tp->param_match = PARAM_MATCH_PARTIAL;
		current_tp->full_command = true;
	} else
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid param_match type %s - ignoring", strvec_slot(strvec, 1));
}
static void
vrrp_tprocess_weight_handler(const vector_t *strvec)
{
	int weight;

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "No weight specified for track process %s - ignoring", current_tp->pname);
		return;
	}

	if (current_tp->weight) {
		report_config_error(CONFIG_GENERAL_ERROR, "Weight already set for track process %s - ignoring %s", current_tp->pname, strvec_slot(strvec, 1));
		return;
	}

	if (!read_int_strvec(strvec, 1, &weight, -254, 254, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Weight (%s) for vrrp_track_process %s must be between "
				 "[-254..254] inclusive. Ignoring...", strvec_slot(strvec, 1), current_tp->pname);
		return;
	}

	if (vector_size(strvec) >= 3) {
		if (!strcmp(strvec_slot(strvec, 2), "reverse"))
			current_tp->weight_reverse = true;
		else
			report_config_error(CONFIG_GENERAL_ERROR, "vrrp_track_process %s unknown weight option %s", current_tp->pname, strvec_slot(strvec, 2));
	}

	current_tp->weight = weight;
}
static void
vrrp_tprocess_quorum_handler(const vector_t *strvec)
{
	unsigned quorum;

	if (!read_unsigned_strvec(strvec, 1, &quorum, 1, 65535, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Quorum (%s) for vrrp_track_process %s must be between "
				 "[1..65535] inclusive. Ignoring...", strvec_slot(strvec, 1), current_tp->pname);
		return;
	}

	if (quorum > current_tp->quorum_max) {
		report_config_error(CONFIG_GENERAL_ERROR, "Quorum is greater than quorum_max - ignoring");
		return;
	}

	current_tp->quorum = quorum;
}
static void
vrrp_tprocess_quorum_max_handler(const vector_t *strvec)
{
	unsigned quorum_max;

	if (!read_unsigned_strvec(strvec, 1, &quorum_max, 0, 65535, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "quorum_max (%s) for vrrp_track_process %s must be between "
				 "[0..65535] inclusive. Ignoring...", strvec_slot(strvec, 1), current_tp->pname);
		return;
	}

	/* Allow quorum_max = 0 if quorum not specified */
	if (quorum_max || current_tp->quorum > 1) {
		if (quorum_max < current_tp->quorum) {
			report_config_error(CONFIG_GENERAL_ERROR, "quorum_max is less than quorum - ignoring");
			return;
		}
	}

	current_tp->quorum_max = quorum_max;
	if (quorum_max == 0)
		current_tp->quorum = 0;
	else if (!current_tp->quorum)
		current_tp->quorum = 1;
}
static void
vrrp_tprocess_delay_general(const vector_t *strvec, enum process_delay delay_type)
{
	unsigned delay;

	if (!read_decimal_unsigned_strvec(strvec, 1, &delay, 1, 3600U * TIMER_HZ, TIMER_HZ_DIGITS, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "%sdelay (%s) for vrrp_track_process %s must be between "
							  "[0.000001..3600] inclusive. Ignoring..."
							, delay_type == PROCESS_TERMINATE_DELAY ? "terminate_" :
							   delay_type == PROCESS_FORK_DELAY ? "fork_" : ""
							, strvec_slot(strvec, 1), current_tp->pname);
		return;
	}

	if (delay_type != PROCESS_FORK_DELAY)
		current_tp->terminate_delay = delay;
	if (delay_type != PROCESS_TERMINATE_DELAY)
		current_tp->fork_delay = delay;
}
static void
vrrp_tprocess_terminate_delay_handler(const vector_t *strvec)
{
	vrrp_tprocess_delay_general(strvec, PROCESS_TERMINATE_DELAY);
}
static void
vrrp_tprocess_fork_delay_handler(const vector_t *strvec)
{
	vrrp_tprocess_delay_general(strvec, PROCESS_FORK_DELAY);
}
static void
vrrp_tprocess_delay_handler(const vector_t *strvec)
{
	vrrp_tprocess_delay_general(strvec, PROCESS_DELAY);
}
static void
vrrp_tprocess_full_handler(__attribute__((unused)) const vector_t *strvec)
{
	current_tp->full_command = true;
}
static void
vrrp_tprocess_end_handler(void)
{
	if (proc_events_not_supported) {
		free_vprocess(current_tp);
		return;
	}

	if (!current_tp->process_path) {
		report_config_error(CONFIG_GENERAL_ERROR, "track process '%s' process name not specified"
							, current_tp->pname);
		free_vprocess(current_tp);
		return;
	}

	if (current_tp->full_command)
		vrrp_data->vrrp_use_process_cmdline = true;
	else
		vrrp_data->vrrp_use_process_comm = true;

	list_add_tail(&current_tp->e_list, &vrrp_data->vrrp_track_processes);
}
#endif
static void
vrrp_vscript_init_fail_handler(__attribute__((unused)) const vector_t *strvec)
{
	current_vscr->init_state = SCRIPT_INIT_STATE_FAILED;
}
static void
vrrp_version_handler(const vector_t *strvec)
{
	int version;

	if (!read_int_strvec(strvec, 1, &version, 2, 3, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s): Version must be either 2 or 3"
							, current_vrrp->iname);
		return;
	}

	if ((current_vrrp->version && current_vrrp->version != version) ||
	    (version == VRRP_VERSION_2 && current_vrrp->family == AF_INET6)) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) vrrp_version %d conflicts with configured"
							  " or deduced version %d; ignoring."
							, current_vrrp->iname, version, current_vrrp->version);
		return;
	}

	current_vrrp->version = version;
}

static void
vrrp_accept_handler(__attribute__((unused)) const vector_t *strvec)
{
#ifdef _WITH_FIREWALL_
	current_vrrp->accept = true;
#endif
}

#ifdef _WITH_FIREWALL_
static void
vrrp_no_accept_handler(__attribute__((unused)) const vector_t *strvec)
{
	current_vrrp->accept = false;
}
#endif

static void
garp_group_handler(const vector_t *strvec)
{
	if (!strvec)
		return;

	current_ggd = alloc_garp_delay();
}
static void
garp_group_garp_interval_handler(const vector_t *strvec)
{
	unsigned val;

	if (!read_decimal_unsigned_strvec(strvec, 1, &val, 0, INT_MAX, TIMER_HZ_DIGITS, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "garp_group garp_interval '%s' invalid", strvec_slot(strvec, 1));
		return;
	}

	current_ggd->garp_interval.tv_sec = (time_t)val / TIMER_HZ;
	current_ggd->garp_interval.tv_usec = (suseconds_t)(val % TIMER_HZ);
	current_ggd->have_garp_interval = true;

	if (current_ggd->garp_interval.tv_sec >= 1)
		log_message(LOG_INFO, "The garp_interval is very large - %s seconds", strvec_slot(strvec,1));
}
static void
garp_group_gna_interval_handler(const vector_t *strvec)
{
	unsigned val;

	if (!read_decimal_unsigned_strvec(strvec, 1, &val, 0, INT_MAX, TIMER_HZ_DIGITS, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "garp_group gna_interval '%s' invalid", strvec_slot(strvec, 1));
		return;
	}

	current_ggd->gna_interval.tv_sec = (time_t)val / TIMER_HZ;
	current_ggd->gna_interval.tv_usec = (suseconds_t)(val % TIMER_HZ);
	current_ggd->have_gna_interval = true;

	if (current_ggd->gna_interval.tv_sec >= 1)
		log_message(LOG_INFO, "The gna_interval is very large - %s seconds", strvec_slot(strvec,1));
}
static void
garp_group_interface_handler(const vector_t *strvec)
{
	interface_t *ifp = if_get_by_ifname(strvec_slot(strvec, 1), IF_CREATE_IF_DYNAMIC);
	if (!ifp) {
		report_config_error(CONFIG_GENERAL_ERROR, "WARNING - interface %s specified for garp_group doesn't exist", strvec_slot(strvec, 1));
		return;
	}

	if (ifp->garp_delay) {
		report_config_error(CONFIG_GENERAL_ERROR, "garp_group already specified for %s - ignoring", strvec_slot(strvec, 1));
		return;
	}

#ifdef _HAVE_VRRP_VMAC_
	/* We cannot have a group on a vmac interface */
	if (IS_MAC_IP_VLAN(ifp)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify garp_delay on a vmac (%s) - ignoring", ifp->ifname);
		return;
	}
#endif
	ifp->garp_delay = current_ggd;
}
static void
garp_group_interfaces_handler(const vector_t *strvec)
{
	interface_t *ifp;
	const vector_t *interface_vec = read_value_block(strvec);
	garp_delay_t *gd;
	size_t i;

	/* Handle the interfaces block being empty */
	if (!interface_vec) {
		report_config_error(CONFIG_GENERAL_ERROR, "Warning - empty garp_group interfaces block");
		return;
	}

	/* First set the next aggregation group number */
	current_ggd->aggregation_group = 1;
	list_for_each_entry(gd, &garp_delay, e_list) {
		if (gd->aggregation_group && gd != current_ggd)
			current_ggd->aggregation_group++;
	}

	for (i = 0; i < vector_size(interface_vec); i++) {
		ifp = if_get_by_ifname(vector_slot(interface_vec, i), IF_CREATE_IF_DYNAMIC);
		if (!ifp) {
			if (global_data->dynamic_interfaces)
				log_message(LOG_INFO, "WARNING - interface %s specified for garp_group doesn't exist", strvec_slot(interface_vec, i));
			else
				report_config_error(CONFIG_GENERAL_ERROR, "WARNING - interface %s specified for garp_group doesn't exist", strvec_slot(interface_vec, i));
			continue;
		}

		if (ifp->garp_delay) {
			report_config_error(CONFIG_GENERAL_ERROR, "garp_group already specified for %s - ignoring", strvec_slot(interface_vec, 1));
			continue;
		}

#ifdef _HAVE_VRRP_VMAC_
		if (IS_MAC_IP_VLAN(ifp)) {
			report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify garp_delay on a vmac (%s) - ignoring", ifp->ifname);
			continue;
		}
#endif
		ifp->garp_delay = current_ggd;
	}

	free_strvec(interface_vec);
}
static void
garp_group_end_handler(void)
{
	interface_t *ifp;
	list_head_t *ifq;

	if (!current_ggd->have_garp_interval && !current_ggd->have_gna_interval) {
		report_config_error(CONFIG_GENERAL_ERROR, "garp group %d does not have any delay set - removing", current_ggd->aggregation_group);

		/* Remove the garp_delay from any interfaces that are using it */
		ifq = get_interface_queue();
		list_for_each_entry(ifp, ifq, e_list) {
			if (ifp->garp_delay == current_ggd)
				ifp->garp_delay = NULL;
		}

		free_garp_delay(current_ggd);
	}
}

static void
alloc_if_up_down_delay(const vector_t *strvec)
{
	unsigned down_delay = 0;
	unsigned up_delay = 0;
	int res;
	unsigned long delay;
	interface_t *ifp;

	if (!(ifp = if_get_by_ifname(strvec_slot(strvec, 0), global_data->dynamic_interfaces))) {
		report_config_error(CONFIG_FATAL, "unknown interface %s specified for up/down delay", strvec_slot(strvec, 0));
		return;
	}

	if (vector_size(strvec) < 2) {
		log_message(LOG_INFO, "No timeouts specified for %s up/down delays", ifp->ifname);
		return;
	}
	if (vector_size(strvec) > 3)
		log_message(LOG_INFO, "Too many parameters for %s up/down delays", ifp->ifname);

	res = read_timer(strvec, 1, &delay, 0, 255 * TIMER_HZ, true);
	if (!res) {
		log_message(LOG_INFO, "Invalid down delay %s for %s", strvec_slot(strvec, 1), ifp->ifname);
		return;
	}
	down_delay = (unsigned)delay;

	if (vector_size(strvec) == 2)
		up_delay = 0;
	else {
		res = read_timer(strvec, 2, &delay, 0, 255 * TIMER_HZ, true);
		if (!res) {
			log_message(LOG_INFO, "Invalid up delay %s for %s", strvec_slot(strvec, 2), ifp->ifname);
			return;
		}
		up_delay = (unsigned)delay;
	}

	ifp->down_debounce_timer = down_delay;
	ifp->up_debounce_timer = up_delay;
}

/* interface state change delays handler */
static void
interface_up_down_delays_handler(const vector_t *strvec)
{
	if (!strvec)
		return;

	alloc_value_block(alloc_if_up_down_delay, strvec);
}

void
init_vrrp_keywords(bool active)
{
#if defined _WITH_VRRP_AUTH_
	vpp_t check_ptr;
#endif

	/* Track group declarations */
	install_keyword_root("track_group", &static_track_group_handler, active, VPP &current_stg);
	install_keyword("group", &static_track_group_group_handler);
	install_level_end_handler(&static_track_group_end_handler);

	/* Static addresses/routes/rules declarations */
	install_keyword_root("static_ipaddress", &static_addresses_handler, active, NULL);
	install_keyword_root("static_routes", &static_routes_handler, active, NULL);
	install_keyword_root("static_rules", &static_rules_handler, active, NULL);

	/* Sync group declarations */
	install_keyword_root("vrrp_sync_group", &vrrp_sync_group_handler, active, VPP &current_vsyncg);
	install_keyword("group", &vrrp_group_handler);
	install_keyword("track_interface", &vrrp_group_track_if_handler);
	install_keyword("track_script", &vrrp_group_track_scr_handler);
	install_keyword("track_file", &vrrp_group_track_file_handler);
#ifdef _WITH_TRACK_PROCESS_
	install_keyword("track_process", &vrrp_group_track_process_handler);
#endif
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
	install_keyword("notify_priority_changes", &vrrp_sg_notify_priority_changes_handler);
	install_level_end_handler(&vrrp_sync_group_end_handler);

	/* Garp declarations */
	install_keyword_root("garp_group", &garp_group_handler, active, VPP &current_ggd);
	install_keyword("garp_interval", &garp_group_garp_interval_handler);
	install_keyword("gna_interval", &garp_group_gna_interval_handler);
	install_keyword("interface", &garp_group_interface_handler);
	install_keyword("interfaces", &garp_group_interfaces_handler);
	install_level_end_handler(&garp_group_end_handler);

#ifdef _WITH_LINKBEAT_
	/* Linkbeat interfaces */
	install_keyword_root("linkbeat_interfaces", &linkbeat_interfaces_handler, active, NULL);
#endif

	/* VRRP Instance declarations */
	install_keyword_root("vrrp_instance", &vrrp_handler, active, VPP &current_vrrp);
	install_level_end_handler(&vrrp_end_handler);
#ifdef _HAVE_VRRP_VMAC_
	install_keyword("use_vmac", &vrrp_vmac_handler);
	install_keyword("use_vmac_addr", &vrrp_vmac_addr_handler);
	install_keyword("vmac_xmit_base", &vrrp_vmac_xmit_base_handler);
#endif
#ifdef _HAVE_VRRP_IPVLAN_
	install_keyword("use_ipvlan", &vrrp_ipvlan_handler);
#endif
	install_keyword("unicast_peer", &vrrp_unicast_peer_handler);
	install_keyword("unicast_fault_no_peer", &vrrp_unicast_fault_no_peer);
	install_keyword("check_unicast_src", &vrrp_check_unicast_src_handler);
#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
	install_keyword("old_unicast_checksum", &vrrp_unicast_chksum_handler);
#endif
	install_keyword("native_ipv6", &vrrp_native_ipv6_handler);
	install_keyword("state", &vrrp_state_handler);
	install_keyword("interface", &vrrp_int_handler);
#ifdef _HAVE_VRF_
	install_keyword("vrf", &vrrp_vrf_handler);
#endif
	install_keyword("dont_track_primary", &vrrp_dont_track_handler);
	install_keyword("track_interface", &vrrp_track_if_handler);
	install_keyword("track_script", &vrrp_track_scr_handler);
	install_keyword("track_file", &vrrp_track_file_handler);
#ifdef _WITH_TRACK_PROCESS_
	install_keyword("track_process", &vrrp_track_process_handler);
#endif
#ifdef _WITH_BFD_
	install_keyword("track_bfd", &vrrp_track_bfd_handler);
#endif
	install_keyword("mcast_src_ip", &vrrp_srcip_handler);
	install_keyword("unicast_src_ip", &vrrp_unicast_srcip_handler);
	install_keyword("mcast_dst_ip", &vrrp_mcast_dstip_handler);
	install_keyword("track_src_ip", &vrrp_track_srcip_handler);
	install_keyword("virtual_router_id", &vrrp_vrid_handler);
	install_keyword("unicast_ttl", &vrrp_ttl_handler);
	install_keyword("version", &vrrp_version_handler);
	install_keyword("priority", &vrrp_prio_handler);
	install_keyword("advert_int", &vrrp_adv_handler);
	install_keyword("virtual_ipaddress", &vrrp_vip_handler);
	install_keyword("virtual_ipaddress_excluded", &vrrp_evip_handler);
	install_keyword("no_virtual_ipaddress", &vrrp_no_vip_handler);
	install_keyword("promote_secondaries", &vrrp_promote_secondaries_handler);
#ifdef _WITH_LINKBEAT_
	install_keyword("linkbeat_use_polling", &vrrp_linkbeat_handler);
#endif
	install_keyword("v3_checksum_as_v2", &v3_checksum_as_v2);
	install_keyword("virtual_routes", &vrrp_vroutes_handler);
	install_keyword("virtual_rules", &vrrp_vrules_handler);
	install_keyword("accept", &vrrp_accept_handler);
#ifdef _WITH_FIREWALL_
	install_keyword("no_accept", &vrrp_no_accept_handler);
#endif
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
	install_keyword("notify_deleted", &vrrp_notify_deleted_handler);
	install_keyword("notify", &vrrp_notify_handler);
	install_keyword("notify_master_rx_lower_pri", vrrp_notify_master_rx_lower_pri);
	install_keyword("smtp_alert", &vrrp_smtp_handler);
	install_keyword("notify_priority_changes", &vrrp_notify_priority_changes_handler);
#ifdef _WITH_LVS_
	install_keyword("lvs_sync_daemon_interface", &vrrp_lvs_syncd_handler);
#endif
	install_keyword("garp_master_delay", &vrrp_garp_delay_handler);
	install_keyword("garp_master_refresh", &vrrp_garp_refresh_handler);
	install_keyword("garp_master_repeat", &vrrp_garp_rep_handler);
	install_keyword("garp_master_refresh_repeat", &vrrp_garp_refresh_rep_handler);
	install_keyword("garp_lower_prio_delay", &vrrp_garp_lower_prio_delay_handler);
	install_keyword("garp_lower_prio_repeat", &vrrp_garp_lower_prio_rep_handler);
	install_keyword("down_timer_adverts", &vrrp_down_timer_adverts_handler);
	install_keyword("timer_expired_backup", &vrrp_timer_expired_backup_handler);
#ifdef _HAVE_VRRP_VMAC_
	install_keyword("garp_extra_if", &vrrp_garp_extra_if_handler);
	install_keyword("vmac_garp_intvl", &vrrp_garp_extra_if_handler);	/* Deprecated after v2.2.2 - incorrect keyword in commit 3dcd13c */
#endif
	install_keyword("lower_prio_no_advert", &vrrp_lower_prio_no_advert_handler);
	install_keyword("higher_prio_send_advert", &vrrp_higher_prio_send_advert_handler);
	install_keyword("kernel_rx_buf_size", &kernel_rx_buf_size_handler);
#if defined _WITH_VRRP_AUTH_
	install_keyword("authentication", NULL);
	check_ptr = install_sublevel(VPP &current_vrrp);
	install_keyword("auth_type", &vrrp_auth_type_handler);
	install_keyword("auth_pass", &vrrp_auth_pass_handler);
	install_sublevel_end(check_ptr);
#endif
	/* Script declarations */
	install_keyword_root("vrrp_script", &vrrp_script_handler, active, VPP &current_vscr);
	install_keyword("script", &vrrp_vscript_script_handler);
	install_keyword("interval", &vrrp_vscript_interval_handler);
	install_keyword("timeout", &vrrp_vscript_timeout_handler);
	install_keyword("weight", &vrrp_vscript_weight_handler);
	install_keyword("rise", &vrrp_vscript_rise_handler);
	install_keyword("fall", &vrrp_vscript_fall_handler);
	install_keyword("user", &vrrp_vscript_user_handler);
	install_keyword("init_fail", &vrrp_vscript_init_fail_handler);
	install_level_end_handler(&vrrp_vscript_end_handler);

#ifdef _WITH_TRACK_PROCESS_
	/* Track process declarations */
	install_keyword_root("vrrp_track_process", &vrrp_tprocess_handler, active, VPP &current_tp);
	install_keyword("process", &vrrp_tprocess_process_handler);
	install_keyword("param_match", vrrp_tprocess_match_handler);
	install_keyword("weight", &vrrp_tprocess_weight_handler);
	install_keyword("quorum", &vrrp_tprocess_quorum_handler);
	install_keyword("quorum_max", &vrrp_tprocess_quorum_max_handler);
	install_keyword("delay", &vrrp_tprocess_delay_handler);
	install_keyword("terminate_delay", &vrrp_tprocess_terminate_delay_handler);
	install_keyword("fork_delay", &vrrp_tprocess_fork_delay_handler);
	install_keyword("full_command", &vrrp_tprocess_full_handler);
	install_level_end_handler(&vrrp_tprocess_end_handler);
#endif

	/* Interface up down delays */
	install_keyword_root("interface_up_down_delays", &interface_up_down_delays_handler, active, NULL);
}

const vector_t *
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
	add_track_file_keywords(true);

	return keywords;
}
