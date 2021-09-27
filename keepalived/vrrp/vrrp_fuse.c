// FUSE: Filesystem in Userspace
// Copyright (C) 2001-2005 Miklos Szeredi <miklos@szeredi.hu>
// This program can be distributed under the terms of the GNU GPL.
// See the file COPYING.

// See https://www.cs.nmsu.edu/~pfeiffer/fuse-tutorial/html/callbacks.html
// and http://www.oug.org/files/presentations/losug-fuse.pdf

/* On Fedora, install fuse (runtime), fuse-devel (build time) */

/* To run:
 *   ./ka MOUNTPOINT
 *
 * To terminate:
 *   fusermount -u MOUNTPOINT
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/select.h>

#include "vrrp_fuse.h"
#include "logger.h"
#include "fuse_interface.h"
#include "vrrp_data.h"


/* To remove */
#include <stdlib.h>

static vrrp_t *last_vrrp;

static void vrrp_populate(void *buf, fuse_fill_dir_t filler)
{
	vrrp_t *vrrp;

        list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
		filler(buf, vrrp->iname, NULL, 0, 0);
	}
}

static bool vrrp_set(const char *path_elem, size_t len)
{
	vrrp_t *vrrp;

log_message(LOG_INFO, "In vrrp_set for %s, len %zu, last %s", path_elem, len, last_vrrp ? last_vrrp->iname : "(none)");
	if (last_vrrp && strlen(last_vrrp->iname) == len && !strncmp(path_elem, last_vrrp->iname, len))
{
log_message(LOG_INFO, "Matched last_vrrp");
		return true;
}
        list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
		if (strlen(vrrp->iname) == len && !strncmp(path_elem, vrrp->iname, len)) {
			last_vrrp = vrrp;
			return true;
		}
	}

	return false;
}

struct ent track_script[] = {
	{"name", NULL, NULL, NULL},
	{"weight", NULL, NULL, NULL},
	{"rise", NULL, NULL, NULL},
	{"fall", NULL, NULL, NULL},
	{NULL, NULL, NULL, NULL}
};

struct ent track_script_list[] = {
	{"check_VI_O", track_script, NULL, NULL},
	{"check_VI_1", track_script, NULL, NULL},
	{NULL, NULL, NULL, NULL},
};

struct ent iface[] = {
	{NULL, NULL, NULL, NULL},
};

struct ent iface_list[] = {
	{"eth0", iface, NULL, NULL},
	{"eth1", iface, NULL, NULL},
	{NULL, NULL, NULL, NULL},
};


struct ent unicast_peer_list[] = {
	{"10.10.1.2", NULL, NULL, NULL},
	{"2001:470:69dd:145::3", NULL, NULL, NULL},
	{NULL, NULL, NULL, NULL},
};

struct ent rule[] = {
	{"rule_param1", NULL, NULL, NULL},
	{"rule_param2", NULL, NULL, NULL},
	{NULL, NULL, NULL, NULL},
};

struct ent rule_list[] = {
	{"1", rule, NULL, NULL},
	{"2", rule, NULL, NULL},
	{NULL, NULL, NULL, NULL},
};

struct ent route[] = {
	{"route_param1", NULL, NULL, NULL},
	{"route_param2", NULL, NULL, NULL},
	{NULL, NULL, NULL, NULL},
};

struct ent route_list[] = {
	{"1", route, NULL, NULL},
	{"2", route, NULL, NULL},
	{NULL, NULL, NULL, NULL},
};

struct ent vrrp[] = {
	{"family", NULL, NULL, NULL},	/* sa_family_t */
	{"iname", NULL, NULL, NULL},	/* char* */
	{"sync", NULL, NULL, NULL},		/* vrrp_sgroup_t* */
	{"stats", NULL, NULL, NULL},	/* vrrp_stats* */
	{"ifp", NULL, NULL, NULL},		/* interface_t* */
	{"dont_track_primary", NULL, NULL, NULL},	/* bool */
	{"linkbeat_use_polling", NULL, NULL, NULL},	/* bool */
	{"skip_check_adv_addr", NULL, NULL, NULL},	/* bool */
	{"strict_mode", NULL, NULL, NULL},	/* unsigned */
#ifdef _HAVE_VRRP_VMAC_
	{"vmac_flags", NULL, NULL, NULL},	/* unsigned long */
	{"vmac_ifname", NULL, NULL, NULL},	/* char[IFNAMSIZ] */
#endif
	{"track_ifp", iface_list, NULL, NULL},	/* list */
	{"track_script", track_script_list, NULL, NULL},	/* list */
	{"num_script_if_fault", NULL, NULL, NULL},	/* unsigned */
	{"saddr", NULL, NULL, NULL},	/* struct sockaddr_storage */
	{"pkt_saddr", NULL, NULL, NULL},	/* struct sockaddr_storage */
	{"unicast_peer", unicast_peer_list, NULL, NULL},	/* list */
	{"master_saddr", NULL, NULL, NULL},	/* struct sockaddr_storage */
	{"master_priority", NULL, NULL, NULL},	/* uint8_t */
	{"last_transition", NULL, NULL, NULL},	/* timeval_t */
	{"garp_delay", NULL, NULL, NULL},	/* unsigned */
	{"garp_refresh", NULL, NULL, NULL},	/* timeval_t */
	{"garp_refresh_timer", NULL, NULL, NULL},	/* timeval_t */
	{"garp_rep", NULL, NULL, NULL},	/* unsigned */
	{"garp_refresh_rep", NULL, NULL, NULL},	/* unsigned */
	{"garp_lower_prio_delay", NULL, NULL, NULL},	/* unsigned */
	{"garp_pending", NULL, NULL, NULL},	/* bool */
	{"gna_pending", NULL, NULL, NULL},	/* bool */
	{"garp_lower_prio_rep", NULL, NULL, NULL},	/* unsigned */
	{"lower_prio_no_advert", NULL, NULL, NULL},	/* unsigned */
	{"higher_prio_send_advert", NULL, NULL, NULL},	/* unsigned */
	{"vrid", NULL, NULL, NULL},	/* uint8_t */
	{"base_priority", NULL, NULL, NULL},	/* uint8_t */
	{"effective_priority", NULL, NULL, NULL},	/* uint8_t */
	{"total_priority", NULL, NULL, NULL},	/* int */
	{"vipset", NULL, NULL, NULL},	/* bool */
	{"vip", NULL, NULL, NULL},	/* list */
	{"evip", NULL, NULL, NULL},	/* list */
	{"promote_secondaries", NULL, NULL, NULL},	/* bool */
	{"evip_add_ipv6", NULL, NULL, NULL},	/* bool */
	{"vroutes", route_list, NULL, NULL},	/* list */
	{"vrules", rule_list, NULL, NULL},	/* list */
	{"adver_int", NULL, NULL, NULL},	/* unsigned */
	{"master_adver_int", NULL, NULL, NULL},	/* unsigned */
	{"accept", NULL, NULL, NULL},	/* unsigned */
	{"iptable_rules_set", NULL, NULL, NULL},	/* bool */
	{"nopreempt", NULL, NULL, NULL},	/* bool */
	{"preempt_delay", NULL, NULL, NULL},	/* unsigned long */
	{"preempt_time", NULL, NULL, NULL},	/* timeval_t */
	{"state", NULL, NULL, NULL},	/* int */
	{"init_state", NULL, NULL, NULL},	/* int */
	{"wantstate", NULL, NULL, NULL},	/* int */
	{"sockets", NULL, NULL, NULL},	/* sock_t* */
	{"debug", NULL, NULL, NULL},	/* int */
	{"version", NULL, NULL, NULL},	/* int */
	{"smtp_alert", NULL, NULL, NULL},	/* bool */
	{"notify_exec", NULL, NULL, NULL},	/* bool */
	{"script_backup", NULL, NULL, NULL},	/* notify_script_t* */
	{"script_master", NULL, NULL, NULL},	/* notify_script_t* */
	{"script_fault", NULL, NULL, NULL},	/* notify_script_t* */
	{"script_stop", NULL, NULL, NULL},	/* notify_script_t* */
	{"script", NULL, NULL, NULL},	/* notify_script_t* */
	{"ms_down_timer", NULL, NULL, NULL},	/* uint32_t */
	{"sands", NULL, NULL, NULL},	/* timeval_t */
	{"send_buffer", NULL, NULL, NULL},	/* char* */
	{"send_buffer_size", NULL, NULL, NULL},	/* size_t */
	{"ipv4_csum", NULL, NULL, NULL},	/* uint32_t */
#if defined _WITH_VRRP_AUTH_
	{"auth_type", NULL, NULL, NULL},	/* uint8_t */
	{"auth_data", NULL, NULL, NULL},	/* uint8_t[8] */
	{"ipsecah_counter", NULL, NULL, NULL},	/* seq_counter_t */
#endif
	{"ip_id", NULL, NULL, NULL},	/* int */
	{NULL, NULL, NULL, NULL}
};

struct ent vrrp_list[] = {
	{"", vrrp, vrrp_populate, vrrp_set},
	{NULL, NULL, NULL, NULL}
};

static struct ent top[] = {
	{"", vrrp_list, NULL, NULL},
	{NULL, NULL, NULL, NULL}
} ;

static void *fuses;
//static const char *mountpoint = "/tmp/ka/fs";
static const char *mountpoint = "/tmp/keepaliveda/low/state/vrrp";

void
start_vrrp_fuse(void)
{
	fuses = start_fuse(mountpoint, top, false);
}

void
stop_vrrp_fuse(void)
{
	if (fuses)
		stop_fuse(fuses, NULL);
	fuses = NULL;
}
