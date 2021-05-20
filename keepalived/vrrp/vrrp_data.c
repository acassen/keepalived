/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Dynamic data structure definition.
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
#include <time.h>

#include "utils.h"
#include "logger.h"
#include "bitops.h"
#include "rttables.h"

#include "global_data.h"
#include "main.h"
#include "vrrp_data.h"
#include "vrrp_sync.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_vmac.h"
#endif
#include "vrrp_ipaddress.h"
#include "vrrp_iprule.h"
#include "vrrp_iproute.h"
#include "vrrp_track.h"
#include "vrrp_sock.h"
#ifdef _WITH_SNMP_RFCV3_
#include "vrrp_snmp.h"
#endif
#include "vrrp_static_track.h"
#include "parser.h"
#include "track_file.h"

/* global vars */
vrrp_data_t *vrrp_data = NULL;
vrrp_data_t *old_vrrp_data = NULL;
void *vrrp_buffer;
size_t vrrp_buffer_len;

static const char *
get_state_str(int state)
{
	if (state == VRRP_STATE_INIT) return "INIT";
	if (state == VRRP_STATE_BACK) return "BACKUP";
	if (state == VRRP_STATE_MAST) return "MASTER";
	if (state == VRRP_STATE_FAULT) return "FAULT";
	return "unknown";
}

/* Static track groups facility function */
static void
free_static_track_groups_list(list_head_t *l)
{
	static_track_group_t *tgroup, *tgroup_tmp;

	list_for_each_entry_safe(tgroup, tgroup_tmp, l, e_list)
		free_static_track_group(tgroup);
}

static void
dump_static_track_groups_list(FILE *fp, const list_head_t *l)
{
	static_track_group_t *tgroup;

	list_for_each_entry(tgroup, l, e_list)
		dump_static_track_group(fp, tgroup);
}

void
alloc_static_track_group(const char *gname)
{
	static_track_group_t *new;

	/* Allocate new VRRP group structure */
	PMALLOC(new);
	INIT_LIST_HEAD(&new->e_list);
	INIT_LIST_HEAD(&new->vrrp_instances);
	new->gname = STRDUP(gname);

	list_add_tail(&new->e_list, &vrrp_data->static_track_groups);
}

/* Static addresses facility function */
void
alloc_saddress(const vector_t *strvec)
{
	alloc_ipaddress(&vrrp_data->static_addresses, strvec, true);
}

/* Static routes facility function */
void
alloc_sroute(const vector_t *strvec)
{
	alloc_route(&vrrp_data->static_routes, strvec, true);
}

/* Static rules facility function */
void
alloc_srule(const vector_t *strvec)
{
	alloc_rule(&vrrp_data->static_rules, strvec, true);
}

/* VRRP Reference list functions */
static void
free_vrrp_sync_group_list(list_head_t *l)
{
	vrrp_t *vrrp, *vrrp_tmp;

	/* Remove the vrrp instances from the sync group */
	list_for_each_entry_safe(vrrp, vrrp_tmp, l, s_list) {
		vrrp->sync = NULL;
		list_del_init(&vrrp->s_list);
	}
}

static void
dump_vrrp_sync_group_list(FILE *fp, const list_head_t *l)
{
	vrrp_t *vrrp;

	list_for_each_entry(vrrp, l, s_list)
		conf_write(fp, "     %s", vrrp->iname);
}

/* VRRP facility functions */
void
free_sync_group(vrrp_sgroup_t *sgroup)
{
	list_del_init(&sgroup->e_list);
	if (sgroup->iname) {
		/* If we are terminating at init time, sgroup->vrrp_instances may not be initialised
		 * yet, or it may have only one member, in which case sgroup->iname will still be set */
		if (sgroup->vrrp_instances.prev != sgroup->vrrp_instances.next)
			log_message(LOG_INFO, "sync group %s - iname vector exists when freeing group"
					    , sgroup->gname);
		free_strvec(sgroup->iname);
	}

	FREE_CONST(sgroup->gname);
	free_vrrp_sync_group_list(&sgroup->vrrp_instances);
	free_track_if_list(&sgroup->track_ifp);
	free_track_script_list(&sgroup->track_script);
	free_track_file_monitor_list(&sgroup->track_file);
#ifdef _WITH_TRACK_PROCESS_
	free_track_process_list(&sgroup->track_process);
#endif
#ifdef _WITH_BFD_
	free_track_bfd_list(&sgroup->track_bfd);
#endif
	free_notify_script(&sgroup->script_backup);
	free_notify_script(&sgroup->script_master);
	free_notify_script(&sgroup->script_fault);
	free_notify_script(&sgroup->script_stop);
	free_notify_script(&sgroup->script);
	FREE(sgroup);
}
static void
free_sync_group_list(list_head_t *l)
{
	vrrp_sgroup_t *sgroup, *sgroup_tmp;

	list_for_each_entry_safe(sgroup, sgroup_tmp, l, e_list)
		free_sync_group(sgroup);
}

static void
dump_notify_script(FILE *fp, const notify_script_t *script, const char *type)
{
	if (!script)
		return;

	conf_write(fp, "   %s state transition script = %s, uid:gid %u:%u"
		     , type, cmd_str(script), script->uid, script->gid);
}

static void
dump_sync_group(FILE *fp, const vrrp_sgroup_t *sgroup)
{
	conf_write(fp, " VRRP Sync Group = %s, %s", sgroup->gname, get_state_str(sgroup->state));
	conf_write(fp, "   Num member fault %u, num member init %u", sgroup->num_member_fault, sgroup->num_member_init);
	if (!list_empty(&sgroup->vrrp_instances)) {
		conf_write(fp, "   VRRP member instances :");
		dump_vrrp_sync_group_list(fp, &sgroup->vrrp_instances);
	}
	if (sgroup->sgroup_tracking_weight)
		conf_write(fp, "   sync group tracking weight set");
	conf_write(fp, "   Using smtp notification = %s", sgroup->smtp_alert ? "yes" : "no");
	if (sgroup->notify_priority_changes != -1)
		conf_write(fp, "   Notify priority changes = %s", sgroup->notify_priority_changes ? "yes" : "no");
	if (!list_empty(&sgroup->track_ifp)) {
		conf_write(fp, "   Tracked interfaces :");
		dump_track_if_list(fp, &sgroup->track_ifp);
	}
	if (!list_empty(&sgroup->track_script)) {
		conf_write(fp, "   Tracked scripts :");
		dump_track_script_list(fp, &sgroup->track_script);
	}
	if (!list_empty(&sgroup->track_file)) {
		conf_write(fp, "   Tracked files :");
		dump_track_file_monitor_list(fp, &sgroup->track_file);
	}
#ifdef _WITH_TRACK_PROCESS_
	if (!list_empty(&sgroup->track_process)) {
		conf_write(fp, "   Tracked process :");
		dump_track_process_list(fp, &sgroup->track_process);
	}
#endif
#ifdef _WITH_BFD_
	if (!list_empty(&sgroup->track_bfd)) {
		conf_write(fp, "   Tracked BFDs :");
		dump_tracked_bfd_list(fp, &sgroup->track_bfd);
	}
#endif
	dump_notify_script(fp, sgroup->script_backup, "Backup");
	dump_notify_script(fp, sgroup->script_master, "Master");
	dump_notify_script(fp, sgroup->script_fault, "Fault");
	dump_notify_script(fp, sgroup->script_stop, "Stop");
	dump_notify_script(fp, sgroup->script, "Generic");
}
static void
dump_sync_group_list(FILE *fp, const list_head_t *l)
{
	vrrp_sgroup_t *sgroup;

	list_for_each_entry(sgroup, l, e_list)
		dump_sync_group(fp, sgroup);
}

void
dump_tracking_vrrp(FILE *fp, const void *obj)
{
	const tracking_obj_t *top = obj;
	const vrrp_t *vrrp = top->obj.vrrp;

	conf_write(fp, "     %s, weight %d%s%s"
		     , vrrp->iname, top->weight
		     , top->weight_multiplier == -1 ? " reverse" : ""
		     , top->type == TRACK_VRRP_DYNAMIC ? " (dynamic)" : "");
}
void
dump_tracking_vrrp_list(FILE *fp, const list_head_t *l)
{
	tracking_obj_t *top;

	list_for_each_entry(top, l, e_list)
		dump_tracking_vrrp(fp, top);
}

void
free_vscript(vrrp_script_t *vscript)
{
	list_del_init(&vscript->e_list);
	free_tracking_obj_list(&vscript->tracking_vrrp);
	FREE_CONST(vscript->sname);
	FREE_PTR(vscript->script.args);
	FREE(vscript);
}
static void
free_vscript_list(list_head_t *l)
{
	vrrp_script_t *vscript, *vscript_tmp;

	list_for_each_entry_safe(vscript, vscript_tmp, l, e_list)
		free_vscript(vscript);
}
static void
dump_vscript(FILE *fp, const vrrp_script_t *vscript)
{
	const char *str;

	conf_write(fp, " VRRP Script = %s", vscript->sname);
	conf_write(fp, "   Command = %s", cmd_str(&vscript->script));
	conf_write(fp, "   Interval = %lu sec", vscript->interval / TIMER_HZ);
	conf_write(fp, "   Timeout = %lu sec", vscript->timeout / TIMER_HZ);
	conf_write(fp, "   Weight = %d%s", vscript->weight, vscript->weight_reverse ? " reverse" : "");
	conf_write(fp, "   Rise = %d", vscript->rise);
	conf_write(fp, "   Fall = %d", vscript->fall);
	conf_write(fp, "   Insecure = %s", vscript->insecure ? "yes" : "no");

	switch (vscript->init_state) {
	case SCRIPT_INIT_STATE_INIT:
		str = "INIT"; break;
	case SCRIPT_INIT_STATE_FAILED:
		str = "INIT/FAILED"; break;
	default:
		str = (vscript->result >= vscript->rise) ? "GOOD" : "BAD";
	}
	conf_write(fp, "   Status = %s", str);
	conf_write(fp, "   Script uid:gid = %u:%u", vscript->script.uid, vscript->script.gid);
	conf_write(fp, "   VRRP instances :");
	dump_tracking_obj_list(fp, &vscript->tracking_vrrp, dump_tracking_vrrp);
	conf_write(fp, "   State = %s",
			vscript->state == SCRIPT_STATE_IDLE ? "idle" :
			vscript->state == SCRIPT_STATE_RUNNING ? "running" :
			vscript->state == SCRIPT_STATE_REQUESTING_TERMINATION ? "requested termination" :
			vscript->state == SCRIPT_STATE_FORCING_TERMINATION ? "forcing termination" : "unknown");
}
static void
dump_vscript_list(FILE *fp, const list_head_t *l)
{
	vrrp_script_t *script;

	list_for_each_entry(script, l, e_list)
		dump_vscript(fp, script);
}

#ifdef _WITH_TRACK_PROCESS_
void
free_vprocess(vrrp_tracked_process_t *vprocess)
{
	list_del_init(&vprocess->e_list);
	free_tracking_obj_list(&vprocess->tracking_vrrp);
	FREE_CONST(vprocess->pname);
	FREE_CONST(vprocess->process_path);
	FREE_CONST_PTR(vprocess->process_params);
	FREE(vprocess);
}
static void
free_vprocess_list(list_head_t *l)
{
	vrrp_tracked_process_t *vprocess, *vprocess_tmp;

	list_for_each_entry_safe(vprocess, vprocess_tmp, l, e_list)
		free_vprocess(vprocess);
}
static void
dump_vprocess(FILE *fp, const vrrp_tracked_process_t *vprocess)
{
	char *params, *p;

	conf_write(fp, " VRRP Track process = %s", vprocess->pname);
	conf_write(fp, "   Process = %s", vprocess->process_path);
	if (vprocess->process_params) {
		params = MALLOC(vprocess->process_params_len);
		memcpy(params, vprocess->process_params, vprocess->process_params_len);
		p = params;
		for (p = strchr(params, '\0'); p < params + vprocess->process_params_len - 1; p = strchr(params + 1, '\0'))
			*p = ' ';
		conf_write(fp, "   Parameters = %s", params);
		FREE(params);
	}
	if (vprocess->param_match != PARAM_MATCH_NONE)
		conf_write(fp, "   Param match%s",
			       vprocess->param_match == PARAM_MATCH_EXACT ? "" :
			       vprocess->param_match == PARAM_MATCH_PARTIAL ? " = partial" :
			       vprocess->param_match == PARAM_MATCH_INITIAL ? " = initial" :
			       "unknown");
	conf_write(fp, "   Min processes = %u", vprocess->quorum);
	if (vprocess->quorum_max < UINT_MAX)
		conf_write(fp, "   Max processes = %u", vprocess->quorum_max);
	conf_write(fp, "   Current processes = %u", vprocess->num_cur_proc);
	conf_write(fp, "   Have quorum = %s", vprocess->have_quorum ? "true" : "false");
	conf_write(fp, "   Weight = %d%s", vprocess->weight, vprocess->weight_reverse ? " reverse" : "");
	conf_write(fp, "   Terminate delay = %fs", (double)vprocess->terminate_delay / TIMER_HZ);
	conf_write(fp, "   Fork delay = %fs", (double)vprocess->fork_delay / TIMER_HZ);
	if (fp) {
		conf_write(fp, "   Fork delay timer %srunning", vprocess->fork_timer_thread ? "" : "not ");
		conf_write(fp, "   Terminate delay timer %srunning", vprocess->terminate_timer_thread ? "" : "not ");
	}
	conf_write(fp, "   Full command = %s", vprocess->full_command ? "true" : "false");
	dump_tracking_obj_list(fp, &vprocess->tracking_vrrp, dump_tracking_vrrp);
}
static void
dump_vprocess_list(FILE *fp, const list_head_t *l)
{
	vrrp_tracked_process_t *vprocess;

	list_for_each_entry(vprocess, l, e_list)
		dump_vprocess(fp, vprocess);
}
#endif

#ifdef _WITH_BFD_
void
free_vrrp_tracked_bfd(vrrp_tracked_bfd_t *vbfd)
{
	list_del_init(&vbfd->e_list);
	free_tracking_obj_list(&vbfd->tracking_vrrp);
	FREE(vbfd);
}
static void
free_vrrp_tracked_bfd_list(list_head_t *l)
{
	vrrp_tracked_bfd_t *vbfd, *vbfd_tmp;

	list_for_each_entry_safe(vbfd, vbfd_tmp, l, e_list)
		free_vrrp_tracked_bfd(vbfd);
}

static void
dump_vrrp_tracked_bfd(FILE *fp, const vrrp_tracked_bfd_t *vbfd)
{
	conf_write(fp, " VRRP Track BFD = %s", vbfd->bname);
	conf_write(fp, "   Weight = %d%s", vbfd->weight, vbfd->weight_reverse ? " reverse" : "");
	conf_write(fp, "   Bfd is %s", vbfd->bfd_up ? "up" : "down");
	conf_write(fp, "   Tracking VRRP instances :");
	dump_tracking_obj_list(fp, &vbfd->tracking_vrrp, dump_tracking_vrrp);
}
static void
dump_vrrp_tracked_bfd_list(FILE *fp, const list_head_t *l)
{
	vrrp_tracked_bfd_t *vbfd;

	list_for_each_entry(vbfd, l, e_list)
		dump_vrrp_tracked_bfd(fp, vbfd);
}
#endif

/* Socket pool functions */
static void
free_sock(sock_t *sock)
{
	/* First of all cancel pending thread. If we are reloading
	 * thread_cleanup_master() has already been called, and so
	 * the thread already will have been cancelled. */
	if (!reload)
		thread_cancel(sock->thread);

	/* Close related socket */
	if (sock->fd_in > 0)
		close(sock->fd_in);
	if (sock->fd_out > 0)
		close(sock->fd_out);
	FREE(sock);
}
void
free_sock_list(list_head_t *l)
{
	sock_t *sock, *sock_tmp;

	list_for_each_entry_safe(sock, sock_tmp, l, e_list)
		free_sock(sock);
}
static void
dump_sock(FILE *fp, const sock_t *sock)
{
	conf_write(fp, "VRRP sockpool: [ifindex(%3u), family(%s), proto(%d), fd(%d,%d)%s%s%s%s]"
			    , sock->ifp ? sock->ifp->ifindex : 0
			    , sock->family == AF_INET ? "IPv4" : sock->family == AF_INET6 ? "IPv6" : "unknown"
			    , sock->proto
			    , sock->fd_in
			    , sock->fd_out
			    , !!sock->unicast_src ? ", unicast" : ""
			    , sock->unicast_src ? ", address(" : ""
			    , sock->unicast_src ? inet_sockaddrtos(sock->unicast_src) : ""
			    , sock->unicast_src ? ")" : ""
			    );
}
void
dump_sock_list(FILE *fp, const list_head_t *l)
{
	sock_t *sock;

	list_for_each_entry(sock, l, e_list)
		dump_sock(fp, sock);
}

static void
dump_sock_pool(FILE *fp, const list_head_t *l)
{
	sock_t *sock;
	const vrrp_t *vrrp;

	list_for_each_entry(sock, l, e_list) {
		conf_write(fp, " fd_in %d fd_out = %d", sock->fd_in, sock->fd_out);
		conf_write(fp, "   Interface = %s", sock->ifp->ifname);
		conf_write(fp, "   Family = %s", sock->family == AF_INET ? "IPv4" : sock->family == AF_INET6 ? "IPv6" : "unknown");
		conf_write(fp, "   Protocol = %s", sock->proto == IPPROTO_AH ? "AH" : sock->proto == IPPROTO_VRRP ? "VRRP" : "unknown");
		conf_write(fp, "   Type = %sicast", sock->unicast_src ? "Un" : "Mult");
		if (sock->unicast_src)	// Also for mcast once can specify
			conf_write(fp, "   Address = %s", inet_sockaddrtos(sock->unicast_src));
		conf_write(fp, "   Rx buf size = %d", sock->rx_buf_size);
		conf_write(fp, "   VRRP instances");
		rb_for_each_entry_const(vrrp, &sock->rb_vrid, rb_vrid)
			conf_write(fp, "     %s vrid %d", vrrp->iname, vrrp->vrid);
	}
}
static void
free_unicast_peer(unicast_peer_t *peer)
{
	list_del_init(&peer->e_list);
	FREE(peer);
}
static void
free_unicast_peer_list(list_head_t *l)
{
	unicast_peer_t *peer, *peer_tmp;

	list_for_each_entry_safe(peer, peer_tmp, l, e_list)
		free_unicast_peer(peer);

}
static void
dump_unicast_peer(FILE *fp, const void *data)
{
	const unicast_peer_t *peer = data;

	conf_write(fp, "     %s min_ttl %u max_ttl %u", inet_sockaddrtos(&peer->address), peer->min_ttl, peer->max_ttl);
#ifdef _CHECKSUM_DEBUG_
	conf_write(fp, "       last rx checksum = 0x%4.4x, priority %d", peer->chk.last_rx_checksum, peer->chk.last_rx_priority);
	conf_write(fp, "       last tx checksum = 0x%4.4x, priority %d", peer->chk.last_tx_checksum, peer->chk.last_tx_priority);
#endif
}
static void
dump_unicast_peer_list(FILE *fp, const list_head_t *l)
{
	unicast_peer_t *peer;

	list_for_each_entry(peer, l, e_list)
		dump_unicast_peer(fp, peer);
}

static void
free_vrrp(vrrp_t *vrrp)
{
	FREE_CONST(vrrp->iname);
#ifdef _HAVE_VRRP_IPVLAN_
	FREE_PTR(vrrp->ipvlan_addr);
#endif
	FREE_PTR(vrrp->send_buffer);
	free_notify_script(&vrrp->script_backup);
	free_notify_script(&vrrp->script_master);
	free_notify_script(&vrrp->script_fault);
	free_notify_script(&vrrp->script_stop);
	free_notify_script(&vrrp->script_deleted);
	free_notify_script(&vrrp->script);
	free_notify_script(&vrrp->script_master_rx_lower_pri);
	FREE_PTR(vrrp->stats);

	free_track_if_list(&vrrp->track_ifp);
	free_track_script_list(&vrrp->track_script);
	free_track_file_monitor_list(&vrrp->track_file);
#ifdef _WITH_TRACK_PROCESS_
	free_track_process_list(&vrrp->track_process);
#endif
#ifdef _WITH_BFD_
	free_track_bfd_list(&vrrp->track_bfd);
#endif
	free_unicast_peer_list(&vrrp->unicast_peer);
	free_ipaddress_list(&vrrp->vip);
	free_ipaddress_list(&vrrp->evip);
	free_iproute_list(&vrrp->vroutes);
	free_iprule_list(&vrrp->vrules);
	list_del_init(&vrrp->e_list);
	FREE(vrrp);
}
static void
free_vrrp_list(list_head_t *l)
{
	vrrp_t *vrrp, *vrrp_tmp;

	list_for_each_entry_safe(vrrp, vrrp_tmp, l, e_list)
		free_vrrp(vrrp);
}
static void
dump_vrrp(FILE *fp, const vrrp_t *vrrp)
{
#ifdef _WITH_VRRP_AUTH_
	char auth_data[sizeof(vrrp->auth_data) + 1];
#endif
	char time_str[26];

	/* If fp is NULL, we are writing configuration to syslog at
	 * startup, so there is no point writing transient state information.
	 */

	conf_write(fp, " VRRP Instance = %s", vrrp->iname);
	conf_write(fp, "   VRRP Version = %d", vrrp->version);
	if (vrrp->sync)
		conf_write(fp, "   Sync group = %s", vrrp->sync->gname);
	if (vrrp->family == AF_INET6)
		conf_write(fp, "   Using Native IPv6");
	if (fp) {
		conf_write(fp, "   State = %s", get_state_str(vrrp->state));
		if (vrrp->state == VRRP_STATE_BACK) {
			conf_write(fp, "   Master router = %s", inet_sockaddrtos(&vrrp->master_saddr));
			conf_write(fp, "   Master priority = %d", vrrp->master_priority);
			if (vrrp->version == VRRP_VERSION_3)
				conf_write(fp, "   Master advert int = %.2f sec", vrrp->master_adver_int / TIMER_HZ_DOUBLE);
		}
	}
	conf_write(fp, "   Wantstate = %s", get_state_str(vrrp->wantstate));
	if (fp) {
		conf_write(fp, "   Number of interface and track script faults = %u", vrrp->num_script_if_fault);
#ifdef _HAVE_VRRP_VMAC_
		if (vrrp->duplicate_vrid_fault)
			conf_write(fp, "   Duplicate VRID");
#endif
		conf_write(fp, "   Number of track scripts init = %u", vrrp->num_script_init);
		ctime_r(&vrrp->last_transition.tv_sec, time_str);
		conf_write(fp, "   Last transition = %ld.%6.6ld (%.24s.%6.6ld)", vrrp->last_transition.tv_sec, vrrp->last_transition.tv_usec, time_str, vrrp->last_transition.tv_usec);
		if (!ctime_r(&vrrp->sands.tv_sec, time_str))
			strcpy(time_str, "invalid time ");
		if (vrrp->sands.tv_sec == TIMER_DISABLED)
			conf_write(fp, "   Read timeout = DISABLED");
		else
			conf_write(fp, "   Read timeout = %ld.%6.6ld (%.19s.%6.6ld)", vrrp->sands.tv_sec, vrrp->sands.tv_usec, time_str, vrrp->sands.tv_usec);
		conf_write(fp, "   Master down timer = %u usecs", vrrp->ms_down_timer);
	}
#ifdef _HAVE_VRRP_VMAC_
	if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags))
		conf_write(fp, "   Use VMAC, i/f name %s, is_up = %s, xmit_base = %s",
				vrrp->vmac_ifname,
				__test_bit(VRRP_VMAC_UP_BIT, &vrrp->vmac_flags) ? "true" : "false",
				__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags) ? "true" : "false");
	if (__test_bit(VRRP_VMAC_ADDR_BIT, &vrrp->vmac_flags))
		conf_write(fp, "   Use VMAC for VIPs on other interfaces");
#ifdef _HAVE_VRRP_IPVLAN_
	else if (__test_bit(VRRP_IPVLAN_BIT, &vrrp->vmac_flags))
		conf_write(fp, "   Use IPVLAN, i/f %s, is_up = %s%s%s, type %s",
				vrrp->vmac_ifname,
				__test_bit(VRRP_VMAC_UP_BIT, &vrrp->vmac_flags) ? "true" : "false",
				vrrp->ipvlan_addr ? ", i/f address = " : "",
				vrrp->ipvlan_addr ? ipaddresstos(NULL, vrrp->ipvlan_addr) : "",
#if HAVE_DECL_IFLA_IPVLAN_FLAGS	/* Since Linux v4.15 */
				!vrrp->ipvlan_type ? "bridge" : vrrp->ipvlan_type == IPVLAN_F_PRIVATE ? "private" : vrrp->ipvlan_type == IPVLAN_F_VEPA ? "vepa" : "unknown"
#else
				"bridge"
#endif
					);
#endif
	if (vrrp->ifp && vrrp->ifp->is_ours) {
		conf_write(fp, "   Interface = %s, %s on %s%s", IF_NAME(vrrp->ifp),
				__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags) ? "vmac" : "ipvlan",
				vrrp->ifp != vrrp->ifp->base_ifp ? vrrp->ifp->base_ifp->ifname : "(unknown)",
				__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags) ? ", xmit base i/f" : "");
	} else
#endif
		conf_write(fp, "   Interface = %s", vrrp->ifp ? IF_NAME(vrrp->ifp) : "not configured");
#ifdef _HAVE_VRRP_VMAC_
	if (vrrp->ifp && vrrp->configured_ifp && vrrp->configured_ifp != vrrp->ifp->base_ifp && vrrp->ifp->is_ours)
		conf_write(fp, "   Configured interface = %s", vrrp->configured_ifp->ifname);
#endif
	if (vrrp->dont_track_primary)
		conf_write(fp, "   VRRP interface tracking disabled");
	if (vrrp->skip_check_adv_addr)
		conf_write(fp, "   Skip checking advert IP addresses");
	if (vrrp->strict_mode)
		conf_write(fp, "   Enforcing strict VRRP compliance");
	conf_write(fp, "   Using src_ip = %s%s", vrrp->saddr.ss_family != AF_UNSPEC
						    ? inet_sockaddrtos(&vrrp->saddr)
						    : "(none)",
						  vrrp->saddr_from_config ? " (from configuration)" : "");
	conf_write(fp, "   Gratuitous ARP delay = %u",
		       vrrp->garp_delay/TIMER_HZ);
	conf_write(fp, "   Gratuitous ARP repeat = %u", vrrp->garp_rep);
	conf_write(fp, "   Gratuitous ARP refresh = %ld",
		       vrrp->garp_refresh.tv_sec);
	conf_write(fp, "   Gratuitous ARP refresh repeat = %u", vrrp->garp_refresh_rep);
	conf_write(fp, "   Gratuitous ARP lower priority delay = %u", vrrp->garp_lower_prio_delay / TIMER_HZ);
	conf_write(fp, "   Gratuitous ARP lower priority repeat = %u", vrrp->garp_lower_prio_rep);
#ifdef _HAVE_VRRP_VMAC_
	if (vrrp->vmac_garp_intvl.tv_sec) {
		conf_write(fp, "   Gratuitous ARP for each secondary %s = %ld", vrrp->vmac_garp_all_if ? "i/f" : "VMAC", vrrp->vmac_garp_intvl.tv_sec);
		ctime_r(&vrrp->vmac_garp_timer.tv_sec, time_str);
		conf_write(fp, "   Next gratuitous ARP for such secondary = %ld.%6.6ld (%.24s.%6.6ld)", vrrp->vmac_garp_timer.tv_sec, vrrp->vmac_garp_timer.tv_usec, time_str, vrrp->vmac_garp_timer.tv_usec);
	}
#endif
	conf_write(fp, "   Send advert after receive lower priority advert = %s", vrrp->lower_prio_no_advert ? "false" : "true");
	conf_write(fp, "   Send advert after receive higher priority advert = %s", vrrp->higher_prio_send_advert ? "true" : "false");
	conf_write(fp, "   Virtual Router ID = %d", vrrp->vrid);
	conf_write(fp, "   Priority = %d", vrrp->base_priority);
	if (fp) {
		conf_write(fp, "   Effective priority = %d", vrrp->effective_priority);
		conf_write(fp, "   Total priority = %d", vrrp->total_priority);
	}
	conf_write(fp, "   Advert interval = %u %s",
		(vrrp->version == VRRP_VERSION_2) ? (vrrp->adver_int / TIMER_HZ) :
		(vrrp->adver_int / (TIMER_HZ / 1000)),
		(vrrp->version == VRRP_VERSION_2) ? "sec" : "milli-sec");
	if (vrrp->state == VRRP_STATE_BACK && vrrp->version == VRRP_VERSION_3)
		conf_write(fp, "   Master advert interval = %u milli-sec", vrrp->master_adver_int / (TIMER_HZ / 1000));
#ifdef _WITH_FIREWALL_
	conf_write(fp, "   Accept = %s", vrrp->accept ? "enabled" : "disabled");
#endif
	conf_write(fp, "   Preempt = %s", vrrp->nopreempt ? "disabled" : "enabled");
	if (vrrp->preempt_delay)
		conf_write(fp, "   Preempt delay = %g secs",
		       vrrp->preempt_delay / TIMER_HZ_DOUBLE);
	conf_write(fp, "   Promote_secondaries = %s", vrrp->promote_secondaries ? "enabled" : "disabled");
#if defined _WITH_VRRP_AUTH_
	if (vrrp->auth_type) {
		conf_write(fp, "   Authentication type = %s",
		       (vrrp->auth_type ==
			VRRP_AUTH_AH) ? "IPSEC_AH" : "SIMPLE_PASSWORD");
		if (vrrp->auth_type != VRRP_AUTH_AH) {
			/* vrrp->auth_data is not \0 terminated */
			memcpy(auth_data, vrrp->auth_data, sizeof(vrrp->auth_data));
			auth_data[sizeof(vrrp->auth_data)] = '\0';
			conf_write(fp, "   Password = %s", auth_data);
		}
	}
	else if (vrrp->version == VRRP_VERSION_2)
		conf_write(fp, "   Authentication type = none");
#endif
	if (vrrp->kernel_rx_buf_size)
		conf_write(fp, "   Kernel rx buffer size = %zu", vrrp->kernel_rx_buf_size);

	if (vrrp->debug)
		conf_write(fp, "   Debug level = %d", vrrp->debug);

#ifdef _CHECKSUM_DEBUG_
	conf_write(fp, "   last rx checksum = 0x%4.4x, priority %d", vrrp->chk.last_rx_checksum, vrrp->chk.last_rx_priority);
	conf_write(fp, "   last tx checksum = 0x%4.4x, priority %d", vrrp->chk.last_tx_checksum, vrrp->chk.last_tx_priority);
#endif

	if (!list_empty(&vrrp->vip)) {
		conf_write(fp, "   Virtual IP :");
		dump_ipaddress_list(fp, &vrrp->vip);
	}
	if (!list_empty(&vrrp->evip)) {
		conf_write(fp, "   Virtual IP Excluded :");
		dump_ipaddress_list(fp, &vrrp->evip);
	}
	if (!list_empty(&vrrp->unicast_peer)) {
		if (vrrp->ttl != -1)
			conf_write(fp, "   Unicast TTL = %d", vrrp->ttl);
		conf_write(fp, "   Check unicast src : %s", vrrp->check_unicast_src ? "yes" : "no");
		conf_write(fp, "   Unicast Peer :");
		dump_unicast_peer_list(fp, &vrrp->unicast_peer);
#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
		conf_write(fp, "   Unicast checksum compatibility = %s",
				vrrp->unicast_chksum_compat == CHKSUM_COMPATIBILITY_NONE ? "no" :
				vrrp->unicast_chksum_compat == CHKSUM_COMPATIBILITY_NEVER ? "never" :
				vrrp->unicast_chksum_compat == CHKSUM_COMPATIBILITY_CONFIG ? "config" :
				vrrp->unicast_chksum_compat == CHKSUM_COMPATIBILITY_AUTO ? "auto" : "unknown");
#endif
	}
	if (vrrp->sockets)
		conf_write(fp, "   fd_in %d, fd_out %d", vrrp->sockets->fd_in, vrrp->sockets->fd_out);
	else
		conf_write(fp, "   No sockets allocated");
	if (!list_empty(&vrrp->vroutes)) {
		conf_write(fp, "   Virtual Routes :");
		dump_iproute_list(fp, &vrrp->vroutes);
	}
	if (!list_empty(&vrrp->vrules)) {
		conf_write(fp, "   Virtual Rules :");
		dump_iprule_list(fp, &vrrp->vrules);
	}

	if (!list_empty(&vrrp->track_ifp)) {
		conf_write(fp, "   Tracked interfaces :");
		dump_track_if_list(fp, &vrrp->track_ifp);
	}
	if (!list_empty(&vrrp->track_script)) {
		conf_write(fp, "   Tracked scripts :");
		dump_track_script_list(fp, &vrrp->track_script);
	}
	if (!list_empty(&vrrp->track_file)) {
		conf_write(fp, "   Tracked files :");
		dump_track_file_monitor_list(fp, &vrrp->track_file);
	}
#ifdef _WITH_TRACK_PROCESS_
	if (!list_empty(&vrrp->track_process)) {
		conf_write(fp, "   Tracked processes :");
		dump_track_process_list(fp, &vrrp->track_process);
	}
#endif
#ifdef _WITH_BFD_
	if (!list_empty(&vrrp->track_bfd)) {
		conf_write(fp, "   Tracked BFDs :");
		dump_tracked_bfd_list(fp, &vrrp->track_bfd);
	}
#endif

	conf_write(fp, "   Using smtp notification = %s", vrrp->smtp_alert ? "yes" : "no");

	conf_write(fp, "   Notify deleted = %s", vrrp->notify_deleted ? "Deleted" : "Fault");

	if (vrrp->script_backup)
		dump_notify_script(fp, vrrp->script_backup, "Backup");
	if (vrrp->script_master)
		dump_notify_script(fp, vrrp->script_master, "Master");
	if (vrrp->script_fault)
		dump_notify_script(fp, vrrp->script_fault, "Fault");
	if (vrrp->script_stop)
		dump_notify_script(fp, vrrp->script_stop, "Stop");
	if (vrrp->script_deleted)
		dump_notify_script(fp, vrrp->script_deleted, "Deleted");
	if (vrrp->script)
		dump_notify_script(fp, vrrp->script, "Generic");
	if (vrrp->script_master_rx_lower_pri)
		dump_notify_script(fp, vrrp->script_master_rx_lower_pri, "Master rx lower pri");
	conf_write(fp, "   Notify priority changes = %s", vrrp->notify_priority_changes ? "true" : "false");
}
static void
dump_vrrp_list(FILE *fp, const list_head_t *l)
{
	vrrp_t *vrrp;

	list_for_each_entry(vrrp, l, e_list)
		dump_vrrp(fp, vrrp);
}

void
alloc_vrrp_sync_group(const char *gname)
{
	vrrp_sgroup_t *new;

	/* Allocate new VRRP group structure */
	PMALLOC(new);
	INIT_LIST_HEAD(&new->e_list);
	INIT_LIST_HEAD(&new->vrrp_instances);
	INIT_LIST_HEAD(&new->track_ifp);
	INIT_LIST_HEAD(&new->track_script);
	INIT_LIST_HEAD(&new->track_file);
#ifdef _WITH_TRACK_PROCESS_
	INIT_LIST_HEAD(&new->track_process);
#endif
#ifdef _WITH_BFD_
	INIT_LIST_HEAD(&new->track_bfd);
#endif
	new->state = VRRP_STATE_INIT;
	new->last_email_state = VRRP_STATE_INIT;
	new->gname = STRDUP(gname);
	new->sgroup_tracking_weight = false;
	new->smtp_alert = -1;
	new->notify_priority_changes = -1;

	list_add_tail(&new->e_list, &vrrp_data->vrrp_sync_group);
}

static vrrp_stats *
alloc_vrrp_stats(void)
{
	vrrp_stats *new;

	PMALLOC(new);
	new->become_master = 0;
	new->release_master = 0;
	new->invalid_authtype = 0;
#ifdef _WITH_VRRP_AUTH_
	new->authtype_mismatch = 0;
	new->auth_failure = 0;
#endif
	new->packet_len_err = 0;
	new->advert_rcvd = 0;
	new->advert_sent = 0;
	new->advert_interval_err = 0;
	new->ip_ttl_err = 0;
	new->pri_zero_rcvd = 0;
	new->pri_zero_sent = 0;
	new->invalid_type_rcvd = 0;
	new->addr_list_err = 0;
#ifdef _WITH_SNMP_RFCV3_
	new->master_reason = VRRPV3_MASTER_REASON_NOT_MASTER;
	new->next_master_reason = VRRPV3_MASTER_REASON_MASTER_NO_RESPONSE;
#endif
	return new;
}

void
alloc_vrrp(const char *iname)
{
	vrrp_t *new;

	/* Allocate new VRRP structure */
	PMALLOC(new);
	INIT_LIST_HEAD(&new->e_list);
	INIT_LIST_HEAD(&new->s_list);
	INIT_LIST_HEAD(&new->track_ifp);
	INIT_LIST_HEAD(&new->track_script);
	INIT_LIST_HEAD(&new->track_file);
	INIT_LIST_HEAD(&new->unicast_peer);
#ifdef _WITH_TRACK_PROCESS_
	INIT_LIST_HEAD(&new->track_process);
#endif
#ifdef _WITH_BFD_
	INIT_LIST_HEAD(&new->track_bfd);
#endif
	INIT_LIST_HEAD(&new->vip);
	INIT_LIST_HEAD(&new->evip);
	INIT_LIST_HEAD(&new->vroutes);
	INIT_LIST_HEAD(&new->vrules);

	/* Set default values */
	new->family = AF_UNSPEC;
	new->saddr.ss_family = AF_UNSPEC;
	new->wantstate = VRRP_STATE_INIT;
	new->last_email_state = VRRP_STATE_INIT;
	new->version = 0;
	new->master_priority = 0;
	new->last_transition = timer_now();
	new->iname = STRDUP(iname);
	new->stats = alloc_vrrp_stats();
	new->ttl = -1;
#ifdef _WITH_FIREWALL_
	new->accept = PARAMETER_UNSET;
#endif
	new->garp_rep = global_data->vrrp_garp_rep;
	new->garp_refresh = global_data->vrrp_garp_refresh;
	new->garp_refresh_rep = global_data->vrrp_garp_refresh_rep;
	new->garp_delay = global_data->vrrp_garp_delay;
	new->garp_lower_prio_delay = PARAMETER_UNSET;
	new->garp_lower_prio_rep = PARAMETER_UNSET;
#ifdef _HAVE_VRRP_VMAC_
	new->vmac_garp_intvl.tv_sec = TIME_T_PARAMETER_UNSET;
#endif
	new->lower_prio_no_advert = PARAMETER_UNSET;
	new->higher_prio_send_advert = PARAMETER_UNSET;
#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
	new->unicast_chksum_compat = CHKSUM_COMPATIBILITY_NONE;
#endif
	new->smtp_alert = -1;
	new->notify_priority_changes = -1;

	new->skip_check_adv_addr = global_data->vrrp_skip_check_adv_addr;
	new->strict_mode = PARAMETER_UNSET;

	list_add_tail(&new->e_list, &vrrp_data->vrrp);
}

void
alloc_vrrp_unicast_peer(const vector_t *strvec)
{
	vrrp_t *vrrp = list_last_entry(&vrrp_data->vrrp, vrrp_t, e_list);
	unicast_peer_t *peer;
	unsigned ttl;
	unsigned i;

	/* Allocate new unicast peer */
	PMALLOC(peer);
	peer->min_ttl = 0;
	peer->max_ttl = 255;

	if (inet_stosockaddr(strvec_slot(strvec, 0), NULL, &peer->address)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: VRRP instance[%s] malformed unicast"
				     " peer address[%s]. Skipping..."
				   , vrrp->iname, strvec_slot(strvec, 0));
		FREE(peer);
		return;
	}

	if (!vrrp->family)
		vrrp->family = peer->address.ss_family;
	else if (peer->address.ss_family != vrrp->family) {
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: VRRP instance[%s] and unicast peer address"
				     "[%s] MUST be of the same family !!! Skipping..."
				   , vrrp->iname, strvec_slot(strvec, 0));
		FREE(peer);
		return;
	}

	for (i = 1; i < vector_size(strvec); i += 2) {
		if (i + 1 >= vector_size(strvec)) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) %s is missing a value", vrrp->iname, strvec_slot(strvec, i));
			break;
		}
		if (read_unsigned(strvec_slot(strvec, i + 1), &ttl, 0, 255, false)) {
			if (!strcmp(strvec_slot(strvec, i), "min_ttl"))
				peer->min_ttl = ttl;
			else if (!strcmp(strvec_slot(strvec, i), "max_ttl"))
				peer->max_ttl = ttl;
			else {
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown unicast_peer option %s", vrrp->iname, strvec_slot(strvec, i));
				break;
			}
			vrrp->check_unicast_src = true;
		}
	}

	if (peer->min_ttl > peer->max_ttl)
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) min_ttl %u > max_ttl %u - all packets will be discarded", vrrp->iname, peer->min_ttl, peer->max_ttl);

	list_add_tail(&peer->e_list, &vrrp->unicast_peer);
}

void
alloc_vrrp_track_if(const vector_t *strvec)
{
	vrrp_t *vrrp = list_last_entry(&vrrp_data->vrrp, vrrp_t, e_list);

	alloc_track_if(vrrp->iname, &vrrp->track_ifp, strvec);
}

void
alloc_vrrp_track_script(const vector_t *strvec)
{
	vrrp_t *vrrp = list_last_entry(&vrrp_data->vrrp, vrrp_t, e_list);

	alloc_track_script(vrrp->iname, &vrrp->track_script, strvec);
}

void
alloc_vrrp_track_file(const vector_t *strvec)
{
	vrrp_t *vrrp = list_last_entry(&vrrp_data->vrrp, vrrp_t, e_list);

	vrrp_alloc_track_file(vrrp->iname, &vrrp_data->vrrp_track_files, &vrrp->track_file, strvec);
}

#ifdef _WITH_TRACK_PROCESS_
void
alloc_vrrp_track_process(const vector_t *strvec)
{
	vrrp_t *vrrp = list_last_entry(&vrrp_data->vrrp, vrrp_t, e_list);

	alloc_track_process(vrrp->iname, &vrrp->track_process, strvec);
}
#endif

#ifdef _WITH_BFD_
void
alloc_vrrp_track_bfd(const vector_t *strvec)
{
	vrrp_t *vrrp = list_last_entry(&vrrp_data->vrrp, vrrp_t, e_list);

	alloc_track_bfd(vrrp->iname, &vrrp->track_bfd, strvec);
}
#endif

void
alloc_vrrp_group_track_if(const vector_t *strvec)
{
	vrrp_sgroup_t *sgroup = list_last_entry(&vrrp_data->vrrp_sync_group, vrrp_sgroup_t, e_list);

	alloc_track_if(sgroup->gname, &sgroup->track_ifp, strvec);
}

void
alloc_vrrp_group_track_script(const vector_t *strvec)
{
	vrrp_sgroup_t *sgroup = list_last_entry(&vrrp_data->vrrp_sync_group, vrrp_sgroup_t, e_list);

	alloc_track_script(sgroup->gname, &sgroup->track_script, strvec);
}

void
alloc_vrrp_group_track_file(const vector_t *strvec)
{
	vrrp_sgroup_t *sgroup = list_last_entry(&vrrp_data->vrrp_sync_group, vrrp_sgroup_t, e_list);

	vrrp_alloc_track_file(sgroup->gname, &vrrp_data->vrrp_track_files, &sgroup->track_file, strvec);
}

#ifdef _WITH_TRACK_PROCESS_
void
alloc_vrrp_group_track_process(const vector_t *strvec)
{
	vrrp_sgroup_t *sgroup = list_last_entry(&vrrp_data->vrrp_sync_group, vrrp_sgroup_t, e_list);

	alloc_track_process(sgroup->gname, &sgroup->track_process, strvec);
}
#endif

#ifdef _WITH_BFD_
void
alloc_vrrp_group_track_bfd(const vector_t *strvec)
{
	vrrp_sgroup_t *sgroup = list_last_entry(&vrrp_data->vrrp_sync_group, vrrp_sgroup_t, e_list);

	alloc_track_bfd(sgroup->gname, &sgroup->track_bfd, strvec);
}
#endif

void
alloc_vrrp_vip(const vector_t *strvec)
{
	vrrp_t *vrrp = list_last_entry(&vrrp_data->vrrp, vrrp_t, e_list);
	ip_address_t *last_ipaddr = NULL, *tail_ipaddr;
	sa_family_t address_family;

	if (!list_empty(&vrrp->vip))
		last_ipaddr = list_last_entry(&vrrp->vip, ip_address_t, e_list);

	alloc_ipaddress(&vrrp->vip, strvec, false);

	tail_ipaddr = list_last_entry(&vrrp->vip, ip_address_t, e_list);
	if (!list_empty(&vrrp->vip) && tail_ipaddr != last_ipaddr) {
		address_family = IP_FAMILY(tail_ipaddr);

		if (vrrp->family == AF_UNSPEC)
			vrrp->family = address_family;
		else if (address_family != vrrp->family) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s): address family must match VRRP instance [%s] - ignoring", vrrp->iname, strvec_slot(strvec, 0));
			free_ipaddress(tail_ipaddr);
			return;
		}

		vrrp->vip_cnt++;
	}
}

void
alloc_vrrp_evip(const vector_t *strvec)
{
	vrrp_t *vrrp = list_last_entry(&vrrp_data->vrrp, vrrp_t, e_list);

	alloc_ipaddress(&vrrp->evip, strvec, false);
}

void
alloc_vrrp_vroute(const vector_t *strvec)
{
	vrrp_t *vrrp = list_last_entry(&vrrp_data->vrrp, vrrp_t, e_list);

	alloc_route(&vrrp->vroutes, strvec, false);
}

void
alloc_vrrp_vrule(const vector_t *strvec)
{
	vrrp_t *vrrp = list_last_entry(&vrrp_data->vrrp, vrrp_t, e_list);

	alloc_rule(&vrrp->vrules, strvec, false);
}

void
alloc_vrrp_script(const char *sname)
{
	vrrp_script_t *new;

	/* Allocate new VRRP script structure */
	PMALLOC(new);
	INIT_LIST_HEAD(&new->e_list);
	INIT_LIST_HEAD(&new->tracking_vrrp);
	new->sname = STRDUP(sname);
	new->interval = VRRP_SCRIPT_DI * TIMER_HZ;
	new->timeout = VRRP_SCRIPT_DT * TIMER_HZ;
	new->weight = VRRP_SCRIPT_DW;
//	new->last_status = VRRP_SCRIPT_STATUS_NOT_SET;
	new->init_state = SCRIPT_INIT_STATE_INIT;
	new->state = SCRIPT_STATE_IDLE;
	new->rise = 1;
	new->fall = 1;
	list_add_tail(&new->e_list, &vrrp_data->vrrp_script);
}

#ifdef _WITH_TRACK_PROCESS_
void
alloc_vrrp_process(const char *pname)
{
	vrrp_tracked_process_t *new;

	/* Allocate new VRRP file structure */
	PMALLOC(new);
	INIT_LIST_HEAD(&new->e_list);
	new->pname = STRDUP(pname);
	new->quorum = 1;
	new->quorum_max = UINT_MAX;
	INIT_LIST_HEAD(&new->tracking_vrrp);
	list_add_tail(&new->e_list, &vrrp_data->vrrp_track_processes);
}
#endif

/* data facility functions */
void
alloc_vrrp_buffer(size_t len)
{
	if (len <= vrrp_buffer_len)
		return;

	if (vrrp_buffer)
		FREE(vrrp_buffer);

	vrrp_buffer = MALLOC(len);
	vrrp_buffer_len = (vrrp_buffer) ? len : 0;
}

void
free_vrrp_buffer(void)
{
	/* If the configuration failed, we may not have
	 * allocated a buffer */
	if (!vrrp_buffer)
		return;

	FREE(vrrp_buffer);
	vrrp_buffer = NULL;
	vrrp_buffer_len = 0;
}

vrrp_data_t *
alloc_vrrp_data(void)
{
	vrrp_data_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->static_track_groups);
	INIT_LIST_HEAD(&new->static_addresses);
	INIT_LIST_HEAD(&new->static_routes);
	INIT_LIST_HEAD(&new->static_rules);
	INIT_LIST_HEAD(&new->vrrp_sync_group);
	INIT_LIST_HEAD(&new->vrrp);
	INIT_LIST_HEAD(&new->vrrp_script);
	INIT_LIST_HEAD(&new->vrrp_track_files);
#ifdef _WITH_TRACK_PROCESS_
	INIT_LIST_HEAD(&new->vrrp_track_processes);
#endif
#ifdef _WITH_BFD_
	INIT_LIST_HEAD(&new->vrrp_track_bfds);
#endif
	INIT_LIST_HEAD(&new->vrrp_socket_pool);

	return new;
}

void
free_vrrp_data(vrrp_data_t * data)
{
	free_ipaddress_list(&data->static_addresses);
	free_iproute_list(&data->static_routes);
	free_iprule_list(&data->static_rules);
	free_static_track_groups_list(&data->static_track_groups);
	free_vrrp_list(&data->vrrp);
	free_sync_group_list(&data->vrrp_sync_group);
	free_vscript_list(&data->vrrp_script);
	free_track_file_list(&data->vrrp_track_files);
#ifdef _WITH_TRACK_PROCESS_
	free_vprocess_list(&data->vrrp_track_processes);
#endif
#ifdef _WITH_BFD_
	free_vrrp_tracked_bfd_list(&data->vrrp_track_bfds);
#endif
	FREE(data);
}

static void
dump_vrrp_data(FILE *fp, const vrrp_data_t * data)
{
	if (!list_empty(&data->static_addresses)) {
		conf_write(fp, "------< Static Addresses >------");
		dump_ipaddress_list(fp, &data->static_addresses);
	}
	if (!list_empty(&data->static_routes)) {
		conf_write(fp, "------< Static Routes >------");
		dump_iproute_list(fp, &data->static_routes);
	}
	if (!list_empty(&data->static_rules)) {
		conf_write(fp, "------< Static Rules >------");
		dump_iprule_list(fp, &data->static_rules);
	}
	if (!list_empty(&data->static_track_groups)) {
		conf_write(fp, "------< Static Track groups >------");
		dump_static_track_groups_list(fp, &data->static_track_groups);
	}
	if (!list_empty(&data->vrrp)) {
		conf_write(fp, "------< VRRP Topology >------");
		dump_vrrp_list(fp, &data->vrrp);
	}
	if (!list_empty(&data->vrrp_socket_pool)) {
		conf_write(fp, "------< VRRP Sockpool >------");
		dump_sock_pool(fp, &data->vrrp_socket_pool);
	}
	if (!list_empty(&data->vrrp_sync_group)) {
		conf_write(fp, "------< VRRP Sync groups >------");
		dump_sync_group_list(fp, &data->vrrp_sync_group);
	}
	if (!list_empty(&data->vrrp_script)) {
		conf_write(fp, "------< VRRP Scripts >------");
		dump_vscript_list(fp, &data->vrrp_script);
	}
	if (!list_empty(&data->vrrp_track_files)) {
		conf_write(fp, "------< VRRP Track files >------");
		dump_track_file_list(fp, &data->vrrp_track_files);
	}
#ifdef _WITH_TRACK_PROCESS_
	if (!list_empty(&data->vrrp_track_processes)) {
		conf_write(fp, "------< VRRP Track processes >------");
		dump_vprocess_list(fp, &data->vrrp_track_processes);
	}
#endif
#ifdef _WITH_BFD_
	if (!list_empty(&data->vrrp_track_bfds)) {
		conf_write(fp, "------< VRRP Track BFDs >------");
		dump_vrrp_tracked_bfd_list(fp, &data->vrrp_track_bfds);
	}
#endif
}

void
dump_data_vrrp(FILE *fp)
{
	list_head_t *ifq;

	dump_global_data(fp, global_data);

	if (!list_empty(&garp_delay)) {
		conf_write(fp, "------< Gratuitous ARP delays >------");
		dump_garp_delay_list(fp, &garp_delay);
	}

	dump_vrrp_data(fp, vrrp_data);

	ifq = get_interface_queue();
	if (!list_empty(ifq)) {
		conf_write(fp, "------< Interfaces >------");
		dump_interface_queue(fp, ifq);
	}
}
