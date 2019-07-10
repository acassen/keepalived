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
#ifdef _HAVE_FIB_ROUTING_
#include "vrrp_iprule.h"
#include "vrrp_iproute.h"
#endif
#include "vrrp_track.h"
#include "vrrp_sock.h"
#ifdef _WITH_SNMP_RFCV3_
#include "vrrp_snmp.h"
#endif
#include "vrrp_static_track.h"
#include "parser.h"

/* global vars */
vrrp_data_t *vrrp_data = NULL;
vrrp_data_t *old_vrrp_data = NULL;
char *vrrp_buffer;
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

/* Static addresses facility function */
void
alloc_saddress(const vector_t *strvec)
{
	if (!LIST_EXISTS(vrrp_data->static_addresses))
		vrrp_data->static_addresses = alloc_list(free_ipaddress, dump_ipaddress);
	alloc_ipaddress(vrrp_data->static_addresses, strvec, NULL, true);
}

#ifdef _HAVE_FIB_ROUTING_
/* Static routes facility function */
void
alloc_sroute(const vector_t *strvec)
{
	if (!LIST_EXISTS(vrrp_data->static_routes))
		vrrp_data->static_routes = alloc_list(free_iproute, dump_iproute);
	alloc_route(vrrp_data->static_routes, strvec, true);
}

/* Static rules facility function */
void
alloc_srule(const vector_t *strvec)
{
	if (!LIST_EXISTS(vrrp_data->static_rules))
		vrrp_data->static_rules = alloc_list(free_iprule, dump_iprule);
	alloc_rule(vrrp_data->static_rules, strvec, true);
}
#endif

/* VRRP facility functions */
static void
free_vgroup(void *data)
{
	vrrp_sgroup_t *vgroup = data;

	if (vgroup->iname) {
		log_message(LOG_INFO, "sync group %s - iname vector exists when freeing group", vgroup->gname);
		free_strvec(vgroup->iname);
	}
	FREE_CONST(vgroup->gname);
	free_list(&vgroup->vrrp_instances);
	free_list(&vgroup->track_ifp);
	free_list(&vgroup->track_script);
	free_list(&vgroup->track_file);
#ifdef _WITH_CN_PROC_
	free_list(&vgroup->track_process);
#endif
#ifdef _WITH_BFD_
	free_list(&vgroup->track_bfd);
#endif
	free_notify_script(&vgroup->script_backup);
	free_notify_script(&vgroup->script_master);
	free_notify_script(&vgroup->script_fault);
	free_notify_script(&vgroup->script_stop);
	free_notify_script(&vgroup->script);
	FREE(vgroup);
}

static void
dump_notify_script(FILE *fp, const notify_script_t *script, const char *type)
{
	if (!script)
		return;

	conf_write(fp, "   %s state transition script = %s, uid:gid %u:%u", type,
	       cmd_str(script), script->uid, script->gid);
}

static void
dump_vgroup(FILE *fp, const void *data)
{
	const vrrp_sgroup_t *vgroup = data;
	element e;

	conf_write(fp, " VRRP Sync Group = %s, %s", vgroup->gname, get_state_str(vgroup->state));
	if (vgroup->vrrp_instances) {
		conf_write(fp, "   VRRP member instances = %u", LIST_SIZE(vgroup->vrrp_instances));
		for (e = LIST_HEAD(vgroup->vrrp_instances); e; ELEMENT_NEXT(e)) {
			vrrp_t *vrrp = ELEMENT_DATA(e);
			conf_write(fp, "     %s", vrrp->iname);
		}
	}
	if (vgroup->sgroup_tracking_weight)
		conf_write(fp, "   sync group tracking weight set");
	conf_write(fp, "   Using smtp notification = %s", vgroup->smtp_alert ? "yes" : "no");
	if (!LIST_ISEMPTY(vgroup->track_ifp)) {
		conf_write(fp, "   Tracked interfaces = %u", LIST_SIZE(vgroup->track_ifp));
		dump_list(fp, vgroup->track_ifp);
	}
	if (!LIST_ISEMPTY(vgroup->track_script)) {
		conf_write(fp, "   Tracked scripts = %u", LIST_SIZE(vgroup->track_script));
		dump_list(fp, vgroup->track_script);
	}
	if (!LIST_ISEMPTY(vgroup->track_file)) {
		conf_write(fp, "   Tracked files = %u", LIST_SIZE(vgroup->track_file));
		dump_list(fp, vgroup->track_file);
	}
#ifdef _WITH_CN_PROC_
	if (!LIST_ISEMPTY(vgroup->track_process)) {
		conf_write(fp, "   Tracked process = %u", LIST_SIZE(vgroup->track_process));
		dump_list(fp, vgroup->track_process);
	}
#endif
#ifdef _WITH_BFD_
	if (!LIST_ISEMPTY(vgroup->track_bfd)) {
		conf_write(fp, "   Tracked BFDs = %u", LIST_SIZE(vgroup->track_bfd));
		dump_list(fp, vgroup->track_bfd);
	}
#endif
	dump_notify_script(fp, vgroup->script_backup, "Backup");
	dump_notify_script(fp, vgroup->script_master, "Master");
	dump_notify_script(fp, vgroup->script_fault, "Fault");
	dump_notify_script(fp, vgroup->script_stop, "Stop");
	dump_notify_script(fp, vgroup->script, "Generic");
}

void
dump_tracking_vrrp(FILE *fp, const void *data)
{
	const tracking_vrrp_t *tvp = (const tracking_vrrp_t *)data;
	const vrrp_t *vrrp = tvp->vrrp;

	conf_write(fp, "     %s, weight %d%s%s", vrrp->iname, tvp->weight, tvp->weight_multiplier == -1 ? " reverse" : "", tvp->type == TRACK_VRRP_DYNAMIC ? " (dynamic)" : "");
}

static void
free_vscript(void *data)
{
	vrrp_script_t *vscript = data;

	free_list(&vscript->tracking_vrrp);
	FREE_CONST(vscript->sname);
	FREE_PTR(vscript->script.args);
	FREE(vscript);
}
static void
dump_vscript(FILE *fp, const void *data)
{
	const vrrp_script_t *vscript = data;
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
	conf_write(fp, "   VRRP instances = %u", vscript->tracking_vrrp ? LIST_SIZE(vscript->tracking_vrrp) : 0);
	if (vscript->tracking_vrrp)
		dump_list(fp, vscript->tracking_vrrp);
	conf_write(fp, "   State = %s",
			vscript->state == SCRIPT_STATE_IDLE ? "idle" :
			vscript->state == SCRIPT_STATE_RUNNING ? "running" :
			vscript->state == SCRIPT_STATE_REQUESTING_TERMINATION ? "requested termination" :
			vscript->state == SCRIPT_STATE_FORCING_TERMINATION ? "forcing termination" : "unknown");
}

static void
free_vfile(void *data)
{
	vrrp_tracked_file_t *vfile = data;

	free_list(&vfile->tracking_vrrp);
	FREE_CONST(vfile->fname);
	FREE_CONST(vfile->file_path);
	FREE(vfile);
}
static void
dump_vfile(FILE *fp, const void *data)
{
	const vrrp_tracked_file_t *vfile = data;

	conf_write(fp, " VRRP Track file = %s", vfile->fname);
	conf_write(fp, "   File = %s", vfile->file_path);
	conf_write(fp, "   Status = %d", vfile->last_status);
	conf_write(fp, "   Weight = %d%s", vfile->weight, vfile->weight_reverse ? " reverse" : "");
	conf_write(fp, "   Tracking VRRP instances = %u", vfile->tracking_vrrp ? LIST_SIZE(vfile->tracking_vrrp) : 0);
	if (vfile->tracking_vrrp)
		dump_list(fp, vfile->tracking_vrrp);
}

#ifdef _WITH_CN_PROC_
static void
free_vprocess(void *data)
{
	vrrp_tracked_process_t *vprocess = data;

	free_list(&vprocess->tracking_vrrp);
	FREE_CONST(vprocess->pname);
	FREE_CONST(vprocess->process_path);
	FREE_CONST_PTR(vprocess->process_params);
	FREE(vprocess);
}
static void
dump_vprocess(FILE *fp, const void *data)
{
	const vrrp_tracked_process_t *vprocess = data;
	char *params;
	char *p;

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
	conf_write(fp, "   Tracking VRRP instances = %u", vprocess->tracking_vrrp ? LIST_SIZE(vprocess->tracking_vrrp) : 0);
	if (vprocess->tracking_vrrp)
		dump_list(fp, vprocess->tracking_vrrp);
}
#endif

#ifdef _WITH_BFD_
/* Track bfd dump */
static void
dump_vrrp_bfd(FILE *fp, const void *track_data)
{
	const vrrp_tracked_bfd_t *vbfd = track_data;

	conf_write(fp, " VRRP Track BFD = %s", vbfd->bname);
	conf_write(fp, "   Weight = %d%s", vbfd->weight, vbfd->weight_reverse ? " reverse" : "");
	conf_write(fp, "   Bfd is %s", vbfd->bfd_up ? "up" : "down");
	conf_write(fp, "   Tracking VRRP instances = %u", vbfd->tracking_vrrp ? LIST_SIZE(vbfd->tracking_vrrp) : 0);
	if (vbfd->tracking_vrrp)
		dump_list(fp, vbfd->tracking_vrrp);
}

static void
free_vrrp_bfd(void *track_data)
{
	vrrp_tracked_bfd_t *vbfd = track_data;

	free_list(&vbfd->tracking_vrrp);
	FREE(track_data);
}
#endif

/* Socket pool functions */
static void
free_sock(void *sock_data)
{
	sock_t *sock = sock_data;

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
	FREE(sock_data);
}

static void
dump_sock(FILE *fp, const void *sock_data)
{
	const sock_t *sock = sock_data;

	conf_write(fp, "VRRP sockpool: [ifindex(%u), family(%s), proto(%d), unicast(%d), fd(%d,%d)]"
			    , sock->ifp->ifindex
			    , sock->family == AF_INET ? "IPv4" : sock->family == AF_INET6 ? "IPv6" : "unknown"
			    , sock->proto
			    , sock->unicast
			    , sock->fd_in
			    , sock->fd_out);
}

static void
dump_sock_pool(FILE *fp, const list sock_pool)
{
	const sock_t *sock;
	element e;
	const vrrp_t *vrrp;

	LIST_FOREACH(sock_pool, sock, e) {
		conf_write(fp, " fd_in %d fd_out = %d", sock->fd_in, sock->fd_out);
		conf_write(fp, "   Interface = %s", sock->ifp->ifname);
		conf_write(fp, "   Family = %s", sock->family == AF_INET ? "IPv4" : sock->family == AF_INET6 ? "IPv6" : "unknown");
		conf_write(fp, "   Protocol = %s", sock->proto == IPPROTO_AH ? "AH" : sock->proto == IPPROTO_VRRP ? "VRRP" : "unknown");
		conf_write(fp, "   Type = %scast", sock->unicast ? "Uni" : "Multi");
		conf_write(fp, "   Rx buf size = %d", sock->rx_buf_size);
		conf_write(fp, "   VRRP instances");
		rb_for_each_entry_const(vrrp, &sock->rb_vrid, rb_vrid)
			conf_write(fp, "     %s vrid %d", vrrp->iname, vrrp->vrid);
	}
}

static void
free_unicast_peer(void *data)
{
	FREE(data);
}

static void
dump_unicast_peer(FILE *fp, const void *data)
{
	const unicast_peer_t *peer = data;

	conf_write(fp, "     %s", inet_sockaddrtos(&peer->address));
#ifdef CHECKSUM_DIAGNOSTICS
	conf_write(fp, "       last rx checksum = 0x%4.4x, priority %d", peer->chk.last_rx_checksum, peer->chk.last_rx_priority);
	conf_write(fp, "       last tx checksum = 0x%4.4x, priority %d", peer->chk.last_tx_checksum, peer->chk.last_tx_priority);
#endif
}

static void
free_vrrp(void *data)
{
	vrrp_t *vrrp = data;

	FREE_CONST(vrrp->iname);
#ifdef _HAVE_VRRP_IPVLAN_
	FREE_PTR(vrrp->ipvlan_addr);
#endif
	FREE_PTR(vrrp->send_buffer);
	free_notify_script(&vrrp->script_backup);
	free_notify_script(&vrrp->script_master);
	free_notify_script(&vrrp->script_fault);
	free_notify_script(&vrrp->script_stop);
	free_notify_script(&vrrp->script);
	free_notify_script(&vrrp->script_master_rx_lower_pri);
	FREE_PTR(vrrp->stats);

	free_list(&vrrp->track_ifp);
	free_list(&vrrp->track_script);
	free_list(&vrrp->track_file);
#ifdef _WITH_CN_PROC_
	free_list(&vrrp->track_process);
#endif
#ifdef _WITH_BFD_
	free_list(&vrrp->track_bfd);
#endif
	free_list(&vrrp->unicast_peer);
	free_list(&vrrp->vip);
	free_list(&vrrp->evip);
	free_list(&vrrp->vroutes);
	free_list(&vrrp->vrules);
	FREE(vrrp);
}

static void
dump_vrrp(FILE *fp, const void *data)
{
	const vrrp_t *vrrp = data;
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
#ifdef _HAVE_VRRP_IPVLAN_
	else if (__test_bit(VRRP_IPVLAN_BIT, &vrrp->vmac_flags))
		conf_write(fp, "   Use IPVLAN, i/f %s, is_up = %s%s%s, type %s",
				vrrp->vmac_ifname,
				__test_bit(VRRP_VMAC_UP_BIT, &vrrp->vmac_flags) ? "true" : "false",
				vrrp->ipvlan_addr ? ", i/f address = " : "",
				vrrp->ipvlan_addr ? ipaddresstos(NULL, vrrp->ipvlan_addr) : "",
#ifdef IPVLAN_F_VEPA	/* Since Linux v4.15 */
				!vrrp->ipvlan_type ? "bridge" : vrrp->ipvlan_type == IPVLAN_F_PRIVATE ? "private" : vrrp->ipvlan_type == IPVLAN_F_VEPA ? "vepa" : "unknown"
#else
				"bridge"
#endif
					);
#endif
	if (vrrp->ifp->is_ours) {
		conf_write(fp, "   Interface = %s, %s on %s%s", IF_NAME(vrrp->ifp),
				__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags) ? "vmac" : "ipvlan",
				vrrp->ifp != vrrp->ifp->base_ifp ? vrrp->ifp->base_ifp->ifname : "(unknown)",
				__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags) ? ", xmit base i/f" : "");
	} else
#endif
		conf_write(fp, "   Interface = %s", IF_NAME(vrrp->ifp));
#ifdef _HAVE_VRRP_VMAC_
	if (vrrp->configured_ifp != vrrp->ifp->base_ifp && vrrp->ifp->is_ours)
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

#ifdef CHECKSUM_DIAGNOSTICS
	conf_write(fp, "   last rx checksum = 0x%4.4x, priority %d", vrrp->chk.last_rx_checksum, vrrp->chk.last_rx_priority);
	conf_write(fp, "   last tx checksum = 0x%4.4x, priority %d", vrrp->chk.last_tx_checksum, vrrp->chk.last_tx_priority);
#endif

	if (!LIST_ISEMPTY(vrrp->vip)) {
		conf_write(fp, "   Virtual IP = %u", LIST_SIZE(vrrp->vip));
		dump_list(fp, vrrp->vip);
	}
	if (!LIST_ISEMPTY(vrrp->evip)) {
		conf_write(fp, "   Virtual IP Excluded = %u",
			LIST_SIZE(vrrp->evip));
		dump_list(fp, vrrp->evip);
	}
	if (!LIST_ISEMPTY(vrrp->unicast_peer)) {
		conf_write(fp, "   Unicast Peer = %u",
			LIST_SIZE(vrrp->unicast_peer));
		dump_list(fp, vrrp->unicast_peer);
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
#ifdef _HAVE_FIB_ROUTING_
	if (!LIST_ISEMPTY(vrrp->vroutes)) {
		conf_write(fp, "   Virtual Routes = %u", LIST_SIZE(vrrp->vroutes));
		dump_list(fp, vrrp->vroutes);
	}
	if (!LIST_ISEMPTY(vrrp->vrules)) {
		conf_write(fp, "   Virtual Rules = %u", LIST_SIZE(vrrp->vrules));
		dump_list(fp, vrrp->vrules);
	}
#endif

	if (!LIST_ISEMPTY(vrrp->track_ifp)) {
		conf_write(fp, "   Tracked interfaces = %u", LIST_SIZE(vrrp->track_ifp));
		dump_list(fp, vrrp->track_ifp);
	}
	if (!LIST_ISEMPTY(vrrp->track_script)) {
		conf_write(fp, "   Tracked scripts = %u", LIST_SIZE(vrrp->track_script));
		dump_list(fp, vrrp->track_script);
	}
	if (!LIST_ISEMPTY(vrrp->track_file)) {
		conf_write(fp, "   Tracked files = %u", LIST_SIZE(vrrp->track_file));
		dump_list(fp, vrrp->track_file);
	}
#ifdef _WITH_CN_PROC_
	if (!LIST_ISEMPTY(vrrp->track_process)) {
		conf_write(fp, "   Tracked processes = %u", LIST_SIZE(vrrp->track_process));
		dump_list(fp, vrrp->track_process);
	}
#endif
#ifdef _WITH_BFD_
	if (!LIST_ISEMPTY(vrrp->track_bfd)) {
		conf_write(fp, "   Tracked BFDs = %u", LIST_SIZE(vrrp->track_bfd));
		dump_list(fp, vrrp->track_bfd);
	}
#endif

	conf_write(fp, "   Using smtp notification = %s", vrrp->smtp_alert ? "yes" : "no");

	if (vrrp->script_backup)
		dump_notify_script(fp, vrrp->script_backup, "Backup");
	if (vrrp->script_master)
		dump_notify_script(fp, vrrp->script_master, "Master");
	if (vrrp->script_fault)
		dump_notify_script(fp, vrrp->script_fault, "Fault");
	if (vrrp->script_stop)
		dump_notify_script(fp, vrrp->script_stop, "Stop");
	if (vrrp->script)
		dump_notify_script(fp, vrrp->script, "Generic");
	if (vrrp->script_master_rx_lower_pri)
		dump_notify_script(fp, vrrp->script_master_rx_lower_pri, "Master rx lower pri");
	conf_write(fp, "   Notify priority changes = %s", vrrp->notify_priority_changes ? "true" : "false");
}

void
alloc_static_track_group(const char *gname)
{
	static_track_group_t *new;

	if (!LIST_EXISTS(vrrp_data->static_track_groups))
		vrrp_data->static_track_groups = alloc_list(free_tgroup, dump_tgroup);

	/* Allocate new VRRP group structure */
	new = (static_track_group_t *) MALLOC(sizeof(*new));
	new->gname = STRDUP(gname);

	list_add(vrrp_data->static_track_groups, new);
}

void
alloc_vrrp_sync_group(const char *gname)
{
	vrrp_sgroup_t *new;

	/* Allocate new VRRP group structure */
	new = (vrrp_sgroup_t *) MALLOC(sizeof(vrrp_sgroup_t));
	new->state = VRRP_STATE_INIT;
	new->last_email_state = VRRP_STATE_INIT;
	new->gname = STRDUP(gname);
	new->sgroup_tracking_weight = false;
	new->smtp_alert = -1;

	list_add(vrrp_data->vrrp_sync_group, new);
}

static vrrp_stats *
alloc_vrrp_stats(void)
{
	vrrp_stats *new;
	new = (vrrp_stats *) MALLOC(sizeof (vrrp_stats));
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
	new = (vrrp_t *) MALLOC(sizeof(vrrp_t));

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
#ifdef _WITH_FIREWALL_
	new->accept = PARAMETER_UNSET;
#endif
	new->garp_rep = global_data->vrrp_garp_rep;
	new->garp_refresh = global_data->vrrp_garp_refresh;
	new->garp_refresh_rep = global_data->vrrp_garp_refresh_rep;
	new->garp_delay = global_data->vrrp_garp_delay;
	new->garp_lower_prio_delay = PARAMETER_UNSET;
	new->garp_lower_prio_rep = PARAMETER_UNSET;
	new->lower_prio_no_advert = PARAMETER_UNSET;
	new->higher_prio_send_advert = PARAMETER_UNSET;
#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
	new->unicast_chksum_compat = CHKSUM_COMPATIBILITY_NONE;
#endif
	new->smtp_alert = -1;
	new->notify_priority_changes = -1;

	new->skip_check_adv_addr = global_data->vrrp_skip_check_adv_addr;
	new->strict_mode = PARAMETER_UNSET;

	list_add(vrrp_data->vrrp, new);
}

void
alloc_vrrp_unicast_peer(const vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	unicast_peer_t *peer;

	if (!LIST_EXISTS(vrrp->unicast_peer))
		vrrp->unicast_peer = alloc_list(free_unicast_peer, dump_unicast_peer);

	/* Allocate new unicast peer */
	peer = (unicast_peer_t *) MALLOC(sizeof(unicast_peer_t));
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

	list_add(vrrp->unicast_peer, peer);
}

void
alloc_vrrp_track_if(const vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->track_ifp))
		vrrp->track_ifp = alloc_list(free_track_if, dump_track_if);
	alloc_track_if(vrrp->iname, vrrp->track_ifp, strvec);
}

void
alloc_vrrp_track_script(const vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->track_script))
		vrrp->track_script = alloc_list(free_track_script, dump_track_script);
	alloc_track_script(vrrp->iname, vrrp->track_script, strvec);
}

void
alloc_vrrp_track_file(const vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->track_file))
		vrrp->track_file = alloc_list(free_track_file, dump_track_file);
	alloc_track_file(vrrp->iname, vrrp->track_file, strvec);
}

#ifdef _WITH_CN_PROC_
void
alloc_vrrp_track_process(const vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->track_process))
		vrrp->track_process = alloc_list(free_track_process, dump_track_process);
	alloc_track_process(vrrp->iname, vrrp->track_process, strvec);
}
#endif

#ifdef _WITH_BFD_
void
alloc_vrrp_track_bfd(const vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->track_bfd))
		vrrp->track_bfd = alloc_list(free_vrrp_tracked_bfd, dump_vrrp_tracked_bfd);
	alloc_track_bfd(vrrp->iname, vrrp->track_bfd, strvec);
}
#endif

void
alloc_vrrp_group_track_if(const vector_t *strvec)
{
	vrrp_sgroup_t *sgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);

	if (!LIST_EXISTS(sgroup->track_ifp))
		sgroup->track_ifp = alloc_list(free_track_if, dump_track_if);
	alloc_track_if(sgroup->gname, sgroup->track_ifp, strvec);
}

void
alloc_vrrp_group_track_script(const vector_t *strvec)
{
	vrrp_sgroup_t *sgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);

	if (!LIST_EXISTS(sgroup->track_script))
		sgroup->track_script = alloc_list(free_track_script, dump_track_script);
	alloc_track_script(sgroup->gname, sgroup->track_script, strvec);
}

void
alloc_vrrp_group_track_file(const vector_t *strvec)
{
	vrrp_sgroup_t *sgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);

	if (!LIST_EXISTS(sgroup->track_file))
		sgroup->track_file = alloc_list(free_track_file, dump_track_file);
	alloc_track_file(sgroup->gname, sgroup->track_file, strvec);
}

#ifdef _WITH_CN_PROC_
void
alloc_vrrp_group_track_process(const vector_t *strvec)
{
	vrrp_sgroup_t *sgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);

	if (!LIST_EXISTS(sgroup->track_process))
		sgroup->track_process = alloc_list(free_track_process, dump_track_process);
	alloc_track_process(sgroup->gname, sgroup->track_process, strvec);
}
#endif

#ifdef _WITH_BFD_
void
alloc_vrrp_group_track_bfd(const vector_t *strvec)
{
	vrrp_sgroup_t *sgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);

	if (!LIST_EXISTS(sgroup->track_bfd))
		sgroup->track_bfd = alloc_list(free_vrrp_tracked_bfd, dump_vrrp_tracked_bfd);
	alloc_track_bfd(sgroup->gname, sgroup->track_bfd, strvec);
}
#endif

void
alloc_vrrp_vip(const vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	void *list_end = NULL;
	sa_family_t address_family;

	if (!LIST_EXISTS(vrrp->vip))
		vrrp->vip = alloc_list(free_ipaddress, dump_ipaddress);
	else if (!LIST_ISEMPTY(vrrp->vip))
		list_end = LIST_TAIL_DATA(vrrp->vip);

	alloc_ipaddress(vrrp->vip, strvec, vrrp->ifp, false);

	if (!LIST_ISEMPTY(vrrp->vip) && LIST_TAIL_DATA(vrrp->vip) != list_end) {
		address_family = IP_FAMILY((ip_address_t*)LIST_TAIL_DATA(vrrp->vip));

		if (vrrp->family == AF_UNSPEC)
			vrrp->family = address_family;
		else if (address_family != vrrp->family) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s): address family must match VRRP instance [%s] - ignoring", vrrp->iname, strvec_slot(strvec, 0));
			free_list_element(vrrp->vip, vrrp->vip->tail);
		}
	}
}

void
alloc_vrrp_evip(const vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->evip))
		vrrp->evip = alloc_list(free_ipaddress, dump_ipaddress);
	alloc_ipaddress(vrrp->evip, strvec, vrrp->ifp, false);
}

#ifdef _HAVE_FIB_ROUTING_
void
alloc_vrrp_vroute(const vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->vroutes))
		vrrp->vroutes = alloc_list(free_iproute, dump_iproute);
	alloc_route(vrrp->vroutes, strvec, false);
}

void
alloc_vrrp_vrule(const vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->vrules))
		vrrp->vrules = alloc_list(free_iprule, dump_iprule);
	alloc_rule(vrrp->vrules, strvec, false);
}
#endif

void
alloc_vrrp_script(const char *sname)
{
	vrrp_script_t *new;

	/* Allocate new VRRP script structure */
	new = (vrrp_script_t *) MALLOC(sizeof(vrrp_script_t));
	new->sname = STRDUP(sname);
	new->interval = VRRP_SCRIPT_DI * TIMER_HZ;
	new->timeout = VRRP_SCRIPT_DT * TIMER_HZ;
	new->weight = VRRP_SCRIPT_DW;
//	new->last_status = VRRP_SCRIPT_STATUS_NOT_SET;
	new->init_state = SCRIPT_INIT_STATE_INIT;
	new->state = SCRIPT_STATE_IDLE;
	new->rise = 1;
	new->fall = 1;
	list_add(vrrp_data->vrrp_script, new);
}

void
alloc_vrrp_file(const char *fname)
{
	vrrp_tracked_file_t *new;

	/* Allocate new VRRP file structure */
	new = (vrrp_tracked_file_t *) MALLOC(sizeof(vrrp_tracked_file_t));
	new->fname = STRDUP(fname);
	new->weight = 1;
	list_add(vrrp_data->vrrp_track_files, new);
}

#ifdef _WITH_CN_PROC_
void
alloc_vrrp_process(const char *pname)
{
	vrrp_tracked_process_t *new;

	/* Allocate new VRRP file structure */
	new = (vrrp_tracked_process_t *) MALLOC(sizeof(vrrp_tracked_process_t));
	new->pname = STRDUP(pname);
	new->quorum = 1;
	new->quorum_max = UINT_MAX;
	list_add(vrrp_data->vrrp_track_processes, new);
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

	vrrp_buffer = (char *) MALLOC(len);
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

	new = (vrrp_data_t *) MALLOC(sizeof(vrrp_data_t));
	new->vrrp = alloc_list(free_vrrp, dump_vrrp);
	new->vrrp_sync_group = alloc_list(free_vgroup, dump_vgroup);
	new->vrrp_script = alloc_list(free_vscript, dump_vscript);
	new->vrrp_track_files = alloc_list(free_vfile, dump_vfile);
#ifdef _WITH_CN_PROC_
	new->vrrp_track_processes = alloc_list(free_vprocess, dump_vprocess);
#endif
#ifdef _WITH_BFD_
	new->vrrp_track_bfds = alloc_list(free_vrrp_bfd, dump_vrrp_bfd);
#endif
	new->vrrp_socket_pool = alloc_list(free_sock, dump_sock);

	return new;
}

void
free_vrrp_data(vrrp_data_t * data)
{
	free_list(&data->static_addresses);
#ifdef _HAVE_FIB_ROUTING_
	free_list(&data->static_routes);
	free_list(&data->static_rules);
#endif
	free_list(&data->static_track_groups);
	free_list(&data->vrrp);
	free_list(&data->vrrp_sync_group);
	free_list(&data->vrrp_script);
	free_list(&data->vrrp_track_files);
#ifdef _WITH_CN_PROC_
	free_list(&data->vrrp_track_processes);
#endif
#ifdef _WITH_BFD_
	free_list(&data->vrrp_track_bfds);
#endif
	FREE(data);
}

static void
dump_vrrp_data(FILE *fp, const vrrp_data_t * data)
{
	if (!LIST_ISEMPTY(data->static_addresses)) {
		conf_write(fp, "------< Static Addresses >------");
		dump_list(fp, data->static_addresses);
	}
#ifdef _HAVE_FIB_ROUTING_
	if (!LIST_ISEMPTY(data->static_routes)) {
		conf_write(fp, "------< Static Routes >------");
		dump_list(fp, data->static_routes);
	}
	if (!LIST_ISEMPTY(data->static_rules)) {
		conf_write(fp, "------< Static Rules >------");
		dump_list(fp, data->static_rules);
	}
#endif
	if (!LIST_ISEMPTY(data->static_track_groups)) {
		conf_write(fp, "------< Static Track groups >------");
		dump_list(fp, data->static_track_groups);
	}
	if (!LIST_ISEMPTY(data->vrrp)) {
		conf_write(fp, "------< VRRP Topology >------");
		dump_list(fp, data->vrrp);
	}
	if (!LIST_ISEMPTY(data->vrrp_socket_pool)) {
		conf_write(fp, "------< VRRP Sockpool >------");
		dump_sock_pool(fp, data->vrrp_socket_pool);
	}
	if (!LIST_ISEMPTY(data->vrrp_sync_group)) {
		conf_write(fp, "------< VRRP Sync groups >------");
		dump_list(fp, data->vrrp_sync_group);
	}
	if (!LIST_ISEMPTY(data->vrrp_script)) {
		conf_write(fp, "------< VRRP Scripts >------");
		dump_list(fp, data->vrrp_script);
	}
	if (!LIST_ISEMPTY(data->vrrp_track_files)) {
		conf_write(fp, "------< VRRP Track files >------");
		dump_list(fp, data->vrrp_track_files);
	}
#ifdef _WITH_CN_PROC_
	if (!LIST_ISEMPTY(data->vrrp_track_processes)) {
		conf_write(fp, "------< VRRP Track processes >------");
		dump_list(fp, data->vrrp_track_processes);
	}
#endif
#ifdef _WITH_BFD_
	if (!LIST_ISEMPTY(data->vrrp_track_bfds)) {
		conf_write(fp, "------< VRRP Track BFDs >------");
		dump_list(fp, data->vrrp_track_bfds);
	}
#endif
}

void
dump_data_vrrp(FILE *fp)
{
	list ifl;

	dump_global_data(fp, global_data);

	if (!LIST_ISEMPTY(garp_delay)) {
		conf_write(fp, "------< Gratuitous ARP delays >------");
		dump_list(fp, garp_delay);
	}

	dump_vrrp_data(fp, vrrp_data);

	ifl = get_if_list();
	if (!LIST_ISEMPTY(ifl)) {
		conf_write(fp, "------< Interfaces >------");
		dump_list(fp, ifl);
	}

	clear_rt_names();
}
