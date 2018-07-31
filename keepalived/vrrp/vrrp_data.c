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
#include "vrrp_index.h"
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

static char *
get_state_str(int state)
{
	if (state == VRRP_STATE_INIT) return "INIT";
	if (state == VRRP_STATE_BACK) return "BACKUP";
	if (state == VRRP_STATE_MAST) return "MASTER";
	if (state == VRRP_STATE_FAULT) return "FAULT";
	if (state == VRRP_DISPATCHER) return "DISPATCHER";
	return "unknown";
}

/* Static addresses facility function */
void
alloc_saddress(vector_t *strvec)
{
	if (!LIST_EXISTS(vrrp_data->static_addresses))
		vrrp_data->static_addresses = alloc_list(free_ipaddress, dump_ipaddress);
	alloc_ipaddress(vrrp_data->static_addresses, strvec, NULL, true);
}

#ifdef _HAVE_FIB_ROUTING_
/* Static routes facility function */
void
alloc_sroute(vector_t *strvec)
{
	if (!LIST_EXISTS(vrrp_data->static_routes))
		vrrp_data->static_routes = alloc_list(free_iproute, dump_iproute);
	alloc_route(vrrp_data->static_routes, strvec, true);
}

/* Static rules facility function */
void
alloc_srule(vector_t *strvec)
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
	FREE(vgroup->gname);
	free_list(&vgroup->vrrp_instances);
	free_notify_script(&vgroup->script_backup);
	free_notify_script(&vgroup->script_master);
	free_notify_script(&vgroup->script_fault);
	free_notify_script(&vgroup->script_stop);
	free_notify_script(&vgroup->script);
	FREE(vgroup);
}

static void
dump_notify_script(FILE *fp, notify_script_t *script, char *type)
{
	if (!script)
		return;

	conf_write(fp, "   %s state transition script = %s, uid:gid %d:%d", type,
	       cmd_str(script), script->uid, script->gid);
}

static void
dump_vgroup(FILE *fp, void *data)
{
	vrrp_sgroup_t *vgroup = data;
	element e;

	conf_write(fp, " VRRP Sync Group = %s, %s", vgroup->gname, get_state_str(vgroup->state));
	if (vgroup->vrrp_instances) {
		conf_write(fp, "   VRRP member instances = %d", LIST_SIZE(vgroup->vrrp_instances));
		for (e = LIST_HEAD(vgroup->vrrp_instances); e; ELEMENT_NEXT(e)) {
			vrrp_t *vrrp = ELEMENT_DATA(e);
			conf_write(fp, "     %s", vrrp->iname);
		}
	}
	if (vgroup->sgroup_tracking_weight)
		conf_write(fp, "   sync group tracking weight set");
	conf_write(fp, "   Using smtp notification = %s", vgroup->smtp_alert ? "yes" : "no");
	if (!LIST_ISEMPTY(vgroup->track_ifp)) {
		conf_write(fp, "   Tracked interfaces = %d", LIST_SIZE(vgroup->track_ifp));
		dump_list(fp, vgroup->track_ifp);
	}
	if (!LIST_ISEMPTY(vgroup->track_script)) {
		conf_write(fp, "   Tracked scripts = %d", LIST_SIZE(vgroup->track_script));
		dump_list(fp, vgroup->track_script);
	}
	if (!LIST_ISEMPTY(vgroup->track_file)) {
		conf_write(fp, "   Tracked files = %d", LIST_SIZE(vgroup->track_file));
		dump_list(fp, vgroup->track_file);
	}
	dump_notify_script(fp, vgroup->script_backup, "Backup");
	dump_notify_script(fp, vgroup->script_master, "Master");
	dump_notify_script(fp, vgroup->script_fault, "Fault");
	dump_notify_script(fp, vgroup->script_stop, "Stop");
	dump_notify_script(fp, vgroup->script, "Generic");
}

void
dump_tracking_vrrp(FILE *fp, void *data)
{
	tracking_vrrp_t *tvp = (tracking_vrrp_t *)data;
	vrrp_t *vrrp = tvp->vrrp;

	conf_write(fp, "     %s, weight %d", vrrp->iname, tvp->weight);
}

static void
free_vscript(void *data)
{
	vrrp_script_t *vscript = data;

	free_list(&vscript->tracking_vrrp);
	FREE(vscript->sname);
	FREE_PTR(vscript->script.args);
	FREE(vscript);
}
static void
dump_vscript(FILE *fp, void *data)
{
	vrrp_script_t *vscript = data;
	const char *str;

	conf_write(fp, " VRRP Script = %s", vscript->sname);
	conf_write(fp, "   Command = %s", cmd_str(&vscript->script));
	conf_write(fp, "   Interval = %lu sec", vscript->interval / TIMER_HZ);
	conf_write(fp, "   Timeout = %lu sec", vscript->timeout / TIMER_HZ);
	conf_write(fp, "   Weight = %d", vscript->weight);
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
	conf_write(fp, "   Script uid:gid = %d:%d", vscript->script.uid, vscript->script.gid);
	conf_write(fp, "   VRRP instances = %d", vscript->tracking_vrrp ? LIST_SIZE(vscript->tracking_vrrp) : 0);
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
	FREE(vfile->fname);
	FREE(vfile->file_path);
	FREE(vfile);
}
static void
dump_vfile(FILE *fp, void *data)
{
	vrrp_tracked_file_t *vfile = data;

	conf_write(fp, " VRRP Track file = %s", vfile->fname);
	conf_write(fp, "   File = %s", vfile->file_path);
	conf_write(fp, "   Weight = %d", vfile->weight);
	conf_write(fp, "   Tracking VRRP instances = %d", vfile->tracking_vrrp ? LIST_SIZE(vfile->tracking_vrrp) : 0);
	if (vfile->tracking_vrrp)
		dump_list(fp, vfile->tracking_vrrp);
}

#ifdef _WITH_BFD_
/* Track bfd dump */
static void
dump_vrrp_bfd(FILE *fp, void *track_data)
{
	vrrp_tracked_bfd_t *vbfd = track_data;

	conf_write(fp, " VRRP Track BFD = %s", vbfd->bname);
	conf_write(fp, "   Weight = %d", vbfd->weight);
	conf_write(fp, "   Tracking VRRP instances = %d", vbfd->tracking_vrrp ? LIST_SIZE(vbfd->tracking_vrrp) : 0);
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

	/* First of all cancel pending thread */
	thread_cancel(sock->thread);

	/* Close related socket */
	if (sock->fd_in > 0)
		close(sock->fd_in);
	if (sock->fd_out > 0)
		close(sock->fd_out);
	FREE(sock_data);
}

static void
dump_sock(FILE *fp, void *sock_data)
{
	sock_t *sock = sock_data;
	conf_write(fp, "VRRP sockpool: [ifindex(%u), proto(%u), unicast(%d), fd(%d,%d)]"
			    , sock->ifindex
			    , sock->proto
			    , sock->unicast
			    , sock->fd_in
			    , sock->fd_out);
}

static void
free_unicast_peer(void *data)
{
	FREE(data);
}

static void
dump_unicast_peer(FILE *fp, void *data)
{
	struct sockaddr_storage *peer = data;

	conf_write(fp, "     %s", inet_sockaddrtos(peer));
}

static void
free_vrrp(void *data)
{
	vrrp_t *vrrp = data;

	FREE(vrrp->iname);
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
dump_vrrp(FILE *fp, void *data)
{
	vrrp_t *vrrp = data;
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
				conf_write(fp, "   Master advert int = %.2f sec", (float)vrrp->master_adver_int / TIMER_HZ);
		}
	}
	conf_write(fp, "   Wantstate = %s", get_state_str(vrrp->wantstate));
	if (fp) {
		conf_write(fp, "   Number of interface and track script faults = %u", vrrp->num_script_if_fault);
		conf_write(fp, "   Number of track scripts init = %d", vrrp->num_script_init);
		ctime_r(&vrrp->last_transition.tv_sec, time_str);
		conf_write(fp, "   Last transition = %ld (%.24s)", vrrp->last_transition.tv_sec, time_str);
		if (!ctime_r(&vrrp->sands.tv_sec, time_str))
			strcpy(time_str, "invalid time ");
		if (vrrp->sands.tv_sec == TIMER_DISABLED)
			conf_write(fp, "   Read timeout = DISABLED");
		else
			conf_write(fp, "   Read timeout = %ld.%6.6ld (%.19s.%6.6ld)", vrrp->sands.tv_sec, vrrp->sands.tv_usec, time_str, vrrp->sands.tv_usec);
		conf_write(fp, "   Master down timer = %u usecs", vrrp->ms_down_timer);
	}
#ifdef _HAVE_VRRP_VMAC_
	if (vrrp->ifp != vrrp->ifp->base_ifp)
		conf_write(fp, "   Interface = %s, vmac on %s, xmit %s i/f", IF_NAME(vrrp->ifp),
				vrrp->ifp->base_ifp->ifname, __test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags) ? "base" : "vmac");
	else
#endif
		conf_write(fp, "   Interface = %s", IF_NAME(vrrp->ifp));
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
	conf_write(fp, "   Gratuitous ARP delay = %d",
		       vrrp->garp_delay/TIMER_HZ);
	conf_write(fp, "   Gratuitous ARP repeat = %d", vrrp->garp_rep);
	conf_write(fp, "   Gratuitous ARP refresh = %lu",
		       vrrp->garp_refresh.tv_sec);
	conf_write(fp, "   Gratuitous ARP refresh repeat = %d", vrrp->garp_refresh_rep);
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
	conf_write(fp, "   Advert interval = %d %s",
		(vrrp->version == VRRP_VERSION_2) ? (vrrp->adver_int / TIMER_HZ) :
		(vrrp->adver_int / (TIMER_HZ / 1000)),
		(vrrp->version == VRRP_VERSION_2) ? "sec" : "milli-sec");
	if (vrrp->state == VRRP_STATE_BACK && vrrp->version == VRRP_VERSION_3)
		conf_write(fp, "   Master advert interval = %d milli-sec", vrrp->master_adver_int / (TIMER_HZ / 1000));
	conf_write(fp, "   Accept = %s", vrrp->accept ? "enabled" : "disabled");
	conf_write(fp, "   Preempt = %s", vrrp->nopreempt ? "disabled" : "enabled");
	if (vrrp->preempt_delay)
		conf_write(fp, "   Preempt delay = %g secs",
		       (float)vrrp->preempt_delay / TIMER_HZ);
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
		conf_write(fp, "   Kernel rx buffer size = %lu", vrrp->kernel_rx_buf_size);

	if (vrrp->debug)
		conf_write(fp, "   Debug level = %d", vrrp->debug);

	if (!LIST_ISEMPTY(vrrp->vip)) {
		conf_write(fp, "   Virtual IP = %d", LIST_SIZE(vrrp->vip));
		dump_list(fp, vrrp->vip);
	}
	if (!LIST_ISEMPTY(vrrp->evip)) {
		conf_write(fp, "   Virtual IP Excluded = %d",
			LIST_SIZE(vrrp->evip));
		dump_list(fp, vrrp->evip);
	}
	if (!LIST_ISEMPTY(vrrp->unicast_peer)) {
		conf_write(fp, "   Unicast Peer = %d",
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
#ifdef _HAVE_FIB_ROUTING_
	if (!LIST_ISEMPTY(vrrp->vroutes)) {
		conf_write(fp, "   Virtual Routes = %d", LIST_SIZE(vrrp->vroutes));
		dump_list(fp, vrrp->vroutes);
	}
	if (!LIST_ISEMPTY(vrrp->vrules)) {
		conf_write(fp, "   Virtual Rules = %d", LIST_SIZE(vrrp->vrules));
		dump_list(fp, vrrp->vrules);
	}
#endif

	if (!LIST_ISEMPTY(vrrp->track_ifp)) {
		conf_write(fp, "   Tracked interfaces = %d", LIST_SIZE(vrrp->track_ifp));
		dump_list(fp, vrrp->track_ifp);
	}
	if (!LIST_ISEMPTY(vrrp->track_script)) {
		conf_write(fp, "   Tracked scripts = %d", LIST_SIZE(vrrp->track_script));
		dump_list(fp, vrrp->track_script);
	}
	if (!LIST_ISEMPTY(vrrp->track_file)) {
		conf_write(fp, "   Tracked files = %d", LIST_SIZE(vrrp->track_file));
		dump_list(fp, vrrp->track_file);
	}
#ifdef _WITH_BFD_
	if (!LIST_ISEMPTY(vrrp->track_bfd)) {
		conf_write(fp, "   Tracked BFDs = %d", LIST_SIZE(vrrp->track_bfd));
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
}

void
alloc_static_track_group(char *gname)
{
	size_t size = strlen(gname);
	static_track_group_t *new;

	if (!LIST_EXISTS(vrrp_data->static_track_groups))
		vrrp_data->static_track_groups = alloc_list(free_tgroup, dump_tgroup);

	/* Allocate new VRRP group structure */
	new = (static_track_group_t *) MALLOC(sizeof(*new));
	new->gname = (char *) MALLOC(size + 1);
	memcpy(new->gname, gname, size);

	list_add(vrrp_data->static_track_groups, new);
}

void
alloc_vrrp_sync_group(char *gname)
{
	size_t size = strlen(gname);
	vrrp_sgroup_t *new;

	/* Allocate new VRRP group structure */
	new = (vrrp_sgroup_t *) MALLOC(sizeof(vrrp_sgroup_t));
	new->gname = (char *) MALLOC(size + 1);
	new->state = VRRP_STATE_INIT;
	new->last_email_state = VRRP_STATE_INIT;
	memcpy(new->gname, gname, size);
	new->sgroup_tracking_weight = false;
	new->smtp_alert = -1;

	list_add(vrrp_data->vrrp_sync_group, new);
}

vrrp_stats *
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
alloc_vrrp(char *iname)
{
	size_t size = strlen(iname);
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
	new->iname = (char *) MALLOC(size + 1);
	memcpy(new->iname, iname, size);
	new->stats = alloc_vrrp_stats();
	new->accept = PARAMETER_UNSET;
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

	new->skip_check_adv_addr = global_data->vrrp_skip_check_adv_addr;
	new->strict_mode = PARAMETER_UNSET;

	list_add(vrrp_data->vrrp, new);
}

void
alloc_vrrp_unicast_peer(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	struct sockaddr_storage *peer = NULL;

	if (!LIST_EXISTS(vrrp->unicast_peer))
		vrrp->unicast_peer = alloc_list(free_unicast_peer, dump_unicast_peer);

	/* Allocate new unicast peer */
	peer = (struct sockaddr_storage *) MALLOC(sizeof(struct sockaddr_storage));
	if (inet_stosockaddr(strvec_slot(strvec, 0), NULL, peer)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: VRRP instance[%s] malformed unicast"
				     " peer address[%s]. Skipping..."
				   , vrrp->iname, FMT_STR_VSLOT(strvec, 0));
		FREE(peer);
		return;
	}

	if (!vrrp->family)
		vrrp->family = peer->ss_family;
	else if (peer->ss_family != vrrp->family) {
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: VRRP instance[%s] and unicast peer address"
				     "[%s] MUST be of the same family !!! Skipping..."
				   , vrrp->iname, FMT_STR_VSLOT(strvec, 0));
		FREE(peer);
		return;
	}

	list_add(vrrp->unicast_peer, peer);
}

void
alloc_vrrp_track_if(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->track_ifp))
		vrrp->track_ifp = alloc_list(free_track_if, dump_track_if);
	alloc_track_if(vrrp, strvec);
}

void
alloc_vrrp_track_script(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->track_script))
		vrrp->track_script = alloc_list(free_track_script, dump_track_script);
	alloc_track_script(vrrp, strvec);
}

void
alloc_vrrp_track_file(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->track_file))
		vrrp->track_file = alloc_list(free_track_file, dump_track_file);
	alloc_track_file(vrrp, strvec);
}

#ifdef _WITH_BFD_
void
alloc_vrrp_track_bfd(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->track_bfd))
		vrrp->track_bfd = alloc_list(free_vrrp_tracked_bfd, dump_vrrp_tracked_bfd);
	alloc_track_bfd(vrrp, strvec);
}
#endif

void
alloc_vrrp_group_track_if(vector_t *strvec)
{
	vrrp_sgroup_t *sgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);

	if (!LIST_EXISTS(sgroup->track_ifp))
		sgroup->track_ifp = alloc_list(free_track_if, dump_track_if);
	alloc_group_track_if(sgroup, strvec);
}

void
alloc_vrrp_group_track_script(vector_t *strvec)
{
	vrrp_sgroup_t *sgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);

	if (!LIST_EXISTS(sgroup->track_script))
		sgroup->track_script = alloc_list(free_track_script, dump_track_script);
	alloc_group_track_script(sgroup, strvec);
}

void
alloc_vrrp_group_track_file(vector_t *strvec)
{
	vrrp_sgroup_t *sgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);

	if (!LIST_EXISTS(sgroup->track_file))
		sgroup->track_file = alloc_list(free_track_file, dump_track_file);
	alloc_group_track_file(sgroup, strvec);
}

#ifdef _WITH_BFD_
void
alloc_vrrp_group_track_bfd(vector_t *strvec)
{
	vrrp_sgroup_t *sgroup = LIST_TAIL_DATA(vrrp_data->vrrp_sync_group);

	if (!LIST_EXISTS(sgroup->track_bfd))
		sgroup->track_bfd = alloc_list(free_vrrp_tracked_bfd, dump_vrrp_tracked_bfd);
	alloc_group_track_bfd(sgroup, strvec);
}
#endif

void
alloc_vrrp_vip(vector_t *strvec)
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
			report_config_error(CONFIG_GENERAL_ERROR, "(%s): address family must match VRRP instance [%s] - ignoring", vrrp->iname, FMT_STR_VSLOT(strvec, 0));
			free_list_element(vrrp->vip, vrrp->vip->tail);
		}
	}
}

void
alloc_vrrp_evip(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->evip))
		vrrp->evip = alloc_list(free_ipaddress, dump_ipaddress);
	alloc_ipaddress(vrrp->evip, strvec, vrrp->ifp, false);
}

#ifdef _HAVE_FIB_ROUTING_
void
alloc_vrrp_vroute(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->vroutes))
		vrrp->vroutes = alloc_list(free_iproute, dump_iproute);
	alloc_route(vrrp->vroutes, strvec, false);
}

void
alloc_vrrp_vrule(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->vrules))
		vrrp->vrules = alloc_list(free_iprule, dump_iprule);
	alloc_rule(vrrp->vrules, strvec, false);
}
#endif

void
alloc_vrrp_script(char *sname)
{
	size_t size = strlen(sname);
	vrrp_script_t *new;

	/* Allocate new VRRP script structure */
	new = (vrrp_script_t *) MALLOC(sizeof(vrrp_script_t));
	new->sname = (char *) MALLOC(size + 1);
	memcpy(new->sname, sname, size + 1);
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
alloc_vrrp_file(char *fname)
{
	size_t size = strlen(fname);
	vrrp_tracked_file_t *new;

	/* Allocate new VRRP file structure */
	new = (vrrp_tracked_file_t *) MALLOC(sizeof(vrrp_tracked_file_t));
	new->fname = (char *) MALLOC(size + 1);
	memcpy(new->fname, fname, size + 1);
	new->weight = 1;
	list_add(vrrp_data->vrrp_track_files, new);
}

/* data facility functions */
void
alloc_vrrp_buffer(size_t len)
{
	if (vrrp_buffer)
		return;

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
	new->vrrp_index = alloc_mlist(NULL, NULL, VRRP_INDEX_FD_SIZE);
	new->vrrp_index_fd = alloc_mlist(NULL, NULL, FD_INDEX_SIZE);
	new->vrrp_sync_group = alloc_list(free_vgroup, dump_vgroup);
	new->vrrp_script = alloc_list(free_vscript, dump_vscript);
	new->vrrp_track_files = alloc_list(free_vfile, dump_vfile);
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
	free_mlist(data->vrrp_index, VRRP_INDEX_FD_SIZE);
	free_mlist(data->vrrp_index_fd, FD_INDEX_SIZE);
	free_list(&data->vrrp);
	free_list(&data->vrrp_sync_group);
	free_list(&data->vrrp_script);
	free_list(&data->vrrp_track_files);
#ifdef _WITH_BFD_
	free_list(&data->vrrp_track_bfds);
#endif
	FREE(data);
}

static void
dump_vrrp_data(FILE *fp, vrrp_data_t * data)
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
