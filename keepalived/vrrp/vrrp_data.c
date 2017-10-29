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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <unistd.h>

#include "utils.h"
#include "logger.h"
#include "bitops.h"

#include "global_data.h"
#include "vrrp_data.h"
#include "vrrp_sync.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_vmac.h"
#endif
#include "vrrp_print.h"
#ifdef _HAVE_FIB_ROUTING_
#include "vrrp_iprule.h"
#include "vrrp_iproute.h"
#endif
#include "vrrp_track.h"
#include "vrrp_sock.h"

/* global vars */
vrrp_data_t *vrrp_data = NULL;
vrrp_data_t *old_vrrp_data = NULL;
char *vrrp_buffer;
size_t vrrp_buffer_len;

/* Static addresses facility function */
void
alloc_saddress(vector_t *strvec)
{
	if (!LIST_EXISTS(vrrp_data->static_addresses))
		vrrp_data->static_addresses = alloc_list(free_ipaddress, dump_ipaddress);
	alloc_ipaddress(vrrp_data->static_addresses, strvec, NULL);
}

#ifdef _HAVE_FIB_ROUTING_
/* Static routes facility function */
void
alloc_sroute(vector_t *strvec)
{
	if (!LIST_EXISTS(vrrp_data->static_routes))
		vrrp_data->static_routes = alloc_list(free_iproute, dump_iproute);
	alloc_route(vrrp_data->static_routes, strvec);
}

/* Static rules facility function */
void
alloc_srule(vector_t *strvec)
{
	if (!LIST_EXISTS(vrrp_data->static_rules))
		vrrp_data->static_rules = alloc_list(free_iprule, dump_iprule);
	alloc_rule(vrrp_data->static_rules, strvec);
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
	free_notify_script(&vgroup->script);
	FREE(vgroup);
}

static void
dump_notify_script(notify_script_t *script, char *type)
{
	if (!script)
		return;

	log_message(LOG_INFO, "   %s state transition script = %s, uid:gid %d:%d", type,
	       script->cmd_str, script->uid, script->gid);
}

static void
dump_vgroup(void *data)
{
	vrrp_sgroup_t *vgroup = data;
	element e;

	log_message(LOG_INFO, " VRRP Sync Group = %s, %s", vgroup->gname, get_state_str(vgroup->state));
	if (vgroup->vrrp_instances) {
		log_message(LOG_INFO, "   VRRP member instances = %d\n", LIST_SIZE(vgroup->vrrp_instances));
		for (e = LIST_HEAD(vgroup->vrrp_instances); e; ELEMENT_NEXT(e)) {
			vrrp_t *vrrp = ELEMENT_DATA(e);
			log_message(LOG_INFO, "     %s", vrrp->iname);
		}
	}
	if (vgroup->sgroup_tracking_weight)
		log_message(LOG_INFO, "   sync group tracking weight set");
	if (!LIST_ISEMPTY(vgroup->track_ifp)) {
		log_message(LOG_INFO, "   Tracked interfaces = %d", LIST_SIZE(vgroup->track_ifp));
		dump_list(vgroup->track_ifp);
	}
	if (!LIST_ISEMPTY(vgroup->track_script)) {
		log_message(LOG_INFO, "   Tracked scripts = %d", LIST_SIZE(vgroup->track_script));
		dump_list(vgroup->track_script);
	}
	if (!LIST_ISEMPTY(vgroup->track_file)) {
		log_message(LOG_INFO, "   Tracked files = %d", LIST_SIZE(vgroup->track_file));
		dump_list(vgroup->track_file);
	}
	dump_notify_script(vgroup->script_backup, "Backup");
	dump_notify_script(vgroup->script_master, "Master");
	dump_notify_script(vgroup->script_fault, "Fault");
	dump_notify_script(vgroup->script, "Generic");
	if (vgroup->smtp_alert)
		log_message(LOG_INFO, "   Using smtp notification");
}

void
dump_tracking_vrrp(void *data)
{
	tracking_vrrp_t *tvp = (tracking_vrrp_t *)data;
	vrrp_t *vrrp = tvp->vrrp;

	log_message(LOG_INFO, "     %s, weight %d", vrrp->iname, tvp->weight);
}

static void
free_vscript(void *data)
{
	vrrp_script_t *vscript = data;

	free_list(&vscript->tracking_vrrp);
	FREE(vscript->sname);
	FREE_PTR(vscript->script.cmd_str);
	FREE_PTR(vscript->script.args);
	FREE(vscript);
}
static void
dump_vscript(void *data)
{
	vrrp_script_t *vscript = data;
	const char *str;

	log_message(LOG_INFO, " VRRP Script = %s", vscript->sname);
	log_message(LOG_INFO, "   Command = %s", vscript->script.cmd_str);
	log_message(LOG_INFO, "   Interval = %lu sec", vscript->interval / TIMER_HZ);
	log_message(LOG_INFO, "   Timeout = %lu sec", vscript->timeout / TIMER_HZ);
	log_message(LOG_INFO, "   Weight = %d", vscript->weight);
	log_message(LOG_INFO, "   Rise = %d", vscript->rise);
	log_message(LOG_INFO, "   Fall = %d", vscript->fall);
	log_message(LOG_INFO, "   Insecure = %s", vscript->insecure ? "yes" : "no");

	switch (vscript->init_state) {
	case SCRIPT_INIT_STATE_INIT:
		str = "INIT"; break;
	case SCRIPT_INIT_STATE_FAILED:
		str = "INIT/FAILED"; break;
	default:
		str = (vscript->result >= vscript->rise) ? "GOOD" : "BAD";
	}
	log_message(LOG_INFO, "   Status = %s", str);
	log_message(LOG_INFO, "   Script uid:gid = %d:%d", vscript->script.uid, vscript->script.gid);
	log_message(LOG_INFO, "   VRRP instances = %d", vscript->tracking_vrrp ? LIST_SIZE(vscript->tracking_vrrp) : 0);
	if (vscript->tracking_vrrp)
		dump_list(vscript->tracking_vrrp);
	log_message(LOG_INFO, "   State = %s",
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
	FREE(vfile);
}
static void
dump_vfile(void *data)
{
	vrrp_tracked_file_t *vfile = data;

	log_message(LOG_INFO, " VRRP Track file = %s", vfile->fname);
	log_message(LOG_INFO, "   File = %s", vfile->file_path);
	log_message(LOG_INFO, "   Weight = %d", vfile->weight);
	log_message(LOG_INFO, "   Tracking VRRP = %d", vfile->tracking_vrrp ? LIST_SIZE(vfile->tracking_vrrp) : 0);
	if (vfile->tracking_vrrp)
		dump_list(vfile->tracking_vrrp);
}

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
dump_sock(void *sock_data)
{
	sock_t *sock = sock_data;
	log_message(LOG_INFO, "VRRP sockpool: [ifindex(%u), proto(%u), unicast(%d), fd(%d,%d)]"
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
dump_unicast_peer(void *data)
{
	struct sockaddr_storage *peer = data;

	log_message(LOG_INFO, "     %s", inet_sockaddrtos(peer));
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
	FREE_PTR(vrrp->stats);

	free_list(&vrrp->track_ifp);
	free_list(&vrrp->track_script);
	free_list(&vrrp->track_file);
	free_list(&vrrp->unicast_peer);
	free_list(&vrrp->vip);
	free_list(&vrrp->evip);
	free_list(&vrrp->vroutes);
	free_list(&vrrp->vrules);
	FREE(vrrp);
}
static void
dump_vrrp(void *data)
{
	vrrp_t *vrrp = data;
#ifdef _WITH_VRRP_AUTH_
	char auth_data[sizeof(vrrp->auth_data) + 1];
#endif

	log_message(LOG_INFO, " VRRP Instance = %s", vrrp->iname);
	log_message(LOG_INFO, "   Using VRRPv%d", vrrp->version);
	if (vrrp->family == AF_INET6)
		log_message(LOG_INFO, "   Using Native IPv6");
	if (vrrp->init_state == VRRP_STATE_BACK)
		log_message(LOG_INFO, "   Want State = BACKUP");
	else
		log_message(LOG_INFO, "   Want State = MASTER");
	log_message(LOG_INFO, "   Running on device = %s", IF_NAME(vrrp->ifp));
#ifdef _WITH_VRRP_VMAC_
	if (vrrp->ifp->vmac)
		log_message(LOG_INFO, "   Real interface = %s\n", IF_NAME(if_get_by_ifindex(vrrp->ifp->base_ifindex)));
#endif
	if (vrrp->dont_track_primary)
		log_message(LOG_INFO, "   VRRP interface tracking disabled");
	log_message(LOG_INFO, "   Skip checking advert IP addresses = %s", vrrp->skip_check_adv_addr ? "yes" : "no");
	log_message(LOG_INFO, "   Enforcing strict VRRP compliance = %s", vrrp->strict_mode ? "yes" : "no");
	if (vrrp->saddr.ss_family)
		log_message(LOG_INFO, "   Using src_ip = %s"
				    , inet_sockaddrtos(&vrrp->saddr));
	log_message(LOG_INFO, "   Gratuitous ARP delay = %d",
		       vrrp->garp_delay/TIMER_HZ);
	log_message(LOG_INFO, "   Gratuitous ARP repeat = %d", vrrp->garp_rep);
	log_message(LOG_INFO, "   Gratuitous ARP refresh timer = %lu",
		       vrrp->garp_refresh.tv_sec);
	log_message(LOG_INFO, "   Gratuitous ARP refresh repeat = %d", vrrp->garp_refresh_rep);
	log_message(LOG_INFO, "   Gratuitous ARP lower priority delay = %d", vrrp->garp_lower_prio_delay / TIMER_HZ);
	log_message(LOG_INFO, "   Gratuitous ARP lower priority repeat = %d", vrrp->garp_lower_prio_rep);
	log_message(LOG_INFO, "   Send advert after receive lower priority advert = %s", vrrp->lower_prio_no_advert ? "false" : "true");
	log_message(LOG_INFO, "   Send advert after receive higher priority advert = %s", vrrp->higher_prio_send_advert ? "true" : "false");
	log_message(LOG_INFO, "   Virtual Router ID = %d", vrrp->vrid);
	log_message(LOG_INFO, "   Priority = %d", vrrp->base_priority);
	log_message(LOG_INFO, "   Advert interval = %d %s",
		(vrrp->version == VRRP_VERSION_2) ? (vrrp->adver_int / TIMER_HZ) :
		(vrrp->adver_int / (TIMER_HZ / 1000)),
		(vrrp->version == VRRP_VERSION_2) ? "sec" : "milli-sec");
	log_message(LOG_INFO, "   Accept %s", vrrp->accept ? "enabled" : "disabled");
	if (vrrp->nopreempt)
		log_message(LOG_INFO, "   Preempt disabled");
	if (vrrp->preempt_delay)
		log_message(LOG_INFO, "   Preempt delay = %ld secs",
		       vrrp->preempt_delay / TIMER_HZ);
	log_message(LOG_INFO, "   Promote_secondaries %s", vrrp->promote_secondaries ? "enabled" : "disabled");
#if defined _WITH_VRRP_AUTH_
	if (vrrp->version == VRRP_VERSION_2) {
		if (vrrp->auth_type) {
			log_message(LOG_INFO, "   Authentication type = %s",
				    (vrrp->auth_type ==
				     VRRP_AUTH_AH) ? "IPSEC_AH" : "SIMPLE_PASSWORD");
			if (vrrp->auth_type != VRRP_AUTH_AH) {
				/* vrrp->auth_data is not \0 terminated */
				memcpy(auth_data, vrrp->auth_data, sizeof(vrrp->auth_data));
				auth_data[sizeof(vrrp->auth_data)] = '\0';
				log_message(LOG_INFO, "   Password = %s", auth_data);
			}
		}
	}
#endif
	if (!LIST_ISEMPTY(vrrp->track_ifp)) {
		log_message(LOG_INFO, "   Tracked interfaces = %d", LIST_SIZE(vrrp->track_ifp));
		dump_list(vrrp->track_ifp);
	}
	if (!LIST_ISEMPTY(vrrp->track_script)) {
		log_message(LOG_INFO, "   Tracked scripts = %d", LIST_SIZE(vrrp->track_script));
		dump_list(vrrp->track_script);
	}
	if (!LIST_ISEMPTY(vrrp->track_file)) {
		log_message(LOG_INFO, "   Tracked files = %d", LIST_SIZE(vrrp->track_file));
		dump_list(vrrp->track_file);
	}
	if (!LIST_ISEMPTY(vrrp->unicast_peer)) {
		log_message(LOG_INFO, "   Unicast Peer = %d", LIST_SIZE(vrrp->unicast_peer));
		dump_list(vrrp->unicast_peer);
#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
		log_message(LOG_INFO, "   Unicast checksum compatibility = %s",
					vrrp->unicast_chksum_compat == CHKSUM_COMPATIBILITY_NONE ? "no" :
					vrrp->unicast_chksum_compat == CHKSUM_COMPATIBILITY_NEVER ? "never" : "yes");
#endif
	}
	if (!LIST_ISEMPTY(vrrp->vip)) {
		log_message(LOG_INFO, "   Virtual IP = %d", LIST_SIZE(vrrp->vip));
		dump_list(vrrp->vip);
	}
	if (!LIST_ISEMPTY(vrrp->evip)) {
		log_message(LOG_INFO, "   Virtual IP Excluded = %d", LIST_SIZE(vrrp->evip));
		dump_list(vrrp->evip);
	}
	if (!LIST_ISEMPTY(vrrp->vroutes)) {
		log_message(LOG_INFO, "   Virtual Routes = %d", LIST_SIZE(vrrp->vroutes));
		dump_list(vrrp->vroutes);
	}
	if (!LIST_ISEMPTY(vrrp->vrules)) {
		log_message(LOG_INFO, "   Virtual Rules = %d", LIST_SIZE(vrrp->vrules));
		dump_list(vrrp->vrules);
	}
	dump_notify_script(vrrp->script_backup, "Backup");
	dump_notify_script(vrrp->script_master, "Master");
	dump_notify_script(vrrp->script_fault, "Fault");
	dump_notify_script(vrrp->script_stop, "Stop");
	dump_notify_script(vrrp->script, "Generic");
	if (vrrp->smtp_alert)
		log_message(LOG_INFO, "   Using smtp notification");
#ifdef _HAVE_VRRP_VMAC_
	if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags))
		log_message(LOG_INFO, "   Using VRRP VMAC (flags:%s|%s), vmac ifindex %u"
				    , (__test_bit(VRRP_VMAC_UP_BIT, &vrrp->vmac_flags)) ? "UP" : "DOWN"
				    , (__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags)) ? "xmit_base" : "xmit"
				    , vrrp->ifp->base_ifp->ifindex);
#endif
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
	new->init_state = VRRP_STATE_INIT;
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
	new->unicast_chksum_compat = CHKSUM_COMPATIBILITY_NONE;

	new->skip_check_adv_addr = global_data->vrrp_skip_check_adv_addr;
	new->strict_mode = PARAMETER_UNSET;

	list_add(vrrp_data->vrrp, new);
}

void
alloc_vrrp_unicast_peer(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	struct sockaddr_storage *peer = NULL;
	int ret;

	if (!LIST_EXISTS(vrrp->unicast_peer))
		vrrp->unicast_peer = alloc_list(free_unicast_peer, dump_unicast_peer);

	/* Allocate new unicast peer */
	peer = (struct sockaddr_storage *) MALLOC(sizeof(struct sockaddr_storage));
	ret = inet_stosockaddr(strvec_slot(strvec, 0), 0, peer);
	if (ret < 0) {
		log_message(LOG_ERR, "Configuration error: VRRP instance[%s] malformed unicast"
				     " peer address[%s]. Skipping..."
				   , vrrp->iname, FMT_STR_VSLOT(strvec, 0));
		FREE(peer);
		return;
	}

	if (!vrrp->family)
		vrrp->family = peer->ss_family;
	else if (peer->ss_family != vrrp->family) {
		log_message(LOG_ERR, "Configuration error: VRRP instance[%s] and unicast peer address"
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

	alloc_ipaddress(vrrp->vip, strvec, vrrp->ifp);

	if (!LIST_ISEMPTY(vrrp->vip) && LIST_TAIL_DATA(vrrp->vip) != list_end) {
		address_family = IP_FAMILY((ip_address_t*)LIST_TAIL_DATA(vrrp->vip));

		if (vrrp->family == AF_UNSPEC)
			vrrp->family = address_family;
		else if (address_family != vrrp->family) {
			log_message(LOG_INFO, "(%s): address family must match VRRP instance [%s] - ignoring", vrrp->iname, FMT_STR_VSLOT(strvec, 0));
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
	alloc_ipaddress(vrrp->evip, strvec, vrrp->ifp);
}

#ifdef _HAVE_FIB_ROUTING_
void
alloc_vrrp_vroute(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->vroutes))
		vrrp->vroutes = alloc_list(free_iproute, dump_iproute);
	alloc_route(vrrp->vroutes, strvec);
}

void
alloc_vrrp_vrule(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->vrules))
		vrrp->vrules = alloc_list(free_iprule, dump_iprule);
	alloc_rule(vrrp->vrules, strvec);
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
	vrrp_buffer = (char *) MALLOC(len);
	vrrp_buffer_len = (vrrp_buffer) ? len : 0;
}

void
free_vrrp_buffer(void)
{
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
	new->vrrp_index = alloc_mlist(NULL, NULL, 1151+1);
	new->vrrp_index_fd = alloc_mlist(NULL, NULL, 1024+1);
	new->vrrp_sync_group = alloc_list(free_vgroup, dump_vgroup);
	new->vrrp_script = alloc_list(free_vscript, dump_vscript);
	new->vrrp_track_files = alloc_list(free_vfile, dump_vfile);
	new->vrrp_socket_pool = alloc_list(free_sock, dump_sock);

	return new;
}

void
free_vrrp_data(vrrp_data_t * data)
{
	free_list(&data->static_addresses);
	free_list(&data->static_routes);
	free_list(&data->static_rules);
	free_mlist(data->vrrp_index, 1151+1);
	free_mlist(data->vrrp_index_fd, 1024+1);
	free_list(&data->vrrp);
	free_list(&data->vrrp_sync_group);
	free_list(&data->vrrp_script);
	free_list(&data->vrrp_track_files);
	FREE(data);
}

void
dump_vrrp_data(vrrp_data_t * data)
{
	if (!LIST_ISEMPTY(data->static_addresses)) {
		log_message(LOG_INFO, "------< Static Addresses >------");
		dump_list(data->static_addresses);
	}
	if (!LIST_ISEMPTY(data->static_routes)) {
		log_message(LOG_INFO, "------< Static Routes >------");
		dump_list(data->static_routes);
	}
	if (!LIST_ISEMPTY(data->static_rules)) {
		log_message(LOG_INFO, "------< Static Rules >------");
		dump_list(data->static_rules);
	}
	if (!LIST_ISEMPTY(data->vrrp)) {
		log_message(LOG_INFO, "------< VRRP Topology >------");
		dump_list(data->vrrp);
	}
	if (!LIST_ISEMPTY(data->vrrp_sync_group)) {
		log_message(LOG_INFO, "------< VRRP Sync groups >------");
		dump_list(data->vrrp_sync_group);
	}
	if (!LIST_ISEMPTY(data->vrrp_script)) {
		log_message(LOG_INFO, "------< VRRP Scripts >------");
		dump_list(data->vrrp_script);
	}
	if (!LIST_ISEMPTY(data->vrrp_track_files)) {
		log_message(LOG_INFO, "------< VRRP Track files >------");
		dump_list(data->vrrp_track_files);
	}
}
