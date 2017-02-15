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

#include "global_data.h"
#include "vrrp_data.h"
#include "vrrp_index.h"
#include "vrrp_sync.h"
#include "vrrp_if.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_vmac.h"
#endif
#include "vrrp.h"
#include "memory.h"
#include "utils.h"
#include "logger.h"
#include "bitops.h"
#ifdef _HAVE_FIB_ROUTING_
#include "vrrp_iprule.h"
#include "vrrp_iproute.h"
#endif

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

	FREE(vgroup->gname);
	free_strvec(vgroup->iname);
	free_list(&vgroup->index_list);
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
	       script->name, script->uid, script->gid);
}

static void
dump_vgroup(void *data)
{
	vrrp_sgroup_t *vgroup = data;
	unsigned int i;
	char *str;

	log_message(LOG_INFO, " VRRP Sync Group = %s, %s", vgroup->gname,
	       (vgroup->state == VRRP_STATE_MAST) ? "MASTER" : "BACKUP");
	for (i = 0; i < vector_size(vgroup->iname); i++) {
		str = vector_slot(vgroup->iname, i);
		log_message(LOG_INFO, "   monitor = %s", str);
	}
	if (vgroup->global_tracking)
		log_message(LOG_INFO, "   Same tracking for all VRRP instances");
	dump_notify_script(vgroup->script_backup, "Backup");
	dump_notify_script(vgroup->script_master, "Master");
	dump_notify_script(vgroup->script_fault, "Fault");
	dump_notify_script(vgroup->script, "Generic");
	if (vgroup->smtp_alert)
		log_message(LOG_INFO, "   Using smtp notification");
}

static void
free_vscript(void *data)
{
	vrrp_script_t *vscript = data;

	FREE(vscript->sname);
	FREE_PTR(vscript->script);
	FREE(vscript);
}
static void
dump_vscript(void *data)
{
	vrrp_script_t *vscript = data;
	const char *str;

	log_message(LOG_INFO, " VRRP Script = %s", vscript->sname);
	log_message(LOG_INFO, "   Command = %s", vscript->script);
	log_message(LOG_INFO, "   Interval = %lu sec", vscript->interval / TIMER_HZ);
	log_message(LOG_INFO, "   Timeout = %lu sec", vscript->timeout / TIMER_HZ);
	log_message(LOG_INFO, "   Weight = %d", vscript->weight);
	log_message(LOG_INFO, "   Rise = %d", vscript->rise);
	log_message(LOG_INFO, "   Fall = %d", vscript->fall);
	log_message(LOG_INFO, "   Insecure = %s", vscript->insecure ? "yes" : "no");

	switch (vscript->result) {
	case VRRP_SCRIPT_STATUS_INIT:
		str = "INIT"; break;
	case VRRP_SCRIPT_STATUS_INIT_GOOD:
		str = "INIT/GOOD"; break;
	case VRRP_SCRIPT_STATUS_INIT_FAILED:
		str = "INIT/FAILED"; break;
	case VRRP_SCRIPT_STATUS_DISABLED:
		str = "DISABLED"; break;
	default:
		str = (vscript->result >= vscript->rise) ? "GOOD" : "BAD";
	}
	log_message(LOG_INFO, "   Status = %s", str);
	if (vscript->uid || vscript->gid)
		log_message(LOG_INFO, "   Script uid:gid = %d:%d", vscript->uid, vscript->gid);

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
	element e;

	FREE(vrrp->iname);
	FREE_PTR(vrrp->send_buffer);
	free_notify_script(&vrrp->script_backup);
	free_notify_script(&vrrp->script_master);
	free_notify_script(&vrrp->script_fault);
	free_notify_script(&vrrp->script_stop);
	free_notify_script(&vrrp->script);
	FREE_PTR(vrrp->stats);
	FREE(vrrp->ipsecah_counter);

	if (!LIST_ISEMPTY(vrrp->track_ifp))
		for (e = LIST_HEAD(vrrp->track_ifp); e; ELEMENT_NEXT(e))
			FREE(ELEMENT_DATA(e));
	free_list(&vrrp->track_ifp);

	if (!LIST_ISEMPTY(vrrp->track_script))
		for (e = LIST_HEAD(vrrp->track_script); e; ELEMENT_NEXT(e))
			FREE(ELEMENT_DATA(e));
	free_list(&vrrp->track_script);

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
	if (!LIST_ISEMPTY(vrrp->unicast_peer)) {
		log_message(LOG_INFO, "   Unicast Peer = %d", LIST_SIZE(vrrp->unicast_peer));
		dump_list(vrrp->unicast_peer);
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
				    , vrrp->ifp->base_ifindex);
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
	memcpy(new->gname, gname, size);
	new->global_tracking = 0;

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
	new->authtype_mismatch = 0;
	new->packet_len_err = 0;
	new->advert_rcvd = 0;
	new->advert_sent = 0;
	new->advert_interval_err = 0;
	new->auth_failure = 0;
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
	seq_counter_t *counter;
	vrrp_t *new;

	/* Allocate new VRRP structure */
	new = (vrrp_t *) MALLOC(sizeof(vrrp_t));
	counter = (seq_counter_t *) MALLOC(sizeof(seq_counter_t));

	/* Build the structure */
	new->ipsecah_counter = counter;

	/* Set default values */
	new->family = AF_UNSPEC;
	new->saddr.ss_family = AF_UNSPEC;
	new->wantstate = VRRP_STATE_BACK;
	new->init_state = VRRP_STATE_BACK;
	new->version = 0;
	new->master_priority = 0;
	new->last_transition = timer_now();
	new->iname = (char *) MALLOC(size + 1);
	memcpy(new->iname, iname, size);
	new->stats = alloc_vrrp_stats();
	new->quick_sync = 0;
	new->accept = PARAMETER_UNSET;
	new->garp_rep = global_data->vrrp_garp_rep;
	new->garp_refresh = global_data->vrrp_garp_refresh;
	new->garp_refresh_rep = global_data->vrrp_garp_refresh_rep;
	new->garp_delay = global_data->vrrp_garp_delay;
	new->garp_lower_prio_delay = PARAMETER_UNSET;
	new->garp_lower_prio_rep = PARAMETER_UNSET;
	new->lower_prio_no_advert = PARAMETER_UNSET;

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
alloc_vrrp_track(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->track_ifp))
		vrrp->track_ifp = alloc_list(NULL, dump_track);
	alloc_track(vrrp->track_ifp, strvec);
}

void
alloc_vrrp_track_script(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->track_script))
		vrrp->track_script = alloc_list(NULL, dump_track_script);
	alloc_track_script(vrrp->track_script, strvec);
}

void
alloc_vrrp_vip(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (!LIST_EXISTS(vrrp->vip))
		vrrp->vip = alloc_list(free_ipaddress, dump_ipaddress);
	alloc_ipaddress(vrrp->vip, strvec, vrrp->ifp);
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

	/* Allocate new VRRP group structure */
	new = (vrrp_script_t *) MALLOC(sizeof(vrrp_script_t));
	new->sname = (char *) MALLOC(size + 1);
	memcpy(new->sname, sname, size + 1);
	new->interval = VRRP_SCRIPT_DI * TIMER_HZ;
	new->timeout = VRRP_SCRIPT_DT * TIMER_HZ;
	new->weight = VRRP_SCRIPT_DW;
	new->result = VRRP_SCRIPT_STATUS_INIT;
	new->inuse = 0;
	new->rise = 1;
	new->fall = 1;
	list_add(vrrp_data->vrrp_script, new);
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
	new->vrrp_index = alloc_mlist(NULL, NULL, 255+1);
	new->vrrp_index_fd = alloc_mlist(NULL, NULL, 1024+1);
	new->vrrp_sync_group = alloc_list(free_vgroup, dump_vgroup);
	new->vrrp_script = alloc_list(free_vscript, dump_vscript);
	new->vrrp_socket_pool = alloc_list(free_sock, dump_sock);

	return new;
}

void
free_vrrp_data(vrrp_data_t * data)
{
	free_list(&data->static_addresses);
	free_list(&data->static_routes);
	free_list(&data->static_rules);
	free_mlist(data->vrrp_index, 255+1);
	free_mlist(data->vrrp_index_fd, 1024+1);
	free_list(&data->vrrp);
	free_list(&data->vrrp_sync_group);
	free_list(&data->vrrp_script);
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
}
