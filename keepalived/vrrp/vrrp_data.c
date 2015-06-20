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

#include "vrrp_data.h"
#include "vrrp_index.h"
#include "vrrp_sync.h"
#include "vrrp_if.h"
#include "vrrp_vmac.h"
#include "vrrp.h"
#include "memory.h"
#include "utils.h"
#include "logger.h"
#include "bitops.h"

/* global vars */
vrrp_data_t *vrrp_data = NULL;
vrrp_data_t *old_vrrp_data = NULL;
char *vrrp_buffer;

/* Static addresses facility function */
void
alloc_saddress(vector_t *strvec)
{
	if (LIST_ISEMPTY(vrrp_data->static_addresses))
		vrrp_data->static_addresses = alloc_list(free_ipaddress, dump_ipaddress);
	alloc_ipaddress(vrrp_data->static_addresses, strvec, NULL);
}

/* Static routes facility function */
void
alloc_sroute(vector_t *strvec)
{
	if (LIST_ISEMPTY(vrrp_data->static_routes))
		vrrp_data->static_routes = alloc_list(free_iproute, dump_iproute);
	alloc_route(vrrp_data->static_routes, strvec);
}

/* VRRP facility functions */
static void
free_vgroup(void *data)
{
	vrrp_sgroup_t *vgroup = data;

	FREE(vgroup->gname);
	free_strvec(vgroup->iname);
	free_list(vgroup->index_list);
	FREE_PTR(vgroup->script_backup);
	FREE_PTR(vgroup->script_master);
	FREE_PTR(vgroup->script_fault);
	FREE_PTR(vgroup->script);
	FREE(vgroup);
}
static void
dump_vgroup(void *data)
{
	vrrp_sgroup_t *vgroup = data;
	int i;
	char *str;

	log_message(LOG_INFO, " VRRP Sync Group = %s, %s", vgroup->gname,
	       (vgroup->state == VRRP_STATE_MAST) ? "MASTER" : "BACKUP");
	for (i = 0; i < vector_size(vgroup->iname); i++) {
		str = vector_slot(vgroup->iname, i);
		log_message(LOG_INFO, "   monitor = %s", str);
	}
	if (vgroup->global_tracking)
		log_message(LOG_INFO, "   Same tracking for all VRRP instances");
	if (vgroup->script_backup)
		log_message(LOG_INFO, "   Backup state transition script = %s",
		       vgroup->script_backup);
	if (vgroup->script_master)
		log_message(LOG_INFO, "   Master state transition script = %s",
		       vgroup->script_master);
	if (vgroup->script_fault)
		log_message(LOG_INFO, "   Fault state transition script = %s",
		       vgroup->script_fault);
	if (vgroup->script)
		log_message(LOG_INFO, "   Generic state transition script = '%s'",
		       vgroup->script);
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
	char *str;

	log_message(LOG_INFO, " VRRP Script = %s", vscript->sname);
	log_message(LOG_INFO, "   Command = %s", vscript->script);
	log_message(LOG_INFO, "   Interval = %d sec", (int)(vscript->interval / TIMER_HZ));
	log_message(LOG_INFO, "   Timeout = %d sec", (int)(vscript->timeout / TIMER_HZ));
	log_message(LOG_INFO, "   Weight = %d", vscript->weight);
	log_message(LOG_INFO, "   Rise = %d", vscript->rise);
	log_message(LOG_INFO, "   Fall = %d", vscript->fall);

	switch (vscript->result) {
	case VRRP_SCRIPT_STATUS_INIT:
		str = "INIT"; break;
	case VRRP_SCRIPT_STATUS_INIT_GOOD:
		str = "INIT/GOOD"; break;
	case VRRP_SCRIPT_STATUS_DISABLED:
		str = "DISABLED"; break;
	default:
		str = (vscript->result >= vscript->rise) ? "GOOD" : "BAD";
	}
	log_message(LOG_INFO, "   Status = %s", str);
}

/* Socket pool functions */
static void
free_sock(void *sock_data)
{
	sock_t *sock = sock_data;
	interface_t *ifp;

	/* First of all cancel pending thread */
	thread_cancel(sock->thread);

	/* Close related socket */
	if (sock->fd_in > 0) {
		ifp = if_get_by_ifindex(sock->ifindex);
		if (sock->unicast) {
			close(sock->fd_in);
		} else {
			if_leave_vrrp_group(sock->family, sock->fd_in, ifp);
		}
	}
	if (sock->fd_out > 0)
		close(sock->fd_out);
	FREE(sock_data);
}

static void
dump_sock(void *sock_data)
{
	sock_t *sock = sock_data;
	log_message(LOG_INFO, "VRRP sockpool: [ifindex(%d), proto(%d), unicast(%d), fd(%d,%d)]"
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
	FREE_PTR(vrrp->lvs_syncd_if);
	FREE_PTR(vrrp->script_backup);
	FREE_PTR(vrrp->script_master);
	FREE_PTR(vrrp->script_fault);
	FREE_PTR(vrrp->script_stop);
	FREE_PTR(vrrp->script);
	FREE_PTR(vrrp->stats);
	FREE(vrrp->ipsecah_counter);

	if (!LIST_ISEMPTY(vrrp->track_ifp))
		for (e = LIST_HEAD(vrrp->track_ifp); e; ELEMENT_NEXT(e))
			FREE(ELEMENT_DATA(e));
	free_list(vrrp->track_ifp);

	if (!LIST_ISEMPTY(vrrp->track_script))
		for (e = LIST_HEAD(vrrp->track_script); e; ELEMENT_NEXT(e))
			FREE(ELEMENT_DATA(e));
	free_list(vrrp->track_script);

	free_list(vrrp->unicast_peer);
	free_list(vrrp->vip);
	free_list(vrrp->evip);
	free_list(vrrp->vroutes);
	FREE(vrrp);
}
static void
dump_vrrp(void *data)
{
	vrrp_t *vrrp = data;
	char auth_data[sizeof(vrrp->auth_data) + 1];

	log_message(LOG_INFO, " VRRP Instance = %s", vrrp->iname);
	log_message(LOG_INFO, "   Using VRRPv%d", vrrp->version);
	if (vrrp->family == AF_INET6)
		log_message(LOG_INFO, "   Using Native IPv6");
	if (vrrp->init_state == VRRP_STATE_BACK)
		log_message(LOG_INFO, "   Want State = BACKUP");
	else
		log_message(LOG_INFO, "   Want State = MASTER");
	log_message(LOG_INFO, "   Runing on device = %s", IF_NAME(vrrp->ifp));
	if (vrrp->dont_track_primary)
		log_message(LOG_INFO, "   VRRP interface tracking disabled");
	if (vrrp->saddr.ss_family)
		log_message(LOG_INFO, "   Using src_ip = %s"
				    , inet_sockaddrtos(&vrrp->saddr));
	if (vrrp->lvs_syncd_if)
		log_message(LOG_INFO, "   Runing LVS sync daemon on interface = %s",
		       vrrp->lvs_syncd_if);
	if (vrrp->garp_delay)
		log_message(LOG_INFO, "   Gratuitous ARP delay = %d",
		       vrrp->garp_delay/TIMER_HZ);
	if (!timer_isnull(vrrp->garp_refresh))
		log_message(LOG_INFO, "   Gratuitous ARP refresh timer = %lu",
		       vrrp->garp_refresh.tv_sec);
	log_message(LOG_INFO, "   Gratuitous ARP repeat = %d", vrrp->garp_rep);
	log_message(LOG_INFO, "   Gratuitous ARP refresh repeat = %d", vrrp->garp_refresh_rep);
	log_message(LOG_INFO, "   Virtual Router ID = %d", vrrp->vrid);
	log_message(LOG_INFO, "   Priority = %d", vrrp->base_priority);
	log_message(LOG_INFO, "   Advert interval = %d %s\n",
		(vrrp->version == VRRP_VERSION_2) ? (vrrp->adver_int / TIMER_HZ) :
		(vrrp->adver_int * 1000 / TIMER_HZ),
		(vrrp->version == VRRP_VERSION_2) ? "sec" : "milli-sec");
	log_message(LOG_INFO, "   Accept %s", ((vrrp->accept) ? "enabled" : "disabled"));
	if (vrrp->nopreempt)
		log_message(LOG_INFO, "   Preempt disabled");
	if (vrrp->preempt_delay)
		log_message(LOG_INFO, "   Preempt delay = %ld secs",
		       vrrp->preempt_delay / TIMER_HZ);
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
	if (vrrp->script_backup)
		log_message(LOG_INFO, "   Backup state transition script = %s", vrrp->script_backup);
	if (vrrp->script_master)
		log_message(LOG_INFO, "   Master state transition script = %s", vrrp->script_master);
	if (vrrp->script_fault)
		log_message(LOG_INFO, "   Fault state transition script = %s", vrrp->script_fault);
	if (vrrp->script_stop)
		log_message(LOG_INFO, "   Stop state transition script = %s", vrrp->script_stop);
	if (vrrp->script)
		log_message(LOG_INFO, "   Generic state transition script = '%s'", vrrp->script);
	if (vrrp->smtp_alert)
		log_message(LOG_INFO, "   Using smtp notification");
	if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags))
		log_message(LOG_INFO, "   Using VRRP VMAC (flags:%s|%s)"
				    , (__test_bit(VRRP_VMAC_UP_BIT, &vrrp->vmac_flags)) ? "UP" : "DOWN"
				    , (__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags)) ? "xmit_base" : "xmit");
}

void
alloc_vrrp_sync_group(char *gname)
{
	int size = strlen(gname);
	vrrp_sgroup_t *new;

	/* Allocate new VRRP group structure */
	new = (vrrp_sgroup_t *) MALLOC(sizeof(vrrp_sgroup_t));
	new->gname = (char *) MALLOC(size + 1);
	new->state = VRRP_STATE_INIT;
	memcpy(new->gname, gname, size);
	new->global_tracking = 0;

	list_add(vrrp_data->vrrp_sync_group, new);
}

void
alloc_vrrp(char *iname)
{
	int size = strlen(iname);
	seq_counter_t *counter;
	vrrp_t *new;

	/* Allocate new VRRP structure */
	new = (vrrp_t *) MALLOC(sizeof(vrrp_t));
	counter = (seq_counter_t *) MALLOC(sizeof(seq_counter_t));

	/* Build the structure */
	new->ipsecah_counter = counter;

	/* Set default values */
	new->family = AF_INET;
	new->wantstate = VRRP_STATE_BACK;
	new->init_state = VRRP_STATE_BACK;
	new->version = VRRP_VERSION_2;
	new->master_priority = 0;
	new->last_transition = timer_now();
	new->adver_int = TIMER_HZ;
	new->iname = (char *) MALLOC(size + 1);
	new->stats = alloc_vrrp_stats();
	memcpy(new->iname, iname, size);
	new->quick_sync = 0;
	new->garp_rep = VRRP_GARP_REP;
	new->garp_refresh_rep = VRRP_GARP_REFRESH_REP;

	list_add(vrrp_data->vrrp, new);
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
alloc_vrrp_unicast_peer(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	struct sockaddr_storage *peer = NULL;
	int ret;

	if (LIST_ISEMPTY(vrrp->unicast_peer))
		vrrp->unicast_peer = alloc_list(free_unicast_peer, dump_unicast_peer);

	/* Allocate new unicast peer */
	peer = (struct sockaddr_storage *) MALLOC(sizeof(struct sockaddr_storage));
	ret = inet_stosockaddr(vector_slot(strvec, 0), 0, peer);
	if (ret < 0) {
		log_message(LOG_ERR, "Configuration error: VRRP instance[%s] malformed unicast"
				     " peer address[%s]. Skipping..."
				   , vrrp->iname, FMT_STR_VSLOT(strvec, 0));
		FREE(peer);
		return;
	}

	if (peer->ss_family != vrrp->family) {
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

	if (LIST_ISEMPTY(vrrp->track_ifp))
		vrrp->track_ifp = alloc_list(NULL, dump_track);
	alloc_track(vrrp->track_ifp, strvec);
}

void
alloc_vrrp_track_script(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (LIST_ISEMPTY(vrrp->track_script))
		vrrp->track_script = alloc_list(NULL, dump_track_script);
	alloc_track_script(vrrp->track_script, strvec);
}

void
alloc_vrrp_vip(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	if (vrrp->ifp == NULL) {
		log_message(LOG_ERR, "Configuration error: VRRP definition must belong to an interface");
	}

	if (LIST_ISEMPTY(vrrp->vip))
		vrrp->vip = alloc_list(free_ipaddress, dump_ipaddress);
	alloc_ipaddress(vrrp->vip, strvec, vrrp->ifp);
}
void
alloc_vrrp_evip(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (LIST_ISEMPTY(vrrp->evip))
		vrrp->evip = alloc_list(free_ipaddress, dump_ipaddress);
	alloc_ipaddress(vrrp->evip, strvec, vrrp->ifp);
}

void
alloc_vrrp_vroute(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (LIST_ISEMPTY(vrrp->vroutes))
		vrrp->vroutes = alloc_list(free_iproute, dump_iproute);
	alloc_route(vrrp->vroutes, strvec);
}

void
alloc_vrrp_script(char *sname)
{
	int size = strlen(sname);
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
alloc_vrrp_buffer(void)
{
	vrrp_buffer = (char *) MALLOC(VRRP_PACKET_TEMP_LEN);
}

void
free_vrrp_buffer(void)
{
	FREE(vrrp_buffer);
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
	free_list(data->static_addresses);
	free_list(data->static_routes);
	free_mlist(data->vrrp_index, 255+1);
	free_mlist(data->vrrp_index_fd, 1024+1);
	free_list(data->vrrp);
	free_list(data->vrrp_sync_group);
	free_list(data->vrrp_script);
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
