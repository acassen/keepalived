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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include "vrrp_data.h"
#include "vrrp_index.h"
#include "vrrp_sync.h"
#include "vrrp_if.h"
#include "vrrp.h"
#include "memory.h"
#include "utils.h"
#include "logger.h"

/* global vars */
vrrp_conf_data *vrrp_data = NULL;
vrrp_conf_data *old_vrrp_data = NULL;
char *vrrp_buffer;

/* Static addresses facility function */
void
alloc_saddress(vector strvec)
{
	if (LIST_ISEMPTY(vrrp_data->static_addresses))
		vrrp_data->static_addresses = alloc_list(free_ipaddress, dump_ipaddress);
	alloc_ipaddress(vrrp_data->static_addresses, strvec, NULL);
}

/* Static routes facility function */
void
alloc_sroute(vector strvec)
{
	if (LIST_ISEMPTY(vrrp_data->static_routes))
		vrrp_data->static_routes = alloc_list(free_iproute, dump_iproute);
	alloc_route(vrrp_data->static_routes, strvec);
}

/* VRRP facility functions */
static void
free_vgroup(void *data)
{
	vrrp_sgroup *vgroup = data;

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
	vrrp_sgroup *vgroup = data;
	int i;
	char *str;

	log_message(LOG_INFO, " VRRP Sync Group = %s, %s", vgroup->gname,
	       (vgroup->state == VRRP_STATE_MAST) ? "MASTER" : "BACKUP");
	for (i = 0; i < VECTOR_SIZE(vgroup->iname); i++) {
		str = VECTOR_SLOT(vgroup->iname, i);
		log_message(LOG_INFO, "   monitor = %s", str);
	}
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
	vrrp_script *vscript = data;

	FREE(vscript->sname);
	FREE_PTR(vscript->script);
	FREE(vscript);
}
static void
dump_vscript(void *data)
{
	vrrp_script *vscript = data;
	char *str;

	log_message(LOG_INFO, " VRRP Script = %s", vscript->sname);
	log_message(LOG_INFO, "   Command = %s", vscript->script);
	log_message(LOG_INFO, "   Interval = %d sec", vscript->interval / TIMER_HZ);
	log_message(LOG_INFO, "   Weight = %d", vscript->weight);
	log_message(LOG_INFO, "   Rise = %d", vscript->rise);
	log_message(LOG_INFO, "   Full = %d", vscript->fall);

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
	interface *ifp;
	if (sock->fd_in > 0) {
		ifp = if_get_by_ifindex(sock->ifindex);
		if_leave_vrrp_group(sock->family, sock->fd_in, ifp);
	}
	if (sock->fd_out > 0)
		close(sock->fd_out);
	FREE(sock_data);
}

static void
dump_sock(void *sock_data)
{
	sock_t *sock = sock_data;
	log_message(LOG_INFO, "VRRP sockpool: [ifindex(%d), proto(%d), fd(%d,%d)]"
			    , sock->ifindex
			    , sock->proto
			    , sock->fd_in
			    , sock->fd_out);
}

static void
free_vrrp(void *data)
{
	vrrp_rt *vrrp = data;
	element e;

	FREE(vrrp->iname);
	FREE_PTR(vrrp->send_buffer);
	FREE_PTR(vrrp->lvs_syncd_if);
	FREE_PTR(vrrp->script_backup);
	FREE_PTR(vrrp->script_master);
	FREE_PTR(vrrp->script_fault);
	FREE_PTR(vrrp->script_stop);
	FREE_PTR(vrrp->script);
	FREE(vrrp->ipsecah_counter);

	if (!LIST_ISEMPTY(vrrp->track_ifp))
		for (e = LIST_HEAD(vrrp->track_ifp); e; ELEMENT_NEXT(e))
			FREE(ELEMENT_DATA(e));
	free_list(vrrp->track_ifp);

	if (!LIST_ISEMPTY(vrrp->track_script))
		for (e = LIST_HEAD(vrrp->track_script); e; ELEMENT_NEXT(e))
			FREE(ELEMENT_DATA(e));
	free_list(vrrp->track_script);

	free_list(vrrp->vip);
	free_list(vrrp->evip);
	free_list(vrrp->vroutes);
	FREE(vrrp);
}
static void
dump_vrrp(void *data)
{
	vrrp_rt *vrrp = data;
	char auth_data[sizeof(vrrp->auth_data) + 1];

	log_message(LOG_INFO, " VRRP Instance = %s", vrrp->iname);
	if (vrrp->family == AF_INET6)
		log_message(LOG_INFO, "   Using Native IPv6");
	if (vrrp->init_state == VRRP_STATE_BACK)
		log_message(LOG_INFO, "   Want State = BACKUP");
	else
		log_message(LOG_INFO, "   Want State = MASTER");
	log_message(LOG_INFO, "   Runing on device = %s", IF_NAME(vrrp->ifp));
	if (vrrp->dont_track_primary)
		log_message(LOG_INFO, "   VRRP interface tracking disabled");
	if (vrrp->mcast_saddr)
		log_message(LOG_INFO, "   Using mcast src_ip = %s",
		       inet_ntop2(vrrp->mcast_saddr));
	if (vrrp->lvs_syncd_if)
		log_message(LOG_INFO, "   Runing LVS sync daemon on interface = %s",
		       vrrp->lvs_syncd_if);
	if (vrrp->garp_delay)
		log_message(LOG_INFO, "   Gratuitous ARP delay = %d",
		       vrrp->garp_delay/TIMER_HZ);
	log_message(LOG_INFO, "   Virtual Router ID = %d", vrrp->vrid);
	log_message(LOG_INFO, "   Priority = %d", vrrp->base_priority);
	log_message(LOG_INFO, "   Advert interval = %dsec",
	       vrrp->adver_int / TIMER_HZ);
	if (vrrp->nopreempt)
		log_message(LOG_INFO, "   Preempt disabled");
	if (vrrp->preempt_delay)
		log_message(LOG_INFO, "   Preempt delay = %ld secs",
		       vrrp->preempt_delay / TIMER_HZ);
	if (vrrp->auth_type) {
		log_message(LOG_INFO, "   Authentication type = %s",
		       (vrrp->auth_type ==
			VRRP_AUTH_AH) ? "IPSEC_AH" : "SIMPLE_PASSWORD");
		/* vrrp->auth_data is not \0 terminated */
		memcpy(auth_data, vrrp->auth_data, sizeof(vrrp->auth_data));
		auth_data[sizeof(vrrp->auth_data)] = '\0';
		log_message(LOG_INFO, "   Password = %s", auth_data);
	}
	if (!LIST_ISEMPTY(vrrp->track_ifp)) {
		log_message(LOG_INFO, "   Tracked interfaces = %d", LIST_SIZE(vrrp->track_ifp));
		dump_list(vrrp->track_ifp);
	}
	if (!LIST_ISEMPTY(vrrp->track_script)) {
		log_message(LOG_INFO, "   Tracked scripts = %d",
		       LIST_SIZE(vrrp->track_script));
		dump_list(vrrp->track_script);
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
		log_message(LOG_INFO, "   Backup state transition script = %s",
		       vrrp->script_backup);
	if (vrrp->script_master)
		log_message(LOG_INFO, "   Master state transition script = %s",
		       vrrp->script_master);
	if (vrrp->script_fault)
		log_message(LOG_INFO, "   Fault state transition script = %s",
		       vrrp->script_fault);
	if (vrrp->script_stop)
		log_message(LOG_INFO, "   Stop state transition script = %s",
		       vrrp->script_stop);
	if (vrrp->script)
		log_message(LOG_INFO, "   Generic state transition script = '%s'",
		       vrrp->script);
	if (vrrp->smtp_alert)
		log_message(LOG_INFO, "   Using smtp notification");
}

void
alloc_vrrp_sync_group(char *gname)
{
	int size = strlen(gname);
	vrrp_sgroup *new;

	/* Allocate new VRRP group structure */
	new = (vrrp_sgroup *) MALLOC(sizeof (vrrp_sgroup));
	new->gname = (char *) MALLOC(size + 1);
	new->state = VRRP_STATE_INIT;
	memcpy(new->gname, gname, size);

	list_add(vrrp_data->vrrp_sync_group, new);
}

void
alloc_vrrp(char *iname)
{
	int size = strlen(iname);
	seq_counter *counter;
	vrrp_rt *new;

	/* Allocate new VRRP structure */
	new = (vrrp_rt *) MALLOC(sizeof (vrrp_rt));
	counter = (seq_counter *) MALLOC(sizeof (seq_counter));

	/* Build the structure */
	new->ipsecah_counter = counter;

	/* Set default values */
	new->family = AF_INET;
	new->wantstate = VRRP_STATE_BACK;
	new->init_state = VRRP_STATE_BACK;
	new->adver_int = TIMER_HZ;
	new->iname = (char *) MALLOC(size + 1);
	memcpy(new->iname, iname, size);

	list_add(vrrp_data->vrrp, new);
}

void
alloc_vrrp_track(vector strvec)
{
	vrrp_rt *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (LIST_ISEMPTY(vrrp->track_ifp))
		vrrp->track_ifp = alloc_list(NULL, dump_track);
	alloc_track(vrrp->track_ifp, strvec);
}

void
alloc_vrrp_track_script(vector strvec)
{
	vrrp_rt *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (LIST_ISEMPTY(vrrp->track_script))
		vrrp->track_script = alloc_list(NULL, dump_track_script);
	alloc_track_script(vrrp->track_script, strvec);
}

void
alloc_vrrp_vip(vector strvec)
{
	vrrp_rt *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	if (vrrp->ifp == NULL) {
		log_message(LOG_ERR, "Configuration error: VRRP definition must belong to an interface");
	}

	if (LIST_ISEMPTY(vrrp->vip))
		vrrp->vip = alloc_list(free_ipaddress, dump_ipaddress);
	alloc_ipaddress(vrrp->vip, strvec, vrrp->ifp);
}
void
alloc_vrrp_evip(vector strvec)
{
	vrrp_rt *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (LIST_ISEMPTY(vrrp->evip))
		vrrp->evip = alloc_list(free_ipaddress, dump_ipaddress);
	alloc_ipaddress(vrrp->evip, strvec, vrrp->ifp);
}

void
alloc_vrrp_vroute(vector strvec)
{
	vrrp_rt *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);

	if (LIST_ISEMPTY(vrrp->vroutes))
		vrrp->vroutes = alloc_list(free_iproute, dump_iproute);
	alloc_route(vrrp->vroutes, strvec);
}

void
alloc_vrrp_script(char *sname)
{
	int size = strlen(sname);
	vrrp_script *new;

	/* Allocate new VRRP group structure */
	new = (vrrp_script *) MALLOC(sizeof (vrrp_script));
	new->sname = (char *) MALLOC(size + 1);
	memcpy(new->sname, sname, size + 1);
	new->interval = VRRP_SCRIPT_DI * TIMER_HZ;
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

vrrp_conf_data *
alloc_vrrp_data(void)
{
	vrrp_conf_data *new;

	new = (vrrp_conf_data *) MALLOC(sizeof (vrrp_conf_data));
	new->vrrp = alloc_list(free_vrrp, dump_vrrp);
	new->vrrp_index = alloc_mlist(NULL, NULL, 255+1);
	new->vrrp_index_fd = alloc_mlist(NULL, NULL, 1024+1);
	new->vrrp_sync_group = alloc_list(free_vgroup, dump_vgroup);
	new->vrrp_script = alloc_list(free_vscript, dump_vscript);
	new->vrrp_socket_pool = alloc_list(free_sock, dump_sock);

	return new;
}

void
free_vrrp_data(vrrp_conf_data * vrrp_data)
{
	free_list(vrrp_data->static_addresses);
	free_list(vrrp_data->static_routes);
	free_mlist(vrrp_data->vrrp_index, 255+1);
	free_mlist(vrrp_data->vrrp_index_fd, 1024+1);
	free_list(vrrp_data->vrrp);
	free_list(vrrp_data->vrrp_sync_group);
	free_list(vrrp_data->vrrp_script);
//	free_list(vrrp_data->vrrp_socket_pool);
	FREE(vrrp_data);
}

void
free_vrrp_sockpool(vrrp_conf_data * vrrp_data)
{
	free_list(vrrp_data->vrrp_socket_pool);
}

void
dump_vrrp_data(vrrp_conf_data * vrrp_data)
{
	if (!LIST_ISEMPTY(vrrp_data->static_addresses)) {
		log_message(LOG_INFO, "------< Static Addresses >------");
		dump_list(vrrp_data->static_addresses);
	}
	if (!LIST_ISEMPTY(vrrp_data->static_routes)) {
		log_message(LOG_INFO, "------< Static Routes >------");
		dump_list(vrrp_data->static_routes);
	}
	if (!LIST_ISEMPTY(vrrp_data->vrrp)) {
		log_message(LOG_INFO, "------< VRRP Topology >------");
		dump_list(vrrp_data->vrrp);
	}
	if (!LIST_ISEMPTY(vrrp_data->vrrp_sync_group)) {
		log_message(LOG_INFO, "------< VRRP Sync groups >------");
		dump_list(vrrp_data->vrrp_sync_group);
	}
	if (!LIST_ISEMPTY(vrrp_data->vrrp_script)) {
		log_message(LOG_INFO, "------< VRRP Scripts >------");
		dump_list(vrrp_data->vrrp_script);
	}
}
