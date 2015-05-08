/*
 * Soft:        Vrrpd is an implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Part:        Print running VRRP state information
 *
 * Author:      John Southworth, <john.southworth@vyatta.com>
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
 * Copyright (C) 2012 John Southworth, <john.southworth@vyatta.com>
 */

#include "vrrp.h"
#include "vrrp_data.h"
#include "vrrp_print.h"

void
vrrp_print_data(void)
{
	FILE *file;
	file = fopen ("/tmp/keepalived.data","w");

        list l = vrrp_data->vrrp;
	element e;
	vrrp_t *vrrp;
	vrrp_sgroup_t *vgroup;
	fprintf(file, "------< VRRP Topology >------\n");
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		vrrp_print(file, vrrp);
	}

	if (!LIST_ISEMPTY(vrrp_data->vrrp_sync_group)) {
		fprintf(file, "------< VRRP Sync groups >------\n");
		l = vrrp_data->vrrp_sync_group;
		for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
			vgroup = ELEMENT_DATA(e);
			vgroup_print(file, vgroup);
		}
	}
        fclose(file);
}

void
vrrp_print_stats(void)
{
	FILE *file;
	file = fopen ("/tmp/keepalived.stats","w");

	list l = vrrp_data->vrrp;
	element e;
	vrrp_t *vrrp;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		fprintf(file, "VRRP Instance: %s\n", vrrp->iname);
		fprintf(file, "  Advertisements:\n");
		fprintf(file, "    Received: %d\n", vrrp->stats->advert_rcvd);
		fprintf(file, "    Sent: %d\n", vrrp->stats->advert_sent);
		fprintf(file, "  Became master: %d\n", vrrp->stats->become_master);
		fprintf(file, "  Released master: %d\n",
			vrrp->stats->release_master);
		fprintf(file, "  Packet Errors:\n");
		fprintf(file, "    Length: %d\n", vrrp->stats->packet_len_err);
		fprintf(file, "    TTL: %d\n", vrrp->stats->ip_ttl_err);
		fprintf(file, "    Invalide Type: %d\n",
			vrrp->stats->invalid_type_rcvd);
		fprintf(file, "    Advertisement Interval: %d\n",
			vrrp->stats->advert_interval_err);
		fprintf(file, "    Address List: %d\n",
			vrrp->stats->addr_list_err);
		fprintf(file, "  Authentication Errors:\n");
		fprintf(file, "    Invalid Type: %d\n",
			vrrp->stats->invalid_authtype);
		fprintf(file, "    Type Mismatch: %d\n",
			vrrp->stats->authtype_mismatch);
		fprintf(file, "    Failure: %d\n",
			vrrp->stats->auth_failure);
		fprintf(file, "  Priority Zero:\n");
		fprintf(file, "    Received: %d\n", vrrp->stats->pri_zero_rcvd);
		fprintf(file, "    Sent: %d\n", vrrp->stats->pri_zero_sent);
	}
	fclose(file);
}

void
vrrp_print(FILE *file, vrrp_t *vrrp)
{
	char auth_data[sizeof(vrrp->auth_data) + 1];
	fprintf(file, " VRRP Instance = %s\n", vrrp->iname);
	if (vrrp->family == AF_INET6)
		fprintf(file, "   Using Native IPv6\n");
	if (vrrp->state == VRRP_STATE_BACK) {
		fprintf(file, "   State = BACKUP\n");
		fprintf(file, "   Master router = %s\n",
			inet_sockaddrtos(&vrrp->master_saddr));
	}
	else if (vrrp->state == VRRP_STATE_FAULT)
		fprintf(file, "   State = FAULT\n");
	else if (vrrp->state == VRRP_STATE_MAST)
		fprintf(file, "   State = MASTER\n");
	else
		fprintf(file, "   State = %d\n", vrrp->state);
	fprintf(file, "   Last transition = %ld\n",
		vrrp->last_transition.tv_sec);
	fprintf(file, "   Listening device = %s\n", IF_NAME(vrrp->ifp));
	if (vrrp->dont_track_primary)
		fprintf(file, "   VRRP interface tracking disabled\n");
	if (vrrp->lvs_syncd_if)
		fprintf(file, "   Runing LVS sync daemon on interface = %s\n",
		       vrrp->lvs_syncd_if);
	if (vrrp->garp_delay)
		fprintf(file, "   Gratuitous ARP delay = %d\n",
		       vrrp->garp_delay/TIMER_HZ);
	fprintf(file, "   Virtual Router ID = %d\n", vrrp->vrid);
	fprintf(file, "   Priority = %d\n", vrrp->base_priority);
	fprintf(file, "   Advert interval = %dsec\n",
	       vrrp->adver_int / TIMER_HZ);
	if (vrrp->nopreempt)
		fprintf(file, "   Preempt disabled\n");
	if (vrrp->preempt_delay)
		fprintf(file, "   Preempt delay = %ld secs\n",
		       vrrp->preempt_delay / TIMER_HZ);
	if (vrrp->auth_type) {
		fprintf(file, "   Authentication type = %s\n",
		       (vrrp->auth_type ==
			VRRP_AUTH_AH) ? "IPSEC_AH" : "SIMPLE_PASSWORD");
		/* vrrp->auth_data is not \0 terminated */
		memcpy(auth_data, vrrp->auth_data, sizeof(vrrp->auth_data));
		auth_data[sizeof(vrrp->auth_data)] = '\0';
		fprintf(file, "   Password = %s\n", auth_data);
	}
	if (!LIST_ISEMPTY(vrrp->track_ifp)) {
		fprintf(file, "   Tracked interfaces = %d\n", LIST_SIZE(vrrp->track_ifp));
	//	dump_list(vrrp->track_ifp);
	}
	if (!LIST_ISEMPTY(vrrp->track_script)) {
		fprintf(file, "   Tracked scripts = %d\n",
		       LIST_SIZE(vrrp->track_script));
	//	dump_list(vrrp->track_script);
	}
	if (!LIST_ISEMPTY(vrrp->vip)) {
		fprintf(file, "   Virtual IP = %d\n", LIST_SIZE(vrrp->vip));
	//	dump_list(vrrp->vip);
	}
	if (!LIST_ISEMPTY(vrrp->evip)) {
		fprintf(file, "   Virtual IP Excluded = %d\n", LIST_SIZE(vrrp->evip));
	//	dump_list(vrrp->evip);
	}
	if (!LIST_ISEMPTY(vrrp->vroutes)) {
		fprintf(file, "   Virtual Routes = %d\n", LIST_SIZE(vrrp->vroutes));
	//	dump_list(vrrp->vroutes);
	}
	if (vrrp->script_backup)
		fprintf(file, "   Backup state transition script = %s\n",
		       vrrp->script_backup);
	if (vrrp->script_master)
		fprintf(file, "   Master state transition script = %s\n",
		       vrrp->script_master);
	if (vrrp->script_fault)
		fprintf(file, "   Fault state transition script = %s\n",
		       vrrp->script_fault);
	if (vrrp->script_stop)
		fprintf(file, "   Stop state transition script = %s\n",
		       vrrp->script_stop);
	if (vrrp->script)
		fprintf(file, "   Generic state transition script = '%s'\n",
		       vrrp->script);
	if (vrrp->smtp_alert)
			fprintf(file, "   Using smtp notification\n");

}

void
vgroup_print(FILE *file, vrrp_sgroup_t *vgroup)
{
	int i;
	char *str;

	fprintf(file, " VRRP Sync Group = %s, %s\n", vgroup->gname,
       		(vgroup->state == VRRP_STATE_MAST) ? "MASTER" : "BACKUP");
	for (i = 0; i < vector_size(vgroup->iname); i++) {
		str = vector_slot(vgroup->iname, i);
		fprintf(file, "   monitor = %s\n", str);
	}
	if (vgroup->script_backup)
		fprintf(file, "   Backup state transition script = %s\n",
		       vgroup->script_backup);
	if (vgroup->script_master)
		fprintf(file, "   Master state transition script = %s\n",
		       vgroup->script_master);
	if (vgroup->script_fault)
		fprintf(file, "   Fault state transition script = %s\n",
		       vgroup->script_fault);
	if (vgroup->script)
		fprintf(file, "   Generic state transition script = '%s\n'",
		       vgroup->script);
	if (vgroup->smtp_alert)
		fprintf(file, "   Using smtp notification\n");

}
