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

#include "memory.h"
#include "vrrp.h"
#include "vrrp_data.h"
#include "vrrp_print.h"
#include "vrrp_iproute.h"
#include "vrrp_netlink.h"

void
vrrp_print_list(FILE *file, list l, void (*fptr)(FILE*, void*))
{
	element e;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		(*fptr)(file, ELEMENT_DATA(e));
	}
}

void
vrrp_print_data(void)
{
	FILE *file;
	file = fopen ("/tmp/keepalived.data","w");

	fprintf(file, "------< VRRP Topology >------\n");
	vrrp_print_list(file, vrrp_data->vrrp, &vrrp_print);

	if (!LIST_ISEMPTY(vrrp_data->vrrp_sync_group)) {
		fprintf(file, "------< VRRP Sync groups >------\n");
		vrrp_print_list(file, vrrp_data->vrrp_sync_group, &vgroup_print);
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
		fprintf(file, "    Invalid Type: %d\n",
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
vrrp_print(FILE *file, void *data)
{
	vrrp_t *vrrp = data;
	char auth_data[sizeof(vrrp->auth_data) + 1];
	fprintf(file, " VRRP Instance = %s\n", vrrp->iname);
	fprintf(file, " VRRP Version = %d\n", vrrp->version);
	if (vrrp->family == AF_INET6)
		fprintf(file, "   Using Native IPv6\n");
	if (vrrp->state == VRRP_STATE_BACK) {
		fprintf(file, "   State = BACKUP\n");
		fprintf(file, "   Master router = %s\n",
			inet_sockaddrtos(&vrrp->master_saddr));
		fprintf(file, "   Master priority = %d\n",
			vrrp->master_priority);
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
	fprintf(file, "   Using src_ip = %s\n", inet_sockaddrtos(&vrrp->saddr));
	if (vrrp->lvs_syncd_if)
		fprintf(file, "   Runing LVS sync daemon on interface = %s\n",
		       vrrp->lvs_syncd_if);
	if (vrrp->garp_delay)
		fprintf(file, "   Gratuitous ARP delay = %d\n",
		       vrrp->garp_delay/TIMER_HZ);
	fprintf(file, "   Virtual Router ID = %d\n", vrrp->vrid);
	fprintf(file, "   Priority = %d\n", vrrp->base_priority);
	fprintf(file, "   Advert interval = %d %s\n",
		(vrrp->version == VRRP_VERSION_2) ? (vrrp->adver_int / TIMER_HZ) :
		(vrrp->adver_int * 1000 / TIMER_HZ),
		(vrrp->version == VRRP_VERSION_2) ? "sec" : "milli-sec");
	fprintf(file, "   Accept = %s\n", ((vrrp->accept) ? "enabled" : "disabled"));
	if (vrrp->nopreempt)
		fprintf(file, "   Preempt = disabled\n");
	else
		fprintf(file, "   Preempt = enabled\n");
	if (vrrp->preempt_delay)
		fprintf(file, "   Preempt delay = %ld secs\n",
		       vrrp->preempt_delay / TIMER_HZ);
	if (vrrp->auth_type) {
		fprintf(file, "   Authentication type = %s\n",
		       (vrrp->auth_type ==
			VRRP_AUTH_AH) ? "IPSEC_AH" : "SIMPLE_PASSWORD");
		if (vrrp->auth_type != VRRP_AUTH_AH) {
			/* vrrp->auth_data is not \0 terminated */
			memcpy(auth_data, vrrp->auth_data, sizeof(vrrp->auth_data));
			auth_data[sizeof(vrrp->auth_data)] = '\0';
			fprintf(file, "   Password = %s\n", auth_data);
		}
	}
	else
		fprintf(file, "   Authentication type = none\n");

	if (!LIST_ISEMPTY(vrrp->track_ifp)) {
		fprintf(file, "   Tracked interfaces = %d\n",
			LIST_SIZE(vrrp->track_ifp));
		vrrp_print_list(file, vrrp->track_ifp, &if_print);
	}
	if (!LIST_ISEMPTY(vrrp->track_script)) {
		fprintf(file, "   Tracked scripts = %d\n",
		       LIST_SIZE(vrrp->track_script));
		vrrp_print_list(file, vrrp->track_script, &vscript_print);
	}
	if (!LIST_ISEMPTY(vrrp->vip)) {
		fprintf(file, "   Virtual IP = %d\n", LIST_SIZE(vrrp->vip));
		vrrp_print_list(file, vrrp->vip, &address_print);
	}
	if (!LIST_ISEMPTY(vrrp->evip)) {
		fprintf(file, "   Virtual IP Excluded = %d\n",
			LIST_SIZE(vrrp->evip));
		vrrp_print_list(file, vrrp->evip, &address_print);
	}
	if (!LIST_ISEMPTY(vrrp->vroutes)) {
		fprintf(file, "   Virtual Routes = %d\n", LIST_SIZE(vrrp->vroutes));
		vrrp_print_list(file, vrrp->vroutes, &route_print);
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
vgroup_print(FILE *file, void *data)
{
	int i;
	char *str;

	vrrp_sgroup_t *vgroup = data;
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

void
vscript_print(FILE *file, void *data)
{
	vrrp_script_t *vscript = data;
	char *str;

	fprintf(file, " VRRP Script = %s\n", vscript->sname);
	fprintf(file, "   Command = %s\n", vscript->script);
	fprintf(file, "   Interval = %ld sec\n", vscript->interval / TIMER_HZ);
	fprintf(file, "   Weight = %d\n", vscript->weight);
	fprintf(file, "   Rise = %d\n", vscript->rise);
	fprintf(file, "   Full = %d\n", vscript->fall);

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
	fprintf(file, "   Status = %s\n", str);
}

void
address_print(FILE *file, void *data)
{
	ip_address_t *ipaddr = data;
	char *broadcast = (char *) MALLOC(21);
	char *addr_str = (char *) MALLOC(41);

	if (IP_IS6(ipaddr)) {
		inet_ntop(AF_INET6, &ipaddr->u.sin6_addr, addr_str, 41);
	} else {
		inet_ntop(AF_INET, &ipaddr->u.sin.sin_addr, addr_str, 41);
	if (ipaddr->u.sin.sin_brd.s_addr)
		snprintf(broadcast, 20, " brd %s",
			 inet_ntop2(ipaddr->u.sin.sin_brd.s_addr));
	}

	fprintf(file, "     %s/%d%s dev %s scope %s%s%s\n"
		, addr_str
		, ipaddr->ifa.ifa_prefixlen
		, broadcast
		, IF_NAME(ipaddr->ifp)
		, netlink_scope_n2a(ipaddr->ifa.ifa_scope)
		, ipaddr->label ? " label " : ""
		, ipaddr->label ? ipaddr->label : "");
	FREE(broadcast);
	FREE(addr_str);
}

void
route_print(FILE *file, void *data)
{
	ip_route_t *route = data;
	char *msg = MALLOC(150);
	char *tmp = MALLOC(30);

	if (route->blackhole) {
		strncat(msg, "blackhole ", 30);
	}
	if (route->dst) {
		snprintf(tmp, 30, "%s/%d", ipaddresstos(route->dst),
			route->dmask);
		strncat(msg, tmp, 30);
	}
	if (route->gw) {
		snprintf(tmp, 30, " gw %s", ipaddresstos(route->gw));
		strncat(msg, tmp, 30);
	}
	if (route->gw2) {
		snprintf(tmp, 30, " or gw %s", ipaddresstos(route->gw2));
		strncat(msg, tmp, 30);
	}
	if (route->src) {
		snprintf(tmp, 30, " src %s", ipaddresstos(route->src));
		strncat(msg, tmp, 30);
	}
	if (route->index) {
		snprintf(tmp, 30, " dev %s",
		  IF_NAME(if_get_by_ifindex(route->index)));
		strncat(msg, tmp, 30);
	}
	if (route->table) {
		snprintf(tmp, 30, " table %d", route->table);
		strncat(msg, tmp, 30);
	}
	if (route->scope) {
		snprintf(tmp, 30, " scope %s",
		  netlink_scope_n2a(route->scope));
		strncat(msg, tmp, 30);
	}
	if (route->metric) {
		snprintf(tmp, 30, " metric %d", route->metric);
		strncat(msg, tmp, 30);
	}

	fprintf(file, "     %s\n", msg);

	FREE(tmp);
	FREE(msg);

}

void
if_print(FILE *file, void * data)
{
	tracked_if_t *tip = data;
	interface_t *ifp = tip->ifp;
	char addr_str[41];
	int weight = tip->weight;

	fprintf(file, "------< NIC >------\n");
	fprintf(file, " Name = %s\n", ifp->ifname);
	fprintf(file, " index = %d\n", ifp->ifindex);
	fprintf(file, " IPv4 address = %s\n",
		inet_ntop2(ifp->sin_addr.s_addr));
	inet_ntop(AF_INET6, &ifp->sin6_addr, addr_str, 41);
	fprintf(file, " IPv6 address = %s\n", addr_str);

	/* FIXME: Harcoded for ethernet */
	if (ifp->hw_type == ARPHRD_ETHER)
	fprintf(file, " MAC = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		ifp->hw_addr[0], ifp->hw_addr[1], ifp->hw_addr[2]
		, ifp->hw_addr[3], ifp->hw_addr[4], ifp->hw_addr[5]);

	if (ifp->flags & IFF_UP)
		fprintf(file, " is UP\n");

	if (ifp->flags & IFF_RUNNING)
		fprintf(file, " is RUNNING\n");

	if (!(ifp->flags & IFF_UP) && !(ifp->flags & IFF_RUNNING))
		fprintf(file, " is DOWN\n");

	if (weight)
		fprintf(file, " weight = %d\n", weight);

	fprintf(file, " MTU = %d\n", ifp->mtu);

	switch (ifp->hw_type) {
	case ARPHRD_LOOPBACK:
		fprintf(file, " HW Type = LOOPBACK\n");
		break;
	case ARPHRD_ETHER:
		fprintf(file, " HW Type = ETHERNET\n");
		break;
	default:
		fprintf(file, " HW Type = UNKNOWN\n");
		break;
	}

	/* MII channel supported ? */
	if (IF_MII_SUPPORTED(ifp))
	        fprintf(file, " NIC support MII regs\n");
	else if (IF_ETHTOOL_SUPPORTED(ifp))
	        fprintf(file, " NIC support EHTTOOL GLINK interface\n");
	else
	        fprintf(file, " Enabling NIC ioctl refresh polling\n");
}

