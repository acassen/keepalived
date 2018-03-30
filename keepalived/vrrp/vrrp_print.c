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
 * Copyright (C) 2015-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include "memory.h"
#include "vrrp.h"
#include "vrrp_data.h"
#include "vrrp_print.h"
#include "vrrp_ipaddress.h"
#ifdef _HAVE_FIB_ROUTING_
#include "vrrp_iproute.h"
#include "vrrp_iprule.h"
#endif
#include "keepalived_netlink.h"
#include "rttables.h"
#include "logger.h"
#include "vrrp_if.h"

#include <time.h>
#include <errno.h>
#include <inttypes.h>

static void
vrrp_print_list(FILE *file, list l, void (*fptr)(FILE*, void*))
{
	element e;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		(*fptr)(file, ELEMENT_DATA(e));
	}
}

static void
vgroup_print(FILE *file, void *data)
{
	unsigned int i;
	char *str;

	vrrp_sgroup_t *vgroup = data;
	fprintf(file, " VRRP Sync Group = %s, %s\n", vgroup->gname,
		(vgroup->state == VRRP_STATE_MAST) ? "MASTER" : "BACKUP");
	for (i = 0; i < vector_size(vgroup->iname); i++) {
		str = vector_slot(vgroup->iname, i);
		fprintf(file, "   monitor = %s\n", str);
	}
	if (vgroup->script_backup)
		fprintf(file, "   Backup state transition script = %s, uid:gid %d:%d\n",
		       vgroup->script_backup->name, vgroup->script_backup->uid, vgroup->script_backup->gid);
	if (vgroup->script_master)
		fprintf(file, "   Master state transition script = %s, uid:gid %d:%d\n",
		       vgroup->script_master->name, vgroup->script_master->uid, vgroup->script_master->gid);
	if (vgroup->script_fault)
		fprintf(file, "   Fault state transition script = %s, uid:gid %d:%d\n",
		       vgroup->script_fault->name, vgroup->script_fault->uid, vgroup->script_fault->gid);
	if (vgroup->script)
		fprintf(file, "   Generic state transition script = '%s', uid:gid %d:%d\n",
		       vgroup->script->name, vgroup->script->uid, vgroup->script->gid);
	if (vgroup->smtp_alert)
		fprintf(file, "   Using smtp notification\n");

}

static void
vscript_print(FILE *file, void *data)
{
	vrrp_script_t *vscript = data;
	const char *str;

	fprintf(file, " VRRP Script = %s\n", vscript->sname);
	fprintf(file, "   Command = %s\n", vscript->script);
	fprintf(file, "   Interval = %lu sec\n", vscript->interval / TIMER_HZ);
	fprintf(file, "   Weight = %d\n", vscript->weight);
	fprintf(file, "   Rise = %d\n", vscript->rise);
	fprintf(file, "   Fall = %d\n", vscript->fall);
	fprintf(file, "   Insecure = %s\n", vscript->insecure ? "yes" : "no");
	fprintf(file, "   uid:gid = %d:%d\n", vscript->uid, vscript->gid);

	switch (vscript->init_state) {
	case SCRIPT_INIT_STATE_INIT:
		str = "INIT"; break;
	case SCRIPT_INIT_STATE_GOOD:
		str = "INIT/GOOD"; break;
	case SCRIPT_INIT_STATE_FAILED:
		str = "INIT/FAILED"; break;
	case SCRIPT_INIT_STATE_DISABLED:
		str = "DISABLED"; break;
	default:
		str = (vscript->result >= vscript->rise) ? "GOOD" : "BAD";
	}
	fprintf(file, "   Status = %s\n", str);
}

static void
script_print(FILE *file, void *data)
{
	tracked_sc_t *tsc = data;
	vrrp_script_t *vscript = tsc->scr;

	fprintf(file, "     %s weight %d\n", vscript->sname, tsc->weight);
}

static void
address_print(FILE *file, void *data)
{
	ip_address_t *ipaddr = data;
	char broadcast[INET_ADDRSTRLEN + 5] = "";	/* allow for " brd " */
	char addr_str[INET6_ADDRSTRLEN] = "";

	if (IP_IS6(ipaddr)) {
		inet_ntop(AF_INET6, &ipaddr->u.sin6_addr, addr_str, sizeof(addr_str));
	} else {
		inet_ntop(AF_INET, &ipaddr->u.sin.sin_addr, addr_str, sizeof(addr_str));
	if (ipaddr->u.sin.sin_brd.s_addr)
		snprintf(broadcast, sizeof(broadcast) - 1, " brd %s",
			 inet_ntop2(ipaddr->u.sin.sin_brd.s_addr));
	}

	fprintf(file, "     %s/%d%s dev %s%s%s%s%s\n"
		, addr_str
		, ipaddr->ifa.ifa_prefixlen
		, broadcast
		, IF_NAME(ipaddr->ifp)
		, IP_IS4(ipaddr) ? " scope " : ""
		, IP_IS4(ipaddr) ? get_rttables_scope(ipaddr->ifa.ifa_scope) : ""
		, ipaddr->label ? " label " : ""
		, ipaddr->label ? ipaddr->label : "");
}

static void
sockaddr_print(FILE *file, void *data)
{
	struct sockaddr_storage *addr = data;

	fprintf(file, "     %s\n", inet_sockaddrtos(addr));
}

#ifdef _HAVE_FIB_ROUTING_
static void
route_print(FILE *file, void *data)
{
	ip_route_t *route = data;
	char *buf = MALLOC(ROUTE_BUF_SIZE);

	format_iproute(route, buf, ROUTE_BUF_SIZE);

	fprintf(file, "     %s\n", buf);

	FREE(buf);

}

static void
rule_print(FILE *file, void *data)
{
	ip_rule_t *rule = data;
	char *buf = MALLOC(RULE_BUF_SIZE);

	format_iprule(rule, buf, RULE_BUF_SIZE);

	fprintf(file, "    %s\n", buf);

	FREE(buf);
}
#endif

static void
if_print(FILE *file, void * data)
{
	/* Track interface dump */
        tracked_if_t *tip = data;
        fprintf(file, "     %s weight %d\n", IF_NAME(tip->ifp), tip->weight);
}

static void
vrrp_print(FILE *file, void *data)
{
	vrrp_t *vrrp = data;
#ifdef _WITH_VRRP_AUTH_
	char auth_data[sizeof(vrrp->auth_data) + 1];
#endif
	char time_str[26];

	fprintf(file, " VRRP Instance = %s\n", vrrp->iname);
	fprintf(file, "   VRRP Version = %d\n", vrrp->version);
	if (vrrp->family == AF_INET6)
		fprintf(file, "   Using Native IPv6\n");
	fprintf(file, "   State = ");
	if (vrrp->state == VRRP_STATE_BACK) {
		fprintf(file, "BACKUP\n");
		fprintf(file, "   Master router = %s\n",
			inet_sockaddrtos(&vrrp->master_saddr));
		fprintf(file, "   Master priority = %d\n",
			vrrp->master_priority);
	}
	else if (vrrp->state == VRRP_STATE_FAULT)
		fprintf(file, "FAULT\n");
	else if (vrrp->state == VRRP_STATE_MAST)
		fprintf(file, "MASTER\n");
	else
		fprintf(file, "%d\n", vrrp->state);
	ctime_r(&vrrp->last_transition.tv_sec, time_str);
	time_str[sizeof(time_str)-2] = '\0';	/* Remove '\n' char */
	fprintf(file, "   Last transition = %ld (%s)\n",
		vrrp->last_transition.tv_sec, time_str);
	fprintf(file, "   Listening device = %s\n", IF_NAME(vrrp->ifp));
#ifdef _HAVE_VRRP_VMAC_
	if (vrrp->ifp->vmac)
		fprintf(file, "   Real interface = %s\n", IF_NAME(if_get_by_ifindex(vrrp->ifp->base_ifindex)));
#endif
	if (vrrp->dont_track_primary)
		fprintf(file, "   VRRP interface tracking disabled\n");
	if (vrrp->skip_check_adv_addr)
		fprintf(file, "   Skip checking advert IP addresses\n");
	if (vrrp->strict_mode)
		fprintf(file, "   Enforcing VRRP compliance\n");
	fprintf(file, "   Using src_ip = %s\n", inet_sockaddrtos(&vrrp->saddr));
	fprintf(file, "   Gratuitous ARP delay = %d\n",
		       vrrp->garp_delay/TIMER_HZ);
	fprintf(file, "   Gratuitous ARP repeat = %d\n", vrrp->garp_rep);
	fprintf(file, "   Gratuitous ARP refresh = %lu\n",
		       vrrp->garp_refresh.tv_sec/TIMER_HZ);
	fprintf(file, "   Gratuitous ARP refresh repeat = %d\n", vrrp->garp_refresh_rep);
	fprintf(file, "   Gratuitous ARP lower priority delay = %u\n", vrrp->garp_lower_prio_delay / TIMER_HZ);
	fprintf(file, "   Gratuitous ARP lower priority repeat = %u\n", vrrp->garp_lower_prio_rep);
	fprintf(file, "   Send advert after receive lower priority advert = %s\n", vrrp->lower_prio_no_advert ? "false" : "true");
	fprintf(file, "   Send advert after receive higher priority advert = %s\n", vrrp->higher_prio_send_advert ? "true" : "false");
	fprintf(file, "   Virtual Router ID = %d\n", vrrp->vrid);
	fprintf(file, "   Priority = %d\n", vrrp->base_priority);
	fprintf(file, "   Effective priority = %d\n", vrrp->effective_priority);
	fprintf(file, "   Advert interval = %d %s\n",
		(vrrp->version == VRRP_VERSION_2) ? (vrrp->adver_int / TIMER_HZ) :
		(vrrp->adver_int / (TIMER_HZ / 1000)),
		(vrrp->version == VRRP_VERSION_2) ? "sec" : "milli-sec");
	if (vrrp->state == VRRP_STATE_BACK && vrrp->version == VRRP_VERSION_3)
		fprintf(file, "   Master advert interval = %d milli-sec", vrrp->master_adver_int / (TIMER_HZ / 1000));
	fprintf(file, "   Accept = %s\n", vrrp->accept ? "enabled" : "disabled");
	fprintf(file, "   Preempt = %s\n", vrrp->nopreempt ? "disabled" : "enabled");
	fprintf(file, "   Promote_secondaries = %s\n", vrrp->promote_secondaries ? "enabled" : "disabled");
	if (vrrp->preempt_delay)
		fprintf(file, "   Preempt delay = %ld secs\n",
		       vrrp->preempt_delay / TIMER_HZ);
#if defined _WITH_VRRP_AUTH_
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
#endif

	if (!LIST_ISEMPTY(vrrp->track_ifp)) {
		fprintf(file, "   Tracked interfaces = %d\n",
			LIST_SIZE(vrrp->track_ifp));
		vrrp_print_list(file, vrrp->track_ifp, &if_print);
	}
	if (!LIST_ISEMPTY(vrrp->track_script)) {
		fprintf(file, "   Tracked scripts = %d\n",
		       LIST_SIZE(vrrp->track_script));
		vrrp_print_list(file, vrrp->track_script, &script_print);
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
	if (!LIST_ISEMPTY(vrrp->unicast_peer)) {
		fprintf(file, "   Unicast Peer = %d\n",
			LIST_SIZE(vrrp->unicast_peer));
		vrrp_print_list(file, vrrp->unicast_peer, &sockaddr_print);
#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
		fprintf(file, "   Unicast checksum compatibility = %s\n",
				vrrp->unicast_chksum_compat == CHKSUM_COMPATIBILITY_NONE ? "no" :
			        vrrp->unicast_chksum_compat == CHKSUM_COMPATIBILITY_NEVER ? "never" :
			        vrrp->unicast_chksum_compat == CHKSUM_COMPATIBILITY_CONFIG ? "config" :
			        vrrp->unicast_chksum_compat == CHKSUM_COMPATIBILITY_AUTO ? "auto" : "unknown");
#endif
	}
#ifdef _HAVE_FIB_ROUTING_
	if (!LIST_ISEMPTY(vrrp->vroutes)) {
		fprintf(file, "   Virtual Routes = %d\n", LIST_SIZE(vrrp->vroutes));
		vrrp_print_list(file, vrrp->vroutes, &route_print);
	}
	if (!LIST_ISEMPTY(vrrp->vrules)) {
		fprintf(file, "   Virtual Rules = %d\n", LIST_SIZE(vrrp->vrules));
		vrrp_print_list(file, vrrp->vrules, &rule_print);
	}
#endif
	if (vrrp->script_backup)
		fprintf(file, "   Backup state transition script = %s, uid:gid %d:%d\n",
				vrrp->script_backup->name, vrrp->script_backup->uid, vrrp->script_backup->gid);
	if (vrrp->script_master)
		fprintf(file, "   Master state transition script = %s, uid:gid %d:%d\n",
				vrrp->script_master->name, vrrp->script_master->uid, vrrp->script_master->gid);
	if (vrrp->script_fault)
		fprintf(file, "   Fault state transition script = %s, uid:gid %d:%d\n",
				vrrp->script_fault->name, vrrp->script_fault->uid, vrrp->script_fault->gid);
	if (vrrp->script_stop)
		fprintf(file, "   Stop state transition script = %s, uid:gid %d:%d\n",
				vrrp->script_stop->name, vrrp->script_stop->uid, vrrp->script_stop->gid);
	if (vrrp->script)
		fprintf(file, "   Generic state transition script = '%s', uid:gid %d:%d\n",
				vrrp->script->name, vrrp->script->uid, vrrp->script->gid);
	if (vrrp->smtp_alert)
			fprintf(file, "   Using smtp notification\n");
}

void
vrrp_print_data(void)
{
	FILE *file;
	file = fopen ("/tmp/keepalived.data","w");

	if (!file) {
		log_message(LOG_INFO, "Can't open /tmp/keepalived.data (%d: %s)",
			errno, strerror(errno));
		return;
	}

	fprintf(file, "------< VRRP Topology >------\n");
	vrrp_print_list(file, vrrp_data->vrrp, &vrrp_print);

	if (!LIST_ISEMPTY(vrrp_data->vrrp_sync_group)) {
		fprintf(file, "------< VRRP Sync groups >------\n");
		vrrp_print_list(file, vrrp_data->vrrp_sync_group, &vgroup_print);
	}

	if (!LIST_ISEMPTY(vrrp_data->vrrp_script)) {
		fprintf(file, "------< VRRP Scripts >------\n");
		vrrp_print_list(file, vrrp_data->vrrp_script, &vscript_print);
	}

	print_interface_list(file);

	fclose(file);

	clear_rt_names();
}

void
vrrp_print_stats(void)
{
	FILE *file;
	file = fopen ("/tmp/keepalived.stats","w");

	if (!file) {
		log_message(LOG_INFO, "Can't open /tmp/keepalived.stats (%d: %s)",
			errno, strerror(errno));
		return;
	}

	list l = vrrp_data->vrrp;
	element e;
	vrrp_t *vrrp;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		fprintf(file, "VRRP Instance: %s\n", vrrp->iname);
		fprintf(file, "  Advertisements:\n");
		fprintf(file, "    Received: %" PRIu64 "\n", vrrp->stats->advert_rcvd);
		fprintf(file, "    Sent: %d\n", vrrp->stats->advert_sent);
		fprintf(file, "  Became master: %d\n", vrrp->stats->become_master);
		fprintf(file, "  Released master: %d\n",
			vrrp->stats->release_master);
		fprintf(file, "  Packet Errors:\n");
		fprintf(file, "    Length: %" PRIu64 "\n", vrrp->stats->packet_len_err);
		fprintf(file, "    TTL: %" PRIu64 "\n", vrrp->stats->ip_ttl_err);
		fprintf(file, "    Invalid Type: %" PRIu64 "\n",
			vrrp->stats->invalid_type_rcvd);
		fprintf(file, "    Advertisement Interval: %" PRIu64 "\n",
			vrrp->stats->advert_interval_err);
		fprintf(file, "    Address List: %" PRIu64 "\n",
			vrrp->stats->addr_list_err);
		fprintf(file, "  Authentication Errors:\n");
		fprintf(file, "    Invalid Type: %d\n",
			vrrp->stats->invalid_authtype);
#ifdef _WITH_VRRP_AUTH_
		fprintf(file, "    Type Mismatch: %d\n",
			vrrp->stats->authtype_mismatch);
		fprintf(file, "    Failure: %d\n",
			vrrp->stats->auth_failure);
#endif
		fprintf(file, "  Priority Zero:\n");
		fprintf(file, "    Received: %" PRIu64 "\n", vrrp->stats->pri_zero_rcvd);
		fprintf(file, "    Sent: %" PRIu64 "\n", vrrp->stats->pri_zero_sent);
	}
	fclose(file);
}
