/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Healthcheckers dynamic data structure definition.
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

#include <netdb.h>

#include "check_data.h"
#include "check_api.h"
#include "check_misc.h"
#include "global_data.h"
#include "check_ssl.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "ipwrapper.h"

/* global vars */
check_data_t *check_data = NULL;
check_data_t *old_check_data = NULL;

/* SSL facility functions */
ssl_data_t *
alloc_ssl(void)
{
	ssl_data_t *ssl = (ssl_data_t *) MALLOC(sizeof(ssl_data_t));
	return ssl;
}
void
free_ssl(void)
{
	ssl_data_t *ssl = check_data->ssl;

	if (!ssl)
		return;
	clear_ssl(ssl);
	FREE_PTR(ssl->password);
	FREE_PTR(ssl->cafile);
	FREE_PTR(ssl->certfile);
	FREE_PTR(ssl->keyfile);
	FREE(ssl);
}
static void
dump_ssl(void)
{
	ssl_data_t *ssl = check_data->ssl;

	if (ssl->password)
		log_message(LOG_INFO, " Password : %s", ssl->password);
	if (ssl->cafile)
		log_message(LOG_INFO, " CA-file : %s", ssl->cafile);
	if (ssl->certfile)
		log_message(LOG_INFO, " Certificate file : %s", ssl->certfile);
	if (ssl->keyfile)
		log_message(LOG_INFO, " Key file : %s", ssl->keyfile);
	if (!ssl->password && !ssl->cafile && !ssl->certfile && !ssl->keyfile)
		log_message(LOG_INFO, " Using autogen SSL context");
}

/* Virtual server group facility functions */
static void
free_vsg(void *data)
{
	virtual_server_group_t *vsg = data;
	FREE_PTR(vsg->gname);
	free_list(&vsg->addr_ip);
	free_list(&vsg->range);
	free_list(&vsg->vfwmark);
	FREE(vsg);
}
static void
dump_vsg(void *data)
{
	virtual_server_group_t *vsg = data;

	log_message(LOG_INFO, " Virtual Server Group = %s", vsg->gname);
	dump_list(vsg->addr_ip);
	dump_list(vsg->range);
	dump_list(vsg->vfwmark);
}
static void
free_vsg_entry(void *data)
{
	FREE(data);
}
static void
dump_vsg_entry(void *data)
{
	virtual_server_group_entry_t *vsg_entry = data;

	if (vsg_entry->vfwmark)
		log_message(LOG_INFO, "   FWMARK = %u", vsg_entry->vfwmark);
	else if (vsg_entry->range)
		log_message(LOG_INFO, "   VIP Range = %s-%d, VPORT = %d"
				    , inet_sockaddrtos(&vsg_entry->addr)
				    , vsg_entry->range
				    , ntohs(inet_sockaddrport(&vsg_entry->addr)));
	else
		log_message(LOG_INFO, "   VIP = %s, VPORT = %d"
				    , inet_sockaddrtos(&vsg_entry->addr)
				    , ntohs(inet_sockaddrport(&vsg_entry->addr)));
}
void
alloc_vsg(char *gname)
{
	size_t size = strlen(gname);
	virtual_server_group_t *new;

	new = (virtual_server_group_t *) MALLOC(sizeof(virtual_server_group_t));
	new->gname = (char *) MALLOC(size + 1);
	memcpy(new->gname, gname, size);
	new->addr_ip = alloc_list(free_vsg_entry, dump_vsg_entry);
	new->range = alloc_list(free_vsg_entry, dump_vsg_entry);
	new->vfwmark = alloc_list(free_vsg_entry, dump_vsg_entry);

	list_add(check_data->vs_group, new);
}
void
alloc_vsg_entry(vector_t *strvec)
{
	virtual_server_group_t *vsg = LIST_TAIL_DATA(check_data->vs_group);
	virtual_server_group_entry_t *new;
	uint32_t start;

	new = (virtual_server_group_entry_t *) MALLOC(sizeof(virtual_server_group_entry_t));

	if (!strcmp(strvec_slot(strvec, 0), "fwmark")) {
		new->vfwmark = (uint32_t)strtoul(strvec_slot(strvec, 1), NULL, 10);
		list_add(vsg->vfwmark, new);
	} else {
		new->range = inet_stor(strvec_slot(strvec, 0));
		inet_stosockaddr(strvec_slot(strvec, 0), strvec_slot(strvec, 1), &new->addr);
		if (!new->range) {
			list_add(vsg->addr_ip, new);
			return;
		}

		if ((new->addr.ss_family == AF_INET && new->range > 255 ) ||
		    (new->addr.ss_family == AF_INET6 && new->range > 0xffff)) {
			log_message(LOG_INFO, "End address of range exceeds limit for address family - %s - skipping", FMT_STR_VSLOT(strvec, 0));
			return;
		}

		if (new->addr.ss_family == AF_INET)
			start = htonl(((struct sockaddr_in *)&new->addr)->sin_addr.s_addr) & 0xFF;
		else
			start = htons(((struct sockaddr_in6 *)&new->addr)->sin6_addr.s6_addr16[7]);
		if (start >= new->range) {
			log_message(LOG_INFO, "Address range end is not greater than address range start - %s - skipping", FMT_STR_VSLOT(strvec, 0));
			return;
		}

		list_add(vsg->range, new);
	}
}

/* Virtual server facility functions */
static void
free_vs(void *data)
{
	virtual_server_t *vs = data;
	FREE_PTR(vs->vsgname);
	FREE_PTR(vs->virtualhost);
	FREE_PTR(vs->s_svr);
	free_list(&vs->rs);
	free_notify_script(&vs->quorum_up);
	free_notify_script(&vs->quorum_down);
	FREE(vs);
}
static void
dump_vs(void *data)
{
	virtual_server_t *vs = data;

	if (vs->vsgname)
		log_message(LOG_INFO, " VS GROUP = %s", vs->vsgname);
	else if (vs->vfwmark)
		log_message(LOG_INFO, " VS FWMARK = %u", vs->vfwmark);
	else
		log_message(LOG_INFO, " VIP = %s, VPORT = %d"
				    , inet_sockaddrtos(&vs->addr), ntohs(inet_sockaddrport(&vs->addr)));
	if (vs->virtualhost)
		log_message(LOG_INFO, "   VirtualHost = %s", vs->virtualhost);
	if (vs->af != AF_UNSPEC)
		log_message(LOG_INFO, "   Address family = inet%s", vs->af == AF_INET ? "" : "6");
	log_message(LOG_INFO, "   delay_loop = %lu, lb_algo = %s",
	       (vs->delay_loop >= TIMER_MAX_SEC) ? vs->delay_loop/TIMER_HZ :
						   vs->delay_loop,
	       vs->sched);
	log_message(LOG_INFO, "   Hashed = %sabled", vs->flags & IP_VS_SVC_F_HASHED ? "en" : "dis");
#ifdef IP_VS_SVC_F_SCHED1
	if (!strcmp(vs->sched, "sh"))
	{
		log_message(LOG_INFO, "   sh-port = %sabled", vs->flags & IP_VS_SVC_F_SCHED_SH_PORT ? "en" : "dis");
		log_message(LOG_INFO, "   sh-fallback = %sabled", vs->flags & IP_VS_SVC_F_SCHED_SH_FALLBACK ? "en" : "dis");
	}
	else
	{
		log_message(LOG_INFO, "   flag-1 = %sabled", vs->flags & IP_VS_SVC_F_SCHED1 ? "en" : "dis");
		log_message(LOG_INFO, "   flag-2 = %sabled", vs->flags & IP_VS_SVC_F_SCHED2 ? "en" : "dis");
		log_message(LOG_INFO, "   flag-3 = %sabled", vs->flags & IP_VS_SVC_F_SCHED3 ? "en" : "dis");
	}
#endif
#ifdef IP_VS_SVC_F_ONEPACKET
	log_message(LOG_INFO, "   One packet scheduling = %sabled%s",
			(vs->flags & IP_VS_SVC_F_ONEPACKET) ? "en" : "dis",
			((vs->flags & IP_VS_SVC_F_ONEPACKET) && vs->service_type != IPPROTO_UDP) ? " (inactive due to not UDP)" : "");
#endif

	if (vs->persistence_timeout)
		log_message(LOG_INFO, "   persistence timeout = %u", vs->persistence_timeout);
	if (vs->persistence_granularity) {
		if (vs->addr.ss_family == AF_INET6)
			log_message(LOG_INFO, "   persistence granularity = %d",
				       vs->persistence_granularity);
		else
			log_message(LOG_INFO, "   persistence granularity = %s",
				       inet_ntop2(vs->persistence_granularity));
	}
	if (vs->service_type == IPPROTO_TCP)
		log_message(LOG_INFO, "   protocol = TCP");
	else if (vs->service_type == IPPROTO_UDP)
		log_message(LOG_INFO, "   protocol = UDP");
	else if (vs->service_type == IPPROTO_SCTP)
		log_message(LOG_INFO, "   protocol = SCTP");
	else
		log_message(LOG_INFO, "   protocol = %d", vs->service_type);
	log_message(LOG_INFO, "   alpha is %s, omega is %s",
		    vs->alpha ? "ON" : "OFF", vs->omega ? "ON" : "OFF");
	log_message(LOG_INFO, "   quorum = %u, hysteresis = %u", vs->quorum, vs->hysteresis);
	if (vs->quorum_up)
		log_message(LOG_INFO, "   -> Notify script UP = %s, uid:gid %d:%d",
			    vs->quorum_up->name, vs->quorum_up->uid, vs->quorum_up->gid);
	if (vs->quorum_down)
		log_message(LOG_INFO, "   -> Notify script DOWN = %s, uid:gid %d:%d",
			    vs->quorum_down->name, vs->quorum_down->uid, vs->quorum_down->gid);
	if (vs->ha_suspend)
		log_message(LOG_INFO, "   Using HA suspend");

#ifdef _WITH_LVS_
	switch (vs->loadbalancing_kind) {
	case IP_VS_CONN_F_MASQ:
		log_message(LOG_INFO, "   lb_kind = NAT");
		break;
	case IP_VS_CONN_F_DROUTE:
		log_message(LOG_INFO, "   lb_kind = DR");
		break;
	case IP_VS_CONN_F_TUNNEL:
		log_message(LOG_INFO, "   lb_kind = TUN");
		break;
	}
#endif

	if (vs->s_svr) {
		log_message(LOG_INFO, "   sorry server = %s"
				    , FMT_RS(vs->s_svr));
	}
	if (!LIST_ISEMPTY(vs->rs))
		dump_list(vs->rs);
}

void
alloc_vs(char *ip, char *port)
{
	size_t size = strlen(port);
	virtual_server_t *new;

	new = (virtual_server_t *) MALLOC(sizeof(virtual_server_t));

	if (!strcmp(ip, "group")) {
		new->vsgname = (char *) MALLOC(size + 1);
		memcpy(new->vsgname, port, size);
	} else if (!strcmp(ip, "fwmark")) {
		new->vfwmark = (uint32_t)strtoul(port, NULL, 10);
	} else {
		inet_stosockaddr(ip, port, &new->addr);
		new->af = new->addr.ss_family;
	}

	new->delay_loop = KEEPALIVED_DEFAULT_DELAY;
	new->virtualhost = NULL;
	new->alpha = false;
	new->omega = false;
	new->quorum_up = NULL;
	new->quorum_down = NULL;
	new->quorum = 1;
	new->hysteresis = 0;
	new->quorum_state = UP;
	new->flags = 0;

	list_add(check_data->vs, new);
}

/* Sorry server facility functions */
void
alloc_ssvr(char *ip, char *port)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);

	vs->s_svr = (real_server_t *) MALLOC(sizeof(real_server_t));
	vs->s_svr->weight = 1;
	vs->s_svr->iweight = 1;
	inet_stosockaddr(ip, port, &vs->s_svr->addr);

	if (! vs->af)
		vs->af = vs->s_svr->addr.ss_family;
}

/* Real server facility functions */
static void
free_rs(void *data)
{
	real_server_t *rs = data;
	free_notify_script(&rs->notify_up);
	free_notify_script(&rs->notify_down);
	free_list(&rs->failed_checkers);
	FREE(rs);
}
static void
dump_rs(void *data)
{
	real_server_t *rs = data;

	log_message(LOG_INFO, "   RIP = %s, RPORT = %d, WEIGHT = %d"
			    , inet_sockaddrtos(&rs->addr)
			    , ntohs(inet_sockaddrport(&rs->addr))
			    , rs->weight);
	if (rs->inhibit)
		log_message(LOG_INFO, "     -> Inhibit service on failure");
	if (rs->notify_up)
		log_message(LOG_INFO, "     -> Notify script UP = %s, uid:gid %d:%d",
		       rs->notify_up->name, rs->notify_up->uid, rs->notify_up->gid);
	if (rs->notify_down)
		log_message(LOG_INFO, "     -> Notify script DOWN = %s, uid:gid %d:%d",
		       rs->notify_down->name, rs->notify_down->uid, rs->notify_down->gid);
}

static void
free_failed_checkers(void *data)
{
	FREE(data);
}

void
alloc_rs(char *ip, char *port)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *new;

	new = (real_server_t *) MALLOC(sizeof(real_server_t));
	inet_stosockaddr(ip, port, &new->addr);

	new->weight = 1;
	new->iweight = 1;
	new->failed_checkers = alloc_list(free_failed_checkers, NULL);

	if (!LIST_EXISTS(vs->rs))
		vs->rs = alloc_list(free_rs, dump_rs);
	list_add(vs->rs, new);

	if (! vs->af)
		vs->af = new->addr.ss_family;
}

/* data facility functions */
check_data_t *
alloc_check_data(void)
{
	check_data_t *new;

	new = (check_data_t *) MALLOC(sizeof(check_data_t));
	new->vs = alloc_list(free_vs, dump_vs);
	new->vs_group = alloc_list(free_vsg, dump_vsg);

	return new;
}

void
free_check_data(check_data_t *data)
{
	free_list(&data->vs);
	free_list(&data->vs_group);
	FREE(data);
}

void
dump_check_data(check_data_t *data)
{
	if (data->ssl) {
		log_message(LOG_INFO, "------< SSL definitions >------");
		dump_ssl();
	}
	if (!LIST_ISEMPTY(data->vs)) {
		log_message(LOG_INFO, "------< LVS Topology >------");
		log_message(LOG_INFO, " System is compiled with LVS v%d.%d.%d",
		       NVERSION(IP_VS_VERSION_CODE));
		if (!LIST_ISEMPTY(data->vs_group))
			dump_list(data->vs_group);
		dump_list(data->vs);
	}
	dump_checkers_queue();
}

char *
format_vs (virtual_server_t *vs)
{
	/* alloc large buffer because of unknown length of vs->vsgname */
	static char ret[512];

	if (vs->vsgname)
		snprintf (ret, sizeof (ret) - 1, "[%s]:%d"
			, vs->vsgname
			, ntohs(inet_sockaddrport(&vs->addr)));
	else if (vs->vfwmark)
		snprintf (ret, sizeof (ret) - 1, "FWM %u", vs->vfwmark);
	else
		snprintf(ret, sizeof(ret) - 1, "%s"
			, inet_sockaddrtopair(&vs->addr));

	return ret;
}

static void
check_check_script_security(void)
{
	element e, e1;
	virtual_server_t *vs;
	real_server_t *rs;
	int script_flags;

	if (LIST_ISEMPTY(check_data->vs))
		return;

	script_flags = check_misc_script_security();

	for (e = LIST_HEAD(check_data->vs); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);

		script_flags |= check_notify_script_secure(&vs->quorum_up, global_data->script_security, false);
		script_flags |= check_notify_script_secure(&vs->quorum_down, global_data->script_security, false);

		for (e1 = LIST_HEAD(vs->rs); e1; ELEMENT_NEXT(e1)) {
			rs = ELEMENT_DATA(e1);

			script_flags |= check_notify_script_secure(&rs->notify_up, global_data->script_security, false);
			script_flags |= check_notify_script_secure(&rs->notify_down, global_data->script_security, false);
		}
	}

	if (!global_data->script_security && script_flags & SC_ISSCRIPT) {
		log_message(LOG_INFO, "SECURITY VIOLATION - check scripts are being executed but script_security not enabled.%s",
				script_flags & SC_INSECURE ? " There are insecure scripts." : "");
	}
}

bool validate_check_config(void)
{
	element e;
	virtual_server_t *vs;

	/* Ensure that no virtual server hysteresis >= quorum */
	if (!LIST_ISEMPTY(check_data->vs)) {
		for (e = LIST_HEAD(check_data->vs); e; ELEMENT_NEXT(e)) {
			vs = ELEMENT_DATA(e);

			if (vs->hysteresis >= vs->quorum) {
				log_message(LOG_INFO, "Virtual server %s: hysteresis %u >= quorum %u; setting hysteresis to %u",
						vs->vsgname, vs->hysteresis, vs->quorum, vs->quorum -1);
				vs->hysteresis = vs->quorum - 1;
			}
		}
	}

	check_check_script_security();

	return true;
}
