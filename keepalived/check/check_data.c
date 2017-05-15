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
#include <stdint.h>

#include "check_data.h"
#include "check_api.h"
#include "check_misc.h"
#include "check_daemon.h"
#include "global_data.h"
#include "check_ssl.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "ipwrapper.h"
#include "parser.h"

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
	ssl_data_t *ssl;
       
	if (!check_data)
		return;

	ssl = check_data->ssl;

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
	else if (vsg_entry->range) {
		if (vsg_entry->addr.ss_family == AF_INET)
			log_message(LOG_INFO, "   VIP Range = %s-%d, VPORT = %d"
					    , inet_sockaddrtos(&vsg_entry->addr)
					    , vsg_entry->range
					    , ntohs(inet_sockaddrport(&vsg_entry->addr)));
		else
			log_message(LOG_INFO, "   VIP Range = %s-%x, VPORT = %d"
					    , inet_sockaddrtos(&vsg_entry->addr)
					    , vsg_entry->range
					    , ntohs(inet_sockaddrport(&vsg_entry->addr)));
	}
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
	virtual_server_group_entry_t *old;
	uint32_t start;
	element e;

	new = (virtual_server_group_entry_t *) MALLOC(sizeof(virtual_server_group_entry_t));

	if (!strcmp(strvec_slot(strvec, 0), "fwmark")) {
		new->vfwmark = (uint32_t)strtoul(strvec_slot(strvec, 1), NULL, 10);
		list_add(vsg->vfwmark, new);
	} else {
		new->range = inet_stor(strvec_slot(strvec, 0));
		inet_stosockaddr(strvec_slot(strvec, 0), strvec_slot(strvec, 1), &new->addr);
#ifndef LIBIPVS_USE_NL
		if (new->addr.ss_family != AF_INET) {
			log_message(LOG_INFO, "IPVS does not support IPv6 in this build - skipping %s", FMT_STR_VSLOT(strvec, 0));
			FREE(new);
			return;
		}
#endif

		/* Ensure the address family matches any previously configured addresses */
		if (!LIST_ISEMPTY(vsg->addr_ip)) {
			e = LIST_HEAD(vsg->addr_ip);
			old = ELEMENT_DATA(e);
			if (old->addr.ss_family != new->addr.ss_family) {
				log_message(LOG_INFO, "Cannot mix IPv4 and IPv6 in virtual server group - %s", vsg->gname);
				FREE(new);
				return;
			}
		}
		if (!LIST_ISEMPTY(vsg->range)) {
			e = LIST_HEAD(vsg->range);
			old = ELEMENT_DATA(e);
			if (old->addr.ss_family != new->addr.ss_family) {
				log_message(LOG_INFO, "Cannot mix IPv4 and IPv6 in virtual server group -  %s", vsg->gname);
				FREE(new);
				return;
			}
		}
		if (!new->range) {
			list_add(vsg->addr_ip, new);
			return;
		}

		if ((new->addr.ss_family == AF_INET && new->range > 255) ||
		    (new->addr.ss_family == AF_INET6 && new->range > 0xffff)) {
			log_message(LOG_INFO, "End address of range exceeds limit for address family - %s - skipping", FMT_STR_VSLOT(strvec, 0));
			FREE(new);
			return;
		}

		if (new->addr.ss_family == AF_INET)
			start = htonl(((struct sockaddr_in *)&new->addr)->sin_addr.s_addr) & 0xFF;
		else
			start = htons(((struct sockaddr_in6 *)&new->addr)->sin6_addr.s6_addr16[7]);
		if (start >= new->range) {
			log_message(LOG_INFO, "Address range end is not greater than address range start - %s - skipping", FMT_STR_VSLOT(strvec, 0));
			FREE(new);
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
		log_message(LOG_INFO, " VS GROUP = %s", FMT_VS(vs));
	else if (vs->vfwmark)
		log_message(LOG_INFO, " VS FWMARK = %u", vs->vfwmark);
	else
		log_message(LOG_INFO, " VS VIP = %s, VPORT = %d"
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

	switch (vs->forwarding_method) {
	case IP_VS_CONN_F_MASQ:
		log_message(LOG_INFO, "   default forwarding method = NAT");
		break;
	case IP_VS_CONN_F_DROUTE:
		log_message(LOG_INFO, "   default forwarding method = DR");
		break;
	case IP_VS_CONN_F_TUNNEL:
		log_message(LOG_INFO, "   default forwarding method = TUN");
		break;
	}

	if (vs->s_svr) {
		log_message(LOG_INFO, "   sorry server = %s"
				    , FMT_RS(vs->s_svr));
	}
	if (!LIST_ISEMPTY(vs->rs))
		dump_list(vs->rs);
}

void
alloc_vs(char *param1, char *param2)
{
	size_t size;
	virtual_server_t *new;

	new = (virtual_server_t *) MALLOC(sizeof(virtual_server_t));

	if (!strcmp(param1, "group")) {
		size = strlen(param2);
		new->vsgname = (char *) MALLOC(size + 1);
		memcpy(new->vsgname, param2, size);
	} else if (!strcmp(param1, "fwmark")) {
		new->vfwmark = (uint32_t)strtoul(param2, NULL, 10);
	} else {
		inet_stosockaddr(param1, param2, &new->addr);
		new->af = new->addr.ss_family;
#ifndef LIBIPVS_USE_NL
		if (new->af != AF_INET) {
			log_message(LOG_INFO, "IPVS with IPv6 is not supported by this build");
			FREE(new);
			skip_block();
			return;
		}
#endif
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
	new->forwarding_method = IP_VS_CONN_F_FWD_MASK;		/* So we can detect if it has been set */

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

	if (!vs->af)
		vs->af = vs->s_svr->addr.ss_family;
	else if (vs->af != vs->s_svr->addr.ss_family) {
		log_message(LOG_INFO, "Address family of virtual server and sorry server %s don't match - skipping.", ip);
		FREE(vs->s_svr);
		vs->s_svr = NULL;
		return;
	}
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
	switch (rs->forwarding_method) {
	case IP_VS_CONN_F_MASQ:
		log_message(LOG_INFO, "   forwarding method = NAT");
		break;
	case IP_VS_CONN_F_DROUTE:
		log_message(LOG_INFO, "   forwarding method = DR");
		break;
	case IP_VS_CONN_F_TUNNEL:
		log_message(LOG_INFO, "   forwarding method = TUN");
		break;
	}
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

#ifndef LIBIPVS_USE_NL
	if (new->addr.ss_family != AF_INET) {
		log_message(LOG_INFO, "IPVS does not support IPv6 in this build - skipping %s", ip);
		skip_block();
		FREE(new);
		return;
	}
#endif

	if (!vs->af)
		vs->af = new->addr.ss_family;
	else if (vs->af != new->addr.ss_family) {
		log_message(LOG_INFO, "Address family of virtual server and real server %s don't match - skipping.", ip);
		FREE(new);
		return;
	}

	new->weight = 1;
	new->iweight = 1;
	new->failed_checkers = alloc_list(free_failed_checkers, NULL);
	new->forwarding_method = vs->forwarding_method;

	if (!LIST_EXISTS(vs->rs))
		vs->rs = alloc_list(free_rs, dump_rs);
	list_add(vs->rs, new);
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
	element e, e1;
	virtual_server_t *vs;
	real_server_t *rs;
	checker_t *checker;
	element next;

	using_ha_suspend = false;
	if (!LIST_ISEMPTY(check_data->vs)) {
		for (e = LIST_HEAD(check_data->vs); e; e = next) {
			next = e->next;

			vs = ELEMENT_DATA(e);

			if (!vs->rs || LIST_ISEMPTY(vs->rs)) {
				log_message(LOG_INFO, "Virtual server %s has no real servers - ignoring", FMT_VS(vs));
				free_list_element(check_data->vs, e);
				continue;
			}

			/* Ensure that no virtual server hysteresis >= quorum */
			if (vs->hysteresis >= vs->quorum) {
				log_message(LOG_INFO, "Virtual server %s: hysteresis %u >= quorum %u; setting hysteresis to %u",
						FMT_VS(vs), vs->hysteresis, vs->quorum, vs->quorum -1);
				vs->hysteresis = vs->quorum - 1;
			}

			/* Ensure that ha_suspend is not set for any virtual server using fwmarks */
			if (vs->ha_suspend &&
			    (vs->vfwmark || (vs->vsg && !LIST_ISEMPTY(vs->vsg->vfwmark)))) {
				log_message(LOG_INFO, "Virtual server %s: cannot use ha_suspend with fwmarks - clearing ha_suspend", FMT_VS(vs));
				vs->ha_suspend = false;
			}

			if (vs->ha_suspend)
				using_ha_suspend = true;

			/* Check protocol set */
			if (!vs->service_type &&
			    ((vs->vsg && (!LIST_ISEMPTY(vs->vsg->addr_ip) || !LIST_ISEMPTY(vs->vsg->range))) ||
			     (!vs->vsg && !vs->vfwmark))) {
				/* If the protocol is 0, the kernel defaults to UDP, so set it explicitly */
				log_message(LOG_INFO, "Virtual server %s: no protocol set - defaulting to UDP", FMT_VS(vs));
				vs->service_type = IPPROTO_UDP;
			}

#ifdef IP_VS_SVC_F_ONEPACKET
			/* Check OPS not set for TCP or SCTP */
			if (vs->flags & IP_VS_SVC_F_ONEPACKET &&
			    vs->service_type != IPPROTO_UDP &&
			    ((vs->vsg && (!LIST_ISEMPTY(vs->vsg->addr_ip) || !LIST_ISEMPTY(vs->vsg->range))) ||
			     (!vs->vsg && !vs->vfwmark))) {
				/* OPS is only valid for UDP, or with a firewall mark */
				log_message(LOG_INFO, "Virtual server %s: one packet scheduling requires UDP - resetting", FMT_VS(vs));
				vs->flags &= ~IP_VS_SVC_F_ONEPACKET;
			}
#endif

			/* Check port specified for udp/tcp/sctp unless persistent */
			if (!(vs->persistence_timeout || vs->persistence_granularity) &&
			    ((!vs->vsg && !vs->vfwmark) ||
			     (vs->vsg && (!LIST_ISEMPTY(vs->vsg->addr_ip) || !LIST_ISEMPTY(vs->vsg->range)))) &&
			    ((vs->addr.ss_family == AF_INET6 && !((struct sockaddr_in6 *)&vs->addr)->sin6_port) ||
			     (vs->addr.ss_family == AF_INET && !((struct sockaddr_in *)&vs->addr)->sin_port))) {
				log_message(LOG_INFO, "Virtual server %s: zero port only valid for persistent sevices - setting", FMT_VS(vs));
				vs->persistence_timeout = IPVS_SVC_PERSISTENT_TIMEOUT;
			}

			/* Check scheduler set */
			if (!vs->sched[0]) {
				log_message(LOG_INFO, "Virtual server %s: no scheduler set, setting default '%s'", FMT_VS(vs), IPVS_DEF_SCHED);
				strcpy(vs->sched, IPVS_DEF_SCHED);
			}


			/* Spin through all the real servers */
			for (e1 = LIST_HEAD(vs->rs); e1; ELEMENT_NEXT(e1)) {
				rs = ELEMENT_DATA(e1);

				/* Check any real server in alpha mode has a checker */
				if (vs->alpha && !rs->alive && LIST_ISEMPTY(rs->failed_checkers))
					log_message(LOG_INFO, "Warning - real server %s for virtual server %s cannot be activated due to no checker and in alpha mode",
							FMT_RS(rs), FMT_VS(vs));

				/* Set the forwarding method if necessary */
				if (rs->forwarding_method == IP_VS_CONN_F_FWD_MASK) {
					if (vs->forwarding_method == IP_VS_CONN_F_FWD_MASK) {
						log_message(LOG_INFO, "Virtual server %s: no forwarding method set, setting default NAT", FMT_VS(vs));
						vs->forwarding_method = IP_VS_CONN_F_MASQ;
					}
					rs->forwarding_method = vs->forwarding_method;
				}
			}
		}
	}

	/* Ensure any checkers that don't have ha_suspend set are enabled */
	if (!LIST_ISEMPTY(checkers_queue)) {
		for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
			checker = ELEMENT_DATA(e);

			if (!checker->vs->ha_suspend)
				checker->enabled = true;
		}
	}

	check_check_script_security();

	return true;
}
