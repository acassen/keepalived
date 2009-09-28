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
 * Copyright (C) 2001-2009 Alexandre Cassen, <acassen@freebox.fr>
 */

#include "check_data.h"
#include "check_api.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "ipwrapper.h"

/* global vars */
check_conf_data *check_data = NULL;
check_conf_data *old_check_data = NULL;

/* SSL facility functions */
SSL_DATA *
alloc_ssl(void)
{
	SSL_DATA *ssl = (SSL_DATA *) MALLOC(sizeof (SSL_DATA));
	return ssl;
}
void
free_ssl(void)
{
	SSL_DATA *ssl = check_data->ssl;

	if (!ssl)
		return;
	FREE_PTR(ssl->password);
	FREE_PTR(ssl->cafile);
	FREE_PTR(ssl->certfile);
	FREE_PTR(ssl->keyfile);
	FREE(ssl);
}
static void
dump_ssl(void)
{
	SSL_DATA *ssl = check_data->ssl;

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
	virtual_server_group *vsg = data;
	FREE_PTR(vsg->gname);
	free_list(vsg->addr_ip);
	free_list(vsg->range);
	free_list(vsg->vfwmark);
	FREE(vsg);
}
static void
dump_vsg(void *data)
{
	virtual_server_group *vsg = data;

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
	virtual_server_group_entry *vsg_entry = data;

	if (vsg_entry->vfwmark)
		log_message(LOG_INFO, "   FWMARK = %d", vsg_entry->vfwmark);
	else if (vsg_entry->range)
		log_message(LOG_INFO, "   VIP Range = %s-%d, VPORT = %d"
		       , inet_ntop2(SVR_IP(vsg_entry))
		       , vsg_entry->range
		       , ntohs(SVR_PORT(vsg_entry)));
	else
		log_message(LOG_INFO, "   VIP = %s, VPORT = %d"
		       , inet_ntop2(SVR_IP(vsg_entry))
		       , ntohs(SVR_PORT(vsg_entry)));
}
void
alloc_vsg(char *gname)
{
	int size = strlen(gname);
	virtual_server_group *new;

	new = (virtual_server_group *) MALLOC(sizeof (virtual_server_group));
	new->gname = (char *) MALLOC(size + 1);
	memcpy(new->gname, gname, size);
	new->addr_ip = alloc_list(free_vsg_entry, dump_vsg_entry);
	new->range = alloc_list(free_vsg_entry, dump_vsg_entry);
	new->vfwmark = alloc_list(free_vsg_entry, dump_vsg_entry);

	list_add(check_data->vs_group, new);
}
void
alloc_vsg_entry(vector strvec)
{
	virtual_server_group *vsg = LIST_TAIL_DATA(check_data->vs_group);
	virtual_server_group_entry *new;

	new = (virtual_server_group_entry *) MALLOC(sizeof (virtual_server_group_entry));

	if (!strcmp(VECTOR_SLOT(strvec, 0), "fwmark")) {
		new->vfwmark = atoi(VECTOR_SLOT(strvec, 1));
		list_add(vsg->vfwmark, new);
	} else {
		inet_ston(VECTOR_SLOT(strvec, 0), &new->addr_ip);
		new->range = inet_stor(VECTOR_SLOT(strvec, 0));
		new->addr_port = htons(atoi(VECTOR_SLOT(strvec, 1)));
		if (!new->range)
			list_add(vsg->addr_ip, new);
		else
			list_add(vsg->range, new);
	}
}

/* Virtual server facility functions */
static void
free_vs(void *data)
{
	virtual_server *vs = data;
	FREE_PTR(vs->vsgname);
	FREE_PTR(vs->virtualhost);
	FREE_PTR(vs->s_svr);
	free_list(vs->rs);
	FREE_PTR(vs->quorum_up);
	FREE_PTR(vs->quorum_down);
	FREE(vs);
}
static void
dump_vs(void *data)
{
	virtual_server *vs = data;

	if (vs->vsgname)
		log_message(LOG_INFO, " VS GROUP = %s", vs->vsgname);
	else if (vs->vfwmark)
		log_message(LOG_INFO, " VS FWMARK = %d", vs->vfwmark);
	else
		log_message(LOG_INFO, " VIP = %s, VPORT = %d", inet_ntop2(SVR_IP(vs))
		       , ntohs(SVR_PORT(vs)));
	if (vs->virtualhost)
		log_message(LOG_INFO, "   VirtualHost = %s", vs->virtualhost);
	log_message(LOG_INFO, "   delay_loop = %lu, lb_algo = %s",
	       (vs->delay_loop >= TIMER_MAX_SEC) ? vs->delay_loop/TIMER_HZ :
						   vs->delay_loop,
	       vs->sched);
	if (atoi(vs->timeout_persistence) > 0)
		log_message(LOG_INFO, "   persistence timeout = %s",
		       vs->timeout_persistence);
	if (vs->granularity_persistence)
		log_message(LOG_INFO, "   persistence granularity = %s",
		       inet_ntop2(vs->granularity_persistence));
	log_message(LOG_INFO, "   protocol = %s",
	       (vs->service_type == IPPROTO_TCP) ? "TCP" : "UDP");
	log_message(LOG_INFO, "   alpha is %s, omega is %s",
		    vs->alpha ? "ON" : "OFF", vs->omega ? "ON" : "OFF");
	log_message(LOG_INFO, "   quorum = %lu, hysteresis = %lu", vs->quorum, vs->hysteresis);
	if (vs->quorum_up)
		log_message(LOG_INFO, "   -> Notify script UP = %s",
			    vs->quorum_up);
	if (vs->quorum_down)
		log_message(LOG_INFO, "   -> Notify script DOWN = %s",
			    vs->quorum_down);
	if (vs->ha_suspend)
		log_message(LOG_INFO, "   Using HA suspend");

	switch (vs->loadbalancing_kind) {
#ifdef _WITH_LVS_
#ifdef _KRNL_2_2_
	case 0:
		log_message(LOG_INFO, "   lb_kind = NAT");
		if (vs->nat_mask)
			log_message(LOG_INFO, "   nat mask = %s", inet_ntop2(vs->nat_mask));
		break;
	case IP_MASQ_F_VS_DROUTE:
		log_message(LOG_INFO, "   lb_kind = DR");
		break;
	case IP_MASQ_F_VS_TUNNEL:
		log_message(LOG_INFO, "   lb_kind = TUN");
		break;
#else
	case IP_VS_CONN_F_MASQ:
		log_message(LOG_INFO, "   lb_kind = NAT");
		break;
	case IP_VS_CONN_F_DROUTE:
		log_message(LOG_INFO, "   lb_kind = DR");
		break;
	case IP_VS_CONN_F_TUNNEL:
		log_message(LOG_INFO, "   lb_kind = TUN");
		break;
#endif
#endif
	}

	if (vs->s_svr) {
		log_message(LOG_INFO, "   sorry server = %s:%d",
		       inet_ntop2(SVR_IP(vs->s_svr))
		       , ntohs(SVR_PORT(vs->s_svr)));
	}
	if (!LIST_ISEMPTY(vs->rs))
		dump_list(vs->rs);
}

void
alloc_vs(char *ip, char *port)
{
	int size = strlen(port);
	virtual_server *new;

	new = (virtual_server *) MALLOC(sizeof (virtual_server));

	if (!strcmp(ip, "group")) {
		new->vsgname = (char *) MALLOC(size + 1);
		memcpy(new->vsgname, port, size);
	} else if (!strcmp(ip, "fwmark")) {
		new->vfwmark = atoi(port);
	} else {
		inet_ston(ip, &new->addr_ip);
		new->addr_port = htons(atoi(port));
	}
	new->delay_loop = KEEPALIVED_DEFAULT_DELAY;
	strncpy(new->timeout_persistence, "0", 1);
	new->virtualhost = NULL;
	new->alpha = 0;
	new->omega = 0;
	new->quorum_up = NULL;
	new->quorum_down = NULL;
	new->quorum = 1;
	new->hysteresis = 0;
	new->quorum_state = UP;

	list_add(check_data->vs, new);
}

/* Sorry server facility functions */
void
alloc_ssvr(char *ip, char *port)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);

	vs->s_svr = (real_server *) MALLOC(sizeof (real_server));
	vs->s_svr->weight = 1;
	inet_ston(ip, &vs->s_svr->addr_ip);
	vs->s_svr->addr_port = htons(atoi(port));
}

/* Real server facility functions */
static void
free_rs(void *data)
{
	real_server *rs = data;
	FREE_PTR(rs->notify_up);
	FREE_PTR(rs->notify_down);
	free_list(rs->failed_checkers);
	FREE(rs);
}
static void
dump_rs(void *data)
{
	real_server *rs = data;
	log_message(LOG_INFO, "   RIP = %s, RPORT = %d, WEIGHT = %d",
	       inet_ntop2(SVR_IP(rs))
	       , ntohs(SVR_PORT(rs))
	       , rs->weight);
	if (rs->inhibit)
		log_message(LOG_INFO, "     -> Inhibit service on failure");
	if (rs->notify_up)
		log_message(LOG_INFO, "     -> Notify script UP = %s",
		       rs->notify_up);
	if (rs->notify_down)
		log_message(LOG_INFO, "     -> Notify script DOWN = %s",
		       rs->notify_down);
}

static void
free_failed_checkers(void *data)
{
	FREE(data);
}

void
alloc_rs(char *ip, char *port)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	real_server *new;

	new = (real_server *) MALLOC(sizeof (real_server));

	inet_ston(ip, &new->addr_ip);
	new->addr_port = htons(atoi(port));
	new->weight = 1;
	new->failed_checkers = alloc_list(free_failed_checkers, NULL);

	if (LIST_ISEMPTY(vs->rs))
		vs->rs = alloc_list(free_rs, dump_rs);
	list_add(vs->rs, new);
}

/* data facility functions */
check_conf_data *
alloc_check_data(void)
{
	check_conf_data *new;

	new = (check_conf_data *) MALLOC(sizeof (check_conf_data));
	new->vs = alloc_list(free_vs, dump_vs);
	new->vs_group = alloc_list(free_vsg, dump_vsg);

	return new;
}

void
free_check_data(check_conf_data *check_data_obj)
{
	free_list(check_data_obj->vs);
	free_list(check_data_obj->vs_group);
	FREE(check_data_obj);
}

void
dump_check_data(check_conf_data *check_data_obj)
{
	if (check_data_obj->ssl) {
		log_message(LOG_INFO, "------< SSL definitions >------");
		dump_ssl();
	}
	if (!LIST_ISEMPTY(check_data_obj->vs)) {
		log_message(LOG_INFO, "------< LVS Topology >------");
		log_message(LOG_INFO, " System is compiled with LVS v%d.%d.%d",
		       NVERSION(IP_VS_VERSION_CODE));
		if (!LIST_ISEMPTY(check_data_obj->vs_group))
			dump_list(check_data_obj->vs_group);
		dump_list(check_data_obj->vs);
	}
	dump_checkers_queue();
}
