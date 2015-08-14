/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        Configuration file parser/reader. Place into the dynamic
 *              data structure representation the conf file representing
 *              the loadbalanced server pool.
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

#include "check_parser.h"
#include "check_data.h"
#include "check_api.h"
#include "global_data.h"
#include "global_parser.h"
#include "logger.h"
#include "parser.h"
#include "memory.h"
#include "utils.h"
#include "ipwrapper.h"

/* SSL handlers */
static void
ssl_handler(vector_t *strvec)
{
	check_data->ssl = alloc_ssl();
}
static void
sslpass_handler(vector_t *strvec)
{
	check_data->ssl->password = set_value(strvec);
}
static void
sslca_handler(vector_t *strvec)
{
	check_data->ssl->cafile = set_value(strvec);
}
static void
sslcert_handler(vector_t *strvec)
{
	check_data->ssl->certfile = set_value(strvec);
}
static void
sslkey_handler(vector_t *strvec)
{
	check_data->ssl->keyfile = set_value(strvec);
}

/* Virtual Servers handlers */
static void
vsg_handler(vector_t *strvec)
{
	/* Fetch queued vsg */
	alloc_vsg(vector_slot(strvec, 1));
	alloc_value_block(strvec, alloc_vsg_entry);
}
static void
vs_handler(vector_t *strvec)
{
	alloc_vs(vector_slot(strvec, 1), vector_slot(strvec, 2));
}
static void
vs_end_handler(void)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	if (! vs->af)
		vs->af = AF_INET;
}
static void
ip_family_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	if (vs->af)
		return;
	if (0 == strcmp(vector_slot(strvec, 1), "inet"))
		vs->af = AF_INET;
	else if (0 == strcmp(vector_slot(strvec, 1), "inet6"))
		vs->af = AF_INET6;
}
static void
delay_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->delay_loop = atoi(vector_slot(strvec, 1)) * TIMER_HZ;
	if (vs->delay_loop < TIMER_HZ)
		vs->delay_loop = TIMER_HZ;
}
static void
lbalgo_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = vector_slot(strvec, 1);
	int size = sizeof (vs->sched);
	int str_len = strlen(str);

	if (size > str_len)
		size = str_len;

	memcpy(vs->sched, str, size);
}
static void
lbkind_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = vector_slot(strvec, 1);

	if (!strcmp(str, "NAT"))
		vs->loadbalancing_kind = IP_VS_CONN_F_MASQ;
	else if (!strcmp(str, "DR"))
		vs->loadbalancing_kind = IP_VS_CONN_F_DROUTE;
	else if (!strcmp(str, "TUN"))
		vs->loadbalancing_kind = IP_VS_CONN_F_TUNNEL;
	else
		log_message(LOG_INFO, "PARSER : unknown [%s] routing method.", str);
}
static void
natmask_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	inet_ston(vector_slot(strvec, 1), &vs->nat_mask);
}
static void
pto_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = vector_slot(strvec, 1);
	int size = sizeof (vs->timeout_persistence);
	int str_len = strlen(str);

	if (size > str_len)
		size = str_len;

	memcpy(vs->timeout_persistence, str, size);
}
static void
pgr_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	if (vs->addr.ss_family == AF_INET6)
		vs->granularity_persistence = atoi(vector_slot(strvec, 1));
	else
		inet_ston(vector_slot(strvec, 1), &vs->granularity_persistence);
}
static void
proto_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = vector_slot(strvec, 1);
	vs->service_type = (!strcmp(str, "TCP")) ? IPPROTO_TCP : IPPROTO_UDP;
}
static void
hasuspend_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->ha_suspend = 1;
}
static void
ops_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->ops = 1;
}
static void
virtualhost_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->virtualhost = set_value(strvec);
}

/* Sorry Servers handlers */
static void
ssvr_handler(vector_t *strvec)
{
	alloc_ssvr(vector_slot(strvec, 1), vector_slot(strvec, 2));
}
static void
ssvri_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	if (vs->s_svr) {
		vs->s_svr->inhibit = 1;
	} else {
		log_message(LOG_ERR, "Ignoring sorry_server_inhibit used before or without sorry_server");
	}
}

/* Real Servers handlers */
static void
rs_handler(vector_t *strvec)
{
	alloc_rs(vector_slot(strvec, 1), vector_slot(strvec, 2));
}
static void
weight_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->weight = atoi(vector_slot(strvec, 1));
	rs->iweight = rs->weight;
}
#ifdef _KRNL_2_6_
static void
uthreshold_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->u_threshold = atoi(vector_slot(strvec, 1));
}
static void
lthreshold_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->l_threshold = atoi(vector_slot(strvec, 1));
}
#endif
static void
inhibit_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->inhibit = 1;
}
static void
notify_up_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->notify_up = set_value(strvec);
}
static void
notify_down_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->notify_down = set_value(strvec);
}
static void
alpha_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->alpha = 1;
	vs->quorum_state = DOWN;
}
static void
omega_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->omega = 1;
}
static void
quorum_up_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->quorum_up = set_value(strvec);
}
static void
quorum_down_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->quorum_down = set_value(strvec);
}
static void
quorum_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	long tmp = atol (vector_slot(strvec, 1));
	if (tmp < 1) {
		log_message(LOG_ERR, "Condition not met: Quorum >= 1");
		log_message(LOG_ERR, "Ignoring requested value %s, using 1 instead",
		  (char *) vector_slot(strvec, 1));
		tmp = 1;
	}
	vs->quorum = tmp;
}
static void
hysteresis_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	long tmp = atol (vector_slot(strvec, 1));
	if (tmp < 0) {
		log_message(LOG_ERR, "Condition not met: 0 <= Hysteresis");
		log_message(LOG_ERR, "Ignoring requested value %s, using 0 instead",
		       (char *) vector_slot(strvec, 1));
		tmp = 0;
	}
	vs->hysteresis = tmp;
}

vector_t *
check_init_keywords(void)
{
	/* global definitions mapping */
	global_init_keywords();

	/* SSL mapping */
	install_keyword_root("SSL", &ssl_handler);
	install_keyword("password", &sslpass_handler);
	install_keyword("ca", &sslca_handler);
	install_keyword("certificate", &sslcert_handler);
	install_keyword("key", &sslkey_handler);

	/* Virtual server mapping */
	install_keyword_root("virtual_server_group", &vsg_handler);
	install_keyword_root("virtual_server", &vs_handler);
	install_keyword("ip_family", &ip_family_handler);
	install_keyword("delay_loop", &delay_handler);
	install_keyword("lb_algo", &lbalgo_handler);
	install_keyword("lvs_sched", &lbalgo_handler);
	install_keyword("lb_kind", &lbkind_handler);
	install_keyword("lvs_method", &lbkind_handler);
	install_keyword("nat_mask", &natmask_handler);
	install_keyword("persistence_timeout", &pto_handler);
	install_keyword("persistence_granularity", &pgr_handler);
	install_keyword("protocol", &proto_handler);
	install_keyword("ha_suspend", &hasuspend_handler);
	install_keyword("ops", &ops_handler);
	install_keyword("virtualhost", &virtualhost_handler);

	/* Pool regression detection and handling. */
	install_keyword("alpha", &alpha_handler);
	install_keyword("omega", &omega_handler);
	install_keyword("quorum_up", &quorum_up_handler);
	install_keyword("quorum_down", &quorum_down_handler);
	install_keyword("quorum", &quorum_handler);
	install_keyword("hysteresis", &hysteresis_handler);

	/* Real server mapping */
	install_keyword("sorry_server", &ssvr_handler);
	install_keyword("sorry_server_inhibit", &ssvri_handler);
	install_keyword("real_server", &rs_handler);
	install_sublevel();
	install_keyword("weight", &weight_handler);
#ifdef _KRNL_2_6_
	install_keyword("uthreshold", &uthreshold_handler);
	install_keyword("lthreshold", &lthreshold_handler);
#endif
	install_keyword("inhibit_on_failure", &inhibit_handler);
	install_keyword("notify_up", &notify_up_handler);
	install_keyword("notify_down", &notify_down_handler);

	install_sublevel_end_handler(&vs_end_handler);

	/* Checkers mapping */
	install_checkers_keyword();
	install_sublevel_end();

	return keywords;
}
