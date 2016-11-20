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

#include "config.h"

#include <errno.h>

#include "check_parser.h"
#include "check_data.h"
#include "check_api.h"
#include "global_data.h"
#include "global_parser.h"
#include "main.h"
#include "logger.h"
#include "parser.h"
#include "memory.h"
#include "utils.h"
#include "ipwrapper.h"
#if defined _WITH_VRRP_
#include "vrrp_parser.h"
#endif

/* SSL handlers */
static void
ssl_handler(__attribute__((unused)) vector_t *strvec)
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
	alloc_vsg(strvec_slot(strvec, 1));
	alloc_value_block(alloc_vsg_entry);
}
static void
vs_handler(vector_t *strvec)
{
	alloc_vs(strvec_slot(strvec, 1), strvec_slot(strvec, 2));
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
	if (0 == strcmp(strvec_slot(strvec, 1), "inet"))
		vs->af = AF_INET;
	else if (0 == strcmp(strvec_slot(strvec, 1), "inet6"))
		vs->af = AF_INET6;
	else
		log_message(LOG_INFO, "unknown address family %s", FMT_STR_VSLOT(strvec, 1));
}
static void
delay_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->delay_loop = strtoul(strvec_slot(strvec, 1), NULL, 10) * TIMER_HZ;
	if (vs->delay_loop < TIMER_HZ)
		vs->delay_loop = TIMER_HZ;
}
static void
lbalgo_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = strvec_slot(strvec, 1);
	size_t size = sizeof (vs->sched);
	size_t str_len = strlen(str);

	if (size > str_len)
		size = str_len;

	memcpy(vs->sched, str, size);
}

static void
lbflags_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = strvec_slot(strvec, 0);

	if (!strcmp(str, "hashed"))
		vs->flags |= IP_VS_SVC_F_HASHED;
#ifdef IP_VS_SVC_F_ONEPACKET
	else if (!strcmp(str, "ops"))
		vs->flags |= IP_VS_SVC_F_ONEPACKET;
#endif
#ifdef IP_VS_SVC_F_SCHED1		/* From Linux 3.11 */
	else if (!strcmp(str, "flag-1"))
		vs->flags |= IP_VS_SVC_F_SCHED1;
	else if (!strcmp(str, "flag-2"))
		vs->flags |= IP_VS_SVC_F_SCHED2;
	else if (!strcmp(str, "flag-3"))
		vs->flags |= IP_VS_SVC_F_SCHED3;
	else if (!strcmp(vs->sched , "sh") )
	{
		/* sh-port and sh-fallback flags are relevant for sh scheduler only */
		if (!strcmp(str, "sh-port")  )
			vs->flags |= IP_VS_SVC_F_SCHED_SH_PORT;
		if (!strcmp(str, "sh-fallback"))
			vs->flags |= IP_VS_SVC_F_SCHED_SH_FALLBACK;
	}
	else
		log_message(LOG_INFO, "%s only applies to sh scheduler - ignoring", str);
#endif
}

static void
lbkind_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = strvec_slot(strvec, 1);

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
pto_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *endptr;
	unsigned long timeout;

	if (vector_size(strvec) < 2) {
		vs->persistence_timeout = IPVS_SVC_PERSISTENT_TIMEOUT;
		return;
	}

	errno = 0;
	timeout = strtoul(strvec_slot(strvec, 1), &endptr, 10);
	if (errno || *endptr || timeout > UINT32_MAX || timeout == 0) {
		log_message(LOG_INFO, "persistent_timeout invalid");
		return;
	}

	vs->persistence_timeout = (uint32_t)timeout;
}
#ifdef _HAVE_PE_NAME_
static void
pengine_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = strvec_slot(strvec, 1);
	size_t size = sizeof (vs->pe_name);

	strncpy(vs->pe_name, str, size - 1);
	vs->pe_name[size - 1] = '\0';
}
#endif
static void
pgr_handler(vector_t *strvec)
{
	struct in_addr addr;

	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	if (vs->addr.ss_family == AF_INET6)
		vs->persistence_granularity = (uint32_t)strtoul(strvec_slot(strvec, 1), NULL, 10);
	else {
		if (inet_aton(strvec_slot(strvec, 1), &addr)) {
			log_message(LOG_INFO, "Invalid persistence_timeout specified - %s", FMT_STR_VSLOT(strvec, 1));
			return;
		}
		vs->persistence_granularity = addr.s_addr;
	}

	if (!vs->persistence_timeout)
		vs->persistence_timeout = IPVS_SVC_PERSISTENT_TIMEOUT;
}
static void
proto_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = strvec_slot(strvec, 1);
	if (!strcmp(str, "TCP"))
		vs->service_type = IPPROTO_TCP;
	else if (!strcmp(str, "SCTP"))
		vs->service_type = IPPROTO_SCTP;
	else if (!strcmp(str, "UDP"))
		vs->service_type = IPPROTO_UDP;
	else
		log_message(LOG_INFO, "Unknown protocol %s - ignoring", str);
}
static void
hasuspend_handler(__attribute__((unused)) vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->ha_suspend = 1;
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
	alloc_ssvr(strvec_slot(strvec, 1), strvec_slot(strvec, 2));
}
static void
ssvri_handler(__attribute__((unused)) vector_t *strvec)
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
	alloc_rs(strvec_slot(strvec, 1), strvec_slot(strvec, 2));
}
static void
weight_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->weight = atoi(strvec_slot(strvec, 1));
	rs->iweight = rs->weight;
}
static void
uthreshold_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->u_threshold = (uint32_t)strtoul(strvec_slot(strvec, 1), NULL, 10);
}
static void
lthreshold_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->l_threshold = (uint32_t)strtoul(strvec_slot(strvec, 1), NULL, 10);
}
static void
inhibit_handler(__attribute__((unused)) vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->inhibit = 1;
}
static inline notify_script_t*
set_check_notify_script(vector_t *strvec)
{
	notify_script_t *script = notify_script_init(strvec, default_script_uid, default_script_gid);

	if (vector_size(strvec) > 2 ) {
		if (set_script_uid_gid(strvec, 2, &script->uid, &script->gid))
			log_message(LOG_INFO, "Invalid user/group for quorum/notify script %s", script->name);
	}

	return script;
}
static void
notify_up_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->notify_up = set_check_notify_script(strvec);
}
static void
notify_down_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->notify_down = set_check_notify_script(strvec);
}
static void
alpha_handler(__attribute__((unused)) vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->alpha = true;
	vs->quorum_state = DOWN;
}
static void
omega_handler(__attribute__((unused)) vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->omega = true;
}
static void
quorum_up_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->quorum_up = set_check_notify_script(strvec);
}
static void
quorum_down_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->quorum_down = set_check_notify_script(strvec);
}
static void
quorum_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->quorum = (unsigned)strtoul(strvec_slot(strvec, 1), NULL, 10);
	if (vs->quorum < 1) {
		log_message(LOG_ERR, "Condition not met: Quorum >= 1");
		log_message(LOG_ERR, "Ignoring requested value %s, using 1 instead",
		  FMT_STR_VSLOT(strvec, 1));
		vs->quorum = 1;
	}
}
static void
hysteresis_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);

	vs->hysteresis = (unsigned)strtoul(strvec_slot(strvec, 1), NULL, 10);
}

void
init_check_keywords(bool active)
{
	/* SSL mapping */
	install_keyword_root("SSL", &ssl_handler, active);
	install_keyword("password", &sslpass_handler);
	install_keyword("ca", &sslca_handler);
	install_keyword("certificate", &sslcert_handler);
	install_keyword("key", &sslkey_handler);

	/* Virtual server mapping */
	install_keyword_root("virtual_server_group", &vsg_handler, active);
	install_keyword_root("virtual_server", &vs_handler, active);
	install_keyword("ip_family", &ip_family_handler);
	install_keyword("delay_loop", &delay_handler);
	install_keyword("lb_algo", &lbalgo_handler);
	install_keyword("lvs_sched", &lbalgo_handler);

	install_keyword("hashed", &lbflags_handler);
#ifdef IP_VS_SVC_F_ONEPACKET
	install_keyword("ops", &lbflags_handler);
#endif
#ifdef IP_VS_SVC_F_SCHED1
	install_keyword("flag-1", &lbflags_handler);
	install_keyword("flag-2", &lbflags_handler);
	install_keyword("flag-3", &lbflags_handler);
	install_keyword("sh-port", &lbflags_handler);
	install_keyword("sh-fallback", &lbflags_handler);
#endif
	install_keyword("lb_kind", &lbkind_handler);
	install_keyword("lvs_method", &lbkind_handler);
#ifdef _HAVE_PE_NAME_
	install_keyword("persistence_engine", &pengine_handler);
#endif
	install_keyword("persistence_timeout", &pto_handler);
	install_keyword("persistence_granularity", &pgr_handler);
	install_keyword("protocol", &proto_handler);
	install_keyword("ha_suspend", &hasuspend_handler);
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
	install_keyword("uthreshold", &uthreshold_handler);
	install_keyword("lthreshold", &lthreshold_handler);
	install_keyword("inhibit_on_failure", &inhibit_handler);
	install_keyword("notify_up", &notify_up_handler);
	install_keyword("notify_down", &notify_down_handler);

	install_sublevel_end_handler(&vs_end_handler);

	/* Checkers mapping */
	install_checkers_keyword();
	install_sublevel_end();
}

vector_t *
check_init_keywords(void)
{
	/* global definitions mapping */
	init_global_keywords(true);

	init_check_keywords(true);
#ifdef _WITH_VRRP_
	init_vrrp_keywords(false);
#endif
	return keywords;
}
