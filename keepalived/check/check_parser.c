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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <errno.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "check_parser.h"
#include "check_data.h"
#include "check_api.h"
#include "global_data.h"
#include "global_parser.h"
#include "main.h"
#include "logger.h"
#include "parser.h"
#include "utils.h"
#include "ipwrapper.h"
#if defined _WITH_VRRP_
#include "vrrp_parser.h"
#endif
#if defined _WITH_BFD_
#include "bfd_parser.h"
#endif
#include "libipvs.h"

/* List of valid schedulers */
char *lvs_schedulers[] =
	{"rr", "wrr", "lc", "wlc", "lblc", "sh", "mh", "dh", "fo", "ovf", "lblcr", "sed", "nq", NULL};

/* SSL handlers */
static void
ssl_handler(vector_t *strvec)
{
	if (!strvec)
		return;

	if (check_data->ssl) {
		free_ssl();
		report_config_error(CONFIG_GENERAL_ERROR, "SSL context already specified - replacing");
	}
	check_data->ssl = alloc_ssl();
}
static void
sslpass_handler(vector_t *strvec)
{
	if (check_data->ssl->password) {
		report_config_error(CONFIG_GENERAL_ERROR, "SSL password already specified - replacing");
		FREE(check_data->ssl->password);
	}
	check_data->ssl->password = set_value(strvec);
}
static void
sslca_handler(vector_t *strvec)
{
	if (check_data->ssl->cafile) {
		report_config_error(CONFIG_GENERAL_ERROR, "SSL cafile already specified - replacing");
		FREE(check_data->ssl->cafile);
	}
	check_data->ssl->cafile = set_value(strvec);
}
static void
sslcert_handler(vector_t *strvec)
{
	if (check_data->ssl->certfile) {
		report_config_error(CONFIG_GENERAL_ERROR, "SSL certfile already specified - replacing");
		FREE(check_data->ssl->certfile);
	}
	check_data->ssl->certfile = set_value(strvec);
}
static void
sslkey_handler(vector_t *strvec)
{
	if (check_data->ssl->keyfile) {
		report_config_error(CONFIG_GENERAL_ERROR, "SSL keyfile already specified - replacing");
		FREE(check_data->ssl->keyfile);
	}
	check_data->ssl->keyfile = set_value(strvec);
}

/* Virtual Servers handlers */
static void
vsg_handler(vector_t *strvec)
{
	virtual_server_group_t *vsg;

	if (!strvec)
		return;

	/* Fetch queued vsg */
	alloc_vsg(strvec_slot(strvec, 1));
	alloc_value_block(alloc_vsg_entry, strvec_slot(strvec, 0));

	/* Ensure the virtual server group has some configuration */
	vsg = LIST_TAIL_DATA(check_data->vs_group);
	if (LIST_ISEMPTY(vsg->vfwmark) && LIST_ISEMPTY(vsg->addr_range)) {
		report_config_error(CONFIG_GENERAL_ERROR, "virtual server group %s has no entries - removing", vsg->gname);
		free_list_element(check_data->vs_group, check_data->vs_group->tail);
	}
}
static void
vs_handler(vector_t *strvec)
{
	global_data->have_checker_config = true;

	/* If we are not in the checker process, we don't want any more info */
	if (!strvec)
		return;

	alloc_vs(strvec_slot(strvec, 1), vector_size(strvec) >= 3 ? strvec_slot(strvec, 2) : NULL);
}
static void
vs_end_handler(void)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs;
	element e;

	/* If the real (sorry) server uses tunnel forwarding, the address family
	 * does not have to match the address family of the virtual server */
	if (vs->s_svr
#if HAVE_DECL_IPVS_DEST_ATTR_ADDR_FAMILY
		      && vs->s_svr->forwarding_method != IP_VS_CONN_F_TUNNEL
#endif
									    )
	{
		if (vs->af == AF_UNSPEC)
			vs->af = vs->s_svr->addr.ss_family;
		else if (vs->af != vs->s_svr->addr.ss_family) {
			report_config_error(CONFIG_GENERAL_ERROR, "Address family of virtual server and sorry server %s don't match - skipping sorry server.", inet_sockaddrtos(&vs->s_svr->addr));
			FREE(vs->s_svr);
			vs->s_svr = NULL;
		}
	}

	if (vs->af == AF_UNSPEC) {
		/* This only occurs if the virtual server uses a fwmark, and all the
		 * real/sorry servers are tunnelled.
		 *
		 * Maintain backward compatibility. Prior to the commit following 17fa4a3c
		 * the address family of the virtual server was set from any of its
		 * real or sorry servers, even if they were tunnelled. However, all the real
		 * and sorry servers had to be the same address family, even if tunnelled,
		 * so only set the address family from the tunnelled real/sorry servers
		 * if all the real/sorry servers are of the same address family. */
		if (vs->s_svr)
			vs->af = vs->s_svr->addr.ss_family;

		if (!LIST_ISEMPTY(vs->rs)) {
			for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
				rs = ELEMENT_DATA(e);
				if (vs->af == AF_UNSPEC)
					vs->af = rs->addr.ss_family;
				else if (vs->af != rs->addr.ss_family) {
					vs->af = AF_UNSPEC;
					break;
				}
			}
		}

		if (vs->af == AF_UNSPEC) {
			/* We have a mixture of IPv4 and IPv6 tunnelled real/sorry servers.
			 * Default to IPv4. */
			vs->af = AF_INET;
		}
	}
}
static void
ip_family_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	uint16_t af;

	if (!strcmp(strvec_slot(strvec, 1), "inet"))
		af = AF_INET;
	else if (!strcmp(strvec_slot(strvec, 1), "inet6")) {
#ifndef LIBIPVS_USE_NL
		report_config_error(CONFIG_GENERAL_ERROR, "IPVS with IPv6 is not supported by this build");
		skip_block(false);
		return;
#endif
		af = AF_INET6;
	}
	else {
		report_config_error(CONFIG_GENERAL_ERROR, "unknown address family %s", FMT_STR_VSLOT(strvec, 1));
		return;
	}

	if (vs->af != AF_UNSPEC &&
	    af != vs->af) {
		report_config_error(CONFIG_GENERAL_ERROR, "Virtual server specified family %s conflicts with server family", FMT_STR_VSLOT(strvec, 1));
		return;
	}

	vs->af = af;
}
static void
vs_delay_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	unsigned long delay;

	if (read_timer(strvec, 1, &delay, 1, 0, true))
		vs->delay_loop = delay;
	else
		report_config_error(CONFIG_GENERAL_ERROR, "virtual server delay loop '%s' invalid - ignoring", FMT_STR_VSLOT(strvec, 1));
}
static void
vs_delay_before_retry_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	unsigned long delay;

	if (read_timer(strvec, 1, &delay, 0, 0, true))
		vs->delay_before_retry = delay;
	else
		report_config_error(CONFIG_GENERAL_ERROR, "virtual server delay before retry '%s' invalid - ignoring", FMT_STR_VSLOT(strvec, 1));
}
static void
vs_retry_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	unsigned retry;

	if (!read_unsigned_strvec(strvec, 1, &retry, 1, UINT32_MAX, false)) {
		report_config_error(CONFIG_GENERAL_ERROR, "retry value invalid - %s", FMT_STR_VSLOT(strvec, 1));
		return;
	}
	vs->retry = retry;
}
static void
vs_warmup_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	unsigned long delay;

	if (read_timer(strvec, 1, &delay, 0, 0, true))
		vs->warmup = delay;
	else
		report_config_error(CONFIG_GENERAL_ERROR, "virtual server warmup '%s' invalid - ignoring", FMT_STR_VSLOT(strvec, 1));
}
static void
lbalgo_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = strvec_slot(strvec, 1);
	int i;

	/* Check valid scheduler name */
	for (i = 0; lvs_schedulers[i] && strcmp(str, lvs_schedulers[i]); i++);

	if (!lvs_schedulers[i] || strlen(str) >= sizeof(vs->sched)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid lvs_scheduler '%s' - ignoring", FMT_STR_VSLOT(strvec, 1));
		return;
	}

	strcpy(vs->sched, str);
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
	else if (!strcmp(vs->sched , "mh") )
	{
		/* mh-port and mh-fallback flags are relevant for mh scheduler only */
		if (!strcmp(str, "mh-port")  )
			vs->flags |= IP_VS_SVC_F_SCHED_MH_PORT;
		if (!strcmp(str, "mh-fallback"))
			vs->flags |= IP_VS_SVC_F_SCHED_MH_FALLBACK;
	}
	else
		report_config_error(CONFIG_GENERAL_ERROR, "%s only applies to sh scheduler - ignoring", str);
#endif
}

static void
forwarding_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = strvec_slot(strvec, 1);

	if (!strcmp(str, "NAT"))
		vs->forwarding_method = IP_VS_CONN_F_MASQ;
	else if (!strcmp(str, "DR"))
		vs->forwarding_method = IP_VS_CONN_F_DROUTE;
	else if (!strcmp(str, "TUN"))
		vs->forwarding_method = IP_VS_CONN_F_TUNNEL;
	else
		report_config_error(CONFIG_GENERAL_ERROR, "PARSER : unknown [%s] routing method.", str);
}
static void
pto_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	unsigned timeout;

	if (vector_size(strvec) < 2) {
		vs->persistence_timeout = IPVS_SVC_PERSISTENT_TIMEOUT;
		return;
	}

	if (!read_unsigned_strvec(strvec, 1, &timeout, 1, UINT32_MAX, false)) {
		report_config_error(CONFIG_GENERAL_ERROR, "persistence_timeout invalid");
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
	uint16_t af = vs->af;
	unsigned granularity;

	if (af == AF_UNSPEC)
		af = strchr(strvec_slot(strvec, 1), '.') ? AF_INET : AF_INET6;

	if (af == AF_INET6) {
		if (!read_unsigned_strvec(strvec, 1, &granularity, 1, 128, false)) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid IPv6 persistence_granularity specified - %s", FMT_STR_VSLOT(strvec, 1));
			return;
		}
		vs->persistence_granularity = granularity;
	} else {
		if (!inet_aton(strvec_slot(strvec, 1), &addr)) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid IPv4 persistence_granularity specified - %s", FMT_STR_VSLOT(strvec, 1));
			return;
		}

		/* Ensure the netmask is solid */
		uint32_t haddr = ntohl(addr.s_addr);
		while (!(haddr & 1))
			haddr = (haddr >> 1) | 0x80000000;
		if (haddr != 0xffffffff) {
			report_config_error(CONFIG_GENERAL_ERROR, "IPv4 persistence_granularity netmask is not solid - %s", FMT_STR_VSLOT(strvec, 1));
			return;
		}

		vs->persistence_granularity = addr.s_addr;
	}

	if (vs->af == AF_UNSPEC)
		vs->af = af;

	if (!vs->persistence_timeout)
		vs->persistence_timeout = IPVS_SVC_PERSISTENT_TIMEOUT;
}
static void
proto_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = strvec_slot(strvec, 1);

	if (!strcasecmp(str, "TCP"))
		vs->service_type = IPPROTO_TCP;
	else if (!strcasecmp(str, "SCTP"))
		vs->service_type = IPPROTO_SCTP;
	else if (!strcasecmp(str, "UDP"))
		vs->service_type = IPPROTO_UDP;
	else
		report_config_error(CONFIG_GENERAL_ERROR, "Unknown protocol %s - ignoring", str);
}
static void
hasuspend_handler(__attribute__((unused)) vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->ha_suspend = true;
}

static void
vs_smtp_alert_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res == -1) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid virtual_server smtp_alert parameter %s", FMT_STR_VSLOT(strvec, 1));
			return;
		}
	}
	vs->smtp_alert = res;
}

static void
vs_virtualhost_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->virtualhost = set_value(strvec);
}

static void
svr_forwarding_handler(real_server_t *rs, vector_t *strvec)
{
	char *str = strvec_slot(strvec, 1);

	if (!strcmp(str, "NAT"))
		rs->forwarding_method = IP_VS_CONN_F_MASQ;
	else if (!strcmp(str, "DR"))
		rs->forwarding_method = IP_VS_CONN_F_DROUTE;
	else if (!strcmp(str, "TUN"))
		rs->forwarding_method = IP_VS_CONN_F_TUNNEL;
	else
		report_config_error(CONFIG_GENERAL_ERROR, "PARSER : unknown [%s] routing method for real server.", str);
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
	if (vs->s_svr)
		vs->s_svr->inhibit = true;
	else
		report_config_error(CONFIG_GENERAL_ERROR, "Ignoring sorry_server inhibit used before or without sorry_server");
}
static void
ss_forwarding_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);

	if (vs->s_svr)
		svr_forwarding_handler(vs->s_svr, strvec);
	else
		report_config_error(CONFIG_GENERAL_ERROR, "sorry_server forwarding used without sorry_server");
}

/* Real Servers handlers */
static void
rs_handler(vector_t *strvec)
{
	alloc_rs(strvec_slot(strvec, 1), strvec_slot(strvec, 2));
}
static void
rs_end_handler(void)
{
	virtual_server_t *vs;
	real_server_t *rs;

	if (LIST_ISEMPTY(check_data->vs))
		return;

	vs = LIST_TAIL_DATA(check_data->vs);

	if (LIST_ISEMPTY(vs->rs))
		return;

	rs = LIST_TAIL_DATA(vs->rs);

	/* For tunnelled forwarding, the address families don't have to be the same, so
	 * long as the kernel supports IPVS_DEST_ATTR_ADDR_FAMILY */
#if HAVE_DECL_IPVS_DEST_ATTR_ADDR_FAMILY
	if (rs->forwarding_method != IP_VS_CONN_F_TUNNEL)
#endif
	{
		if (vs->af == AF_UNSPEC)
			vs->af = rs->addr.ss_family;
		else if (vs->af != rs->addr.ss_family) {
			report_config_error(CONFIG_GENERAL_ERROR, "Address family of virtual server and real server %s don't match - skipping real server.", inet_sockaddrtos(&rs->addr));
			free_list_element(vs->rs, vs->rs->tail);
		}
	}
}
static void
rs_weight_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	unsigned weight;

	if (!read_unsigned_strvec(strvec, 1, &weight, 1, 65535, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Real server weight %s is outside range 1-65535", FMT_STR_VSLOT(strvec, 1));
		return;
	}
	rs->weight = weight;
	rs->iweight = weight;
}
static void
rs_forwarding_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);

	svr_forwarding_handler(rs, strvec);
}
static void
uthreshold_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	unsigned threshold;

	if (!read_unsigned_strvec(strvec, 1, &threshold, 0, UINT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid real_server uthreshold '%s' - ignoring", FMT_STR_VSLOT(strvec, 1));
		return;
	}
	rs->u_threshold = threshold;
}
static void
lthreshold_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	unsigned threshold;

	if (!read_unsigned_strvec(strvec, 1, &threshold, 0, UINT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid real_server lthreshold '%s' - ignoring", FMT_STR_VSLOT(strvec, 1));
		return;
	}
	rs->l_threshold = threshold;
}
static void
vs_inhibit_handler(__attribute__((unused)) vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->inhibit = true;
}
static inline notify_script_t*
set_check_notify_script(__attribute__((unused)) vector_t *strvec, const char *type)
{
	return notify_script_init(0, type);
}
static void
notify_up_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	if (rs->notify_up) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) notify_up script already specified - ignoring %s", vs->vsgname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	rs->notify_up = set_check_notify_script(strvec, "notify");
}
static void
notify_down_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	if (rs->notify_down) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) notify_down script already specified - ignoring %s", vs->vsgname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	rs->notify_down = set_check_notify_script(strvec, "notify");
}
static void
rs_delay_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	unsigned long delay;

	if (read_timer(strvec, 1, &delay, 1, 0, true))
		rs->delay_loop = delay;
	else
		report_config_error(CONFIG_GENERAL_ERROR, "real server delay_loop '%s' invalid - ignoring", FMT_STR_VSLOT(strvec, 1));
}
static void
rs_delay_before_retry_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	unsigned long delay;

	if (read_timer(strvec, 1, &delay, 0, 0, true))
		rs->delay_before_retry = delay;
	else
		report_config_error(CONFIG_GENERAL_ERROR, "real server delay_before_retry '%s' invalid - ignoring", FMT_STR_VSLOT(strvec, 1));
}
static void
rs_retry_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	unsigned retry;

	if (!read_unsigned_strvec(strvec, 1, &retry, 1, UINT32_MAX, false)) {
		report_config_error(CONFIG_GENERAL_ERROR, "retry value invalid - %s", FMT_STR_VSLOT(strvec, 1));
		return;
	}
	rs->retry = (unsigned)retry;
}
static void
rs_warmup_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	unsigned long delay;

	if (read_timer(strvec, 1, &delay, 0, 0, true))
		rs->warmup = delay;
	else
		report_config_error(CONFIG_GENERAL_ERROR, "real server warmup '%s' invalid - ignoring", FMT_STR_VSLOT(strvec, 1));
}
static void
rs_inhibit_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res == -1) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid inhibit_on_failure parameter %s", FMT_STR_VSLOT(strvec, 1));
			return;
		}
	}
	rs->inhibit = res;
}
static void
rs_alpha_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res == -1) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid alpha parameter %s", FMT_STR_VSLOT(strvec, 1));
			return;
		}
	}
	rs->alpha = res;
}
static void
rs_smtp_alert_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res == -1) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid real_server smtp_alert parameter %s", FMT_STR_VSLOT(strvec, 1));
			return;
		}
	}
	rs->smtp_alert = res;
}
static void
rs_virtualhost_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->virtualhost = set_value(strvec);
}
static void
vs_alpha_handler(__attribute__((unused)) vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->alpha = true;
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
	if (vs->notify_quorum_up) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) quorum_up script already specified - ignoring %s", vs->vsgname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vs->notify_quorum_up = set_check_notify_script(strvec, "quorum");
}
static void
quorum_down_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	if (vs->notify_quorum_down) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) quorum_down script already specified - ignoring %s", vs->vsgname, FMT_STR_VSLOT(strvec,1));
		return;
	}
	vs->notify_quorum_down = set_check_notify_script(strvec, "quorum");
}
static void
quorum_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	unsigned quorum;

	if (!read_unsigned_strvec(strvec, 1, &quorum, 1, UINT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Quorum %s must be in [1, %u]. Setting to 1.", FMT_STR_VSLOT(strvec, 1), UINT_MAX);
		quorum = 1;
	}

	vs->quorum = quorum;
}
static void
hysteresis_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	unsigned hysteresis;

	if (!read_unsigned_strvec(strvec, 1, &hysteresis, 0, UINT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Hysteresis %s must be in [0, %u] - ignoring", FMT_STR_VSLOT(strvec, 1), UINT_MAX);
		return;
	}

	vs->hysteresis = hysteresis;
}
static void
vs_weight_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	unsigned weight;

	if (!read_unsigned_strvec(strvec, 1, &weight, 1, 65535, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Virtual server weight %s is outside range 1-65535", FMT_STR_VSLOT(strvec, 1));
		return;
	}
	vs->weight = weight;
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
	install_root_end_handler(&vs_end_handler);
	install_keyword("ip_family", &ip_family_handler);
	install_keyword("retry", &vs_retry_handler);
	install_keyword("delay_before_retry", &vs_delay_before_retry_handler);
	install_keyword("warmup", &vs_warmup_handler);
	install_keyword("delay_loop", &vs_delay_handler);
	install_keyword("inhibit_on_failure", &vs_inhibit_handler);
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
	install_keyword("lb_kind", &forwarding_handler);
	install_keyword("lvs_method", &forwarding_handler);
#ifdef _HAVE_PE_NAME_
	install_keyword("persistence_engine", &pengine_handler);
#endif
	install_keyword("persistence_timeout", &pto_handler);
	install_keyword("persistence_granularity", &pgr_handler);
	install_keyword("protocol", &proto_handler);
	install_keyword("ha_suspend", &hasuspend_handler);
	install_keyword("smtp_alert", &vs_smtp_alert_handler);
	install_keyword("virtualhost", &vs_virtualhost_handler);

	/* Pool regression detection and handling. */
	install_keyword("alpha", &vs_alpha_handler);
	install_keyword("omega", &omega_handler);
	install_keyword("quorum_up", &quorum_up_handler);
	install_keyword("quorum_down", &quorum_down_handler);
	install_keyword("quorum", &quorum_handler);
	install_keyword("hysteresis", &hysteresis_handler);
	install_keyword("weight", &vs_weight_handler);

	/* Real server mapping */
	install_keyword("sorry_server", &ssvr_handler);
	install_keyword("sorry_server_inhibit", &ssvri_handler);
	install_keyword("sorry_server_lvs_method", &ss_forwarding_handler);
	install_keyword("real_server", &rs_handler);
	install_sublevel();
	install_keyword("weight", &rs_weight_handler);
	install_keyword("lvs_method", &rs_forwarding_handler);
	install_keyword("uthreshold", &uthreshold_handler);
	install_keyword("lthreshold", &lthreshold_handler);
	install_keyword("inhibit_on_failure", &rs_inhibit_handler);
	install_keyword("notify_up", &notify_up_handler);
	install_keyword("notify_down", &notify_down_handler);
	install_keyword("alpha", &rs_alpha_handler);
	install_keyword("retry", &rs_retry_handler);
	install_keyword("delay_before_retry", &rs_delay_before_retry_handler);
	install_keyword("warmup", &rs_warmup_handler);
	install_keyword("delay_loop", &rs_delay_handler);
	install_keyword("smtp_alert", &rs_smtp_alert_handler);
	install_keyword("virtualhost", &rs_virtualhost_handler);

	install_sublevel_end_handler(&rs_end_handler);

	/* Checkers mapping */
	install_checkers_keyword();
	install_sublevel_end();
}

vector_t *
check_init_keywords(void)
{
	/* global definitions mapping */
	init_global_keywords(reload);

	init_check_keywords(true);
#ifdef _WITH_VRRP_
	init_vrrp_keywords(false);
#endif
#ifdef _WITH_BFD_
	init_bfd_keywords(true);
#endif
	return keywords;
}
