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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

#include "main.h"
#include "check_data.h"
#include "check_api.h"
#include "check_misc.h"
#include "check_daemon.h"
#include "global_data.h"
#include "check_ssl.h"
#include "logger.h"
#include "utils.h"
#include "ipwrapper.h"
#include "parser.h"
#include "libipvs.h"
#include "keepalived_magic.h"
#include "track_file.h"
#ifdef _WITH_BFD_
#include "check_bfd.h"
#endif

/* global vars */
check_data_t *check_data = NULL;
check_data_t *old_check_data = NULL;

/* SSL facility functions */
ssl_data_t *
alloc_ssl(void)
{
	ssl_data_t *ssl_data;

	PMALLOC(ssl_data);
	return ssl_data;
}
void
free_ssl(void)
{
	ssl_data_t *ssl;

	if (!check_data || !check_data->ssl)
		return;

	ssl = check_data->ssl;

	clear_ssl(ssl);
	FREE_CONST_PTR(ssl->password);
	FREE_CONST_PTR(ssl->cafile);
	FREE_CONST_PTR(ssl->certfile);
	FREE_CONST_PTR(ssl->keyfile);
	FREE(ssl);
	check_data->ssl = NULL;
}
static void
dump_ssl(FILE *fp)
{
	ssl_data_t *ssl = check_data->ssl;

	if (!ssl->password && !ssl->cafile && !ssl->certfile && !ssl->keyfile) {
		conf_write(fp, " Using autogen SSL context");
		return;
	}

	if (ssl->password)
		conf_write(fp, " Password : %s", ssl->password);
	if (ssl->cafile)
		conf_write(fp, " CA-file : %s", ssl->cafile);
	if (ssl->certfile)
		conf_write(fp, " Certificate file : %s", ssl->certfile);
	if (ssl->keyfile)
		conf_write(fp, " Key file : %s", ssl->keyfile);
}

/* Virtual server group facility functions */
static void
free_vsg_entry_list(list_head_t *l)
{
	virtual_server_group_entry_t *vsge, *vsge_tmp;

	list_for_each_entry_safe(vsge, vsge_tmp, l, e_list) {
		list_del_init(&vsge->e_list);
		FREE(vsge);
	}
}
static void
dump_vsg_entry(FILE *fp, const virtual_server_group_entry_t *vsg_entry)
{
	char start_addr[INET6_ADDRSTRLEN];

	if (vsg_entry->is_fwmark) {
		conf_write(fp, "   FWMARK = %u%s", vsg_entry->vfwmark, vsg_entry->fwm_family == AF_INET ? " IPv4" : vsg_entry->fwm_family == AF_INET6 ? " IPv6" : "");
		conf_write(fp, "     Alive: %u IPv4, %u IPv6",
				vsg_entry->fwm4_alive, vsg_entry->fwm6_alive);
	} else {
		if (inet_sockaddrcmp(&vsg_entry->addr, &vsg_entry->addr_end)) {
			strcpy(start_addr, inet_sockaddrtos(&vsg_entry->addr));
			conf_write(fp, "   VIP Range = %s-%s, VPORT = %d",
				   start_addr,
				   inet_sockaddrtos(&vsg_entry->addr_end),
				   ntohs(inet_sockaddrport(&vsg_entry->addr)));
		} else
			conf_write(fp, "   VIP = %s, VPORT = %d"
					    , inet_sockaddrtos(&vsg_entry->addr)
					    , ntohs(inet_sockaddrport(&vsg_entry->addr)));
		conf_write(fp, "     Alive: %u tcp, %u udp, %u sctp",
			    vsg_entry->tcp_alive, vsg_entry->udp_alive, vsg_entry->sctp_alive);
	}
	conf_write(fp, "     reloaded = %s", vsg_entry->reloaded ? "True" : "False");
}
static void
dump_vsg_entry_list(FILE *fp, const list_head_t *l)
{
	virtual_server_group_entry_t *vsge;

	list_for_each_entry(vsge, l, e_list)
		dump_vsg_entry(fp, vsge);
}
void
free_vsg(virtual_server_group_t *vsg)
{
	list_del_init(&vsg->e_list);
	FREE_PTR(vsg->gname);
	free_vsg_entry_list(&vsg->addr_range);
	free_vsg_entry_list(&vsg->vfwmark);
	FREE(vsg);
}
static void
free_vsg_list(list_head_t *l)
{
	virtual_server_group_t *vsg, *vsg_tmp;

	list_for_each_entry_safe(vsg, vsg_tmp, l, e_list)
		free_vsg(vsg);
}
static void
dump_vsg(FILE *fp, const virtual_server_group_t *vsg)
{
	conf_write(fp, " ------< Virtual server group >------");
	conf_write(fp, " Virtual Server Group = %s, IPv4 = %s, IPv6 = %s", vsg->gname, vsg->have_ipv4 ? "yes" : "no", vsg->have_ipv6 ? "yes" : "no");
#ifdef _WITH_NFTABLES_
	if (global_data->ipvs_nf_table_name &&
	    (vsg->auto_fwmark[TCP_INDEX] ||
	     vsg->auto_fwmark[UDP_INDEX] ||
	     vsg->auto_fwmark[SCTP_INDEX]))
		conf_write(fp, "  Fwmark TCP: %u UDP: %u SCTP: %u", vsg->auto_fwmark[TCP_INDEX], vsg->auto_fwmark[UDP_INDEX], vsg->auto_fwmark[SCTP_INDEX]);
#endif
	dump_vsg_entry_list(fp, &vsg->addr_range);
	dump_vsg_entry_list(fp, &vsg->vfwmark);
}
static void
dump_vsg_list(FILE *fp, const list_head_t *l)
{
	virtual_server_group_t *vsg;

	list_for_each_entry(vsg, l, e_list)
		dump_vsg(fp, vsg);
}
void
alloc_vsg(const char *gname)
{
	virtual_server_group_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->e_list);
	INIT_LIST_HEAD(&new->addr_range);
	INIT_LIST_HEAD(&new->vfwmark);
	new->gname = STRDUP(gname);

	list_add_tail(&new->e_list, &check_data->vs_group);
}
void
alloc_vsg_entry(const vector_t *strvec)
{
	virtual_server_group_t *vsg = list_last_entry(&check_data->vs_group, virtual_server_group_t, e_list);
	virtual_server_group_entry_t *new;
	uint32_t start;
	const char *port_str;
	uint32_t range;
	unsigned fwmark;
	const char *family_str;
	const char *addr_str = strvec_slot(strvec, 0);
	char *endptr;
	const char *mask_str;
	unsigned mask;
	uint32_t mask_bit, mask_bits;
	bool bad;
	unsigned i;
	const char *end_str;
	int diff;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->e_list);

	if (!strcmp(addr_str, "fwmark")) {
		if (!read_unsigned_strvec(strvec, 1, &fwmark, 0, UINT32_MAX, true)) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s): fwmark '%s' must be in [0, %u] - ignoring", vsg->gname, strvec_slot(strvec, 1), UINT32_MAX);
			FREE(new);
			return;
		}
		if (vector_size(strvec) > 2) {
			family_str = strvec_slot(strvec, 2);
			if (!strcmp(family_str, "inet")) {
				new->fwm_family = AF_INET;
				vsg->have_ipv4 = true;
			} else if (!strcmp(family_str, "inet6")) {
				new->fwm_family = AF_INET6;
				vsg->have_ipv6 = true;
			} else {
				report_config_error(CONFIG_GENERAL_ERROR, "(%s): fwmark '%u' family %s unknown - ignoring", vsg->gname, fwmark, family_str);
				FREE(new);
				return;
			}
		} else {
			new->fwm_family = AF_UNSPEC;
			vsg->fwmark_no_family = true;
		}

		new->vfwmark = fwmark;
		new->is_fwmark = true;
		list_add_tail(&new->e_list, &vsg->vfwmark);
	} else {
		if (vector_size(strvec) >= 2) {
			/* Don't pass a port number of 0. This was added v2.0.7 to support legacy
			 * configuration since previously having no port wasn't allowed. */
			port_str = strvec_slot(strvec, 1);
			if (!port_str[strspn(port_str, "0")])
				port_str = NULL;
		}
		else
			port_str = NULL;

		if (inet_stosockaddr(addr_str, port_str, &new->addr)) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid virtual server group IP address %s %s%s%s - skipping", strvec_slot(strvec, 0),
						port_str ? "/port" : "", port_str ? "/" : "", port_str ? port_str : "");
			FREE(new);
			return;
		}
#ifndef LIBIPVS_USE_NL
		if (new->addr.ss_family != AF_INET) {
			report_config_error(CONFIG_GENERAL_ERROR, "IPVS does not support IPv6 in this build - skipping %s", addr_str);
			FREE(new);
			return;
		}
#endif

		if ((mask_str = strchr(addr_str, '/'))) {
			mask = strtoul(mask_str + 1, &endptr, 10);
			if (*endptr ||
			    !mask ||
			    (new->addr.ss_family == AF_INET && mask > 32) ||
			    (new->addr.ss_family == AF_INET6 && mask > 128)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid netmask - %s - skipping", addr_str);
				FREE(new);
				return;
			}

			new->addr_end = new->addr;
			bad = false;

			if (new->addr.ss_family == AF_INET && mask < 32) {
				for (i = mask, mask_bit = 1, mask_bits = 0; i < 32; i++, mask_bit <<= 1)
					mask_bits |= mask_bit;

				if (PTR_CAST(struct sockaddr_in, &new->addr)->sin_addr.s_addr & htonl(mask_bits))
					bad = true;
				else
					PTR_CAST(struct sockaddr_in, &new->addr_end)->sin_addr.s_addr |= htonl(mask_bits);
			} else if (mask < 128) {
				for (i = mask % 16, mask_bit = 1, mask_bits = 0; i < 16; i++, mask_bit <<= 1)
					mask_bits |= mask_bit;

				i = mask / 16;
				if (PTR_CAST(struct sockaddr_in6, &new->addr)->sin6_addr.s6_addr16[i] & htons(mask_bits))
					bad = true;
				else {
					PTR_CAST(struct sockaddr_in6, &new->addr_end)->sin6_addr.s6_addr16[i] |= htons(mask_bits);
					for (i++; i < 8; i++) {
						if (PTR_CAST(struct sockaddr_in6, &new->addr)->sin6_addr.s6_addr16[i])
							bad = true;
						else
							PTR_CAST(struct sockaddr_in6, &new->addr_end)->sin6_addr.s6_addr16[i] = 0xffff;
					}
				}
			}
			if (bad) {
				report_config_error(CONFIG_GENERAL_ERROR, "Address mask bits not empty - %s - skipping", addr_str);
				FREE(new);
				return;
			}
		} else {
			if ((end_str = strchr(addr_str, '-')) &&
			    ((new->addr.ss_family == AF_INET && strchr(end_str + 1, '.')) ||
			     (new->addr.ss_family == AF_INET6 && strchr(end_str + 1, ':')))) {
				if (inet_stosockaddr(++end_str, port_str, &new->addr_end)) {
					report_config_error(CONFIG_GENERAL_ERROR, "Invalid range end %s - skipping", addr_str);
					FREE(new);
					return;
				}
				if (new->addr.ss_family != new->addr_end.ss_family) {
					report_config_error(CONFIG_GENERAL_ERROR, "Range address families do not match %s - skipping", addr_str);
					FREE(new);
					return;
				}

				bad = false;
				if (new->addr.ss_family == AF_INET) {
					if (htonl(PTR_CAST(struct sockaddr_in, &new->addr)->sin_addr.s_addr) >
					    htonl(PTR_CAST(struct sockaddr_in, &new->addr_end)->sin_addr.s_addr))
						bad = true;
				} else {
					for (i = 0; i < 8; i++) {
						diff = htons(PTR_CAST(struct sockaddr_in6, &new->addr_end)->sin6_addr.s6_addr16[i]) -
							    htons(PTR_CAST(struct sockaddr_in6, &new->addr)->sin6_addr.s6_addr16[i]);
						if (diff < 0) {
							bad = true;
							break;
						}
						if (diff > 0)
							break;
					}
				}

				if (bad) {
					report_config_error(CONFIG_GENERAL_ERROR, "Address range end is less than address range start - %s - skipping", addr_str);
					FREE(new);
					return;
				}
			} else {
				if (!inet_stor(addr_str, &range)) {
					FREE(new);
					return;
				}

				/* If no range specified, range == UINT32_MAX */
				new->addr_end = new->addr;
				if (range != UINT32_MAX) {
					if (new->addr.ss_family == AF_INET) {
						PTR_CAST(struct sockaddr_in, &new->addr_end)->sin_addr.s_addr &= htonl(~0xFF);
						PTR_CAST(struct sockaddr_in, &new->addr_end)->sin_addr.s_addr |= htonl(range);
						start = ntohl(PTR_CAST(struct sockaddr_in, &new->addr)->sin_addr.s_addr) & 0xFF;
					} else {
						PTR_CAST(struct sockaddr_in6, &new->addr_end)->sin6_addr.s6_addr16[7] = htons(range);
						start = ntohs(PTR_CAST(struct sockaddr_in6, &new->addr)->sin6_addr.s6_addr16[7]);
					}

					if (start >= range) {
						report_config_error(CONFIG_GENERAL_ERROR, "Address range end is not greater than address range start - %s - skipping", addr_str);
						FREE(new);
						return;
					}
				}
			}
		}

		new->is_fwmark = false;
		list_add_tail(&new->e_list, &vsg->addr_range);

		if (new->addr.ss_family == AF_INET)
			vsg->have_ipv4 = true;
		else
			vsg->have_ipv6 = true;
	}
}

static void
dump_forwarding_method(FILE *fp, const char *prefix, const real_server_t *rs)
{
	const char *fwd_method = "forwarding method = ";
#ifdef _HAVE_IPVS_TUN_TYPE_
	const char *csum_str = "";
	const char *tun_type = "TUN, type = ";
#endif

	switch (rs->forwarding_method) {
	case IP_VS_CONN_F_MASQ:
		conf_write(fp, "   %s%sNAT", prefix, fwd_method);
		break;
	case IP_VS_CONN_F_DROUTE:
		conf_write(fp, "   %s%sDR", prefix, fwd_method);
		break;
	case IP_VS_CONN_F_TUNNEL:
#ifdef _HAVE_IPVS_TUN_TYPE_
		if (rs->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_IPIP)
			conf_write(fp, "   %s%s%sIPIP", prefix, fwd_method, tun_type);
		else {
#ifdef _HAVE_IPVS_TUN_CSUM_
			csum_str = rs->tun_flags == IP_VS_TUNNEL_ENCAP_FLAG_NOCSUM ? ", no checksum" :
				   rs->tun_flags == IP_VS_TUNNEL_ENCAP_FLAG_CSUM ? ", checksum" :
				   rs->tun_flags == IP_VS_TUNNEL_ENCAP_FLAG_REMCSUM ? ", remote checksum" :
				   ", unknown checksum type";
#endif
			if (rs->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_GUE)
				conf_write(fp, "   %s%sGUE, port = %u%s", fwd_method, tun_type, ntohs(rs->tun_port), csum_str);
#ifdef _HAVE_IPVS_TUN_GRE_
			else if (rs->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_GRE)
				conf_write(fp, "   %s%sGRE%s", fwd_method, tun_type, csum_str);
#endif
		}
#else
		conf_write(fp, "   %s%sTUN", prefix, fwd_method);
#endif
		break;
	default:
		conf_write(fp, "   %s 0x%x", fwd_method, rs->forwarding_method);
		break;
	}
}

/*
 *	Real server facility functions
 */
void
free_rs(real_server_t *rs)
{
	list_del_init(&rs->e_list);
	free_notify_script(&rs->notify_up);
	free_notify_script(&rs->notify_down);
	free_track_file_monitor_list(&rs->track_files);
#ifdef _WITH_BFD_
	free_checker_tracked_bfd_list(&rs->tracked_bfds);
#endif
	FREE_CONST_PTR(rs->virtualhost);
#ifdef _WITH_SNMP_CHECKER_
	FREE_CONST_PTR(rs->snmp_name);
#endif
	free_rs_checkers(rs);
	FREE(rs);
}
static void
free_rs_list(list_head_t *l)
{
	real_server_t *rs, *rs_tmp;

	list_for_each_entry_safe(rs, rs_tmp, l, e_list)
		free_rs(rs);
}

void
dump_tracking_rs(FILE *fp, const void *data)
{
	const tracking_obj_t *top = PTR_CAST_CONST(tracking_obj_t, data);
	const checker_t *checker = top->obj.checker;

	conf_write(fp, "     %s -> %s, weight %d%s", FMT_VS(checker->vs), FMT_RS(checker->rs, checker->vs), top->weight, top->weight_multiplier == -1 ? " reverse" : "");
}

static void
dump_rs(FILE *fp, const real_server_t *rs)
{
#ifdef _WITH_BFD_
	cref_tracked_bfd_t *tbfd;
#endif

	conf_write(fp, "   ------< Real server >------");
	conf_write(fp, "   RIP = %s, RPORT = %d, WEIGHT = %d EFF WEIGHT = %" PRIi64
			    , inet_sockaddrtos(&rs->addr)
			    , ntohs(inet_sockaddrport(&rs->addr))
			    , real_weight(rs->effective_weight), rs->effective_weight);
	dump_forwarding_method(fp, "", rs);

	conf_write(fp, "   Alpha is %s", rs->alpha ? "ON" : "OFF");
	conf_write(fp, "   connection timeout = %f", ((double)rs->connection_to) / TIMER_HZ);
	conf_write(fp, "   connection limit range = %" PRIu32 " -> %" PRIu32, rs->l_threshold, rs->u_threshold);
	conf_write(fp, "   Delay loop = %f" , (double)rs->delay_loop / TIMER_HZ);
	if (rs->retry != UINT_MAX)
		conf_write(fp, "   Retry count = %u" , rs->retry);
	if (rs->delay_before_retry != ULONG_MAX)
		conf_write(fp, "   Retry delay = %f" , (double)rs->delay_before_retry / TIMER_HZ);
	if (rs->warmup != ULONG_MAX)
		conf_write(fp, "   Warmup = %f", (double)rs->warmup / TIMER_HZ);
	conf_write(fp, "   Inhibit on failure is %s", rs->inhibit ? "ON" : "OFF");

	if (rs->notify_up)
		conf_write(fp, "     RS up notify script = %s, uid:gid %u:%u",
				cmd_str(rs->notify_up), rs->notify_up->uid, rs->notify_up->gid);
	if (rs->notify_down)
		conf_write(fp, "     RS down notify script = %s, uid:gid %u:%u",
				cmd_str(rs->notify_down), rs->notify_down->uid, rs->notify_down->gid);
	if (rs->virtualhost)
		conf_write(fp, "    VirtualHost = '%s'", rs->virtualhost);
#ifdef _WITH_SNMP_CHECKER_
	if (rs->snmp_name)
		conf_write(fp, "   SNMP name = %s", rs->snmp_name);
#endif
	conf_write(fp, "   Using smtp notification = %s", rs->smtp_alert ? "yes" : "no");

	conf_write(fp, "   initial weight = %d", rs->iweight);
	conf_write(fp, "   effective weight = %" PRIi64, rs->effective_weight);
	conf_write(fp, "   previous effective_weight = %" PRIi64, rs->peffective_weight);
	conf_write(fp, "   alive = %d", rs->alive);
	conf_write(fp, "   num failed checkers = %u", rs->num_failed_checkers);
	conf_write(fp, "   RS set = %d", rs->set);
	conf_write(fp, "   reloaded = %d", rs->reloaded);

	if (!list_empty(&rs->track_files)) {
		conf_write(fp, "   Tracked Files");
		dump_track_file_monitor_list(fp, &rs->track_files);
	}

#ifdef _WITH_BFD_
	if (!list_empty(&rs->tracked_bfds)) {
		conf_write(fp, "   Tracked BFDs");
		list_for_each_entry(tbfd, &rs->tracked_bfds, e_list)
			conf_write(fp, "     %s", tbfd->bfd->bname);
	}
#endif
}
static void
dump_rs_list(FILE *fp, const list_head_t *l)
{
	real_server_t *rs;

	list_for_each_entry(rs, l, e_list)
		dump_rs(fp, rs);
}

void
alloc_rs(const char *ip, const char *port)
{
	virtual_server_t *vs = list_last_entry(&check_data->vs, virtual_server_t, e_list);
	real_server_t *new;
	const char *port_str;

	/* inet_stosockaddr rejects port 0 */
	port_str = (port && port[strspn(port, "0")]) ? port : NULL;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->e_list);
	INIT_LIST_HEAD(&new->track_files);
#ifdef _WITH_BFD_
	INIT_LIST_HEAD(&new->tracked_bfds);
#endif
	if (inet_stosockaddr(ip, port_str, &new->addr)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid real server ip address/port %s/%s - skipping", ip, port);
		skip_block(true);
		FREE(new);
		return;
	}

#ifndef LIBIPVS_USE_NL
	if (new->addr.ss_family != AF_INET) {
		report_config_error(CONFIG_GENERAL_ERROR, "IPVS does not support IPv6 in this build - skipping %s/%s", ip, port);
		skip_block(true);
		FREE(new);
		return;
	}
#else
#if !HAVE_DECL_IPVS_DEST_ATTR_ADDR_FAMILY
	if (vs->af != AF_UNSPEC && new->addr.ss_family != vs->af) {
		report_config_error(CONFIG_GENERAL_ERROR, "Your kernel doesn't support mixed IPv4/IPv6 for virtual/real servers");
		skip_block(true);
		FREE(new);
		return;
	}
#endif
#endif

	new->effective_weight = INT64_MAX;
	new->forwarding_method = vs->forwarding_method;
#ifdef _HAVE_IPVS_TUN_TYPE_
	new->tun_type = vs->tun_type;
	new->tun_port = vs->tun_port;
#ifdef _HAVE_IPVS_TUN_CSUM_
	new->tun_flags = vs->tun_flags;
#endif
#endif
	new->alpha = -1;
	new->inhibit = -1;
	new->connection_to = UINT_MAX;
	new->delay_loop = ULONG_MAX;
	new->warmup = ULONG_MAX;
	new->retry = UINT_MAX;
	new->delay_before_retry = ULONG_MAX;
	new->virtualhost = NULL;
#ifdef _WITH_SNMP_CHECKER_
	new->snmp_name = NULL;
#endif
	new->smtp_alert = -1;

	list_add_tail(&new->e_list, &vs->rs);
	vs->rs_cnt++;
}

/*
 *	Virtual server facility functions
 */
void
free_vs(virtual_server_t *vs)
{
	list_del_init(&vs->e_list);
	FREE_CONST_PTR(vs->vsgname);
	FREE_CONST_PTR(vs->virtualhost);
#ifdef _WITH_SNMP_CHECKER_
	FREE_CONST_PTR(vs->snmp_name);
#endif
	FREE_PTR(vs->s_svr);
	free_rs_list(&vs->rs);
	free_notify_script(&vs->notify_quorum_up);
	free_notify_script(&vs->notify_quorum_down);
	free_vs_checkers(vs);
	FREE(vs);
}

static void
free_vs_list(list_head_t *l)
{
	virtual_server_t *vs, *vs_tmp;

	list_for_each_entry_safe(vs, vs_tmp, l, e_list)
		free_vs(vs);
}

static void
dump_vs(FILE *fp, const virtual_server_t *vs)
{
	conf_write(fp, " ------< Virtual server >------");
	if (vs->vsgname)
		conf_write(fp, " VS GROUP = %s", FMT_VS(vs));
	else if (vs->vfwmark)
		conf_write(fp, " VS FWMARK = %u", vs->vfwmark);
	else
		conf_write(fp, " VS VIP = %s, VPORT = %d"
				    , inet_sockaddrtos(&vs->addr), ntohs(inet_sockaddrport(&vs->addr)));
	if (vs->virtualhost)
		conf_write(fp, "   VirtualHost = %s", vs->virtualhost);
#ifdef _WITH_SNMP_CHECKER_
	if (vs->snmp_name)
		conf_write(fp, "   SNMP name = '%s'", vs->snmp_name);
#endif
	if (vs->af != AF_UNSPEC)
		conf_write(fp, "   Address family = inet%s", vs->af == AF_INET ? "" : "6");
	else if (vs->vsg && vs->vsg->have_ipv4 && vs->vsg->have_ipv6)
		conf_write(fp, "   Address family = IPv4 & IPv6");
	else
		conf_write(fp, "   Address family = unknown");
	conf_write(fp, "   connection timeout = %f", (double)vs->connection_to / TIMER_HZ);
	conf_write(fp, "   delay_loop = %f", (double)vs->delay_loop / TIMER_HZ);
	conf_write(fp, "   lvs_sched = %s", vs->sched);
	conf_write(fp, "   Hashed = %sabled", vs->flags & IP_VS_SVC_F_HASHED ? "en" : "dis");
#ifdef IP_VS_SVC_F_SCHED1
	if (!strcmp(vs->sched, "sh"))
	{
		conf_write(fp, "   sh-port = %sabled", vs->flags & IP_VS_SVC_F_SCHED_SH_PORT ? "en" : "dis");
		conf_write(fp, "   sh-fallback = %sabled", vs->flags & IP_VS_SVC_F_SCHED_SH_FALLBACK ? "en" : "dis");
	}
	else if (!strcmp(vs->sched, "mh"))
	{
		conf_write(fp, "   mh-port = %sabled", vs->flags & IP_VS_SVC_F_SCHED_MH_PORT ? "en" : "dis");
		conf_write(fp, "   mh-fallback = %sabled", vs->flags & IP_VS_SVC_F_SCHED_MH_FALLBACK ? "en" : "dis");
	}
	else
	{
		conf_write(fp, "   flag-1 = %sabled", vs->flags & IP_VS_SVC_F_SCHED1 ? "en" : "dis");
		conf_write(fp, "   flag-2 = %sabled", vs->flags & IP_VS_SVC_F_SCHED2 ? "en" : "dis");
		conf_write(fp, "   flag-3 = %sabled", vs->flags & IP_VS_SVC_F_SCHED3 ? "en" : "dis");
	}
#endif
	conf_write(fp, "   One packet scheduling = %sabled%s",
			(vs->flags & IP_VS_SVC_F_ONEPACKET) ? "en" : "dis",
			((vs->flags & IP_VS_SVC_F_ONEPACKET) && vs->service_type != IPPROTO_UDP) ? " (inactive due to not UDP)" : "");

	if (vs->persistence_timeout)
		conf_write(fp, "   persistence timeout = %u", vs->persistence_timeout);
	if (vs->persistence_granularity != 0xffffffff) {
		if (vs->af == AF_INET6)
			conf_write(fp, "   persistence granularity = %" PRIu32,
				       vs->persistence_granularity);
		else
			conf_write(fp, "   persistence granularity = %s",
				       inet_ntop2(vs->persistence_granularity));
	}
	if (vs->service_type == IPPROTO_TCP)
		conf_write(fp, "   protocol = TCP");
	else if (vs->service_type == IPPROTO_UDP)
		conf_write(fp, "   protocol = UDP");
	else if (vs->service_type == IPPROTO_SCTP)
		conf_write(fp, "   protocol = SCTP");
	else if (vs->service_type == 0)
		conf_write(fp, "   protocol = none");
	else
		conf_write(fp, "   protocol = %d", vs->service_type);
	conf_write(fp, "   alpha is %s", vs->alpha ? "ON" : "OFF");
	conf_write(fp, "   omega is %s", vs->omega ? "ON" : "OFF");
	if (vs->retry != UINT_MAX)
		conf_write(fp, "   Retry count = %u" , vs->retry);
	if (vs->delay_before_retry != ULONG_MAX)
		conf_write(fp, "   Retry delay = %f" , (double)vs->delay_before_retry / TIMER_HZ);
	if (vs->warmup != ULONG_MAX)
		conf_write(fp, "   Warmup = %f", (double)vs->warmup / TIMER_HZ);
	conf_write(fp, "   Inhibit on failure is %s", vs->inhibit ? "ON" : "OFF");
	conf_write(fp, "   quorum = %u, hysteresis = %u", vs->quorum, vs->hysteresis);
	if (vs->notify_quorum_up)
		conf_write(fp, "   Quorum up notify script = %s, uid:gid %u:%u",
			    cmd_str(vs->notify_quorum_up), vs->notify_quorum_up->uid, vs->notify_quorum_up->gid);
	if (vs->notify_quorum_down)
		conf_write(fp, "   Quorum down notify script = %s, uid:gid %u:%u",
			    cmd_str(vs->notify_quorum_down), vs->notify_quorum_down->uid, vs->notify_quorum_down->gid);
	if (vs->ha_suspend)
		conf_write(fp, "   Using HA suspend");
	conf_write(fp, "   Using smtp notification = %s", vs->smtp_alert ? "yes" : "no");

	real_server_t rs = { .forwarding_method = vs->forwarding_method };
#ifdef _HAVE_IPVS_TUN_TYPE_
	rs.tun_type = vs->tun_type;
	rs.tun_port = vs->tun_port;
#ifdef _HAVE_IPVS_TUN_CSUM_
	rs.tun_flags = vs->tun_flags;
#endif
#endif
	dump_forwarding_method(fp, "default ", &rs);

	if (vs->s_svr) {
		conf_write(fp, "   sorry server %s= %s"
				    , vs->s_svr_duplicates_rs ? "(duplicates rs) " : ""
				    , FMT_RS(vs->s_svr, vs));
		dump_forwarding_method(fp, "  ", vs->s_svr);
		conf_write(fp, "     Inhibit on failure is %s", vs->s_svr->inhibit ? "ON" : "OFF");
	}
	conf_write(fp, "   alive = %d", vs->alive);
	conf_write(fp, "   quorum_state_up = %d", vs->quorum_state_up);
	conf_write(fp, "   reloaded = %d", vs->reloaded);

	dump_rs_list(fp, &vs->rs);
}

static void
dump_vs_list(FILE *fp, const list_head_t *l)
{
	virtual_server_t *vs;

	list_for_each_entry(vs, l, e_list)
		dump_vs(fp, vs);
}

void
alloc_vs(const char *param1, const char *param2)
{
	virtual_server_t *new;
	const char *port_str;
	unsigned fwmark;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->e_list);

	new->af = AF_UNSPEC;

	if (!strcmp(param1, "group"))
		new->vsgname = STRDUP(param2);
	else if (!strcmp(param1, "fwmark")) {
		if (!read_unsigned(param2, &fwmark, 0, IPVS_FWMARK_MAX, true)) {
			report_config_error(CONFIG_GENERAL_ERROR, "virtual server fwmark '%s' must be in [0, %u] - ignoring", param2, IPVS_FWMARK_MAX);
			skip_block(true);
			FREE(new);
			return;
		}
		new->vfwmark = fwmark;
	} else {
		/* Don't pass a zero for port number to inet_stosockaddr. This was added in v2.0.7
		 * to support legacy configuration since previously having no port wasn't allowed. */
		port_str = (param2 && param2[strspn(param2, "0")]) ? param2 : NULL;
		if (inet_stosockaddr(param1, port_str, &new->addr)) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid virtual server IP address%s %s%s%s - skipping",
						port_str ? "/port" : "", param1, port_str ? "/" : "", port_str ? port_str : "");
			skip_block(true);
			FREE(new);
			return;
		}

		new->af = new->addr.ss_family;
#ifndef LIBIPVS_USE_NL
		if (new->af != AF_INET) {
			report_config_error(CONFIG_GENERAL_ERROR, "IPVS with IPv6 is not supported by this build");
			FREE(new);
			skip_block(true);
			return;
		}
#endif
	}

	new->virtualhost = NULL;
#ifdef _WITH_SNMP_CHECKER_
	new->snmp_name = NULL;
#endif
	new->alpha = false;
	new->omega = false;
	new->notify_quorum_up = NULL;
	new->notify_quorum_down = NULL;
	new->quorum = 1;
	new->hysteresis = 0;
	new->quorum_state_up = true;
	new->flags = 0;
	new->forwarding_method = IP_VS_CONN_F_FWD_MASK;		/* So we can detect if it has been set */
	new->connection_to = 5 * TIMER_HZ;
	new->delay_loop = KEEPALIVED_DEFAULT_DELAY;
	new->warmup = ULONG_MAX;
	new->retry = UINT_MAX;
	new->delay_before_retry = ULONG_MAX;
	new->weight = 1;
	new->smtp_alert = -1;
	new->persistence_granularity = 0xffffffff;
	INIT_LIST_HEAD(&new->rs);

	list_add_tail(&new->e_list, &check_data->vs);
}

/* Sorry server facility functions */
void
alloc_ssvr(const char *ip, const char *port)
{
	virtual_server_t *vs = list_last_entry(&check_data->vs, virtual_server_t, e_list);
	real_server_t *new;
	const char *port_str;

	/* inet_stosockaddr rejects port 0 */
	port_str = (port && port[strspn(port, "0")]) ? port : NULL;

	PMALLOC(new);
	new->effective_weight = 1;
	new->iweight = 1;
	new->forwarding_method = vs->forwarding_method;
#ifdef _HAVE_IPVS_TUN_TYPE_
	new->tun_type = vs->tun_type;
	new->tun_port = vs->tun_port;
#ifdef _HAVE_IPVS_TUN_CSUM_
	new->tun_flags = vs->tun_flags;
#endif
#endif
	if (inet_stosockaddr(ip, port_str, &new->addr)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid sorry server IP address %s - skipping", ip);
		FREE(new);
		return;
	}

	vs->s_svr = new;
}

#ifdef _WITH_BFD_
/* Track bfd dump */
static void
dump_checker_bfd(FILE *fp, const checker_tracked_bfd_t *cbfd)
{
	conf_write(fp, " Checker Track BFD = %s", cbfd->bname);
//	conf_write(fp, "   Weight = %d", cbfd->weight);
	conf_write(fp, "   Tracking RS :");
	dump_bfds_rs_list(fp, &cbfd->tracking_rs);
}
static void
dump_checker_bfd_list(FILE *fp, const list_head_t *l)
{
	checker_tracked_bfd_t *cbfd;

	list_for_each_entry(cbfd, l, e_list)
		dump_checker_bfd(fp, cbfd);

}

void
free_checker_bfd(checker_tracked_bfd_t *cbfd)
{
	list_del_init(&cbfd->e_list);
	FREE(cbfd->bname);
	free_bfds_rs_list(&cbfd->tracking_rs);
	FREE(cbfd);
}
static void
free_checker_bfd_list(list_head_t *l)
{
	checker_tracked_bfd_t *cbfd, *cbfd_tmp;

	list_for_each_entry_safe(cbfd, cbfd_tmp, l, e_list)
		free_checker_bfd(cbfd);
}

#endif

/* data facility functions */
check_data_t *
alloc_check_data(void)
{
	check_data_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->vs);
	INIT_LIST_HEAD(&new->vs_group);
	INIT_LIST_HEAD(&new->track_files);
#ifdef _WITH_BFD_
	INIT_LIST_HEAD(&new->track_bfds);
#endif

	return new;
}

void
free_check_data(check_data_t *data)
{
	free_vs_list(&data->vs);
	free_vsg_list(&data->vs_group);
	free_track_file_list(&data->track_files);
#ifdef _WITH_BFD_
	free_checker_bfd_list(&data->track_bfds);
#endif
	FREE(data);
}

static void
dump_check_data(FILE *fp, const check_data_t *data)
{
	if (data->ssl) {
		conf_write(fp, "------< SSL definitions >------");
		dump_ssl(fp);
	}

	if (!list_empty(&data->vs)) {
		conf_write(fp, "------< LVS Topology >------");
		conf_write(fp, " System is compiled with LVS v%d.%d.%d"
			     , NVERSION(IP_VS_VERSION_CODE));
		if (!list_empty(&data->vs_group))
			dump_vsg_list(fp, &data->vs_group);
		dump_vs_list(fp, &data->vs);
	}
	dump_checkers_queue(fp);

	if (!list_empty(&data->track_files)) {
		conf_write(fp, "------< Checker track files >------");
		dump_track_file_list(fp, &data->track_files);
	}

#ifdef _WITH_BFD_
	if (!list_empty(&data->track_bfds)) {
		conf_write(fp, "------< Checker track BFDs >------");
		dump_checker_bfd_list(fp, &data->track_bfds);
	}
#endif
}

void
dump_data_check(FILE *fp)
{
	dump_global_data(fp, global_data);

	dump_check_data(fp, check_data);
}

const char *
format_vs(const virtual_server_t *vs)
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
			, inet_sockaddrtotrio(&vs->addr, vs->service_type));

	return ret;
}

const char *
format_vsge(const virtual_server_group_entry_t *vsge)
{
	static char ret[INET6_ADDRSTRLEN + 1 + INET6_ADDRSTRLEN + 1 + 5 + 1]; /* IPv6 addr-IPv6 addr:ppppp */
	unsigned offs;

	if (vsge->is_fwmark)
		snprintf(ret, sizeof(ret), "FWM %u", vsge->vfwmark);
	else if (inet_sockaddrcmp(&vsge->addr, &vsge->addr_end)) {
		offs = snprintf(ret, sizeof(ret), "%s-",
				inet_sockaddrtos(&vsge->addr));
		snprintf(ret + offs, sizeof(ret) - offs, "%s,%d",
				inet_sockaddrtos(&vsge->addr_end),
				ntohs(inet_sockaddrport(&vsge->addr)));
	} else
		snprintf(ret, sizeof(ret), "%s,%d",
			    inet_sockaddrtos(&vsge->addr), ntohs(inet_sockaddrport(&vsge->addr)));

	return ret;
}

const char *
format_rs(const real_server_t *rs, const virtual_server_t *vs)
{
	static char buf[SOCKADDRTRIO_STR_LEN];

	inet_sockaddrtotrio_r(&rs->addr, vs->service_type, buf);

	return buf;
}

static void
check_check_script_security(void)
{
	virtual_server_t *vs;
	real_server_t *rs;
	unsigned script_flags;
	magic_t magic;

	if (list_empty(&check_data->vs))
		return;

	magic = ka_magic_open();

	script_flags = check_misc_script_security(magic);

	list_for_each_entry(vs, &check_data->vs, e_list) {
		script_flags |= check_notify_script_secure(&vs->notify_quorum_up, magic);
		script_flags |= check_notify_script_secure(&vs->notify_quorum_down, magic);

		list_for_each_entry(rs, &vs->rs, e_list) {
			script_flags |= check_notify_script_secure(&rs->notify_up, magic);
			script_flags |= check_notify_script_secure(&rs->notify_down, magic);
		}
	}

	if (global_data->notify_fifo.script)
		script_flags |= check_notify_script_secure(&global_data->notify_fifo.script, magic);
	if (global_data->lvs_notify_fifo.script)
		script_flags |= check_notify_script_secure(&global_data->lvs_notify_fifo.script, magic);

	if (!script_security && script_flags & SC_ISSCRIPT) {
		report_config_error(CONFIG_SECURITY_ERROR, "SECURITY VIOLATION - check scripts are being executed but script_security not enabled.%s",
				script_flags & SC_INSECURE ? " There are insecure scripts." : "");
	}

	if (magic)
		ka_magic_close(magic);
}

bool
validate_check_config(void)
{
	virtual_server_t *vs, *vs_tmp;
	virtual_server_group_entry_t *vsge;
	real_server_t *rs, *rs_tmp, *rs1;
	checker_t *checker;
	unsigned weight_sum;
	bool rs_removed;

	using_ha_suspend = false;
	list_for_each_entry_safe(vs, vs_tmp, &check_data->vs, e_list) {
		if (list_empty(&vs->rs)) {
			report_config_error(CONFIG_GENERAL_ERROR, "Virtual server %s has no real servers - ignoring", FMT_VS(vs));
			free_vs(vs);
			continue;
		}

		/* Ensure that ha_suspend is not set for any virtual server using fwmarks */
		if (vs->ha_suspend &&
		    (vs->vfwmark || (vs->vsg && !list_empty(&vs->vsg->vfwmark)))) {
			report_config_error(CONFIG_GENERAL_ERROR, "Virtual server %s: cannot use ha_suspend with fwmarks - clearing ha_suspend", FMT_VS(vs));
			vs->ha_suspend = false;
		}

		if (vs->ha_suspend)
			using_ha_suspend = true;

		/* If the virtual server is specified by address (rather than fwmark), make some further checks */
		if ((vs->vsg && !list_empty(&vs->vsg->addr_range)) ||
		    (!vs->vsg && !vs->vfwmark)) {
			/* Check protocol set */
			if (!vs->service_type) {
				/* If the protocol is 0, the kernel defaults to UDP, so set it explicitly */
				report_config_error(CONFIG_GENERAL_ERROR, "Virtual server %s: no protocol set - defaulting to UDP", FMT_VS(vs));
				vs->service_type = IPPROTO_UDP;
			}

			/* Check OPS not set for TCP or SCTP */
			if (vs->flags & IP_VS_SVC_F_ONEPACKET &&
			    vs->service_type != IPPROTO_UDP) {
				/* OPS is only valid for UDP, or with a firewall mark */
				report_config_error(CONFIG_GENERAL_ERROR, "Virtual server %s: one packet scheduling requires UDP - resetting", FMT_VS(vs));
				vs->flags &= ~(unsigned)IP_VS_SVC_F_ONEPACKET;
			}

			/* Check port specified for udp/tcp/sctp unless persistent */
			if (!vs->persistence_timeout &&
			    !vs->vsg &&
			    !vs->vfwmark &&
			    !inet_sockaddrport(&vs->addr)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Virtual server %s: zero port only valid for persistent services - setting", FMT_VS(vs));
				vs->persistence_timeout = IPVS_SVC_PERSISTENT_TIMEOUT;
			}
		}

		/* If a virtual server group with addresses has persistence not set,
		 * make sure all the address blocks have a port, otherwise set
		 * persistence. */
		if (!vs->persistence_timeout && vs->vsg) {
			list_for_each_entry(vsge, &vs->vsg->addr_range, e_list) {
				if (!inet_sockaddrport(&vsge->addr)) {
					report_config_error(CONFIG_GENERAL_ERROR, "Virtual server %s: zero port only valid for persistent services - setting", FMT_VS(vs));
					vs->persistence_timeout = IPVS_SVC_PERSISTENT_TIMEOUT;
					break;
				}
			}
		}

		/* A virtual server using fwmarks will ignore any protocol setting, so warn if one is set */
		if (vs->service_type &&
		    ((vs->vsg && list_empty(&vs->vsg->addr_range) && !list_empty(&vs->vsg->vfwmark)) ||
		     (!vs->vsg && vs->vfwmark))) {
			report_config_error(CONFIG_GENERAL_ERROR, "Warning: Virtual server %s: protocol specified for fwmark - protocol will be ignored", FMT_VS(vs));
			vs->service_type = 0;
		}

		/* Check scheduler set */
		if (!vs->sched[0]) {
			report_config_error(CONFIG_GENERAL_ERROR, "Virtual server %s: no scheduler set, setting default '%s'", FMT_VS(vs), IPVS_DEF_SCHED);
			strcpy(vs->sched, IPVS_DEF_SCHED);
		}

		/* Set default values */
		if (vs->smtp_alert == -1) {
			if (global_data->smtp_alert_checker != -1)
				vs->smtp_alert = global_data->smtp_alert_checker;
			else if (global_data->smtp_alert != -1)
				vs->smtp_alert = global_data->smtp_alert;
			else
				vs->smtp_alert = false;
		}

		/* Spin through all the real servers */
		weight_sum = 0;
		list_for_each_entry_safe(rs, rs_tmp, &vs->rs, e_list) {
			/* Check the real server is not a duplicate of any rs earlier in the list */
			rs_removed = false;
			list_for_each_entry(rs1, &vs->rs, e_list) {
				if (rs == rs1)
					break;
				if (rs_iseq(rs, rs1)) {
					report_config_error(CONFIG_GENERAL_ERROR, "VS %s: real server %s is duplicated - removing second rs", FMT_VS(vs), FMT_RS(rs, vs));
					free_rs(rs);
					vs->rs_cnt--;
					rs_removed = true;
					break;
				}
			}
			if (rs_removed)
				continue;

			/* Set the forwarding method if necessary */
			if (rs->forwarding_method == IP_VS_CONN_F_FWD_MASK) {
				if (vs->forwarding_method == IP_VS_CONN_F_FWD_MASK) {
					report_config_error(CONFIG_GENERAL_ERROR, "Virtual server %s: no forwarding method set, setting default NAT", FMT_VS(vs));
					vs->forwarding_method = IP_VS_CONN_F_MASQ;
				}
				rs->forwarding_method = vs->forwarding_method;
#ifdef _HAVE_IPVS_TUN_TYPE_
				rs->tun_type = vs->tun_type;
				rs->tun_port = vs->tun_port;
#ifdef _HAVE_IPVS_TUN_CSUM_
				rs->tun_flags = vs->tun_flags;
#endif
#endif
			}

			/* Take default values from virtual server */
			if (rs->alpha == -1)
				rs->alpha = vs->alpha;
			if (rs->inhibit == -1)
				rs->inhibit = vs->inhibit;
			if (rs->retry == UINT_MAX)
				rs->retry = vs->retry;
			if (rs->connection_to == UINT_MAX)
				rs->connection_to = vs->connection_to;
			if (rs->delay_loop == ULONG_MAX)
				rs->delay_loop = vs->delay_loop;
			if (rs->warmup == ULONG_MAX)
				rs->warmup = vs->warmup;
			if (rs->delay_before_retry == ULONG_MAX)
				rs->delay_before_retry = vs->delay_before_retry;
			if (rs->effective_weight == INT64_MAX) {
				rs->effective_weight = vs->weight;
				rs->iweight = rs->effective_weight;
			}

			if (rs->smtp_alert == -1) {
				if (global_data->smtp_alert_checker != -1)
					rs->smtp_alert = global_data->smtp_alert_checker;
				else if (global_data->smtp_alert != -1)
					rs->smtp_alert = global_data->smtp_alert;
				else {
					/* This is inconsistent with the defaults for other smtp_alerts
					 * in order to maintain backwards compatibility */
					rs->smtp_alert = true;
				}
			}
			weight_sum += rs->effective_weight;

			/* Check if the real server is the same as the sorry server,
			 * and if so the inhibit on failure settings must match. */
			if (vs->s_svr &&
			    rs_iseq(vs->s_svr, rs)) {
				if (vs->s_svr->inhibit != rs->inhibit) {
					report_config_error(CONFIG_GENERAL_ERROR, "Virtual server %s: real server %s matches sorry server, but inhibit setting differs, %sing on sorry server", FMT_VS(vs), FMT_RS(rs, vs), rs->inhibit ? "sett" : "clear");
					vs->s_svr->inhibit = rs->inhibit;
				}

				vs->s_svr_duplicates_rs = true;
			}
		}

		if (vs->s_svr && vs->s_svr->forwarding_method == IP_VS_CONN_F_FWD_MASK) {
			if (vs->forwarding_method == IP_VS_CONN_F_FWD_MASK) {
				report_config_error(CONFIG_GENERAL_ERROR, "Virtual server %s: no forwarding method set, setting default NAT", FMT_VS(vs));
				vs->forwarding_method = IP_VS_CONN_F_MASQ;
			}
			vs->s_svr->forwarding_method = vs->forwarding_method;
#ifdef _HAVE_IPVS_TUN_TYPE_
			vs->s_svr->tun_type = vs->tun_type;
			vs->s_svr->tun_port = vs->tun_port;
#ifdef _HAVE_IPVS_TUN_CSUM_
			vs->s_svr->tun_flags = vs->tun_flags;
#endif
#endif
		}

		/* Check that the quorum isn't higher than the total weight of
		 * the real servers, otherwise we will never be able to come up. */
// TODO - Allow 253 * multiplier per MISC_CHECK if !reverse and ignore this if FILE_CHECK
		if (vs->quorum > weight_sum) {
			report_config_error(CONFIG_GENERAL_ERROR, "Warning - quorum %u for %s exceeds total weight of real servers %u, reducing quorum to %u", vs->quorum, FMT_VS(vs), weight_sum, weight_sum);
			vs->quorum = weight_sum;
		}

		/* Ensure that no virtual server hysteresis >= quorum */
		if (vs->hysteresis >= vs->quorum) {
			report_config_error(CONFIG_GENERAL_ERROR, "Virtual server %s: hysteresis %u >= quorum %u; setting hysteresis to %u",
					FMT_VS(vs), vs->hysteresis, vs->quorum, vs->quorum -1);
			vs->hysteresis = vs->quorum - 1;
		}

		/* Now check that, unless using NAT, real and virtual servers have the same port.
		 * Also if a fwmark is used, ensure that unless NAT, the real server port is 0. */
		if (vs->vsg) {
			if (!list_empty(&vs->vsg->vfwmark)) {
				list_for_each_entry(rs, &vs->rs, e_list) {
					if (rs->forwarding_method == IP_VS_CONN_F_MASQ)
						continue;
					if (inet_sockaddrport(&rs->addr))
						report_config_error(CONFIG_GENERAL_ERROR, "WARNING - fwmark virtual server %s, real server %s has port specified - port will be ignored", FMT_VS(vs), FMT_RS(rs, vs));
				}
				if (vs->s_svr && vs->s_svr->forwarding_method != IP_VS_CONN_F_MASQ &&
				    inet_sockaddrport(&vs->s_svr->addr))
					report_config_error(CONFIG_GENERAL_ERROR, "WARNING - fwmark virtual server %s, sorry server has port specified - port will be ignored", FMT_VS(vs));
			}
			list_for_each_entry(vsge, &vs->vsg->addr_range, e_list) {
				list_for_each_entry(rs, &vs->rs, e_list) {
					if (rs->forwarding_method == IP_VS_CONN_F_MASQ)
						continue;
					if (inet_sockaddrport(&rs->addr) &&
					    inet_sockaddrport(&vsge->addr) != inet_sockaddrport(&rs->addr))
						report_config_error(CONFIG_GENERAL_ERROR, "virtual server %s:[%s] and real server %s ports don't match", FMT_VS(vs), format_vsge(vsge), FMT_RS(rs, vs));
				}
				if (vs->s_svr && vs->s_svr->forwarding_method != IP_VS_CONN_F_MASQ &&
				    inet_sockaddrport(&vs->s_svr->addr) &&
				    inet_sockaddrport(&vsge->addr) != inet_sockaddrport(&vs->s_svr->addr))
					report_config_error(CONFIG_GENERAL_ERROR, "WARNING - virtual server %s, sorry server has port specified - port will be ignored", FMT_VS(vs));
			}
		} else {
			/* We can also correct errors here */
			list_for_each_entry(rs, &vs->rs, e_list) {
				if (rs->forwarding_method == IP_VS_CONN_F_MASQ) {
					if (!vs->vfwmark && !inet_sockaddrport(&rs->addr))
						inet_set_sockaddrport(&rs->addr, inet_sockaddrport(&vs->addr));
					continue;
				}

				if (vs->vfwmark) {
					if (inet_sockaddrport(&rs->addr)) {
						report_config_error(CONFIG_GENERAL_ERROR, "WARNING - fwmark virtual server %s, real server %s has port specified - clearing", FMT_VS(vs), FMT_RS(rs, vs));
						inet_set_sockaddrport(&rs->addr, 0);
					}
				} else {
					if (!inet_sockaddrport(&rs->addr))
						inet_set_sockaddrport(&rs->addr, inet_sockaddrport(&vs->addr));
					else if (inet_sockaddrport(&vs->addr) != inet_sockaddrport(&rs->addr)) {
						report_config_error(CONFIG_GENERAL_ERROR, "WARNING - virtual server %s and real server %s ports don't match - resetting", FMT_VS(vs), FMT_RS(rs, vs));
						inet_set_sockaddrport(&rs->addr, inet_sockaddrport(&vs->addr));
					}
				}
			}

			/* Check any sorry server */
			if (vs->s_svr && vs->s_svr->forwarding_method != IP_VS_CONN_F_MASQ) {
				if (vs->vfwmark) {
					if (inet_sockaddrport(&vs->s_svr->addr)) {
						report_config_error(CONFIG_GENERAL_ERROR, "WARNING - virtual server %s, sorry server has port specified - clearing", FMT_VS(vs));
						inet_set_sockaddrport(&vs->s_svr->addr, 0);
					}
				} else {
					if (!inet_sockaddrport(&vs->s_svr->addr))
						inet_set_sockaddrport(&vs->s_svr->addr, inet_sockaddrport(&vs->addr));
					else if (inet_sockaddrport(&vs->addr) != inet_sockaddrport(&vs->s_svr->addr)) {
						report_config_error(CONFIG_GENERAL_ERROR, "WARNING - virtual server %s and sorry server ports don't match - resetting", FMT_VS(vs));
						inet_set_sockaddrport(&vs->s_svr->addr, inet_sockaddrport(&vs->addr));
					}
				}
			}
		}
	}

	list_for_each_entry(checker, &checkers_queue, e_list) {
		/* Ensure any checkers that don't have ha_suspend set are enabled */
		if (!checker->vs->ha_suspend)
			checker->enabled = true;

		/* Take default values from real server */
		if (checker->alpha == -1)
			checker->alpha = checker->rs->alpha;
		if (checker->launch) {
			if (checker->retry == UINT_MAX)
				checker->retry = checker->rs->retry != UINT_MAX ? checker->rs->retry : checker->default_retry;
			if (checker->co && checker->co->connection_to == UINT_MAX)
				checker->co->connection_to = checker->rs->connection_to;
			if (checker->delay_loop == ULONG_MAX)
				checker->delay_loop = checker->rs->delay_loop;
			if (checker->warmup == ULONG_MAX)
				checker->warmup = checker->rs->warmup != ULONG_MAX ? checker->rs->warmup : checker->delay_loop;
			if (checker->delay_before_retry == ULONG_MAX) {
				checker->delay_before_retry =
					checker->rs->delay_before_retry != ULONG_MAX ?
						checker->rs->delay_before_retry :
					checker->default_delay_before_retry ?
						checker->default_delay_before_retry :
						checker->delay_loop;
			}
		}

		/* In Alpha mode also mark any checker that hasn't run as failed.
		 * Reloading is handled in migrate_checkers() */
		if (!reload) {
			if (checker->alpha) {
				set_checker_state(checker, false);
				UNSET_ALIVE(checker->rs);
			}

			/* For non alpha mode, one failure is enough initially.
			 * For alpha mode, log failure after one failure */
			checker->retry_it = checker->retry;
		}
	}

	/* Add the FIFO name to the end of the parameter list */
	if (global_data->notify_fifo.script)
		add_script_param(global_data->notify_fifo.script, global_data->notify_fifo.name);
	if (global_data->lvs_notify_fifo.script)
		add_script_param(global_data->lvs_notify_fifo.script, global_data->lvs_notify_fifo.name);

// ??? This should probably be done in check_daemon after clear_diff_services()
	set_quorum_states();

	check_check_script_security();

	return true;
}
