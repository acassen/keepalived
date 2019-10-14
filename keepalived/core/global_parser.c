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

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#ifdef _HAVE_SCHED_RT_
#include <sched.h>
#endif
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WITH_SNMP_
#include "snmp.h"
#endif

#include "global_parser.h"
#include "global_data.h"
#include "main.h"
#include "parser.h"
#include "smtp.h"
#include "utils.h"
#include "logger.h"
#ifdef _WITH_FIREWALL_
#include "vrrp_firewall.h"
#endif
#include "memory.h"

#if HAVE_DECL_CLONE_NEWNET
#include "namespaces.h"
#endif

/* Defined in kernel source file include/linux/sched.h but
 * not currently exposed to userspace */
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN	16
#endif

#ifdef _WITH_LVS_
#define LVS_MAX_TIMEOUT		(86400*31)	/* 31 days */
#endif

/* data handlers */
/* Global def handlers */
#ifdef _WITH_LINKBEAT_
static void
use_polling_handler(const vector_t *strvec)
{
	if (!strvec)
		return;

	global_data->linkbeat_use_polling = true;
}
#endif
static void
save_process_name(char const **dest, const char *src)
{
	size_t len;

	if (!src) {
		report_config_error(CONFIG_GENERAL_ERROR, "Process name missing");
		return;
	}

	if (*dest)
		FREE_CONST_PTR(*dest);

	if ((len = strlen(src)) >= TASK_COMM_LEN) {
		report_config_error(CONFIG_GENERAL_ERROR, "Process name %s more than %d characters, truncating", src, TASK_COMM_LEN - 1);
		len = TASK_COMM_LEN - 1;
	}

	*dest = STRNDUP(src, len);
}
static void
process_names_handler(__attribute__((unused)) const vector_t *strvec)
{
#ifdef _WITH_VRRP_
	save_process_name(&global_data->vrrp_process_name, "keepalived_vrrp");
#endif
#ifdef _WITH_LVS_
	save_process_name(&global_data->lvs_process_name, "keepalived_lvs");
#endif
#ifdef _WITH_BFD_
	save_process_name(&global_data->bfd_process_name, "keepalived_bfd");
#endif
}
static void
process_name_handler(const vector_t *strvec)
{
	save_process_name(&global_data->process_name, strvec_slot(strvec, 1));
}
#ifdef _WITH_VRRP_
static void
vrrp_process_name_handler(const vector_t *strvec)
{
	save_process_name(&global_data->vrrp_process_name, strvec_slot(strvec, 1));
}
#endif
#ifdef _WITH_LVS_
static void
lvs_process_name_handler(const vector_t *strvec)
{
	save_process_name(&global_data->lvs_process_name, strvec_slot(strvec, 1));
}
#endif
#ifdef _WITH_BFD_
static void
bfd_process_name_handler(const vector_t *strvec)
{
	save_process_name(&global_data->bfd_process_name, strvec_slot(strvec, 1));
}
#endif
static void
routerid_handler(const vector_t *strvec)
{
	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "routerid name missing - ignoring");
		return;
	}

	FREE_CONST_PTR(global_data->router_id);
	global_data->router_id = set_value(strvec);
}
static void
emailfrom_handler(const vector_t *strvec)
{
	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "emailfrom missing - ignoring");
		return;
	}

	FREE_CONST_PTR(global_data->email_from);
	global_data->email_from = set_value(strvec);
}
static void
smtpto_handler(const vector_t *strvec)
{
	unsigned timeout;

	/* The min value should be 1, but allow 0 to maintain backward compatibility
	 * with pre v2.0.7 */
	if (!read_unsigned_strvec(strvec, 1, &timeout, 0, UINT_MAX / TIMER_HZ, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "smtp_connect_timeout '%s' must be in [0, %u] - ignoring", strvec_slot(strvec, 1), UINT_MAX / TIMER_HZ);
		return;
	}

	if (timeout == 0) {
		report_config_error(CONFIG_GENERAL_ERROR, "smtp_conect_timeout must be greater than 0, setting to 1");
		timeout = 1;
	}

	global_data->smtp_connection_to = timeout * TIMER_HZ;
}
#ifdef _WITH_VRRP_
static void
dynamic_interfaces_handler(const vector_t *strvec)
{
	const char *str;

	global_data->dynamic_interfaces = true;

	if (vector_size(strvec) >= 2) {
		str = strvec_slot(strvec, 1);

		if (!strcmp(str, "allow_if_changes"))
			global_data->allow_if_changes = true;
		else
			report_config_error(CONFIG_GENERAL_ERROR, "Unknown dynamic_interfaces option '%s'",str);
	}
}
static void
no_email_faults_handler(__attribute__((unused))const vector_t *strvec)
{
	global_data->no_email_faults = true;
}
#endif
static void
smtpserver_handler(const vector_t *strvec)
{
	bool ret = true;
	const char *port_str = SMTP_PORT_STR;

	/* Has a port number been specified? */
	if (vector_size(strvec) >= 3)
		port_str = strvec_slot(strvec,2);

	/* It can't be an IP address if it contains '-' or '/' */
	if (!strpbrk(strvec_slot(strvec, 1), "-/"))
		ret = inet_stosockaddr(strvec_slot(strvec, 1), port_str, &global_data->smtp_server);

	if (ret)
		domain_stosockaddr(strvec_slot(strvec, 1), port_str, &global_data->smtp_server);

	if (global_data->smtp_server.ss_family == AF_UNSPEC)
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid smtp server %s %s", strvec_slot(strvec, 1), port_str);
}
static void
smtphelo_handler(const vector_t *strvec)
{
	if (vector_size(strvec) < 2)
		return;

	global_data->smtp_helo_name = STRDUP(strvec_slot(strvec, 1));
}
static void
email_handler(const vector_t *strvec)
{
	const vector_t *email_vec = read_value_block(strvec);
	unsigned int i;
	char *str;

	if (!email_vec) {
		report_config_error(CONFIG_GENERAL_ERROR, "Warning - empty notification_email block");
		return;
	}

	for (i = 0; i < vector_size(email_vec); i++) {
		str = vector_slot(email_vec, i);
		alloc_email(str);
	}

	free_strvec(email_vec);
}
static void
smtp_alert_handler(const vector_t *strvec)
{
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid value '%s' for global smtp_alert specified", strvec_slot(strvec, 1));
			return;
		}
	}

	global_data->smtp_alert = res;
}
#ifdef _WITH_VRRP_
static void
smtp_alert_vrrp_handler(const vector_t *strvec)
{
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid value '%s' for global smtp_alert_vrrp specified", strvec_slot(strvec, 1));
			return;
		}
	}

	global_data->smtp_alert_vrrp = res;
}
#endif
#ifdef _WITH_LVS_
static void
smtp_alert_checker_handler(const vector_t *strvec)
{
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid value '%s' for global smtp_alert_checker specified", strvec_slot(strvec, 1));
			return;
		}
	}

	global_data->smtp_alert_checker = res;
}
static void
checker_log_all_failures_handler(const vector_t *strvec)
{
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid value for checker_log_all_failures specified");
			return;
		}
	}

	global_data->checker_log_all_failures = res;
}
#endif
#ifdef _WITH_VRRP_
static void
default_interface_handler(const vector_t *strvec)
{
	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "default_interface requires interface name");
		return;
	}
	FREE_CONST_PTR(global_data->default_ifname);
	global_data->default_ifname = set_value(strvec);

	/* On a reload, the VRRP process needs the default_ifp */
#ifndef _DEBUG_
	if (prog_type == PROG_TYPE_VRRP)
#endif
	{
		global_data->default_ifp = if_get_by_ifname(global_data->default_ifname, IF_CREATE_IF_DYNAMIC);
		if (!global_data->default_ifp)
			report_config_error(CONFIG_GENERAL_ERROR, "WARNING - default interface %s doesn't exist", global_data->default_ifname);
	}
}
#endif
#ifdef _WITH_LVS_
static void
lvs_timeouts(const vector_t *strvec)
{
	unsigned val;
	size_t i;

	if (vector_size(strvec) < 3) {
		report_config_error(CONFIG_GENERAL_ERROR, "lvs_timeouts requires at least one option");
		return;
	}

	for (i = 1; i < vector_size(strvec); i++) {
		if (!strcmp(strvec_slot(strvec, i), "tcp")) {
			if (i == vector_size(strvec) - 1) {
				report_config_error(CONFIG_GENERAL_ERROR, "No value specified for lvs_timeout tcp - ignoring");
				continue;
			}
			if (!read_unsigned_strvec(strvec, i + 1, &val, 0, LVS_MAX_TIMEOUT, false))
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid lvs_timeout tcp (%s) - ignoring", strvec_slot(strvec, i+1));
			else
				global_data->lvs_tcp_timeout = val;
			i++;	/* skip over value */
			continue;
		}
		if (!strcmp(strvec_slot(strvec, i), "tcpfin")) {
			if (i == vector_size(strvec) - 1) {
				report_config_error(CONFIG_GENERAL_ERROR, "No value specified for lvs_timeout tcpfin - ignoring");
				continue;
			}
			if (!read_unsigned_strvec(strvec, i + 1, &val, 0, LVS_MAX_TIMEOUT, false))
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid lvs_timeout tcpfin (%s) - ignoring", strvec_slot(strvec, i+1));
			else
				global_data->lvs_tcpfin_timeout = val;
			i++;	/* skip over value */
			continue;
		}
		if (!strcmp(strvec_slot(strvec, i), "udp")) {
			if (i == vector_size(strvec) - 1) {
				report_config_error(CONFIG_GENERAL_ERROR, "No value specified for lvs_timeout udp - ignoring");
				continue;
			}
			if (!read_unsigned_strvec(strvec, i + 1, &val, 0, LVS_MAX_TIMEOUT, false))
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid lvs_timeout udp (%s) - ignoring", strvec_slot(strvec, i+1));
			else
				global_data->lvs_udp_timeout = val;
			i++;	/* skip over value */
			continue;
		}
		report_config_error(CONFIG_GENERAL_ERROR, "Unknown option %s specified for lvs_timeouts", strvec_slot(strvec, i));
	}
}
#if defined _WITH_LVS_ && defined _WITH_VRRP_
static void
lvs_syncd_handler(const vector_t *strvec)
{
	unsigned val;
	size_t i;

	if (global_data->lvs_syncd.ifname) {
		report_config_error(CONFIG_GENERAL_ERROR, "lvs_sync_daemon has already been specified as %s %s - ignoring", global_data->lvs_syncd.ifname, global_data->lvs_syncd.vrrp_name);
		return;
	}

	if (vector_size(strvec) < 3) {
		report_config_error(CONFIG_GENERAL_ERROR, "lvs_sync_daemon requires interface, VRRP instance");
		return;
	}

	if (strlen(strvec_slot(strvec, 1)) >= IP_VS_IFNAME_MAXLEN) {
		report_config_error(CONFIG_GENERAL_ERROR, "lvs_sync_daemon interface name '%s' too long - ignoring", strvec_slot(strvec, 1));
		return;
	}

	if (strlen(strvec_slot(strvec, 2)) >= IP_VS_IFNAME_MAXLEN) {
		report_config_error(CONFIG_GENERAL_ERROR, "lvs_sync_daemon vrrp interface name '%s' too long - ignoring", strvec_slot(strvec, 2));
		return;
	}

	global_data->lvs_syncd.ifname = set_value(strvec);

	if (!(global_data->lvs_syncd.vrrp_name = STRDUP(strvec_slot(strvec, 2))))
		return;

	/* This is maintained for backwards compatibility, prior to adding "id" option */
	if (vector_size(strvec) >= 4 && isdigit(strvec_slot(strvec, 3)[0])) {
		report_config_error(CONFIG_GENERAL_ERROR, "Please use keyword \"id\" before lvs_sync_daemon syncid value");
		if (!read_unsigned_strvec(strvec, 3, &val, 0, 255, false))
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid syncid (%s) - defaulting to vrid", strvec_slot(strvec, 3));
		else
			global_data->lvs_syncd.syncid = val;
		i = 4;
	}
	else
		i = 3;

	for ( ; i < vector_size(strvec); i++) {
		if (!strcmp(strvec_slot(strvec, i), "id")) {
			if (i == vector_size(strvec) - 1) {
				report_config_error(CONFIG_GENERAL_ERROR, "No value specified for lvs_sync_daemon id, defaulting to vrid");
				continue;
			}
			if (!read_unsigned_strvec(strvec, i + 1, &val, 0, 255, false))
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid syncid (%s) - defaulting to vrid", strvec_slot(strvec, i+1));
			else
				global_data->lvs_syncd.syncid = val;
			i++;	/* skip over value */
			continue;
		}
#ifdef _HAVE_IPVS_SYNCD_ATTRIBUTES_
		if (!strcmp(strvec_slot(strvec, i), "maxlen")) {
			if (i == vector_size(strvec) - 1) {
				report_config_error(CONFIG_GENERAL_ERROR, "No value specified for lvs_sync_daemon maxlen - ignoring");
				continue;
			}
			if (!read_unsigned_strvec(strvec, i + 1, &val, 0, 65535 - 20 - 8, false))
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid lvs_sync_daemon maxlen (%s) - ignoring", strvec_slot(strvec, i+1));
			else
				global_data->lvs_syncd.sync_maxlen = (uint16_t)val;
			i++;	/* skip over value */
			continue;
		}
		if (!strcmp(strvec_slot(strvec, i), "port")) {
			if (i == vector_size(strvec) - 1) {
				report_config_error(CONFIG_GENERAL_ERROR, "No value specified for lvs_sync_daemon port - ignoring");
				continue;
			}
			if (!read_unsigned_strvec(strvec, i + 1, &val, 0, 65535, false))
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid lvs_sync_daemon port (%s) - ignoring", strvec_slot(strvec, i+1));
			else
				global_data->lvs_syncd.mcast_port = (uint16_t)val;
			i++;	/* skip over value */
			continue;
		}
		if (!strcmp(strvec_slot(strvec, i), "ttl")) {
			if (i == vector_size(strvec) - 1) {
				report_config_error(CONFIG_GENERAL_ERROR, "No value specified for lvs_sync_daemon ttl - ignoring");
				continue;
			}
			if (!read_unsigned_strvec(strvec, i + 1, &val, 0, 255, false))
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid lvs_sync_daemon ttl (%s) - ignoring", strvec_slot(strvec, i+1));
			else
				global_data->lvs_syncd.mcast_ttl = (uint8_t)val;
			i++;	/* skip over value */
			continue;
		}
		if (!strcmp(strvec_slot(strvec, i), "group")) {
			if (i == vector_size(strvec) - 1) {
				report_config_error(CONFIG_GENERAL_ERROR, "No value specified for lvs_sync_daemon group - ignoring");
				continue;
			}

			if (inet_stosockaddr(strvec_slot(strvec, i+1), NULL, &global_data->lvs_syncd.mcast_group))
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid lvs_sync_daemon group (%s) - ignoring", strvec_slot(strvec, i+1));

			if ((global_data->lvs_syncd.mcast_group.ss_family == AF_INET  && !IN_MULTICAST(htonl(((struct sockaddr_in *)&global_data->lvs_syncd.mcast_group)->sin_addr.s_addr))) ||
			    (global_data->lvs_syncd.mcast_group.ss_family == AF_INET6 && !IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6 *)&global_data->lvs_syncd.mcast_group)->sin6_addr))) {
				report_config_error(CONFIG_GENERAL_ERROR, "lvs_sync_daemon group address %s is not multicast - ignoring", strvec_slot(strvec, i+1));
				global_data->lvs_syncd.mcast_group.ss_family = AF_UNSPEC;
			}

			i++;	/* skip over value */
			continue;
		}
#endif
		report_config_error(CONFIG_GENERAL_ERROR, "Unknown option %s specified for lvs_sync_daemon", strvec_slot(strvec, i));
	}
}
#endif
static void
lvs_flush_handler(__attribute__((unused)) const vector_t *strvec)
{
	global_data->lvs_flush = true;
}

static void
lvs_flush_onstop_handler(const vector_t *strvec)
{
	if (vector_size(strvec) == 1)
		global_data->lvs_flush_onstop = LVS_FLUSH_FULL;
	else if (!strcmp(strvec_slot(strvec, 1), "VS"))
		global_data->lvs_flush_onstop = LVS_FLUSH_VS;
	else
		report_config_error(CONFIG_GENERAL_ERROR, "Unknown lvs_flush_onstop type %s", strvec_slot(strvec, 1));
}
#endif
#ifdef _HAVE_SCHED_RT_
static int
get_realtime_priority(const vector_t *strvec, const char *process)
{
	int min_priority;
	int max_priority;
	int priority;

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "No %s process real-time priority specified", process);
		return -1;
	}

	min_priority = sched_get_priority_min(SCHED_RR);
	max_priority = sched_get_priority_max(SCHED_RR);

	if (!read_int_strvec(strvec, 1, &priority, INT_MIN, INT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "%s process real-time priority '%s' invalid", process, strvec_slot(strvec, 1));
		return -1;
	}

	if (priority < min_priority) {
		report_config_error(CONFIG_GENERAL_ERROR, "%s process real-time priority %d less than minimum %d - setting to minimum", process, priority, min_priority);
		priority = min_priority;
	}
	else if (priority > max_priority) {
		report_config_error(CONFIG_GENERAL_ERROR, "%s process real-time priority %d greater than maximum %d - setting to maximum", process, priority, max_priority);
		priority = max_priority;
	}

	return priority;
}
static int
get_cpu_affinity(const vector_t *strvec, cpu_set_t *set, const char *process)
{
	int cpu_id, num_cpus;
	unsigned i;

	if (!strvec)
		return -1;

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "No %s cpu_id set specified", process);
		return -1;
	}

	CPU_ZERO(set);
	/* TODO: instead of sysconf, maybe we could fetch current cpu_set via
	 * sched_getaffinity and use CPU_COUNT */
	num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	for (i = 1; i < vector_size(strvec); i++) {
		if (!read_int_strvec(strvec, i, &cpu_id, 0, num_cpus-1, true)) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid cpu_id:%d specified for %s process"
								, cpu_id, process);
			/* Reset cpu_set at first error */
			CPU_ZERO(set);
			return -1;
		}

		CPU_SET(cpu_id, set);
	}

	return 0;
}
#if HAVE_DECL_RLIMIT_RTTIME == 1
static rlim_t
get_rt_rlimit(const vector_t *strvec, const char *process)
{
	unsigned limit;
	rlim_t rlim;

	if (!read_unsigned_strvec(strvec, 1, &limit, 1, UINT32_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid %s real-time limit - %s", process, strvec_slot(strvec, 1));
		return 0;
	}

	rlim = limit;
	return rlim;
}
#endif
#endif
static int8_t
get_priority(const vector_t *strvec, const char *process)
{
	int priority;

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "No %s process priority specified", process);
		return 0;
	}

	if (!read_int_strvec(strvec, 1, &priority, -20, 19, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid %s process priority specified", process);
		return 0;
	}

	return (int8_t)priority;
}

#ifdef _WITH_VRRP_
static void
vrrp_mcast_group4_handler(const vector_t *strvec)
{
	struct sockaddr_in *mcast = &global_data->vrrp_mcast_group4;
	int ret;

	ret = inet_stosockaddr(strvec_slot(strvec, 1), 0, (struct sockaddr_storage *)mcast);
	if (ret < 0) {
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: Cant parse vrrp_mcast_group4 [%s]. Skipping"
				   , strvec_slot(strvec, 1));
	}
}
static void
vrrp_mcast_group6_handler(const vector_t *strvec)
{
	struct sockaddr_in6 *mcast = &global_data->vrrp_mcast_group6;
	int ret;

	ret = inet_stosockaddr(strvec_slot(strvec, 1), 0, (struct sockaddr_storage *)mcast);
	if (ret < 0) {
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: Cant parse vrrp_mcast_group6 [%s]. Skipping"
				   , strvec_slot(strvec, 1));
	}
}
static void
vrrp_garp_delay_handler(const vector_t *strvec)
{
	unsigned timeout;

        if (!read_unsigned_strvec(strvec, 1, &timeout, 0, UINT_MAX / TIMER_HZ, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp_garp_master_delay '%s' invalid - ignoring", strvec_slot(strvec, 1));
                return;
        }

	global_data->vrrp_garp_delay = timeout * TIMER_HZ;
}
static void
vrrp_garp_rep_handler(const vector_t *strvec)
{
	unsigned repeats;

	/* The min value should be 1, but allow 0 to maintain backward compatibility
	 * with pre v2.0.7 */
	if (!read_unsigned_strvec(strvec, 1, &repeats, 0, UINT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp_garp_master_repeat '%s' invalid - ignoring", strvec_slot(strvec, 1));
		return;
	}

	if (repeats == 0) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp_garp_master_repeat must be greater than 0, setting to 1");
		repeats = 1;
	}

	global_data->vrrp_garp_rep = repeats;

}
static void
vrrp_garp_refresh_handler(const vector_t *strvec)
{
        unsigned refresh;

        if (!read_unsigned_strvec(strvec, 1, &refresh, 0, UINT_MAX, true)) {
                report_config_error(CONFIG_GENERAL_ERROR, "Invalid vrrp_garp_master_refresh '%s' - ignoring", strvec_slot(strvec, 1));
                global_data->vrrp_garp_refresh.tv_sec = 0;
        }
        else
		global_data->vrrp_garp_refresh.tv_sec = refresh;

        global_data->vrrp_garp_refresh.tv_usec = 0;
}
static void
vrrp_garp_refresh_rep_handler(const vector_t *strvec)
{
        unsigned repeats;

        /* The min value should be 1, but allow 0 to maintain backward compatibility
         * with pre v2.0.7 */
        if (!read_unsigned_strvec(strvec, 1, &repeats, 0, UINT_MAX, true)) {
                report_config_error(CONFIG_GENERAL_ERROR, "vrrp_garp_master_refresh_repeat '%s' invalid - ignoring", strvec_slot(strvec, 1));
                return;
        }

        if (repeats == 0) {
                report_config_error(CONFIG_GENERAL_ERROR, "vrrp_garp_master_refresh_repeat must be greater than 0, setting to 1");
                repeats = 1;
        }

	global_data->vrrp_garp_refresh_rep = repeats;

}
static void
vrrp_garp_lower_prio_delay_handler(const vector_t *strvec)
{
        unsigned delay;

        if (!read_unsigned_strvec(strvec, 1, &delay, 0, UINT_MAX / TIMER_HZ, true)) {
                report_config_error(CONFIG_GENERAL_ERROR, "vrrp_garp_lower_prio_delay '%s' invalid - ignoring", strvec_slot(strvec, 1));
                return;
        }

	global_data->vrrp_garp_lower_prio_delay = delay * TIMER_HZ;
}
static void
vrrp_garp_lower_prio_rep_handler(const vector_t *strvec)
{
	unsigned garp_lower_prio_rep;

        if (!read_unsigned_strvec(strvec, 1, &garp_lower_prio_rep, 0, INT_MAX, true)) {
                report_config_error(CONFIG_GENERAL_ERROR, "Invalid vrrp_garp_lower_prio_repeat '%s'", strvec_slot(strvec, 1));
                return;
        }

	global_data->vrrp_garp_lower_prio_rep = garp_lower_prio_rep;
}
static void
vrrp_garp_interval_handler(const vector_t *strvec)
{
	double interval;

	if (!read_double_strvec(strvec, 1, &interval, 1.0F / TIMER_HZ, (unsigned)(UINT_MAX / TIMER_HZ), true))
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp_garp_interval '%s' is invalid", strvec_slot(strvec, 1));
	else
		global_data->vrrp_garp_interval = (unsigned)(interval * TIMER_HZ);

	if (global_data->vrrp_garp_interval >= 1 * TIMER_HZ)
		log_message(LOG_INFO, "The vrrp_garp_interval is very large - %s seconds", strvec_slot(strvec, 1));
}
static void
vrrp_gna_interval_handler(const vector_t *strvec)
{
	double interval;

	if (!read_double_strvec(strvec, 1, &interval, 1.0F / TIMER_HZ, (unsigned)(UINT_MAX / TIMER_HZ), true))
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp_gna_interval '%s' is invalid", strvec_slot(strvec, 1));
	else
		global_data->vrrp_gna_interval = (unsigned)(interval * TIMER_HZ);

	if (global_data->vrrp_gna_interval >= 1 * TIMER_HZ)
		log_message(LOG_INFO, "The vrrp_gna_interval is very large - %s seconds", strvec_slot(strvec, 1));
}
static void
vrrp_min_garp_handler(const vector_t *strvec)
{
	int res = false;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid value for vrrp_min_garp specified");
			return;
		}

		if (!res)
			return;
	}

	/* Set to only send 1 gratuitous ARP/NA message with no repeat, but don't
	 * overwrite any parameters already set. */
	if (global_data->vrrp_garp_rep == VRRP_GARP_REP)
		global_data->vrrp_garp_rep = 1;
	if (global_data->vrrp_garp_refresh.tv_sec == VRRP_GARP_REFRESH)
		global_data->vrrp_garp_refresh.tv_sec = 0;
	if (global_data->vrrp_garp_refresh_rep == VRRP_GARP_REFRESH_REP)
		global_data->vrrp_garp_refresh_rep = 0;
	if (global_data->vrrp_garp_delay == VRRP_GARP_DELAY)
		global_data->vrrp_garp_delay = 0;
}
static void
vrrp_lower_prio_no_advert_handler(const vector_t *strvec)
{
	int res;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0)
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid value for vrrp_lower_prio_no_advert specified");
		else
			global_data->vrrp_lower_prio_no_advert = res;
	}
	else
		global_data->vrrp_lower_prio_no_advert = true;
}
static void
vrrp_higher_prio_send_advert_handler(const vector_t *strvec)
{
	int res;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0)
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid value for vrrp_higher_prio_send_advert specified");
		else
			global_data->vrrp_higher_prio_send_advert = res;
	}
	else
		global_data->vrrp_higher_prio_send_advert = true;
}
#ifdef _WITH_IPTABLES_
static void
vrrp_iptables_handler(const vector_t *strvec)
{
	if (vector_size(strvec) >= 2) {
		if (strlen(strvec_slot(strvec,1)) >= sizeof(global_data->vrrp_iptables_inchain)-1) {
			report_config_error(CONFIG_GENERAL_ERROR, "VRRP Error : iptables in chain name too long - ignored");
			return;
		}
		strcpy(global_data->vrrp_iptables_inchain, strvec_slot(strvec,1));
		if (vector_size(strvec) >= 3) {
			if (strlen(strvec_slot(strvec,2)) >= sizeof(global_data->vrrp_iptables_outchain)-1) {
				report_config_error(CONFIG_GENERAL_ERROR, "VRRP Error : iptables out chain name too long - ignored");
				return;
			}
			strcpy(global_data->vrrp_iptables_outchain, strvec_slot(strvec,2));
		}
	} else {
		strcpy(global_data->vrrp_iptables_inchain, DEFAULT_IPTABLES_CHAIN_IN);
		strcpy(global_data->vrrp_iptables_outchain, DEFAULT_IPTABLES_CHAIN_OUT);
	}
}
#ifdef _HAVE_LIBIPSET_
static void
vrrp_ipsets_handler(const vector_t *strvec)
{
	size_t len;

	if (vector_size(strvec) >= 2) {
		if (strlen(strvec_slot(strvec,1)) >= sizeof(global_data->vrrp_ipset_address)-1) {
			report_config_error(CONFIG_GENERAL_ERROR, "VRRP Error : ipset address name too long - ignored");
			return;
		}
		strcpy(global_data->vrrp_ipset_address, strvec_slot(strvec,1));
	}
	else {
		global_data->using_ipsets = false;
		return;
	}

	if (vector_size(strvec) >= 3) {
		if (strlen(strvec_slot(strvec,2)) >= sizeof(global_data->vrrp_ipset_address6)-1) {
			report_config_error(CONFIG_GENERAL_ERROR, "VRRP Error : ipset IPv6 address name too long - ignored");
			return;
		}
		strcpy(global_data->vrrp_ipset_address6, strvec_slot(strvec,2));
	}
	else {
		/* No second set specified, copy first name and add "6" */
		strcpy(global_data->vrrp_ipset_address6, global_data->vrrp_ipset_address);
		global_data->vrrp_ipset_address6[sizeof(global_data->vrrp_ipset_address6) - 2] = '\0';
		strcat(global_data->vrrp_ipset_address6, "6");
	}
	if (vector_size(strvec) >= 4) {
		if (strlen(strvec_slot(strvec,3)) >= sizeof(global_data->vrrp_ipset_address_iface6)-1) {
			report_config_error(CONFIG_GENERAL_ERROR, "VRRP Error : ipset IPv6 address_iface name too long - ignored");
			return;
		}
		strcpy(global_data->vrrp_ipset_address_iface6, strvec_slot(strvec,3));
	}
	else {
		/* No third set specified, copy second name and add "_if6" */
		strcpy(global_data->vrrp_ipset_address_iface6, global_data->vrrp_ipset_address6);
		len = strlen(global_data->vrrp_ipset_address_iface6);
		if (global_data->vrrp_ipset_address_iface6[len-1] == '6')
			global_data->vrrp_ipset_address_iface6[--len] = '\0';
		global_data->vrrp_ipset_address_iface6[sizeof(global_data->vrrp_ipset_address_iface6) - 5] = '\0';
		strcat(global_data->vrrp_ipset_address_iface6, "_if6");
	}
	if (vector_size(strvec) >= 5) {
		if (strlen(strvec_slot(strvec,4)) >= sizeof(global_data->vrrp_ipset_igmp)-1) {
			report_config_error(CONFIG_GENERAL_ERROR, "VRRP Error : ipset IGMP name too long - ignored");
			return;
		}
		strcpy(global_data->vrrp_ipset_igmp, strvec_slot(strvec,4));
	}
	else {
		/* No second set specified, copy first name and add "_igmp" */
		strcpy(global_data->vrrp_ipset_igmp, global_data->vrrp_ipset_address);
		global_data->vrrp_ipset_address6[sizeof(global_data->vrrp_ipset_igmp) - 6] = '\0';
		strcat(global_data->vrrp_ipset_igmp, "_igmp");
	}
	if (vector_size(strvec) >= 6) {
		if (strlen(strvec_slot(strvec,5)) >= sizeof(global_data->vrrp_ipset_mld)-1) {
			report_config_error(CONFIG_GENERAL_ERROR, "VRRP Error : ipset MLD name too long - ignored");
			return;
		}
		strcpy(global_data->vrrp_ipset_mld, strvec_slot(strvec,5));
	}
	else {
		/* No second set specified, copy first name and add "_mld" */
		strcpy(global_data->vrrp_ipset_mld, global_data->vrrp_ipset_address);
		global_data->vrrp_ipset_mld[sizeof(global_data->vrrp_ipset_mld) - 5] = '\0';
		strcat(global_data->vrrp_ipset_mld, "_mld");
	}
}
#endif
#endif
#ifdef _WITH_NFTABLES_
static void
vrrp_nftables_handler(__attribute__((unused)) const vector_t *strvec)
{
	const char *name;

	if (global_data->vrrp_nf_table_name) {
		report_config_error(CONFIG_GENERAL_ERROR, "nftables already specified - ignoring");
		return;
	}

	if (vector_size(strvec) >= 2) {
		if (strlen(strvec_slot(strvec, 1)) >= NFT_TABLE_MAXNAMELEN) {
			report_config_error(CONFIG_GENERAL_ERROR, "nftables table name too long - ignoring");
			return;
		}
		name = strvec_slot(strvec, 1);
	}
	else {
		/* Table named defaults to "keepalived" */
		name = DEFAULT_NFTABLES_TABLE;
	}

	global_data->vrrp_nf_table_name = STRDUP(name);
	global_data->vrrp_nf_chain_priority = -1;
}
static void
vrrp_nftables_priority_handler(const vector_t *strvec)
{
	int priority;

	if (read_int_strvec(strvec, 1, &priority, INT32_MIN, INT32_MAX, false))
		global_data->vrrp_nf_chain_priority = priority;
	else
		report_config_error(CONFIG_INVALID_NUMBER, "invalid nftables chain priority '%s'", strvec_slot(strvec, 1));
}
static void
vrrp_nftables_counters_handler(__attribute__((unused)) const vector_t *strvec)
{
	global_data->vrrp_nf_counters = true;
}
static void
vrrp_nftables_ifindex_handler(__attribute__((unused)) const vector_t *strvec)
{
	global_data->vrrp_nf_ifindex = true;
}
#endif
static void
vrrp_version_handler(const vector_t *strvec)
{
	int version;

	if (!read_int_strvec(strvec, 1, &version, 2, 3, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "VRRP Error: Version must be either 2 or 3");
		return;
	}

	global_data->vrrp_version = version;
}
static void
vrrp_check_unicast_src_handler(__attribute__((unused)) const vector_t *strvec)
{
	global_data->vrrp_check_unicast_src = 1;
}
static void
vrrp_check_adv_addr_handler(__attribute__((unused)) const vector_t *strvec)
{
	global_data->vrrp_skip_check_adv_addr = 1;
}
static void
vrrp_strict_handler(__attribute__((unused)) const vector_t *strvec)
{
	global_data->vrrp_strict = 1;
}
static void
vrrp_prio_handler(const vector_t *strvec)
{
	global_data->vrrp_process_priority = get_priority(strvec, "vrrp");
}
static void
vrrp_no_swap_handler(__attribute__((unused)) const vector_t *strvec)
{
	global_data->vrrp_no_swap = true;
}
#ifdef _HAVE_SCHED_RT_
static void
vrrp_rt_priority_handler(const vector_t *strvec)
{
	int priority = get_realtime_priority(strvec, "vrrp");

	if (priority >= 0)
		global_data->vrrp_realtime_priority = priority;
}
static void
vrrp_cpu_affinity_handler(const vector_t *strvec)
{
	get_cpu_affinity(strvec, &global_data->vrrp_cpu_mask, "vrrp");
}
#if HAVE_DECL_RLIMIT_RTTIME == 1
static void
vrrp_rt_rlimit_handler(const vector_t *strvec)
{
	global_data->vrrp_rlimit_rt = get_rt_rlimit(strvec, "vrrp");
}
#endif
#endif
#endif
static void
notify_fifo(const vector_t *strvec, const char *type, notify_fifo_t *fifo)
{
	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "No %snotify_fifo name specified", type);
		return;
	}

	if (fifo->name) {
		report_config_error(CONFIG_GENERAL_ERROR, "%snotify_fifo already specified - ignoring %s", type, strvec_slot(strvec,1));
		return;
	}

	if (vector_size(strvec) > 2) {
		if (set_script_uid_gid(strvec, 2, &fifo->uid, &fifo->gid)) {
			log_message(LOG_INFO, "Invalid user/group for %s fifo %s - ignoring", type, fifo->name);
			return;
		}
	}
	else {
		if (set_default_script_user(NULL, NULL)) {
			log_message(LOG_INFO, "Failed to set default user for %s fifo %s - ignoring", type, fifo->name);
			return;
		}

		fifo->uid = default_script_uid;
		fifo->gid = default_script_gid;
	}

	fifo->name = STRDUP(strvec_slot(strvec, 1));
}
static void
notify_fifo_script(const vector_t *strvec, const char *type, notify_fifo_t *fifo)
{
	char *id_str;

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "No %snotify_fifo_script specified", type);
		return;
	}

	if (fifo->script) {
		report_config_error(CONFIG_GENERAL_ERROR, "%snotify_fifo_script already specified - ignoring %s", type, strvec_slot(strvec,1));
		return;
	}

	id_str = MALLOC(strlen(type) + strlen("notify_fifo") + 1);
	strcpy(id_str, type);
	strcat(id_str, "notify_fifo");
	fifo->script = notify_script_init(1, id_str);

	FREE(id_str);
}
static void
global_notify_fifo(const vector_t *strvec)
{
	notify_fifo(strvec, "", &global_data->notify_fifo);
}
static void
global_notify_fifo_script(const vector_t *strvec)
{
	notify_fifo_script(strvec, "", &global_data->notify_fifo);
}
#ifdef _WITH_VRRP_
static void
vrrp_notify_fifo(const vector_t *strvec)
{
	notify_fifo(strvec, "vrrp_", &global_data->vrrp_notify_fifo);
}
static void
vrrp_notify_fifo_script(const vector_t *strvec)
{
	notify_fifo_script(strvec, "vrrp_", &global_data->vrrp_notify_fifo);
}
static void
vrrp_notify_priority_changes(const vector_t *strvec)
{
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid value '%s' for global vrrp_notify_priority_changes specified", strvec_slot(strvec, 1));
			return;
		}
	}

	global_data->vrrp_notify_priority_changes = res;
}
#endif
#ifdef _WITH_LVS_
static void
lvs_notify_fifo(const vector_t *strvec)
{
	notify_fifo(strvec, "lvs_", &global_data->lvs_notify_fifo);
}
static void
lvs_notify_fifo_script(const vector_t *strvec)
{
	notify_fifo_script(strvec, "lvs_", &global_data->lvs_notify_fifo);
}
#endif
#ifdef _WITH_LVS_
static void
checker_prio_handler(const vector_t *strvec)
{
	global_data->checker_process_priority = get_priority(strvec, "checker");
}
static void
checker_no_swap_handler(__attribute__((unused)) const vector_t *strvec)
{
	global_data->checker_no_swap = true;
}
#ifdef _HAVE_SCHED_RT_
static void
checker_rt_priority_handler(const vector_t *strvec)
{
	int priority = get_realtime_priority(strvec, "checker");

	if (priority >= 0)
		global_data->checker_realtime_priority = priority;
}
static void
checker_cpu_affinity_handler(const vector_t *strvec)
{
	get_cpu_affinity(strvec, &global_data->checker_cpu_mask, "checker");
}
#if HAVE_DECL_RLIMIT_RTTIME == 1
static void
checker_rt_rlimit_handler(const vector_t *strvec)
{
	global_data->checker_rlimit_rt = get_rt_rlimit(strvec, "checker");
}
#endif
#endif
#endif
#ifdef _WITH_BFD_
static void
bfd_prio_handler(const vector_t *strvec)
{
	global_data->bfd_process_priority = get_priority(strvec, "bfd");
}
static void
bfd_no_swap_handler(__attribute__((unused)) const vector_t *strvec)
{
	global_data->bfd_no_swap = true;
}
#ifdef _HAVE_SCHED_RT_
static void
bfd_rt_priority_handler(const vector_t *strvec)
{
	int priority = get_realtime_priority(strvec, "bfd");

	if (priority >= 0)
		global_data->bfd_realtime_priority = priority;
}
static void
bfd_cpu_affinity_handler(const vector_t *strvec)
{
	get_cpu_affinity(strvec, &global_data->bfd_cpu_mask, "bfd");
}
#if HAVE_DECL_RLIMIT_RTTIME == 1
static void
bfd_rt_rlimit_handler(const vector_t *strvec)
{
	global_data->bfd_rlimit_rt = get_rt_rlimit(strvec, "bfd");
}
#endif
#endif
#endif
#ifdef _WITH_SNMP_
static void
snmp_socket_handler(const vector_t *strvec)
{
	if (vector_size(strvec) > 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "Too many parameters specified for snmp_socket - ignoring");
		return;
	}

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "SNMP error : snmp socket name missing");
		return;
	}

	if (strlen(strvec_slot(strvec,1)) > PATH_MAX - 1) {
		report_config_error(CONFIG_GENERAL_ERROR, "SNMP error : snmp socket name too long - ignored");
		return;
	}

	if (global_data->snmp_socket) {
		report_config_error(CONFIG_GENERAL_ERROR, "SNMP socket already set to %s - ignoring", global_data->snmp_socket);
		return;
	}

	global_data->snmp_socket = STRDUP(strvec_slot(strvec, 1));
}
static void
trap_handler(__attribute__((unused)) const vector_t *strvec)
{
	global_data->enable_traps = true;
}
#ifdef _WITH_SNMP_VRRP_
static void
snmp_vrrp_handler(__attribute__((unused)) const vector_t *strvec)
{
	global_data->enable_snmp_vrrp = true;
}
#endif
#ifdef _WITH_SNMP_RFC_
static void
snmp_rfc_handler(__attribute__((unused)) const vector_t *strvec)
{
#ifdef _WITH_SNMP_RFCV2_
	global_data->enable_snmp_rfcv2 = true;
#endif
#ifdef _WITH_SNMP_RFCV3_
	global_data->enable_snmp_rfcv3 = true;
#endif
}
#endif
#ifdef _WITH_SNMP_RFCV2_
static void
snmp_rfcv2_handler(__attribute__((unused)) const vector_t *strvec)
{
	global_data->enable_snmp_rfcv2 = true;
}
#endif
#ifdef _WITH_SNMP_RFCV3_
static void
snmp_rfcv3_handler(__attribute__((unused)) const vector_t *strvec)
{
	global_data->enable_snmp_rfcv3 = true;
}
#endif
#ifdef _WITH_SNMP_CHECKER_
static void
snmp_checker_handler(__attribute__((unused)) const vector_t *strvec)
{
	global_data->enable_snmp_checker = true;
}
#endif
#endif
#if HAVE_DECL_CLONE_NEWNET
static void
net_namespace_handler(const vector_t *strvec)
{
	if (!strvec)
		return;

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "net_namespace name missing - ignoring");
		return;
	}

	if (!global_data->network_namespace) {
		global_data->network_namespace = set_value(strvec);
		use_pid_dir = true;
	}
	else
		report_config_error(CONFIG_GENERAL_ERROR, "Duplicate net_namespace definition %s - ignoring", strvec_slot(strvec, 1));
}

static void
namespace_ipsets_handler(const vector_t *strvec)
{
	if (!strvec)
		return;

	global_data->namespace_with_ipsets = true;
}
#endif

#ifdef _WITH_DBUS_
static void
enable_dbus_handler(__attribute__((unused)) const vector_t *strvec)
{
	global_data->enable_dbus = true;
}

static void
dbus_service_name_handler(const vector_t *strvec)
{
	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "dbus_service_name missing - ignoring");
		return;
	}

	FREE_CONST_PTR(global_data->dbus_service_name);
	global_data->dbus_service_name = set_value(strvec);
}
#endif

static void
instance_handler(const vector_t *strvec)
{
	if (!strvec)
		return;

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "instance name missing - ignoring");
		return;
	}

	if (!reload) {
		if (!global_data->instance_name) {
			global_data->instance_name = set_value(strvec);
			use_pid_dir = true;
		}
		else
			report_config_error(CONFIG_GENERAL_ERROR, "Duplicate instance definition %s - ignoring", strvec_slot(strvec, 1));
	}
}

static void
use_pid_dir_handler(const vector_t *strvec)
{
	if (!strvec)
		return;

	use_pid_dir = true;
}

static void
script_user_handler(const vector_t *strvec)
{
	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "No script username specified");
		return;
	}

	if (set_default_script_user(strvec_slot(strvec, 1), vector_size(strvec) > 2 ? strvec_slot(strvec, 2) : NULL))
		report_config_error(CONFIG_GENERAL_ERROR, "Error setting global script uid/gid");
}

static void
script_security_handler(__attribute__((unused)) const vector_t *strvec)
{
	script_security = true;
}

static void
child_wait_handler(const vector_t *strvec)
{
	unsigned secs;

	if (!strvec)
		return;

	if (!read_unsigned_strvec(strvec, 1, &secs, 0, UINT_MAX, false)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid child_wait_time %s", strvec_slot(strvec, 1));
		return;
	}

	child_wait_time = secs;
}

#ifdef _WITH_VRRP_
static void
vrrp_rx_bufs_policy_handler(const vector_t *strvec)
{
	unsigned rx_buf_size;
	unsigned i;

	if (!strvec)
		return;

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp_rx_bufs_policy missing");
		return;
	}

	for (i = 1; i < vector_size(strvec); i++) {
		if (!strcasecmp(strvec_slot(strvec, i), "MTU"))
			global_data->vrrp_rx_bufs_policy |= RX_BUFS_POLICY_MTU;
		else if (!strcasecmp(strvec_slot(strvec, i), "ADVERT"))
			global_data->vrrp_rx_bufs_policy |= RX_BUFS_POLICY_ADVERT;
		else {
			if (!read_unsigned_strvec(strvec, 1, &rx_buf_size, 0, UINT_MAX, false))
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid vrrp_rx_bufs_policy %s", strvec_slot(strvec, i));
			else {
				global_data->vrrp_rx_bufs_size = rx_buf_size;
				global_data->vrrp_rx_bufs_policy |= RX_BUFS_SIZE;
			}
		}
	}

	if ((global_data->vrrp_rx_bufs_policy & RX_BUFS_SIZE) &&
	    (global_data->vrrp_rx_bufs_policy & (RX_BUFS_POLICY_MTU | RX_BUFS_POLICY_ADVERT))) {
		report_config_error(CONFIG_GENERAL_ERROR, "Cannot set vrrp_rx_bufs_policy size and policy, ignoring policy");
		global_data->vrrp_rx_bufs_policy &= ~(RX_BUFS_POLICY_MTU | RX_BUFS_POLICY_ADVERT);
	}
	else if ((global_data->vrrp_rx_bufs_policy & RX_BUFS_POLICY_MTU) &&
		 (global_data->vrrp_rx_bufs_policy & RX_BUFS_POLICY_ADVERT)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Cannot set both vrrp_rx_bufs_policy MTU and ADVERT, ignoring ADVERT");
		global_data->vrrp_rx_bufs_policy &= ~RX_BUFS_POLICY_ADVERT;
	}
}

static void
vrrp_rx_bufs_multiplier_handler(const vector_t *strvec)
{
	unsigned rx_buf_mult;

	if (!strvec)
		return;

	if (vector_size(strvec) != 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid vrrp_rx_bufs_multiplier");
		return;
	}

	if (!read_unsigned_strvec(strvec, 1, &rx_buf_mult, 1, UINT_MAX, false))
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid vrrp_rx_bufs_multiplier %s", strvec_slot(strvec, 1));
	else
		global_data->vrrp_rx_bufs_multiples = rx_buf_mult;
}
#endif

#if defined _WITH_VRRP_ || defined _WITH_LVS_
static unsigned
get_netlink_rcv_bufs_size(const vector_t *strvec, const char *type)
{
	unsigned val;

	if (!strvec)
		return 0;

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "%s_rcv_bufs size missing", type);
		return 0;
	}

	if (!read_unsigned_strvec(strvec, 1, &val, 0, UINT_MAX, false)) {
		report_config_error(CONFIG_GENERAL_ERROR, "%s_rcv_bufs size (%s) invalid", type, strvec_slot(strvec, 1));
		return 0;
	}

	return val;
}
#endif

#ifdef _WITH_VRRP_
static void
vrrp_netlink_monitor_rcv_bufs_handler(const vector_t *strvec)
{
	unsigned val;

	if (!strvec)
		return;

	val = get_netlink_rcv_bufs_size(strvec, "vrrp_netlink_monitor");

	if (val)
		global_data->vrrp_netlink_monitor_rcv_bufs = val;
}

static void
vrrp_netlink_monitor_rcv_bufs_force_handler(const vector_t *strvec)
{
	int res = true;

	if (!strvec)
		return;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid value '%s' for global vrrp_netlink_monitor_rcv_bufs_force specified", strvec_slot(strvec, 1));
			return;
		}
	}

	global_data->vrrp_netlink_monitor_rcv_bufs_force = res;
}

static void
vrrp_netlink_cmd_rcv_bufs_handler(const vector_t *strvec)
{
	unsigned val;

	if (!strvec)
		return;

	val = get_netlink_rcv_bufs_size(strvec, "vrrp_netlink_cmd");

	if (val)
		global_data->vrrp_netlink_cmd_rcv_bufs = val;
}

static void
vrrp_netlink_cmd_rcv_bufs_force_handler(const vector_t *strvec)
{
	int res = true;

	if (!strvec)
		return;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid value '%s' for global vrrp_netlink_cmd_rcv_bufs_force specified", strvec_slot(strvec, 1));
			return;
		}
	}

	global_data->vrrp_netlink_cmd_rcv_bufs_force = res;
}

#ifdef _WITH_CN_PROC_
static void
process_monitor_rcv_bufs_handler(const vector_t *strvec)
{
	unsigned val;

	if (!strvec)
		return;

	val = get_netlink_rcv_bufs_size(strvec, "process_monitor");

	if (val)
		global_data->process_monitor_rcv_bufs = val;
}

static void
process_monitor_rcv_bufs_force_handler(const vector_t *strvec)
{
	int res = true;

	if (!strvec)
		return;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid value '%s' for global process_monitor_rcv_bufs_force specified", strvec_slot(strvec, 1));
			return;
		}
	}

	global_data->process_monitor_rcv_bufs_force = res;
}
#endif
#endif

#ifdef _WITH_LVS_
static void
lvs_netlink_monitor_rcv_bufs_handler(const vector_t *strvec)
{
	unsigned val;

	if (!strvec)
		return;

	val = get_netlink_rcv_bufs_size(strvec, "lvs_netlink_monitor");

	if (val)
		global_data->lvs_netlink_monitor_rcv_bufs = val;
}

static void
lvs_netlink_monitor_rcv_bufs_force_handler(const vector_t *strvec)
{
	int res = true;

	if (!strvec)
		return;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid value '%s' for global lvs_netlink_monitor_rcv_bufs_force specified", strvec_slot(strvec, 1));
			return;
		}
	}

	global_data->lvs_netlink_monitor_rcv_bufs_force = res;
}

static void
lvs_netlink_cmd_rcv_bufs_handler(const vector_t *strvec)
{
	unsigned val;

	if (!strvec)
		return;

	val = get_netlink_rcv_bufs_size(strvec, "lvs_netlink_cmd");

	if (val)
		global_data->lvs_netlink_cmd_rcv_bufs = val;
}

static void
lvs_netlink_cmd_rcv_bufs_force_handler(const vector_t *strvec)
{
	int res = true;

	if (!strvec)
		return;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid value '%s' for global lvs_netlink_cmd_rcv_bufs_force specified", strvec_slot(strvec, 1));
			return;
		}
	}

	global_data->lvs_netlink_cmd_rcv_bufs_force = res;
}

static void
rs_init_notifies_handler(const vector_t *strvec)
{
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid value '%s' for global rs_init_notifies specified", strvec_slot(strvec, 1));
			return;
		}
	}

	global_data->rs_init_notifies = res;
}

static void
no_checker_emails_handler(const vector_t *strvec)
{
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec,1));
		if (res < 0) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid value '%s' for global no_checker_emails specified", strvec_slot(strvec, 1));
			return;
		}
	}

	global_data->no_checker_emails = res;
}
#endif

static void
umask_handler(const vector_t *strvec)
{
	long umask_long;
	mode_t umask_bits = 0;
	const char *mask = strvec_slot(strvec, 1);
	char *endptr;
	unsigned i;
	const char *p;

	if (umask_cmdline) {
		log_message(LOG_INFO, "umask command line option specified, ignoring config option");
		return;
	}

	if (isdigit(mask[0])) {
		if (vector_size(strvec) != 2) {
			report_config_error(CONFIG_GENERAL_ERROR, "%s parameter(s) to umask option", vector_size(strvec) == 1 ? "Missing" : "Extra");
			return;
		}
		umask_long = strtol(mask, &endptr, 0);
		if (*endptr || umask_long < 0 || umask_long & ~(S_IRWXU | S_IRWXG | S_IRWXO)) {
			report_config_error(CONFIG_GENERAL_ERROR, "invalid umask value %s", mask);
			return;
		}
		umask_bits = umask_long & (S_IRWXU | S_IRWXG | S_IRWXO);
	}
	else {
		bool need_or = false;
		for (i = 1; i < vector_size(strvec); i++) {
			for (p = strvec_slot(strvec, i); *p; ) {
				if (need_or) {
					if (*p == '|') {
						need_or = false;
						p++;
						continue;
					}

					report_config_error(CONFIG_GENERAL_ERROR, "Invalid umask syntax %s", strvec_slot(strvec, i));
					return;
				}

				if      (!strncmp(p, "IRUSR", 5)) umask_bits |= S_IRUSR;
				else if (!strncmp(p, "IWUSR", 5)) umask_bits |= S_IWUSR;
				else if (!strncmp(p, "IXUSR", 5)) umask_bits |= S_IXUSR;
				else if (!strncmp(p, "IRGRP", 5)) umask_bits |= S_IRGRP;
				else if (!strncmp(p, "IWGRP", 5)) umask_bits |= S_IWGRP;
				else if (!strncmp(p, "IXGRP", 5)) umask_bits |= S_IXGRP;
				else if (!strncmp(p, "IROTH", 5)) umask_bits |= S_IROTH;
				else if (!strncmp(p, "IWOTH", 5)) umask_bits |= S_IWOTH;
				else if (!strncmp(p, "IXOTH", 5)) umask_bits |= S_IXOTH;
				else {
					report_config_error(CONFIG_GENERAL_ERROR, "Unknown umask bit %s", p);
					return;
				}

				p += 5;
				need_or = true;
			}
		}
		if (!need_or) {
			report_config_error(CONFIG_GENERAL_ERROR, "umask missing bit value");
			return;
		}
	}

	umask_val = umask_bits;
	umask(umask_bits);

#ifdef _MEM_CHECK_
	update_mem_check_log_perms(umask_bits);
#endif
#ifdef ENABLE_LOG_TO_FILE
	update_log_file_perms(umask_bits);
#endif
}

#ifdef _WITH_VRRP_
static void
vrrp_startup_delay_handler(const vector_t *strvec)
{
	double startup_delay;

	if (!read_double_strvec(strvec, 1, &startup_delay, 0.001F / TIMER_HZ, (unsigned)(UINT_MAX / TIMER_HZ), true))
		report_config_error(CONFIG_GENERAL_ERROR, "vrrp_startup_delay '%s' is invalid", strvec_slot(strvec, 1));
	else
		global_data->vrrp_startup_delay = (unsigned)(startup_delay * TIMER_HZ);

	if (global_data->vrrp_startup_delay >= 60 * TIMER_HZ)
		log_message(LOG_INFO, "The vrrp_startup_delay is very large - %s seconds", strvec_slot(strvec, 1));
}

static void
vrrp_log_unknown_vrids_handler(__attribute__((unused)) const vector_t *strvec)
{
	global_data->log_unknown_vrids = true;
}
#endif

static void
random_seed_handler(const vector_t *strvec)
{
	unsigned val;

	if (!read_unsigned_strvec(strvec, 1, &val, 0, UINT_MAX, false)) {
		report_config_error(CONFIG_GENERAL_ERROR, "random_seed %s invalid", strvec_slot(strvec, 1));
		return;
	}

	set_random_seed(val);
}

void
init_global_keywords(bool global_active)
{
	/* global definitions mapping */
#ifdef _WITH_LINKBEAT_
	install_keyword_root("linkbeat_use_polling", use_polling_handler, global_active);
#endif
#if HAVE_DECL_CLONE_NEWNET
	install_keyword_root("net_namespace", &net_namespace_handler, global_active);
	install_keyword_root("namespace_with_ipsets", &namespace_ipsets_handler, global_active);
#endif
	install_keyword_root("use_pid_dir", &use_pid_dir_handler, global_active);
	install_keyword_root("instance", &instance_handler, global_active);
	install_keyword_root("child_wait_time", &child_wait_handler, global_active);
	install_keyword_root("global_defs", NULL, global_active);
	install_keyword("process_names", &process_names_handler);
	install_keyword("process_name", &process_name_handler);
#ifdef _WITH_VRRP_
	install_keyword("vrrp_process_name", &vrrp_process_name_handler);
#endif
#ifdef _WITH_LVS_
	install_keyword("lvs_process_name", &lvs_process_name_handler);
#endif
#ifdef _WITH_BFD_
	install_keyword("bfd_process_name", &bfd_process_name_handler);
#endif
	install_keyword("router_id", &routerid_handler);
	install_keyword("notification_email_from", &emailfrom_handler);
	install_keyword("smtp_server", &smtpserver_handler);
	install_keyword("smtp_helo_name", &smtphelo_handler);
	install_keyword("smtp_connect_timeout", &smtpto_handler);
	install_keyword("notification_email", &email_handler);
	install_keyword("smtp_alert", &smtp_alert_handler);
#ifdef _WITH_VRRP_
	install_keyword("smtp_alert_vrrp", &smtp_alert_vrrp_handler);
#endif
#ifdef _WITH_LVS_
	install_keyword("smtp_alert_checker", &smtp_alert_checker_handler);
	install_keyword("checker_log_all_failures", &checker_log_all_failures_handler);
#endif
#ifdef _WITH_VRRP_
	install_keyword("dynamic_interfaces", &dynamic_interfaces_handler);
	install_keyword("no_email_faults", &no_email_faults_handler);
	install_keyword("default_interface", &default_interface_handler);
#endif
#ifdef _WITH_LVS_
	install_keyword("lvs_timeouts", &lvs_timeouts);
	install_keyword("lvs_flush", &lvs_flush_handler);
	install_keyword("lvs_flush_onstop", &lvs_flush_onstop_handler);
#ifdef _WITH_VRRP_
	install_keyword("lvs_sync_daemon", &lvs_syncd_handler);
#endif
#endif
#ifdef _WITH_VRRP_
	install_keyword("vrrp_mcast_group4", &vrrp_mcast_group4_handler);
	install_keyword("vrrp_mcast_group6", &vrrp_mcast_group6_handler);
	install_keyword("vrrp_garp_master_delay", &vrrp_garp_delay_handler);
	install_keyword("vrrp_garp_master_repeat", &vrrp_garp_rep_handler);
	install_keyword("vrrp_garp_master_refresh", &vrrp_garp_refresh_handler);
	install_keyword("vrrp_garp_master_refresh_repeat", &vrrp_garp_refresh_rep_handler);
	install_keyword("vrrp_garp_lower_prio_delay", &vrrp_garp_lower_prio_delay_handler);
	install_keyword("vrrp_garp_lower_prio_repeat", &vrrp_garp_lower_prio_rep_handler);
	install_keyword("vrrp_garp_interval", &vrrp_garp_interval_handler);
	install_keyword("vrrp_gna_interval", &vrrp_gna_interval_handler);
	install_keyword("vrrp_min_garp", &vrrp_min_garp_handler);
	install_keyword("vrrp_lower_prio_no_advert", &vrrp_lower_prio_no_advert_handler);
	install_keyword("vrrp_higher_prio_send_advert", &vrrp_higher_prio_send_advert_handler);
	install_keyword("vrrp_version", &vrrp_version_handler);
#ifdef _WITH_IPTABLES_
	install_keyword("vrrp_iptables", &vrrp_iptables_handler);
#ifdef _HAVE_LIBIPSET_
	install_keyword("vrrp_ipsets", &vrrp_ipsets_handler);
#endif
#endif
#ifdef _WITH_NFTABLES_
	install_keyword("nftables", &vrrp_nftables_handler);
	install_keyword("nftables_priority", &vrrp_nftables_priority_handler);
	install_keyword("nftables_counters", &vrrp_nftables_counters_handler);
	install_keyword("nftables_ifindex", &vrrp_nftables_ifindex_handler);
#endif
	install_keyword("vrrp_check_unicast_src", &vrrp_check_unicast_src_handler);
	install_keyword("vrrp_skip_check_adv_addr", &vrrp_check_adv_addr_handler);
	install_keyword("vrrp_strict", &vrrp_strict_handler);
	install_keyword("vrrp_priority", &vrrp_prio_handler);
	install_keyword("vrrp_no_swap", &vrrp_no_swap_handler);
#ifdef _HAVE_SCHED_RT_
	install_keyword("vrrp_rt_priority", &vrrp_rt_priority_handler);
	install_keyword("vrrp_cpu_affinity", &vrrp_cpu_affinity_handler);
#if HAVE_DECL_RLIMIT_RTTIME == 1
	install_keyword("vrrp_rlimit_rtime", &vrrp_rt_rlimit_handler);
#endif
#endif
#endif
	install_keyword("notify_fifo", &global_notify_fifo);
	install_keyword("notify_fifo_script", &global_notify_fifo_script);
#ifdef _WITH_VRRP_
	install_keyword("vrrp_notify_fifo", &vrrp_notify_fifo);
	install_keyword("vrrp_notify_fifo_script", &vrrp_notify_fifo_script);
	install_keyword("vrrp_notify_priority_changes", &vrrp_notify_priority_changes);
#endif
#ifdef _WITH_LVS_
	install_keyword("lvs_notify_fifo", &lvs_notify_fifo);
	install_keyword("lvs_notify_fifo_script", &lvs_notify_fifo_script);
	install_keyword("checker_priority", &checker_prio_handler);
	install_keyword("checker_no_swap", &checker_no_swap_handler);
#ifdef _HAVE_SCHED_RT_
	install_keyword("checker_rt_priority", &checker_rt_priority_handler);
	install_keyword("checker_cpu_affinity", &checker_cpu_affinity_handler);
#if HAVE_DECL_RLIMIT_RTTIME == 1
	install_keyword("checker_rlimit_rtime", &checker_rt_rlimit_handler);
#endif
#endif
#endif
#ifdef _WITH_BFD_
	install_keyword("bfd_priority", &bfd_prio_handler);
	install_keyword("bfd_no_swap", &bfd_no_swap_handler);
#ifdef _HAVE_SCHED_RT_
	install_keyword("bfd_rt_priority", &bfd_rt_priority_handler);
	install_keyword("bfd_cpu_affinity", &bfd_cpu_affinity_handler);
#if HAVE_DECL_RLIMIT_RTTIME == 1
	install_keyword("bfd_rlimit_rtime", &bfd_rt_rlimit_handler);
#endif
#endif
#endif
#ifdef _WITH_SNMP_
	install_keyword("snmp_socket", &snmp_socket_handler);
	install_keyword("enable_traps", &trap_handler);
#ifdef _WITH_SNMP_VRRP_
	install_keyword("enable_snmp_vrrp", &snmp_vrrp_handler);
	install_keyword("enable_snmp_keepalived", &snmp_vrrp_handler);	/* Deprecated v2.0.0 */
#endif
#ifdef _WITH_SNMP_RFC_
	install_keyword("enable_snmp_rfc", &snmp_rfc_handler);
#endif
#ifdef _WITH_SNMP_RFCV2_
	install_keyword("enable_snmp_rfcv2", &snmp_rfcv2_handler);
#endif
#ifdef _WITH_SNMP_RFCV3_
	install_keyword("enable_snmp_rfcv3", &snmp_rfcv3_handler);
#endif
#ifdef _WITH_SNMP_CHECKER_
	install_keyword("enable_snmp_checker", &snmp_checker_handler);
#endif
#endif
#ifdef _WITH_DBUS_
	install_keyword("enable_dbus", &enable_dbus_handler);
	install_keyword("dbus_service_name", &dbus_service_name_handler);
#endif
	install_keyword("script_user", &script_user_handler);
	install_keyword("enable_script_security", &script_security_handler);
#ifdef _WITH_VRRP_
	install_keyword("vrrp_netlink_cmd_rcv_bufs", &vrrp_netlink_cmd_rcv_bufs_handler);
	install_keyword("vrrp_netlink_cmd_rcv_bufs_force", &vrrp_netlink_cmd_rcv_bufs_force_handler);
	install_keyword("vrrp_netlink_monitor_rcv_bufs", &vrrp_netlink_monitor_rcv_bufs_handler);
	install_keyword("vrrp_netlink_monitor_rcv_bufs_force", &vrrp_netlink_monitor_rcv_bufs_force_handler);
#ifdef _WITH_CN_PROC_
	install_keyword("process_monitor_rcv_bufs", &process_monitor_rcv_bufs_handler);
	install_keyword("process_monitor_rcv_bufs_force", &process_monitor_rcv_bufs_force_handler);
#endif
#endif
#ifdef _WITH_LVS_
	install_keyword("lvs_netlink_cmd_rcv_bufs", &lvs_netlink_cmd_rcv_bufs_handler);
	install_keyword("lvs_netlink_cmd_rcv_bufs_force", &lvs_netlink_cmd_rcv_bufs_force_handler);
	install_keyword("lvs_netlink_monitor_rcv_bufs", &lvs_netlink_monitor_rcv_bufs_handler);
	install_keyword("lvs_netlink_monitor_rcv_bufs_force", &lvs_netlink_monitor_rcv_bufs_force_handler);
#endif
#ifdef _WITH_LVS_
	install_keyword("rs_init_notifies", &rs_init_notifies_handler);
	install_keyword("no_checker_emails", &no_checker_emails_handler);
#endif
#ifdef _WITH_VRRP_
	install_keyword("vrrp_rx_bufs_policy", &vrrp_rx_bufs_policy_handler);
	install_keyword("vrrp_rx_bufs_multiplier", &vrrp_rx_bufs_multiplier_handler);
	install_keyword("vrrp_startup_delay", &vrrp_startup_delay_handler);
	install_keyword("log_unknown_vrids", &vrrp_log_unknown_vrids_handler);
#endif
	install_keyword("umask", &umask_handler);
	install_keyword("random_seed", &random_seed_handler);
}
