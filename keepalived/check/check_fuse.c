// FUSE: Filesystem in Userspace
// Copyright (C) 2001-2005 Miklos Szeredi <miklos@szeredi.hu>
// This program can be distributed under the terms of the GNU GPL.
// See the file COPYING.

// See https://www.cs.nmsu.edu/~pfeiffer/fuse-tutorial/html/callbacks.html
// and http://www.oug.org/files/presentations/losug-fuse.pdf

/* On Fedora, install fuse (runtime), fuse-devel (build time) */

/* To run:
 *   ./ka MOUNTPOINT
 *
 * To terminate:
 *   fusermount -u MOUNTPOINT
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/select.h>

#include "check_fuse.h"
#include "logger.h"
#include "fuse_interface.h"

/* To remove */
#include <stdlib.h>


struct ent ssl_ent[] = {
	{"enable", NULL, NULL, NULL},	/* int */
	{"strong_check", NULL, NULL, NULL},	/* int */
	{"ctx", NULL, NULL, NULL},	/* SSL_CTX* */
	{"meth", NULL, NULL, NULL},	/* SSL_METHOD* */
	{"password", NULL, NULL, NULL},	/* char* */
	{"cafile", NULL, NULL, NULL},	/* char* */
	{"certfile", NULL, NULL, NULL},	/* char* */
	{"keyfile", NULL, NULL, NULL},	/* char* */
	{NULL, NULL, NULL, NULL}
};

struct ent failed_checker_list[] = {
	{"checker1", NULL, NULL, NULL},
	{"checker2", NULL, NULL, NULL},
	{NULL, NULL, NULL, NULL}
};

struct ent rs[] = {
	{"addr", NULL, NULL, NULL},	/* struct sockaddr_storage */
	{"weight", NULL, NULL, NULL},	/* int */
	{"iweight", NULL, NULL, NULL},	/* int */
	{"pweight", NULL, NULL, NULL},	/* int */
	{"u_threshold", NULL, NULL, NULL},	/* uint32_t */
	{"l_threshold", NULL, NULL, NULL},	/* uint32_t */
	{"inhibit", NULL, NULL, NULL},	/* int */
	{"notify_up", NULL, NULL, NULL},	/* notify_script_t* */
	{"notify_down", NULL, NULL, NULL},	/* notify_script_t* */
	{"alive", NULL, NULL, NULL},	/* bool */
	{"failed_checkers", failed_checker_list, NULL, NULL},	/* list */
	{"set", NULL, NULL, NULL},	/* bool */
	{"reloaded", NULL, NULL, NULL},	/* bool */
#if defined(_WITH_SNMP_CHECKER_)
	{"activeconns", NULL, NULL, NULL},	/* uint32_t */
	{"inactconns", NULL, NULL, NULL},	/* uint32_t */
	{"persistconns", NULL, NULL, NULL},	/* uint32_t */
#ifndef _WITH_LVS_64BIT_STATS_
	{"stats", NULL, NULL, NULL},	/* struct ip_vs_stats_user */
#else
	{"stats", NULL, NULL, NULL},	/* struct ip_vs_stats64 */
#endif
#endif
	{NULL, NULL, NULL, NULL}
};

struct ent rs_list[] = {
	{"1", rs, NULL, NULL},
	{"2", rs, NULL, NULL},
	{"3", rs, NULL, NULL},
	{NULL, NULL, NULL, NULL}
};

struct ent vs[] = {
	{"vsgname", NULL, NULL, NULL},	/* char* */
	{"vsg", NULL, NULL, NULL},	/* virtual_server_group_t* */	// Possibly use this rather than have ../virtual_server_group
	{"addr", NULL, NULL, NULL},	/* struct sockaddr_storage */
	{"s_svr", NULL, NULL, NULL},	/* real_server_t* */
	{"vfwmark", NULL, NULL, NULL},	/* uint32_t */
	{"af", NULL, NULL, NULL},	/* uint16_t */
	{"service_type", NULL, NULL, NULL},	/* uint16_t */
	{"delay_loop", NULL, NULL, NULL},	/* unsigned long */
	{"ha_suspend", NULL, NULL, NULL},	/* bool */
	{"ha_suspend_addr_count", NULL, NULL, NULL},	/* int */
	{"sched", NULL, NULL, NULL},	/* char[IP_VS_SCHEDNAME_MAXLEN] */
	{"flags", NULL, NULL, NULL},	/* uint32_t */
	{"persistence_timeout", NULL, NULL, NULL},	/* uint32_t */
#ifdef _HAVE_PE_NAME_
	{"pe_name", NULL, NULL, NULL},	/* char[IP_VS_PENAME_MAXLEN] */
#endif
	{"loadbalancing_kind", NULL, NULL, NULL},	/* unsigned */
	{"persistence_granularity", NULL, NULL, NULL},	/* uint32_t */
	{"virtualhost", NULL, NULL, NULL},	/* char* */
	{"rs", rs_list, NULL, NULL},	/* list */
	{"alive", NULL, NULL, NULL},	/* bool */
	{"alpha", NULL, NULL, NULL},	/* bool */
	{"omega", NULL, NULL, NULL},	/* bool */
	{"quorum_up", NULL, NULL, NULL},	/* notify_script_t* */
	{"quorum_down", NULL, NULL, NULL},	/* notify_script_t* */
	{"quorum", NULL, NULL, NULL},	/* unsigned */
	{"hysteresis", NULL, NULL, NULL},	/* unsigned */
	{"quorum_state", NULL, NULL, NULL},	/* bool */
	{"reloaded", NULL, NULL, NULL},	/* bool */
#if defined(_WITH_SNMP_CHECKER_)
	{"lastupdated", NULL, NULL, NULL},	/* time_t */
#ifndef _WITH_LVS_64BIT_STATS_
	{"stats", NULL, NULL, NULL},	/* struct ip_vs_stats_user */
#else
	{"stats", NULL, NULL, NULL},	/* struct ip_vs_stats64 */
#endif
#endif
	{NULL, NULL, NULL, NULL}
};

struct ent vs_list[] = {
	// How are they logged?
	{"123.2.3.1:0", vs, NULL, NULL},
	{"fred:0", vs, NULL, NULL},
	{"2001:470:69dd:123::2-15:80", vs, NULL, NULL},
	{NULL, NULL, NULL, NULL}
};

struct ent vs_group_addr[] = {
	{"addr", NULL, NULL, NULL},		// struct storage_addr
	{"alive", NULL, NULL, NULL},	// bool
	{"reloaded", NULL, NULL, NULL},	// bool
	{NULL, NULL, NULL, NULL}
};

struct ent vs_group_range[] = {
	{"range", NULL, NULL, NULL},		// struct storage_addr
	{"alive", NULL, NULL, NULL},	// bool
	{"reloaded", NULL, NULL, NULL},	// bool
	{NULL, NULL, NULL, NULL}
};

struct ent vs_group_fwmark[] = {
	{"fwmark", NULL, NULL, NULL},		// struct storage_addr
	{"alive", NULL, NULL, NULL},	// bool
	{"reloaded", NULL, NULL, NULL},	// bool
	{NULL, NULL, NULL, NULL}
};

struct ent vs_group[] = {
	// T? he following will appear if there are any
	{"addr", vs_group_addr, NULL, NULL},
	{"range", vs_group_range, NULL, NULL},
	{"fwmark", vs_group_fwmark, NULL, NULL},
	{NULL, NULL, NULL, NULL}
};

struct ent vs_group_list[] = {
	{"group1", vs_group, NULL, NULL},
	{"group2", vs_group, NULL, NULL},
	{NULL, NULL, NULL, NULL}
};

struct ent ssl_data[] = {
	{"ssl", ssl_ent, NULL, NULL},
	{"vs_group", vs_group_list, NULL, NULL},
	{"vs", vs_list, NULL, NULL},
	{NULL, NULL, NULL, NULL}
};

struct ent ipvs[] = {
	{"virtual_server_group", vs_group_list, NULL, NULL},
	{"virtual_server", vs_list, NULL, NULL},
	{"ssl", ssl_data, NULL, NULL},
	{NULL, NULL, NULL, NULL}
};

static struct ent top[] = {
	{"", ipvs, NULL, NULL},
	{NULL, NULL, NULL, NULL}
} ;

static void *fuses;
//static const char *mountpoint = "/tmp/ka/fs";
static const char *mountpoint = "/tmp/keepaliveda/low/state/ipvs";

void
start_check_fuse(void)
{
	fuses = start_fuse(mountpoint, top, false);
}

void
stop_check_fuse(void)
{
	if (fuses)
		stop_fuse(fuses, NULL);
	fuses = NULL;
}
