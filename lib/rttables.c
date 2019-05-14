/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Routing table names parser/reader. Place into the dynamic
 *              data structure representation the table names and ids.
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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>

#include "list.h"
#include "memory.h"
#include "logger.h"
#include "parser.h"
#include "rttables.h"

#define IPROUTE2_DIR	"/etc/iproute2/"

#ifdef _HAVE_FIB_ROUTING_
#define RT_TABLES_FILE	IPROUTE2_DIR "rt_tables"
#define	RT_DSFIELD_FILE IPROUTE2_DIR "rt_dsfield"
#define	RT_REALMS_FILE	IPROUTE2_DIR "rt_realms"
#define	RT_PROTOS_FILE	IPROUTE2_DIR "rt_protos"
#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
#define	RT_GROUPS_FILE	IPROUTE2_DIR "group"
#endif
#endif
#define	RT_SCOPES_FILE	IPROUTE2_DIR "rt_scopes"

struct rt_entry {
	unsigned int id;
	const char *name;
} ;
typedef struct rt_entry rt_entry_t;

#ifdef _HAVE_FIB_ROUTING_
static rt_entry_t const rtntypes[] = {
	{ RTN_LOCAL, "local"},
	{ RTN_NAT, "nat"},
	{ RTN_BROADCAST, "broadcast"},
	{ RTN_BROADCAST, "brd"},
	{ RTN_ANYCAST, "anycast"},
	{ RTN_MULTICAST, "multicast"},
	{ RTN_PROHIBIT, "prohibit"},
	{ RTN_UNREACHABLE, "unreachable"},
	{ RTN_BLACKHOLE, "blackhole"},
	{ RTN_XRESOLVE, "xresolve"},
	{ RTN_UNICAST, "unicast"},
	{ RTN_THROW, "throw"},
	{ 0, NULL},
};

static rt_entry_t const rtprot_default[] = {
	{ RTPROT_UNSPEC, "none"},
	{ RTPROT_REDIRECT, "redirect"},
	{ RTPROT_KERNEL, "kernel"},
	{ RTPROT_BOOT, "boot"},
	{ RTPROT_STATIC, "static"},

	{ RTPROT_GATED, "gated"},
	{ RTPROT_RA, "ra"},
	{ RTPROT_MRT, "mrt"},
	{ RTPROT_ZEBRA, "zebra"},
	{ RTPROT_BIRD, "bird"},
#ifdef RTPROT_BABEL		/* Since Linux 3.19 */
	{ RTPROT_BABEL, "babel"},
#endif
	{ RTPROT_DNROUTED, "dnrouted"},
	{ RTPROT_XORP, "xorp"},
	{ RTPROT_NTK, "ntk"},
	{ RTPROT_DHCP, "dhcp"},
	{ 0, NULL},
};

static rt_entry_t const rttable_default[] = {
	{ RT_TABLE_DEFAULT, "default"},
	{ RT_TABLE_MAIN, "main"},
	{ RT_TABLE_LOCAL, "local"},
	{ 0, NULL},
};
#endif

static rt_entry_t const rtscope_default[] = {
	{ RT_SCOPE_UNIVERSE, "global"},
	{ RT_SCOPE_NOWHERE, "nowhere"},
	{ RT_SCOPE_HOST, "host"},
	{ RT_SCOPE_LINK, "link"},
	{ RT_SCOPE_SITE, "site"},
	{ 0, NULL},
};

#define	MAX_RT_BUF	128

#ifdef _HAVE_FIB_ROUTING_
static list rt_tables;
static list rt_dsfields;
#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
static list rt_groups;
#endif
static list rt_realms;
static list rt_protos;
#endif
static list rt_scopes;

static char ret_buf[11];	/* uint32_t in decimal */

static void
read_file(const char* file_name, list *l, uint32_t max)
{
	FILE *fp;
	rt_entry_t *rte;
	vector_t *strvec = NULL;
	char buf[MAX_RT_BUF];
	unsigned long id;
	const char *number;
	char *endptr;

	fp = fopen(file_name, "r");
	if (!fp)
		return;

	while (fgets(buf, MAX_RT_BUF, fp)) {
		strvec = alloc_strvec(buf);

		if (!strvec)
			continue;

		if (vector_size(strvec) != 2) {
			free_strvec(strvec);
			continue;
		}

		rte = MALLOC(sizeof(rt_entry_t));
		if (!rte) {
			free_strvec(strvec);
			goto err;
		}

		number = strvec_slot(strvec, 0);
		number += strspn(number, " \t");
		id = strtoul(number, &endptr, 0);
		if (*number == '-' || number == endptr || *endptr || id > max) {
			FREE(rte);
			free_strvec(strvec);
			continue;
		}
		rte->id = (unsigned)id;

		rte->name = STRDUP(strvec_slot(strvec, 1));
		if (!rte->name) {
			FREE(rte);
			free_strvec(strvec);
			goto err;
		}

		list_add(*l, rte);

		free_strvec(strvec);
	}

	fclose(fp);

	return;
err:
	fclose(fp);

	if (strvec)
		free_strvec(strvec);

	free_list(l);

	return;
}

void
clear_rt_names(void)
{
#ifdef _HAVE_FIB_ROUTING_
	free_list(&rt_tables);
	free_list(&rt_dsfields);
#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
	free_list(&rt_groups);
#endif
	free_list(&rt_realms);
	free_list(&rt_protos);
#endif
	free_list(&rt_scopes);
}

static void
free_rt_entry(void *e)
{
	rt_entry_t *rte = (rt_entry_t*)e;

	if (rte->name)
		FREE_CONST(rte->name);
	FREE(rte);
}

static void
dump_rt_entry(FILE *fp, const void *e)
{
	const rt_entry_t *rte = (const rt_entry_t *)e;

	conf_write(fp, "rt_table %u, name %s", rte->id, rte->name);
}

static void
add_default(list *l, const struct rt_entry* default_list)
{
	bool found;
	rt_entry_t *rte;
	element e;

	for (;default_list->name; default_list++) {
		for (e = LIST_HEAD(*l), found = false; e; ELEMENT_NEXT(e)) {
			rte = ELEMENT_DATA(e);

			if (rte->id == default_list->id) {
				found = true;
				break;
			}
		}

		if (found)
			continue;

		rte = MALLOC(sizeof(rt_entry_t));
		rte->name = STRDUP(default_list->name);
		if (!rte->name) {
			FREE(rte);
			return;
		}

		rte->id = default_list->id;

		list_add(*l, rte);
	}
}

static void
initialise_list(list *l, const char *file_name, const struct rt_entry *default_list, uint32_t max)
{

	if (*l)
		return;

	*l = alloc_list(free_rt_entry, dump_rt_entry);
	if (!*l)
		return;

	read_file(file_name, l, max);

	if (default_list)
		add_default(l, default_list);
}

static bool
find_entry(const char *name, unsigned int *id, list *l, const char* file_name, const struct rt_entry* default_list, uint32_t max)
{
	element e;
	char	*endptr;
	unsigned long l_id;

	l_id = strtoul(name, &endptr, 0);
	*id = (unsigned int)l_id;
	if (endptr != name && *endptr == '\0')
		return (*id <= max);

	if (!(*l))
		initialise_list(l, file_name, default_list, max);

	if (LIST_ISEMPTY(*l))
		return false;

	for (e = LIST_HEAD(*l); e; ELEMENT_NEXT(e)) {
		rt_entry_t *rte = ELEMENT_DATA(e);

		if (!strcmp(rte->name, name)) {
			*id = rte->id;
			return true;
		}
	}
	return false;
}

#ifdef _HAVE_FIB_ROUTING_
bool
find_rttables_table(const char *name, uint32_t *id)
{
	return find_entry(name, id, &rt_tables, RT_TABLES_FILE, rttable_default, RT_TABLE_MAX);
}

bool
find_rttables_dsfield(const char *name, uint8_t *id)
{
	uint32_t val;
	bool ret;

	ret = find_entry(name, &val, &rt_dsfields, RT_DSFIELD_FILE, NULL, 255);
	*id = val & 0xff;

	return ret;
}

#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
bool
find_rttables_group(const char *name, uint32_t *id)
{
	return find_entry(name, id, &rt_groups, RT_GROUPS_FILE, NULL, INT32_MAX);
}
#endif

bool
find_rttables_realms(const char *name, uint32_t *id)
{
	return find_entry(name, id, &rt_realms, RT_REALMS_FILE, NULL, 255);
}

bool
find_rttables_proto(const char *name, uint8_t *id)
{
	uint32_t val;
	bool ret;

	ret = find_entry(name, &val, &rt_protos, RT_PROTOS_FILE, rtprot_default, 255);
	*id = val & 0xff;

	return ret;
}

bool
find_rttables_rtntype(const char *str, uint8_t *id)
{
	char *end;
	unsigned long res;
	int i;

	for (i = 0; rtntypes[i].name; i++) {
		if (!strcmp(str, rtntypes[i].name)) {
			*id = (uint8_t)rtntypes[i].id;
			return true;
		}
	}

	res = strtoul(str, &end, 0);
	if (*end || res > 255 || str[0] == '-')
		return false;

	*id = (uint8_t)res;
	return true;
}
#endif

static const char *
get_entry(unsigned int id, list* l, const char* file_name, const struct rt_entry* default_list, uint32_t max)
{
	element e;
	const rt_entry_t *rte;


	if (!(*l))
		initialise_list(l, file_name, default_list, max);

	if (!LIST_ISEMPTY(*l)) {
		LIST_FOREACH(*l, rte, e) {
			if (rte->id == id)
				return rte->name;
		}
	}

	snprintf(ret_buf, sizeof(ret_buf), "%u", id);
	return ret_buf;
}

#ifdef _HAVE_FIB_ROUTING_
#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
const char *
get_rttables_group(uint32_t id)
{
	return get_entry(id, &rt_groups, RT_GROUPS_FILE, NULL, INT32_MAX);
}
#endif

const char *
get_rttables_rtntype(uint8_t val)
{
	int i;

	for (i = 0; rtntypes[i].name; i++) {
		if (val == rtntypes[i].id)
			return rtntypes[i].name;
	}

	snprintf(ret_buf, sizeof(ret_buf), "%u", val);
	return ret_buf;
}
#endif

bool
find_rttables_scope(const char *name, uint8_t *id)
{
	uint32_t val;
	bool ret;

	ret = find_entry(name, &val, &rt_scopes, RT_SCOPES_FILE, rtscope_default, 255);
	*id = val & 0xff;

	return ret;
}

const char *
get_rttables_scope(uint32_t id)
{
	return get_entry(id, &rt_scopes, RT_SCOPES_FILE, rtscope_default, 255);
}
