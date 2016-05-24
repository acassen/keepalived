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
 * Copyright (C) 2001-2016 Alexandre Cassen, <acassen@linux-vs.org>
 */
#include <stdbool.h>
#include <errno.h>

#include "vector.h"
#include "list.h"
#include "memory.h"
#include "logger.h"
#include "parser.h"
#include "rttables.h"

#define RT_TABLES_FILE	"/etc/iproute2/rt_tables"
#define	MAX_RT_TABLES_BUF	128

struct rt_entry {
	unsigned int id;
	char *name;
} ;
typedef struct rt_entry rt_entry_t;

static list rt_list;

static void
free_rt_entry(void *e)
{
	rt_entry_t *rte = (rt_entry_t*)e;

	if (rte->name)
		FREE(rte->name);
	FREE(rte);
}

static void
dump_rt_entry(void *e)
{
	rt_entry_t *rte = (rt_entry_t *)e;

	log_message(LOG_INFO, "rt_table %u, name %s", rte->id, rte->name);
}

static bool
read_rttables(void)
{
	FILE *fp;
	rt_entry_t *rte;
	vector_t *strvec = NULL;
	char buf[MAX_RT_TABLES_BUF];

	if (rt_list)
		return true;

	fp = fopen(RT_TABLES_FILE, "r");
	if (!fp) {
		if (errno == EACCES || errno == EISDIR || errno == ENOENT) {
			/* This is a permanent error, so don't keep trying to reopen the file */
			rt_list = alloc_list(NULL, NULL);
			return true;
		}
		return false;
	}

	rt_list = alloc_list(free_rt_entry, dump_rt_entry);
	if (!rt_list)
		goto err;

	while (fgets(buf, MAX_RT_TABLES_BUF, fp)) {
		strvec = alloc_strvec(buf);

		if (!strvec)
			continue;

		if (vector_size(strvec) != 2) {
			free_strvec(strvec);
			continue;
		}

		rte = MALLOC(sizeof(rt_entry_t));
		if (!rte)
			goto err;

		rte->id = strtoul(FMT_STR_VSLOT(strvec, 0), NULL, 0);
		rte->name = MALLOC(strlen(FMT_STR_VSLOT(strvec, 1)) + 1);
		if (!rte->name) {
			FREE(rte);
			goto err;
		}

		strcpy(rte->name, FMT_STR_VSLOT(strvec, 1));

		list_add(rt_list, rte);

		free_strvec(strvec);
		strvec = NULL;
	}

	fclose(fp);

	return true;
err:
	fclose(fp);

	if (!strvec)
		free_strvec(strvec);

	free_list(&rt_list);

	return false;
}

void
clear_rttables(void)
{
	free_list(&rt_list);
}

bool
find_rttables_table(const char *name, unsigned int *id)
{
	element e;
	char	*endptr;

	*id = strtoul(name, &endptr, 0);
	if (endptr != name && *endptr == '\0')
		return true;

	if (!rt_list && !read_rttables())
		return false;

	if (LIST_ISEMPTY(rt_list))
		return false;

	for (e = LIST_HEAD(rt_list); e; ELEMENT_NEXT(e)) {
		rt_entry_t *rte = ELEMENT_DATA(e);

		if (!strcmp(rte->name, name)) {
			*id = rte->id;
			return true;
		}
	}
	return false;
}
