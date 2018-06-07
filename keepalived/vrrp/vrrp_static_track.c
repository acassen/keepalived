/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Tracking static addresses/routes/rules framework.
 *
 * Author:      Quentin Armitage, <quentin@armitage.org.uk>
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
 * Copyright (C) 2018-2018 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

//#include <net/if.h>
//#include <stdlib.h>
//#include <sys/stat.h>
//#include <limits.h>
//#include <stdlib.h>
//#include <sys/inotify.h>
//#include <errno.h>
//#include <sys/types.h>
//#include <fcntl.h>
//#include <stdio.h>

/* local include */
//#include "vrrp_track.h"
#include "vrrp_data.h"
#include "vrrp.h"
#include "vrrp_sync.h"
#include "logger.h"
//#include "memory.h"
//#include "vrrp_scheduler.h"
//#include "scheduler.h"
#include "vrrp_static_track.h"

void
free_tgroup(void *data)
{
	static_track_group_t *tgroup = data;

	if (tgroup->iname) {
		log_message(LOG_INFO, "track group %s - iname vector exists when freeing group", tgroup->gname);
		free_strvec(tgroup->iname);
	}
	FREE(tgroup->gname);
	free_list(&tgroup->vrrp_instances);
	FREE(tgroup);
}

void
dump_tgroup(FILE *fp, void *data)
{
	static_track_group_t *tgroup = data;
	vrrp_t *vrrp;
	element e;

	conf_write(fp, " Static Track Group = %s", tgroup->gname);
	if (tgroup->vrrp_instances) {
		conf_write(fp, "   VRRP member instances = %d", LIST_SIZE(tgroup->vrrp_instances));
		LIST_FOREACH(tgroup->vrrp_instances, vrrp, e)
			conf_write(fp, "     %s", vrrp->iname);
	}
}

static_track_group_t *
find_track_group(const char *gname)
{
	element e;
	static_track_group_t *tg;

	LIST_FOREACH(vrrp_data->static_track_groups, tg, e)
		if (!strcmp(gname, tg->gname))
			return tg;

	return NULL;
}

void
static_track_set_group(static_track_group_t *tgroup)
{
	vrrp_t *vrrp;
	char *str;
	unsigned int i;

	/* Can't handle no members of the group */
	if (!tgroup->iname)
		return;

	tgroup->vrrp_instances = alloc_list(NULL, NULL);

	for (i = 0; i < vector_size(tgroup->iname); i++) {
		str = vector_slot(tgroup->iname, i);
		vrrp = vrrp_get_instance(str);
		if (!vrrp) {
			log_message(LOG_INFO, "Virtual router %s specified in track group %s doesn't exist - ignoring", str, tgroup->gname);
			continue;
		}

		list_add(tgroup->vrrp_instances, vrrp);
	}

	/* The iname vector is only used for us to set up the sync groups, so delete it */
	free_strvec(tgroup->iname);
	tgroup->iname = NULL;
}
