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

/* local include */
#include "vrrp_data.h"
#include "vrrp.h"
#include "vrrp_sync.h"
#include "logger.h"
#include "vrrp_static_track.h"
#include "vrrp_ipaddress.h"
#include "vrrp_track.h"
#if _HAVE_FIB_ROUTING_
#include "vrrp_iproute.h"
#include "vrrp_iprule.h"
#endif

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

static void
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
			log_message(LOG_INFO, "vrrp instance %s specified in track group %s doesn't exist - ignoring", str, tgroup->gname);
			continue;
		}

		list_add(tgroup->vrrp_instances, vrrp);
	}

	/* The iname vector is only used for us to set up the sync groups, so delete it */
	free_strvec(tgroup->iname);
	tgroup->iname = NULL;
}

void
static_track_group_init(void)
{
	static_track_group_t *tg;
	vrrp_t *vrrp;
	ip_address_t *addr;
#if _HAVE_FIB_ROUTING_
	ip_route_t *route;
	ip_rule_t *rule;
#endif
	element e, e1, next;

	LIST_FOREACH_NEXT(vrrp_data->static_track_groups, tg, e, next) {
		if (!tg->iname) {
                        log_message(LOG_INFO, "Static track group %s has no virtual router(s) - removing", tg->gname);
                        free_list_element(vrrp_data->static_track_groups, e);
                        continue;
                }

		static_track_set_group(tg);

		if (!tg->vrrp_instances) {
                        free_list_element(vrrp_data->static_track_groups, e);
                        continue;
                }
	}

	/* Add the tracking vrrps to track the interface of each tracked address */
	LIST_FOREACH(vrrp_data->static_addresses, addr, e) {
		if (!addr->track_group)
			continue;
		if (addr->dont_track) {
			log_message(LOG_INFO, "Static address has both track_group and no_track set - not tracking");
			continue;
		}

		LIST_FOREACH(addr->track_group->vrrp_instances, vrrp, e1)
			add_vrrp_to_interface(vrrp, addr->ifp, 0, false, TRACK_SADDR);
	}

#if _HAVE_FIB_ROUTING_
	/* Add the tracking vrrps to track the interface of each tracked address */
	LIST_FOREACH(vrrp_data->static_routes, route, e) {
		if (!route->track_group)
			continue;
		if (route->dont_track) {
			log_message(LOG_INFO, "Static route has both track_group and no_track set - not tracking");
			continue;
		}

		LIST_FOREACH(route->track_group->vrrp_instances, vrrp, e1) {
			if (route->oif)
				add_vrrp_to_interface(vrrp, route->oif, 0, false, TRACK_SROUTE);
		}
	}

	LIST_FOREACH(vrrp_data->static_rules, rule, e) {
		if (!rule->track_group)
			continue;
		if (rule->dont_track) {
			log_message(LOG_INFO, "Static rule has both track_group and no_track set - not tracking");
			continue;
		}

		LIST_FOREACH(rule->track_group->vrrp_instances, vrrp, e1) {
			if (rule->iif)
				add_vrrp_to_interface(vrrp, rule->iif, 0, false, TRACK_SRULE);
		}
	}
#endif
}

void
static_track_reinstate_config(interface_t *ifp)
{
	ip_address_t *addr;
#if _HAVE_FIB_ROUTING_
	ip_route_t *route;
/*	ip_rule_t *rule; */
#endif
	element e;

	LIST_FOREACH(vrrp_data->static_addresses, addr, e) {
		if (addr->dont_track)
			continue;
		if (addr->ifp != ifp)
			continue;
		reinstate_static_address(addr);
	}

#if _HAVE_FIB_ROUTING_
	/* Add the tracking vrrps to track the interface of each tracked address */
	LIST_FOREACH(vrrp_data->static_routes, route, e) {
		if (route->dont_track)
			continue;
		if (route->oif != ifp)
			continue;
		reinstate_static_route(route);
	}

	/* Rules don't get deleted on interface deletion, so we don't need to do anything for them
	LIST_FOREACH(vrrp_data->static_rules, rule, e) {
		if (rule->dont_track)
			continue;
		if (rule->iif != ifp)
			continue;
		reinstate_static_route(route);
	}
	*/
#endif
}
