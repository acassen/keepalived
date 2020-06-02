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
 * Copyright (C) 2018-2020 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

/* local include */
#include "vrrp_track.h"
#include "vrrp_data.h"
#include "vrrp.h"
#include "vrrp_sync.h"
#include "logger.h"
#include "vrrp_static_track.h"
#include "vrrp_ipaddress.h"
#ifdef _HAVE_FIB_ROUTING_
#include "vrrp_iproute.h"
#include "vrrp_iprule.h"
#endif


static void
free_static_track_group_vrrp_list(list_head_t *l)
{
	tracking_obj_t *top, *top_tmp;

	list_for_each_entry_safe(top, top_tmp, l, e_list)
		FREE(top);
}

void
free_static_track_group(static_track_group_t *tgroup)
{
	if (tgroup->iname) {
		/* If we are terminating at init time, tgroup->vrrp may not be initialised yet, in
		 * which case tgroup->iname will still be set */
		if (!list_empty(&tgroup->vrrp_instances))
			log_message(LOG_INFO, "track group %s - iname vector exists when freeing group"
					    , tgroup->gname);
		free_strvec(tgroup->iname);
	}
	list_del_init(&tgroup->e_list);
	FREE_CONST(tgroup->gname);
	free_static_track_group_vrrp_list(&tgroup->vrrp_instances);
	FREE(tgroup);
}

void
dump_static_track_group(FILE *fp, const static_track_group_t *tgroup)
{
	tracking_obj_t *top;

	conf_write(fp, " Static Track Group = %s", tgroup->gname);
	if (!list_empty(&tgroup->vrrp_instances)) {
		conf_write(fp, "   VRRP member instances :");
		list_for_each_entry(top, &tgroup->vrrp_instances, e_list)
			conf_write(fp, "     %s", top->obj.vrrp->iname);
	}
}

static_track_group_t * __attribute__ ((pure))
static_track_group_find(const char *gname)
{
	static_track_group_t *tgroup;

	list_for_each_entry(tgroup, &vrrp_data->static_track_groups, e_list)
		if (!strcmp(gname, tgroup->gname))
			return tgroup;

	return NULL;
}

static bool
static_track_group_set(static_track_group_t *tgroup)
{
	tracking_obj_t *top;
	vrrp_t *vrrp;
	char *str;
	unsigned int i;

	/* Can't handle no members of the group */
	if (!tgroup->iname) {
		log_message(LOG_INFO, "Static track group %s has no virtual router(s)"
				    , tgroup->gname);
		return false;
	}

	for (i = 0; i < vector_size(tgroup->iname); i++) {
		str = vector_slot(tgroup->iname, i);
		vrrp = vrrp_get_instance(str);
		if (!vrrp) {
			log_message(LOG_INFO, "vrrp instance %s specified in track group %s doesn't exist - ignoring"
					    , str, tgroup->gname);
			continue;
		}

		/* Create tracking object */
		PMALLOC(top);
		INIT_LIST_HEAD(&top->e_list);
		top->obj.vrrp = vrrp;
		top->type = TRACK_VRRP;

		list_add_tail(&top->e_list, &tgroup->vrrp_instances);
	}

	/* The iname vector is only used for us to set up the sync groups, so delete it */
	free_strvec(tgroup->iname);
	tgroup->iname = NULL;

	if (list_empty(&tgroup->vrrp_instances)) {
		log_message(LOG_INFO, "Static track group %s has no VRRP instance(s)"
				    , tgroup->gname);
		return false;
	}

	return true;
}

void
static_track_group_init(void)
{
	static_track_group_t *tgroup, *tgroup_tmp;
	tracking_obj_t *top;
	ip_address_t *addr;
#ifdef _HAVE_FIB_ROUTING_
	ip_route_t *route;
	ip_rule_t *rule;
#endif

	list_for_each_entry_safe(tgroup, tgroup_tmp, &vrrp_data->static_track_groups, e_list) {
		if (!static_track_group_set(tgroup)) {
			log_message(LOG_INFO, "Static track group %s init fails - removing"
					    , tgroup->gname);
			free_static_track_group(tgroup);
		}
	}

	/* Add the tracking vrrps to track the interface of each tracked address */
	list_for_each_entry(addr, &vrrp_data->static_addresses, e_list) {
		if (!addr->track_group)
			continue;
		if (addr->dont_track) {
			log_message(LOG_INFO, "Static address has both track_group and no_track set - not tracking");
			continue;
		}

		list_for_each_entry(top, &addr->track_group->vrrp_instances, e_list)
			add_vrrp_to_interface(top->obj.vrrp, addr->ifp, 0, false, false, TRACK_SADDR);
	}

#ifdef _HAVE_FIB_ROUTING_
	/* Add the tracking vrrps to track the interface of each tracked address */
	list_for_each_entry(route, &vrrp_data->static_routes, e_list) {
		if (!route->track_group)
			continue;
		if (route->dont_track) {
			log_message(LOG_INFO, "Static route has both track_group and no_track set - not tracking");
			continue;
		}

		list_for_each_entry(top, &route->track_group->vrrp_instances, e_list) {
			if (route->oif)
				add_vrrp_to_interface(top->obj.vrrp, route->oif, 0, false, false, TRACK_SROUTE);
		}
	}

	list_for_each_entry(rule, &vrrp_data->static_rules, e_list) {
		if (!rule->track_group)
			continue;
		if (rule->dont_track) {
			log_message(LOG_INFO, "Static rule has both track_group and no_track set - not tracking");
			continue;
		}

		list_for_each_entry(top, &rule->track_group->vrrp_instances, e_list) {
			if (rule->iif)
				add_vrrp_to_interface(top->obj.vrrp, rule->iif, 0, false, false, TRACK_SRULE);
		}
	}
#endif
}

void
static_track_group_reinstate_config(interface_t *ifp)
{
	ip_address_t *addr;
#ifdef _HAVE_FIB_ROUTING_
	ip_route_t *route;
/*	ip_rule_t *rule; */
#endif

	list_for_each_entry(addr, &vrrp_data->static_addresses, e_list) {
		if (addr->dont_track)
			continue;
		if (addr->ifp != ifp)
			continue;
		reinstate_static_address(addr);
	}

#ifdef _HAVE_FIB_ROUTING_
	/* Add the tracking vrrps to track the interface of each tracked address */
	list_for_each_entry(route, &vrrp_data->static_routes, e_list) {
		if (route->dont_track)
			continue;
		if (route->oif != ifp)
			continue;
		reinstate_static_route(route);
	}

	/* Rules don't get deleted on interface deletion, so we don't need to do anything for them
	list_for_each_entry(rule, &vrrp_data->static_rules, e_list) {
		if (rule->dont_track)
			continue;
		if (rule->iif != ifp)
			continue;
		reinstate_static_route(route);
	}
	*/
#endif
}
