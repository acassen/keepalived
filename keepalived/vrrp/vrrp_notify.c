/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        VRRP state transition notification scripts handling.
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

/* system include */
#include <errno.h>

/* local include */
#include "vrrp_notify.h"
#ifdef _WITH_DBUS_
#include "vrrp_dbus.h"
#endif
#include "global_data.h"
#include "notify.h"
#include "logger.h"

static notify_script_t*
get_iscript(vrrp_t * vrrp, int state)
{
	if (!vrrp->notify_exec)
		return NULL;
	if (state == VRRP_STATE_BACK)
		return vrrp->script_backup;
	if (state == VRRP_STATE_MAST)
		return vrrp->script_master;
	if (state == VRRP_STATE_FAULT)
		return vrrp->script_fault;
	return NULL;
}

static notify_script_t*
get_gscript(vrrp_sgroup_t * vgroup, int state)
{
	if (!vgroup->notify_exec)
		return NULL;
	if (state == VRRP_STATE_BACK)
		return vgroup->script_backup;
	if (state == VRRP_STATE_MAST)
		return vgroup->script_master;
	if (state == VRRP_STATE_FAULT)
		return vgroup->script_fault;
	return NULL;
}

static notify_script_t*
get_igscript(vrrp_t *vrrp)
{
	return vrrp->script;
}

static notify_script_t*
get_ggscript(vrrp_sgroup_t * vgroup)
{
	return vgroup->script;
}

static void
notify_script_exec(notify_script_t* script, char *type, int state_num, char* name, int prio)
{
	notify_script_t new_script;
	char *words[6];
	char prio_buf[4];

	/*
	 * script {GROUP|INSTANCE} NAME {MASTER|BACKUP|FAULT} PRIO
	 *
	 * Note that the prio will be indicated as zero for a group.
	 *
	 */
	words[0] = script->args[0];
	words[1] = type;
	words[2] = name;
	switch (state_num) {
		case VRRP_STATE_MAST  : words[3] = "MASTER" ; break;
		case VRRP_STATE_BACK  : words[3] = "BACKUP" ; break;
		case VRRP_STATE_FAULT : words[3] = "FAULT" ; break;
		default:		words[3] = "{UNKNOWN}"; break;
	}
	snprintf(prio_buf, sizeof(prio_buf), "%d", prio);
	words[4] = prio_buf;
	words[5] = NULL;
	new_script.args = words;

	/* Launch the script */
	new_script.cmd_str = script->args[0];
	new_script.uid = script->uid;
	new_script.gid = script->gid;

	notify_exec(&new_script);
}

int
notify_instance_exec(vrrp_t * vrrp, int state)
{
	notify_script_t *script = get_iscript(vrrp, state);
	notify_script_t *gscript = get_igscript(vrrp);
	int ret = 0;

	/* Launch the notify_* script */
	if (script) {
		notify_exec(script);
		ret = 1;
	}

	/* Launch the generic notify script */
	if (gscript) {
		notify_script_exec(gscript, "INSTANCE", state, vrrp->iname,
				   vrrp->effective_priority);
		ret = 1;
	}

#ifdef _WITH_DBUS_
	if (global_data->enable_dbus)
		dbus_send_state_signal(vrrp); // send signal to all subscribers
#endif

	return ret;
}

int
notify_group_exec(vrrp_sgroup_t * vgroup, int state)
{
	notify_script_t *script = get_gscript(vgroup, state);
	notify_script_t *gscript = get_ggscript(vgroup);
	int ret = 0;

	/* Launch the notify_* script */
	if (script) {
		notify_exec(script);
		ret = 1;
	}

	/* Launch the generic notify script */
	if (gscript) {
		notify_script_exec(gscript, "GROUP", state, vgroup->gname, 0);
		ret = 1;
	}

	return ret;
}
