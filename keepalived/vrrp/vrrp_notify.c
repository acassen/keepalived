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
#include <ctype.h>

/* local include */
#include "vrrp_notify.h"
#ifdef _WITH_DBUS_
#include "vrrp_dbus.h"
#endif
#include "global_data.h"
#include "memory.h"
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

static char *
notify_script_name(char *cmdline)
{
	char *cp = cmdline;
	char *script;
	size_t str_len;

	if (!cmdline)
		return NULL;
	while (!isspace(*cp) && *cp != '\0')
		cp++;
	str_len = (size_t)(cp - cmdline);
	script = MALLOC(str_len + 1);
	memcpy(script, cmdline, str_len);
	*(script + str_len) = '\0';

	return script;
}

static bool
script_open_literal(char *script)
{
	log_message(LOG_DEBUG, "Opening script file %s",script);
	FILE *fOut = fopen(script, "r");;
	if (!fOut) {
		log_message(LOG_INFO, "Can't open %s (errno %d %s)", script,
		       errno, strerror(errno));
		return false;
	}
	fclose(fOut);
	return true;
}

static bool
script_open(notify_script_t *script)
{
	char *name = notify_script_name(script->name);
	int ret;

	if (!name)
		return false;

	ret = script_open_literal(name);
	FREE(name);

	return ret;
}

static void
notify_script_exec(notify_script_t* script, const char *type, int state_num, char* name, int prio)
{
	const char *state = "{UNKNOWN}";
	size_t size = 0;
	notify_script_t new_script;

	/*
	 * Determine the length of the buffer that we'll need to generate the command
	 * to run:
	 *
	 * "script" {GROUP|INSTANCE} "NAME" {MASTER|BACKUP|FAULT} PRIO
	 *
	 * Thus, the length of the buffer will be:
	 *
	 *     ( strlen(script) + 3 ) + ( strlen(type) + 1 ) + ( strlen(name) + 1 ) +
	 *      ( strlen(state) + 2 ) + ( strlen(prio) + 1 ) + 1
	 *
	 * Note that the prio will be indicated as zero for a group.
	 *
	 * Which is:
	 *     - The length of the script plus two enclosing quotes plus adjacent space
	 *     - The length of the type string plus the adjacent space
	 *     - The length of the name of the instance or group, plus two enclosing
	 *       quotes (just in case)
	 *     - The length of the state string plus the adjacent space
	 *     - The length of the priority value (3 digits) plus the adjacent
	 *       space
	 *     - The null-terminator
	 *
	 * Which results in:
	 *
	 *     strlen(script) + strlen(type) + strlen(state) + strlen(name) + 12
	 */
	switch (state_num) {
		case VRRP_STATE_MAST  : state = "MASTER" ; break;
		case VRRP_STATE_BACK  : state = "BACKUP" ; break;
		case VRRP_STATE_FAULT : state = "FAULT" ; break;
	}

	size = strlen(script->name) + strlen(type) + strlen(state) + strlen(name) + 12;
	new_script.name = MALLOC(size);
	if (!new_script.name)
		return;

	/* Launch the script */
	snprintf(new_script.name, size, "\"%s\" %s \"%s\" %s %d",
		 script->name, type, name, state, prio);
	new_script.uid = script->uid;
	new_script.gid = script->gid;

	notify_exec(&new_script);

	FREE(new_script.name);
}

int
notify_instance_exec(vrrp_t * vrrp, int state)
{
	notify_script_t *script = get_iscript(vrrp, state);
	notify_script_t *gscript = get_igscript(vrrp);
	int ret = 0;

	/* Launch the notify_* script */
	if (script && script_open(script)) {
		notify_exec(script);
		ret = 1;
	}

	/* Launch the generic notify script */
	if (gscript && script_open_literal(gscript->name)) {
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
	if (script && script_open(script)) {
		notify_exec(script);
		ret = 1;
	}

	/* Launch the generic notify script */
	if (gscript && script_open_literal(gscript->name)) {
		notify_script_exec(gscript, "GROUP", state, vgroup->gname, 0);
		ret = 1;
	}

	return ret;
}
