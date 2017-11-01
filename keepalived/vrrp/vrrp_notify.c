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
#include <unistd.h>

/* local include */
#include "vrrp_notify.h"
#ifdef _WITH_DBUS_
#include "vrrp_dbus.h"
#endif
#include "global_data.h"
#include "notify.h"
#include "logger.h"
#ifdef _WITH_SNMP_
#include "vrrp_snmp.h"
#endif
#include "smtp.h"

static notify_script_t*
get_iscript(vrrp_t * vrrp)
{
	if (!vrrp->notify_exec)
		return NULL;
	if (vrrp->state == VRRP_STATE_BACK)
		return vrrp->script_backup;
	if (vrrp->state == VRRP_STATE_MAST)
		return vrrp->script_master;
	if (vrrp->state == VRRP_STATE_FAULT)
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
notify_fifo(const char *name, int state_num, bool group, uint8_t priority)
{
	char *state = "{UNKNOWN}";
	size_t size;
	char *line;
	char *type;

	if (global_data->notify_fifo.fd == -1 &&
	    global_data->vrrp_notify_fifo.fd == -1)
		return;

	switch (state_num) {
		case VRRP_STATE_MAST  : state = "MASTER" ; break;
		case VRRP_STATE_BACK  : state = "BACKUP" ; break;
		case VRRP_STATE_FAULT : state = "FAULT" ; break;
		case VRRP_STATE_STOP  : state = "STOP" ; break;
	}

	type = group ? "GROUP" : "INSTANCE";

	size = strlen(type) + strlen(state) + strlen(name) + 10;
	line = MALLOC(size);
	if (!line)
		return;

	snprintf(line, size, "%s \"%s\" %s %d\n", type, name, state, priority);

	if (global_data->notify_fifo.fd != -1) {
		if (write(global_data->notify_fifo.fd, line, strlen(line)) == -1) {}
	}
	if (global_data->vrrp_notify_fifo.fd != -1) {
		if (write(global_data->vrrp_notify_fifo.fd, line, strlen(line)) == -1) {}
	}

	FREE(line);
}

void
notify_instance_fifo(const vrrp_t *vrrp, int state_num)
{
	notify_fifo(vrrp->iname, state_num, false, vrrp->effective_priority);
}

static void
notify_group_fifo(const vrrp_sgroup_t *vgroup)
{
	notify_fifo(vgroup->gname, vgroup->state, true, 0);
}

static void
notify_script_exec(notify_script_t* script, char *type, int state_num, char* name, int prio)
{
	notify_script_t new_script;
	char *args[6];
	char prio_buf[4];

	/*
	 * script {GROUP|INSTANCE} NAME {MASTER|BACKUP|FAULT} PRIO
	 *
	 * Note that the prio will be indicated as zero for a group.
	 *
	 */
	args[0] = script->args[0];
	args[1] = type;
	args[2] = name;
	switch (state_num) {
		case VRRP_STATE_MAST  : args[3] = "MASTER" ; break;
		case VRRP_STATE_BACK  : args[3] = "BACKUP" ; break;
		case VRRP_STATE_FAULT : args[3] = "FAULT" ; break;
		default:		args[3] = "{UNKNOWN}"; break;
	}
	snprintf(prio_buf, sizeof(prio_buf), "%d", prio);
	args[4] = prio_buf;
	args[5] = NULL;
	new_script.args = args;

	/* Launch the script */
	new_script.cmd_str = NULL;
	new_script.uid = script->uid;
	new_script.gid = script->gid;

	notify_exec(&new_script);
}

static int
notify_instance_exec(vrrp_t * vrrp)
{
	notify_script_t *script = get_iscript(vrrp);
	notify_script_t *gscript = get_igscript(vrrp);
	int ret = 0;

	/* Launch the notify_* script */
	if (script) {
		notify_exec(script);
		ret = 1;
	}

	/* Launch the generic notify script */
	if (gscript) {
		notify_script_exec(gscript, "INSTANCE", vrrp->state, vrrp->iname,
				   vrrp->effective_priority);
		ret = 1;
	}

	notify_instance_fifo(vrrp, vrrp->state);

#ifdef _WITH_DBUS_
	if (global_data->enable_dbus)
		dbus_send_state_signal(vrrp); // send signal to all subscribers
#endif

	return ret;
}

static int
notify_group_exec(vrrp_sgroup_t * vgroup)
{
	notify_script_t *script = get_gscript(vgroup, vgroup->state);
	notify_script_t *gscript = get_ggscript(vgroup);
	int ret = 0;

	/* Launch the notify_* script */
	if (script) {
		notify_exec(script);
		ret = 1;
	}

	/* Launch the generic notify script */
	if (gscript) {
		notify_script_exec(gscript, "GROUP", vgroup->state, vgroup->gname, 0);
		ret = 1;
	}

	notify_group_fifo(vgroup);

	return ret;
}

/* SMTP alert notifier */
static void
vrrp_smtp_notifier(vrrp_t * vrrp)
{
	if (vrrp->smtp_alert &&
	    (global_data->email_faults || vrrp->state != VRRP_STATE_FAULT) &&
	    vrrp->last_email_state != vrrp->state) {
		if (vrrp->state == VRRP_STATE_MAST)
			smtp_alert(NULL, vrrp, NULL,
				   "Entering MASTER state",
				   "=> VRRP Instance is now owning VRRP VIPs <=");
		else if (vrrp->state == VRRP_STATE_BACK)
			smtp_alert(NULL, vrrp, NULL,
				   "Entering BACKUP state",
				   "=> VRRP Instance is no longer owning VRRP VIPs <=");
		else if (vrrp->state == VRRP_STATE_FAULT)
			smtp_alert(NULL, vrrp, NULL,
				   "Entering FAULT state",
				   "=> VRRP Instance is no longer owning VRRP VIPs <=");

		vrrp->last_email_state = vrrp->state;
	}
}

/* SMTP alert group notifier */
static void
vrrp_sync_smtp_notifier(vrrp_sgroup_t *vgroup)
{
	if (vgroup->smtp_alert &&
	    (global_data->email_faults || vgroup->state != VRRP_STATE_FAULT) &&
	    vgroup->last_email_state != vgroup->state) {
		if (vgroup->state == VRRP_STATE_MAST)
			smtp_alert(NULL, NULL, vgroup,
				   "Entering MASTER state",
				   "=> All VRRP group instances are now in MASTER state <=");
		else if (vgroup->state == VRRP_STATE_BACK)
			smtp_alert(NULL, NULL, vgroup,
				   "Entering BACKUP state",
				   "=> All VRRP group instances are now in BACKUP state <=");
		else if (vgroup->state == VRRP_STATE_FAULT)
			smtp_alert(NULL, NULL, vgroup,
				   "Entering FAULT state",
				   "=> All VRRP group instances are now in FAULT state <=");

		vgroup->last_email_state = vgroup->state;
	}
}

void
send_instance_notifies(vrrp_t *vrrp)
{
	notify_instance_exec(vrrp);
#ifdef _WITH_SNMP_KEEPALIVED_
	vrrp_snmp_instance_trap(vrrp);
#endif
	if (vrrp->state == VRRP_STATE_MAST) {
#ifdef _WITH_SNMP_RFCV2_
		vrrp_rfcv2_snmp_new_master_trap(vrrp);
#endif
#ifdef _WITH_SNMP_RFCV3_
		vrrp_rfcv3_snmp_new_master_notify(vrrp);
#endif
	}
	vrrp_smtp_notifier(vrrp);
}

void
send_group_notifies(vrrp_sgroup_t *vgroup)
{
	notify_group_exec(vgroup);
#ifdef _WITH_SNMP_KEEPALIVED_
	vrrp_snmp_group_trap(vgroup);
#endif
	vrrp_sync_smtp_notifier(vgroup);
}
