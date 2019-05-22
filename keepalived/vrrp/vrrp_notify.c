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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

/* system include */
#include <errno.h>
#include <unistd.h>
#include <main.h>

/* local include */
#include "vrrp_notify.h"
#include "vrrp_data.h"
#ifdef _WITH_DBUS_
#include "vrrp_dbus.h"
#endif
#include "global_data.h"
#include "notify.h"
#include "logger.h"
#if defined _WITH_SNMP_RFC_ || defined _WITH_SNMP_VRRP_
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
	if (vrrp->state == VRRP_STATE_STOP)
		return vrrp->script_stop;
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
	if (state == VRRP_STATE_STOP)
		return vgroup->script_stop;
	return NULL;
}

static inline notify_script_t*
get_igscript(vrrp_t *vrrp)
{
	return vrrp->script;
}

static inline notify_script_t*
get_ggscript(vrrp_sgroup_t * vgroup)
{
	return vgroup->script;
}

static void
notify_fifo(const char *name, int state_num, bool group, uint8_t priority)
{
	const char *state = "{UNKNOWN}";
	size_t size;
	char *line;
	const char *type;

	if (global_data->notify_fifo.fd == -1 &&
	    global_data->vrrp_notify_fifo.fd == -1)
		return;

	switch (state_num) {
	case VRRP_STATE_MAST:
		state = "MASTER";
		break;
	case VRRP_STATE_BACK:
		state = "BACKUP";
		break;
	case VRRP_STATE_FAULT:
		state = "FAULT";
		break;
	case VRRP_STATE_STOP:
		state = "STOP";
		break;
	case VRRP_EVENT_MASTER_RX_LOWER_PRI:
		state = "MASTER_RX_LOWER_PRI";
		break;
	case VRRP_EVENT_MASTER_PRIORITY_CHANGE:
		state = "MASTER_PRIORITY";
		break;
	case VRRP_EVENT_BACKUP_PRIORITY_CHANGE:
		state = "BACKUP_PRIORITY";
		break;
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

static void
notify_instance_fifo(const vrrp_t *vrrp)
{
	notify_fifo(vrrp->iname, vrrp->state, false, vrrp->effective_priority);
}

static void
notify_group_fifo(const vrrp_sgroup_t *vgroup)
{
	notify_fifo(vgroup->gname, vgroup->state, true, 0);
}

static void
notify_script_exec(notify_script_t* script, const char *type, int state_num, const char* name, int prio)
{
	char prio_buf[4];

	/*
	 * script {GROUP|INSTANCE} NAME {MASTER|BACKUP|FAULT|STOP} PRIO
	 *
	 * Note that the prio will be indicated as zero for a group.
	 *
	 */
	script->args[script->num_args] = type;
	script->args[script->num_args+1] = name;
	switch (state_num) {
		case VRRP_STATE_MAST  : script->args[script->num_args+2] = "MASTER" ; break;
		case VRRP_STATE_BACK  : script->args[script->num_args+2] = "BACKUP" ; break;
		case VRRP_STATE_FAULT : script->args[script->num_args+2] = "FAULT" ; break;
		case VRRP_STATE_STOP  : script->args[script->num_args+2] = "STOP" ; break;
		default:		script->args[script->num_args+2] = "{UNKNOWN}"; break;
	}
	snprintf(prio_buf, sizeof(prio_buf), "%d", prio);
	script->args[script->num_args+3] = prio_buf;
	script->num_args += 4;

	/* Launch the script */
	if (state_num == VRRP_STATE_STOP)
		system_call_script(master, child_killed_thread, NULL, TIMER_HZ, script);
	else
		notify_exec(script);
	script->num_args -= 4;
}

/* SMTP alert notifier */
static void
vrrp_smtp_notifier(vrrp_t * vrrp)
{
	if (vrrp->smtp_alert &&
	    (!global_data->no_email_faults || vrrp->state != VRRP_STATE_FAULT) &&
	    vrrp->last_email_state != vrrp->state) {
		if (vrrp->state == VRRP_STATE_MAST)
			smtp_alert(SMTP_MSG_VRRP, vrrp,
				   "Entering MASTER state",
				   "=> VRRP Instance is now owning VRRP VIPs <=");
		else if (vrrp->state == VRRP_STATE_BACK)
			smtp_alert(SMTP_MSG_VRRP, vrrp,
				   "Entering BACKUP state",
				   "=> VRRP Instance is no longer owning VRRP VIPs <=");
		else if (vrrp->state == VRRP_STATE_FAULT)
			smtp_alert(SMTP_MSG_VRRP, vrrp,
				   "Entering FAULT state",
				   "=> VRRP Instance is no longer owning VRRP VIPs <=");
		else if (vrrp->state == VRRP_STATE_STOP)
			smtp_alert(SMTP_MSG_VRRP, vrrp,
				   "Stopping",
				   "=> VRRP Instance stopping <=");
		else
			return;

		vrrp->last_email_state = vrrp->state;
	}
}

/* SMTP alert group notifier */
static void
vrrp_sync_smtp_notifier(vrrp_sgroup_t *vgroup)
{
	if (vgroup->smtp_alert &&
	    (!global_data->no_email_faults || vgroup->state != VRRP_STATE_FAULT) &&
	    vgroup->last_email_state != vgroup->state) {
		if (vgroup->state == VRRP_STATE_MAST)
			smtp_alert(SMTP_MSG_VGROUP, vgroup,
				   "Entering MASTER state",
				   "=> All VRRP group instances are now in MASTER state <=");
		else if (vgroup->state == VRRP_STATE_BACK)
			smtp_alert(SMTP_MSG_VGROUP, vgroup,
				   "Entering BACKUP state",
				   "=> All VRRP group instances are now in BACKUP state <=");
		else if (vgroup->state == VRRP_STATE_FAULT)
			smtp_alert(SMTP_MSG_VGROUP, vgroup,
				   "Entering FAULT state",
				   "=> All VRRP group instances are now in FAULT state <=");
		else if (vgroup->state == VRRP_STATE_STOP)
			smtp_alert(SMTP_MSG_VGROUP, vgroup,
				   "Stopping",
				   "=> All VRRP group instances are now stopping <=");
		else
			return;

		vgroup->last_email_state = vgroup->state;
	}
}

void
send_event_notify(vrrp_t *vrrp, int event)
{
	notify_script_t *script = vrrp->script_master_rx_lower_pri;

	/* Launch the notify_* script */
	if (script)
		notify_exec(script);

	notify_fifo(vrrp->iname, event, false, vrrp->effective_priority);
}

void
send_instance_notifies(vrrp_t *vrrp)
{
	notify_script_t *script = get_iscript(vrrp);
	notify_script_t *gscript = get_igscript(vrrp);

	if (vrrp->notifies_sent && vrrp->sync && vrrp->state == vrrp->sync->state) {
		/* We are already in the required state due to our sync group,
		 * so don't send further notifies. */
		return;
	}

	vrrp->notifies_sent = true;

	/* Launch the notify_* script */
	if (script) {
		if (vrrp->state == VRRP_STATE_STOP)
			system_call_script(master, child_killed_thread, NULL, TIMER_HZ, script);
		else
			notify_exec(script);
	}

	/* Launch the generic notify script */
	if (gscript)
		notify_script_exec(gscript, "INSTANCE", vrrp->state, vrrp->iname,
				   vrrp->effective_priority);

	notify_instance_fifo(vrrp);

#ifdef _WITH_DBUS_
	if (global_data->enable_dbus)
		dbus_send_state_signal(vrrp); // send signal to all subscribers
#endif

#ifdef _WITH_SNMP_VRRP_
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
	notify_script_t *script = get_gscript(vgroup, vgroup->state);
	notify_script_t *gscript = get_ggscript(vgroup);

	/* Launch the notify_* script */
	if (script)
		notify_exec(script);

	/* Launch the generic notify script */
	if (gscript)
		notify_script_exec(gscript, "GROUP", vgroup->state, vgroup->gname, 0);

	notify_group_fifo(vgroup);

#ifdef _WITH_SNMP_VRRP_
	vrrp_snmp_group_trap(vgroup);
#endif
	vrrp_sync_smtp_notifier(vgroup);
}

void
send_instance_priority_notifies(vrrp_t *vrrp)
{
	notify_fifo(vrrp->iname,
		    vrrp->state == VRRP_STATE_MAST ? VRRP_EVENT_MASTER_PRIORITY_CHANGE : VRRP_EVENT_BACKUP_PRIORITY_CHANGE,
		    false,
		    vrrp->effective_priority);
}

/* handle terminate state */
void
notify_shutdown(void)
{
	element e;
	vrrp_t *vrrp;
	vrrp_sgroup_t *vgroup;

	LIST_FOREACH(vrrp_data->vrrp, vrrp, e) {
		vrrp->state = VRRP_STATE_STOP;
		send_instance_notifies(vrrp);
	}

	LIST_FOREACH(vrrp_data->vrrp_sync_group, vgroup, e) {
		vgroup->state = VRRP_STATE_STOP;
		send_group_notifies(vgroup);
	}
}
