/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        VRRP state transition notification scripts handling.
 *
 * Version:     $Id: vrrp_notify.c,v 1.1.0 2003/07/20 23:41:34 acassen Exp $
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
 */

/* system include */
#include <ctype.h>

/* local include */
#include "vrrp_notify.h"
#include "memory.h"
#include "notify.h"

static char *
get_iscript(vrrp_rt * vrrp, int state)
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

static char *
get_gscript(vrrp_sgroup * vgroup, int state)
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

static char *
notify_script_name(char *cmdline)
{
	char *cp = cmdline;
	char *script;
	int strlen;

	if (!cmdline)
		return NULL;
	while (!isspace((int) *cp) && *cp != '\0')
		cp++;
	strlen = cp - cmdline;
	script = MALLOC(strlen + 1);
	memcpy(script, cmdline, strlen);
	*(script + strlen) = '\0';

	return script;
}

static int
script_open(char *script)
{
	char *script_name = notify_script_name(script);
	FILE *fOut;

	fOut = fopen(script_name, "r");;
	if (!fOut) {
		syslog(LOG_INFO, "Can't open %s (errno %d %s)", script_name,
		       errno, strerror(errno));
		return 0;
	}
	FREE(script_name);
	fclose(fOut);
	return 1;
}

int
notify_instance_exec(vrrp_rt * vrrp, int state)
{
	char *script = get_iscript(vrrp, state);

	if (!script || !script_open(script))
		return 0;

	/* Launch the script */
	notify_exec(script);
	return 1;
}

int
notify_group_exec(vrrp_sgroup * vgroup, int state)
{
	char *script = get_gscript(vgroup, state);

	if (!script || !script_open(script))
		return 0;

	/* Launch the script */
	notify_exec(script);
	return 1;
}
