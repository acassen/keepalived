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

/* system include */
#include <ctype.h>
#include <stdbool.h>

/* local include */
#include "vrrp_notify.h"
#include "memory.h"
#include "notify.h"
#include "logger.h"

static char *
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

static char *
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

static char *
get_ggscript(vrrp_sgroup_t * vgroup)
{
	return vgroup->script;
}

static char *
notify_script_name(char *cmdline)
{
	char *cp = cmdline;
	char *script;
	int str_len;

	if (!cmdline)
		return NULL;
	while (!isspace((int) *cp) && *cp != '\0')
		cp++;
	str_len = cp - cmdline;
	script = MALLOC(str_len + 1);
	memcpy(script, cmdline, str_len);
	*(script + str_len) = '\0';

	return script;
}

static int
script_open_litteral(char *script)
{
	log_message(LOG_DEBUG, "Opening script file %s",script);
	FILE *fOut = fopen(script, "r");;
	if (!fOut) {
		log_message(LOG_INFO, "Can't open %s (errno %d %s)", script,
		       errno, strerror(errno));
		return 0;
	}
	fclose(fOut);
	return 1;
}

static int
script_open(char *script)
{
	char *name = notify_script_name(script);
	int ret = name ? script_open_litteral(name) : 0;
	if (name)
		FREE(name);
	return ret;
}

static int
notify_script_exec(char* script, char *type, int state_num, char* name, int prio)
{
	char *state = "{UNKNOWN}";
	char *command_line = NULL;
	int size = 0;

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

	size = strlen(script) + strlen(type) + strlen(state) + strlen(name) + 12;
	command_line = MALLOC(size);
	if (!command_line)
		return 0;

	/* Launch the script */
	snprintf(command_line, size, "\"%s\" %s \"%s\" %s %d",
		 script, type, name, state, prio);
	notify_exec(command_line);
	FREE(command_line);
	return 1;
}

/* This function acts as a proxy, temporarily changing each VRRP's notify
 * list. It should be called when we are in the init state. We get to this
 * stage if our daemon has just been initialized, or if we perform a reload
 * on the daemon. In the latter situation, this causes us to leave and then
 * re-enter the state we just left. We do not want to notify when we go
 * from, for example, master->master.
 *
 * This function prevents the above from happening by comparing our current
 * configured notify script list with the previous scripts we had configured.
 * We create a new list that contains scripts that are in our current
 * configuration AND were not in our configuration before reload.
 * We then update our vrrp instance to point to this list temporarily before
 * calling notify_instance_exec(...). After this call has returned, we then
 * update our vrrp reference to point back to the original, currently configured
 * list.
 */
int
notify_instance_exec_init(vrrp_t * vrrp, int state)
{
	bool match = false;
	char *cur_script, *prev_script;
	element e_cur, e_prev = NULL;
	int ret;
	list l_temp = alloc_list(NULL, dump_notify_script);
	list l_orig = vrrp->script;
	notify_sc_t *nsc_cur, *nsc_prev = NULL;

	/* The algorithm here is essentially:
	 * for each element in our currently configured list
	 * 		if this element did not exist in our previous configuration
	 * 			add this element to our temporary list
	 *
	 * NOTE: this loop can be optimised if scripts are stored in an
	 * alphabetical order. The inner loop can be exited early if
	 * strcmp returns > 0.
	 */
	if (!LIST_ISEMPTY(vrrp->script) && !LIST_ISEMPTY(vrrp->pscript[0])) {
		for (e_cur = LIST_HEAD(vrrp->script); e_cur; ELEMENT_NEXT(e_cur)) {
			nsc_cur = e_cur->data;
			cur_script = nsc_cur->sname;
			for (e_prev = LIST_HEAD(vrrp->pscript[0]); e_prev; ELEMENT_NEXT(e_prev)) {
				nsc_prev = e_prev->data;
				prev_script = nsc_prev->sname;
				if (strcmp(cur_script, prev_script) == 0) {
					match = true;
					break;
				}
			}
			if (match == false)
				list_add(l_temp, nsc_cur);
			match = false;
		}
		/* Change our reference to temp list. This means the call to
		 * notify_instance_exec(...) will only invoke the scripts that we
		 * have not previously been configured with.
		 */
		vrrp->script = l_temp;
	}
	ret = notify_instance_exec(vrrp, state);

	/* Reset our reference back to our original list containing all our
	 * configured scripts. This means subsequent state changes will cause
	 * all of our configured scripts to be executed
	 */
	vrrp->script = l_orig;

	free_list(l_temp);
	return ret;
}

int
notify_instance_exec(vrrp_t * vrrp, int state)
{
	char *script = get_iscript(vrrp, state);
	int ret = 0;
    element e;
    notify_sc_t *nsc;

	/* Launch the notify_* script */
	if (script && script_open(script)) {
		notify_exec(script);
		ret = 1;
	}

	/* Launch the generic notify script */
    if (!LIST_ISEMPTY(vrrp->script)) {
        for (e = LIST_HEAD(vrrp->script); e; ELEMENT_NEXT(e)) {
            nsc = ELEMENT_DATA(e);
            if (nsc->sname && script_open_litteral(nsc->sname)) {
                notify_script_exec(nsc->sname, "INSTANCE", state, vrrp->iname,
                   vrrp->effective_priority);
                ret = 1;
            }
        }
    }
	return ret;
}

int
notify_group_exec(vrrp_sgroup_t * vgroup, int state)
{
	char *script = get_gscript(vgroup, state);
	char *gscript = get_ggscript(vgroup);
	int ret = 0;

	/* Launch the notify_* script */
	if (script && script_open(script)) {
		notify_exec(script);
		ret = 1;
	}

	/* Launch the generic notify script */
	if (gscript && script_open_litteral(gscript)) {
		notify_script_exec(gscript, "GROUP", state, vgroup->gname, 0);
		ret = 1;
	}

	return ret;
}

/* Notify script dump */
void
dump_notify_script(void *data)
{
    notify_sc_t *nsc = data;
    log_message(LOG_INFO, "      %s", nsc->sname);
}

void
alloc_notify_script(list notify_list, vector_t *strvec)
{
    notify_sc_t *nsc = NULL;
    nsc = (notify_sc_t *) MALLOC(sizeof(notify_sc_t));
    nsc->sname = (char *)MALLOC(strlen(vector_slot(strvec, 0)) + 1);
    strncpy(nsc->sname, vector_slot(strvec, 0), strlen(vector_slot(strvec, 0)) + 1);
    list_add(notify_list, nsc);
}
