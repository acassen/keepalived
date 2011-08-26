/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        IPVS Kernel wrapper. Use setsockopt call to add/remove
 *              server to/from the loadbalanced server pool.
 *  
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *              
 *               This program is distributed in the hope that it will be useful,
 *               but WITHOUT ANY WARRANTY; without even the implied warranty of
 *               MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *               See the GNU General Public License for more details.
 *
 *               This program is free software; you can redistribute it and/or
 *               modify it under the terms of the GNU General Public License
 *               as published by the Free Software Foundation; either version
 *               2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include "ipvswrapper.h"
#include "check_data.h"
#include "list.h"
#include "utils.h"
#include "memory.h"
#include "logger.h"

/* local helpers functions */
static int parse_timeout(char *, unsigned *);
static int string_to_number(const char *, int, int);
static int modprobe_ipvs(void);

/* fetch virtual server group from group name */
virtual_server_group *
ipvs_get_group_by_name(char *gname, list l)
{
	element e;
	virtual_server_group *vsg;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg = ELEMENT_DATA(e);
		if (!strcmp(vsg->gname, gname))
			return vsg;
	}
	return NULL;
}

#ifdef _KRNL_2_4_			/* KERNEL 2.4 IPVS handling */

/* Global module def IPVS rules */
static struct ip_vs_rule_user *urule;

/* Initialization helpers */
int
ipvs_start(void)
{
	log_message(LOG_DEBUG, "Initializing ipvs 2.4");
	/* Init IPVS kernel channel */
	if (ipvs_init()) {
		/* try to insmod the ip_vs module if ipvs_init failed */
		if (modprobe_ipvs() || ipvs_init()) {
			log_message(LOG_INFO,
			       "IPVS : Can't initialize ipvs: %s",
		 	       ipvs_strerror(errno));
			return IPVS_ERROR;
		}
	}

	/* Allocate global user rules */
	urule = (struct ip_vs_rule_user *) MALLOC(sizeof (struct ip_vs_rule_user));
	return IPVS_SUCCESS;
}

void
ipvs_stop(void)
{
	/* Clean up the room */
	FREE(urule);
	ipvs_close();
}

static int
ipvs_talk(int cmd)
{
	int result;
	if (result = ipvs_command(cmd, urule))
		if ((cmd == IP_VS_SO_SET_EDITDEST) &&
		    (errno == ENOENT))
			result = ipvs_command(IP_VS_SO_SET_ADDDEST, urule);
	if (result)
		log_message(LOG_INFO, "IPVS : %s", ipvs_strerror(errno));
	return IPVS_SUCCESS;
}

int
ipvs_syncd_cmd(int cmd, char *ifname, int state, int syncid)
{
#ifdef _HAVE_IPVS_SYNCD_

	memset(urule, 0, sizeof (struct ip_vs_rule_user));

	/* prepare user rule */
	urule->state = state;
	urule->syncid = syncid;
	if (ifname != NULL)
		strncpy(urule->mcast_ifn, ifname, IP_VS_IFNAME_MAXLEN);

	/* Talk to the IPVS channel */
	return ipvs_talk(cmd);

#else
	log_message(LOG_INFO, "IPVS : Sync daemon not supported");
	return IPVS_ERROR;
#endif
}

/* IPVS group range rule */
static int
ipvs_group_range_cmd(int cmd, virtual_server_group_entry *vsg_entry)
{
	uint32_t addr_ip;
	int err = 0;

	/* Parse the whole range */
	for (addr_ip = inet_sockaddrip4(&vsg_entry->addr);
	     ((addr_ip >> 24) & 0xFF) <= vsg_entry->range;
	     addr_ip += 0x01000000) {
		urule->vaddr = addr_ip;
		urule->vport = inet_sockaddrport(&vsg_entry->addr);

		/* Talk to the IPVS channel */
		err = ipvs_talk(cmd);
	}

	return err;
}

/* set IPVS group rules */
static int
ipvs_group_cmd(int cmd, list vs_group, real_server * rs, char * vsgname)
{
	virtual_server_group *vsg = ipvs_get_group_by_name(vsgname, vs_group);
	virtual_server_group_entry *vsg_entry;
	list l;
	element e;
	int err = 1;

	/* return if jointure fails */
	if (!vsg) return -1;

	/* visit addr_ip list */
	l = vsg->addr_ip;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);
		urule->vaddr = inet_sockaddrip4(&vsg_entry->addr);
		urule->vport = inet_sockaddrport(&vsg_entry->addr);

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry, rs)) {
			err = ipvs_talk(cmd);
			IPVS_SET_ALIVE(cmd, vsg_entry);
		}
	}

	/* visit vfwmark list */
	l = vsg->vfwmark;
	urule->vaddr = 0;
	urule->vport = 0;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);
		urule->vfwmark = vsg_entry->vfwmark;

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry, rs)) {
			err = ipvs_talk(cmd);
			IPVS_SET_ALIVE(cmd, vsg_entry);
		}
	}

	/* visit range list */
	l = vsg->range;
	urule->vfwmark = 0;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry, rs)) {
			err = ipvs_group_range_cmd(cmd, vsg_entry);
			IPVS_SET_ALIVE(cmd, vsg_entry);
		}
	}

	return err;
}

/* Fill IPVS rule with root vs infos */
void
ipvs_set_rule(int cmd, virtual_server * vs, real_server * rs)
{
	/* Clean up target rule */
	memset(urule, 0, sizeof (struct ip_vs_rule_user));

	strncpy(urule->sched_name, vs->sched, IP_VS_SCHEDNAME_MAXLEN);
	urule->weight = 1;
	urule->conn_flags = vs->loadbalancing_kind;
	urule->netmask = ((u_int32_t) 0xffffffff);
	urule->protocol = vs->service_type;

	if (!parse_timeout(vs->timeout_persistence, &urule->timeout))
		log_message(LOG_INFO, "IPVS : Virtual service [%s]:%d illegal timeout."
				    , inet_ntop2(inet_sockaddrip4(&vs->addr))
				    , ntohs(inet_sockaddrport(&vs->addr)));

	if (urule->timeout != 0 || vs->granularity_persistence)
		urule->vs_flags = IP_VS_SVC_F_PERSISTENT;

	if (cmd == IP_VS_SO_SET_ADD || cmd == IP_VS_SO_SET_DEL)
		if (vs->granularity_persistence)
			urule->netmask = vs->granularity_persistence;

	/* SVR specific */
	if (rs) {
		if (cmd == IP_VS_SO_SET_ADDDEST
		    || cmd == IP_VS_SO_SET_DELDEST
		    || cmd == IP_VS_SO_SET_EDITDEST) {
			urule->weight = rs->weight;
			urule->daddr = inet_sockaddrip4(&rs->addr);
			urule->dport = inet_sockaddrport(&rs->addr);
		}
	}
}

/* Set/Remove a RS from a VS */
int
ipvs_cmd(int cmd, list vs_group, virtual_server * vs, real_server * rs)
{
	int err = 0;

	/* Prepare target rule */
	ipvs_set_rule(cmd, vs, rs);

	/* Does the service use inhibit flag ? */
	if (cmd == IP_VS_SO_SET_DELDEST && rs->inhibit) {
		urule->weight = 0;
		cmd = IP_VS_SO_SET_EDITDEST;
	}
	if (cmd == IP_VS_SO_SET_ADDDEST && rs->inhibit && rs->set)
		cmd = IP_VS_SO_SET_EDITDEST;

	/* Set flag */
	if (cmd == IP_VS_SO_SET_ADDDEST && !rs->set)
		rs->set = 1;
	if (cmd == IP_VS_SO_SET_DELDEST && rs->set)
		rs->set = 0;

	/* Set vs rule and send to kernel */
	if (vs->vsgname) {
		err = ipvs_group_cmd(cmd, vs_group, rs, vs->vsgname);
	} else {
		if (vs->vfwmark) {
			urule->vfwmark = vs->vfwmark;
		} else {
			urule->vaddr = inet_sockaddrip4(&vs->addr);
			urule->vport = inet_sockaddrport(&vs->addr);
		}

		/* Talk to the IPVS channel */
		err = ipvs_talk(cmd);
	}

	return err;
}

/* Remove a specific vs group entry */
int
ipvs_group_remove_entry(virtual_server *vs, virtual_server_group_entry *vsge)
{
	real_server *rs;
	int err = 0;
	element e;
	list l = vs->rs;

	/* Clean target rules */
	memset(urule, 0, sizeof (struct ip_vs_rule_user));

	/* Process realserver queue */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);

		if (rs->alive) {
			/* Prepare the IPVS rule */
			if (urule->daddr) {
				/* Setting IPVS rule with vs root rs */
				ipvs_set_rule(IP_VS_SO_SET_DELDEST, vs, rs);
			} else {
				urule->weight = rs->weight;
				urule->daddr = inet_sockaddrip4(&rs->addr);
				urule->dport = inet_sockaddrport(&rs->addr);
			}

			/* Set vs rule */
			if (vsge->range) {
				ipvs_group_range_cmd(IP_VS_SO_SET_DELDEST, vsge);
			} else {
				urule->vfwmark = vsge->vfwmark;
				urule->vaddr = inet_sockaddrip4(&vsge->addr);
				urule->vport = inet_sockaddrport(&vsge->addr);

				/* Talk to the IPVS channel */
				err = ipvs_talk(IP_VS_SO_SET_DELDEST);
			}
		}
	}

	/* Remove VS entry */
	if (vsge->range)
		err = ipvs_group_range_cmd(IP_VS_SO_SET_DEL, vsge);
	else
		err = ipvs_talk(IP_VS_SO_SET_DEL);
	return err;
}

#else					/* KERNEL 2.6 IPVS handling */

/* Global module def IPVS rules */
static ipvs_service_t *srule;
static ipvs_dest_t *drule;
static ipvs_daemon_t *daemonrule;

/* Initialization helpers */
int
ipvs_start(void)
{
	log_message(LOG_DEBUG, "Initializing ipvs 2.6");
	/* Initialize IPVS module */
	if (ipvs_init()) {
		if (modprobe_ipvs() || ipvs_init()) {
			log_message(LOG_INFO, "IPVS: Can't initialize ipvs: %s",
			       ipvs_strerror(errno));
			return IPVS_ERROR;
		}
	}

	/* Allocate global user rules */
	srule = (ipvs_service_t *) MALLOC(sizeof(ipvs_service_t));
	drule = (ipvs_dest_t *) MALLOC(sizeof(ipvs_dest_t));
	daemonrule = (ipvs_daemon_t *) MALLOC(sizeof(ipvs_daemon_t));
	return IPVS_SUCCESS;
}

void
ipvs_stop(void)
{
	/* Clean up the room */
	FREE(srule);
	FREE(drule);
	FREE(daemonrule);
	ipvs_close();
}

/* Send user rules to IPVS module */
static void
ipvs_talk(int cmd)
{
	int result = -1;

	switch (cmd) {
		case IP_VS_SO_SET_STARTDAEMON:
			result = ipvs_start_daemon(daemonrule);
			break;
		case IP_VS_SO_SET_STOPDAEMON:
			result = ipvs_stop_daemon(daemonrule);
			break;
		case IP_VS_SO_SET_ADD:
			result = ipvs_add_service(srule);
			break;
		case IP_VS_SO_SET_DEL:
			result = ipvs_del_service(srule);
			break;
		case IP_VS_SO_SET_EDIT:
			result = ipvs_update_service(srule);
			break;
		case IP_VS_SO_SET_ZERO:
			result = ipvs_zero_service(srule);
			break;
		case IP_VS_SO_SET_ADDDEST:
			result = ipvs_add_dest(srule, drule);
			break;
		case IP_VS_SO_SET_DELDEST:
			result = ipvs_del_dest(srule, drule);
			break;
		case IP_VS_SO_SET_EDITDEST:
			if ((result = ipvs_update_dest(srule, drule)) &&
			    (errno == ENOENT))
				result = ipvs_add_dest(srule, drule);
			break;
	}

	if (result)
		log_message(LOG_INFO, "IPVS: %s", ipvs_strerror(errno));
}

int
ipvs_syncd_cmd(int cmd, char *ifname, int state, int syncid)
{
	memset(daemonrule, 0, sizeof(ipvs_daemon_t));

	/* prepare user rule */
	daemonrule->state = state;
	daemonrule->syncid = syncid;
	if (ifname != NULL)
		strncpy(daemonrule->mcast_ifn, ifname, IP_VS_IFNAME_MAXLEN);

	/* Talk to the IPVS channel */
	ipvs_talk(cmd);
	return IPVS_SUCCESS;
}

/* IPVS group range rule */
static void
ipvs_group_range_cmd(int cmd, virtual_server_group_entry *vsg_entry)
{
	uint32_t addr_ip, ip;

	if (vsg_entry->addr.ss_family == AF_INET6) {
		inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
		ip = srule->addr.in6.s6_addr32[3];
	} else {
		ip = inet_sockaddrip4(&vsg_entry->addr);
	}

	/* Set Address Family */
	srule->af = vsg_entry->addr.ss_family;

	/* Parse the whole range */
	for (addr_ip = ip;
	     ((addr_ip >> 24) & 0xFF) <= vsg_entry->range;
	     addr_ip += 0x01000000) {
		if (srule->af == AF_INET6) {
			if (srule->netmask == 0xffffffff)
				srule->netmask = 128;
			srule->addr.in6.s6_addr32[3] = addr_ip;
		} else {
			srule->addr.ip = addr_ip;
		}
		srule->port = inet_sockaddrport(&vsg_entry->addr);

		/* Talk to the IPVS channel */
		ipvs_talk(cmd);
	}
}

/* set IPVS group rules */
static void
ipvs_group_cmd(int cmd, list vs_group, real_server * rs, char * vsgname)
{
	virtual_server_group *vsg = ipvs_get_group_by_name(vsgname, vs_group);
	virtual_server_group_entry *vsg_entry;
	list l;
	element e;

	/* return if jointure fails */
	if (!vsg) return;

	/* visit addr_ip list */
	l = vsg->addr_ip;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);
		srule->af = vsg_entry->addr.ss_family;
		if (vsg_entry->addr.ss_family == AF_INET6) {
			if (srule->netmask == 0xffffffff)
				srule->netmask = 128;
			inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
		} else
			srule->addr.ip = inet_sockaddrip4(&vsg_entry->addr);
		srule->port = inet_sockaddrport(&vsg_entry->addr);

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry, rs)) {
			ipvs_talk(cmd);
			IPVS_SET_ALIVE(cmd, vsg_entry);
		}
	}

	/* visit vfwmark list */
	l = vsg->vfwmark;
	srule->addr.ip = 0;
	srule->af = 0;
	srule->port = 0;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);
		srule->af = AF_INET;
		srule->fwmark = vsg_entry->vfwmark;

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry, rs)) {
			ipvs_talk(cmd);
			IPVS_SET_ALIVE(cmd, vsg_entry);
		}
	}

	/* visit range list */
	l = vsg->range;
	srule->fwmark = 0;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry, rs)) {
			ipvs_group_range_cmd(cmd, vsg_entry);
			IPVS_SET_ALIVE(cmd, vsg_entry);
		}
	}
}

/* Fill IPVS rule with root vs infos */
void
ipvs_set_rule(int cmd, virtual_server * vs, real_server * rs)
{
	/* Clean target rule */
	memset(drule, 0, sizeof(ipvs_dest_t));

	drule->weight = 1;
	drule->u_threshold = 0;
	drule->l_threshold = 0;
	drule->conn_flags = vs->loadbalancing_kind;
	strncpy(srule->sched_name, vs->sched, IP_VS_SCHEDNAME_MAXLEN);
	srule->netmask = (vs->addr.ss_family == AF_INET6) ? 128 : ((u_int32_t) 0xffffffff);
	srule->protocol = vs->service_type;

	if (!parse_timeout(vs->timeout_persistence, &srule->timeout))
		log_message(LOG_INFO, "IPVS : Virtual service [%s]:%d illegal timeout."
				    , inet_ntop2(inet_sockaddrip4(&vs->addr))
				    , ntohs(inet_sockaddrport(&vs->addr)));

	if (srule->timeout != 0 || vs->granularity_persistence)
		srule->flags = IP_VS_SVC_F_PERSISTENT;

	if (cmd == IP_VS_SO_SET_ADD || cmd == IP_VS_SO_SET_DEL)
		if (vs->granularity_persistence)
			srule->netmask = vs->granularity_persistence;

	/* SVR specific */
	if (rs) {
		if (cmd == IP_VS_SO_SET_ADDDEST || cmd == IP_VS_SO_SET_DELDEST ||
		    cmd == IP_VS_SO_SET_EDITDEST) {
			drule->af = rs->addr.ss_family;
			if (rs->addr.ss_family == AF_INET6)
				inet_sockaddrip6(&rs->addr, &drule->addr.in6);
			else
				drule->addr.ip = inet_sockaddrip4(&rs->addr);
			drule->port = inet_sockaddrport(&rs->addr);
			drule->weight = rs->weight;	
			drule->u_threshold = rs->u_threshold;
			drule->l_threshold = rs->l_threshold;
		}
	}
}

/* Set/Remove a RS from a VS */
int
ipvs_cmd(int cmd, list vs_group, virtual_server * vs, real_server * rs)
{
	/* Allocate the room */
	memset(srule, 0, sizeof(ipvs_service_t));
	ipvs_set_rule(cmd, vs, rs);

	/* Does the service use inhibit flag ? */
	if (cmd == IP_VS_SO_SET_DELDEST && rs->inhibit) {
		drule->weight = 0;
		cmd = IP_VS_SO_SET_EDITDEST;
	}
	if (cmd == IP_VS_SO_SET_ADDDEST && rs->inhibit && rs->set)
		cmd = IP_VS_SO_SET_EDITDEST;

	/* Set flag */
	if (cmd == IP_VS_SO_SET_ADDDEST && !rs->set)
		rs->set = 1;
	if (cmd == IP_VS_SO_SET_DELDEST && rs->set)
		rs->set = 0;

	/* Set vs rule and send to kernel */
	if (vs->vsgname) {
		ipvs_group_cmd(cmd, vs_group, rs, vs->vsgname);
	} else {
		if (vs->vfwmark) {
			srule->af = AF_INET;
			srule->fwmark = vs->vfwmark;
		} else {
			srule->af = vs->addr.ss_family;
			if (vs->addr.ss_family == AF_INET6)
				inet_sockaddrip6(&vs->addr, &srule->addr.in6);
			else
				srule->addr.ip = inet_sockaddrip4(&vs->addr);
			srule->port = inet_sockaddrport(&vs->addr);
		}

		/* Talk to the IPVS channel */
		ipvs_talk(cmd);
	}

	return IPVS_SUCCESS;
}

/* Remove a specific vs group entry */
int
ipvs_group_remove_entry(virtual_server *vs, virtual_server_group_entry *vsge)
{
	real_server *rs;
	element e;
	list l = vs->rs;

	/* Clean target rules */
	memset(srule, 0, sizeof(ipvs_service_t));
	memset(drule, 0, sizeof(ipvs_dest_t));

	/* Process realserver queue */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);

		if (rs->alive) {
			/* Prepare the IPVS rule */
			if (!drule->addr.ip) {
				/* Setting IPVS rule with vs root rs */
				ipvs_set_rule(IP_VS_SO_SET_DELDEST, vs, rs);
			} else {
				drule->af = rs->addr.ss_family;
				if (rs->addr.ss_family == AF_INET6)
					inet_sockaddrip6(&rs->addr, &drule->addr.in6);
				else
					drule->addr.ip = inet_sockaddrip4(&rs->addr);
				drule->port = inet_sockaddrport(&rs->addr);
				drule->weight = rs->weight;
			}

			/* Set vs rule */
			if (vsge->range) {
				ipvs_group_range_cmd(IP_VS_SO_SET_DELDEST, vsge);
			} else {
				srule->af = vsge->addr.ss_family;
				if (vsge->addr.ss_family == AF_INET6)
					inet_sockaddrip6(&vsge->addr, &srule->addr.in6);
				else
					srule->addr.ip = inet_sockaddrip4(&vsge->addr);
				srule->port = inet_sockaddrport(&vsge->addr);
				srule->fwmark = vsge->vfwmark;
				drule->u_threshold = rs->u_threshold;
				drule->l_threshold = rs->l_threshold;

				/* Talk to the IPVS channel */
				ipvs_talk(IP_VS_SO_SET_DELDEST);
			}
		}
	}

	/* Remove VS entry */
	if (vsge->range)
		ipvs_group_range_cmd(IP_VS_SO_SET_DEL, vsge);
	else
		ipvs_talk(IP_VS_SO_SET_DEL);

	return IPVS_SUCCESS;
}

#endif

/*
 * Common IPVS functions
 */
void
ipvs_syncd_master(char *ifname, int syncid)
{
	ipvs_syncd_cmd(IPVS_STOPDAEMON, ifname, IPVS_BACKUP, syncid);
	ipvs_syncd_cmd(IPVS_STARTDAEMON, ifname, IPVS_MASTER, syncid);
}

void
ipvs_syncd_backup(char *ifname, int syncid)
{
	ipvs_syncd_cmd(IPVS_STOPDAEMON, ifname, IPVS_MASTER, syncid);
	ipvs_syncd_cmd(IPVS_STARTDAEMON, ifname, IPVS_BACKUP, syncid);
}

/*
 * Utility functions coming from Wensong code
 */

static int
parse_timeout(char *buf, unsigned *timeout)
{
	int i;

	if (buf == NULL) {
		*timeout = IP_VS_TEMPLATE_TIMEOUT;
		return 1;
	}

	if ((i = string_to_number(buf, 0, 86400 * 31)) == -1)
		return 0;

	*timeout = i * (IP_VS_TEMPLATE_TIMEOUT / (6*60));
	return 1;
}

static int
string_to_number(const char *s, int min, int max)
{
	int number;
	char *end;

	number = (int) strtol(s, &end, 10);
	if (*end == '\0' && end != s) {
		/*
		 * We parsed a number, let's see if we want this.
		 * If max <= min then ignore ranges
		 */
		if (max <= min || (min <= number && number <= max))
			return number;
		else
			return -1;
	} else
		return -1;
}

static int
modprobe_ipvs(void)
{
	char *argv[] = { "/sbin/modprobe", "-s", "--", "ip_vs", NULL };
	int child;
	int status;
	int rc;

	if (!(child = fork())) {
		execv(argv[0], argv);
		exit(1);
	}

	rc = waitpid(child, &status, 0);

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		return 1;
	}

	return 0;
}
