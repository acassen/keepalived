/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        IPVS Kernel wrapper. Use setsockopt call to add/remove
 *              server to/from the loadbalanced server pool.
 *  
 * Version:     $Id: ipvswrapper.c,v 1.0.2 2003/04/14 02:35:12 acassen Exp $
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
 */

#include "data.h"
#include "list.h"
#include "ipvswrapper.h"
#include "utils.h"
#include "memory.h"

/* external types */
extern data *conf_data;

/* local helpers functions */
static int parse_timeout(char *, unsigned *);
static int string_to_number(const char *, int, int);
static int modprobe_ipvs(void);

#ifdef _KRNL_2_2_		/* KERNEL 2.2 LVS handling */

int
ipvs_syncd_cmd(int cmd, char *ifname, int state)
{
	syslog(LOG_INFO, "IPVS : Sync daemon not supported on kernel v2.2");
	return IPVS_ERROR;
}

int
ipvs_cmd(int cmd, list vs_group, virtual_server * vs, real_server * rs)
{
	struct ip_masq_ctl ctl;
	int result = 0;
	int sockfd;

	memset(&ctl, 0, sizeof (struct ip_masq_ctl));

	ctl.m_target = IP_MASQ_TARGET_VS;
	ctl.m_cmd = cmd;
	strncpy(ctl.m_tname, vs->sched, IP_MASQ_TNAME_MAX);
	ctl.u.vs_user.weight = -1;
	ctl.u.vs_user.masq_flags = vs->loadbalancing_kind;
	ctl.u.vs_user.netmask = ((u_int32_t) 0xffffffff);
	ctl.u.vs_user.protocol = vs->service_type;

	if (!parse_timeout(vs->timeout_persistence, &ctl.u.vs_user.timeout))
		syslog(LOG_INFO,
		       "IPVS : Virtual service [%s:%d] illegal timeout.",
		       inet_ntop2(SVR_IP(vs))
		       , ntohs(SVR_PORT(vs)));
	if (ctl.u.vs_user.timeout != 0 || vs->granularity_persistence)
		ctl.u.vs_user.vs_flags = IP_VS_SVC_F_PERSISTENT;

	/* VS specific */
	if (vs->vfwmark) {
		ctl.u.vs_user.vfwmark = vs->vfwmark;
	} else {
		ctl.u.vs_user.vaddr = SVR_IP(vs);
		ctl.u.vs_user.vport = SVR_PORT(vs);
	}

	if (ctl.m_cmd == IP_MASQ_CMD_ADD || ctl.m_cmd == IP_MASQ_CMD_DEL)
		if (vs->granularity_persistence)
			ctl.u.vs_user.netmask = vs->granularity_persistence;

	/* SVR specific */
	if (ctl.m_cmd == IP_MASQ_CMD_ADD_DEST
	    || ctl.m_cmd == IP_MASQ_CMD_DEL_DEST) {
		ctl.u.vs_user.weight = rs->weight;
		ctl.u.vs_user.daddr = SVR_IP(rs);
		ctl.u.vs_user.dport = SVR_PORT(rs);
	}

	/* Does the service use inhibit flag ? */
	if (ctl.m_cmd == IP_MASQ_CMD_DEL_DEST && rs->inhibit) {
		ctl.m_cmd = IP_MASQ_CMD_SET_DEST;
		ctl.u.vs_user.weight = 0;
	}
	if (ctl.m_cmd == IP_MASQ_CMD_ADD_DEST && rs->inhibit && rs->alive)
		ctl.m_cmd = IP_MASQ_CMD_SET_DEST;

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd == -1) {
		syslog(LOG_INFO,
		       "IPVS : Can not initialize SOCK_RAW descriptor.");
		return IPVS_ERROR;
	}

	result =
	    setsockopt(sockfd, IPPROTO_IP, IP_FW_MASQ_CTL, (char *) &ctl,
		       sizeof (ctl));

	if (errno == ESRCH) {
		syslog(LOG_INFO, "IPVS : Virtual service [%s:%d] not defined.",
		       inet_ntop2(SVR_IP(vs))
		       , ntohs(SVR_PORT(vs)));
		close(sockfd);
		return IPVS_ERROR;
	} else if (errno == EEXIST) {
		if (rs)
			syslog(LOG_INFO,
			       "IPVS : Destination already exists [%s:%d].",
			       inet_ntop2(SVR_IP(rs))
			       , ntohs(SVR_PORT(rs)));
	} else if (errno == ENOENT) {
		if (rs)
			syslog(LOG_INFO, "IPVS : No such destination [%s:%d].",
			       inet_ntop2(SVR_IP(rs))
			       , ntohs(SVR_PORT(rs)));
	}

	close(sockfd);
	return IPVS_SUCCESS;
}


#else				/* KERNEL 2.4 LVS handling */

static int
ipvs_talk(int cmd, struct ip_vs_rule_user *urule)
{
	int result;

	/* Init IPVS kernel channel */
	if (ipvs_init()) {
		/* try to insmod the ip_vs module if ipvs_init failed */
		if (modprobe_ipvs() || ipvs_init()) {
			syslog(LOG_INFO,
			       "IPVS : Can't initialize ipvs: %s",
		 	       ipvs_strerror(errno));
			return IPVS_ERROR;
		}
	}

	result = ipvs_command(cmd, urule);
	if (result)
		syslog(LOG_INFO, "IPVS : %s", ipvs_strerror(errno));
	ipvs_close();
	return IPVS_SUCCESS;
}

int
ipvs_syncd_cmd(int cmd, char *ifname, int state)
{
#ifdef _HAVE_IPVS_SYNCD_

	struct ip_vs_rule_user urule;

	memset(&urule, 0, sizeof (struct ip_vs_rule_user));

	/* prepare user rule */
	urule.state = state;
	if (ifname != NULL)
		strncpy(urule.mcast_ifn, ifname, IP_VS_IFNAME_MAXLEN);

	/* Talk to the IPVS channel */
	return ipvs_talk(cmd, &urule);

#else
	syslog(LOG_INFO, "IPVS : Sync daemon not supported");
	return IPVS_ERROR;
#endif
}

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

/* IPVS group range rule */
static int
ipvs_group_range_cmd(int cmd, struct ip_vs_rule_user *urule
		     , virtual_server_group_entry *vsg_entry)
{
	uint32_t addr_ip;
	int err = 0;

	/* Parse the whole range */
	for (addr_ip = SVR_IP(vsg_entry);
	     ((addr_ip >> 24) & 0xFF) <= vsg_entry->range;
	     addr_ip += 0x01000000) {
		urule->vaddr = addr_ip;
		urule->vport = SVR_PORT(vsg_entry);

		/* Talk to the IPVS channel */
		err = ipvs_talk(cmd, urule);
	}

	return err;
}

/* set IPVS group rules */
static int
ipvs_group_cmd(int cmd, list vs_group, struct ip_vs_rule_user *urule, char * vsgname)
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
		urule->vaddr = SVR_IP(vsg_entry);
		urule->vport = SVR_PORT(vsg_entry);

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry)) {
			err = ipvs_talk(cmd, urule);
			if (cmd == IP_VS_SO_SET_ADD)
				SET_ALIVE(vsg_entry);
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
		if (IPVS_ALIVE(cmd, vsg_entry)) {
			err = ipvs_talk(cmd, urule);
			if (cmd == IP_VS_SO_SET_ADD)
				SET_ALIVE(vsg_entry);
		}
	}

	/* visit range list */
	l = vsg->range;
	urule->vfwmark = 0;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry)) {
			err = ipvs_group_range_cmd(cmd, urule, vsg_entry);
			if (cmd == IP_VS_SO_SET_ADD)
				SET_ALIVE(vsg_entry);
		}
	}

	return err;
}

/* Fill IPVS rule with root vs infos */
struct ip_vs_rule_user *
ipvs_set_rule(int cmd, virtual_server * vs, real_server * rs)
{
	struct ip_vs_rule_user *urule;

	/* Allocate target rule */
	urule = (struct ip_vs_rule_user *) MALLOC(sizeof (struct ip_vs_rule_user));

	strncpy(urule->sched_name, vs->sched, IP_VS_SCHEDNAME_MAXLEN);
	urule->weight = 1;
	urule->conn_flags = vs->loadbalancing_kind;
	urule->netmask = ((u_int32_t) 0xffffffff);
	urule->protocol = vs->service_type;

	if (!parse_timeout(vs->timeout_persistence, &urule->timeout))
		syslog(LOG_INFO,
		       "IPVS : Virtual service [%s:%d] illegal timeout.",
		       inet_ntop2(SVR_IP(vs)), ntohs(SVR_PORT(vs)));

	if (urule->timeout != 0 || vs->granularity_persistence)
		urule->vs_flags = IP_VS_SVC_F_PERSISTENT;

	if (cmd == IP_VS_SO_SET_ADD || cmd == IP_VS_SO_SET_DEL)
		if (vs->granularity_persistence)
			urule->netmask = vs->granularity_persistence;

	/* SVR specific */
	if (rs) {
		if (cmd == IP_VS_SO_SET_ADDDEST || cmd == IP_VS_SO_SET_DELDEST) {
			urule->weight = rs->weight;
			urule->daddr = SVR_IP(rs);
			urule->dport = SVR_PORT(rs);
		}
	}

	return urule;
}

/* Set/Remove a RS from a VS */
int
ipvs_cmd(int cmd, list vs_group, virtual_server * vs, real_server * rs)
{
	struct ip_vs_rule_user *urule = ipvs_set_rule(cmd, vs, rs);
	int err = 0;

	/* Does the service use inhibit flag ? */
	if (cmd == IP_VS_SO_SET_DELDEST && rs->inhibit) {
		urule->weight = 0;
		cmd = IP_VS_SO_SET_EDITDEST;
	}
	if (cmd == IP_VS_SO_SET_ADDDEST && rs->inhibit && rs->alive)
		cmd = IP_VS_SO_SET_EDITDEST;

	/* Set vs rule and send to kernel */
	if (vs->vsgname) {
		err = ipvs_group_cmd(cmd, vs_group, urule, vs->vsgname);
	} else {
		if (vs->vfwmark) {
			urule->vfwmark = vs->vfwmark;
		} else {
			urule->vaddr = SVR_IP(vs);
			urule->vport = SVR_PORT(vs);
		}

		/* Talk to the IPVS channel */
		err = ipvs_talk(cmd, urule);
	}

	FREE(urule);
	return err;
}

/* Remove a specific vs group entry */
int
ipvs_group_remove_entry(virtual_server *vs, virtual_server_group_entry *vsge)
{
	struct ip_vs_rule_user *urule = NULL;
	real_server *rs;
	int err = 0;
	element e;
	list l = vs->rs;

	/* Process realserver queue */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);

		if (rs->alive) {
			/* Prepare the IPVS rule */
			if (!urule) {
				/* Setting IPVS rule with vs root rs */
				urule = ipvs_set_rule(IP_VS_SO_SET_DELDEST, vs, rs);
			} else {
				urule->weight = rs->weight;
				urule->daddr = SVR_IP(rs);
				urule->dport = SVR_PORT(rs);
			}

			/* Set vs rule */
			if (vsge->range) {
				ipvs_group_range_cmd(IP_VS_SO_SET_DELDEST, urule, vsge);
			} else {
				urule->vfwmark = vsge->vfwmark;
				urule->vaddr = SVR_IP(vsge);
				urule->vport = SVR_PORT(vsge);

				/* Talk to the IPVS channel */
				err = ipvs_talk(IP_VS_SO_SET_DELDEST, urule);
			}
		}
	}

	/* Remove VS entry */
	if (vsge->range)
		err = ipvs_group_range_cmd(IP_VS_SO_SET_DEL, urule, vsge);
	else
		err = ipvs_talk(IP_VS_SO_SET_DEL, urule);

	FREE(urule);
	return err;
}

#endif

/*
 * Common IPVS functions
 */
void
ipvs_syncd_master(char *ifname)
{
	ipvs_syncd_cmd(IPVS_STOPDAEMON, ifname, IPVS_BACKUP);
	ipvs_syncd_cmd(IPVS_STARTDAEMON, ifname, IPVS_MASTER);
}

void
ipvs_syncd_backup(char *ifname)
{
	ipvs_syncd_cmd(IPVS_STOPDAEMON, ifname, IPVS_MASTER);
	ipvs_syncd_cmd(IPVS_STARTDAEMON, ifname, IPVS_BACKUP);
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
	char *argv[] = { "/sbin/modprobe", "-s", "-k", "--", "ip_vs", NULL };
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
