/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        IPVS Kernel wrapper. Use setsockopt call to add/remove
 *              server to/from the loadbalanced server pool.
 *  
 * Version:     $Id: ipvswrapper.c,v 0.6.10 2002/08/06 02:18:05 acassen Exp $
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

#include "ipvswrapper.h"
#include "utils.h"
#include "memory.h"

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
ipvs_cmd(int cmd, virtual_server * vs, real_server * rs)
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

int
ipvs_cmd(int cmd, virtual_server * vs, real_server * rs)
{
	struct ip_vs_rule_user *urule;
	int err = 0;

	urule = (struct ip_vs_rule_user *) MALLOC(sizeof (struct ip_vs_rule_user));
	memset(urule, 0, sizeof (struct ip_vs_rule_user));

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

	/* VS specific */
	if (vs->vfwmark) {
		urule->vfwmark = vs->vfwmark;
	} else {
		urule->vaddr = SVR_IP(vs);
		urule->vport = SVR_PORT(vs);
	}

	if (cmd == IP_VS_SO_SET_ADD || cmd == IP_VS_SO_SET_DEL)
		if (vs->granularity_persistence)
			urule->netmask = vs->granularity_persistence;

	/* SVR specific */
	if (cmd == IP_VS_SO_SET_ADDDEST || cmd == IP_VS_SO_SET_DELDEST) {
		urule->weight = rs->weight;
		urule->daddr = SVR_IP(rs);
		urule->dport = SVR_PORT(rs);
	}

	/* Does the service use inhibit flag ? */
	if (cmd == IP_VS_SO_SET_DELDEST && rs->inhibit) {
		urule->weight = 0;
		cmd = IP_VS_SO_SET_EDITDEST;
	}
	if (cmd == IP_VS_SO_SET_ADDDEST && rs->inhibit && rs->alive)
		cmd = IP_VS_SO_SET_EDITDEST;

	/* Talk to the IPVS channel */
	err = ipvs_talk(cmd, urule);

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
