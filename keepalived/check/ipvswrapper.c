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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* to make O_CLOEXEC available */
#endif

#include <fcntl.h>

#ifndef O_CLOEXEC	/* Since Linux 2.6.23 and glibc 2.7 */
#define O_CLOEXEC 0	/* It doesn't really matter if O_CLOEXEC isn't set here */
#endif

#include "ipvswrapper.h"
#include "check_data.h"
#include "list.h"
#include "utils.h"
#include "memory.h"
#include "logger.h"

/*
 * Utility functions coming from Wensong code
 */

static char*
get_modprobe(void)
{
	int procfile;
	char *ret;
	ssize_t count;

	ret = MALLOC(PATH_MAX);
	if (!ret)
		return NULL;

	procfile = open("/proc/sys/kernel/modprobe", O_RDONLY | O_CLOEXEC);
	if (procfile < 0) {
		FREE(ret);
		return NULL;
	}

	count = read(procfile, ret, PATH_MAX);
	close(procfile);

	if (count > 0 && count < PATH_MAX)
	{
		if (ret[count - 1] == '\n')
			ret[count - 1] = '\0';
		else
			ret[count] = '\0';
		return ret;
	}

	FREE(ret);

	return NULL;
}

static int
modprobe_ipvs(void)
{
	char *argv[] = { "/sbin/modprobe", "-s", "--", "ip_vs", NULL };
	int child;
	int status;
	int rc;
	char *modprobe = get_modprobe();
	struct sigaction act, old_act;

	if (modprobe)
		argv[0] = modprobe;

	act.sa_handler = SIG_DFL;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	sigaction ( SIGCHLD, &act, &old_act);

	if (!(child = fork())) {
		execv(argv[0], argv);
		exit(1);
	}

	rc = waitpid(child, &status, 0);

	sigaction ( SIGCHLD, &old_act, NULL);

	if (rc < 0) {
		log_message(LOG_INFO, "IPVS: waitpid error (%s)"
				    , strerror(errno));
	}

	if (modprobe)
		FREE(modprobe);

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		return 1;
	}

	return 0;
}
/* fetch virtual server group from group name */
virtual_server_group_t *
ipvs_get_group_by_name(char *gname, list l)
{
	element e;
	virtual_server_group_t *vsg;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg = ELEMENT_DATA(e);
		if (!strcmp(vsg->gname, gname))
			return vsg;
	}
	return NULL;
}

/* Global module def IPVS rules */
static ipvs_service_t *srule;
static ipvs_dest_t *drule;
static ipvs_daemon_t *daemonrule;

/* Initialization helpers */
int
ipvs_start(void)
{
	log_message(LOG_DEBUG, "Initializing ipvs");
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

void
ipvs_set_timeouts(int tcp_timeout, int tcpfin_timeout, int udp_timeout)
{
	ipvs_timeout_t to;

	if (!tcp_timeout && !tcpfin_timeout && !udp_timeout)
		return;

	to.tcp_timeout = tcp_timeout;
	to.tcp_fin_timeout = tcpfin_timeout;
	to.udp_timeout = udp_timeout;

	ipvs_set_timeout(&to);
}

/* Send user rules to IPVS module */
static int
ipvs_talk(int cmd, bool ignore_error)
{
	int result = -1;

	switch (cmd) {
		case IP_VS_SO_SET_STARTDAEMON:
			result = ipvs_start_daemon(daemonrule);
			break;
		case IP_VS_SO_SET_STOPDAEMON:
			result = ipvs_stop_daemon(daemonrule);
			break;
		case IP_VS_SO_SET_FLUSH:
			result = ipvs_flush();
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
			    (errno == ENOENT)) {
				cmd = IP_VS_SO_SET_ADDDEST;
				result = ipvs_add_dest(srule, drule);
			}
			break;
	}

	if (ignore_error)
		result = 0;
	else if (result) {
		if (errno == EEXIST &&
			(cmd == IP_VS_SO_SET_ADD || cmd == IP_VS_SO_SET_ADDDEST))
			result = 0;
		else if (errno == ENOENT &&
			(cmd == IP_VS_SO_SET_DEL || cmd == IP_VS_SO_SET_DELDEST))
			result = 0;
		log_message(LOG_INFO, "IPVS: %s", ipvs_strerror(errno));
	}
	return result;
}

#ifdef _WITH_LVS_
/* Note: This function is called in the context of the vrrp child process, not the checker process */
void
ipvs_syncd_cmd(int cmd, const struct lvs_syncd_config *config, int state, bool ignore_interface, bool ignore_error)
{
	memset(daemonrule, 0, sizeof(ipvs_daemon_t));

	/* prepare user rule */
	daemonrule->state = state;
	if (config) {
		daemonrule->syncid = (int)config->syncid;
		if (!ignore_interface)
			strncpy(daemonrule->mcast_ifn, config->ifname, IP_VS_IFNAME_MAXLEN);
#ifdef _HAVE_IPVS_SYNCD_ATTRIBUTES_
		if (cmd == IPVS_STARTDAEMON) {
			if (config->sync_maxlen)
				daemonrule->sync_maxlen = config->sync_maxlen;
			if (config->mcast_port)
				daemonrule->mcast_port = config->mcast_port;
			if (config->mcast_ttl)
				daemonrule->mcast_ttl = config->mcast_ttl;
			if (config->mcast_group.ss_family == AF_INET) {
				daemonrule->mcast_af = AF_INET;
				daemonrule->mcast_group.ip = ((struct sockaddr_in *)&config->mcast_group)->sin_addr.s_addr;
			}
			else if (config->mcast_group.ss_family == AF_INET6) {
				daemonrule->mcast_af = AF_INET6;
				memcpy(&daemonrule->mcast_group.in6, &((struct sockaddr_in6 *)&config->mcast_group)->sin6_addr, sizeof(daemonrule->mcast_group.in6));
			}
		}
#endif
	}

	/* Talk to the IPVS channel */
	ipvs_talk(cmd, ignore_error);
}

void
ipvs_flush_cmd(void)
{
	ipvs_talk(IP_VS_SO_SET_FLUSH, false);
}
#endif

/* IPVS group range rule */
static int
ipvs_group_range_cmd(int cmd, virtual_server_group_entry_t *vsg_entry)
{
	uint32_t addr_start;
	uint32_t num_addr, i;
	uint32_t addr_incr;

	if (vsg_entry->addr.ss_family == AF_INET6) {
		inet_sockaddrip6(&vsg_entry->addr, &srule->nf_addr.in6);
		addr_start = ntohs(srule->nf_addr.in6.s6_addr16[7]);
	} else {
		srule->nf_addr.ip = inet_sockaddrip4(&vsg_entry->addr);
		addr_start = htonl(srule->nf_addr.ip) & 0xFF;
		addr_incr = ntohl(1);
	}

	/* Set Address Family and port */
	srule->af = vsg_entry->addr.ss_family;
	srule->user.port = inet_sockaddrport(&vsg_entry->addr);

	/* Parse the whole range */
	num_addr = vsg_entry->range - addr_start + 1;
	for (i = 0; i < num_addr; i++) {
		if (srule->af == AF_INET6) {
			srule->nf_addr.in6.s6_addr16[7] = (htons(addr_start));
			addr_start++;
		}

		/* Talk to the IPVS channel */
		if (ipvs_talk(cmd, false))
			return -1;

		if (srule->af == AF_INET)
			srule->nf_addr.ip += addr_incr;
	}

	return 0;
}

/* set IPVS group rules */
static int
ipvs_group_cmd(int cmd, virtual_server_t * vs, real_server_t * rs)
{
	virtual_server_group_t *vsg = vs->vsg;
	virtual_server_group_entry_t *vsg_entry;
	list l;
	element e;

	/* return if jointure fails */
	if (!vsg) return 0;

	/* visit addr_ip list */
	l = vsg->addr_ip;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);
		srule->af = vsg_entry->addr.ss_family;
		if (vsg_entry->addr.ss_family == AF_INET6) {
			if (srule->user.netmask == 0xffffffff)
				srule->user.netmask = 128;
			inet_sockaddrip6(&vsg_entry->addr, &srule->nf_addr.in6);
		} else
			srule->nf_addr.ip = inet_sockaddrip4(&vsg_entry->addr);
		srule->user.port = inet_sockaddrport(&vsg_entry->addr);

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry, rs)) {
			if (ipvs_talk(cmd, false))
				return -1;
			IPVS_SET_ALIVE(cmd, vsg_entry);
		}
	}

	/* visit vfwmark list */
	l = vsg->vfwmark;
	srule->nf_addr.ip = 0;
	srule->af = 0;
	srule->user.port = 0;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);
		srule->af = vs->af;
		if (vs->af == AF_INET6)
			srule->user.netmask = 128;
		srule->user.fwmark = vsg_entry->vfwmark;

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry, rs)) {
			if (ipvs_talk(cmd, false))
				return -1;
			IPVS_SET_ALIVE(cmd, vsg_entry);
		}
	}

	/* visit range list */
	l = vsg->range;
	srule->user.fwmark = 0;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);

		/* Talk to the IPVS channel */
		if (IPVS_ALIVE(cmd, vsg_entry, rs)) {
			if (ipvs_group_range_cmd(cmd, vsg_entry))
				return -1;
			IPVS_SET_ALIVE(cmd, vsg_entry);
		}
	}
	return 0;
}

/* Fill IPVS rule with root vs infos */
static void
ipvs_set_rule(int cmd, virtual_server_t * vs, real_server_t * rs)
{
	/* Clean target rule */
	memset(drule, 0, sizeof(ipvs_dest_t));

	drule->user.weight = 1;
	drule->user.u_threshold = 0;
	drule->user.l_threshold = 0;
	drule->user.conn_flags = vs->loadbalancing_kind;
	strncpy(srule->user.sched_name, vs->sched, IP_VS_SCHEDNAME_MAXLEN);
	srule->user.flags = vs->flags;
	srule->user.netmask = (vs->addr.ss_family == AF_INET6) ? 128 : ((u_int32_t) 0xffffffff);
	srule->user.protocol = vs->service_type;

	srule->user.timeout = vs->persistence_timeout;
	if (cmd == IP_VS_SO_SET_ADD || cmd == IP_VS_SO_SET_DEL)
		if (vs->persistence_granularity)
			srule->user.netmask = vs->persistence_granularity;

	if (vs->persistence_timeout || vs->persistence_granularity)
		srule->user.flags |= IP_VS_SVC_F_PERSISTENT;

#ifdef IP_VS_SVC_F_ONEPACKET
	/* Disable ops flag if service is not UDP */
	if (vs->flags & IP_VS_SVC_F_ONEPACKET && srule->user.protocol != IPPROTO_UDP)
		srule->user.flags &= (unsigned)~IP_VS_SVC_F_ONEPACKET;
#endif

#ifdef _HAVE_PE_NAME_
	strcpy(srule->pe_name, vs->pe_name);
#endif

	/* SVR specific */
	if (rs) {
		if (cmd == IP_VS_SO_SET_ADDDEST || cmd == IP_VS_SO_SET_DELDEST ||
		    cmd == IP_VS_SO_SET_EDITDEST) {
			drule->af = rs->addr.ss_family;
			if (rs->addr.ss_family == AF_INET6)
				inet_sockaddrip6(&rs->addr, &drule->nf_addr.in6);
			else
				drule->nf_addr.ip = inet_sockaddrip4(&rs->addr);
			drule->user.port = inet_sockaddrport(&rs->addr);
			drule->user.weight = rs->weight;
			drule->user.u_threshold = rs->u_threshold;
			drule->user.l_threshold = rs->l_threshold;
		}
	}
}

/* Set/Remove a RS from a VS */
int
ipvs_cmd(int cmd, virtual_server_t * vs, real_server_t * rs)
{
	int err = 0;

	/* Allocate the room */
	memset(srule, 0, sizeof(ipvs_service_t));
	ipvs_set_rule(cmd, vs, rs);

	/* Does the service use inhibit flag ? */
	if (cmd == IP_VS_SO_SET_DELDEST && rs->inhibit) {
		drule->user.weight = 0;
		cmd = IP_VS_SO_SET_EDITDEST;
	}
	if (cmd == IP_VS_SO_SET_ADDDEST && rs->inhibit && rs->set)
		cmd = IP_VS_SO_SET_EDITDEST;

	/* Set flag */
	if (cmd == IP_VS_SO_SET_ADDDEST && !rs->set)
		rs->set = true;
	if (cmd == IP_VS_SO_SET_DELDEST && rs->set)
		rs->set = false;

	/* Set vs rule and send to kernel */
	if (vs->vsgname) {
		err = ipvs_group_cmd(cmd, vs, rs);
	} else {
		srule->af = vs->af;
		if (vs->vfwmark) {
			if (vs->af == AF_INET6)
				srule->user.netmask = 128;
			srule->user.fwmark = vs->vfwmark;
		} else {
			if (vs->af == AF_INET6)
				inet_sockaddrip6(&vs->addr, &srule->nf_addr.in6);
			else
				srule->nf_addr.ip = inet_sockaddrip4(&vs->addr);
			srule->user.port = inet_sockaddrport(&vs->addr);
		}

		/* Talk to the IPVS channel */
		err = ipvs_talk(cmd, false);
	}

	return err;
}

/* add alive destinations to the newly created vsge */
void
ipvs_group_sync_entry(virtual_server_t *vs, virtual_server_group_entry_t *vsge)
{
	real_server_t *rs;
	element e;
	list l = vs->rs;

	/* Clean target rules */
	memset(srule, 0, sizeof(ipvs_service_t));
	memset(drule, 0, sizeof(ipvs_dest_t));

	/* Process realserver queue */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);

		if (rs->reloaded && (rs->alive || (rs->inhibit && rs->set))) {
			/* Prepare the IPVS rule */
			if (!drule->nf_addr.ip) {
				/* Setting IPVS rule with vs root rs */
				ipvs_set_rule(IP_VS_SO_SET_ADDDEST, vs, rs);
			} else {
				drule->af = rs->addr.ss_family;
				if (rs->addr.ss_family == AF_INET6)
					inet_sockaddrip6(&rs->addr, &drule->nf_addr.in6);
				else
					drule->nf_addr.ip = inet_sockaddrip4(&rs->addr);
				drule->user.port = inet_sockaddrport(&rs->addr);
			}
			drule->user.weight = rs->inhibit && ! rs->alive ? 0: rs->weight;

			/* Set vs rule */
			if (vsge->range) {
				ipvs_group_range_cmd(IP_VS_SO_SET_ADDDEST, vsge);
			} else {
				srule->af = vsge->addr.ss_family;
				if (vsge->addr.ss_family == AF_INET6)
					inet_sockaddrip6(&vsge->addr, &srule->nf_addr.in6);
				else
					srule->nf_addr.ip = inet_sockaddrip4(&vsge->addr);
				srule->user.port = inet_sockaddrport(&vsge->addr);
				srule->user.fwmark = vsge->vfwmark;
				drule->user.u_threshold = rs->u_threshold;
				drule->user.l_threshold = rs->l_threshold;

				/* Talk to the IPVS channel */
				ipvs_talk(IP_VS_SO_SET_ADDDEST, false);
			}
		}
	}
}

/* Remove a specific vs group entry */
void
ipvs_group_remove_entry(virtual_server_t *vs, virtual_server_group_entry_t *vsge)
{
	real_server_t *rs;
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
			if (!drule->nf_addr.ip) {
				/* Setting IPVS rule with vs root rs */
				ipvs_set_rule(IP_VS_SO_SET_DELDEST, vs, rs);
			} else {
				drule->af = rs->addr.ss_family;
				if (rs->addr.ss_family == AF_INET6)
					inet_sockaddrip6(&rs->addr, &drule->nf_addr.in6);
				else
					drule->nf_addr.ip = inet_sockaddrip4(&rs->addr);
				drule->user.port = inet_sockaddrport(&rs->addr);
				drule->user.weight = rs->weight;
			}

			/* Set vs rule */
			if (vsge->range) {
				ipvs_group_range_cmd(IP_VS_SO_SET_DELDEST, vsge);
			} else {
				srule->af = vsge->addr.ss_family;
				if (vsge->addr.ss_family == AF_INET6)
					inet_sockaddrip6(&vsge->addr, &srule->nf_addr.in6);
				else
					srule->nf_addr.ip = inet_sockaddrip4(&vsge->addr);
				srule->user.port = inet_sockaddrport(&vsge->addr);
				srule->user.fwmark = vsge->vfwmark;
				drule->user.u_threshold = rs->u_threshold;
				drule->user.l_threshold = rs->l_threshold;

				/* Talk to the IPVS channel */
				ipvs_talk(IP_VS_SO_SET_DELDEST, false);
			}
		}
	}

	/* Remove VS entry */
	if (vsge->range)
		ipvs_group_range_cmd(IP_VS_SO_SET_DEL, vsge);
	else
		ipvs_talk(IP_VS_SO_SET_DEL, false);
	UNSET_ALIVE(vsge);
}

#ifdef _WITH_SNMP_CHECKER_
/* Update statistics for a given virtual server. This includes
   statistics of real servers. The update is only done if we need
   refreshing. */
void
ipvs_update_stats(virtual_server_t *vs)
{
	element e, ge = NULL;
	real_server_t *rs;
	virtual_server_group_t *vsg = NULL;
	virtual_server_group_entry_t *vsg_entry = NULL;
	uint32_t addr_ip = 0;
	union nf_inet_addr nfaddr;
	ipvs_service_entry_t *serv = NULL;
	struct ip_vs_get_dests_app *dests = NULL;
	unsigned i;
#define UPDATE_STATS_INIT 1
#define UPDATE_STATS_VSG_IP 2
#define UPDATE_STATS_VSG_FWMARK 4
#define UPDATE_STATS_VSG_RANGE 6
#define UPDATE_STATS_VSG_RANGE_IP 7
#define UPDATE_STATS_END 99
	int state = UPDATE_STATS_INIT;

	if (time(NULL) - vs->lastupdated < STATS_REFRESH)
		return;
	vs->lastupdated = time(NULL);
	/* Reset stats */
	memset(&vs->stats, 0, sizeof(vs->stats));
	if (vs->s_svr) {
		memset(&vs->s_svr->stats, 0, sizeof(vs->s_svr->stats));
		vs->s_svr->activeconns =
			vs->s_svr->inactconns = vs->s_svr->persistconns = 0;
	}
	if (!LIST_ISEMPTY(vs->rs)) {
		for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
			rs = ELEMENT_DATA(e);
			memset(&rs->stats, 0, sizeof(rs->stats));
			rs->activeconns = rs->inactconns = rs->persistconns = 0;
		}
	}
	/* FSM: at each transition, we process "serv" if it is not NULL */
	while (state != UPDATE_STATS_END) {
		serv = NULL;
		switch (state) {
		case UPDATE_STATS_INIT:
			/* We need to know the next state to reach */
			if (vs->vsgname) {
				if (!LIST_ISEMPTY(check_data->vs_group))
					vsg = ipvs_get_group_by_name(vs->vsgname,
								     check_data->vs_group);
				else
					vsg = NULL;
				if (!vsg)
					state = UPDATE_STATS_END;
				else {
					state = UPDATE_STATS_VSG_IP;
					ge = NULL;
				}
				continue;
			}
			state = UPDATE_STATS_END;
			if (vs->vfwmark) {
				memset(&nfaddr, 0, sizeof(nfaddr));
				serv = ipvs_get_service(vs->vfwmark,
							AF_INET,
							vs->service_type,
							nfaddr, 0);
				break;
			}
			memcpy(&nfaddr, (vs->addr.ss_family == AF_INET6)?
			       (void*)(&((struct sockaddr_in6 *)&vs->addr)->sin6_addr):
			       (void*)(&((struct sockaddr_in *)&vs->addr)->sin_addr),
			       sizeof(nfaddr));
			serv = ipvs_get_service(0,
						vs->addr.ss_family,
						vs->service_type,
						nfaddr,
						inet_sockaddrport(&vs->addr));
			break;
		case UPDATE_STATS_VSG_IP:
			if (!ge)
				ge = LIST_HEAD(vsg->addr_ip);
			else
				ELEMENT_NEXT(ge);
			if (!ge) {
				state = UPDATE_STATS_VSG_FWMARK;
				continue;
			}
			vsg_entry = ELEMENT_DATA(ge);
			memcpy(&nfaddr, (vsg_entry->addr.ss_family == AF_INET6)?
			       (void*)(&((struct sockaddr_in6 *)&vsg_entry->addr)->sin6_addr):
			       (void*)(&((struct sockaddr_in *)&vsg_entry->addr)->sin_addr),
			       sizeof(nfaddr));
			serv = ipvs_get_service(0,
						vsg_entry->addr.ss_family,
						vs->service_type,
						nfaddr,
						inet_sockaddrport(&vsg_entry->addr));
			break;
		case UPDATE_STATS_VSG_FWMARK:
			if (!ge)
				ge = LIST_HEAD(vsg->vfwmark);
			else
				ELEMENT_NEXT(ge);
			if (!ge) {
				state = UPDATE_STATS_VSG_RANGE;
				continue;
			}
			vsg_entry = ELEMENT_DATA(ge);
			memset(&nfaddr, 0, sizeof(nfaddr));
			serv = ipvs_get_service(vsg_entry->vfwmark,
						AF_INET,
						vs->service_type,
						nfaddr, 0);
			break;
		case UPDATE_STATS_VSG_RANGE:
			if (!ge)
				ge = LIST_HEAD(vsg->range);
			else
				ELEMENT_NEXT(ge);
			if (!ge) {
				state = UPDATE_STATS_END;
				continue;
			}
			vsg_entry = ELEMENT_DATA(ge);
			addr_ip = (vsg_entry->addr.ss_family == AF_INET6) ?
				  ((struct sockaddr_in6 *)&vsg_entry->addr)->sin6_addr.s6_addr32[3]:
				  ((struct sockaddr_in *)&vsg_entry->addr)->sin_addr.s_addr;
			state = UPDATE_STATS_VSG_RANGE_IP;
			continue;
		case UPDATE_STATS_VSG_RANGE_IP:
			if (((addr_ip >> 24) & 0xFF) > vsg_entry->range) {
				state = UPDATE_STATS_VSG_RANGE;
				continue;
			}
			if (vsg_entry->addr.ss_family == AF_INET6) {
				inet_sockaddrip6(&vsg_entry->addr, &nfaddr.in6);
				nfaddr.in6.s6_addr32[3] = addr_ip;
			} else {
				nfaddr.ip = addr_ip;
			}
			serv = ipvs_get_service(0,
						vsg_entry->addr.ss_family,
						vs->service_type,
						nfaddr,
						inet_sockaddrport(&vsg_entry->addr));
			addr_ip += 0x01000000;
			break;
		}
		if (!serv)
			continue;

		/* Update virtual server stats */
#define ADD_TO_VSSTATS(X) vs->stats.X += serv->stats.X;
		ADD_TO_VSSTATS(conns);
		ADD_TO_VSSTATS(inpkts);
		ADD_TO_VSSTATS(outpkts);
		ADD_TO_VSSTATS(inbytes);
		ADD_TO_VSSTATS(outbytes);
		ADD_TO_VSSTATS(cps);
		ADD_TO_VSSTATS(inpps);
		ADD_TO_VSSTATS(outpps);
		ADD_TO_VSSTATS(inbps);
		ADD_TO_VSSTATS(outbps);

		/* Get real servers */
		dests = ipvs_get_dests(serv);
		if (!dests) {
			FREE(serv);
			return;
		}
		for (i = 0; i < dests->user.num_dests; i++) {
			rs = NULL;

#define VSD_EQUAL(entity) (((entity)->addr.ss_family == AF_INET &&	\
			    dests->user.entrytable[i].af == AF_INET &&	\
			    inaddr_equal(AF_INET,			\
					 &dests->user.entrytable[i].nf_addr,    \
					 &((struct sockaddr_in *)&(entity)->addr)->sin_addr) &&	\
			    dests->user.entrytable[i].user.port == ((struct sockaddr_in *)&(entity)->addr)->sin_port) || \
			    ((entity)->addr.ss_family == AF_INET6 &&	\
			    dests->user.entrytable[i].af == AF_INET6 &&	\
			    inaddr_equal(AF_INET6,			\
					 &dests->user.entrytable[i].nf_addr,	\
					 &((struct sockaddr_in6 *)&(entity)->addr)->sin6_addr) &&	\
			    dests->user.entrytable[i].user.port == ((struct sockaddr_in6 *)&(entity)->addr)->sin6_port))
			/* Is it the sorry server? */
			if (vs->s_svr && VSD_EQUAL(vs->s_svr))
				rs = vs->s_svr;
			else if (!LIST_ISEMPTY(vs->rs))
				/* Search for a match in the list of real servers */
				for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
					rs = ELEMENT_DATA(e);
					if (VSD_EQUAL(rs))
						break;
				}
			if (rs) {
#define ADD_TO_RSSTATS(X) rs->X += dests->user.entrytable[i].X
#define ADD_TO_RSSTATS_USER(X) rs->X += dests->user.entrytable[i].user.X
				ADD_TO_RSSTATS_USER(activeconns);
				ADD_TO_RSSTATS_USER(inactconns);
				ADD_TO_RSSTATS_USER(persistconns);
//				rs->activeconns = dests->user.entrytable[i].user.activeconns;
//				rs->inactconns = dests->user.entrytable[i].user.inactconns;
//				rs->persistconns = dests->user.entrytable[i].user.persistconns;
				ADD_TO_RSSTATS(stats.conns);
				ADD_TO_RSSTATS(stats.inpkts);
				ADD_TO_RSSTATS(stats.outpkts);
				ADD_TO_RSSTATS(stats.inbytes);
				ADD_TO_RSSTATS(stats.outbytes);
				ADD_TO_RSSTATS(stats.cps);
				ADD_TO_RSSTATS(stats.inpps);
				ADD_TO_RSSTATS(stats.outpps);
				ADD_TO_RSSTATS(stats.inbps);
				ADD_TO_RSSTATS(stats.outbps);
			}
		}
		FREE(dests);
		FREE(serv);
	}
}
#endif /* _WITH_SNMP_CHECKER_ */

/*
 * Common IPVS functions
 */
#ifdef _WITH_LVS_
/* Note: This function is called in the context of the vrrp child process, not the checker process */
void
ipvs_syncd_master(const struct lvs_syncd_config *config)
{
	ipvs_syncd_cmd(IPVS_STOPDAEMON, config, IPVS_BACKUP, false, false);
	ipvs_syncd_cmd(IPVS_STARTDAEMON, config, IPVS_MASTER, false, false);
}

/* Note: This function is called in the context of the vrrp child process, not the checker process */
void
ipvs_syncd_backup(const struct lvs_syncd_config *config)
{
	ipvs_syncd_cmd(IPVS_STOPDAEMON, config, IPVS_MASTER, false, false);
	ipvs_syncd_cmd(IPVS_STARTDAEMON, config, IPVS_BACKUP, false, false);
}
#endif
