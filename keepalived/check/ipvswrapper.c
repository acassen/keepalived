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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef O_CLOEXEC	/* Since Linux 2.6.23 and glibc 2.7 */
#define O_CLOEXEC 0	/* It doesn't really matter if O_CLOEXEC isn't set here */
#endif

#include "ipvswrapper.h"
#include "list.h"
#include "utils.h"
#include "memory.h"
#include "logger.h"

static bool no_ipvs = false;

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

static bool
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

	if (log_file_name)
		flush_log_file();

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
		return true;
	}

	return false;
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
			no_ipvs = true;
			return IPVS_ERROR;
		}
	}

	return IPVS_SUCCESS;
}

void
ipvs_stop(void)
{
	if (no_ipvs)
		return;

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
ipvs_talk(int cmd, ipvs_service_t *srule, ipvs_dest_t *drule, ipvs_daemon_t *daemonrule, bool ignore_error)
{
	int result = -1;

	if (no_ipvs)
		return result;

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
		log_message(LOG_INFO, "IPVS (cmd %d, errno %d): %s", cmd, errno, ipvs_strerror(errno));
	}
	return result;
}

#ifdef _WITH_VRRP_
/* Note: This function is called in the context of the vrrp child process, not the checker process */
void
ipvs_syncd_cmd(int cmd, const struct lvs_syncd_config *config, int state, bool ignore_interface, bool ignore_error)
{
	ipvs_daemon_t daemonrule;

	memset(&daemonrule, 0, sizeof(ipvs_daemon_t));

	/* prepare user rule */
	daemonrule.state = state;
	if (config) {
		daemonrule.syncid = (int)config->syncid;
		if (!ignore_interface)
			strcpy(daemonrule.mcast_ifn, config->ifname);
#ifdef _HAVE_IPVS_SYNCD_ATTRIBUTES_
		if (cmd == IPVS_STARTDAEMON) {
			if (config->sync_maxlen)
				daemonrule.sync_maxlen = config->sync_maxlen;
			if (config->mcast_port)
				daemonrule.mcast_port = config->mcast_port;
			if (config->mcast_ttl)
				daemonrule.mcast_ttl = config->mcast_ttl;
			if (config->mcast_group.ss_family == AF_INET) {
				daemonrule.mcast_af = AF_INET;
				daemonrule.mcast_group.ip = ((struct sockaddr_in *)&config->mcast_group)->sin_addr.s_addr;
			}
			else if (config->mcast_group.ss_family == AF_INET6) {
				daemonrule.mcast_af = AF_INET6;
				memcpy(&daemonrule.mcast_group.in6, &((struct sockaddr_in6 *)&config->mcast_group)->sin6_addr, sizeof(daemonrule.mcast_group.in6));
			}
		}
#endif
	}

	/* Talk to the IPVS channel */
	ipvs_talk(cmd, NULL, NULL, &daemonrule, ignore_error);
}
#endif

void
ipvs_flush_cmd(void)
{
	ipvs_talk(IP_VS_SO_SET_FLUSH, NULL, NULL, NULL, false);
}

/* IPVS group range rule */
static int
ipvs_group_range_cmd(int cmd, ipvs_service_t *srule, ipvs_dest_t *drule, virtual_server_group_entry_t *vsg_entry)
{
	uint32_t i;

	/* Set address and port */
	if (vsg_entry->addr.ss_family == AF_INET6)
		inet_sockaddrip6(&vsg_entry->addr, &srule->nf_addr.in6);
	else
		srule->nf_addr.ip = inet_sockaddrip4(&vsg_entry->addr);

	/* Process the whole range */
	for (i = 0; i <= vsg_entry->range; i++) {
		/* Talk to the IPVS channel */
		if (ipvs_talk(cmd, srule, drule, NULL, false))
			return -1;

		if (srule->af == AF_INET)
			srule->nf_addr.ip += htonl(1);
		else
			srule->nf_addr.in6.s6_addr16[7] = htons(ntohs(srule->nf_addr.in6.s6_addr16[7]) + 1);
	}

	return 0;
}

/* set IPVS group rules */
static bool
is_vsge_alive(virtual_server_group_entry_t *vsge, virtual_server_t *vs)
{
	if (vsge->vfwmark) {
		if (vs->af == AF_INET)
			return !!vsge->fwm4_alive;
		else
			return !!vsge->fwm6_alive;
	}
	else if (vs->service_type == IPPROTO_TCP)
		return !!vsge->tcp_alive;
	else if (vs->service_type == IPPROTO_UDP)
		return !!vsge->udp_alive;
	else
		return !!vsge->sctp_alive;
}

static void
update_vsge_alive_count(virtual_server_group_entry_t *vsge, virtual_server_t *vs, bool up)
{
	unsigned *alive_p;

	if (vsge->vfwmark) {
		if (vs->af == AF_INET)
			alive_p = &vsge->fwm4_alive;
		else
			alive_p = &vsge->fwm6_alive;
	}
	else if (vs->service_type == IPPROTO_TCP)
		alive_p = &vsge->tcp_alive;
	else if (vs->service_type == IPPROTO_UDP)
		alive_p = &vsge->udp_alive;
	else
		alive_p = &vsge->sctp_alive;

	if (up)
		(*alive_p)++;
	else
		(*alive_p)--;
}

static void
set_vsge_alive(virtual_server_group_entry_t *vsge, virtual_server_t *vs)
{
	update_vsge_alive_count(vsge, vs, true);
}

static void
unset_vsge_alive(virtual_server_group_entry_t *vsge, virtual_server_t *vs)
{
	update_vsge_alive_count(vsge, vs, false);
}

static bool
ipvs_change_needed(int cmd, virtual_server_group_entry_t *vsge, virtual_server_t *vs, real_server_t *rs)
{
	unsigned count;

	if (cmd == IP_VS_SO_SET_ADD)
		return !is_vsge_alive(vsge, vs);
	else if (cmd == IP_VS_SO_SET_DEL) {
		count = vsge->vfwmark ? (vs->af == AF_INET ? vsge->fwm4_alive : vsge->fwm6_alive) :
			vs->service_type == IPPROTO_TCP ? vsge->tcp_alive :
			vs->service_type == IPPROTO_UDP ? vsge->udp_alive : vsge->sctp_alive;

		return (count == 1);
	}
	else if (cmd == IP_VS_SO_SET_ADDDEST)
		return !rs->alive;
	else if (cmd == IP_VS_SO_SET_DELDEST)
		return rs->alive;
	else /* cmd == IP_VS_SO_SET_EDITDEST */
		return true;
}

static void
ipvs_set_vsge_alive_state(int cmd, virtual_server_group_entry_t *vsge, virtual_server_t *vs)
{
	if (cmd == IP_VS_SO_SET_ADD)
		set_vsge_alive(vsge, vs);
	else if (cmd == IP_VS_SO_SET_DEL)
		unset_vsge_alive(vsge, vs);
}

static int
ipvs_group_cmd(int cmd, ipvs_service_t *srule, ipvs_dest_t *drule, virtual_server_t *vs, real_server_t *rs)
{
	virtual_server_group_t *vsg = vs->vsg;
	virtual_server_group_entry_t *vsg_entry;
	element e;

	/* return if jointure fails */
	if (!vsg)
		return 0;

	/* visit addr_ip list */
	for (e = LIST_HEAD(vsg->addr_range); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);

		if (ipvs_change_needed(cmd, vsg_entry, vs, rs)) {
			srule->user.port = inet_sockaddrport(&vsg_entry->addr);

			if (vsg_entry->range) {
				if (ipvs_group_range_cmd(cmd, srule, drule, vsg_entry))
					return -1;
			} else {
				if (vsg_entry->addr.ss_family == AF_INET6)
					inet_sockaddrip6(&vsg_entry->addr, &srule->nf_addr.in6);
				else
					srule->nf_addr.ip = inet_sockaddrip4(&vsg_entry->addr);

				/* Talk to the IPVS channel */
				if (ipvs_talk(cmd, srule, drule, NULL, false))
					return -1;
			}
			ipvs_set_vsge_alive_state(cmd, vsg_entry, vs);
		}
	}

	/* visit vfwmark list */
	memset(&srule->nf_addr, 0, sizeof(srule->nf_addr));
	srule->user.port = 0;
	for (e = LIST_HEAD(vsg->vfwmark); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);
		srule->user.fwmark = vsg_entry->vfwmark;

		/* Talk to the IPVS channel */
		if (ipvs_change_needed(cmd, vsg_entry, vs, rs)) {
			if (ipvs_talk(cmd, srule, drule, NULL, false))
				return -1;
			ipvs_set_vsge_alive_state(cmd, vsg_entry, vs);
		}
	}

	return 0;
}

/* Fill IPVS rule with root vs infos */
static void
ipvs_set_srule(int cmd, ipvs_service_t *srule, virtual_server_t *vs)
{
	/* Clean service rule */
	memset(srule, 0, sizeof(ipvs_service_t));

	strncpy(srule->user.sched_name, vs->sched, IP_VS_SCHEDNAME_MAXLEN);
	srule->af = vs->af;
	srule->user.flags = vs->flags;
	srule->user.netmask = (vs->af == AF_INET6) ? 128 : ((uint32_t) 0xffffffff);
	srule->user.protocol = vs->service_type;

	if (vs->persistence_timeout &&
	    (cmd == IP_VS_SO_SET_ADD || cmd == IP_VS_SO_SET_DEL)) {
		srule->user.timeout = vs->persistence_timeout;
		srule->user.flags |= IP_VS_SVC_F_PERSISTENT;

		if (vs->persistence_granularity)
			srule->user.netmask = vs->persistence_granularity;
	}

#ifdef _HAVE_PE_NAME_
	strcpy(srule->pe_name, vs->pe_name);
#endif
}

/* Fill IPVS rule with rs infos */
static void
ipvs_set_drule(int cmd, ipvs_dest_t *drule, real_server_t * rs)
{
	if (cmd != IP_VS_SO_SET_ADDDEST &&
	    cmd != IP_VS_SO_SET_DELDEST &&
	    cmd != IP_VS_SO_SET_EDITDEST)
		return;

	/* Clean target rule */
	memset(drule, 0, sizeof(ipvs_dest_t));

	drule->af = rs->addr.ss_family;
	if (rs->addr.ss_family == AF_INET6)
		inet_sockaddrip6(&rs->addr, &drule->nf_addr.in6);
	else
		drule->nf_addr.ip = inet_sockaddrip4(&rs->addr);
	drule->user.port = inet_sockaddrport(&rs->addr);
	drule->user.conn_flags = rs->forwarding_method;
	drule->user.weight = rs->weight;
	drule->user.u_threshold = rs->u_threshold;
	drule->user.l_threshold = rs->l_threshold;
}

/* Set/Remove a RS from a VS */
int
ipvs_cmd(int cmd, virtual_server_t *vs, real_server_t *rs)
{
	ipvs_service_t srule;
	ipvs_dest_t drule;

	/* Allocate the room */
	ipvs_set_srule(cmd, &srule, vs);
	if (rs) {
		ipvs_set_drule(cmd, &drule, rs);

		/* Does the service use inhibit flag ? */
		if (cmd == IP_VS_SO_SET_DELDEST && rs->inhibit) {
			drule.user.weight = 0;
			cmd = IP_VS_SO_SET_EDITDEST;
		}
		else if (cmd == IP_VS_SO_SET_ADDDEST && rs->inhibit && rs->set)
			cmd = IP_VS_SO_SET_EDITDEST;

		/* Set flag */
		else if (cmd == IP_VS_SO_SET_ADDDEST && !rs->set) {
			rs->set = true;
			if (rs->inhibit && rs->num_failed_checkers)
				drule.user.weight = 0;
		}
		else if (cmd == IP_VS_SO_SET_DELDEST && rs->set)
			rs->set = false;
	}

	/* Set vs rule and send to kernel */
	if (vs->vsgname)
		return ipvs_group_cmd(cmd, &srule, &drule, vs, rs);

	if (vs->vfwmark) {
		srule.user.fwmark = vs->vfwmark;
	} else {
		if (vs->af == AF_INET6)
			inet_sockaddrip6(&vs->addr, &srule.nf_addr.in6);
		else
			srule.nf_addr.ip = inet_sockaddrip4(&vs->addr);
		srule.user.port = inet_sockaddrport(&vs->addr);
	}

	/* Talk to the IPVS channel */
	return ipvs_talk(cmd, &srule, &drule, NULL, false);
}

/* at reload, add alive destinations to the newly created vsge */
void
ipvs_group_sync_entry(virtual_server_t *vs, virtual_server_group_entry_t *vsge)
{
	real_server_t *rs;
	element e;
	ipvs_service_t srule;
	ipvs_dest_t drule;

	ipvs_set_srule(IP_VS_SO_SET_ADDDEST, &srule, vs);
	if (!vsge->vfwmark)
		srule.user.port = inet_sockaddrport(&vsge->addr);

	/* Process realserver queue */
	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);

// ??? What if !quorum_state_up?
		if (rs->reloaded && (rs->alive || (rs->inhibit && rs->set))) {
			/* Prepare the IPVS drule */
			ipvs_set_drule(IP_VS_SO_SET_ADDDEST, &drule, rs);
			drule.user.weight = rs->inhibit && !rs->alive ? 0 : rs->weight;

			/* Set vs rule */
			if (vsge->range)
				ipvs_group_range_cmd(IP_VS_SO_SET_ADDDEST, &srule, &drule, vsge);
			else {
				if (vsge->vfwmark)
					srule.user.fwmark = vsge->vfwmark;
				else {
					if (vsge->addr.ss_family == AF_INET6)
						inet_sockaddrip6(&vsge->addr, &srule.nf_addr.in6);
					else
						srule.nf_addr.ip = inet_sockaddrip4(&vsge->addr);
				}

				/* Talk to the IPVS channel */
				ipvs_talk(IP_VS_SO_SET_ADDDEST, &srule, &drule, NULL, false);
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
	ipvs_service_t srule;
	ipvs_dest_t drule;

	/* Prepare target rules */
	ipvs_set_srule(IP_VS_SO_SET_DELDEST, &srule, vs);
	if (!vsge->vfwmark)
		srule.user.port = inet_sockaddrport(&vsge->addr);

	/* Process realserver queue */
	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);

		if (rs->alive) {
			/* Setting IPVS drule */
			ipvs_set_drule(IP_VS_SO_SET_DELDEST, &drule, rs);

			/* Set vs rule */
			if (vsge->range)
				ipvs_group_range_cmd(IP_VS_SO_SET_DELDEST, &srule, &drule, vsge);
			else {
				if (vsge->vfwmark)
					srule.user.fwmark = vsge->vfwmark;
				else {
					if (vsge->addr.ss_family == AF_INET6)
						inet_sockaddrip6(&vsge->addr, &srule.nf_addr.in6);
					else
						srule.nf_addr.ip = inet_sockaddrip4(&vsge->addr);
				}

				/* Talk to the IPVS channel */
				ipvs_talk(IP_VS_SO_SET_DELDEST, &srule, &drule, NULL, false);
			}
		}
	}

	/* Remove VS entry */
	if (vsge->range)
		ipvs_group_range_cmd(IP_VS_SO_SET_DEL, &srule, NULL, vsge);
	else
		ipvs_talk(IP_VS_SO_SET_DEL, &srule, NULL, NULL, false);
	unset_vsge_alive(vsge,vs);
}

#ifdef _WITH_SNMP_CHECKER_
static inline bool
vsd_equal(real_server_t *rs, struct ip_vs_dest_entry_app *entry)
{
	if (entry->af != AF_INET && entry->af != AF_INET6)
		return false;

	if (rs->addr.ss_family != entry->af)
		return false;

	if (!inaddr_equal(entry->af, &entry->nf_addr,
			entry->af == AF_INET ? (void *)&((struct sockaddr_in *)&rs->addr)->sin_addr
					     : (void *)&((struct sockaddr_in6 *)&rs->addr)->sin6_addr))
		return false;

	if (entry->user.port != (entry->af == AF_INET ? ((struct sockaddr_in *)&rs->addr)->sin_port
						      : ((struct sockaddr_in6 *)&rs->addr)->sin6_port))
		return false;

	return true;
}

static void
ipvs_update_vs_stats(virtual_server_t *vs, uint32_t fwmark, union nf_inet_addr *nfaddr, uint16_t port)
{
	element e;
	struct ip_vs_get_dests_app *dests = NULL;
	real_server_t *rs;
	unsigned int i;
	ipvs_service_entry_t *serv;

	if (!(serv = ipvs_get_service(fwmark, vs->af, vs->service_type, nfaddr, port)))
		return;

	/* Update virtual server stats */
	vs->stats.conns		+= serv->stats.conns;
	vs->stats.inpkts	+= serv->stats.inpkts;
	vs->stats.outpkts	+= serv->stats.outpkts;
	vs->stats.inbytes	+= serv->stats.inbytes;
	vs->stats.outbytes	+= serv->stats.outbytes;
	vs->stats.cps		+= serv->stats.cps;
	vs->stats.inpps		+= serv->stats.inpps;
	vs->stats.outpps	+= serv->stats.outpps;
	vs->stats.inbps		+= serv->stats.inbps;
	vs->stats.outbps	+= serv->stats.outbps;

	/* Get real servers */
	dests = ipvs_get_dests(serv);
	FREE(serv);
	if (!dests)
		return;

	for (i = 0; i < dests->user.num_dests; i++) {
		rs = NULL;

		/* Is it the sorry server? */
		if (vs->s_svr && vsd_equal(vs->s_svr, &dests->user.entrytable[i]))
			rs = vs->s_svr;
		else {
			/* Search for a match in the list of real servers */
			for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
				rs = ELEMENT_DATA(e);
				if (vsd_equal(rs, &dests->user.entrytable[i]))
					break;
			}
			if (!e)
				rs = NULL;
		}

		if (rs) {
			rs->activeconns		+= dests->user.entrytable[i].user.activeconns;
			rs->inactconns		+= dests->user.entrytable[i].user.inactconns;
			rs->persistconns	+= dests->user.entrytable[i].user.persistconns;
			rs->stats.conns		+= dests->user.entrytable[i].stats.conns;
			rs->stats.inpkts	+= dests->user.entrytable[i].stats.inpkts;
			rs->stats.outpkts	+= dests->user.entrytable[i].stats.outpkts;
			rs->stats.inbytes	+= dests->user.entrytable[i].stats.inbytes;
			rs->stats.outbytes	+= dests->user.entrytable[i].stats.outbytes;
			rs->stats.cps		+= dests->user.entrytable[i].stats.cps;
			rs->stats.inpps		+= dests->user.entrytable[i].stats.inpps;
			rs->stats.outpps	+= dests->user.entrytable[i].stats.outpps;
			rs->stats.inbps		+= dests->user.entrytable[i].stats.inbps;
			rs->stats.outbps	+= dests->user.entrytable[i].stats.outbps;
		}
	}
	FREE(dests);
}

/* Update statistics for a given virtual server. This includes
   statistics of real servers. The update is only done if we need
   refreshing. */
void
ipvs_update_stats(virtual_server_t *vs)
{
	element e, ge;
	virtual_server_group_entry_t *vsg_entry;
	uint32_t addr_ip;
	uint16_t port;
	union nf_inet_addr nfaddr;
	unsigned i;
	real_server_t *rs;
	time_t time_now = time(NULL);

	if (time_now - vs->lastupdated < STATS_REFRESH)
		return;
	vs->lastupdated = time_now;

	/* Reset stats */
	memset(&vs->stats, 0, sizeof(vs->stats));
	if (vs->s_svr) {
		memset(&vs->s_svr->stats, 0, sizeof(vs->s_svr->stats));
		vs->s_svr->activeconns =
			vs->s_svr->inactconns = vs->s_svr->persistconns = 0;
	}
	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		memset(&rs->stats, 0, sizeof(rs->stats));
		rs->activeconns = rs->inactconns = rs->persistconns = 0;
	}

	/* Update the stats */
	if (vs->vsgname) {
		for (ge = LIST_HEAD(vs->vsg->vfwmark); ge; ELEMENT_NEXT(ge)) {
			vsg_entry = ELEMENT_DATA(ge);
			ipvs_update_vs_stats(vs, vsg_entry->vfwmark, &nfaddr, 0);
		}
		for (ge = LIST_HEAD(vs->vsg->addr_range); ge; ELEMENT_NEXT(ge)) {
			vsg_entry = ELEMENT_DATA(ge);
			addr_ip = (vsg_entry->addr.ss_family == AF_INET6) ?
				    ntohs(((struct sockaddr_in6 *)&vsg_entry->addr)->sin6_addr.s6_addr16[7]) :
				    ntohl(((struct sockaddr_in *)&vsg_entry->addr)->sin_addr.s_addr);
			if (vsg_entry->addr.ss_family == AF_INET6)
				inet_sockaddrip6(&vsg_entry->addr, &nfaddr.in6);

			port = inet_sockaddrport(&vsg_entry->addr);
			for (i = 0; i <= vsg_entry->range; i++, addr_ip++) {
				if (vsg_entry->addr.ss_family == AF_INET6)
					nfaddr.in6.s6_addr16[7] = htons(addr_ip);
				else
					nfaddr.ip = htonl(addr_ip);

				ipvs_update_vs_stats(vs, 0, &nfaddr, port);
			}
		}
	} else if (vs->vfwmark) {
		memset(&nfaddr, 0, sizeof(nfaddr));
		ipvs_update_vs_stats(vs, vs->vfwmark, &nfaddr, 0);
	} else {
		memcpy(&nfaddr, (vs->addr.ss_family == AF_INET6)?
		       (void*)(&((struct sockaddr_in6 *)&vs->addr)->sin6_addr):
		       (void*)(&((struct sockaddr_in *)&vs->addr)->sin_addr),
		       sizeof(nfaddr));
		ipvs_update_vs_stats(vs, 0, &nfaddr, inet_sockaddrport(&vs->addr));
	}
}
#endif /* _WITH_SNMP_CHECKER_ */

#ifdef _WITH_VRRP_
/*
 * Common IPVS functions
 */
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
