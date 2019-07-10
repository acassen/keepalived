/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        SNMP framework
 *
 * Authors:     Vincent Bernat <bernat@luffy.cx>
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

#include "scheduler.h"
#include "snmp.h"
#include "logger.h"
#include "global_data.h"
#include "main.h"
#include "utils.h"
#include "warnings.h"

#include <net-snmp/agent/agent_sysORTable.h>

static int
snmp_keepalived_log(__attribute__((unused)) int major, __attribute__((unused)) int minor, void *serverarg, __attribute__((unused)) void *clientarg)
{
	struct snmp_log_message *slm = (struct snmp_log_message*)serverarg;
	int slm_len = strlen(slm->msg);

	if (slm_len && slm->msg[slm_len-1] == '\n')
		slm_len--;
	log_message(slm->priority, "%.*s", slm_len, slm->msg);

	/* If we get an AgentX subagent connected message when we think
	 * we are connected, we need to re-register the fds for epoll */
	if (master->snmp_fdsetsize && slm->priority == 6)
		snmp_epoll_reset(master);

	return 0;
}

/* Convert linux scope to InetScopeType */
unsigned long
snmp_scope(int scope)
{
	switch (scope) {
	case 0: return 14;  /* global */
	case 255: return 0; /* nowhere */
	case 254: return 1; /* host */
	case 253: return 2; /* link */
	case 200: return 5; /* site */
	default: return 0;
	}
	return 0;
}

void*
snmp_header_list_table(struct variable *vp, oid *name, size_t *length,
		  int exact, size_t *var_len, WriteMethod **write_method, list dlist)
{
	element e;
	void *scr;
	oid target, current;

	if (header_simple_table(vp, name, length, exact, var_len, write_method, -1) != MATCH_SUCCEEDED)
		return NULL;

	if (LIST_ISEMPTY(dlist))
		return NULL;

	target = name[*length - 1];
	current = 0;

	/* If there are insufficent entries in the list, just return no match */
	if (LIST_SIZE(dlist) < target)
		return NULL;

	LIST_FOREACH(dlist, scr, e) {
		if (++current < target)
			/* No match found yet */
			continue;
		if (current == target)
			/* Exact match */
			return scr;
		if (exact)
			/* No exact match found */
			return NULL;
		/* current is the best match */
		name[*length - 1] = current;
		return scr;
	}

	/* No match found at end */
	return NULL;
}

/* This is the equivalent of snmp_header_list_table where each element of the first
 * list has a list itself for which each element in turn needs to be returned. */
element
snmp_find_element(struct variable *vp, oid *name, size_t *length,
	     int exact, size_t *var_len, WriteMethod **write_method,
	     list list1, size_t list2_offset)
{
	oid *target, current[2];
	int result;
	size_t target_len;
	element e, e1;
	void *element_data;
	__attribute__((unused)) void *dummy;
	list list2;

	*write_method = 0;
	*var_len = sizeof(long);

	if (LIST_ISEMPTY(list1))
		return NULL;

	if (exact && *length != (size_t)vp->namelen + 2)
		return NULL;

	if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
		memcpy(name, vp->name, sizeof(oid) * vp->namelen);
		*length = vp->namelen;
	}

	/* We search the best match: equal if exact, the lower OID in
	   the set of the OID strictly superior to the target
	   otherwise. */
	target = &name[vp->namelen];   /* Our target match */
	target_len = *length - vp->namelen;
	current[0] = 0;

	if (target_len && LIST_SIZE(list1) < target[0])
		return NULL;

	LIST_FOREACH(list1, element_data, e) {
		current[0]++;

		if (target_len) {
			if (current[0] < target[0])
				continue; /* Optimization: cannot be part of our set */
			if (exact && current[0] > target[0])
				return NULL;
		}

		list2 = *(list *)((char *)element_data + list2_offset);

		if (target_len && LIST_SIZE(list2) < target[1]) {
			if (exact)
				return NULL;
			continue;
		}

		current[1] = 0;
		LIST_FOREACH(list2, dummy, e1) {
			current[1]++;

			/* Compare to our target match */
			if (target_len) {
				if ((result = snmp_oid_compare(current, 2, target,
							       target_len)) < 0)
					continue;

				if (result == 0) {
					if (!exact)
						continue;

					/* Got an exact match and asked for it */
					return e1;
				}

				if (exact) {
					/* result > 0, so no match */
					return NULL;
				}
			}

			/* This is our best match */
			memcpy(target, current, sizeof(oid) * 2);
			*length = (unsigned)vp->namelen + 2;
			return e1;
		}
	}

	/* No match at all */
	return NULL;
}

enum snmp_global_magic {
	SNMP_KEEPALIVEDVERSION,
	SNMP_ROUTERID,
	SNMP_MAIL_SMTPSERVERADDRESSTYPE,
	SNMP_MAIL_SMTPSERVERADDRESS,
	SNMP_MAIL_SMTPSERVERTIMEOUT,
	SNMP_MAIL_EMAILFROM,
	SNMP_MAIL_EMAILADDRESS,
	SNMP_MAIL_EMAILFAULTS,
	SNMP_MAIL_SMTPSERVERPORT,
	SNMP_TRAPS,
	SNMP_LINKBEAT,
	SNMP_LVSFLUSH,
	SNMP_LVSFLUSH_ONSTOP,
	SNMP_IPVS_64BIT_STATS,
	SNMP_NET_NAMESPACE,
	SNMP_DBUS,
	SNMP_DYNAMIC_INTERFACES,
	SNMP_SMTP_ALERT,
	SNMP_SMTP_ALERT_VRRP,
	SNMP_SMTP_ALERT_CHECKER,
};

static u_char*
snmp_scalar(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	snmp_ret_t ret;

	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;

	switch (vp->magic) {
	case SNMP_KEEPALIVEDVERSION:
		*var_len = strlen(version_string);
		ret.cp = version_string;
		return ret.p;
	case SNMP_ROUTERID:
		if (!global_data->router_id) return NULL;
		*var_len = strlen(global_data->router_id);
		ret.cp = global_data->router_id;
		return ret.p;
	case SNMP_MAIL_SMTPSERVERADDRESSTYPE:
		long_ret = (global_data->smtp_server.ss_family == AF_INET6)?2:1;
		return (u_char *)&long_ret;
	case SNMP_MAIL_SMTPSERVERADDRESS:
		if (global_data->smtp_server.ss_family == AF_INET6) {
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&global_data->smtp_server;
			*var_len = 16;
			return (u_char *)&addr6->sin6_addr;
		} else {
			struct sockaddr_in *addr4 = (struct sockaddr_in *)&global_data->smtp_server;
			*var_len = 4;
			return (u_char *)&addr4->sin_addr;
		}
		return NULL;
	case SNMP_MAIL_SMTPSERVERPORT:
		long_ret = ntohs(inet_sockaddrport(&global_data->smtp_server));
		return (u_char *)&long_ret;
	case SNMP_MAIL_SMTPSERVERTIMEOUT:
		long_ret = global_data->smtp_connection_to / TIMER_HZ;
		return (u_char *)&long_ret;
	case SNMP_MAIL_EMAILFROM:
		if (!global_data->email_from) return NULL;
		*var_len = strlen(global_data->email_from);
		ret.cp = global_data->email_from;
		return ret.p;
#ifdef _WITH_VRRP_
	case SNMP_MAIL_EMAILFAULTS:
		long_ret = global_data->no_email_faults?2:1;
		return (u_char *)&long_ret;
#endif
	case SNMP_TRAPS:
		long_ret = global_data->enable_traps?1:2;
		return (u_char *)&long_ret;
#ifdef _WITH_LINKBEAT_
	case SNMP_LINKBEAT:
		long_ret = global_data->linkbeat_use_polling?2:1;
		return (u_char *)&long_ret;
#endif
#ifdef _WITH_LVS_
	case SNMP_LVSFLUSH:
		long_ret = global_data->lvs_flush?1:2;
		return (u_char *)&long_ret;
	case SNMP_LVSFLUSH_ONSTOP:
		long_ret = global_data->lvs_flush_onstop == LVS_FLUSH_FULL ? 1 :
			   global_data->lvs_flush_onstop == LVS_FLUSH_VS ? 3 : 2;
		return (u_char *)&long_ret;
#endif
	case SNMP_IPVS_64BIT_STATS:
#ifdef _WITH_LVS_64BIT_STATS_
		long_ret = 1;
#else
		long_ret = 2;
#endif
		return (u_char *)&long_ret;
	case SNMP_NET_NAMESPACE:
#if HAVE_DECL_CLONE_NEWNET
		if (global_data->network_namespace) {
			*var_len = strlen(global_data->network_namespace);
			ret.cp = global_data->network_namespace;
			return ret.p;
		}
#endif
		*var_len = 0;
		ret.cp = "";
		return ret.p;
	case SNMP_DBUS:
#ifdef _WITH_DBUS_
		if (global_data->enable_dbus)
			long_ret = 1;
		else
#endif
			long_ret = 2;
		return (u_char *)&long_ret;
#ifdef _WITH_VRRP_
	case SNMP_DYNAMIC_INTERFACES:
		long_ret = global_data->dynamic_interfaces ? 1 : 2;
		return (u_char *)&long_ret;
#endif
	case SNMP_SMTP_ALERT:
		long_ret = global_data->smtp_alert == -1 ? 3 : global_data->smtp_alert ? 1 : 2;
		return (u_char *)&long_ret;
#ifdef _WITH_VRRP_
	case SNMP_SMTP_ALERT_VRRP:
		long_ret = global_data->smtp_alert_vrrp == -1 ? 3 : global_data->smtp_alert_vrrp ? 1 : 2;
		return (u_char *)&long_ret;
#endif
#ifdef _WITH_LVS_
	case SNMP_SMTP_ALERT_CHECKER:
		long_ret = global_data->smtp_alert_checker == -1 ? 3 : global_data->smtp_alert_checker ? 1 : 2;
		return (u_char *)&long_ret;
#endif
	default:
		break;
	}
	return NULL;
}

static u_char*
snmp_mail(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	char *m;
	if ((m = (char *)snmp_header_list_table(vp, name, length, exact,
						 var_len, write_method,
						 global_data->email)) == NULL)
		return NULL;

	switch (vp->magic) {
	case SNMP_MAIL_EMAILADDRESS:
		*var_len = strlen(m);
		return (u_char *)m;
	default:
		break;
	}
	return NULL;
}

static const char global_name[] = "Keepalived";
static oid global_oid[] = GLOBAL_OID;
static struct variable8 global_vars[] = {
	/* version */
	{SNMP_KEEPALIVEDVERSION, ASN_OCTET_STR, RONLY, snmp_scalar, 1, {1}},
	/* routerId */
	{SNMP_ROUTERID, ASN_OCTET_STR, RONLY, snmp_scalar, 1, {2}},
	/* mail */
	{SNMP_MAIL_SMTPSERVERADDRESSTYPE, ASN_INTEGER, RONLY, snmp_scalar, 2, {3, 1}},
	{SNMP_MAIL_SMTPSERVERADDRESS, ASN_OCTET_STR, RONLY, snmp_scalar, 2, {3, 2}},
	{SNMP_MAIL_SMTPSERVERTIMEOUT, ASN_UNSIGNED, RONLY, snmp_scalar, 2, {3, 3}},
	{SNMP_MAIL_EMAILFROM, ASN_OCTET_STR, RONLY, snmp_scalar, 2, {3, 4}},
	/* emailTable */
	{SNMP_MAIL_EMAILADDRESS, ASN_OCTET_STR, RONLY, snmp_mail, 4, {3, 5, 1, 2}},
	/* SMTP server port */
	{SNMP_MAIL_SMTPSERVERPORT, ASN_UNSIGNED, RONLY, snmp_scalar, 2, {3, 6}},
	/* are vrrp fault state transitions emailed */
	{SNMP_MAIL_EMAILFAULTS, ASN_INTEGER, RONLY, snmp_scalar, 2, {3, 7}},
	{SNMP_SMTP_ALERT, ASN_INTEGER, RONLY, snmp_scalar, 2, {3, 8}},
#ifdef _WITH_VRRP_
	{SNMP_SMTP_ALERT_VRRP, ASN_INTEGER, RONLY, snmp_scalar, 2, {3, 9}},
#endif
#ifdef _WITH_LVS_
	{SNMP_SMTP_ALERT_CHECKER, ASN_INTEGER, RONLY, snmp_scalar, 2, {3, 10}},
#endif
	/* trapEnable */
	{SNMP_TRAPS, ASN_INTEGER, RONLY, snmp_scalar, 1, {4}},
	/* linkBeat */
	{SNMP_LINKBEAT, ASN_INTEGER, RONLY, snmp_scalar, 1, {5}},
#ifdef _WITH_LVS_
	/* lvsFlush */
	{SNMP_LVSFLUSH, ASN_INTEGER, RONLY, snmp_scalar, 1, {6}},
#endif
#ifdef _WITH_LVS_64BIT_STATS_
	/* LVS 64-bit stats */
	{SNMP_IPVS_64BIT_STATS, ASN_INTEGER, RONLY, snmp_scalar, 1, {7}},
#endif
	{SNMP_NET_NAMESPACE, ASN_OCTET_STR, RONLY, snmp_scalar, 1, {8}},
#ifdef _WITH_DBUS_
	{SNMP_DBUS, ASN_INTEGER, RONLY, snmp_scalar, 1, {9}},
#endif
#ifdef _WITH_VRRP_
	{SNMP_DYNAMIC_INTERFACES, ASN_INTEGER, RONLY, snmp_scalar, 1, {10}},
#endif
#ifdef _WITH_LVS_
	/* lvsFlushOnStop */
	{SNMP_LVSFLUSH_ONSTOP, ASN_INTEGER, RONLY, snmp_scalar, 1, {11}},
#endif
};

static int
snmp_setup_session_cb(__attribute__((unused)) int majorID, __attribute__((unused)) int minorID,
		      void *serverarg, __attribute__((unused)) void *clientarg)
{
	netsnmp_session *sess = serverarg;
	if (serverarg == NULL)
		return 0;
	/*
	 * Because ping are done synchronously, we do everything to
	 * avoid to block too long. Better disconnect from the master
	 * agent than waiting for him...
	 */
	sess->timeout = ONE_SEC / 3;
	sess->retries = 0;
	return 0;
}

void snmp_register_mib(oid *myoid, size_t len, const char *name,
		       struct variable *variables, size_t varsize, size_t varlen)
{
	char name_buf[80];

	if (register_mib(name, (struct variable *) variables, varsize,
			 varlen, myoid, len) != MIB_REGISTERED_OK)
		log_message(LOG_WARNING, "Unable to register %s MIB", name);

	snprintf(name_buf, sizeof(name_buf), "The MIB module for %s", name);
	register_sysORTable(myoid, len, name_buf);
}

void
snmp_unregister_mib(oid *myoid, size_t len)
{
	unregister_sysORTable(myoid, len);
}

void
snmp_agent_init(const char *snmp_socket_name, bool base_mib)
{
	if (snmp_running)
		return;

	log_message(LOG_INFO, "Starting SNMP subagent");
	netsnmp_enable_subagent();
	snmp_disable_log();
	snmp_enable_calllog();
	snmp_register_callback(SNMP_CALLBACK_LIBRARY,
			       SNMP_CALLBACK_LOGGING,
			       snmp_keepalived_log,
			       NULL);

	/* Do not handle persistent states */
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
	    NETSNMP_DS_LIB_DONT_PERSIST_STATE, TRUE);
	/* Do not load any MIB */
	setenv("MIBS", "", 1);
	/*
	 * We also register a callback to modify default timeout and
	 * retries value.
	 */
	snmp_register_callback(SNMP_CALLBACK_LIBRARY,
			       SNMP_CALLBACK_SESSION_INIT,
			       snmp_setup_session_cb, NULL);
	/* Specify the socket to master agent, if provided */
	if (snmp_socket_name != NULL) {
		netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
				      NETSNMP_DS_AGENT_X_SOCKET,
				      snmp_socket_name);
	}
	/*
	 * Ping AgentX less often than every 15 seconds: pinging can
	 * block keepalived. We check every 2 minutes.
	 */
	netsnmp_ds_set_int(NETSNMP_DS_APPLICATION_ID,
			   NETSNMP_DS_AGENT_AGENTX_PING_INTERVAL, 120);

	/* Tell library not to raise SIGALRM */
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_ALARM_DONT_USE_SIG, 1);

	init_agent(global_name);
	if (base_mib)
		snmp_register_mib(global_oid, OID_LENGTH(global_oid), global_name,
				  (struct variable *)global_vars,
				  sizeof(struct variable8),
				  sizeof(global_vars)/sizeof(struct variable8));
	init_snmp(global_name);

	master->snmp_timer_thread = thread_add_timer(master, snmp_timeout_thread, 0, TIMER_NEVER);

	snmp_running = true;
}

void
snmp_agent_close(bool base_mib)
{
	if (!snmp_running)
		return;

	if (base_mib)
		snmp_unregister_mib(global_oid, OID_LENGTH(global_oid));
	snmp_shutdown(global_name);

	snmp_running = false;
}

#ifdef THREAD_DUMP
void
register_snmp_addresses(void)
{
	register_thread_address("snmp_timeout_thread", snmp_timeout_thread);
}
#endif
