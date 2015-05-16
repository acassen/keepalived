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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#include "snmp.h"
#include "logger.h"
#include "config.h"
#include "global_data.h"

static int
snmp_keepalived_log(int major, int minor, void *serverarg, void *clientarg)
{
	struct snmp_log_message *slm = (struct snmp_log_message*)serverarg;
	log_message(slm->priority, "%s", slm->msg);
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
	unsigned int target, current;

	if (header_simple_table(vp, name, length, exact, var_len, write_method, -1))
		return NULL;

	if (LIST_ISEMPTY(dlist))
		return NULL;

	target = name[*length - 1];
	current = 0;

	for (e = LIST_HEAD(dlist); e; ELEMENT_NEXT(e)) {
		scr = ELEMENT_DATA(e);
		current++;
		if (current == target)
			/* Exact match */
			return scr;
		if (current < target)
			/* No match found yet */
			continue;
		if (exact)
			/* No exact match found */
			return NULL;
		/* current is the best match */
		name[*length - 1] = current;
		return scr;
	}
	/* No macth found at end */
	return NULL;
}

#define SNMP_KEEPALIVEDVERSION 1
#define SNMP_ROUTERID 2
#define SNMP_MAIL_SMTPSERVERADDRESSTYPE 3
#define SNMP_MAIL_SMTPSERVERADDRESS 4
#define SNMP_MAIL_SMTPSERVERTIMEOUT 5
#define SNMP_MAIL_EMAILFROM 6
#define SNMP_MAIL_EMAILADDRESS 7
#define SNMP_TRAPS 8
#define SNMP_LINKBEAT 9

static u_char*
snmp_scalar(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	static char version[] = VERSION_STRING;

	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;
	
	switch (vp->magic) {
	case SNMP_KEEPALIVEDVERSION:
		*var_len = sizeof(version) - 2;
		return (u_char *)version;
	case SNMP_ROUTERID:
		if (!global_data->router_id) return NULL;
		*var_len = strlen(global_data->router_id);
		return (u_char *)global_data->router_id;
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
	case SNMP_MAIL_SMTPSERVERTIMEOUT:
		long_ret = global_data->smtp_connection_to / TIMER_HZ;
		return (u_char *)&long_ret;
	case SNMP_MAIL_EMAILFROM:
		if (!global_data->email_from) return NULL;
		*var_len = strlen(global_data->email_from);
		return (u_char *)global_data->email_from;
	case SNMP_TRAPS:
		long_ret = global_data->enable_traps?1:2;
		return (u_char *)&long_ret;
	case SNMP_LINKBEAT:
		long_ret = global_data->linkbeat_use_polling?2:1;
		return (u_char *)&long_ret;
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
	/* trapEnable */
	{SNMP_TRAPS, ASN_INTEGER, RONLY, snmp_scalar, 1, {4}},
	/* linkBeat */
	{SNMP_LINKBEAT, ASN_INTEGER, RONLY, snmp_scalar, 1, {5}},
};

static int
snmp_setup_session_cb(int majorID, int minorID,
		      void *serverarg, void *clientarg)
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

void snmp_register_mib(oid *myoid, int len, const char *name,
		       struct variable *variables, int varsize, int varlen)
{
	char name_buf[80];

	if (register_mib(name, (struct variable *) variables, varsize,
			 varlen, myoid, len) != MIB_REGISTERED_OK)
		log_message(LOG_WARNING, "Unable to register %s MIB", name);

	snprintf(name_buf, sizeof(name_buf), "The MIB module for %s", name);
	register_sysORTable(myoid, OID_LENGTH(myoid) - 1, name_buf);
}

void
snmp_agent_init(const char *snmp_socket)
{
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
	if (snmp_socket != NULL) {
		netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
				      NETSNMP_DS_AGENT_X_SOCKET,
				      snmp_socket);
	}
	/*
	 * Ping AgentX less often than every 15 seconds: pinging can
	 * block keepalived. We check every 2 minutes.
	 */
	netsnmp_ds_set_int(NETSNMP_DS_APPLICATION_ID,
			   NETSNMP_DS_AGENT_AGENTX_PING_INTERVAL, 120);

	init_agent(global_name);
	snmp_register_mib(global_oid, OID_LENGTH(global_oid), global_name,
			  (struct variable *)global_vars,
			  sizeof(struct variable8),
			  sizeof(global_vars)/sizeof(struct variable8));
	init_snmp(global_name);
}

void
snmp_agent_close(oid *myoid, int len, char *name)
{
	unregister_sysORTable(myoid, len);
	unregister_sysORTable(global_oid, OID_LENGTH(global_oid));
	snmp_shutdown(global_name);
}
