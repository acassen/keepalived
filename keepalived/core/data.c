/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Dynamic data structure definition.
 *
 * Version:     $Id: data.c,v 1.0.1 2003/03/17 22:14:34 acassen Exp $
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

#include "data.h"
#include "memory.h"
#include "utils.h"
#include "check_api.h"
#include "vrrp.h"
#include "vrrp_sync.h"

extern data *conf_data;

/* email facility functions */
static void
free_email(void *data)
{
	FREE(data);
}
static void
dump_email(void *data)
{
	char *addr = data;
	syslog(LOG_INFO, " Email notification = %s", addr);
}

void
alloc_email(char *addr)
{
	int size = strlen(addr);
	char *new;

	new = (char *) MALLOC(size + 1);
	memcpy(new, addr, size);

	list_add(conf_data->email, new);
}

/* SSL facility functions */
SSL_DATA *
alloc_ssl(void)
{
	SSL_DATA *ssl = (SSL_DATA *) MALLOC(sizeof (SSL_DATA));
	return ssl;
}
void
free_ssl(void)
{
	SSL_DATA *ssl = conf_data->ssl;

	if (!ssl)
		return;
	FREE_PTR(ssl->password);
	FREE_PTR(ssl->cafile);
	FREE_PTR(ssl->certfile);
	FREE_PTR(ssl->keyfile);
	FREE(ssl);
}
static void
dump_ssl(void)
{
	SSL_DATA *ssl = conf_data->ssl;

	if (ssl->password)
		syslog(LOG_INFO, " Password : %s", ssl->password);
	if (ssl->cafile)
		syslog(LOG_INFO, " CA-file : %s", ssl->cafile);
	if (ssl->certfile)
		syslog(LOG_INFO, " Certificate file : %s", ssl->certfile);
	if (ssl->keyfile)
		syslog(LOG_INFO, " Key file : %s", ssl->keyfile);
	if (!ssl->password && !ssl->cafile && !ssl->certfile && !ssl->keyfile)
		syslog(LOG_INFO, " Using autogen SSL context");
}

#ifdef _WITH_VRRP_
/* Static routes facility functions */
void
alloc_sroute(vector strvec)
{
	if (LIST_ISEMPTY(conf_data->static_routes))
		conf_data->static_routes = alloc_list(free_route, dump_route);
	alloc_route(conf_data->static_routes, strvec);
}

/* VRRP facility functions */
static void
free_vgroup(void *data)
{
	vrrp_sgroup *vgroup = data;

	FREE(vgroup->gname);
	free_strvec(vgroup->iname);
	FREE_PTR(vgroup->script_backup);
	FREE_PTR(vgroup->script_master);
	FREE_PTR(vgroup->script_fault);
	FREE(vgroup);
}
static void
dump_vgroup(void *data)
{
	vrrp_sgroup *vgroup = data;
	int i;
	char *str;

	syslog(LOG_INFO, " VRRP Sync Group = %s, %s", vgroup->gname,
	       (vgroup->state == VRRP_STATE_MAST) ? "MASTER" : "BACKUP");
	for (i = 0; i < VECTOR_SIZE(vgroup->iname); i++) {
		str = VECTOR_SLOT(vgroup->iname, i);
		syslog(LOG_INFO, "   monitor = %s", str);
	}
	if (vgroup->script_backup)
		syslog(LOG_INFO, "   Backup state transition script = %s",
		       vgroup->script_backup);
	if (vgroup->script_master)
		syslog(LOG_INFO, "   Master state transition script = %s",
		       vgroup->script_master);
	if (vgroup->script_fault)
		syslog(LOG_INFO, "   Fault state transition script = %s",
		       vgroup->script_fault);
	if (vgroup->smtp_alert)
		syslog(LOG_INFO, "   Using smtp notification");
}

static void
free_vrrp(void *data)
{
	vrrp_rt *vrrp = data;

	FREE(vrrp->iname);
	FREE_PTR(vrrp->lvs_syncd_if);
	FREE_PTR(vrrp->script_backup);
	FREE_PTR(vrrp->script_master);
	FREE_PTR(vrrp->script_fault);
	FREE(vrrp->ipsecah_counter);
	if (!LIST_ISEMPTY(vrrp->vip))
		free_list(vrrp->vip);
	if (!LIST_ISEMPTY(vrrp->evip))
		free_list(vrrp->evip);
	if (!LIST_ISEMPTY(vrrp->vroutes))
		free_list(vrrp->vroutes);
	FREE(vrrp);
}
static void
dump_vrrp(void *data)
{
	vrrp_rt *vrrp = data;

	syslog(LOG_INFO, " VRRP Instance = %s", vrrp->iname);
	if (vrrp->init_state == VRRP_STATE_BACK)
		syslog(LOG_INFO, "   Want State = BACKUP");
	else
		syslog(LOG_INFO, "   Want State = MASTER");
	syslog(LOG_INFO, "   Runing on device = %s", IF_NAME(vrrp->ifp));
	if (vrrp->track_ifp)
		syslog(LOG_INFO, "   Track interface = %s",
		       IF_NAME(vrrp->track_ifp));
	if (vrrp->mcast_saddr)
		syslog(LOG_INFO, "   Using mcast src_ip = %s",
		       inet_ntop2(vrrp->mcast_saddr));
	if (vrrp->lvs_syncd_if)
		syslog(LOG_INFO, "   Runing LVS sync daemon on interface = %s",
		       vrrp->lvs_syncd_if);
	if (vrrp->garp_delay)
		syslog(LOG_INFO, "   Gratuitous ARP delay = %d", vrrp->garp_delay);
	syslog(LOG_INFO, "   Virtual Router ID = %d", vrrp->vrid);
	syslog(LOG_INFO, "   Priority = %d", vrrp->priority);
	syslog(LOG_INFO, "   Advert interval = %dsec",
	       vrrp->adver_int / TIMER_HZ);
	if (vrrp->preempt)
		syslog(LOG_INFO, "   Preempt Active");
	if (vrrp->auth_type) {
		syslog(LOG_INFO, "   Authentication type = %s",
		       (vrrp->auth_type ==
			VRRP_AUTH_AH) ? "IPSEC_AH" : "SIMPLE_PASSWORD");
		syslog(LOG_INFO, "   Password = %s", vrrp->auth_data);
	}
	if (!LIST_ISEMPTY(vrrp->vip)) {
		syslog(LOG_INFO, "   Virtual IP = %d", LIST_SIZE(vrrp->vip));
		dump_list(vrrp->vip);
	}
	if (!LIST_ISEMPTY(vrrp->evip)) {
		syslog(LOG_INFO, "   Virtual IP Excluded = %d", LIST_SIZE(vrrp->evip));
		dump_list(vrrp->evip);
	}
	if (!LIST_ISEMPTY(vrrp->vroutes)) {
		syslog(LOG_INFO, "   Virtual Routes = %d", LIST_SIZE(vrrp->vroutes));
		dump_list(vrrp->vroutes);
	}
	if (vrrp->script_backup)
		syslog(LOG_INFO, "   Backup state transition script = %s",
		       vrrp->script_backup);
	if (vrrp->script_master)
		syslog(LOG_INFO, "   Master state transition script = %s",
		       vrrp->script_master);
	if (vrrp->script_fault)
		syslog(LOG_INFO, "   Fault state transition script = %s",
		       vrrp->script_fault);
	if (vrrp->smtp_alert)
		syslog(LOG_INFO, "   Using smtp notification");
}

void
alloc_vrrp_sync_group(char *gname)
{
	int size = strlen(gname);
	vrrp_sgroup *new;

	/* Allocate new VRRP group structure */
	new = (vrrp_sgroup *) MALLOC(sizeof (vrrp_sgroup));
	new->gname = (char *) MALLOC(size + 1);
	new->state = VRRP_STATE_BACK;
	memcpy(new->gname, gname, size);

	list_add(conf_data->vrrp_sync_group, new);
}

void
alloc_vrrp(char *iname)
{
	int size = strlen(iname);
	seq_counter *counter;
	vrrp_rt *new;

	/* Allocate new VRRP structure */
	new = (vrrp_rt *) MALLOC(sizeof (vrrp_rt));
	counter = (seq_counter *) MALLOC(sizeof (seq_counter));

	/* Build the structure */
	new->ipsecah_counter = counter;

	/* Set default values */
	new->wantstate = VRRP_STATE_BACK;
	new->init_state = VRRP_STATE_BACK;
	new->adver_int = TIMER_HZ;
	new->iname = (char *) MALLOC(size + 1);
	memcpy(new->iname, iname, size);
	new->sync = vrrp_get_sync_group(iname);

	list_add(conf_data->vrrp, new);
}

void
alloc_vrrp_vip(vector strvec)
{
	vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);

	if (LIST_ISEMPTY(vrrp->vip))
		vrrp->vip = alloc_list(free_ipaddress, dump_ipaddress);
	alloc_ipaddress(vrrp->vip, strvec, IF_INDEX(vrrp->ifp));
}
void
alloc_vrrp_evip(vector strvec)
{
	vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);

	if (LIST_ISEMPTY(vrrp->evip))
		vrrp->evip = alloc_list(free_ipaddress, dump_ipaddress);
	alloc_ipaddress(vrrp->evip, strvec, IF_INDEX(vrrp->ifp));
}

void
alloc_vrrp_vroute(vector strvec)
{
	vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);

	if (LIST_ISEMPTY(vrrp->vroutes))
		vrrp->vroutes = alloc_list(free_route, dump_route);
	alloc_route(vrrp->vroutes, strvec);
}
#endif

/* Virtual server facility functions */
static void
free_vs(void *data)
{
	virtual_server *vs = data;
	FREE_PTR(vs->virtualhost);
	FREE_PTR(vs->s_svr);
	if (!LIST_ISEMPTY(vs->rs))
		free_list(vs->rs);
	FREE(vs);
}
static void
dump_vs(void *data)
{
	virtual_server *vs = data;

	if (vs->vfwmark)
		syslog(LOG_INFO, " VS FWMARK = %d", vs->vfwmark);
	else
		syslog(LOG_INFO, " VIP = %s, VPORT = %d", inet_ntop2(SVR_IP(vs))
		       , ntohs(SVR_PORT(vs)));
	if (vs->virtualhost)
		syslog(LOG_INFO, "   VirtualHost = %s", vs->virtualhost);
	syslog(LOG_INFO, "   delay_loop = %d, lb_algo = %s", vs->delay_loop,
	       vs->sched);
	if (atoi(vs->timeout_persistence) > 0)
		syslog(LOG_INFO, "   persistence timeout = %s",
		       vs->timeout_persistence);
	if (vs->granularity_persistence)
		syslog(LOG_INFO, "   persistence granularity = %s",
		       inet_ntop2(vs->granularity_persistence));
	syslog(LOG_INFO, "   protocol = %s",
	       (vs->service_type == IPPROTO_TCP) ? "TCP" : "UDP");
	if (vs->ha_suspend)
		syslog(LOG_INFO, "   Using HA suspend");

	switch (vs->loadbalancing_kind) {
#ifdef _WITH_LVS_
#ifdef _KRNL_2_2_
	case 0:
		syslog(LOG_INFO, "   lb_kind = NAT");
		if (vs->nat_mask)
			syslog(LOG_INFO, "   nat mask = %s", inet_ntop2(vs->nat_mask));
		break;
	case IP_MASQ_F_VS_DROUTE:
		syslog(LOG_INFO, "   lb_kind = DR");
		break;
	case IP_MASQ_F_VS_TUNNEL:
		syslog(LOG_INFO, "   lb_kind = TUN");
		break;
#else
	case IP_VS_CONN_F_MASQ:
		syslog(LOG_INFO, "   lb_kind = NAT");
		break;
	case IP_VS_CONN_F_DROUTE:
		syslog(LOG_INFO, "   lb_kind = DR");
		break;
	case IP_VS_CONN_F_TUNNEL:
		syslog(LOG_INFO, "   lb_kind = TUN");
		break;
#endif
#endif
	}

	if (vs->s_svr) {
		syslog(LOG_INFO, "   sorry server = %s:%d",
		       inet_ntop2(SVR_IP(vs->s_svr))
		       , ntohs(SVR_PORT(vs->s_svr)));
	}
	if (!LIST_ISEMPTY(vs->rs))
		dump_list(vs->rs);
}

void
alloc_vs(char *ip, char *port)
{
	virtual_server *new;

	new = (virtual_server *) MALLOC(sizeof (virtual_server));

	if (!strcmp(ip, "fwmark")) {
		new->vfwmark = atoi(port);
	} else {
		inet_ston(ip, &new->addr_ip);
		new->addr_port = htons(atoi(port));
	}
	new->delay_loop = KEEPALIVED_DEFAULT_DELAY;
	strncpy(new->timeout_persistence, "0", 1);
	new->virtualhost = NULL;

	list_add(conf_data->vs, new);
}

/* Sorry server facility functions */
void
alloc_ssvr(char *ip, char *port)
{
	virtual_server *vs = LIST_TAIL_DATA(conf_data->vs);

	vs->s_svr = (real_server *) MALLOC(sizeof (real_server));
	vs->s_svr->weight = 1;
	inet_ston(ip, &vs->s_svr->addr_ip);
	vs->s_svr->addr_port = htons(atoi(port));
}

/* Real server facility functions */
static void
free_rs(void *data)
{
	real_server *rs = data;
	FREE_PTR(rs->notify_up);
	FREE_PTR(rs->notify_down);
	FREE(rs);
}
static void
dump_rs(void *data)
{
	real_server *rs = data;
	syslog(LOG_INFO, "   RIP = %s, RPORT = %d, WEIGHT = %d",
	       inet_ntop2(SVR_IP(rs))
	       , ntohs(SVR_PORT(rs))
	       , rs->weight);
	if (rs->inhibit)
		syslog(LOG_INFO, "     -> Inhibit service on failure");
	if (rs->notify_up)
		syslog(LOG_INFO, "     -> Notify script UP = %s",
		       rs->notify_up);
	if (rs->notify_down)
		syslog(LOG_INFO, "     -> Notify script DOWN = %s",
		       rs->notify_down);
}

void
alloc_rs(char *ip, char *port)
{
	virtual_server *vs = LIST_TAIL_DATA(conf_data->vs);
	real_server *new;

	new = (real_server *) MALLOC(sizeof (real_server));

	inet_ston(ip, &new->addr_ip);
	new->addr_port = htons(atoi(port));
	new->weight = 1;

	if (LIST_ISEMPTY(vs->rs))
		vs->rs = alloc_list(free_rs, dump_rs);
	list_add(vs->rs, new);
}

/* data facility functions */
data *
alloc_data(void)
{
	data *new;

	new = (data *) MALLOC(sizeof (data));
	new->email = alloc_list(free_email, dump_email);
#ifdef _WITH_VRRP_
	new->vrrp = alloc_list(free_vrrp, dump_vrrp);
	new->vrrp_sync_group = alloc_list(free_vgroup, dump_vgroup);
#endif
	new->vs = alloc_list(free_vs, dump_vs);

	return new;
}

void
free_data(data * data)
{
	free_list(data->email);
#ifdef _WITH_VRRP_
	free_list(data->vrrp);
	free_list(data->vrrp_sync_group);
#endif
	free_list(data->vs);

	FREE_PTR(data->lvs_id);
	FREE_PTR(data->email_from);
	FREE(data);
}

void
dump_data(data * data)
{
	if (data->lvs_id ||
	    data->smtp_server ||
	    data->smtp_connection_to || data->email_from) {
		syslog(LOG_INFO, "------< Global definitions >------");
	}
	if (data->lvs_id)
		syslog(LOG_INFO, " LVS ID = %s", data->lvs_id);
	if (data->smtp_server)
		syslog(LOG_INFO, " Smtp server = %s",
		       inet_ntop2(data->smtp_server));
	if (data->smtp_connection_to)
		syslog(LOG_INFO, " Smtp server connection timeout = %d",
		       data->smtp_connection_to);
	if (data->email_from) {
		syslog(LOG_INFO, " Email notification from = %s",
		       data->email_from);
		dump_list(data->email);
	}
	if (data->ssl) {
		syslog(LOG_INFO, "------< SSL definitions >------");
		dump_ssl();
	}
	if (!LIST_ISEMPTY(data->static_routes)) {
		syslog(LOG_INFO, "------< Static Routes >------");
		dump_list(data->static_routes);
	}
	if (!LIST_ISEMPTY(data->vrrp)) {
		syslog(LOG_INFO, "------< VRRP Topology >------");
		dump_list(data->vrrp);
	}
	if (!LIST_ISEMPTY(data->vrrp_sync_group)) {
		syslog(LOG_INFO, "------< VRRP Sync groups >------");
		dump_list(data->vrrp_sync_group);
	}
#ifdef _WITH_LVS_
	if (!LIST_ISEMPTY(data->vs)) {
		syslog(LOG_INFO, "------< LVS Topology >------");
		syslog(LOG_INFO, " System is compiled with LVS v%d.%d.%d",
		       NVERSION(IP_VS_VERSION_CODE));
		dump_list(data->vs);
	}
	dump_checkers_queue();
#endif
}
