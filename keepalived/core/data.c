/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Dynamic data structure definition.
 *
 * Version:     $Id: data.c,v 0.6.9 2002/07/31 01:33:12 acassen Exp $
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
}

static void
free_vrrp(void *data)
{
	vrrp_rt *vrrp = data;

	FREE(vrrp->iname);
	FREE_PTR(vrrp->lvs_syncd_if);
	FREE_PTR(vrrp->vaddr);
	FREE_PTR(vrrp->evaddr);
	FREE_PTR(vrrp->script_backup);
	FREE_PTR(vrrp->script_master);
	FREE_PTR(vrrp->script_fault);
	FREE(vrrp->ipsecah_counter);
	FREE(vrrp);
}
static void
dump_vrrp(void *data)
{
	vrrp_rt *vrrp = data;
	int i;

	syslog(LOG_INFO, " VRRP Instance = %s", vrrp->iname);
	if (vrrp->init_state == VRRP_STATE_BACK)
		syslog(LOG_INFO, "   Want State = BACKUP");
	else
		syslog(LOG_INFO, "   Want State = MASTER");
	syslog(LOG_INFO, "   Runing on device = %s", IF_NAME(vrrp->ifp));
	if (vrrp->mcast_saddr)
		syslog(LOG_INFO, "   Using mcast src_ip = %s",
		       inet_ntop2(vrrp->mcast_saddr));
	if (vrrp->lvs_syncd_if)
		syslog(LOG_INFO, "   Runing LVS sync daemon on interface = %s",
		       vrrp->lvs_syncd_if);
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
	syslog(LOG_INFO, "   VIP count = %d", vrrp->naddr);
	for (i = 0; i < vrrp->naddr; i++)
		syslog(LOG_INFO, "     VIP%d = %s/%d", i + 1,
		       inet_ntop2(vrrp->vaddr[i].addr)
		       , vrrp->vaddr[i].mask);
	if (vrrp->neaddr) {
		syslog(LOG_INFO, "   Excluded VIP count = %d", vrrp->neaddr);
		for (i = 0; i < vrrp->neaddr; i++)
			syslog(LOG_INFO, "     E-VIP%d = %s/%d", i + 1,
			       inet_ntop2(vrrp->evaddr[i].addr)
			       , vrrp->evaddr[i].mask);
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
#ifdef _WITH_VRRP_
	new->sync = vrrp_get_sync_group(iname);
#endif

	list_add(conf_data->vrrp, new);
}

void
alloc_vrrp_vip(char *vip)
{
	vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);
	uint32_t ipaddr = 0;
	uint8_t mask = inet_stom(vip);
	inet_ston(vip, &ipaddr);

	vrrp->naddr++;
	if (vrrp->vaddr)
		vrrp->vaddr =
		    REALLOC(vrrp->vaddr, vrrp->naddr * sizeof (*vrrp->vaddr));
	else
		vrrp->vaddr = (vip_addr *) MALLOC(sizeof (*vrrp->vaddr));
	vrrp->vaddr[vrrp->naddr - 1].addr = ipaddr;
	vrrp->vaddr[vrrp->naddr - 1].mask = mask;
	vrrp->vaddr[vrrp->naddr - 1].set = 0;
}

void
alloc_vrrp_evip(char *vip)
{
	vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);
	uint32_t ipaddr = 0;
	uint8_t mask = inet_stom(vip);
	inet_ston(vip, &ipaddr);

	vrrp->neaddr++;
	if (vrrp->evaddr)
		vrrp->evaddr =
		    REALLOC(vrrp->evaddr,
			    vrrp->neaddr * sizeof (*vrrp->evaddr));
	else
		vrrp->evaddr = (vip_addr *) MALLOC(sizeof (*vrrp->evaddr));
	vrrp->evaddr[vrrp->neaddr - 1].addr = ipaddr;
	vrrp->evaddr[vrrp->neaddr - 1].mask = mask;
	vrrp->evaddr[vrrp->neaddr - 1].set = 0;
}

/* Virtual server facility functions */
static void
free_vs(void *data)
{
	virtual_server *vs = data;
	FREE_PTR(vs->virtualhost);
	FREE_PTR(vs->s_svr);
	if (!LIST_ISEMPTY(vs->rs))
		free_list(vs->rs);
	if (!LIST_ISEMPTY(vs->rs_group))
		free_list(vs->rs_group);
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

	switch (vs->loadbalancing_kind) {
#ifdef _WITH_LVS_
#ifdef _KRNL_2_2_
	case 0:
		syslog(LOG_INFO, "   lb_kind = NAT");
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
	if (!LIST_ISEMPTY(vs->rs_group))
		dump_list(vs->rs_group);
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
}

void
alloc_rs(char *ip, char *port)
{
	virtual_server *vs = LIST_TAIL_DATA(conf_data->vs);
	real_server *new;

	new = (real_server *) MALLOC(sizeof (real_server));

	inet_ston(ip, &new->addr_ip);
	new->addr_port = htons(atoi(port));

	if (LIST_ISEMPTY(vs->rs))
		vs->rs = alloc_list(free_rs, dump_rs);
	list_add(vs->rs, new);
	vs->last_rs_type = RS;
}

/* Real server group facility functions */
static void
free_group(void *data)
{
	real_server_group *group = data;
	FREE(group->gname);
	if (!LIST_ISEMPTY(group->rs))
		free_list(group->rs);
//  if (!LIST_ISEMPTY(group->vs))
//    free_list(group->vs);
	FREE(group);
}
static void
dump_group(void *data)
{
	real_server_group *group = data;
	syslog(LOG_INFO, " Real Server Group = %s", group->gname);
	dump_list(group->rs);
}

void
alloc_rsgroup(char *ip, char *port)
{
	real_server_group *group = LIST_TAIL_DATA(conf_data->group);
	real_server *new;

	new = (real_server *) MALLOC(sizeof (real_server));

	inet_ston(ip, &new->addr_ip);
	new->addr_port = htons(atoi(port));
	new->alive = 1;

	if (LIST_ISEMPTY(group->rs))
		group->rs = alloc_list(free_rs, dump_rs);
	list_add(group->rs, new);
}

void
alloc_group(char *name)
{
	real_server_group *new;
	int size = strlen(name);

	new = (real_server_group *) MALLOC(sizeof (real_server_group));

	new->gname = (char *) MALLOC(size + 1);
	memcpy(new->gname, name, size);
	list_add(conf_data->group, new);
}
static real_server_group *
get_group_by_name(char *name)
{
	real_server_group *group;
	element e;

	for (e = LIST_HEAD(conf_data->group); e; ELEMENT_NEXT(e)) {
		group = ELEMENT_DATA(e);
		if (strcmp(group->gname, name) == 0)
			return group;
	}
	return NULL;
}
static void
dump_rs_group(void *data)
{
	real_server_group *group = data;
	syslog(LOG_INFO, "   Linking Real Server Group = %s", group->gname);
}

void
set_rsgroup(char *gname)
{
	real_server_group *group = get_group_by_name(gname);
	virtual_server *vs = LIST_TAIL_DATA(conf_data->vs);

	if (group) {
		if (LIST_ISEMPTY(vs->rs_group))
			vs->rs_group = alloc_list(NULL, dump_rs_group);
		list_add(vs->rs_group, group);
		vs->last_rs_type = RS_GROUP;
	}
}

/* data facility functions */
data *
alloc_data(void)
{
	data *new;

	new = (data *) MALLOC(sizeof (data));
	new->email = alloc_list(free_email, dump_email);
	new->vrrp = alloc_list(free_vrrp, dump_vrrp);
	new->vrrp_sync_group = alloc_list(free_vgroup, dump_vgroup);
	new->vs = alloc_list(free_vs, dump_vs);
	new->group = alloc_list(free_group, dump_group);

	return new;
}

void
free_data(data * data)
{
	free_list(data->email);
	free_list(data->vrrp);
	free_list(data->vrrp_sync_group);
	free_list(data->vs);
	free_list(data->group);

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
	if (!LIST_ISEMPTY(data->vrrp)) {
		syslog(LOG_INFO, "------< VRRP Topology >------");
		dump_list(data->vrrp);
	}
	if (!LIST_ISEMPTY(data->vrrp_sync_group)) {
		syslog(LOG_INFO, "------< VRRP Sync groups >------");
		dump_list(data->vrrp_sync_group);
	}
	if (!LIST_ISEMPTY(data->group)) {
		syslog(LOG_INFO, "------< Real Servers groups >------");
		dump_list(data->group);
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
