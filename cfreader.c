/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        Configuration file parser/reader. Place into the dynamic
 *              data structure representation the conf file representing
 *              the loadbalanced server pool.
 *  
 * Version:     $Id: cfreader.c,v 0.4.1 2001/09/14 00:37:56 acassen Exp $
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

#include "cfreader.h"

/* Global keyword structure defs */
char *string; /* Temp read buffer */

struct keyword keywords[] = {
  {KW_BEGINFLAG,    "{"},
  {KW_ENDFLAG,      "}"},

  {KW_GLOBALDEFS,   "global_defs"},
  {KW_EMAIL,        "notification_email"},
  {KW_EMAILFROM,    "notification_email_from"},
  {KW_LVSID,        "lvs_id"},
  {KW_SMTP,         "smtp_server"},
  {KW_STIMEOUT,     "smtp_connect_timeout"},

  {KW_VS,           "virtual_server"},
  {KW_DELAY,        "delay_loop"},
  {KW_LBSCHED,      "lb_algo"},
  {KW_LBKIND,       "lb_kind"},
  {KW_NATMASK,      "nat_mask"},
  {KW_PTIMEOUT,     "persistence_timeout"},
  {KW_PROTOCOL,     "protocol"},
  {KW_SSVR,         "sorry_server"},

  {KW_SVR,          "real_server"},
  {KW_WEIGHT,       "weight"},
  {KW_CTIMEOUT,     "connect_timeout"},
  {KW_URL,          "url"},
  {KW_URLPATH,      "path"},
  {KW_DIGEST,       "digest"},
  {KW_NBGETRETRY,   "nb_get_retry"},
  {KW_DELAYRETRY,   "delay_before_retry"},

  {KW_ICMPCHECK,    "ICMP_CHECK"},
  {KW_TCPCHECK,     "TCP_CHECK"},
  {KW_HTTPGET,      "HTTP_GET"},
  {KW_SSLGET,       "SSL_GET"},
  {KW_LDAPGET,      "LDAP_GET"},

  {KW_VRRP,         "vrrp_instance"},
  {KW_VRRPINT,      "interface"},
  {KW_VRRPVRID,     "virtual_router_id"},
  {KW_VRRPAUTH,     "authentication"},
  {KW_VRRPAUTHTYPE, "auth_type"},
  {KW_VRRPAUTHAH,   "AH"},
  {KW_VRRPAUTHPWD,  "PASS"},
  {KW_VRRPAUTHPASS, "auth_pass"},
  {KW_VRRPPRIO,     "priority"},
  {KW_VRRPADVERT,   "advert_int"},
  {KW_VRRPIPADD,    "virtual_ipaddress"},
  {KW_VRRPSYNC,     "sync_instance"},
  {KW_VRRPPREEMPT,  "preempt"},

  {KW_UNKNOWN,     NULL}
};

int key(const char *word)
{
  int i;

  for (i=0; keywords[i].word; i++)
    if (strcmp(word, keywords[i].word) == 0)
      return keywords[i].key;

  return KW_UNKNOWN;
}

/* Dynamic data structure creation functions start here */
int already_exist_vs(virtualserver *lstptr, uint32_t ip, uint16_t port)
{
  virtualserver *pointerptr=lstptr;

  while(lstptr != NULL) {
    if((lstptr->addr_ip.s_addr == ip) && (lstptr->addr_port == port)) {
      lstptr = pointerptr;
      return 1;
    }
    lstptr = (virtualserver *)lstptr->next;
  }
  lstptr = pointerptr;
  return 0;
}

int already_exist_svr(realserver *lstptr, uint32_t ip, uint16_t port)
{
  realserver *pointerptr=lstptr;

  while(lstptr != NULL) {
    if((lstptr->addr_ip.s_addr == ip) && (lstptr->addr_port == port)) {
      lstptr = pointerptr;
      return 1;
    }
    lstptr = (realserver *)lstptr->next;
  }
  lstptr = pointerptr;
  return 0;
}

vrrp_instance * add_item_vrrp(vrrp_instance *lstvrrp, vrrp_instance *vrrp)
{
  vrrp_instance *pointerlst = lstvrrp;

  if (lstvrrp != NULL) {
    while(lstvrrp->next != NULL) lstvrrp = (vrrp_instance *)lstvrrp->next;
    lstvrrp->next = (struct vrrp_instance *)vrrp;
    return pointerlst;
  } else {
    lstvrrp = vrrp;
    return lstvrrp;
  }
}

notification_email * add_item_email(notification_email *lstemail,notification_email *email)
{
  notification_email *pointerlst = lstemail;

  if (lstemail != NULL) {
    while(lstemail->next != NULL) lstemail = (notification_email *)lstemail->next;
    lstemail->next = (struct notification_email *)email;
    return pointerlst;
  } else {
    lstemail = email;
    return lstemail;
  }
}

virtualserver * add_item_vs(virtualserver *lstvs,virtualserver *vs)
{
  virtualserver *pointerlst = lstvs;

  if(already_exist_vs(lstvs, vs->addr_ip.s_addr, vs->addr_port)) return lstvs;

  if (lstvs != NULL) {
    while(lstvs->next != NULL) lstvs = (virtualserver *)lstvs->next;
    lstvs->next = (struct virtualserver *)vs;
    return pointerlst;
  } else {
    lstvs = vs;
    return lstvs;
  }
}

realserver * add_item_svr(realserver *lstsvr,realserver *svr)
{
  realserver *pointerlst = lstsvr;

  if(already_exist_svr(lstsvr, svr->addr_ip.s_addr, svr->addr_port)) return lstsvr;

  if (lstsvr != NULL) {
    while(lstsvr->next != NULL) lstsvr = (realserver *)lstsvr->next;
    lstsvr->next = (struct realserver *)svr;
    return pointerlst;
  } else {
    lstsvr = svr;
    return lstsvr;
  }
}

urls * add_item_url(urls *lsturls,urls *url)
{
  urls *pointerlst = lsturls;

  if (lsturls != NULL) {
    while(lsturls->next != NULL) lsturls = (urls *)lsturls->next;
    lsturls->next = (struct urls *)url;
    return pointerlst;
  } else {
    lsturls = url;
    return lsturls;
  }
}

/* Dynamic data structure cleanup functions start here */
urls * remove_url(urls * lstptr)
{
  urls *t;

  t = (urls *)lstptr->next;
  free(lstptr);
  return t;
}

realserver * remove_svr(realserver * lstptr)
{
  realserver *t;

  t = (realserver *)lstptr->next;

  if(lstptr->method->http_get != NULL) {
    while(lstptr->method->http_get->check_urls != NULL)
      lstptr->method->http_get->check_urls = remove_url(lstptr->method->http_get->check_urls);
    free(lstptr->method->http_get);
  }

  free(lstptr->method);
  free(lstptr);
  return t;
}

virtualserver * remove_vs(virtualserver * lstptr)
{
  virtualserver *t;

  t = (virtualserver *)lstptr->next;
  while(lstptr->svr != NULL) lstptr->svr = remove_svr(lstptr->svr);
  free(lstptr->s_svr);
  free(lstptr);
  return t;
}

vrrp_instance * remove_vrrp(vrrp_instance *lstptr)
{
  vrrp_instance *t;

  t = (vrrp_instance *)lstptr->next;
  free(lstptr->vsrv->vaddr);
  free(lstptr->vsrv->ipsecah_counter);
  free(lstptr->vsrv->vif);
  free(lstptr->vsrv);
  free(lstptr);
  return t;
}

notification_email * remove_email(notification_email *lstptr)
{
  notification_email *t;

  t = (notification_email *)lstptr->next;
  free(lstptr);
  return t;
}

void clear_conf(configuration_data * lstptr)
{
  while(lstptr->email != NULL)
    lstptr->email = remove_email(lstptr->email);

  while(lstptr->vrrp != NULL)
    lstptr->vrrp = remove_vrrp(lstptr->vrrp);

  while(lstptr->lvstopology != NULL)
    lstptr->lvstopology = remove_vs(lstptr->lvstopology);
}

void clear_vrrp_instance(vrrp_instance *lstptr)
{
  while (lstptr) {
    vrrp_state_stop_instance(lstptr->vsrv);
    lstptr = (vrrp_instance *)lstptr->next;
  }
}

/* Dynamic data structure dump functions start here */
void dump_httpget(http_get_check *pointerhttpget)
{
  urls *pointerurls;

  syslog(LOG_DEBUG,"       -> Nb get retry = %d",
                   pointerhttpget->nb_get_retry);
  syslog(LOG_DEBUG,"       -> Delay before retry = %d",
                   pointerhttpget->delay_before_retry);

  pointerurls = pointerhttpget->check_urls;
  while(pointerhttpget->check_urls) {
    syslog(LOG_DEBUG,"       -> Url = %s, Digest = %s",
                     pointerhttpget->check_urls->url,
                     pointerhttpget->check_urls->digest);

    pointerhttpget->check_urls = (urls *)pointerhttpget->check_urls->next;
  }
  pointerhttpget->check_urls = pointerurls;
}

void dump_svr(realserver *pointersvr)
{
  while(pointersvr != NULL) {
    syslog(LOG_DEBUG,"    -> SVR IP = %s, PORT = %d, WEIGHT = %d",
                     inet_ntoa(pointersvr->addr_ip),
                     ntohs(pointersvr->addr_port),
                     pointersvr->weight);

    switch (pointersvr->method->type) {
      case ICMP_CHECK_ID:
        syslog(LOG_DEBUG,"       -> Keepalive method = ICMP_CHECK");
        break;
      case TCP_CHECK_ID:
        syslog(LOG_DEBUG,"       -> Keepalive method = TCP_CHECK");
        syslog(LOG_DEBUG,"       -> Connection timeout = %d",
                         pointersvr->method->connection_to);
        break;
      case HTTP_GET_ID:
        syslog(LOG_DEBUG,"       -> Keepalive method = HTTP_GET");
        syslog(LOG_DEBUG,"       -> Connection timeout = %d",
                         pointersvr->method->connection_to);
        dump_httpget(pointersvr->method->http_get);
        break;
      case SSL_GET_ID:
        break;
      case LDAP_GET_ID:
        break;
    }

    pointersvr = (realserver *)pointersvr->next;
  }
}

void dump_vs(virtualserver *pointervs)
{
  while(pointervs != NULL) {
    syslog(LOG_DEBUG, " VS IP = %s, PORT = %d",
                      inet_ntoa(pointervs->addr_ip),
                      ntohs(pointervs->addr_port));

    syslog(LOG_DEBUG, " -> delay_loop = %d, lb_algo = %s, "
                      "lb_kind = %s, persistence = %s, protocol = %s",
                      pointervs->delay_loop, pointervs->sched,
                      (pointervs->loadbalancing_kind == 0)?"NAT":"UNKNOWN",
                      pointervs->timeout_persistence,
                      (pointervs->service_type == IPPROTO_TCP)?"TCP":"UDP");

    syslog(LOG_DEBUG, " -> nat mask = %s", inet_ntoa(pointervs->nat_mask));

    if (pointervs->s_svr != NULL) {
      syslog(LOG_DEBUG, " -> sorry server = [%s:%d]", 
                        inet_ntoa(pointervs->s_svr->addr_ip),
                        ntohs(pointervs->s_svr->addr_port));
    }

    dump_svr(pointervs->svr);

    pointervs = (virtualserver *)pointervs->next;
  }
}

void dump_email(notification_email *pointeremail)
{
  while(pointeremail != NULL) {
    syslog(LOG_DEBUG," Email notification = %s", pointeremail->addr);

    pointeremail = (notification_email *)pointeremail->next;
  }
}

void dump_vrrp(vrrp_instance *pointervrrp)
{
  int i;

  while (pointervrrp != NULL) {
    syslog(LOG_DEBUG, " VRRP Instance = %s", pointervrrp->iname);
    syslog(LOG_DEBUG, "   Device = %s", pointervrrp->vsrv->vif->ifname);
    if (strlen(pointervrrp->isync) > 0)
      syslog(LOG_DEBUG, "   Sync with instance = %s", pointervrrp->isync);
    syslog(LOG_DEBUG, "   Virtual Router ID = %d", pointervrrp->vsrv->vrid);
    syslog(LOG_DEBUG, "   Priority = %d", pointervrrp->vsrv->priority);
    syslog(LOG_DEBUG, "   Advert interval = %dsec",
                      pointervrrp->vsrv->adver_int/VRRP_TIMER_HZ);
    if (pointervrrp->vsrv->preempt)
      syslog(LOG_DEBUG, "   Preempt active");
    if (pointervrrp->vsrv->vif->auth_type) {
      syslog(LOG_DEBUG, "   Authentication type = %s", 
            (pointervrrp->vsrv->vif->auth_type == VRRP_AUTH_AH)?"IPSEC_AH":"SIMPLE_PASSWORD" );
      syslog(LOG_DEBUG, "   Password = %s", pointervrrp->vsrv->vif->auth_data);
    }
    syslog(LOG_DEBUG, "   VIP count = %d", pointervrrp->vsrv->naddr);
    for (i = 0; i<pointervrrp->vsrv->naddr; i++)
      syslog(LOG_DEBUG, "     VIP%d = %s", i+1, ip_ntoa(ntohl(pointervrrp->vsrv->vaddr[i].addr)));

    pointervrrp = (vrrp_instance *)pointervrrp->next;
  }
}

void dump_conf(configuration_data *lstconf)
{
  if(lstconf == NULL) {
    syslog(LOG_DEBUG, "Empty data configuration !!!");
  } else {
    syslog(LOG_DEBUG,"------< Global definitions >------");
    syslog(LOG_DEBUG," LVS ID = %s",lstconf->lvs_id);
    syslog(LOG_DEBUG," Smtp server = %s", inet_ntoa(lstconf->smtp_server));
    syslog(LOG_DEBUG," Smtp server connection timeout = %d", lstconf->smtp_connection_to);
    syslog(LOG_DEBUG," Email notification from = %s",lstconf->email_from);
    dump_email(lstconf->email);

    if (lstconf->vrrp) {
      syslog(LOG_DEBUG,"------< VRRP Topology >------");
      dump_vrrp(lstconf->vrrp);
    }

    if (lstconf->lvstopology) {
      syslog(LOG_DEBUG,"------< LVS Topology >------");
      dump_vs(lstconf->lvstopology);
    }
  }
}

/* Dynamic data structure stream processing functions start here */
void process_stream_icmpcheck(FILE *stream, realserver *svrfill)
{
  keepalive_check *methodfill;

  /* Allocate new method structure */
  methodfill = (keepalive_check *)malloc(sizeof(keepalive_check));
  memset(methodfill, 0, sizeof(keepalive_check));

  methodfill->type = ICMP_CHECK_ID;
  methodfill->http_get = NULL;

  svrfill->method = methodfill;
}

void process_stream_tcpcheck(FILE *stream, realserver *svrfill)
{
  keepalive_check *methodfill;

  /* Allocate new method structure */
  methodfill = (keepalive_check *)malloc(sizeof(keepalive_check));
  memset(methodfill, 0, sizeof(keepalive_check));

  methodfill->type = TCP_CHECK_ID;
  methodfill->http_get = NULL;

  do {
    switch (key(string)) {
      case KW_CTIMEOUT:
        fscanf(stream, "%d", &methodfill->connection_to);
        break;
      case KW_UNKNOWN:
        break;
    }
    fscanf(stream, "%s", string);
  } while(key(string) != KW_ENDFLAG);

  svrfill->method = methodfill;
}

void process_stream_url(FILE *stream, http_get_check *httpgetfill)
{
  urls *urlfill;

  /* Allocate new url structure */
  urlfill = (urls *)malloc(sizeof(urls));
  memset(urlfill, 0, sizeof(urls));

  urlfill->next = NULL;

  do {
    switch (key(string)) {
      case KW_URLPATH:
        fscanf(stream, "%s", urlfill->url);
        break;
      case KW_DIGEST:
        fscanf(stream, "%s", urlfill->digest);
        break;
      case KW_UNKNOWN:
        break;
    }
    fscanf(stream, "%s", string);
  } while(key(string) != KW_ENDFLAG);

  httpgetfill->check_urls = add_item_url(httpgetfill->check_urls, urlfill);
}

void process_stream_httpget(FILE *stream, realserver *svrfill)
{
  keepalive_check *methodfill;
  http_get_check *httpgetfill;

  /* Allocate new method structure */
  methodfill = (keepalive_check *)malloc(sizeof(keepalive_check));
  memset(methodfill, 0, sizeof(keepalive_check));

  /* Allocate new http get structure */
  httpgetfill = (http_get_check *)malloc(sizeof(http_get_check));
  memset(httpgetfill, 0, sizeof(http_get_check));

  methodfill->type = HTTP_GET_ID;
  methodfill->http_get = httpgetfill;
  httpgetfill->check_urls = NULL;

  do {
    switch (key(string)) {
      case KW_CTIMEOUT:
        fscanf(stream, "%d", &methodfill->connection_to);
        break;
      case KW_NBGETRETRY:
        fscanf(stream, "%d", &httpgetfill->nb_get_retry);
        break;
      case KW_DELAYRETRY:
        fscanf(stream, "%d", &httpgetfill->delay_before_retry);
        break;
      case KW_URL:
        process_stream_url(stream, httpgetfill);
        break;
      case KW_UNKNOWN:
        break;
    }
    fscanf(stream, "%s", string);
  } while(key(string) != KW_ENDFLAG);

  svrfill->method = methodfill;
}

void process_stream_svr(FILE *stream, virtualserver *vsfill)
{
  realserver *svrfill;

  /* Allocate new real server structure */
  svrfill = (realserver *)malloc(sizeof(realserver));
  memset(svrfill, 0, sizeof(realserver));

  /* Add the real server allocated to the virtual server
   * data structure.
   */
  svrfill->next = NULL;                   /* not required */
  svrfill->alive = 1;                     /* server is alive */
  vsfill->svr = add_item_svr(vsfill->svr, svrfill);

  fscanf(stream, "%s", string); 
  svrfill->addr_ip.s_addr = inet_addr(string);
  fscanf(stream, "%s", string);
  svrfill->addr_port = htons(atoi(string));

  do {
    switch (key(string)) {
      case KW_WEIGHT:
        fscanf(stream, "%d", &svrfill->weight);
        break;
      case KW_ICMPCHECK:
        process_stream_icmpcheck(stream, svrfill);
        break;
      case KW_TCPCHECK:
        process_stream_tcpcheck(stream, svrfill);
        break;
      case KW_HTTPGET:
        process_stream_httpget(stream, svrfill);
        break;
      case KW_SSLGET: /* not yet implemented */
        break;
      case KW_LDAPGET: /* not yet implemented */
        break;
      case KW_UNKNOWN:
        break;
    }
    fscanf(stream, "%s", string);
  } while(key(string) != KW_ENDFLAG);
}

void process_stream_ssvr(FILE *stream, virtualserver *vsfill)
{
  realserver *ssvrfill;

  /* Allocate new sorry server structure */
  ssvrfill = (realserver *)malloc(sizeof(realserver));
  memset(ssvrfill, 0, sizeof(realserver));

  /* direct affectation, we can use add_item_svr, so
   * can specify more than 1 sorry_server...
   * Not really needed !
   */
  vsfill->s_svr = ssvrfill;

  ssvrfill->alive = 0;
  ssvrfill->weight = 1;
  ssvrfill->method = NULL;
  ssvrfill->next = NULL;

  fscanf(stream, "%s", string);
  ssvrfill->addr_ip.s_addr = inet_addr(string);
  fscanf(stream, "%s", string);
  ssvrfill->addr_port = htons(atoi(string));
}

void process_stream_vs(FILE *stream, configuration_data *conf_data)
{
  virtualserver *vsfill;

  /* Allocate new virtual server structure */
  vsfill = (virtualserver *)malloc(sizeof(virtualserver));
  memset(vsfill, 0, sizeof(virtualserver));

  /* Add the virtual server allocated to the configuration
   * data structure.
   */
  vsfill->next = NULL;                      /* not required */
  vsfill->s_svr = NULL;
  conf_data->lvstopology = add_item_vs(conf_data->lvstopology, vsfill);

  fscanf(stream, "%s", string);
  vsfill->addr_ip.s_addr = inet_addr(string);
  fscanf(stream, "%s", string);
  vsfill->addr_port = htons(atoi(string));

  do {
    switch (key(string)) {
      case KW_DELAY:
        fscanf(stream, "%d", &vsfill->delay_loop);
        break;
      case KW_LBSCHED:
        fscanf(stream, "%s", vsfill->sched);
        break;
      case KW_LBKIND:
        fscanf(stream, "%s", string);
        /* For the moment only NAT is supported.
         * masq_flags : IP_MASQ_F_VS_DROUTE & IP_MASQ_F_VS_TUNNEL not supported.
         * So we just set masq_flags to 0.
         */
        vsfill->loadbalancing_kind = 0;
        break;
      case KW_NATMASK:
        fscanf(stream, "%s", string);
        vsfill->nat_mask.s_addr = inet_addr(string);
        break;
      case KW_PTIMEOUT:
        fscanf(stream, "%s", vsfill->timeout_persistence);
        break;
      case KW_PROTOCOL:
        fscanf(stream, "%s", string);
        vsfill->service_type = (strcmp(string,"TCP") == 0)?IPPROTO_TCP:IPPROTO_UDP;
        break;
      case KW_SSVR:
        process_stream_ssvr(stream, vsfill);
        break;
      case KW_SVR:
        process_stream_svr(stream, vsfill);
        break;
      case KW_UNKNOWN:
        break;
    }
    fscanf(stream, "%s", string);
  } while(key(string) != KW_ENDFLAG);
}

void process_stream_email(FILE *stream, configuration_data *conf_data)
{
  notification_email *emailfill;

  /* Fill in email liste */
  do {
    fscanf(stream, "%s", string);
    if(key(string) != KW_BEGINFLAG && key(string) != KW_ENDFLAG) {
      emailfill = (notification_email *)malloc(sizeof(notification_email));
      memset(emailfill, 0, sizeof(notification_email));
      strncat(emailfill->addr, string, sizeof(emailfill->addr));
      emailfill->next = NULL;
      conf_data->email = add_item_email(conf_data->email, emailfill);
    }
  } while(key(string) != KW_ENDFLAG);
}

void process_stream_globaldefs(FILE *stream, configuration_data *conf_data)
{
  /* Fill in the global defs structure */
  do {
    switch (key(string)) {
      case KW_LVSID:
        fscanf(stream, "%s", conf_data->lvs_id);
        break;
      case KW_SMTP:
        fscanf(stream, "%s", string);
        conf_data->smtp_server.s_addr = inet_addr(string);
        break;
      case KW_STIMEOUT:
        fscanf(stream, "%d", &conf_data->smtp_connection_to);
        break;
      case KW_EMAILFROM:
        fscanf(stream, "%s", conf_data->email_from);
        break;
      case KW_EMAIL:
        process_stream_email(stream, conf_data);
        break;
      case KW_UNKNOWN:
        break;
    }
    fscanf(stream, "%s", string);
  } while(key(string) != KW_ENDFLAG);
}

static void add_item_vrrp_vip(vrrp_rt *vsrv, uint32_t ipaddr)
{
  vsrv->naddr++;
  /* alloc the room */
  if( vsrv->vaddr ){
    vsrv->vaddr = realloc(vsrv->vaddr, vsrv->naddr*sizeof(*vsrv->vaddr));
  } else {
    vsrv->vaddr = malloc(sizeof(*vsrv->vaddr));
  }
  /* store the data */
  vsrv->vaddr[vsrv->naddr-1].addr = ipaddr;
  vsrv->vaddr[vsrv->naddr-1].deletable = 0;
}

void process_stream_vrrp_ipaddress(FILE *stream, vrrp_rt *vrrp)
{
  uint32_t ipaddr;

  do {
    fscanf(stream, "%s", string);
    if(key(string) != KW_BEGINFLAG && key(string) != KW_ENDFLAG) {
      ipaddr = inet_addr(string);
      add_item_vrrp_vip(vrrp, ntohl(ipaddr));
    }
  } while(key(string) != KW_ENDFLAG);
}

void process_stream_vrrp_auth(FILE *stream, vrrp_if *vif)
{
  do {
    switch (key(string)) {
      case KW_VRRPAUTHTYPE:
        fscanf(stream, "%s", string);
        vif->auth_type = (key(string) == KW_VRRPAUTHAH)?VRRP_AUTH_AH:VRRP_AUTH_PASS;
        break;
      case KW_VRRPAUTHPASS:
        fscanf(stream, "%s", vif->auth_data);
        break;
      case KW_UNKNOWN:
        break;
    }
    fscanf(stream, "%s", string);
  } while(key(string) != KW_ENDFLAG);
}

int process_stream_vrrp(FILE *stream, configuration_data *conf_data)
{
  vrrp_instance *vrrpfill;
  vrrp_rt *rtfill;
  vrrp_if *viffill;
  seq_counter *counterfill;

  /* Allocate new VRRP structure */
  vrrpfill = (vrrp_instance *)malloc(sizeof(vrrp_instance));
  rtfill = (vrrp_rt *)malloc(sizeof(vrrp_rt));
  viffill = (vrrp_if *)malloc(sizeof(vrrp_if));
  counterfill = (seq_counter *)malloc(sizeof(seq_counter));

  memset(vrrpfill, 0, sizeof(vrrp_instance));
  memset(rtfill, 0, sizeof(vrrp_rt));
  memset(viffill, 0, sizeof(vrrp_if));
  memset(counterfill, 0, sizeof(seq_counter));

  /* Add the vrrp instance allocated to the configuration
   * data structure.
   */
  vrrpfill->vsrv = rtfill;
  vrrpfill->vsrv->vif = viffill;
  vrrpfill->vsrv->ipsecah_counter = counterfill;
  vrrpfill->vsrv->vaddr = NULL;
  vrrpfill->vsrv->vaddr = NULL;
  vrrpfill->next = NULL;

  conf_data->vrrp = add_item_vrrp(conf_data->vrrp, vrrpfill);

  fscanf(stream, "%s", vrrpfill->iname);

  /* Fill in the VRRP structure */
  do {
    switch (key(string)) {
      case KW_VRRPSYNC:
        fscanf(stream, "%s", vrrpfill->isync);
        break;
      case KW_VRRPINT:
        fscanf(stream, "%s", viffill->ifname);
        break;
      case KW_VRRPVRID:
        fscanf(stream, "%d", &rtfill->vrid);
        if (VRRP_IS_BAD_VID(rtfill->vrid)) {
          syslog(LOG_DEBUG, "VRRP Error : VRID not valid !");
          syslog(LOG_DEBUG, "VRRP Error : must be between 1 & 255. reconfigure !");
          return 0;
        }
        break;
      case KW_VRRPPRIO:
        fscanf(stream, "%d", &rtfill->priority);
        if (VRRP_IS_BAD_PRIORITY(rtfill->priority)) {
          syslog(LOG_DEBUG, "VRRP Error : priority not valid !");
          syslog(LOG_DEBUG, "VRRP Error : must be between 1 & 255. reconfigure !");
          return 0;
        }
        break;
      case KW_VRRPADVERT:
        fscanf(stream, "%d", &rtfill->adver_int);
        if (VRRP_IS_BAD_ADVERT_INT(rtfill->adver_int)) {
          syslog(LOG_DEBUG, "VRRP Error : Advert intervall not valid !");
          syslog(LOG_DEBUG, "VRRP Error : must be between less than 1sec. reconfigure !");
          return 0;
        }
        rtfill->adver_int *= VRRP_TIMER_HZ;
        break;
      case KW_VRRPAUTH:
        process_stream_vrrp_auth(stream, viffill);
        break;
      case KW_VRRPIPADD:
        process_stream_vrrp_ipaddress(stream, rtfill);
        break;
      case KW_VRRPPREEMPT:
        rtfill->preempt = !rtfill->preempt;
        break;
      case KW_UNKNOWN:
        break;
    }
    fscanf(stream, "%s", string);
  } while(key(string) != KW_ENDFLAG);

  /* Compute the static values to finish initialization */
  if (!complete_vrrp_init(rtfill))
    return 0;

  return 1;
}

configuration_data * conf_reader()
{
  configuration_data *conf_data;
  FILE *stream;

  /* Allocate configuration data memory */
  conf_data = (configuration_data *)malloc(sizeof(configuration_data));
  memset(conf_data, 0, sizeof(configuration_data));

  /* Parse the confuguration file */
  stream = fopen(CONFFILE, "r");
  if(!stream) {
    syslog(LOG_INFO, "ConfReader : Can not read the configuration file...");
    return(NULL);
  }

  /* Allocate temp buffer string */
  string = (char *)malloc(TEMP_BUFFER_LENGTH);
  memset(string, 0, TEMP_BUFFER_LENGTH);

  /* Initialise the dynamic data structure */
  conf_data->email = NULL;
  conf_data->lvstopology = NULL;

  while (!feof(stream)) {
    switch (key(string)) {
      case KW_GLOBALDEFS:
        process_stream_globaldefs(stream, conf_data);
        break;
      case KW_VS:
        process_stream_vs(stream, conf_data);
        break;
      case KW_VRRP:
        if (!process_stream_vrrp(stream, conf_data))
          return NULL;
        break;
      case KW_UNKNOWN:
        break;
    }
    fscanf(stream, "%s", string);
  }

  free(string);
  fclose(stream);
  return(conf_data);
}
