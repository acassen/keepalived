/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        Configuration file parser/reader. Place into the dynamic
 *              data structure representation the conf file representing
 *              the loadbalanced server pool.
 *  
 * Version:     $Id: parser.c,v 0.5.6 2002/04/13 06:21:33 acassen Exp $
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

#include "parser.h"
#include "memory.h"
#include "vrrp.h"
#include "check_api.h"

/* global defs */
static vector keywords;
static int sublevel = 0;
static FILE *stream;
extern data *conf_data;

static void keyword_alloc(vector keywords, char *string, void (*handler)(vector))
{
  struct keyword *keyword;

  vector_alloc_slot(keywords);

  keyword = (struct keyword *)MALLOC(sizeof(struct keyword));
  keyword->string   = string;
  keyword->handler  = handler;

  vector_set_slot(keywords, keyword);
}

static void install_keyword_root(char *string, void (*handler)(vector))
{
  keyword_alloc(keywords, string, handler);
}

void install_sublevel(void)
{
  sublevel++;
}
void install_sublevel_end(void)
{
  sublevel--;
}

void install_keyword(char *string, void (*handler)(vector))
{
  int i = 0;
  struct keyword *keyword;

  /* fetch last keyword */
  keyword = VECTOR_SLOT(keywords, VECTOR_SIZE(keywords)-1);

  /* position to last sub level */
  for (i = 0; i < sublevel; i++)
    keyword = VECTOR_SLOT(keyword->sub, VECTOR_SIZE(keyword->sub)-1);

  /* First sub level allocation */
  if (!keyword->sub)
    keyword->sub = vector_alloc();

  /* add new sub keyword */
  keyword_alloc(keyword->sub, string, handler);
}

static void dump_keywords(vector keydump, int level)
{
  int i, j;
  struct keyword *keyword;

  for (i = 0; i < VECTOR_SIZE(keydump); i++) {
    keyword = VECTOR_SLOT(keydump, i);
    for (j = 0; j < level; j++) printf("  ");
    printf ("Keyword : %s\n", keyword->string);
    if (keyword->sub)
      dump_keywords(keyword->sub, level+1);
  }
}

static void free_keywords(vector keywords)
{
  int i;
  struct keyword *keyword;

  for (i = 0; i < VECTOR_SIZE(keywords); i++) {
    keyword = VECTOR_SLOT(keywords, i);
    if (keyword->sub)
      free_keywords(keyword->sub);
    FREE(keyword);
  }
  vector_free(keywords);
}

/*
static void dump_strvec(vector strvec)
{
  int i;
  char *str;

  if (!strvec)
    return;

  printf("String Vector : ");

  for (i = 0; i < VECTOR_SIZE(strvec); i++) {
    str = VECTOR_SLOT(strvec, i);
    printf("[%i]=%s ", i, str);
  }
  printf("\n");
}
*/

static void free_strvec(vector strvec)
{
  int i;
  char *str;

  if (!strvec)
    return;

  for (i=0; i < VECTOR_SIZE(strvec); i++)
    if ((str = VECTOR_SLOT(strvec, i)) != NULL)
      FREE(str);

  vector_free(strvec);
}

static vector alloc_strvec(char *string)
{
  char *cp, *start, *token;
  int strlen;
  vector strvec;

  if (!string)
    return NULL;

  cp = string;

  /* Skip white spaces */
  while ((isspace((int) *cp) || *cp == '\r' || *cp == '\n') &&
         *cp != '\0')
    cp++;

  /* Return if there is only white spaces */
  if (*cp == '\0')
    return NULL;

  /* Return if string begin with a comment */
  if (*cp == '!' || *cp == '#')
    return NULL;

  /* Create a vector and alloc each command piece */
  strvec = vector_alloc();

  while (1) {
    start = cp;
    while (!(isspace((int) *cp) || *cp == '\r' || *cp == '\n') &&
           *cp != '\0')
      cp++;
    strlen = cp - start;
    token = MALLOC(strlen + 1);
    memcpy(token, start, strlen);
    *(token + strlen) = '\0';

    /* Alloc & set the slot */
    vector_alloc_slot(strvec);
    vector_set_slot(strvec, token);

    while ((isspace((int) *cp) || *cp == '\n' || *cp == '\r') &&
           *cp != '\0')
      cp++;
    if (*cp == '\0' || *cp == '!' || *cp == '#')
      return strvec;
  }
}

static char *read_line(char *buf, int size)
{
  return(fgets(buf, size, stream));
}

vector read_value_block(void)
{
  char buf[BUFSIZ];
  int i;
  char *str = NULL;
  char *dup;
  vector vec = NULL;
  vector elements = vector_alloc();

  while (read_line(buf, BUFSIZ)) {
    vec = alloc_strvec(buf);
    str = VECTOR_SLOT(vec, 0);
    if (!strcmp(str, EOB)) {
      free_strvec(vec);
      break;
    }

    if (VECTOR_SIZE(vec))
      for (i = 0; i < VECTOR_SIZE(vec); i++) {
        str = VECTOR_SLOT(vec, i);
        dup = (char *)MALLOC(strlen(str)+1);
        memcpy(dup, str, strlen(str));
        vector_alloc_slot(elements);
        vector_set_slot(elements, dup);
      }
    free_strvec(vec);
  }

  return elements;
}

void *set_value(vector strvec)
{
  char *str = VECTOR_SLOT(strvec, 1);
  int size = strlen(str);
  void *alloc;

  alloc = MALLOC(size+1);
  memcpy(alloc, str, size);
  return alloc;
}

/* data handlers */
/* Global def handlers */
static void lvsid_handler(vector strvec)
{
  conf_data->lvs_id = set_value(strvec);
}
static void emailfrom_handler(vector strvec)
{
  conf_data->email_from = set_value(strvec);
}
static void smtpto_handler(vector strvec)
{
  conf_data->smtp_connection_to = atoi(VECTOR_SLOT(strvec, 1));
}
static void smtpip_handler(vector strvec)
{
  conf_data->smtp_server = inet_addr(VECTOR_SLOT(strvec, 1));
}
static void email_handler(vector strvec)
{
  vector email = read_value_block();
  int i;
  char *str;

  for (i = 0; i < VECTOR_SIZE(email); i++) {
    str = VECTOR_SLOT(email, i);
    alloc_email(str);
  }

  free_strvec(email);
}

/* SSL handlers */
static void ssl_handler(vector strvec)
{
  conf_data->ssl = alloc_ssl();
}
static void sslpass_handler(vector strvec)
{
  conf_data->ssl->password = set_value(strvec);
}
static void sslca_handler(vector strvec)
{
  conf_data->ssl->cafile = set_value(strvec);
}
static void sslcert_handler(vector strvec)
{
  conf_data->ssl->certfile = set_value(strvec);
}
static void sslkey_handler(vector strvec)
{
  conf_data->ssl->keyfile = set_value(strvec);
}

/* VRRP handlers */
static void vrrp_handler(vector strvec)
{
  alloc_vrrp(VECTOR_SLOT(strvec, 1));
}
static void vrrp_isync_handler(vector strvec)
{
  vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);
  vrrp->isync = set_value(strvec);
}
static void vrrp_state_handler(vector strvec)
{
  char *str = VECTOR_SLOT(strvec, 1);
  vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);

  if (!strcmp(str, "MASTER")) {
    vrrp->wantstate  = VRRP_STATE_MAST;
    vrrp->init_state = VRRP_STATE_MAST;
  } else {
    vrrp->wantstate  = VRRP_STATE_BACK;
    vrrp->init_state = VRRP_STATE_BACK;
  }
}
static void vrrp_int_handler(vector strvec)
{
  vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);
  char *name = VECTOR_SLOT(strvec, 1);

  vrrp->ifp = if_get_by_ifname(name);
}
static void vrrp_vrid_handler(vector strvec)
{
  vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);
  vrrp->vrid = atoi(VECTOR_SLOT(strvec, 1));

  if (VRRP_IS_BAD_VID(vrrp->vrid)) {
    syslog(LOG_INFO, "VRRP Error : VRID not valid !\n");
    syslog(LOG_INFO, "             must be between 1 & 255. reconfigure !\n");
  }
}
static void vrrp_prio_handler(vector strvec)
{
  vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);
  vrrp->priority = atoi(VECTOR_SLOT(strvec, 1));

  if (VRRP_IS_BAD_PRIORITY(vrrp->priority)) {
    syslog(LOG_INFO, "VRRP Error : Priority not valid !\n");
    syslog(LOG_INFO, "             must be between 1 & 255. reconfigure !\n");
    syslog(LOG_INFO, "             Using default value : 100\n");
    vrrp->priority = 100;
  }
}
static void vrrp_adv_handler(vector strvec)
{
  vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);
  vrrp->adver_int = atoi(VECTOR_SLOT(strvec, 1));

  if (VRRP_IS_BAD_ADVERT_INT(vrrp->adver_int)) {
    syslog(LOG_INFO, "VRRP Error : Advert intervall not valid !\n");
    syslog(LOG_INFO, "             must be between less than 1sec.\n");
    syslog(LOG_INFO, "             Using default value : 1sec\n");
    vrrp->adver_int = 1;
  }
  vrrp->adver_int *= TIMER_HZ;
}
static void vrrp_debug_handler(vector strvec)
{
  vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);
  vrrp->debug = atoi(VECTOR_SLOT(strvec, 1));

  if (VRRP_IS_BAD_DEBUG_INT(vrrp->debug)) {
    syslog(LOG_INFO, "VRRP Error : Debug intervall not valid !\n");
    syslog(LOG_INFO, "             must be between 0-4\n");
    vrrp->debug = 0;
  }
}
static void vrrp_preempt_handler(vector strvec)
{
  vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);
  vrrp->preempt = !vrrp->preempt;
}
static void vrrp_notify_handler(vector strvec)
{
  vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);
  char *str = VECTOR_SLOT(strvec, 1);
  int size = sizeof(vrrp->notify_file);

  memcpy(vrrp->notify_file, str, size);
  vrrp->notify_exec = 1;
}
static void vrrp_lvs_syncd_handler(vector strvec)
{
  vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);
  vrrp->lvs_syncd_if = set_value(strvec);
}
static void vrrp_auth_type_handler(vector strvec)
{
  vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);
  char *str = VECTOR_SLOT(strvec, 1);

  if (!strcmp(str, "AH"))
    vrrp->auth_type = VRRP_AUTH_AH;
  else
    vrrp->auth_type = VRRP_AUTH_PASS;
}
static void vrrp_auth_pass_handler(vector strvec)
{
  vrrp_rt *vrrp = LIST_TAIL_DATA(conf_data->vrrp);
  char *str = VECTOR_SLOT(strvec, 1);
  int size = sizeof(vrrp->auth_data);

  memcpy(vrrp->auth_data, str, size);
}
static void vrrp_vip_handler(vector strvec)
{
  vector vips = read_value_block();
  int i;
  char *str;

  for (i = 0; i < VECTOR_SIZE(vips); i++) {
    str = VECTOR_SLOT(vips, i);
    alloc_vrrp_vip(str);
  }

  free_strvec(vips);
}

/* Virtual Servers handlers */
static void vs_handler(vector strvec)
{
  alloc_vs(VECTOR_SLOT(strvec, 1), VECTOR_SLOT(strvec, 2));
}
static void delay_handler(vector strvec)
{
  virtual_server *vs = LIST_TAIL_DATA(conf_data->vs);
  vs->delay_loop = atoi(VECTOR_SLOT(strvec, 1));
}
static void lbalgo_handler(vector strvec)
{
  virtual_server *vs = LIST_TAIL_DATA(conf_data->vs);
  char *str = VECTOR_SLOT(strvec, 1);
  int size = sizeof(vs->sched);
  
  memcpy(vs->sched, str, size);
}
static void lbkind_handler(vector strvec)
{
  virtual_server *vs = LIST_TAIL_DATA(conf_data->vs);
  char *str = VECTOR_SLOT(strvec, 1);

#ifdef _KRNL_2_2_
  if (!strcmp(str, "NAT"))
    vs->loadbalancing_kind = 0;
  else
    if (!strcmp(str, "DR"))
      vs->loadbalancing_kind = IP_MASQ_F_VS_DROUTE;
    else
      if (!strcmp(str, "TUN"))
        vs->loadbalancing_kind = IP_MASQ_F_VS_TUNNEL;
#else
  if (!strcmp(str, "NAT"))
    vs->loadbalancing_kind = IP_VS_CONN_F_MASQ;
  else
    if (!strcmp(str, "DR"))
      vs->loadbalancing_kind = IP_VS_CONN_F_DROUTE;
    else
      if (!strcmp(str, "TUN"))
        vs->loadbalancing_kind = IP_VS_CONN_F_TUNNEL;
#endif
      else
        syslog(LOG_DEBUG, "PARSER : unknown [%s] routing method."
                        , str);
}
static void natmask_handler(vector strvec)
{
  virtual_server *vs = LIST_TAIL_DATA(conf_data->vs);
  vs->nat_mask = inet_addr(VECTOR_SLOT(strvec, 1));
}
static void pto_handler(vector strvec)
{
  virtual_server *vs = LIST_TAIL_DATA(conf_data->vs);
  char *str = VECTOR_SLOT(strvec, 1);
  int size = sizeof(vs->timeout_persistence);
  
  memcpy(vs->timeout_persistence, str, size);
  
}
static void proto_handler(vector strvec)
{
  virtual_server *vs = LIST_TAIL_DATA(conf_data->vs);
  char *str = VECTOR_SLOT(strvec, 1);
  vs->service_type = (!strcmp(str, "TCP"))?IPPROTO_TCP:IPPROTO_UDP;
}

/* Sorry Servers handlers */
static void ssvr_handler(vector strvec)
{
  alloc_ssvr(VECTOR_SLOT(strvec, 1), VECTOR_SLOT(strvec, 2));
}

/* Real Servers handlers */
static void rs_handler(vector strvec)
{
  alloc_rs(VECTOR_SLOT(strvec, 1), VECTOR_SLOT(strvec, 2));
}
static void weight_handler(vector strvec)
{
  virtual_server *vs = LIST_TAIL_DATA(conf_data->vs);
  real_server *rs = LIST_TAIL_DATA(vs->rs);
  rs->weight = atoi(VECTOR_SLOT(strvec, 1));
}

/* recursive configuration stream handler */
static void process_stream(vector keywords)
{
  int i;
  struct keyword *keyword;
  char *str;
  char buf[BUFSIZ];
  vector strvec;

  if (!read_line(buf, BUFSIZ))
    return;

  strvec = alloc_strvec(buf);

  if (!strvec) {
    process_stream(keywords);
    return;
  }

  str = VECTOR_SLOT(strvec, 0);

  if (!strcmp(str, EOB)) {
    free_strvec(strvec);
    return;
  }

  for (i = 0; i < VECTOR_SIZE(keywords); i++) {
    keyword = VECTOR_SLOT(keywords, i);

    if (!strcmp(keyword->string, str)) {
      if (keyword->handler)
        (*keyword->handler) (strvec);

      if (keyword->sub)
        process_stream(keyword->sub);
      break;
    }
  }

  free_strvec(strvec);
  process_stream(keywords);
}

void init_keywords(void)
{
  keywords = vector_alloc();

  /* global definitions mapping */
  install_keyword_root("global_defs",		NULL);
  install_keyword("lvs_id",			&lvsid_handler);
  install_keyword("notification_email_from",	&emailfrom_handler);
  install_keyword("smtp_server",		&smtpip_handler);
  install_keyword("smtp_connect_timeout",	&smtpto_handler);
  install_keyword("notification_email",		&email_handler);

  /* SSL mapping */
  install_keyword_root("SSL",			&ssl_handler);
  install_keyword("password",			&sslpass_handler);
  install_keyword("ca",				&sslca_handler);
  install_keyword("certificate",		&sslcert_handler);
  install_keyword("key", 			&sslkey_handler);

  /* VRRP Instance mapping */
  install_keyword_root("vrrp_instance",		&vrrp_handler);
  install_keyword("state",			&vrrp_state_handler);
  install_keyword("interface",			&vrrp_int_handler);
  install_keyword("virtual_router_id",		&vrrp_vrid_handler);
  install_keyword("priority",			&vrrp_prio_handler);
  install_keyword("advert_int",			&vrrp_adv_handler);
  install_keyword("virtual_ipaddress",		&vrrp_vip_handler);
  install_keyword("sync_instance",		&vrrp_isync_handler);
  install_keyword("preempt",			&vrrp_preempt_handler);
  install_keyword("debug",			&vrrp_debug_handler);
  install_keyword("notify",			&vrrp_notify_handler);
  install_keyword("lvs_sync_daemon_interface",	&vrrp_lvs_syncd_handler);
  install_keyword("authentication",		NULL);
  install_sublevel();
    install_keyword("auth_type",		&vrrp_auth_type_handler);
    install_keyword("auth_pass",		&vrrp_auth_pass_handler);
  install_sublevel_end();

  /* Virtual server mapping */
  install_keyword_root("virtual_server", 	&vs_handler);
  install_keyword("delay_loop", 		&delay_handler);
  install_keyword("lb_algo", 			&lbalgo_handler);
  install_keyword("lb_kind", 			&lbkind_handler);
  install_keyword("nat_mask", 			&natmask_handler);
  install_keyword("persistence_timeout", 	&pto_handler);
  install_keyword("protocol", 			&proto_handler);

  /* Real server mapping */
  install_keyword("sorry_server",		&ssvr_handler);
  install_keyword("real_server", 		&rs_handler);
  install_sublevel();
  install_keyword("weight", 			&weight_handler);

  /* Checkers mapping */
  install_checkers_keyword();
}

void init_data(char *conf_file)
{
  conf_data = NULL;
  stream = fopen((conf_file)?conf_file:CONF, "r");
  if (!stream) {
    syslog(LOG_INFO, "Configuration file open problem...\n");
    return;
  }

  /* Init data structure */
  conf_data = alloc_data();

  /* Stream handling */
  process_stream(keywords);

/* Dump configuration *

  vector_dump(keywords);
  dump_keywords(keywords, 0);
  free_keywords(keywords);
*/

  fclose(stream);
  free_keywords(keywords);
}
