/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        IPVS Kernel wrapper. Use setsockopt call to add/remove
 *              server to/from the loadbalanced server pool.
 *  
 * Version:     $Id: ipvswrapper.c,v 0.4.8 2001/11/20 15:26:11 acassen Exp $
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

#ifdef KERNEL_2_2  /* KERNEL 2.2 LVS handling */

int ipvs_cmd(int cmd, virtualserver *vserver, realserver *rserver)
{
  struct ip_masq_ctl ctl;
  int result=0;
  int sockfd;

  memset(&ctl, 0, sizeof(struct ip_masq_ctl));

  ctl.m_target = IP_MASQ_TARGET_VS;
  ctl.m_cmd = cmd;
  strncpy(ctl.m_tname, vserver->sched, IP_MASQ_TNAME_MAX);
  ctl.u.vs_user.weight = -1;
  ctl.u.vs_user.masq_flags = vserver->loadbalancing_kind;
  ctl.u.vs_user.netmask = ((u_int32_t) 0xffffffff); /* f:f:f:f for default netmask */
  ctl.u.vs_user.protocol = vserver->service_type;

  if(!parse_timeout(vserver->timeout_persistence, &ctl.u.vs_user.timeout)) {
    syslog(LOG_INFO, "IPVS WRAPPER : Virtual service [%s:%d] illegal timeout.",
                      inet_ntoa(vserver->addr_ip), ntohs(vserver->addr_port));
  }
  ctl.u.vs_user.vs_flags = (ctl.u.vs_user.timeout!=0)?IP_VS_SVC_F_PERSISTENT:0;
  
  /* VS specific */
  ctl.u.vs_user.vaddr = vserver->addr_ip.s_addr;
  ctl.u.vs_user.vport = vserver->addr_port;

  /* SVR specific */
  if (ctl.m_cmd == IP_MASQ_CMD_ADD_DEST || ctl.m_cmd == IP_MASQ_CMD_DEL_DEST) {
    ctl.u.vs_user.weight = rserver->weight;
    ctl.u.vs_user.daddr = rserver->addr_ip.s_addr;
    ctl.u.vs_user.dport = rserver->addr_port;
  }

  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sockfd == -1) {
    syslog(LOG_INFO, "IPVS WRAPPER : Can not initialize SOCK_RAW descriptor.");
    return IPVS_ERROR;
  }

  result = setsockopt(sockfd, IPPROTO_IP, IP_FW_MASQ_CTL, (char *)&ctl, sizeof(ctl));

  if (errno == ESRCH) {
    syslog(LOG_INFO, "IPVS WRAPPER : Virtual service [%s:%d] not defined.",
                      inet_ntoa(vserver->addr_ip), ntohs(vserver->addr_port));
    close(sockfd);
    return IPVS_ERROR;
  } else if (errno == EEXIST) {
    syslog(LOG_INFO, "IPVS WRAPPER : Destination already exists [%s:%d].",
                      inet_ntoa(rserver->addr_ip), ntohs(rserver->addr_port));
  } else if (errno == ENOENT) {
    syslog(LOG_INFO, "IPVS WRAPPER : No such destination [%s:%d].",
                      inet_ntoa(rserver->addr_ip), ntohs(rserver->addr_port));
  }

  close(sockfd);
  return IPVS_SUCCESS;
}

#else /* KERNEL 2.4 LVS handling */

int ipvs_cmd(int cmd, virtualserver *vserver, realserver *rserver)
{
  struct ip_vs_rule_user urule;
  int result=0;
  int sockfd;

  memset(&urule, 0, sizeof(struct ip_vs_rule_user));

  strncpy(urule.sched_name, vserver->sched, IP_VS_SCHEDNAME_MAXLEN);
  urule.weight = 1;
  urule.conn_flags = vserver->loadbalancing_kind;
  urule.netmask    = ((u_int32_t) 0xffffffff);
  urule.protocol   = vserver->service_type;
  
  if (!parse_timeout(vserver->timeout_persistence, &urule.timeout)) {
    syslog(LOG_INFO, "IPVS WRAPPER : Virtual service [%s:%d] illegal timeout.",
                      inet_ntoa(vserver->addr_ip), ntohs(vserver->addr_port));
  }
  urule.vs_flags = (urule.timeout != 0)?IP_VS_SVC_F_PERSISTENT:0;

  /* VS specific */
  urule.vaddr = vserver->addr_ip.s_addr;
  urule.vport = vserver->addr_port;

  /* SVR specific */
  if (cmd == IP_VS_SO_SET_ADDDEST || cmd == IP_VS_SO_SET_DELDEST) {
    urule.weight = rserver->weight;
    urule.daddr  = rserver->addr_ip.s_addr;
    urule.dport  = rserver->addr_port;
  }

  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sockfd == -1) {
    syslog(LOG_INFO, "IPVS WRAPPER : Can not initialize SOCK_RAW descriptor.");
    return IPVS_ERROR;
  } 
  
  result = setsockopt(sockfd, IPPROTO_IP, cmd, (char *)&urule, sizeof(urule));

  /* kernel return error handling */

  if (result) {
    syslog(LOG_INFO, "IPVS WRAPPER : setsockopt failed !!!");

    switch (cmd) {
      case IP_VS_SO_SET_ADD:
        if (errno == EEXIST)
          syslog(LOG_INFO, "IPVS WRAPPER : Destination already exists [%s:%d].",
                           inet_ntoa(vserver->addr_ip), ntohs(vserver->addr_port));
        else if (errno == ENOENT) {
          syslog(LOG_INFO, "IPVS WRAPPER : Scheduler not found: ip_vs_%s.o !!!",
                           urule.sched_name);
          close(sockfd);
          return IPVS_ERROR;
        }
        break;

      case IP_VS_SO_SET_DEL:
        if (errno == ESRCH)
          syslog(LOG_INFO, "IPVS WRAPPER : No such service [%s:%d].",
                           inet_ntoa(vserver->addr_ip), ntohs(vserver->addr_port));
        close(sockfd);
        return IPVS_ERROR;
        break;

      case IP_VS_SO_SET_ADDDEST:
        if (errno == ESRCH)
          syslog(LOG_INFO, "IPVS WRAPPER : Service not defined [%s:%d].",
                           inet_ntoa(rserver->addr_ip), ntohs(rserver->addr_port));
        else if (errno == EEXIST)
          syslog(LOG_INFO, "IPVS WRAPPER : Destination already exists [%s:%d].",
                           inet_ntoa(rserver->addr_ip), ntohs(rserver->addr_port));
        break;

      case IP_VS_SO_SET_DELDEST:
        if (errno == ESRCH)
          syslog(LOG_INFO, "IPVS WRAPPER : Service not defined [%s:%d].",
                           inet_ntoa(rserver->addr_ip), ntohs(rserver->addr_port));
        else if (errno == ENOENT)
          syslog(LOG_INFO, "IPVS WRAPPER : No such destination [%s:%d].",
                           inet_ntoa(rserver->addr_ip), ntohs(rserver->addr_port));
        break;
    }
  }

  close(sockfd);
  return IPVS_SUCCESS;
}

#endif

/*
 * Source code from the ipvsadm.c Wensong code
 */

int parse_timeout(char *buf, unsigned *timeout)
{
  int i;

  if (buf == NULL) {
    *timeout = IP_VS_TEMPLATE_TIMEOUT;
    return 1;
  }

  if ((i=string_to_number(buf, 1, 86400*31)) == -1)
    return 0;

  *timeout = i * HZ;
  return 1;
}

int string_to_number(const char *s, int min, int max)
{
  int number;
  char *end;

  number = (int)strtol(s, &end, 10);
  if (*end == '\0' && end != s) {
    /*
     * We parsed a number, let's see if we want this.
     * If max <= min then ignore ranges
     */
    if (max <= min || ( min <= number && number <= max))
      return number;
    else
      return -1;
  } else
    return -1;
}
