/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        IPVS Kernel wrapper. Use setsockopt call to add/remove
 *              server to/from the loadbalanced server pool.
 *  
 * Version:     $Id: ipvswrapper.c,v 0.3.6 2001/08/23 23:02:51 acassen Exp $
 * 
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *              
 * Changes:     
 *              Alexandre Cassen : 2001/03/27 :
 *                <+> Added setsockopt return value.
 *                <+> Added support to the IP_MASQ_CMD ruleset.
 *                    IP_MASQ_CMD_ADD : Adding a virtual service.
 *                    IP_MASQ_CMD_DEL : Deleting a virtual service.
 *                    IP_MASQ_CMD_ADD_DEST : Adding a real service.
 *                    IP_MASQ_CMD_DEL_DEST : Deleting a real service.
 *               Alexandre Cassen      :       Initial release
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
#ifdef DEBUG
    syslog(LOG_DEBUG, "IPVS WRAPPER : Virtual service [%s:%d] illegal timeout.",
                      inet_ntoa(vserver->addr_ip), ntohs(vserver->addr_port));
#endif
  }
  ctl.u.vs_user.vs_flags = (ctl.u.vs_user.timeout!=0)?IP_VS_SVC_F_PERSISTENT:0;
  ctl.u.vs_user.vfwmark  = 0;
  
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
#ifdef DEBUG
    syslog(LOG_DEBUG, "IPVS WRAPPER : Can not initialize SOCK_RAW descriptor.");
#endif
    return IPVS_ERROR;
  }

  result = setsockopt(sockfd, IPPROTO_IP, IP_FW_MASQ_CTL, (char *)&ctl, sizeof(ctl));

  if (errno == ESRCH) {
#ifdef DEBUG
    syslog(LOG_DEBUG, "IPVS WRAPPER : Virtual service [%s:%d] not defined.",
                      inet_ntoa(vserver->addr_ip), ntohs(vserver->addr_port));
#endif
    close(sockfd);
    return IPVSNOTDEFINED;
  } else if (errno == EEXIST) {
#ifdef DEBUG
    syslog(LOG_DEBUG, "IPVS WRAPPER : Destination already exists [%s:%d].",
                      inet_ntoa(rserver->addr_ip), ntohs(rserver->addr_port));
#endif
    close(sockfd);
    return IPVSSVREXIST;
  } else if (errno == ENOENT) {
#ifdef DEBUG
    syslog(LOG_DEBUG, "IPVS WRAPPER : No such destination [%s:%d].",
                      inet_ntoa(rserver->addr_ip), ntohs(rserver->addr_port));
#endif
    close(sockfd);
    return IPVSNODEST;
  }

  close(sockfd);
  return IPVS_SUCCESS;
}

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
