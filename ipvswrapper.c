/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        IPVS Kernel wrapper. Use setsockopt call to add/remove
 *              server to/from the loadbalanced server pool.
 *  
 * Version:     $Id: ipvswrapper.c,v 0.2.7 2001/03/27 $
 * 
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *              
 * Changes:     
 *              Alexandre Cassen : 2001/03/27 :
 *               <+> Added setsockopt return value.
 *               <+> Added support to the IP_MASQ_CMD ruleset.
 *                   IP_MASQ_CMD_ADD : Adding a virtual service.
 *                   IP_MASQ_CMD_DEL : Deleting a virtual service.
 *                   IP_MASQ_CMD_ADD_DEST : Adding a real service.
 *                   IP_MASQ_CMD_DEL_DEST : Deleting a real service.
 *
 *              Alexandre Cassen      :       Initial release
 *              
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#include "ipvswrapper.h"

int ipvs_cmd(int cmd, virtualserver *vserver)
{
  struct ip_masq_ctl ctl;
  struct in_addr inaddr;
  char *debugmsg;
  int result=0;
  int sockfd;

  debugmsg=(char *)malloc(LOGBUFFER_LENGTH);
  memset(&ctl,0, sizeof(struct ip_masq_ctl));

  ctl.m_target = IP_MASQ_TARGET_VS;
  ctl.m_cmd = cmd;
  strcpy(ctl.m_tname,vserver->sched);
  ctl.u.vs_user.weight = -1;
  
  if (strcmp(vserver->loadbalancing_kind,"NAT")==0)
    ctl.u.vs_user.masq_flags = 0;
  else
    if (strcmp(vserver->loadbalancing_kind,"DR")==0)
      ctl.u.vs_user.masq_flags = IP_MASQ_F_VS_DROUTE;
    else
      if (strcmp(vserver->loadbalancing_kind,"TUN")==0)
        ctl.u.vs_user.masq_flags = IP_MASQ_F_VS_TUNNEL;
      else {
        memset(debugmsg,0,LOGBUFFER_LENGTH);
        sprintf(debugmsg,"ipvs_pool_cmd : service [%s:%s] [%s] unknown routing method...\n",
                         vserver->svr->addr_ip, vserver->svr->addr_port,
                         vserver->loadbalancing_kind);
        logmessage(debugmsg);
        logmessage("ipvs_pool_cmd : Check your configuration file...\n");
        free(debugmsg);
        return(IPVS_ERROR);
      }

  ctl.u.vs_user.netmask = ((u_int32_t) 0xffffffff); /* f:f:f:f for default netmask */

  ctl.u.vs_user.protocol = (strcmp(vserver->service_type,"UDP")==0)?IPPROTO_UDP:IPPROTO_TCP;

  if(!parse_timeout(vserver->timeout_persistence,&ctl.u.vs_user.timeout)) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"ipvs_pool_cmd : Virtual service [%s:%s] illegal timeout.\n",
                     vserver->addr_ip, vserver->addr_port);
    logmessage(debugmsg);
#endif
  }
  ctl.u.vs_user.vs_flags = (ctl.u.vs_user.timeout!=0)?IP_VS_SVC_F_PERSISTENT:0;

  ctl.u.vs_user.vfwmark  = 0;
  
  /* VS specific */
  if (inet_aton(vserver->addr_ip,&inaddr) != 0)
    ctl.u.vs_user.vaddr = inaddr.s_addr;
  ctl.u.vs_user.vport = htons(atoi(vserver->addr_port));

  /* SVR specific */
  if (ctl.m_cmd == IP_MASQ_CMD_ADD_DEST || ctl.m_cmd == IP_MASQ_CMD_DEL_DEST) {
    ctl.u.vs_user.weight = atoi(vserver->svr->weight);
    if (inet_aton(vserver->svr->addr_ip,&inaddr) != 0)
      ctl.u.vs_user.daddr = inaddr.s_addr;
    ctl.u.vs_user.dport = htons(atoi(vserver->svr->addr_port));
  }

  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sockfd == -1) {
#ifdef DEBUG
    logmessage("ipvs_pool_cmd : Can not initialize SOCK_RAW descriptor\n");
#endif
    free(debugmsg);
    return IPVS_ERROR;
  }

  result = setsockopt(sockfd, IPPROTO_IP, IP_FW_MASQ_CTL, (char *)&ctl, sizeof(ctl));

  if (errno == ESRCH) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"ipvs_pool_cmd : Virtual service [%s:%s] not defined.\n",
                     vserver->addr_ip, vserver->addr_port);
    logmessage(debugmsg);
#endif
    close(sockfd);
    free(debugmsg);
    return IPVSNOTDEFINED;
  } else if (errno == EEXIST) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"ipvs_pool_cmd : Destination already exists [%s:%s]\n",vserver->svr->addr_ip,vserver->svr->addr_port);
    logmessage(debugmsg);
#endif
    close(sockfd);
    free(debugmsg);
    return IPVSSVREXIST;
  } else if (errno == ENOENT) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"ipvs_pool_cmd : No such destination [%s:%s]\n",vserver->svr->addr_ip,vserver->svr->addr_port);
    logmessage(debugmsg);
#endif
    close(sockfd);
    free(debugmsg);
    return IPVSNODEST;
  }

  close(sockfd);
  free(debugmsg);
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

