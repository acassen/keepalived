/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        IPVS Kernel wrapper. Use setsockopt call to add/remove
 *              server to/from the loadbalanced server pool.
 *  
 * Version:     $Id: keepalived.c,v 0.2.1 2000/12/09 $
 * 
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *              
 * Changes:     
 *              Alexandre Cassen      :       Initial release
 *              
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#include "ipvswrapper.h"

int ipvs_pool_cmd(int cmd, virtualserver *vserver)
{
  struct ip_masq_ctl ctl;
  struct in_addr inaddr;
  char *debugmsg;
  int result=0;
  int sockfd;

  debugmsg=(char *)malloc(LOGBUFFER_LENGTH);
  memset(&ctl,0, sizeof(struct ip_masq_ctl));

  ctl.m_target = IP_MASQ_TARGET_VS;
  ctl.m_cmd = (cmd)?IP_MASQ_CMD_ADD_DEST:IP_MASQ_CMD_DEL_DEST;
  strcpy(ctl.m_tname,vserver->sched);

  ctl.u.vs_user.weight = atoi(vserver->svr->weight);
  
  if (strcmp(vserver->svr->loadbalancing_kind,"NAT")==0)
    ctl.u.vs_user.masq_flags = 0;
  else
    if (strcmp(vserver->svr->loadbalancing_kind,"DR")==0)
      ctl.u.vs_user.masq_flags = IP_MASQ_F_VS_DROUTE;
    else
      if (strcmp(vserver->svr->loadbalancing_kind,"TUN")==0)
        ctl.u.vs_user.masq_flags = IP_MASQ_F_VS_TUNNEL;
      else {
        bzero(debugmsg,LOGBUFFER_LENGTH);
        sprintf(debugmsg,"ipvs_pool_cmd : service [%s:%s] [%s] unknown routing method...\n",
                         vserver->svr->addr_ip, vserver->svr->addr_port,
                         vserver->svr->loadbalancing_kind);
        logmessage(debugmsg,getpid());
        logmessage("ipvs_pool_cmd : Check your configuration file...\n",getpid());
        free(debugmsg);
        return(IPVS_ERROR);
      }

  ctl.u.vs_user.netmask = ((u_int32_t) 0xffffffff); /* f:f:f:f for default netmask */

  ctl.u.vs_user.protocol = (strcmp(vserver->svr->service_type,"UDP")==0)?IPPROTO_UDP:IPPROTO_TCP;
  ctl.u.vs_user.timeout  = (strcmp(vserver->timeout_persistence,"NULL")==0)?0:atoi(vserver->timeout_persistence);

  ctl.u.vs_user.vfwmark  = 0;
  ctl.u.vs_user.vs_flags = (ctl.u.vs_user.timeout!=0)?IP_VS_SVC_F_PERSISTENT:0;
  
  if (inet_aton(vserver->addr_ip,&inaddr) != 0)
    ctl.u.vs_user.vaddr = inaddr.s_addr;
  if (inet_aton(vserver->svr->addr_ip,&inaddr) != 0)
    ctl.u.vs_user.daddr = inaddr.s_addr;
  ctl.u.vs_user.vport = htons(atoi(vserver->addr_port));
  ctl.u.vs_user.dport = htons(atoi(vserver->svr->addr_port));

  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sockfd == -1) {
#ifdef DEBUG
    logmessage("ipvs__pool_cmd : Can not initialize SOCK_RAW descriptor\n",getpid());
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
    logmessage(debugmsg,getpid());
#endif
    close(sockfd);
    free(debugmsg);
    return IPVS_ERROR;
  } else if (errno == ENOENT) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"ipvs_pool_cmd : No such destination %s\n",vserver->svr->addr_ip);
    logmessage(debugmsg,getpid());
#endif
    close(sockfd);
    free(debugmsg);
    return IPVS_ERROR;
  }

  close(sockfd);
  free(debugmsg);
  return IPVS_SUCCESS;
}
