/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        IPFW Kernel wrapper. Use Rusty firewall manipulation
 *              library to add/remove server MASQ rules to the kernel 
 *              firewall framework.
 *  
 * Version:     $Id: ipfwwrapper.c,v 0.2.7 2001/03/30 $
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

#include "ipfwwrapper.h"

int ipfw_cmd(int cmd, virtualserver *vserver)
{
  struct ip_fwuser ctl;
  struct in_addr inaddr;
  int ret = 1;
  char *debugmsg;

  debugmsg=(char *)malloc(LOGBUFFER_LENGTH);
  memset(&ctl,0,sizeof(struct ip_fwuser));

  /* Create the firewall MASQ rule */
  strcpy(ctl.label,IP_FW_LABEL_MASQUERADE);
  ctl.ipfw.fw_proto = (strcmp(vserver->service_type,"UDP")==0)?IPPROTO_UDP:IPPROTO_TCP;
  inet_aton(vserver->svr->addr_ip,&ctl.ipfw.fw_src); 
  inet_aton(IPFW_SRC_NETMASK,&ctl.ipfw.fw_smsk);
  ctl.ipfw.fw_spts[0] = ctl.ipfw.fw_spts[1] = atoi(vserver->svr->addr_port);
  ctl.ipfw.fw_dpts[0] = 0x0000;
  ctl.ipfw.fw_dpts[1] = 0xFFFF;
  ctl.ipfw.fw_tosand = 0xFF;
  ctl.ipfw.fw_tosxor = 0x00;

  if (cmd&IP_FW_CMD_ADD) {
    ipfwc_delete_entry(IP_FW_LABEL_FORWARD,&ctl);
    if (!(errno&EINVAL)) {
#ifdef DEBUG
      memset(debugmsg,0,LOGBUFFER_LENGTH);
      sprintf(debugmsg,"ipfw_cmd : MASQ firewall rule [%s:%s] already exist.\n",
                       vserver->svr->addr_ip,vserver->svr->addr_port);
      logmessage(debugmsg);
#endif
    }
    ret &= ipfwc_insert_entry(IP_FW_LABEL_FORWARD,&ctl,1);
  }

  if (cmd&IP_FW_CMD_DEL) {
    ret &= ipfwc_delete_entry(IP_FW_LABEL_FORWARD,&ctl);
    if (errno&EINVAL) {
#ifdef DEBUG
      memset(debugmsg,0,LOGBUFFER_LENGTH);
      sprintf(debugmsg,"ipfw_cmd : Can not delete MASQ firewall rule [%s:%s].\n",
                     vserver->svr->addr_ip,vserver->svr->addr_port);
      logmessage(debugmsg);
#endif
    }
  }

  if(!ret) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"ipfw_cmd : firewall error (%s) processing [%s:%s] MASQ rule.\n",
                     strerror(errno),vserver->svr->addr_ip,vserver->svr->addr_port);
    logmessage(debugmsg);
#endif
    free(debugmsg);
    return IPFW_ERROR;
  }

  free(debugmsg);
  return IPFW_SUCCESS;
}

