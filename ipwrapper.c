/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Manipulation functions for IPVS & IPFW wrappers.
 *
 * Version:     $Id: ipwrapper.c,v 0.3.7 2001/09/14 00:37:56 acassen Exp $
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

#include "ipwrapper.h"

int clear_service_vs(virtualserver *vserver)
{
  realserver *pointersvr;

  pointersvr = vserver->svr;
  while (vserver->svr) {
    /* IPVS cleaning server entry */
    if (!ipvs_cmd(LVS_CMD_DEL_DEST, vserver, vserver->svr)) {
      vserver->svr = pointersvr;
      return 0;
    }

    /* IPFW cleaning server entry if granularity = /32 */
    if (vserver->nat_mask.s_addr == HOST_NETMASK)
      if (!ipfw_cmd(IP_FW_CMD_DEL, vserver, vserver->svr))
        return 0;

    vserver->svr = (realserver *)vserver->svr->next;
  }
  vserver->svr = pointersvr;

  if (!ipvs_cmd(LVS_CMD_DEL, vserver, vserver->svr))
    return 0;

  return 1;
}

int clear_services(virtualserver *vserver)
{
  while (vserver) {
    /* IPVS cleaner processing */
    if (!clear_service_vs(vserver))
      return 0;

    /* IPFW cleaner processing */
    if (vserver->nat_mask.s_addr != HOST_NETMASK) {
      if (!ipfw_cmd(IP_FW_CMD_DEL, vserver, vserver->svr))
        return 0;
    }

    vserver = (virtualserver *)vserver->next;
  }
  return 1;
}

int all_realservers_down(virtualserver *vserver)
{
  realserver *pointersvr;

  pointersvr = vserver->svr;
  while (vserver->svr) {
    if (vserver->svr->alive) return 0;

    vserver->svr = (realserver *)vserver->svr->next;
  }
  vserver->svr = pointersvr;
  return 1;
}

void perform_svr_state(int alive, virtualserver *vserver, realserver *rserver)
{
  if (!rserver->alive && alive) {

    /* adding a server to the vs pool, if sorry server is flagged alive,
     * we remove it from the vs pool.
     */
    if (vserver->s_svr) {
      if (vserver->s_svr->alive) {
        syslog(LOG_INFO, "Removing sorry server [%s:%d] from VS [%s:%d]",
               inet_ntoa(vserver->s_svr->addr_ip), ntohs(vserver->s_svr->addr_port),
               inet_ntoa(vserver->addr_ip), ntohs(vserver->addr_port));

        vserver->s_svr->alive = 0;
        ipvs_cmd(LVS_CMD_DEL_DEST, vserver, vserver->s_svr);
        ipfw_cmd(IP_FW_CMD_DEL, vserver, vserver->s_svr);
      }
    }

    rserver->alive = alive;
    syslog(LOG_INFO, "Adding service [%s:%d] to VS [%s:%d]",
           inet_ntoa(rserver->addr_ip), ntohs(rserver->addr_port),
           inet_ntoa(vserver->addr_ip), ntohs(vserver->addr_port));
    ipvs_cmd(LVS_CMD_ADD_DEST, vserver, rserver);
    if (vserver->nat_mask.s_addr == HOST_NETMASK)
      ipfw_cmd(IP_FW_CMD_ADD, vserver, rserver);

  } else {

    rserver->alive = alive;
    syslog(LOG_INFO, "Removing service [%s:%d] from VS [%s:%d]",
           inet_ntoa(rserver->addr_ip), ntohs(rserver->addr_port),
           inet_ntoa(vserver->addr_ip), ntohs(vserver->addr_port));

    /* server is down, it is removed from the LVS realserver pool */
    ipvs_cmd(LVS_CMD_DEL_DEST, vserver, rserver);
    if (vserver->nat_mask.s_addr == HOST_NETMASK)
      ipfw_cmd(IP_FW_CMD_DEL, vserver, rserver);

    /* if all the realserver pool is down, we add sorry server */
    if (vserver->s_svr && all_realservers_down(vserver)) {
      syslog(LOG_INFO, "Adding sorry server [%s:%d] to VS [%s:%d]",
             inet_ntoa(vserver->s_svr->addr_ip), ntohs(vserver->s_svr->addr_port),
             inet_ntoa(vserver->addr_ip), ntohs(vserver->addr_port));

      /* the sorry server is now up in the pool, we flag it alive */
      vserver->s_svr->alive = 1;
      ipvs_cmd(LVS_CMD_ADD_DEST, vserver, vserver->s_svr);
      ipfw_cmd(IP_FW_CMD_ADD, vserver, vserver->s_svr);
    }

  }
}

int init_service_vs(virtualserver *vserver)
{
  realserver *pointersvr;

  pointersvr = vserver->svr;
  while (vserver->svr) {
    if (!ipvs_cmd(LVS_CMD_ADD_DEST, vserver, vserver->svr)) {
      vserver->svr = pointersvr;
      return 0;
    }

    /* if we have a /32 mask, we create one nat rules per
     * realserver.
     */
    if (vserver->nat_mask.s_addr == HOST_NETMASK)
      if(!ipfw_cmd(IP_FW_CMD_ADD, vserver, vserver->svr)) {
        vserver->svr = pointersvr;
        return 0;
      }
    vserver->svr = (realserver *)vserver->svr->next;
  }
  vserver->svr = pointersvr;

  return 1;
}

int init_services(virtualserver *vserver)
{
  virtualserver *pointervs;

  pointervs = vserver;
  while (vserver) {
    if (!ipvs_cmd(LVS_CMD_ADD, vserver, vserver->svr))
      return 0;

    /* work if all realserver ip address are in the
     * same network (it is assumed).
     */
    if (vserver->nat_mask.s_addr != HOST_NETMASK)
      if (!ipfw_cmd(IP_FW_CMD_ADD, vserver, vserver->svr))
        return 0;

    if (!init_service_vs(vserver))
      return 0;

    vserver = (virtualserver *)vserver->next;
  }
  vserver = pointervs;

  return 1;
}
