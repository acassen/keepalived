/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Manipulation functions for IPVS & IPFW wrappers.
 *
 * Version:     $id: ipwrapper.c,v 0.5.6 2002/04/13 06:21:33 acassen Exp $
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
#include "utils.h"

extern data *conf_data;

int clear_service_vs(virtual_server *vs)
{
  element e;

  for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
    /* IPVS cleaning server entry */
    if (!ipvs_cmd(LVS_CMD_DEL_DEST, vs, e->data))
      return 0;

#ifdef _KRNL_2_2_
    /* IPFW cleaning server entry if granularity = /32 */
    if (vs->nat_mask == HOST_NETMASK)
      if (!ipfw_cmd(IP_FW_CMD_DEL, vs, e->data))
        return 0;
#endif
  }

  if (!ipvs_cmd(LVS_CMD_DEL, vs, NULL))
    return 0;
  return 1;
}

/* IPVS cleaner processing */
int clear_services(void)
{
  element e;
  list vs = conf_data->vs;
  virtual_server *vsvr;
  real_server *rsvr;

  for (e = LIST_HEAD(vs); e; ELEMENT_NEXT(e)) {
    vsvr = ELEMENT_DATA(e);
    rsvr = (real_server *)LIST_HEAD(vsvr->rs);
    if (!clear_service_vs(vsvr))
      return 0;

#ifdef _KRNL_2_2_
    if (vsvr->nat_mask != HOST_NETMASK)
      if (!ipfw_cmd(IP_FW_CMD_DEL, vsvr, rsvr))
        return 0;
#endif
  }
  return 1;
}

int all_realservers_down(virtual_server *vs)
{
  element e;
  real_server *svr;

  for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
    svr = ELEMENT_DATA(e);
    if (svr->alive) return 0;
  }
  return 1;
}

void perform_svr_state(int alive, virtual_server *vs, real_server *rs)
{
  if (!ISALIVE(rs) && alive) {

    /* adding a server to the vs pool, if sorry server is flagged alive,
     * we remove it from the vs pool.
     */
    if (vs->s_svr) {
      if (vs->s_svr->alive) {
        syslog(LOG_INFO, "Removing sorry server [%s:%d] from VS [%s:%d]"
                       , ip_ntoa(SVR_IP(vs->s_svr))
                       , ntohs(SVR_PORT(vs->s_svr))
                       , ip_ntoa(SVR_IP(vs))
                       , ntohs(SVR_PORT(vs)));

        vs->s_svr->alive = 0;
        ipvs_cmd(LVS_CMD_DEL_DEST, vs, vs->s_svr);
#ifdef _KRNL_2_2_
        ipfw_cmd(IP_FW_CMD_DEL, vs, vs->s_svr);
#endif
      }
    }

    rs->alive = alive;
    syslog(LOG_INFO, "Adding service [%s:%d] to VS [%s:%d]"
                   , ip_ntoa(SVR_IP(rs))
                   , ntohs(SVR_PORT(rs))
                   , ip_ntoa(SVR_IP(vs))
                   , ntohs(SVR_PORT(vs)));
    ipvs_cmd(LVS_CMD_ADD_DEST, vs, rs);

#ifdef _KRNL_2_2_
    if (vs->nat_mask == HOST_NETMASK)
      ipfw_cmd(IP_FW_CMD_ADD, vs, rs);
#endif

  } else {

    rs->alive = alive;
    syslog(LOG_INFO, "Removing service [%s:%d] from VS [%s:%d]"
                   , ip_ntoa(SVR_IP(rs))
                   , ntohs(SVR_PORT(rs))
                   , ip_ntoa(SVR_IP(vs))
                   , ntohs(SVR_PORT(vs)));

    /* server is down, it is removed from the LVS realserver pool */
    ipvs_cmd(LVS_CMD_DEL_DEST, vs, rs);

#ifdef _KRNL_2_2_
    if (vs->nat_mask == HOST_NETMASK)
      ipfw_cmd(IP_FW_CMD_DEL, vs, rs);
#endif

    /* if all the realserver pool is down, we add sorry server */
    if (vs->s_svr && all_realservers_down(vs)) {
      syslog(LOG_INFO, "Adding sorry server [%s:%d] to VS [%s:%d]"
                     , ip_ntoa(SVR_IP(vs->s_svr))
                     , ntohs(SVR_PORT(vs->s_svr))
                     , ip_ntoa(SVR_IP(vs))
                     , ntohs(SVR_PORT(vs)));

      /* the sorry server is now up in the pool, we flag it alive */
      vs->s_svr->alive = 1;
      ipvs_cmd(LVS_CMD_ADD_DEST, vs, vs->s_svr);

#ifdef _KRNL_2_2_
      ipfw_cmd(IP_FW_CMD_ADD, vs, vs->s_svr);
#endif
    }

  }
}

int init_service_vs(virtual_server *vs)
{
  element e;

  /* Init the IPVS root */
  if (!ipvs_cmd(LVS_CMD_ADD, vs, NULL))
    return 0;

  for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
    if (!ipvs_cmd(LVS_CMD_ADD_DEST, vs, e->data))
      return 0;

#ifdef _KRNL_2_2_
    /* if we have a /32 mask, we create one nat rules per
     * realserver.
     */
    if (vs->nat_mask == HOST_NETMASK)
      if(!ipfw_cmd(IP_FW_CMD_ADD, vs, e->data))
        return 0;
#endif
  }
  return 1;
}

int init_services(void)
{
  element e;
  list vs = conf_data->vs;
  virtual_server *vsvr;
  real_server *rsvr;

  for (e = LIST_HEAD(vs); e; ELEMENT_NEXT(e)) {
    vsvr = ELEMENT_DATA(e);
    rsvr = (real_server *)LIST_HEAD(vsvr->rs);
    if (!init_service_vs(vsvr))
      return 0;

#ifdef _KRNL_2_2_
    /* work if all realserver ip address are in the
     * same network (it is assumed).
     */
    if (vsvr->nat_mask != HOST_NETMASK)
      if (!ipfw_cmd(IP_FW_CMD_ADD, vsvr, rsvr))
        return 0;
#endif
  }
  return 1;
}
