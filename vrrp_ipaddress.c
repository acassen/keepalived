/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        VRRP implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Version:     $Id: vrrp_ipaddress.c,v 0.4.1 2001/09/14 00:37:56 acassen Exp $
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

/* local include */
#include "vrrp_ipaddress.h"
#include "libnetlink/libnetlink.h"

static int get_addrinfo(struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
  struct ifaddrmsg *ifa = NLMSG_DATA(n);
  int len = n->nlmsg_len;
  iplist_ctx *ctx = (iplist_ctx *)arg;
  struct rtattr *rta_tb[IFA_MAX+1];

  /* sanity check */
  len -= NLMSG_LENGTH(sizeof(*ifa));
  if (len < 0) {
    syslog(LOG_INFO, "IPADDRESS : BUG: wrong nlmsg len %d", len);
    return -1;
  }

  /* check the message type */
  if (n->nlmsg_type != RTM_NEWADDR)
    return 0;
  /* check it is ipv4 */
  if( ifa->ifa_family != AF_INET)
    return 0;

  /* check it is the good interface */
  if(ifa->ifa_index != ctx->ifindex)
    return 0;
    
  /* parse the attribute */
  memset(rta_tb, 0, sizeof(rta_tb));
  parse_rtattr(rta_tb, IFA_MAX, IFA_RTA(ifa), len);

  if (!rta_tb[IFA_LOCAL])
    rta_tb[IFA_LOCAL] = rta_tb[IFA_ADDRESS];

  if (rta_tb[IFA_LOCAL]) {
    u_char *src = RTA_DATA(rta_tb[IFA_LOCAL]);
    if( ctx->nb_elem >= ctx->max_elem )
      return 0;
    ctx->addr[ctx->nb_elem++] = (src[0]<<24) + (src[1]<<16) +
            (src[2]<<8) + src[3];
  }
  return 0;
}

int ipaddr_list( int ifindex, uint32_t *array, int max_elem )
{
  struct rtnl_handle  rth;
  iplist_ctx  ctx;

  /* init the struct */
  ctx.ifindex  = ifindex;
  ctx.addr  = array;
  ctx.max_elem  = max_elem;
  ctx.nb_elem  = 0;

  /* open the rtnetlink socket */
  if( rtnl_open( &rth, 0) )
    return -1;

  /* send the request */
  if (rtnl_wilddump_request(&rth, AF_INET, RTM_GETADDR) < 0) {
    syslog(LOG_INFO, "IPADDRESS : Cannot send dump request");
    return -1;
  }

  /* parse the answer */
  if (rtnl_dump_filter(&rth, get_addrinfo, &ctx, NULL, NULL) < 0) {
    syslog(LOG_INFO, "IPADDRESS : Flush terminated");
    exit(1);
  }
  
  /* to close the clocket */
   rtnl_close(&rth);
  
  return ctx.nb_elem;
}

int ipaddr_op(int ifindex, uint32_t addr, int addF)
{
  struct rtnl_handle  rth;
  struct {
    struct nlmsghdr   n;
    struct ifaddrmsg   ifa;
    char         buf[256];
  } req;

  memset(&req, 0, sizeof(req));

  req.n.nlmsg_len    = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.n.nlmsg_flags  = NLM_F_REQUEST;
  req.n.nlmsg_type   = addF ? RTM_NEWADDR : RTM_DELADDR;
  req.ifa.ifa_family = AF_INET;
  req.ifa.ifa_index  = ifindex;
  req.ifa.ifa_prefixlen  = 32;
  
  addr = htonl(addr);
  addattr_l(&req.n, sizeof(req), IFA_LOCAL, &addr, sizeof(addr));

  if (rtnl_open(&rth, 0) < 0)
    return -1;
  if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
    return -1;
  
  /* to close the clocket */
   rtnl_close( &rth );

  return(0);
}

