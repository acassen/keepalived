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
 * Version:     $Id: vrrp_ipaddress.c,v 0.4.8 2001/11/20 15:26:11 acassen Exp $
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
#include "vrrp_netlink.h"

int netlink_address_ipv4(int ifindex, uint32_t addr, int cmd)
{
  struct nl_handle nlh;
  struct {
    struct nlmsghdr n;
    struct ifaddrmsg ifa;
    char buf[256];
  } req;

  memset(&req, 0, sizeof(req));

  req.n.nlmsg_len    = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.n.nlmsg_flags  = NLM_F_REQUEST;
  req.n.nlmsg_type   = cmd ? RTM_NEWADDR:RTM_DELADDR;
  req.ifa.ifa_family = AF_INET;
  req.ifa.ifa_index  = ifindex;
  req.ifa.ifa_prefixlen  = 32;
  
  addr = htonl(addr);
  addattr_l(&req.n, sizeof(req), IFA_LOCAL, &addr, sizeof(addr));

  if (netlink_socket(&nlh, 0) < 0)
    return -1;

  if (netlink_talk(&nlh, &req.n) < 0)
    return -1;
  
  /* to close the clocket */
  netlink_close(&nlh);

  return(0);
}
