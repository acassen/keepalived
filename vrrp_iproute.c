/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Routing utilities using the NETLINK kernel interface.
 *
 * Version:     $Id: vrrp_iproute.c,v 0.4.0 2001/08/24 00:35:19 acassen Exp $
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *
 * Changes:     Alexandre Cassen : 2001/08/20      Initial release
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

/* local includes */
#include "vrrp_iproute.h"
#include "libnetlink/libnetlink.h"
#include "libnetlink/ll_map.h"
#include "utils.h"

/* Allocation function */
struct rt_entry * iproute_new()
{
  struct rt_entry *entry;

  entry = (struct rt_entry *)malloc(sizeof(struct rt_entry));
  memset(entry, 0, sizeof(struct rt_entry));

  entry->rtm = (struct rtmsg *)malloc(sizeof(struct rtmsg));
  memset(entry->rtm, 0, sizeof(struct rtmsg));

  return entry;
}

/* free memory */
void iproute_del(struct rt_entry *entry)
{
  free(entry->rtm);
  free(entry);
}

/* destroy functions */
struct rt_entry * clear_entry(struct rt_entry *entry)
{
  struct rt_entry *t;

  t = (struct rt_entry *)entry->next;
  iproute_del(entry);
  return t;
}

void iproute_clear(struct rt_entry *lstentry)
{
  while (lstentry)
    lstentry = clear_entry(lstentry);
}

/* Append rt entry function */
struct rt_entry * iproute_append(struct rt_entry *lstentry, struct rt_entry *entry)
{
  struct rt_entry *ptr = lstentry;

  if (lstentry) {
    while (lstentry->next) lstentry = (struct rt_entry *)lstentry->next;
    lstentry->next = (struct rt_entry *)entry;
    return ptr;
  } else {
    lstentry = entry;
    return lstentry;
  }
}

/* Our rt netlink filter */
int iproute_filter(struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
  struct rt_entry *rtarg;
  struct rtmsg *r = NLMSG_DATA(n);
  int len = n->nlmsg_len;
  struct rtattr *tb[RTA_MAX+1];
  struct rt_entry *entry;

  rtarg = (struct rt_entry *)arg;

  /* Just lookup the Main routing table */
  if (r->rtm_table != RT_TABLE_MAIN)
    return 0;

  /* init len value  */
  len -= NLMSG_LENGTH(sizeof(*r));
  if (len <0) {
    syslog(LOG_INFO, "IPROUTE : BUG: wrong nlmsg len %d", len);
    return -1;
  }

  /* init the parse attribute space */
  memset(tb, 0, sizeof(tb));
  parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);

  /*
   * we return from filter when route is
   * cloned from another route, learn by an
   * ICMP redirect or set by kernel.
   * Return too when rt type != gateway or direct route.
   */
  if (r->rtm_flags & RTM_F_CLONED)
    return 0;
  if (r->rtm_protocol == RTPROT_REDIRECT)
    return 0;
  if (r->rtm_protocol == RTPROT_KERNEL)
    return 0;
  if (r->rtm_type != RTN_UNICAST)
    return 0;

  if (tb[RTA_OIF]) {
    /* alloc new memory entry */
    entry = iproute_new();

    /* copy the rtmsg infos */
    memcpy(entry->rtm, r, sizeof(struct rtmsg));

    /*
     * can use RTA_PAYLOAD(tb[RTA_SRC])
     * but ipv4 addr are 4 bytes coded
     */
    entry->oif = *(int *) RTA_DATA(tb[RTA_OIF]);
    if (tb[RTA_SRC]) memcpy(&entry->src, RTA_DATA(tb[RTA_SRC]), 4);
    if (tb[RTA_PREFSRC]) memcpy(&entry->psrc, RTA_DATA(tb[RTA_PREFSRC]), 4);
    if (tb[RTA_DST]) memcpy(&entry->dest, RTA_DATA(tb[RTA_DST]), 4);
    if (tb[RTA_GATEWAY]) memcpy(&entry->gate, RTA_DATA(tb[RTA_GATEWAY]), 4);
    if (tb[RTA_FLOW]) memcpy(&entry->flow, RTA_DATA(tb[RTA_FLOW]), 4);
    if (tb[RTA_IIF]) entry->iif = *(int *) RTA_DATA(tb[RTA_IIF]);
    if (tb[RTA_PRIORITY]) entry->prio = *(int *) RTA_DATA(tb[RTA_PRIORITY]);
    if (tb[RTA_METRICS]) entry->metrics = *(int *) RTA_DATA(tb[RTA_METRICS]);

    /* save this entry */
    rtarg = iproute_append(rtarg, entry);
  }

  return 0;
}

struct rt_entry * iproute_fetch(struct rt_entry *r)
{
  struct rtnl_handle rth;

  if (rtnl_open(&rth, 0) < 0) {
    syslog(LOG_INFO, "IPROUTE : Can not initialize netlink interface...");
    return NULL;
  }

  ll_init_map(&rth);

  if (rtnl_wilddump_request(&rth, AF_INET, RTM_GETROUTE) < 0) {
    syslog(LOG_INFO, "IPROUTE : Cannot send dump request.");
    close(rth.fd);
    return NULL;
  }

  if (rtnl_dump_filter(&rth, iproute_filter, r, NULL, NULL) < 0) {
    syslog(LOG_INFO, "IPROUTE : Dump terminated.");
    close(rth.fd);
    return NULL;
  }

  close(rth.fd);
  return r;
}

int iproute_restore_entry(struct rt_entry *r)
{
  struct rtnl_handle rth;

  struct {
    struct nlmsghdr n;
    struct rtmsg r;
    char buf[1024];
  } req;

  memset(&req, 0, sizeof(req));

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
  req.n.nlmsg_type = RTM_NEWROUTE;

  memcpy(&req.r, r->rtm, sizeof(struct rtmsg));

  if (r->src)
    addattr_l(&req.n, sizeof(req), RTA_SRC, &r->src, 4);
  if (r->psrc)
    addattr_l(&req.n, sizeof(req), RTA_PREFSRC, &r->psrc, 4);
  if (r->dest)
    addattr_l(&req.n, sizeof(req), RTA_DST, &r->dest, 4);
  if (r->gate)
    addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &r->gate, 4);
  if (r->flow)
    addattr_l(&req.n, sizeof(req), RTA_FLOW, &r->flow, 4);

  if (r->oif)
    addattr32(&req.n, sizeof(req), RTA_OIF, r->oif);
  if (r->iif)
    addattr32(&req.n, sizeof(req), RTA_IIF, r->iif);
  if (r->prio)
    addattr32(&req.n, sizeof(req), RTA_PRIORITY, r->prio);
  if (r->metrics)
    addattr32(&req.n, sizeof(req), RTA_METRICS, r->metrics);

  if (rtnl_open(&rth, 0) < 0) {
    syslog(LOG_INFO, "IPROUTE : Can not initialize netlink interface...");
    return -1;
  }

  if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0) {
    syslog(LOG_INFO, "IPROUTE : Can not talk with netlink interface...");
    return -1;
  }

  return 0;
}

/* rt netlink dump function */
void iproute_dump(struct rt_entry *r)
{
  while (r) {
    if (r->src) syslog(LOG_DEBUG, "src %s ", ip_ntoa(r->src));
    if (r->psrc) syslog(LOG_DEBUG, "prefsrc %s ", ip_ntoa(r->psrc));
    if (r->iif) syslog(LOG_DEBUG, "idev %s", ll_index_to_name(r->iif));

    if (r->dest) syslog(LOG_DEBUG, "dest %s ", ip_ntoa(r->dest));
    if (r->gate) syslog(LOG_DEBUG, "gateway %s ", ip_ntoa(r->gate));

    if (r->prio) syslog(LOG_DEBUG, "priority %d ", r->prio);
    if (r->metrics) syslog(LOG_DEBUG, "metrics %d ", r->metrics);

    if (r->oif) syslog(LOG_DEBUG, "odev %s ", ll_index_to_name(r->oif));

    /* rtmsg specifics */
    if (r->rtm->rtm_dst_len) syslog(LOG_DEBUG, "mask %d ", r->rtm->rtm_dst_len);
    if (r->rtm->rtm_scope == RT_SCOPE_LINK) syslog(LOG_DEBUG, "scope link");

    printf("\n");

    r = (struct rt_entry *)r->next;
  }
}

struct rt_entry *iproute_list(char *dev)
{
  struct rt_entry rt_table;

  /* Fetch the main routing table */
  memset(&rt_table, 0, sizeof(struct rt_entry));
  if (!iproute_fetch(&rt_table)) return NULL;

  return rt_table.next;
}

int iproute_restore(struct rt_entry *lstentry, char *dev)
{
  int idx = ll_name_to_index(dev);
  int ret = 0;

  while (lstentry) {
    if (lstentry->oif == idx) {
      ret = iproute_restore_entry(lstentry);
      if (ret < 0) return ret;
    }

    lstentry = (struct rt_entry *)lstentry->next;
  }

  return 0;
}
