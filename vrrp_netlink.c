/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK kernel command channel.
 *
 * Version:     $Id: vrrp_netlink.c,v 0.4.8 2001/11/20 15:26:11 acassen Exp $
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/uio.h>

#include "vrrp_netlink.h"

/* Create a socket to netlink interface */
int netlink_socket(struct nl_handle *nl, unsigned long groups)
{
  int addr_len;
  int ret;

  memset(nl, 0, sizeof(nl));

  nl->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (nl->fd < 0) {
    syslog(LOG_INFO, "Netlink: Cannot open netlink socket : (%s)"
                   , strerror(errno));
    return -1;
  }

  ret = fcntl(nl->fd, F_SETFL, O_NONBLOCK);
  if (ret < 0) {
    syslog(LOG_INFO, "Netlink: Cannot set netlink socket flags : (%s)"
                   , strerror(errno));
    close(nl->fd);
    return -1;
  }

  memset(&nl->snl, 0, sizeof(nl->snl));
  nl->snl.nl_family = AF_NETLINK;
  nl->snl.nl_groups = groups;

  ret = bind(nl->fd, (struct sockaddr*)&nl->snl, sizeof(nl->snl));
  if (ret < 0) {
    syslog(LOG_INFO, "Netlink: Cannot bind netlink socket : (%s)"
                   , strerror(errno));
    close(nl->fd);
    return -1;
  }

  addr_len = sizeof(nl->snl);
  ret = getsockname(nl->fd, (struct sockaddr *)&nl->snl, &addr_len);
  if (ret < 0 || addr_len != sizeof(nl->snl)) {
    syslog(LOG_INFO, "Netlink: Cannot getsockname : (%s)"
                   , strerror(errno));
    close(nl->fd);
    return -1;
  }

  if (nl->snl.nl_family != AF_NETLINK) {
    syslog(LOG_INFO, "Netlink: Wrong address family %d", nl->snl.nl_family);
    close(nl->fd);
    return -1;
  }

  nl->seq = time(NULL);

  return ret;
}

/* Close a netlink socket */
int netlink_close(struct nl_handle *nl)
{
  close(nl->fd);
  return 0;
}

/* iproute2 utility function */
int addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data, int alen)
{
  int len = RTA_LENGTH(alen);
  struct rtattr *rta;

  if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen)
    return -1;

  rta = (struct rtattr*)(((char*)n) + NLMSG_ALIGN(n->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = len;
  memcpy(RTA_DATA(rta), data, alen);
  n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;

  return 0;
}

/* Our netlink parser */
static int netlink_parse_info(int (*filter) (struct sockaddr_nl *, struct nlmsghdr *),
                              struct nl_handle *nl)
{
  int status;
  int ret = 0;
  int error;

  while (1) {
    char buf[4096];
    struct iovec iov = { buf, sizeof buf };
    struct sockaddr_nl snl;
    struct msghdr msg = {(void*)&snl, sizeof snl, &iov, 1, NULL, 0, 0};
    struct nlmsghdr *h;

    status = recvmsg (nl->fd, &msg, 0);

    if (status < 0) {
      if (errno == EINTR)
        continue;
      if (errno == EWOULDBLOCK)
        break;
      syslog(LOG_INFO, "Netlink: Received message overrun");
      continue;
    }

    if (status == 0) {
      syslog(LOG_INFO, "Netlink: EOF");
      return -1;
    }

    if (msg.msg_namelen != sizeof snl) {
      syslog(LOG_INFO, "Netlink: Sender address length error: length %d"
                     , msg.msg_namelen);
      return -1;
    }

    for (h = (struct nlmsghdr *) buf; NLMSG_OK (h, status);
         h = NLMSG_NEXT (h, status)) {
      /* Finish of reading. */
      if (h->nlmsg_type == NLMSG_DONE)
        return ret;

      /* Error handling. */
      if (h->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA (h);
        if (h->nlmsg_len < NLMSG_LENGTH (sizeof (struct nlmsgerr))) {
          syslog(LOG_INFO, "Netlink: error: message truncated");
          return -1;
        }
        syslog (LOG_INFO, "Netlink: error: %s, type=(%u), seq=%u, pid=%d"
                        , strerror (-err->error)
                        , err->msg.nlmsg_type, err->msg.nlmsg_seq
                        , err->msg.nlmsg_pid);

        return -1;
      }

      error = (*filter) (&snl, h);
      if (error < 0) {
        syslog(LOG_INFO, "Netlink: filter function error");
        ret = error;
      }
    }

    /* After error care. */
    if (msg.msg_flags & MSG_TRUNC) {
      syslog(LOG_INFO, "Netlink: error: message truncated");
      continue;
    }
    if (status) {
      syslog(LOG_INFO, "Netlink: error: data remnant size %d", status);
      return -1;
    }
  }

  return ret;
}

/* Out talk filter */
static int netlink_talk_filter(struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  syslog(LOG_INFO, "Netlink: ignoring message type 0x%04x"
                 , h->nlmsg_type);
  return 0;
}

/* send message to netlink kernel socket, then receive response */
int netlink_talk(struct nl_handle *nl, struct nlmsghdr *n)
{
  int status;
  struct sockaddr_nl snl;
  struct iovec iov = { (void*) n, n->nlmsg_len };
  struct msghdr msg = {(void*) &snl, sizeof snl, &iov, 1, NULL, 0, 0};

  memset(&snl, 0, sizeof snl);
  snl.nl_family = AF_NETLINK;

  n->nlmsg_seq = ++nl->seq;

  /* Send message to netlink interface. */
  status = sendmsg(nl->fd, &msg, 0);
  if (status < 0) {
    syslog(LOG_INFO, "Netlink: sendmsg() error: %s"
                   , strerror (errno));
    return -1;
  }

  status = netlink_parse_info(netlink_talk_filter, nl);
  return status;
}
