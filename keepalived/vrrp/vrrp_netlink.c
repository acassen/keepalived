/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK kernel command channel.
 *
 * Version:     $Id: vrrp_netlink.c,v 0.6.9 2002/07/31 01:33:12 acassen Exp $
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

/* global include */
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

/* local include */
#include "check_api.h"
#include "vrrp_netlink.h"
#include "vrrp_if.h"
#include "memory.h"
#include "scheduler.h"
#include "utils.h"

/* Global vars */
extern thread_master *master;

/* Create a socket to netlink interface */
int
netlink_socket(struct nl_handle *nl, unsigned long groups)
{
	int addr_len;
	int ret;

	memset(nl, 0, sizeof (nl));

	nl->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nl->fd < 0) {
		syslog(LOG_INFO, "Netlink: Cannot open netlink socket : (%s)",
		       strerror(errno));
		return -1;
	}

	ret = fcntl(nl->fd, F_SETFL, O_NONBLOCK);
	if (ret < 0) {
		syslog(LOG_INFO,
		       "Netlink: Cannot set netlink socket flags : (%s)",
		       strerror(errno));
		close(nl->fd);
		return -1;
	}

	memset(&nl->snl, 0, sizeof (nl->snl));
	nl->snl.nl_family = AF_NETLINK;
	nl->snl.nl_groups = groups;

	ret = bind(nl->fd, (struct sockaddr *) &nl->snl, sizeof (nl->snl));
	if (ret < 0) {
		syslog(LOG_INFO, "Netlink: Cannot bind netlink socket : (%s)",
		       strerror(errno));
		close(nl->fd);
		return -1;
	}

	addr_len = sizeof (nl->snl);
	ret = getsockname(nl->fd, (struct sockaddr *) &nl->snl, &addr_len);
	if (ret < 0 || addr_len != sizeof (nl->snl)) {
		syslog(LOG_INFO, "Netlink: Cannot getsockname : (%s)",
		       strerror(errno));
		close(nl->fd);
		return -1;
	}

	if (nl->snl.nl_family != AF_NETLINK) {
		syslog(LOG_INFO, "Netlink: Wrong address family %d",
		       nl->snl.nl_family);
		close(nl->fd);
		return -1;
	}

	nl->seq = time(NULL);

	return ret;
}

/* Close a netlink socket */
int
netlink_close(struct nl_handle *nl)
{
	close(nl->fd);
	return 0;
}

/* iproute2 utility function */
int
addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen)
		return -1;

	rta = (struct rtattr *) (((char *) n) + NLMSG_ALIGN(n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;

	return 0;
}

static void
parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta, int len)
{
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta, len);
	}
}

/* Our netlink parser */
static int
netlink_parse_info(int (*filter) (struct sockaddr_nl *, struct nlmsghdr *),
		   struct nl_handle *nl)
{
	int status;
	int ret = 0;
	int error;

	while (1) {
		char buf[4096];
		struct iovec iov = { buf, sizeof buf };
		struct sockaddr_nl snl;
		struct msghdr msg =
		    { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };
		struct nlmsghdr *h;

		status = recvmsg(nl->fd, &msg, 0);

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
			syslog(LOG_INFO,
			       "Netlink: Sender address length error: length %d",
			       msg.msg_namelen);
			return -1;
		}

		for (h = (struct nlmsghdr *) buf; NLMSG_OK(h, status);
		     h = NLMSG_NEXT(h, status)) {
			/* Finish of reading. */
			if (h->nlmsg_type == NLMSG_DONE)
				return ret;

			/* Error handling. */
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err =
				    (struct nlmsgerr *) NLMSG_DATA(h);
				if (h->nlmsg_len <
				    NLMSG_LENGTH(sizeof (struct nlmsgerr))) {
					syslog(LOG_INFO,
					       "Netlink: error: message truncated");
					return -1;
				}
				syslog(LOG_INFO,
				       "Netlink: error: %s, type=(%u), seq=%u, pid=%d",
				       strerror(-err->error),
				       err->msg.nlmsg_type,
				       err->msg.nlmsg_seq, err->msg.nlmsg_pid);

				return -1;
			}

			error = (*filter) (&snl, h);
			if (error < 0) {
				syslog(LOG_INFO,
				       "Netlink: filter function error");
				ret = error;
			}
		}

		/* After error care. */
		if (msg.msg_flags & MSG_TRUNC) {
			syslog(LOG_INFO, "Netlink: error: message truncated");
			continue;
		}
		if (status) {
			syslog(LOG_INFO, "Netlink: error: data remnant size %d",
			       status);
			return -1;
		}
	}

	return ret;
}

/* Out talk filter */
static int
netlink_talk_filter(struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	syslog(LOG_INFO, "Netlink: ignoring message type 0x%04x",
	       h->nlmsg_type);
	return 0;
}

/* send message to netlink kernel socket, then receive response */
int
netlink_talk(struct nl_handle *nl, struct nlmsghdr *n)
{
	int status;
	struct sockaddr_nl snl;
	struct iovec iov = { (void *) n, n->nlmsg_len };
	struct msghdr msg = { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };

	memset(&snl, 0, sizeof snl);
	snl.nl_family = AF_NETLINK;

	n->nlmsg_seq = ++nl->seq;

	/* Send message to netlink interface. */
	status = sendmsg(nl->fd, &msg, 0);
	if (status < 0) {
		syslog(LOG_INFO, "Netlink: sendmsg() error: %s",
		       strerror(errno));
		return -1;
	}

	status = netlink_parse_info(netlink_talk_filter, nl);
	return status;
}

/* Fetch a specific type information from netlink kernel */
static int
netlink_request(struct nl_handle *nl, int family, int type)
{
	int status;
	struct sockaddr_nl snl;
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;

	/* Cleanup the room */
	memset(&snl, 0, sizeof (snl));
	snl.nl_family = AF_NETLINK;

	req.nlh.nlmsg_len = sizeof (req);
	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = ++nl->seq;
	req.g.rtgen_family = family;

	status = sendto(nl->fd, (void *) &req, sizeof (req)
			, 0, (struct sockaddr *) &snl, sizeof (snl));
	if (status < 0) {
		syslog(LOG_INFO, "Netlink: sendto() failed: %s",
		       strerror(errno));
		return -1;
	}
	return 0;
}

/* Netlink interface link lookup filter */
static int
netlink_if_link_filter(struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	struct ifinfomsg *ifi;
	struct rtattr *tb[IFLA_MAX + 1];
	interface *ifp;
	int i, len;
	char *name;

	ifi = NLMSG_DATA(h);

	if (h->nlmsg_type != RTM_NEWLINK)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct ifinfomsg));
	if (len < 0)
		return -1;

	/* Interface name lookup */
	memset(tb, 0, sizeof (tb));
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
	if (tb[IFLA_IFNAME] == NULL)
		return -1;
	name = (char *) RTA_DATA(tb[IFLA_IFNAME]);

	/* Return if loopback */
	if (ifi->ifi_type == ARPHRD_LOOPBACK)
		return 0;

	/* Fill the interface structure */
	ifp = (interface *) MALLOC(sizeof (interface));
	memcpy(ifp->ifname, name, strlen(name));
	ifp->ifindex = ifi->ifi_index;
	ifp->flags = ifi->ifi_flags;
	ifp->mtu = *(int *) RTA_DATA(tb[IFLA_MTU]);
	ifp->hw_type = ifi->ifi_type;

	if (tb[IFLA_ADDRESS]) {
		int hw_addr_len = RTA_PAYLOAD(tb[IFLA_ADDRESS]);

		if (hw_addr_len > IF_HWADDR_MAX)
			syslog(LOG_ERR, "MAC address for %s is too large: %d",
			       name, hw_addr_len);
		else {
			ifp->hw_addr_len = hw_addr_len;
			memcpy(ifp->hw_addr, RTA_DATA(tb[IFLA_ADDRESS]),
			       hw_addr_len);
			for (i = 0; i < hw_addr_len; i++)
				if (ifp->hw_addr[i] != 0)
					break;
			if (i == hw_addr_len)
				ifp->hw_addr_len = 0;
			else
				ifp->hw_addr_len = hw_addr_len;
		}
	}

	/* Queue this new interface */
	if_add_queue(ifp);
	return 0;
}

/*
 * Netlink interface address lookup filter
 * We need to handle multiple primary address and
 * multiple secondary address to the same interface.
 */
static int
netlink_if_address_filter(struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	struct ifaddrmsg *ifa;
	struct rtattr *tb[IFA_MAX + 1];
	interface *ifp;
	uint32_t address = 0;
	int len;

	ifa = NLMSG_DATA(h);

	/* Only IPV4 are valid us */
	if (ifa->ifa_family != AF_INET)
		return 0;

	if (h->nlmsg_type != RTM_NEWADDR && h->nlmsg_type != RTM_DELADDR)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct ifaddrmsg));
	if (len < 0)
		return -1;

	memset(tb, 0, sizeof (tb));
	parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), len);

	/* Fetch interface */
	ifp = if_get_by_ifindex(ifa->ifa_index);
	if (!ifp)
		return 0;

	if (tb[IFA_ADDRESS] == NULL)
		tb[IFA_ADDRESS] = tb[IFA_LOCAL];

	if (ifp->flags & IFF_POINTOPOINT) {
		if (tb[IFA_LOCAL])
			address = *(uint32_t *) RTA_DATA(tb[IFA_LOCAL]);
	} else {
		if (tb[IFA_ADDRESS])
			address = *(uint32_t *) RTA_DATA(tb[IFA_ADDRESS]);
	}

	/* If no address is set on interface then set the first time */
	if (!ifp->address)
		ifp->address = address;

#ifdef _WITH_LVS_
	/* Refresh checkers state */
	update_checker_activity(address,
				(h->nlmsg_type == RTM_NEWADDR) ? 1 : 0);
#endif

	return 0;
}

/* Interfaces lookup bootstrap function */
int
netlink_interface_lookup(void)
{
	struct nl_handle nlh;
	int status = 0;

	if (netlink_socket(&nlh, 0) < 0)
		return -1;

	/* Interface lookup */
	if (netlink_request(&nlh, AF_PACKET, RTM_GETLINK) < 0) {
		status = -1;
		goto end_int;
	}
	status = netlink_parse_info(netlink_if_link_filter, &nlh);

end_int:
	netlink_close(&nlh);
	return status;
}

/* Adresses lookup bootstrap function */
static int
netlink_address_lookup(void)
{
	struct nl_handle nlh;
	int status = 0;

	if (netlink_socket(&nlh, 0) < 0)
		return -1;

	/* Address lookup */
	if (netlink_request(&nlh, AF_INET, RTM_GETADDR) < 0) {
		status = -1;
		goto end_addr;
	}
	status = netlink_parse_info(netlink_if_address_filter, &nlh);

end_addr:
	netlink_close(&nlh);
	return status;
}

/* Netlink flag Link update */
static int
netlink_reflect_filter(struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	struct ifinfomsg *ifi;
	struct rtattr *tb[IFLA_MAX + 1];
	interface *ifp;
	int len;

	ifi = NLMSG_DATA(h);
	if (!(h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK))
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct ifinfomsg));
	if (len < 0)
		return -1;

	/* Interface name lookup */
	memset(tb, 0, sizeof (tb));
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
	if (tb[IFLA_IFNAME] == NULL)
		return -1;

	/* ignore loopback device */
	if (ifi->ifi_type == ARPHRD_LOOPBACK)
		return 0;

	/* find the interface */
	ifp = if_get_by_ifindex(ifi->ifi_index);
	if (!ifp)
		return -1;

	/* Update flags */
	ifp->flags = ifi->ifi_flags;

	return 0;
}

/* Netlink kernel message reflection */
static int
netlink_broadcast_filter(struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	switch (h->nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
		return netlink_reflect_filter(snl, h);
		break;
	case RTM_NEWADDR:
	case RTM_DELADDR:
		return netlink_if_address_filter(snl, h);
		break;
	default:
		syslog(LOG_INFO,
		       "Kernel is reflecting an unknown netlink nlmsg_type: %d",
		       h->nlmsg_type);
		break;
	}
	return 0;
}

int
kernel_netlink(thread * thread)
{
	int status = 0;

	if (thread->type != THREAD_READ_TIMEOUT)
		status =
		    netlink_parse_info(netlink_broadcast_filter, &nl_kernel);
	thread_add_read(master, kernel_netlink, NULL, nl_kernel.fd,
			NETLINK_TIMER);
	return 0;
}

void
kernel_netlink_init(void)
{
	unsigned long groups;

	/* Start with a netlink address lookup */
	netlink_address_lookup();

	/*
	 * Prepare netlink kernel broadcast channel
	 * subscribtion. We subscribe to LINK and ADDR
	 * netlink broadcast messages.
	 */
	groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;
	netlink_socket(&nl_kernel, groups);

	if (nl_kernel.fd > 0) {
		syslog(LOG_INFO, "Registering Kernel netlink reflector");
		thread_add_read(master, kernel_netlink, NULL, nl_kernel.fd,
				NETLINK_TIMER);
	}
}
