/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK kernel command channel.
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
 *
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
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
#include <stdarg.h>

/* local include */
#include "check_api.h"
#include "vrrp_netlink.h"
#include "vrrp_vmac.h"
#include "logger.h"
#include "memory.h"
#include "scheduler.h"
#include "utils.h"
#include "bitops.h"

/* Global vars */
nl_handle_t nl_kernel;	/* Kernel reflection channel */
nl_handle_t nl_cmd;	/* Command channel */
int netlink_error_ignore; /* If we get this error, ignore it */

/* Create a socket to netlink interface_t */
int
netlink_socket(nl_handle_t *nl, int flags, int group, ...)
{
	int ret;
	va_list gp;

	memset(nl, 0, sizeof (*nl));

#ifdef _HAVE_LIBNL3_
	/* We need to keep libnl3 in step with our netlink socket creation.  */
	nl->sk = nl_socket_alloc();
	if ( nl->sk == NULL ) {
		log_message(LOG_INFO, "Netlink: Cannot allocate netlink socket" );
		return -1;
	}

	ret = nl_connect(nl->sk, NETLINK_ROUTE);
	if (ret != 0) {
		log_message(LOG_INFO, "Netlink: Cannot open netlink socket : (%d)", ret);
		return -1;
	}

	/* Unfortunately we can't call nl_socket_add_memberships() with variadic arguments
	 * from a variadic argument list passed to us
	 */
	va_start(gp, group);
	while (group != 0) {
		if (group < 0) {
			va_end(gp);
			return -1;
		}

		if ((ret = nl_socket_add_membership(nl->sk, group))) {
			log_message(LOG_INFO, "Netlink: Cannot add socket membership 0x%x : (%d)", group, ret);
			return -1;
		}

		group = va_arg(gp,int);
	}
	va_end(gp);

	if (flags & SOCK_NONBLOCK) {
		if ((ret = nl_socket_set_nonblocking(nl->sk))) {
			log_message(LOG_INFO, "Netlink: Cannot set netlink socket non-blocking : (%d)", ret);
			return -1;
		}
	}

	if ((ret = nl_socket_set_buffer_size(nl->sk, IF_DEFAULT_BUFSIZE, 0))) {
		log_message(LOG_INFO, "Netlink: Cannot set netlink buffer size : (%d)", ret);
		return -1;
	}

	nl->nl_pid = nl_socket_get_local_port(nl->sk);

	nl->fd = nl_socket_get_fd(nl->sk);

	/* Set CLOEXEC */
	fcntl(nl->fd, F_SETFD, fcntl(nl->fd, F_GETFD) | FD_CLOEXEC);
#else
	socklen_t addr_len;
	struct sockaddr_nl snl;

	nl->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | flags, NETLINK_ROUTE);
	if (nl->fd < 0) {
		log_message(LOG_INFO, "Netlink: Cannot open netlink socket : (%s)",
		       strerror(errno));
		return -1;
	}

	memset(&snl, 0, sizeof (snl));
	snl.nl_family = AF_NETLINK;

	ret = bind(nl->fd, (struct sockaddr *) &snl, sizeof (snl));
	if (ret < 0) {
		log_message(LOG_INFO, "Netlink: Cannot bind netlink socket : (%s)",
		       strerror(errno));
		close(nl->fd);
		return -1;
	}

	/* Join the requested groups */
	va_start(gp, group);
	while (group != 0) {
		if (group < 0) {
			va_end(gp);
			return -1;
		}

		ret = setsockopt(nl->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group));
		if (ret < 0) {
			log_message(LOG_INFO, "Netlink: Cannot add membership on netlink socket : (%s)",
			       strerror(errno));
			va_end(gp);
			return -1;
		}

		group = va_arg(gp,int);
	}
	va_end(gp);

	addr_len = sizeof (snl);
	ret = getsockname(nl->fd, (struct sockaddr *) &snl, &addr_len);
	if (ret < 0 || addr_len != sizeof (snl)) {
		log_message(LOG_INFO, "Netlink: Cannot getsockname : (%s)",
		       strerror(errno));
		close(nl->fd);
		return -1;
	}

	if (snl.nl_family != AF_NETLINK) {
		log_message(LOG_INFO, "Netlink: Wrong address family %d",
		       snl.nl_family);
		close(nl->fd);
		return -1;
	}

	/* Save the port id for checking message source later */
	nl->nl_pid = snl.nl_pid;

	/* Set default rcvbuf size */
	if_setsockopt_rcvbuf(&nl->fd, IF_DEFAULT_BUFSIZE);
#endif

	nl->seq = time(NULL);

	if (nl->fd < 0)
		return -1;

	return ret;
}

/* Close a netlink socket */
int
netlink_close(nl_handle_t *nl)
{
	/* First of all release pending thread */
	thread_cancel(nl->thread);
#ifdef _HAVE_LIBNL3_
	nl_socket_free(nl->sk);
#else
	close(nl->fd);
#endif
	return 0;
}

/* Set netlink socket channel as blocking */
int
netlink_set_block(nl_handle_t *nl, int *flags)
{
	if ((*flags = fcntl(nl->fd, F_GETFL, 0)) < 0) {
		log_message(LOG_INFO, "Netlink: Cannot F_GETFL socket : (%s)",
		       strerror(errno));
		return -1;
	}
	*flags &= ~O_NONBLOCK;
	if (fcntl(nl->fd, F_SETFL, *flags) < 0) {
		log_message(LOG_INFO, "Netlink: Cannot F_SETFL socket : (%s)",
		       strerror(errno));
		return -1;
	}
	return 0;
}

/* Set netlink socket channel as non-blocking */
int
netlink_set_nonblock(nl_handle_t *nl, int *flags)
{
#ifdef _HAVE_LIBNL3_
	int ret;

	if ((ret = nl_socket_set_nonblocking(nl->sk)) < 0 ) {
		log_message(LOG_INFO, "Netlink: Cannot set nonblocking : (%s)",
			strerror(ret));
		return -1;
	}
#else
	*flags |= O_NONBLOCK;
	if (fcntl(nl->fd, F_SETFL, *flags) < 0) {
		log_message(LOG_INFO, "Netlink: Cannot F_SETFL socket : (%s)",
		       strerror(errno));
		return -1;
	}
#endif
	return 0;
}

/* iproute2 utility function */
int
addattr32(struct nlmsghdr *n, int maxlen, int type, uint32_t data)
{
	int len = RTA_LENGTH(sizeof(data));
	struct rtattr *rta;
	if (n->nlmsg_len + NLMSG_ALIGN(len) > maxlen)
		return -1;
	rta = (struct rtattr*)(((char*)n) + n->nlmsg_len);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), &data, sizeof(data));
	n->nlmsg_len += NLMSG_ALIGN(len);
	return 0;
}

int
addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (n->nlmsg_len + NLMSG_ALIGN(len) > maxlen)
		return -1;

	rta = (struct rtattr *) (((char *) n) + n->nlmsg_len);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len += NLMSG_ALIGN(len);

	return 0;
}

int rta_addattr_l(struct rtattr *rta, int maxlen, int type,
		  const void *data, int alen)
{
	struct rtattr *subrta;
	int len = RTA_LENGTH(alen);

	if (RTA_ALIGN(rta->rta_len) + RTA_ALIGN(len) > maxlen) {
		return -1;
	}
	subrta = (struct rtattr*)(((char*)rta) + RTA_ALIGN(rta->rta_len));
	subrta->rta_type = type;
	subrta->rta_len = len;
	memcpy(RTA_DATA(subrta), data, alen);
	rta->rta_len = NLMSG_ALIGN(rta->rta_len) + RTA_ALIGN(len);
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

static void
parse_rtattr_nested(struct rtattr **tb, int max, struct rtattr *rta)
{
        parse_rtattr(tb, max, RTA_DATA(rta), RTA_PAYLOAD(rta));
}

char *
netlink_scope_n2a(int scope)
{
	if (scope == RT_SCOPE_UNIVERSE)
		return "global";
	if (scope == RT_SCOPE_NOWHERE)
		return "nowhere";
	if (scope == RT_SCOPE_HOST)
		return "host";
	if (scope == RT_SCOPE_LINK)
		return "link";
	if (scope == RT_SCOPE_SITE)
		return "site";
	return "unknown";
}

int
netlink_scope_a2n(char *scope)
{
	if (!strcmp(scope, "global"))
		return RT_SCOPE_UNIVERSE;
	if (!strcmp(scope, "nowhere"))
		return RT_SCOPE_NOWHERE;
	if (!strcmp(scope, "host"))
		return RT_SCOPE_HOST;
	if (!strcmp(scope, "link"))
		return RT_SCOPE_LINK;
	if (!strcmp(scope, "site"))
		return RT_SCOPE_SITE;
	return -1;
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
	interface_t *ifp;
	int len;
	void *addr;

	ifa = NLMSG_DATA(h);

	/* Only IPV4 are valid us */
	if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6)
		return 0;

	if (h->nlmsg_type != RTM_NEWADDR && h->nlmsg_type != RTM_DELADDR)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct ifaddrmsg));
	if (len < 0)
		return -1;

	memset(tb, 0, sizeof (tb));
	parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), len);

	/* Fetch interface_t */
	ifp = if_get_by_ifindex(ifa->ifa_index);
	if (!ifp)
		return 0;
	if (tb[IFA_LOCAL] == NULL)
		tb[IFA_LOCAL] = tb[IFA_ADDRESS];
	if (tb[IFA_ADDRESS] == NULL)
		tb[IFA_ADDRESS] = tb[IFA_LOCAL];

	/* local interface address */
	addr = (tb[IFA_LOCAL] ? RTA_DATA(tb[IFA_LOCAL]) : NULL);

	if (addr == NULL)
		return -1;

	/* If no address is set on interface then set the first time */
	if (ifa->ifa_family == AF_INET) {
		if (!ifp->sin_addr.s_addr)
			ifp->sin_addr = *(struct in_addr *) addr;
	} else {
		if (!ifp->sin6_addr.s6_addr16[0] && ifa->ifa_scope == RT_SCOPE_LINK)
			ifp->sin6_addr = *(struct in6_addr *) addr;
	}

#ifdef _WITH_LVS_
	/* Refresh checkers state */
	update_checker_activity(ifa->ifa_family, addr,
				(h->nlmsg_type == RTM_NEWADDR) ? 1 : 0);
#endif
	return 0;
}

/* Our netlink parser */
static int
netlink_parse_info(int (*filter) (struct sockaddr_nl *, struct nlmsghdr *),
		   nl_handle_t *nl, struct nlmsghdr *n)
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
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;
			log_message(LOG_INFO, "Netlink: Received message overrun (%m)");
			continue;
		}

		if (status == 0) {
			log_message(LOG_INFO, "Netlink: EOF");
			return -1;
		}

		if (msg.msg_namelen != sizeof snl) {
			log_message(LOG_INFO,
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
				struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA(h);

				/*
				 * If error == 0 then this is a netlink ACK.
				 * return if not related to multipart message.
				 */
				if (err->error == 0) {
					if (!(h->nlmsg_flags & NLM_F_MULTI))
						return 0;
					continue;
				}

				if (h->nlmsg_len < NLMSG_LENGTH(sizeof (struct nlmsgerr))) {
					log_message(LOG_INFO,
					       "Netlink: error: message truncated");
					return -1;
				}

				if (n && (err->error == -EEXIST) &&
				    ((n->nlmsg_type == RTM_NEWROUTE) ||
				     (n->nlmsg_type == RTM_NEWADDR)))
					return 0;

				/* If have more than one IPv4 address in the same CIDR
				 * and the "primary" address is removed, unless promote_secondaries
				 * is configured on the interface, all the "secondary" addresses
				 * in the same CIDR are deleted */
				if (n && err->error == -EADDRNOTAVAIL &&
				    n->nlmsg_type == RTM_DELADDR) {
					netlink_if_address_filter(NULL, n);
					if (!(h->nlmsg_flags & NLM_F_MULTI))
						return 0;
					continue;
				}
				if (netlink_error_ignore != -err->error)
					log_message(LOG_INFO,
					       "Netlink: error: %s, type=(%u), seq=%u, pid=%d",
					       strerror(-err->error),
					       err->msg.nlmsg_type,
					       err->msg.nlmsg_seq, err->msg.nlmsg_pid);

				return -1;
			}

			/* Skip unsolicited messages from cmd channel */
			if (nl != &nl_cmd && h->nlmsg_pid == nl_cmd.nl_pid)
				continue;

			error = (*filter) (&snl, h);
			if (error < 0) {
				log_message(LOG_INFO, "Netlink: filter function error");
				ret = error;
			}
		}

		/* After error care. */
		if (msg.msg_flags & MSG_TRUNC) {
			log_message(LOG_INFO, "Netlink: error: message truncated");
			continue;
		}
		if (status) {
			log_message(LOG_INFO, "Netlink: error: data remnant size %d",
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
	log_message(LOG_INFO, "Netlink: ignoring message type 0x%04x",
	       h->nlmsg_type);
	return 0;
}

/* send message to netlink kernel socket, then receive response */
int
netlink_talk(nl_handle_t *nl, struct nlmsghdr *n)
{
	int status;
	int ret, flags;
	struct sockaddr_nl snl;
	struct iovec iov = { (void *) n, n->nlmsg_len };
	struct msghdr msg = { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };

	memset(&snl, 0, sizeof snl);
	snl.nl_family = AF_NETLINK;

	n->nlmsg_seq = ++nl->seq;

	/* Request Netlink acknowledgement */
	n->nlmsg_flags |= NLM_F_ACK;

	/* Send message to netlink interface. */
	status = sendmsg(nl->fd, &msg, 0);
	if (status < 0) {
		log_message(LOG_INFO, "Netlink: sendmsg() error: %s",
		       strerror(errno));
		return -1;
	}

	/* Set blocking flag */
	ret = netlink_set_block(nl, &flags);
	if (ret < 0)
		log_message(LOG_INFO, "Netlink: Warning, couldn't set "
		       "blocking flag to netlink socket...");

	status = netlink_parse_info(netlink_talk_filter, nl, n);

	/* Restore previous flags */
	if (ret == 0)
		netlink_set_nonblock(nl, &flags);
	return status;
}

/* Fetch a specific type information from netlink kernel */
static int
netlink_request(nl_handle_t *nl, int family, int type)
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
		log_message(LOG_INFO, "Netlink: sendto() failed: %s",
		       strerror(errno));
		return -1;
	}
	return 0;
}

static int
netlink_if_link_populate(interface_t *ifp, struct rtattr *tb[], struct ifinfomsg *ifi)
{
	char *name;
	int i;
	struct rtattr* linkinfo[IFLA_INFO_MAX+1];
	struct rtattr* linkattr[IFLA_MACVLAN_MAX+1];
	interface_t *ifp_base;

	name = (char *) RTA_DATA(tb[IFLA_IFNAME]);
	/* Fill the interface structure */
	memcpy(ifp->ifname, name, strlen(name));
	ifp->ifindex = ifi->ifi_index;
	ifp->mtu = *(int *) RTA_DATA(tb[IFLA_MTU]);
	ifp->hw_type = ifi->ifi_type;

	if (tb[IFLA_ADDRESS]) {
		int hw_addr_len = RTA_PAYLOAD(tb[IFLA_ADDRESS]);

		if (hw_addr_len > IF_HWADDR_MAX) {
			log_message(LOG_ERR, "MAC address for %s is too large: %d",
				name, hw_addr_len);
			return -1;
		}
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

	/* See if this interface is a MACVLAN of ours */
	if (tb[IFLA_LINKINFO] && tb[IFLA_LINK]){
		/* If appears that the value of *(int*)RTA_DATA(tb[IFLA_LINKINFO]) is 0x1000c
		 *   for macvlan.  0x10000 for nested data, or'ed with 0x0c for macvlan;
		 *   other values are 0x09 for vlan, 0x0b for bridge, 0x08 for tun, -1 for no
		 *   underlying interface.
		 *
		 * I can't find where in the kernel these values are set or defined, so use
		 * the string as below.
		 */
		parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO]);

		if (linkinfo[IFLA_INFO_KIND] &&
		    RTA_PAYLOAD(linkinfo[IFLA_INFO_KIND]) >= strlen(macvlan_ll_kind) &&
		    !strncmp(macvlan_ll_kind, RTA_DATA(linkinfo[IFLA_INFO_KIND]), strlen(macvlan_ll_kind)) &&
		    linkinfo[IFLA_INFO_DATA]) {
			parse_rtattr_nested(linkattr, IFLA_MACVLAN_MAX, linkinfo[IFLA_INFO_DATA]);

			if (linkattr[IFLA_MACVLAN_MODE] &&
			    *(int*)RTA_DATA(linkattr[IFLA_MACVLAN_MODE]) == MACVLAN_MODE_PRIVATE) {
				ifp->base_ifindex = *(int*)RTA_DATA(tb[IFLA_LINK]);
				ifp->vmac = true;
			}
		}
	}

	if (!ifp->vmac) {
		if_vmac_reflect_flags(ifi->ifi_index, ifi->ifi_flags);
		ifp->flags = ifi->ifi_flags;
		ifp->base_ifindex = ifi->ifi_index;
	} else {
		if ((ifp_base = if_get_by_ifindex(ifp->base_ifindex)))
			ifp->flags = ifp_base->flags;
	}

	return 1;
}

/* Netlink interface link lookup filter */
static int
netlink_if_link_filter(struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	struct ifinfomsg *ifi;
	struct rtattr *tb[IFLA_MAX + 1];
	interface_t *ifp;
	int len, status;
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

	/* Skip it if already exist */
	ifp = if_get_by_ifname(name);
	if (ifp) {
		if (!ifp->vmac) {
			if_vmac_reflect_flags(ifi->ifi_index, ifi->ifi_flags);
			ifp->flags = ifi->ifi_flags;
		}
		return 0;
	}

	/* Fill the interface structure */
	ifp = (interface_t *) MALLOC(sizeof(interface_t));

	status = netlink_if_link_populate(ifp, tb, ifi);
	if (status < 0) {
		FREE(ifp);
		return -1;
	}
	/* Queue this new interface_t */
	if_add_queue(ifp);
	return 0;
}

/* Interfaces lookup bootstrap function */
int
netlink_interface_lookup(void)
{
	nl_handle_t nlh;
	int status = 0;

	if (netlink_socket(&nlh, 0, 0) < 0)
		return -1;

	/* Interface lookup */
	if (netlink_request(&nlh, AF_PACKET, RTM_GETLINK) < 0) {
		status = -1;
		goto end_int;
	}
	status = netlink_parse_info(netlink_if_link_filter, &nlh, NULL);

end_int:
	netlink_close(&nlh);
	return status;
}

/* Adresses lookup bootstrap function */
static int
netlink_address_lookup(void)
{
	nl_handle_t nlh;
	int status = 0;

	if (netlink_socket(&nlh, 0, 0) < 0)
		return -1;

	/* IPv4 Address lookup */
	if (netlink_request(&nlh, AF_INET, RTM_GETADDR) < 0) {
		status = -1;
		goto end_addr;
	}
	status = netlink_parse_info(netlink_if_address_filter, &nlh, NULL);

	/* IPv6 Address lookup */
	if (netlink_request(&nlh, AF_INET6, RTM_GETADDR) < 0) {
		status = -1;
		goto end_addr;
	}
	status = netlink_parse_info(netlink_if_address_filter, &nlh, NULL);

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
	interface_t *ifp;
	int len, status;

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

	/* find the interface_t. If the interface doesn't exist in the interface
	 * list and this is a new interface add it to the interface list.
	 * If an interface with the same name exists overwrite the older
	 * structure and fill it with the new interface information.
	 */
	ifp = if_get_by_ifindex(ifi->ifi_index);
	if (!ifp) {
		if (h->nlmsg_type == RTM_NEWLINK) {
			char *name;
			name = (char *) RTA_DATA(tb[IFLA_IFNAME]);
			ifp = if_get_by_ifname(name);
			if (!ifp) {
				ifp = (interface_t *) MALLOC(sizeof(interface_t));
				if_add_queue(ifp);
			} else {
				memset(ifp, 0, sizeof(interface_t));
			}
			status = netlink_if_link_populate(ifp, tb, ifi);
			if (status < 0)
				return -1;
		} else {
			if (__test_bit(LOG_DETAIL_BIT, &debug))
				log_message(LOG_INFO, "Unknown interface %s deleted", (char *)tb[IFLA_IFNAME]);
			return 0;
		}
	}

	/*
	 * Update flags.
	 * VMAC interfaces should never update it own flags, only be reflected
	 * by the base interface flags.
	 */
	if (!ifp->vmac) {
		if_vmac_reflect_flags(ifi->ifi_index, ifi->ifi_flags);
		ifp->flags = ifi->ifi_flags;
	}

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
		log_message(LOG_INFO,
		       "Kernel is reflecting an unknown netlink nlmsg_type: %d",
		       h->nlmsg_type);
		break;
	}
	return 0;
}

int
kernel_netlink(thread_t * thread)
{
	nl_handle_t *nl = THREAD_ARG(thread);

	if (thread->type != THREAD_READ_TIMEOUT)
		netlink_parse_info(netlink_broadcast_filter, nl, NULL);
	nl->thread = thread_add_read(master, kernel_netlink, nl, nl->fd,
				      NETLINK_TIMER);
	return 0;
}

void
kernel_netlink_init(void)
{
	/* Start with a netlink address lookup */
	netlink_address_lookup();

	/*
	 * Prepare netlink kernel broadcast channel
	 * subscribtion. We subscribe to LINK and ADDR
	 * netlink broadcast messages.
	 */
	netlink_socket(&nl_kernel, SOCK_NONBLOCK, RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR, 0);

	if (nl_kernel.fd > 0) {
		log_message(LOG_INFO, "Registering Kernel netlink reflector");
		nl_kernel.thread = thread_add_read(master, kernel_netlink, &nl_kernel, nl_kernel.fd,
						   NETLINK_TIMER);
	} else
		log_message(LOG_INFO, "Error while registering Kernel netlink reflector channel");

	/* Prepare netlink command channel. */
	netlink_socket(&nl_cmd, SOCK_NONBLOCK, 0);
	if (nl_cmd.fd > 0)
		log_message(LOG_INFO, "Registering Kernel netlink command channel");
	else
		log_message(LOG_INFO, "Error while registering Kernel netlink cmd channel");
}

void
kernel_netlink_close(void)
{
	netlink_close(&nl_kernel);
	netlink_close(&nl_cmd);
}
