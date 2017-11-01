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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <netinet/ip.h>
/* global include */
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <sys/uio.h>
#ifdef _HAVE_LIBNL3_
#include <netlink/netlink.h>
#endif
#include <net/if_arp.h>
#include <arpa/inet.h>
#if !defined _HAVE_LIBNL3_ || defined _LIBNL_DYNAMIC_
#ifdef HAVE_LIBNFNETLINK_LIBNFNETLINK_H
#include <libnfnetlink/libnfnetlink.h>
#endif
#endif
#include <time.h>

/* local include */
#ifdef _LIBNL_DYNAMIC_
#include "libnl_link.h"
#endif
#include "keepalived_netlink.h"
#ifdef _WITH_LVS_
#include "check_api.h"
#endif
#ifdef _WITH_VRRP_
#include "vrrp_scheduler.h"
#include "vrrp_track.h"
#include "vrrp_data.h"
#include "vrrp_sync.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_vmac.h"
#endif
#endif
#include "logger.h"
#include "scheduler.h"
#include "utils.h"
#include "bitops.h"
#if !HAVE_DECL_SOCK_NONBLOCK
#include "old_socket.h"
#endif
#include "vrrp_ipaddress.h"

/* Default values */
#define IF_DEFAULT_BUFSIZE	(65*1024)

/* Global vars */
#ifdef _WITH_VRRP_
nl_handle_t nl_cmd;		/* Command channel */
int netlink_error_ignore;	/* If we get this error, ignore it */
#endif

/* Static vars */
static nl_handle_t nl_kernel;	/* Kernel reflection channel */
static int nlmsg_buf_size;	/* Size of netlink message buffer */

static inline bool
addr_is_equal(struct ifaddrmsg* ifa, void* addr, ip_address_t* vip_addr, interface_t *ifp)
{
	struct in_addr* sin_addr;
	struct in6_addr* sin6_addr;

	if (vip_addr->ifa.ifa_family != ifa->ifa_family)
		return false;
	if (vip_addr->ifp != ifp)
		return false;
	if (vip_addr->ifa.ifa_family == AF_INET) {
		sin_addr = (struct in_addr *)addr;
		return vip_addr->u.sin.sin_addr.s_addr == sin_addr->s_addr;
	}

	sin6_addr = (struct in6_addr*)addr;
	return vip_addr->u.sin6_addr.s6_addr32[0] == sin6_addr->s6_addr32[0] &&
	       vip_addr->u.sin6_addr.s6_addr32[1] == sin6_addr->s6_addr32[1] &&
	       vip_addr->u.sin6_addr.s6_addr32[2] == sin6_addr->s6_addr32[2] &&
	       vip_addr->u.sin6_addr.s6_addr32[3] == sin6_addr->s6_addr32[3];
}

#ifdef _WITH_VRRP_
static vrrp_t *
address_is_ours(struct ifaddrmsg* ifa, struct in_addr* addr, interface_t* ifp)
{
	element e, e1;
	tracking_vrrp_t* tvp;
	vrrp_t* vrrp;

	if (LIST_ISEMPTY(ifp->tracking_vrrp))
		return NULL;

	for (e = LIST_HEAD(ifp->tracking_vrrp); e; ELEMENT_NEXT(e)) {
		tvp = ELEMENT_DATA(e);
		vrrp = tvp->vrrp;

		/* If we are not master, then we won't have the address configured */
		if (vrrp->state != VRRP_STATE_MAST)
			continue;

		if (ifa->ifa_family == vrrp->family &&
		    !LIST_ISEMPTY(vrrp->vip)) {
			for (e1 = LIST_HEAD(vrrp->vip); e1; ELEMENT_NEXT(e1)) {
				if (addr_is_equal(ifa, addr, ELEMENT_DATA(e1), ifp))
					return vrrp;
			}
		}

		if (!LIST_ISEMPTY(vrrp->evip)) {
			for (e1 = LIST_HEAD(vrrp->evip); e1; ELEMENT_NEXT(e1)) {
				if (addr_is_equal(ifa, addr, ELEMENT_DATA(e1), ifp))
					return vrrp;
			}
		}
	}

	return NULL;
}
#endif

void
netlink_set_recv_buf_size(void)
{
	/* The size of the read buffer for the NL socket is based on page
	 * size however, it should not exceed 8192. See the comment in:
	 * linux/include/linux/netlink.h (copied below):
	 * skb should fit one page. This choice is good for headerless malloc.
	 * But we should limit to 8K so that userspace does not have to
	 * use enormous buffer sizes on recvmsg() calls just to avoid
	 * MSG_TRUNC when PAGE_SIZE is very large.
	 */
	nlmsg_buf_size = getpagesize();
	if (nlmsg_buf_size > 8192)
		nlmsg_buf_size = 8192;
}

/* Create a socket to netlink interface_t */
static int
netlink_socket(nl_handle_t *nl, int flags, int group, ...)
{
	int ret;
	va_list gp;
#if !defined _HAVE_LIBNL3_ || defined _LIBNL_DYNAMIC_
	int rcvbuf_size;
#endif

	memset(nl, 0, sizeof (*nl));

#ifdef _HAVE_LIBNL3_
#ifdef _LIBNL_DYNAMIC_
	if (use_nl)
#endif
	{
		/* We need to keep libnl3 in step with our netlink socket creation.  */
		nl->sk = nl_socket_alloc();
		if (nl->sk == NULL) {
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
	}
#endif
#if !defined _HAVE_LIBNL3_ || defined _LIBNL_DYNAMIC_
#if defined _HAVE_LIBNL3_ && defined _LIBNL_DYNAMIC_
	else
#endif
	{
		socklen_t addr_len;
		struct sockaddr_nl snl;
		int sock_flags = flags;
#if !HAVE_DECL_SOCK_NONBLOCK
		sock_flags &= ~SOCK_NONBLOCK;
#endif

		nl->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | sock_flags, NETLINK_ROUTE);
		if (nl->fd < 0) {
			log_message(LOG_INFO, "Netlink: Cannot open netlink socket : (%s)",
			       strerror(errno));
			return -1;
		}

#if !HAVE_DECL_SOCK_NONBLOCK
		if ((flags & SOCK_NONBLOCK) &&
		    set_sock_flags(nl->fd, F_SETFL, O_NONBLOCK))
			return -1;
#endif

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
		rcvbuf_size = IF_DEFAULT_BUFSIZE;
		ret = setsockopt(nl->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));
		if (ret < 0) {
			log_message(LOG_INFO, "cant set SO_RCVBUF IP option. errno=%d (%m)", errno);
			close(nl->fd);
			return -1;
		}
	}
#endif

	nl->seq = (uint32_t)time(NULL);

	if (nl->fd < 0)
		return -1;

	return ret;
}

/* Close a netlink socket */
static void
netlink_close(nl_handle_t *nl)
{
	if (!nl)
		return;

	/* First of all release pending thread */
	thread_cancel(nl->thread);

#ifdef _HAVE_LIBNL3_
#ifdef _LIBNL_DYNAMIC_
	if (use_nl)
#endif
		nl_socket_free(nl->sk);
#endif
#if !defined _HAVE_LIBNL3_ || defined _LIBNL_DYNAMIC_
#if defined _HAVE_LIBNL3_ && defined _LIBNL_DYNAMIC_
	else
#endif
		close(nl->fd);
#endif
}

#ifdef _WITH_VRRP_
/* Set netlink socket channel as blocking */
static int
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
static int
netlink_set_nonblock(nl_handle_t *nl,
#ifdef _HAVE_LIBNL3_
				     __attribute__((unused))
#endif
							     int *flags)
{
#ifdef _HAVE_LIBNL3_
#ifdef _LIBNL_DYNAMIC_
	if (use_nl)
#endif
	{
		int ret;

		if ((ret = nl_socket_set_nonblocking(nl->sk)) < 0 ) {
			log_message(LOG_INFO, "Netlink: Cannot set nonblocking : (%s)",
				strerror(ret));
			return -1;
		}
	}
#endif
#if !defined _HAVE_LIBNL3_ || defined _LIBNL_DYNAMIC_
#if defined _HAVE_LIBNL3_ && defined _LIBNL_DYNAMIC_
	else
#endif
	{
		*flags |= O_NONBLOCK;
		if (fcntl(nl->fd, F_SETFL, *flags) < 0) {
			log_message(LOG_INFO, "Netlink: Cannot F_SETFL socket : (%s)",
			       strerror(errno));
			return -1;
		}
	}
#endif

	return 0;
}
#endif

/* iproute2 utility function */
int
addattr_l(struct nlmsghdr *n, size_t maxlen, unsigned short type, void *data, size_t alen)
{
	size_t len = RTA_LENGTH(alen);
	size_t align_len = NLMSG_ALIGN(len);
	struct rtattr *rta;

	if (n->nlmsg_len + align_len > maxlen)
		return -1;

	rta = (struct rtattr *) (((char *) n) + n->nlmsg_len);
	rta->rta_type = type;
	rta->rta_len = (unsigned short)len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len += (uint32_t)align_len;

	return 0;
}

#ifdef _WITH_VRRP_
int
addattr8(struct nlmsghdr *n, size_t maxlen, unsigned short type, uint8_t data)
{
	return addattr_l(n, maxlen, type, &data, sizeof data);
}
#endif

int
addattr32(struct nlmsghdr *n, size_t maxlen, unsigned short type, uint32_t data)
{
	return addattr_l(n, maxlen, type, &data, sizeof data);
}

#ifdef _WITH_VRRP_
int
addattr64(struct nlmsghdr *n, size_t maxlen, unsigned short type, uint64_t data)
{
	return addattr_l(n, maxlen, type, &data, sizeof(data));
}

int
addattr_l2(struct nlmsghdr *n, size_t maxlen, unsigned short type, void *data, size_t alen, void *data2, size_t alen2)
{
	size_t len = RTA_LENGTH(alen + alen2);
	size_t align_len = NLMSG_ALIGN(len);
	struct rtattr *rta;

	if (n->nlmsg_len + align_len > maxlen)
		return -1;

	rta = (struct rtattr *) (((char *) n) + n->nlmsg_len);
	rta->rta_type = type;
	rta->rta_len = (unsigned short)len;
	memcpy(RTA_DATA(rta), data, alen);
	memcpy(RTA_DATA(rta) + alen, data2, alen2);
	n->nlmsg_len += (uint32_t)align_len;

	return 0;
}

int
addraw_l(struct nlmsghdr *n, size_t maxlen, const void *data, size_t len)
{
	size_t align_len = NLMSG_ALIGN(len);

	if (n->nlmsg_len + align_len > maxlen)
		return -1;

	memcpy(NLMSG_TAIL(n), data, len);
	memset((void *) NLMSG_TAIL(n) + len, 0, align_len - len);
	n->nlmsg_len += (uint32_t)align_len;
	return 0;
}

size_t
rta_addattr_l(struct rtattr *rta, size_t maxlen, unsigned short type,
		  const void *data, size_t alen)
{
	struct rtattr *subrta;
	size_t len = RTA_LENGTH(alen);
	size_t align_len = RTA_ALIGN(len);

	if (rta->rta_len + align_len > maxlen)
		return 0;

	subrta = (struct rtattr*)(((char*)rta) + rta->rta_len);
	subrta->rta_type = type;
	subrta->rta_len = (unsigned short)len;
	memcpy(RTA_DATA(subrta), data, alen);
	rta->rta_len = (unsigned short)(rta->rta_len + align_len);
	return align_len;
}

size_t
rta_addattr_l2(struct rtattr *rta, size_t maxlen, unsigned short type,
		  const void *data, size_t alen,
		  const void *data2, size_t alen2)
{
	struct rtattr *subrta;
	size_t len = RTA_LENGTH(alen + alen2);
	size_t align_len = RTA_ALIGN(len);

	if (rta->rta_len + align_len > maxlen)
		return 0;

	subrta = (struct rtattr*)(((char*)rta) + rta->rta_len);
	subrta->rta_type = type;
	subrta->rta_len = (unsigned short)len;
	memcpy(RTA_DATA(subrta), data, alen);
	memcpy(RTA_DATA(subrta) + alen, data2, alen2);
	rta->rta_len = (unsigned short)(rta->rta_len + align_len);
	return align_len;
}

size_t
rta_addattr64(struct rtattr *rta, size_t maxlen, unsigned short type, uint64_t data)
{
	return rta_addattr_l(rta, maxlen, type, &data, sizeof data);
}

size_t
rta_addattr32(struct rtattr *rta, size_t maxlen, unsigned short type, uint32_t data)
{
	struct rtattr *subrta;
	size_t len = RTA_LENGTH(sizeof data);
	size_t align_len = RTA_ALIGN(len);

	if (rta->rta_len + align_len > maxlen)
		return 0;

	subrta = (struct rtattr*)(((char*)rta) + rta->rta_len);
	subrta->rta_type = type;
	subrta->rta_len = (unsigned short)len;
	memcpy(RTA_DATA(subrta), &data, sizeof data);
	rta->rta_len = (unsigned short)(rta->rta_len + align_len);
	return align_len;
}

size_t
rta_addattr16(struct rtattr *rta, size_t maxlen, unsigned short type, uint16_t data)
{
	return rta_addattr_l(rta, maxlen, type, &data, sizeof data);
}

size_t
rta_addattr8(struct rtattr *rta, size_t maxlen, unsigned short type, uint8_t data)
{
	return rta_addattr_l(rta, maxlen, type, &data, sizeof data);
}

struct rtattr *
rta_nest(struct rtattr *rta, size_t maxlen, unsigned short type)
{
	struct rtattr *nest = RTA_TAIL(rta);

	rta_addattr_l(rta, maxlen, type, NULL, 0);

	return nest;
}

size_t
rta_nest_end(struct rtattr *rta, struct rtattr *nest)
{
	nest->rta_len = (unsigned short)((void *)RTA_TAIL(rta) - (void *)nest);

	return rta->rta_len;
}
#endif

static inline __u8 rta_getattr_u8(const struct rtattr *rta)
{
        return *(__u8 *)RTA_DATA(rta);
}

static void
parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta, size_t len)
{
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta, len);
	}
}

#ifdef _HAVE_VRRP_VMAC_
static void
parse_rtattr_nested(struct rtattr **tb, int max, struct rtattr *rta)
{
	parse_rtattr(tb, max, RTA_DATA(rta), RTA_PAYLOAD(rta));
}
#endif

/*
 * Netlink interface address lookup filter
 * We need to handle multiple primary address and
 * multiple secondary address to the same interface.
 * We also need to handle the same address on
 * multiple interfaces, for IPv6 link local addresses.
 */
static int
netlink_if_address_filter(__attribute__((unused)) struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	struct ifaddrmsg *ifa;
	struct rtattr *tb[IFA_MAX + 1];
#ifdef _WITH_VRRP_
	interface_t *ifp;
#endif
	size_t len;
	union {
		void *addr;
		struct in_addr *in;
		struct in6_addr *in6;
	} addr;
#ifdef _WITH_VRRP_
	char addr_str[INET6_ADDRSTRLEN];
	bool addr_chg = false;
	element e;
	vrrp_t *vrrp;
	vrrp_t *sync_vrrp;
	vrrp_t *address_vrrp;
	tracking_vrrp_t *tvp;
	bool is_tracking_saddr;
#endif

	if (h->nlmsg_type != RTM_NEWADDR && h->nlmsg_type != RTM_DELADDR)
		return 0;

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof (struct ifaddrmsg)))
		return -1;

	ifa = NLMSG_DATA(h);

	/* Only IPv4 and IPv6 are valid for us */
	if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct ifaddrmsg));

	memset(tb, 0, sizeof (tb));
	parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), len);

	if (tb[IFA_LOCAL] == NULL)
		tb[IFA_LOCAL] = tb[IFA_ADDRESS];
	if (tb[IFA_ADDRESS] == NULL)
		tb[IFA_ADDRESS] = tb[IFA_LOCAL];

	/* local interface address */
	addr.addr = (tb[IFA_LOCAL] ? RTA_DATA(tb[IFA_LOCAL]) : NULL);

	if (addr.addr == NULL)
		return -1;

#ifdef _WITH_VRRP_
#ifndef _DEBUG_
	if (prog_type == PROG_TYPE_VRRP)
#endif
	{
		/* Fetch interface_t */
		ifp = if_get_by_ifindex(ifa->ifa_index);
		if (!ifp)
			return 0;

// ?? Only interested in link-local for IPv6 unless unicast
// we take address from vrrp->ifp->base-ifp, unless we have made an IPv6 address
// do we want to set a flag to say it is a generated link local address (or set saddr and track_saddr, but not saddr_from_config)
// or can we just compare address to vrrp->ifp->base_ifp address.
// We still need to consider non-vmac IPv6 if interface doesn't have a
// link local address.
		if (!ifp->vmac || ifa->ifa_family == AF_INET6) {
			if (h->nlmsg_type == RTM_NEWADDR) {
				/* If no address is set on interface then set the first time */
// TODO if saddr from config && track saddr, addresses must match
				if (ifa->ifa_family == AF_INET) {
					if (!ifp->sin_addr.s_addr) {
						ifp->sin_addr = *addr.in;
						if (!LIST_ISEMPTY(ifp->tracking_vrrp))
							addr_chg = true;
					}
				} else {
// TODO  might not be link local if configured address
					if (ifa->ifa_scope == RT_SCOPE_LINK) {
						if (!ifp->sin6_addr.s6_addr32[0]) {
							ifp->sin6_addr = *addr.in6;
							if (!LIST_ISEMPTY(ifp->tracking_vrrp))
								addr_chg = true;
						}
#if defined _HAVE_VRRP_VMAC_ && !HAVE_DECL_IFLA_INET6_ADDR_GEN_MODE
						else if (ifp->vmac) {
							/* We already have an address; is this an auto generated link local address?
							 * For some reason if we recreate the VMAC when the underlying interface is
							 * recreated, deleting the autogenerated address doesn't get rid of the address */
							remove_vmac_auto_gen_addr(ifp, addr.in6);
						}
#endif
					}
				}

				if (addr_chg) {
					if (__test_bit(LOG_DETAIL_BIT, &debug)) {
						inet_ntop(ifa->ifa_family, addr.addr, addr_str, sizeof(addr_str));
						log_message(LOG_INFO, "Assigned address %s for interface %s"
								    , addr_str, ifp->ifname);
					}

					/* Now see if any vrrp instances were missing an interface address
					 * and see if they can be brought up */
					for (e = LIST_HEAD(ifp->tracking_vrrp); e; ELEMENT_NEXT(e)) {
						tvp = ELEMENT_DATA(e);
						vrrp = tvp->vrrp;

						is_tracking_saddr = false;
						if (vrrp->track_saddr) {
							if (vrrp->family == ifa->ifa_family)
								is_tracking_saddr = inaddr_equal(ifa->ifa_family, &vrrp->saddr, addr.addr);
						}

						if (ifp == (vrrp->family == AF_INET ? vrrp->ifp->base_ifp : vrrp->ifp) &&
						    vrrp->num_script_if_fault &&
						    vrrp->family == ifa->ifa_family &&
						    vrrp->saddr.ss_family == AF_UNSPEC &&
						    (!vrrp->saddr_from_config || is_tracking_saddr)) {
							/* Copy the address */
							if (ifa->ifa_family == AF_INET)
								inet_ip4tosockaddr(addr.in, &vrrp->saddr);
							else
								inet_ip6tosockaddr(addr.in6, &vrrp->saddr);
							try_up_instance(vrrp, false);
						}
#ifdef _HAVE_VRRP_VMAC_
						// If IPv6 link local and vmac doesn't have an address, add it to the vmac
						else if (vrrp->family == AF_INET6 &&
							 ifp == vrrp->ifp->base_ifp &&
							 vrrp->ifp->vmac &&
							 vrrp->num_script_if_fault &&
							 vrrp->family == ifa->ifa_family &&
							 vrrp->saddr.ss_family == AF_UNSPEC &&
							 (!vrrp->saddr_from_config || is_tracking_saddr)) {
							if (add_link_local_address(vrrp->ifp, addr.in6)) {
								inet_ip6tosockaddr(addr.in6, &vrrp->saddr);
								try_up_instance(vrrp, false);
							}
						}
#endif
					}
				}
			} else {
				/* Mark the address as needing to go. We can't delete the address
				 * until after down_instance is called, since it sends a prio 0 message */
				if (ifa->ifa_family == AF_INET) {
					if (ifp->sin_addr.s_addr == addr.in->s_addr)
						addr_chg = true;
				}
				else {
					if (ifp->sin6_addr.s6_addr32[0] == addr.in6->s6_addr32[0] &&
					    ifp->sin6_addr.s6_addr32[1] == addr.in6->s6_addr32[1] &&
					    ifp->sin6_addr.s6_addr32[2] == addr.in6->s6_addr32[2] &&
					    ifp->sin6_addr.s6_addr32[3] == addr.in6->s6_addr32[3])
						addr_chg = true;
				}

				if (addr_chg && !LIST_ISEMPTY(ifp->tracking_vrrp)) {
					if (__test_bit(LOG_DETAIL_BIT, &debug)) {
						inet_ntop(ifa->ifa_family, addr.addr, addr_str, sizeof(addr_str));
						log_message(LOG_INFO, "Deassigned address %s from interface %s"
								    , addr_str, ifp->ifname);
					}

					/* See if any vrrp instances need to be downed */
					for (e = LIST_HEAD(ifp->tracking_vrrp); e; ELEMENT_NEXT(e)) {
						tvp = ELEMENT_DATA(e);
						vrrp = tvp->vrrp;

						is_tracking_saddr = false;
						if (vrrp->track_saddr) {
							if (vrrp->family == ifa->ifa_family)
								is_tracking_saddr = inaddr_equal(ifa->ifa_family, &vrrp->saddr, addr.addr);
						}
#ifdef _HAVE_VRRP_VMAC_
						/* If we are a VMAC and took this address from the parent interface, we need to
						 * release the address and create one for ourself */
						if (ifa->ifa_family == AF_INET6 &&
						    __test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags) &&
						    ifp == vrrp->ifp->base_ifp &&
						    ifa->ifa_scope == RT_SCOPE_LINK &&
						    !vrrp->saddr_from_config &&
						    vrrp->ifp->base_ifp->sin6_addr.s6_addr32[0] == addr.in6->s6_addr32[0] &&
						    vrrp->ifp->base_ifp->sin6_addr.s6_addr32[1] == addr.in6->s6_addr32[1] &&
						    vrrp->ifp->base_ifp->sin6_addr.s6_addr32[2] == addr.in6->s6_addr32[2] &&
						    vrrp->ifp->base_ifp->sin6_addr.s6_addr32[3] == addr.in6->s6_addr32[3]) {
							if (IF_ISUP(ifp) && replace_link_local_address(vrrp->ifp))
								inet_ip6tosockaddr(&vrrp->ifp->sin6_addr, &vrrp->saddr);
							else if (IF_ISUP(ifp)) {
								/* We failed to add an address, so down the instance */
								down_instance(vrrp);
								vrrp->saddr.ss_family = AF_UNSPEC;
							}
						}
						else
#endif
						     if (ifp == (vrrp->family == AF_INET ? vrrp->ifp->base_ifp : vrrp->ifp) &&
							 vrrp->family == ifa->ifa_family &&
							 vrrp->saddr.ss_family != AF_UNSPEC &&
							 (!vrrp->saddr_from_config || is_tracking_saddr)) {
/* There might be another address available. Either send a netlink request for current addresses, or we keep a list */
							down_instance(vrrp);
							vrrp->saddr.ss_family = AF_UNSPEC;
						}
					}
				}

				if (addr_chg) {
					/* Now we can remove the address */
					if (ifa->ifa_family == AF_INET)
						ifp->sin_addr.s_addr = 0;
					else
						ifp->sin6_addr.s6_addr32[0] = 0;
				}
			}
		}

		if (!addr_chg || LIST_ISEMPTY(ifp->tracking_vrrp)) {
			if (h->nlmsg_type == RTM_DELADDR)
				address_vrrp = address_is_ours(ifa, addr.addr, ifp);
			else
				address_vrrp = NULL;

			/* Display netlink operation */
			if (__test_bit(LOG_ADDRESS_CHANGES, &debug) ||
			    (__test_bit(LOG_DETAIL_BIT, &debug) && address_vrrp)) {
				inet_ntop(ifa->ifa_family, addr.addr, addr_str, sizeof(addr_str));
				log_message(LOG_INFO, "Netlink reflector reports IP %s %s %s"
						    , addr_str, h->nlmsg_type == RTM_NEWADDR ? "added to" : "removed from", ifp->ifname);
			}

			/* If one of our VIPs/eVIPs has been deleted, transition to backup */
			if (address_vrrp && address_vrrp->state == VRRP_STATE_MAST) {
				address_vrrp->wantstate = VRRP_STATE_BACK;
				vrrp_state_leave_master(address_vrrp, true);
				if (address_vrrp->sync) {
					for (e = LIST_HEAD(address_vrrp->sync->vrrp_instances); e; ELEMENT_NEXT(e)) {
						sync_vrrp = ELEMENT_DATA(e);
						if (sync_vrrp->state == VRRP_STATE_MAST) {
							sync_vrrp->wantstate = VRRP_STATE_BACK;
							vrrp_state_leave_master(sync_vrrp, true);

							/* We want a quick transition back to master */
							sync_vrrp->ms_down_timer = VRRP_TIMER_SKEW(sync_vrrp);
							vrrp_init_instance_sands(sync_vrrp);
							vrrp_thread_requeue_read(sync_vrrp);
						}
					}
					address_vrrp->sync->state = VRRP_STATE_BACK;
				}

				/* We want a quick transition back to master */
				address_vrrp->ms_down_timer = VRRP_TIMER_SKEW(address_vrrp);
				vrrp_init_instance_sands(address_vrrp);
				vrrp_thread_requeue_read(address_vrrp);
			}
		}
	}
#endif

#ifdef _WITH_LVS_
#ifndef _DEBUG_
	if (prog_type == PROG_TYPE_CHECKER)
#endif
	{
		/* Refresh checkers state */
		update_checker_activity(ifa->ifa_family, addr.addr,
					(h->nlmsg_type == RTM_NEWADDR));
	}
#endif

	return 0;
}

/* Our netlink parser */
static int
netlink_parse_info(int (*filter) (struct sockaddr_nl *, struct nlmsghdr *),
		   nl_handle_t *nl, struct nlmsghdr *n, bool read_all)
{
	ssize_t status;
	int ret = 0;
	int error;

	while (true) {
		char buf[nlmsg_buf_size];
		struct iovec iov = {
			.iov_base = buf,
			.iov_len = sizeof buf
		};
		struct sockaddr_nl snl;
		struct msghdr msg = {
			.msg_name = &snl,
			.msg_namelen = sizeof(snl),
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = NULL,
			.msg_controllen = 0,
			.msg_flags = 0
		};
		struct nlmsghdr *h;

		status = recvmsg(nl->fd, &msg, 0);

		if (status < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;
			if (errno == ENOBUFS) {
				/* It appears the if we add a large number of interfaces, then
				 * within a few seconds of starting up the kernel can decide to
				 * notify us again of all the new interfaces (or it may have something
				 * to do with becoming master). In any event, if we add a
				 * kernel_netlink_poll() at every stage of the process, we suddenly
				 * go from having nothing to receive on nl_kernel to ENOBUFS. Since it
				 * relates to the interfaces, and we have already got the information
				 * about the interfaces, it appears that we aren't losing any useful info. */
				log_message(LOG_INFO, "Netlink: Received message overrun - (%m)");
			}
			else
				log_message(LOG_INFO, "Netlink: recvmsg error - %d (%m)", errno);
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

		for (h = (struct nlmsghdr *) buf; NLMSG_OK(h, (size_t)status);
		     h = NLMSG_NEXT(h, status)) {
			/* Finish off reading. */
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
					if (!(h->nlmsg_flags & NLM_F_MULTI) && !read_all)
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
					if (!(h->nlmsg_flags & NLM_F_MULTI))
						return 0;
					continue;
				}
#ifdef _WITH_VRRP_
				if (netlink_error_ignore != -err->error)
#endif
					log_message(LOG_INFO,
					       "Netlink: error: %s, type=(%u), seq=%u, pid=%d",
					       strerror(-err->error),
					       err->msg.nlmsg_type,
					       err->msg.nlmsg_seq, err->msg.nlmsg_pid);

				return -1;
			}

#ifdef _WITH_VRRP_
			/* Skip unsolicited messages from cmd channel */
			if (
#ifndef _DEBUG_
			    prog_type == PROG_TYPE_VRRP &&
#endif
			    nl != &nl_cmd && h->nlmsg_pid == nl_cmd.nl_pid)
				continue;
#endif

			error = (*filter) (&snl, h);
			if (error < 0) {
				log_message(LOG_INFO, "Netlink: filter function error");
				ret = error;
			}

			if (!(h->nlmsg_flags & NLM_F_MULTI) && !read_all)
				return ret;
		}

		/* After error care. */
		if (msg.msg_flags & MSG_TRUNC) {
			log_message(LOG_INFO, "Netlink: error: message truncated");
			continue;
		}
		if (status) {
			log_message(LOG_INFO, "Netlink: error: data remnant size %zd",
			       status);
			return -1;
		}
	}

	return ret;
}

#ifdef _WITH_VRRP_
/* Out talk filter */
static int
netlink_talk_filter(__attribute__((unused)) struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	log_message(LOG_INFO, "Netlink: ignoring message type 0x%04x",
	       h->nlmsg_type);
	return 0;
}

/* send message to netlink kernel socket, then receive response */
ssize_t
netlink_talk(nl_handle_t *nl, struct nlmsghdr *n)
{
	ssize_t status;
	int ret, flags;
	struct sockaddr_nl snl;
	struct iovec iov = {
		.iov_base = n,
		.iov_len = n->nlmsg_len
	};
	struct msghdr msg = {
		.msg_name = &snl,
		.msg_namelen = sizeof(snl),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0
	};

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

	status = netlink_parse_info(netlink_talk_filter, nl, n, false);

	/* Restore previous flags */
	if (ret == 0)
		netlink_set_nonblock(nl, &flags);
	return status;
}
#endif

/* Fetch a specific type of information from netlink kernel */
static int
netlink_request(nl_handle_t *nl,
		unsigned char family,
		uint16_t type,
#ifndef _WITH_VRRP_
		__attribute__((unused))
#endif
					char *name)
{
	ssize_t status;
	struct sockaddr_nl snl;
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg i;
		char buf[64];
	} req;

	/* Cleanup the room */
	memset(&snl, 0, sizeof (snl));
	snl.nl_family = AF_NETLINK;

	memset(&req, 0, sizeof req);
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof req.i);
	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = ++nl->seq;
	req.i.ifi_family = family;

#ifdef _WITH_VRRP_
	if (name)
		addattr_l(&req.nlh, sizeof req, IFLA_IFNAME, name, strlen(name) + 1);
	else
#endif
		req.nlh.nlmsg_flags |= NLM_F_DUMP;
#if HAVE_DECL_RTEXT_FILTER_SKIP_STATS
	addattr32(&req.nlh, sizeof req, IFLA_EXT_MASK, RTEXT_FILTER_SKIP_STATS);
#endif

	status = sendto(nl->fd, (void *) &req, sizeof (req)
			, 0, (struct sockaddr *) &snl, sizeof (snl));
	if (status < 0) {
		log_message(LOG_INFO, "Netlink: sendto() failed: %s",
		       strerror(errno));
		return -1;
	}
	return 0;
}

#ifdef _WITH_VRRP_
void
process_if_status_change(interface_t *ifp)
{
	vrrp_t *vrrp;
	element e;
	tracking_vrrp_t *tvp;
	bool now_up = FLAGS_UP(ifp->ifi_flags);

	/* The state of the interface has changed from up to down or vice versa.
	 * Find which vrrp instances are affected */
	for (e = LIST_HEAD(ifp->tracking_vrrp); e; ELEMENT_NEXT(e)) {
		tvp = ELEMENT_DATA(e);
		vrrp = tvp->vrrp;

		/* If this interface isn't relevant to the vrrp instance, skip the instance */
		if (LIST_ISEMPTY(vrrp->track_ifp))
			continue;

		if (tvp->weight == VRRP_NOT_TRACK_IF) {
			/* We might want to restore things to the interface if it is coming up */
			continue;
		}

		if (tvp->weight) {
			if (now_up)
				vrrp->total_priority += abs(tvp->weight);
			else
				vrrp->total_priority -= abs(tvp->weight);
			vrrp_set_effective_priority(vrrp);

			continue;
		}

		/* This vrrp's interface or underlying interface has changed */
		if (now_up)
			try_up_instance(vrrp, false);
		else
			down_instance(vrrp);
	}
}

static void
update_interface_flags(interface_t *ifp, unsigned ifi_flags)
{
	bool was_up, now_up;

	if (ifi_flags == ifp->ifi_flags)
		return;

	if (!vrrp_data)
		return;

	/* We get called after a VMAC is created, but before tracking_vrrp is set */
	if (!ifp->tracking_vrrp &&
	    ifp == IF_BASE_IFP(ifp))
		return;

	was_up = IF_FLAGS_UP(ifp);
	now_up = FLAGS_UP(ifi_flags);

	ifp->ifi_flags = ifi_flags;

	if (was_up == now_up)
		return;

	if (!ifp->tracking_vrrp)
		return;

	log_message(LOG_INFO, "Netlink reports %s %s", ifp->ifname, now_up ? "up" : "down");

	process_if_status_change(ifp);
}

static bool
netlink_if_link_populate(interface_t *ifp, struct rtattr *tb[], struct ifinfomsg *ifi)
{
	char *name;
	size_t i;
#ifdef _HAVE_VRRP_VMAC_
	struct rtattr* linkinfo[IFLA_INFO_MAX+1];
	struct rtattr* linkattr[IFLA_MACVLAN_MAX+1];
#endif

	name = (char *)RTA_DATA(tb[IFLA_IFNAME]);
	/* Fill the interface structure */
	memcpy(ifp->ifname, name, strlen(name));
	ifp->ifindex = (ifindex_t)ifi->ifi_index;
	ifp->mtu = *(uint32_t *)RTA_DATA(tb[IFLA_MTU]);
	ifp->hw_type = ifi->ifi_type;
#ifdef _HAVE_VRRP_VMAC_
	ifp->base_ifp = ifp;
#endif

	if (tb[IFLA_ADDRESS]) {
		size_t hw_addr_len = RTA_PAYLOAD(tb[IFLA_ADDRESS]);

		if (hw_addr_len > sizeof(ifp->hw_addr)) {
			log_message(LOG_ERR, "MAC address for %s is too large: %zu",
				name, hw_addr_len);
			return false;
		}

		ifp->hw_addr_len = hw_addr_len;
		memcpy(ifp->hw_addr, RTA_DATA(tb[IFLA_ADDRESS]), hw_addr_len);

		/* Don't allow a hw address of all 0s */
		for (i = 0; i < hw_addr_len; i++)
			if (ifp->hw_addr[i])
				break;
		if (i == hw_addr_len)
			ifp->hw_addr_len = 0;
	}

#ifdef _HAVE_VRRP_VMAC_
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
			    *(uint32_t*)RTA_DATA(linkattr[IFLA_MACVLAN_MODE]) == MACVLAN_MODE_PRIVATE) {
				ifp->base_ifindex = *(uint32_t *)RTA_DATA(tb[IFLA_LINK]);
				ifp->base_ifp = if_get_by_ifindex(ifp->base_ifindex);
				if (ifp->base_ifp)
					ifp->base_ifindex = 0;	/* Make sure this isn't used at runtime */
				ifp->vmac = true;
			}
		}
	}

	ifp->rp_filter = UINT_MAX;	/* We have not read it yet */
#endif

	ifp->ifi_flags = ifi->ifi_flags;

	return true;
}

/* Netlink interface link lookup filter */
static int
netlink_if_link_filter(__attribute__((unused)) struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	struct ifinfomsg *ifi;
	struct rtattr *tb[IFLA_MAX + 1];
	interface_t *ifp;
	size_t len;
	char *name;

	ifi = NLMSG_DATA(h);

	if (h->nlmsg_type != RTM_NEWLINK)
		return 0;

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof (struct ifinfomsg)))
		return -1;
	len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct ifinfomsg));

	/* Interface name lookup */
	memset(tb, 0, sizeof (tb));
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

	if (tb[IFLA_IFNAME] == NULL)
		return -1;
	name = (char *) RTA_DATA(tb[IFLA_IFNAME]);

	/* Skip it if already exists */
	ifp = if_get_by_ifname(name, IF_CREATE_NETLINK);

	if (ifp->ifindex) {
		update_interface_flags(ifp, ifi->ifi_flags);

		return 0;
	}

	/* Fill the interface structure */
	if (!netlink_if_link_populate(ifp, tb, ifi))
		return -1;

	return 0;
}

/* Interfaces lookup bootstrap function */
int
netlink_interface_lookup(char *name)
{
	nl_handle_t nlh;
	int status = 0;

	if (netlink_socket(&nlh, 0, 0) < 0)
		return -1;

	/* Interface lookup */
	if (netlink_request(&nlh, AF_PACKET, RTM_GETLINK, name) < 0) {
		status = -1;
		goto end_int;
	}
	status = netlink_parse_info(netlink_if_link_filter, &nlh, NULL, false);

end_int:
	netlink_close(&nlh);
	return status;
}
#endif

/* Addresses lookup bootstrap function */
static int
netlink_address_lookup(void)
{
	nl_handle_t nlh;
	int status = 0;

	if (netlink_socket(&nlh, 0, 0) < 0)
		return -1;

	/* IPv4 Address lookup */
	if (netlink_request(&nlh, AF_INET, RTM_GETADDR, NULL) < 0) {
		status = -1;
		goto end_addr;
	}
	status = netlink_parse_info(netlink_if_address_filter, &nlh, NULL, false);

	/* IPv6 Address lookup */
	if (netlink_request(&nlh, AF_INET6, RTM_GETADDR, NULL) < 0) {
		status = -1;
		goto end_addr;
	}
	status = netlink_parse_info(netlink_if_address_filter, &nlh, NULL, false);

end_addr:
	netlink_close(&nlh);
	return status;
}

#ifdef _WITH_VRRP_
/* Netlink flag Link update */
static int
netlink_reflect_filter(__attribute__((unused)) struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	struct ifinfomsg *ifi;
	struct rtattr *tb[IFLA_MAX + 1];
	interface_t *ifp;
	size_t len;

	if (!(h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK))
		return 0;

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof (struct ifinfomsg)))
		return -1;
	len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct ifinfomsg));

	/* Interface name lookup */
	memset(tb, 0, sizeof (tb));
	ifi = NLMSG_DATA(h);
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
	if (tb[IFLA_IFNAME] == NULL)
		return -1;

	/* Ignore NEWLINK messages with ifi_change == 0 and IFLA_WIRELESS set
	   See for example https://bugs.chromium.org/p/chromium/issues/detail?id=501982 */
	if (!ifi->ifi_change && tb[IFLA_WIRELESS] && h->nlmsg_type == RTM_NEWLINK)
		return 0;

	/* find the interface_t. If the interface doesn't exist in the interface
	 * list and this is a new interface add it to the interface list.
	 * If an interface with the same name exists overwrite the older
	 * structure and fill it with the new interface information.
	 */
	ifp = if_get_by_ifindex((ifindex_t)ifi->ifi_index);

	if (ifp) {
		if (h->nlmsg_type == RTM_DELLINK) {
			if (!LIST_ISEMPTY(ifp->tracking_vrrp) || __test_bit(LOG_DETAIL_BIT, &debug))
				log_message(LOG_INFO, "Interface %s deleted", ifp->ifname);
#ifndef _DEBUG_
			if (prog_type == PROG_TYPE_VRRP)
				cleanup_lost_interface(ifp);
			else {
				ifp->ifi_flags = 0;
				ifp->ifindex = 0;
			}
#else
			cleanup_lost_interface(ifp);
#endif
		} else {
			/* The name can change, so handle that here */
			char *name = (char *)RTA_DATA(tb[IFLA_IFNAME]);
			if (strcmp(ifp->ifname, name)) {
				log_message(LOG_INFO, "Interface name has changed from %s to %s", ifp->ifname, name);

#ifndef _DEBUG_
				if (prog_type == PROG_TYPE_VRRP)
					cleanup_lost_interface(ifp);
				else {
					ifp->ifi_flags = 0;
					ifp->ifindex = 0;
				}
#else
				cleanup_lost_interface(ifp);
#endif
// TODO - Remove any vmacs on the interface (internally)

				/* Set ifp to null, to force creating a new interface_t */
				ifp = NULL;
			} else {
				/* Ignore interface if we are using linkbeat on it */
				if (ifp->linkbeat_use_polling)
					return 0;
			}
		}
	}

	if (!ifp) {
		if (h->nlmsg_type == RTM_NEWLINK) {
			char *name;
			name = (char *) RTA_DATA(tb[IFLA_IFNAME]);
			ifp = if_get_by_ifname(name, IF_CREATE_NETLINK);

			/* Since the garp_delay and tracking_vrrp are set up by name,
			 * it is reasonable to preserve them.
			 * If what is created is a vmac, we could end up in a complete mess. */
			garp_delay_t *sav_garp_delay = ifp->garp_delay;
			list sav_tracking_vrrp = ifp->tracking_vrrp;

			memset(ifp, 0, sizeof(interface_t));

			ifp->garp_delay = sav_garp_delay;
			ifp->tracking_vrrp = sav_tracking_vrrp;

			if (!netlink_if_link_populate(ifp, tb, ifi))
				return -1;

			if (__test_bit(LOG_DETAIL_BIT, &debug))
				log_message(LOG_INFO, "Interface %s added", ifp->ifname);

			update_added_interface(ifp);
		} else {
			if (__test_bit(LOG_DETAIL_BIT, &debug))
				log_message(LOG_INFO, "Unknown interface %s deleted", (char *)tb[IFLA_IFNAME]);
			return 0;
		}
	}

	/* Update flags. Flags == 0 means interface deleted. */
	update_interface_flags(ifp, (h->nlmsg_type == RTM_DELLINK) ? 0 : ifi->ifi_flags);

	return 0;
}

static int
netlink_route_filter(__attribute__((unused)) struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	struct rtmsg *rt;
	struct rtattr *tb[RTA_MAX + 1];
	size_t len;
// char src[INET6_ADDRSTRLEN] = "None";
// char dst[INET6_ADDRSTRLEN] = "None";

	if (h->nlmsg_type != RTM_NEWROUTE && h->nlmsg_type != RTM_DELROUTE)
		return 0;

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof (struct rtmsg)))
		return -1;

	rt = NLMSG_DATA(h);

// log_message(LOG_INFO, "Netlink route message (%s): IPv%d, table %d, protocol %d, type %d, scope %d, dlen %d, slen %d, flags 0x%x",
//	h->nlmsg_type == RTM_NEWROUTE ? "add" : "del", rt->rtm_family == AF_INET ? 4 : rt->rtm_family == AF_INET6 ? 6 : -rt->rtm_family,
//	rt->rtm_table, rt->rtm_protocol, rt->rtm_type, rt->rtm_scope, rt->rtm_dst_len, rt->rtm_src_len, rt->rtm_flags);

	/* Only IPv4 and IPv6 are valid for us */
	if (rt->rtm_family != AF_INET && rt->rtm_family != AF_INET6)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct rtmsg));

	memset(tb, 0, sizeof (tb));
	parse_rtattr(tb, RTA_MAX, RTM_RTA(rt), len);

// if (tb[RTA_DST] != NULL)
//   inet_ntop(rt->rtm_family, RTA_DATA(tb[RTA_DST]), dst, INET6_ADDRSTRLEN);
// if (tb[RTA_SRC] != NULL)
//   inet_ntop(rt->rtm_family, RTA_DATA(tb[RTA_SRC]), src, INET6_ADDRSTRLEN);
// log_message(LOG_INFO, "src: %s/%d, dst: %s/%d, table: %d", src, rt->rtm_src_len, dst, rt->rtm_dst_len, tb[RTA_TABLE] ? *(uint32_t *)RTA_DATA(tb[RTA_TABLE]) : rt->rtm_table);

	return 0;
}
#endif

/* Netlink kernel message reflection */
static int
netlink_broadcast_filter(struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	switch (h->nlmsg_type) {
#ifdef _WITH_VRRP_
	case RTM_NEWLINK:
	case RTM_DELLINK:
		return netlink_reflect_filter(snl, h);
		break;
#endif
	case RTM_NEWADDR:
	case RTM_DELADDR:
		return netlink_if_address_filter(snl, h);
		break;
#ifdef _WITH_VRRP_
	case RTM_NEWROUTE:
	case RTM_DELROUTE:
		return netlink_route_filter(snl, h);
#endif
	default:
		log_message(LOG_INFO,
		       "Kernel is reflecting an unknown netlink nlmsg_type: %d",
		       h->nlmsg_type);
		break;
	}
	return 0;
}

static int
kernel_netlink(thread_t * thread)
{
	nl_handle_t *nl = THREAD_ARG(thread);

	if (thread->type != THREAD_READ_TIMEOUT)
		netlink_parse_info(netlink_broadcast_filter, nl, NULL, true);
	nl->thread = thread_add_read(master, kernel_netlink, nl, nl->fd,
				      NETLINK_TIMER);
	return 0;
}

#ifdef _WITH_VRRP_
void
kernel_netlink_poll(void)
{
	if (!nl_kernel.fd)
		return;

	netlink_parse_info(netlink_broadcast_filter, &nl_kernel, NULL, true);
}
#endif

void
kernel_netlink_init(void)
{
	/* Start with a netlink address lookup */
	netlink_address_lookup();

	/*
	 * Prepare netlink kernel broadcast channel
	 * subscription. We subscribe to LINK, ADDR,
	 * and ROUTE netlink broadcast messages, but
	 * the checker process does not need the
	 * route messages.
	 */
	/* TODO
	 * If an interface goes down, or an address is removed, any routes that specify the interface or address are deleted.
	 * If an interface goes down, any address on that interface is deleted. In this case, the vrrp instance should go to fault state.
	 * If an interface goes down, any VMACs are deleted. We need to recreate them when the interface returns.
	 * If a static route/ip_address goes down, some vrrp instances maybe should go down - add a tracking_instance option
	 * We need to reinstate routes/addresses/VMACs when we can.
	 * We need an option on routes to put the instance in fault state if the route disappears.
	 * When i/f deleted (? or down), close any sockets
	 * No ipaddr on i/f <=> link down, for us
	 * Do LVS services get lost on addr/link deletion?
	 */
#ifdef _DEBUG_
#ifdef _WITH_VRRP_
	netlink_socket(&nl_kernel, SOCK_NONBLOCK, RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR, 0);
#else
	netlink_socket(&nl_kernel, SOCK_NONBLOCK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR, 0);
#endif
#else
#ifdef _WITH_VRRP_
	if (prog_type == PROG_TYPE_VRRP)
		netlink_socket(&nl_kernel, SOCK_NONBLOCK, RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV6_ROUTE, 0);
#endif
#ifdef _WITH_LVS_
	if (prog_type == PROG_TYPE_CHECKER)
		netlink_socket(&nl_kernel, SOCK_NONBLOCK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR, 0);
#endif
#endif

	if (nl_kernel.fd > 0) {
		log_message(LOG_INFO, "Registering Kernel netlink reflector");
		nl_kernel.thread = thread_add_read(master, kernel_netlink, &nl_kernel, nl_kernel.fd,
						   NETLINK_TIMER);
	} else
		log_message(LOG_INFO, "Error while registering Kernel netlink reflector channel");

#ifdef _WITH_VRRP_
#ifndef _DEBUG_
	if (prog_type == PROG_TYPE_VRRP)
#endif
	{
		/* Prepare netlink command channel. */
		netlink_socket(&nl_cmd, SOCK_NONBLOCK, 0);
		if (nl_cmd.fd > 0)
			log_message(LOG_INFO, "Registering Kernel netlink command channel");
		else
			log_message(LOG_INFO, "Error while registering Kernel netlink cmd channel");
	}
#endif
}

void
kernel_netlink_close(void)
{
	netlink_close(&nl_kernel);
#ifdef _WITH_VRRP_
#ifndef _DEBUG_
	if (prog_type == PROG_TYPE_VRRP)
#endif
		netlink_close(&nl_cmd);
#endif
}

#ifdef _TIMER_DEBUG_
void
print_vrrp_netlink_addresses(void)
{
	log_message(LOG_INFO, "Address of kernel_netlink() is 0x%p", kernel_netlink);
}
#endif
