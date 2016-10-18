/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_if_config interface
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
 * Copyright (C) 2001-2015 Alexandre Cassen, <acassen@gmail.com>
 */

/* The following parameters need to be set on the vmac interface and its parent:
 *
 *   vmac interface:
 *     accept_local=1	// We need to be able to hear another instance multicasting it's presence
 *     arp_ignore=1	// We mustn't reply to ARP requests on this interface for IP address on parent interface
 *			// and we mustn't only reply to addresses on the same subnet.
 *     rp_filter=0	// Allows us to receive on VMAC interface when it has no IP address.
 *
 *   parent interface:
 *     arp_ignore=1	// We mustn't reply to ARP requests on this interface for vrrp IP address
 *     arp_filter=1	// We mustn't reply to ARP requests for our own IP address
 */

#include "config.h"

#include <string.h>
#include "vrrp_if_config.h"
#include "memory.h"

#ifdef _HAVE_IPV4_DEVCONF_

#ifdef _HAVE_IF_H_LINK_H_COLLISION_
/* The following is a horrible workaround. There was a longstanding problem with symbol
 * collision including both net/if.h and netlink/route/link.h, due to the latter
 * including linux/if.h unnecessarily.
 *
 * See: https://github.com/thom311/libnl/commit/50a76998ac36ace3716d3c979b352fac73cfc80a
 *
 * Defining _LINUX_IF_H stops linux/if.h being included.
 */

#define _LINUX_IF_H
#endif

#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/link/inet.h>
#include <linux/ip.h>
#include <syslog.h>

#include "vrrp_if.h"
#include "logger.h"
#endif

#include <limits.h>
#include <unistd.h>

#ifdef _HAVE_IPV4_DEVCONF_
int
set_promote_secondaries(interface_t *ifp)
{
	struct nl_sock *sk;
	struct nl_cache *cache;
	struct rtnl_link *link = NULL;
	struct rtnl_link *new_state = NULL;
	int res = 0;
	uint32_t prom_secs;

	if (!(sk = nl_socket_alloc())) {
		log_message(LOG_INFO, "Unable to open netlink socket");
		return -1;
	}

	if (nl_connect(sk, NETLINK_ROUTE) < 0)
		goto err;
	if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache))
		goto err;
	if (!(link = rtnl_link_get(cache, (int)ifp->ifindex)))
		goto err;

	if (rtnl_link_inet_get_conf(link, IPV4_DEVCONF_PROMOTE_SECONDARIES, &prom_secs) < 0)
		goto err;
	if (prom_secs) {
		ifp->promote_secondaries_already_set = true;
		goto exit_ok;
	}

	// Allocate a new link
	if (!(new_state = rtnl_link_alloc()))
		goto err;

	if (rtnl_link_inet_set_conf(new_state, IPV4_DEVCONF_PROMOTE_SECONDARIES, 1) ||
	    rtnl_link_change (sk, link, new_state, 0))
		goto err;
	ifp->reset_promote_secondaries = 1;

	rtnl_link_put(new_state);
	new_state = NULL;

	rtnl_link_put(link);
	link = NULL;

	goto exit;
err:
	res = -1;

exit_ok:
	if (link)
		rtnl_link_put(link);
	if (new_state)
		rtnl_link_put(new_state);

exit:
	nl_socket_free(sk);

	return res;
}

int
reset_promote_secondaries(interface_t *ifp)
{
	struct nl_sock *sk;
	struct nl_cache *cache;
	struct rtnl_link *link = NULL;
	struct rtnl_link *new_state = NULL;
	int res = 0;

	if (!ifp->reset_promote_secondaries ||
	    --ifp->reset_promote_secondaries)
		return 0;

	if (!(sk = nl_socket_alloc())) {
		log_message(LOG_INFO, "Unable to open netlink socket");
		return -1;
	}

	if (nl_connect(sk, NETLINK_ROUTE) < 0)
		goto err;
	if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache))
		goto err;
	if (!(link = rtnl_link_get(cache, (int)ifp->ifindex)))
		goto err;
	if (!(new_state = rtnl_link_alloc()))
		goto err;
	if (rtnl_link_inet_set_conf(new_state, IPV4_DEVCONF_PROMOTE_SECONDARIES, 0) ||
	    rtnl_link_change (sk, link, new_state, 0))
		goto err;

	rtnl_link_put(new_state);
	new_state = NULL;

	rtnl_link_put(link);
	link = NULL;

	goto exit;
err:
	res = -1;

	if (link)
		rtnl_link_put(link);
	if (new_state)
		rtnl_link_put(new_state);

exit:
	nl_socket_free(sk);

	return res;
}

#ifdef _HAVE_VRRP_VMAC_
static int
netlink3_set_interface_parameters(const interface_t *ifp, interface_t *base_ifp)
{
	struct nl_sock *sk;
	struct nl_cache *cache;
	struct rtnl_link *link = NULL;
	struct rtnl_link *new_state = NULL;
	int res = 0;

	if (!(sk = nl_socket_alloc())) {
		log_message(LOG_INFO, "Unable to open netlink socket");
		return -1;
	}

	if (nl_connect(sk, NETLINK_ROUTE) < 0)
		goto err;
	if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache))
		goto err;
	if (!(link = rtnl_link_get(cache, (int)ifp->ifindex)))
		goto err;

	// Allocate a new link
	if (!(new_state = rtnl_link_alloc()))
		goto err;

	if (rtnl_link_inet_set_conf(new_state, IPV4_DEVCONF_ARP_IGNORE, 1) ||
	    rtnl_link_inet_set_conf(new_state, IPV4_DEVCONF_ACCEPT_LOCAL, 1) ||
	    rtnl_link_inet_set_conf(new_state, IPV4_DEVCONF_RP_FILTER, 0) ||
	    rtnl_link_inet_set_conf(new_state, IPV4_DEVCONF_PROMOTE_SECONDARIES, 1) ||
	    rtnl_link_change (sk, link, new_state, 0))
		goto err;

	rtnl_link_put(new_state);
	new_state = NULL;

	rtnl_link_put(link);
	link = NULL;

	/* Set arp_ignore and arp_filter on base interface if needed */
	if (base_ifp->reset_arp_config)
		(base_ifp->reset_arp_config)++;
	else {
		if (!(link = rtnl_link_get(cache, (int)base_ifp->ifindex)))
			goto err;
		if (rtnl_link_inet_get_conf(link, IPV4_DEVCONF_ARP_IGNORE, &base_ifp->reset_arp_ignore_value) < 0)
			goto err;
		if (rtnl_link_inet_get_conf(link, IPV4_DEVCONF_ARPFILTER, &base_ifp->reset_arp_filter_value) < 0)
			goto err;

		if (base_ifp->reset_arp_ignore_value != 1 ||
		    base_ifp->reset_arp_filter_value != 1 ) {
			/* The underlying interface mustn't reply for our address(es) */
			if (!(new_state = rtnl_link_alloc()))
				goto err;

			if (rtnl_link_inet_set_conf(new_state, IPV4_DEVCONF_ARP_IGNORE, 1) ||
			    rtnl_link_inet_set_conf(new_state, IPV4_DEVCONF_ARPFILTER, 1) ||
			    rtnl_link_change(sk, link, new_state, 0))
				goto err;

			rtnl_link_put(new_state);
			new_state = NULL;

			rtnl_link_put(link);
			link = NULL;

			base_ifp->reset_arp_config = 1;
		}
	}

	goto exit;
err:
	res = -1;

	if (link)
		rtnl_link_put(link);
	if (new_state)
		rtnl_link_put(new_state);

exit:
	nl_socket_free(sk);

	return res;
}

static int
netlink3_reset_interface_parameters(const interface_t* ifp)
{
	struct nl_sock *sk;
	struct nl_cache *cache;
	struct rtnl_link *link = NULL;
	struct rtnl_link *new_state = NULL;
	int res = 0;

	if (!(sk = nl_socket_alloc())) {
		log_message(LOG_INFO, "Unable to open netlink socket");
		return -1;
	}

	if (nl_connect(sk, NETLINK_ROUTE) < 0)
		goto err;
	if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache))
		goto err;
	if (!(link = rtnl_link_get(cache, (int)ifp->ifindex)))
		goto err;
	if (!(new_state = rtnl_link_alloc()))
		goto err;
	if (rtnl_link_inet_set_conf(new_state, IPV4_DEVCONF_ARP_IGNORE, ifp->reset_arp_ignore_value) ||
	    rtnl_link_inet_set_conf(new_state, IPV4_DEVCONF_ARPFILTER, ifp->reset_arp_filter_value) ||
	    rtnl_link_change(sk, link, new_state, 0))
		goto err;

	rtnl_link_put(link);
	link = NULL;

	rtnl_link_put(new_state);
	new_state = NULL;

	goto exit;
err:
	res = -1;

	if (link)
		rtnl_link_put(link);
	if (new_state)
		rtnl_link_put(new_state);

exit:
	nl_socket_free(sk);

	return res;
}

void
set_interface_parameters(const interface_t *ifp, interface_t *base_ifp)
{
	if (netlink3_set_interface_parameters(ifp, base_ifp))
		log_message(LOG_INFO, "Unable to set parameters for %s", ifp->ifname);
}

void
reset_interface_parameters(interface_t *base_ifp)
{
	if (base_ifp->reset_arp_config && --base_ifp->reset_arp_config == 0) {
		if (netlink3_reset_interface_parameters(base_ifp))
			log_message(LOG_INFO, "Unable to reset parameters for %s", base_ifp->ifname);
	}
}
#endif
#endif

/* Sysctl get and set functions */
static void
make_sysctl_filename(char *dest, const char* prefix, const char* iface, const char* parameter)
{
	strcpy(dest, "/proc/sys/");
	strcat(dest, prefix);
	strcat(dest, "/");
	strcat(dest, iface);
	strcat(dest, "/");
	strcat(dest, parameter);
}

static int
set_sysctl(const char* prefix, const char* iface, const char* parameter, int value)
{
	char* filename;
	char buf[1];
	int fd;
	ssize_t len;

	/* Make the filename */
	filename = MALLOC(PATH_MAX);
	make_sysctl_filename(filename, prefix, iface, parameter);

	fd = open(filename, O_WRONLY);
	FREE(filename);
	if (fd < 0)
		return -1;

	/* We only write integers 0-9 */
	buf[0] = (char)('0' + value);
	len = write(fd, &buf, 1);
	close(fd);

	if (len != 1)
		return -1;

	/* Success */
	return 0;
}

static int
get_sysctl(const char* prefix, const char* iface, const char* parameter)
{
	char *filename;
	char buf[1];
	int fd;
	ssize_t len;

	/* Make the filename */
	filename = MALLOC(PATH_MAX);
	make_sysctl_filename(filename, prefix, iface, parameter);

	fd = open(filename, O_RDONLY);
	FREE(filename);
	if (fd < 0)
		return -1;

	len = read(fd, &buf, 1);
	close(fd);

	/* We only read integers 0-9 */
	if (len <= 0)
		return -1;

	/* Return the value of the string read */
	return buf[0] - '0';
}

#ifndef _HAVE_IPV4_DEVCONF_
int
set_promote_secondaries(interface_t *ifp)
{
	if (get_sysctl("net/ipv4/conf", ifp->ifname, "promote_secondaries")) {
		ifp->promote_secondaries_already_set = true;
		return 0;
	}
	set_sysctl("net/ipv4/conf", ifp->ifname, "promote_secondaries", 1);
	ifp->reset_promote_secondaries = 1;

	return 0;
}

int
reset_promote_secondaries(interface_t *ifp)
{
	if (ifp->reset_promote_secondaries && !--ifp->reset_promote_secondaries)
		set_sysctl("net/ipv4/conf", ifp->ifname, "promote_secondaries", 0);

	return 0;
}

#ifdef _HAVE_VRRP_VMAC_
void
set_interface_parameters(const interface_t *ifp, interface_t *base_ifp)
{
	set_sysctl("net/ipv4/conf", ifp->ifname, "arp_ignore", 1);
	set_sysctl("net/ipv4/conf", ifp->ifname, "accept_local", 1);
	set_sysctl("net/ipv4/conf", ifp->ifname, "rp_filter", 0);

	set_sysctl("net/ipv4/conf", ifp->ifname, "promote_secondaries", 1);

	if (base_ifp->reset_arp_config)
		base_ifp->reset_arp_config++;
	else {
		if ((base_ifp->reset_arp_ignore_value = get_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_ignore")) != 1)
			set_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_ignore", 1);

		if ((base_ifp->reset_arp_filter_value = get_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_filter")) != 1)
			set_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_filter", 1);

		base_ifp->reset_arp_config = 1;
	}
}

void reset_interface_parameters(interface_t *base_ifp)
{
	if (base_ifp->reset_arp_config && --base_ifp->reset_arp_config == 0) {
		set_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_ignore", base_ifp->reset_arp_ignore_value);
		set_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_filter", base_ifp->reset_arp_filter_value);
	}
}
#endif
#endif

void link_disable_ipv6(const interface_t* ifp)
{
	/* libnl3, nor the kernel, support setting IPv6 options */
	set_sysctl("net/ipv6/conf", ifp->ifname, "disable_ipv6", 1);
}

int get_ipv6_forwarding(const interface_t* ifp)
{
	return get_sysctl("net/ipv6/conf", ifp->ifname, "forwarding");
}
