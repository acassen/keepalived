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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
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

#include <fcntl.h>

#include "vrrp_if_config.h"
#include "keepalived_netlink.h"
#include "memory.h"

#ifdef _HAVE_IPV4_DEVCONF_

#ifdef _HAVE_IF_H_LINK_H_COLLISION_
/* There was a longstanding problem with symbol collision including both
 * net/if.h and netlink/route/link.h, due to the latter including linux/if.h unnecessarily.
 *
 * See: https://github.com/thom311/libnl/commit/50a76998ac36ace3716d3c979b352fac73cfc80a
 *
 */

#ifdef _HAVE_NET_LINUX_IF_H_COLLISION_
/* Defining _LINUX_IF_H stops linux/if.h being included */
#define _LINUX_IF_H
#else
/* Including net/if.h first resolves the problem */
#include <net/if.h>
#endif
#endif

#include <netlink/route/link.h>
#include <netlink/route/link/inet.h>
#include <linux/ip.h>
#include <stdint.h>

#include "vrrp_if.h"
#endif

#include <limits.h>
#include <unistd.h>

#include "logger.h"

#ifdef _HAVE_VRRP_VMAC_
static unsigned all_rp_filter = UINT_MAX;
static unsigned default_rp_filter = UINT_MAX;
#endif

#ifdef _HAVE_IPV4_DEVCONF_

#ifdef _LIBNL_DYNAMIC_
#include "libnl_link.h"
#endif

static inline void
set_promote_secondaries_devconf(interface_t *ifp)
{
	struct nl_sock *sk;
	struct nl_cache *cache;
	struct rtnl_link *link = NULL;
	struct rtnl_link *new_state = NULL;
	uint32_t prom_secs;

	if (!(sk = nl_socket_alloc())) {
		log_message(LOG_INFO, "Unable to open netlink socket");
		return;
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

	rtnl_link_put(new_state);
	new_state = NULL;

	rtnl_link_put(link);
	link = NULL;

	goto exit;
err:
exit_ok:
	if (link)
		rtnl_link_put(link);
	if (new_state)
		rtnl_link_put(new_state);

exit:
	nl_socket_free(sk);

	return;
}

static inline void
reset_promote_secondaries_devconf(interface_t *ifp)
{
	struct nl_sock *sk;
	struct nl_cache *cache;
	struct rtnl_link *link = NULL;
	struct rtnl_link *new_state = NULL;

	if (!(sk = nl_socket_alloc())) {
		log_message(LOG_INFO, "Unable to open netlink socket");
		return;
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
	if (link)
		rtnl_link_put(link);
	if (new_state)
		rtnl_link_put(new_state);

exit:
	nl_socket_free(sk);

	return;
}

#ifdef _HAVE_VRRP_VMAC_
static inline int
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

static inline int
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

static inline void
set_interface_parameters_devconf(const interface_t *ifp, interface_t *base_ifp)
{
	if (netlink3_set_interface_parameters(ifp, base_ifp))
		log_message(LOG_INFO, "Unable to set parameters for %s", ifp->ifname);
}

static inline void
reset_interface_parameters_devconf(interface_t *base_ifp)
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
set_sysctl(const char* prefix, const char* iface, const char* parameter, unsigned value)
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

static unsigned
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
		return UINT_MAX;

	len = read(fd, &buf, 1);
	close(fd);

	/* We only read integers 0-9 */
	if (len <= 0)
		return UINT_MAX;

	/* Return the value of the string read */
	return (unsigned)buf[0] - '0';
}

#if !defined _HAVE_IPV4_DEVCONF_ || defined _LIBNL_DYNAMIC_
static inline void
set_promote_secondaries_sysctl(interface_t *ifp)
{
	if (get_sysctl("net/ipv4/conf", ifp->ifname, "promote_secondaries") == 1) {
		ifp->promote_secondaries_already_set = true;
		return;
	}
	set_sysctl("net/ipv4/conf", ifp->ifname, "promote_secondaries", 1);
}

static inline void
reset_promote_secondaries_sysctl(interface_t *ifp)
{
	set_sysctl("net/ipv4/conf", ifp->ifname, "promote_secondaries", 0);
}

#ifdef _HAVE_VRRP_VMAC_
static inline void
set_interface_parameters_sysctl(const interface_t *ifp, interface_t *base_ifp)
{
	unsigned val;

	set_sysctl("net/ipv4/conf", ifp->ifname, "arp_ignore", 1);
	set_sysctl("net/ipv4/conf", ifp->ifname, "accept_local", 1);
	set_sysctl("net/ipv4/conf", ifp->ifname, "rp_filter", 0);

	set_sysctl("net/ipv4/conf", ifp->ifname, "promote_secondaries", 1);

	if (base_ifp->reset_arp_config)
		base_ifp->reset_arp_config++;
	else {
		if ((val = get_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_ignore")) != UINT_MAX &&
		    (base_ifp->reset_arp_ignore_value = (uint32_t)val) != 1)
			set_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_ignore", 1);

		if ((val = get_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_filter")) != UINT_MAX &&
		    (base_ifp->reset_arp_filter_value = (uint32_t)val) != 1)
			set_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_filter", 1);

		base_ifp->reset_arp_config = true;
	}
}

static inline void
reset_interface_parameters_sysctl(interface_t *base_ifp)
{
	if (base_ifp->reset_arp_config && --base_ifp->reset_arp_config == 0) {
		set_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_ignore", (int)base_ifp->reset_arp_ignore_value);
		set_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_filter", (int)base_ifp->reset_arp_filter_value);
	}
}
#endif
#endif

void
set_promote_secondaries(interface_t *ifp)
{
	if (ifp->promote_secondaries_already_set)
		return;

	if (ifp->reset_promote_secondaries++)
		return;

#ifdef _HAVE_IPV4_DEVCONF_
#ifdef _LIBNL_DYNAMIC_
	if (use_nl)
#endif
	{
		set_promote_secondaries_devconf(ifp);
		return;
	}
#endif

#if !defined _HAVE_IPV4_DEVCONF_ || defined _LIBNL_DYNAMIC_
	set_promote_secondaries_sysctl(ifp);
#endif
}

void
reset_promote_secondaries(interface_t *ifp)
{
	if (!ifp->reset_promote_secondaries ||
	    --ifp->reset_promote_secondaries)
		return;

#ifdef _HAVE_IPV4_DEVCONF_
#ifdef _LIBNL_DYNAMIC_
	if (use_nl)
#endif
	{
		reset_promote_secondaries_devconf(ifp);
		return;
	}
#endif

#if !defined _HAVE_IPV4_DEVCONF_ || defined _LIBNL_DYNAMIC_
	reset_promote_secondaries_sysctl(ifp);
#endif
}

#ifdef _HAVE_VRRP_VMAC_
/* IPv4 VMAC interfaces require rp_filter to be 0; this in turn requires
 * net.ipv4.conf.all.rp_filter to be 0, but if it is non-zero, then all
 * interfaces will be operating with a non-zero value of rp_filter.
 * In this function, if all.rp_filter > 0 and default.rp_filter < all.rp_filter,
 * we first set default.rp_filter to the current value of all.rp_filter,
 * so that any new interfaces are created with the current value of all.rp_filter.
 * We then iterate through all interfaces, and if {interface}.rp_filter < all.rp_filter
 * we set {interface}.rp_filter = all.rp_filter.
 * Finally we set all.rp_filter = 0.
 *
 * This should not alter the operation of any interface, or any interface
 * subsequently created, but it does allow us to set rp_filter = 0
 * on vmac interfaces.
 */
static void
clear_rp_filter(void)
{
	list ifs;
	element e;
	interface_t *ifp;
	unsigned rp_filter;

	rp_filter = get_sysctl("net/ipv4/conf", "all", "rp_filter");
	if (rp_filter == UINT_MAX) {
		log_message(LOG_INFO, "Unable to read sysctl net.ipv4.conf.all.rp_filter");
		return;
	}

	if (rp_filter == 0)
		return;

	/* Save current value of all/rp_filter */
	all_rp_filter = rp_filter;

	/* We want to ensure that default/rp_filter is at least the value of all/rp_filter */
	rp_filter = get_sysctl("net/ipv4/conf", "default", "rp_filter");
	if (rp_filter < all_rp_filter) {
		log_message(LOG_INFO, "NOTICE: setting sysctl net.ipv4.conf.default.rp_filter from %d to %d", rp_filter, all_rp_filter);
		set_sysctl("net/ipv4/conf", "default", "rp_filter", all_rp_filter);
		default_rp_filter = rp_filter;
	}

	/* Now ensure rp_filter for all interfaces is at least all/rp_filter. */
	kernel_netlink_poll();		/* Update our view of interfaces first */
	ifs = get_if_list();
	if (!LIST_ISEMPTY(ifs)) {
		for (e = LIST_HEAD(ifs); e; ELEMENT_NEXT(e)) {
			ifp = ELEMENT_DATA(e);

			if ((rp_filter = get_sysctl("net/ipv4/conf", ifp->ifname, "rp_filter")) == UINT_MAX)
				log_message(LOG_INFO, "Unable to read rp_filter for %s", ifp->ifname);
			else if (rp_filter < all_rp_filter) {
				set_sysctl("net/ipv4/conf", ifp->ifname, "rp_filter", all_rp_filter);
				ifp->rp_filter = rp_filter;
			}
		}
	}

	/* We have now made sure that all the interfaces have rp_filter >= all_rp_filter */
	log_message(LOG_INFO, "NOTICE: setting sysctl net.ipv4.conf.all.rp_filter from %d to 0", all_rp_filter);
	set_sysctl("net/ipv4/conf", "all", "rp_filter", 0);
}

void
restore_rp_filter(void)
{
	list ifs;
	element e;
	interface_t *ifp;
	unsigned rp_filter;

	/* Restore the original settings of rp_filter, but only if they
	 * are the same as what we set them to */
	if (all_rp_filter == UINT_MAX)
		return;

	rp_filter = get_sysctl("net/ipv4/conf", "all", "rp_filter");
	if (rp_filter == 0) {
		log_message(LOG_INFO, "NOTICE: resetting sysctl net.ipv4.conf.all.rp_filter to %d", all_rp_filter);
		set_sysctl("net/ipv4/conf", "all", "rp_filter", all_rp_filter);
	}

	if (default_rp_filter != UINT_MAX) {
		rp_filter = get_sysctl("net/ipv4/conf", "default", "rp_filter");
		if (rp_filter == all_rp_filter) {
			log_message(LOG_INFO, "NOTICE: resetting sysctl net.ipv4.conf.default.rp_filter to %d", default_rp_filter);
			set_sysctl("net/ipv4/conf", "default", "rp_filter", default_rp_filter);
		}
		default_rp_filter = UINT_MAX;
	}

	ifs = get_if_list();
	if (!LIST_ISEMPTY(ifs)) {
		for (e = LIST_HEAD(ifs); e; ELEMENT_NEXT(e)) {
			ifp = ELEMENT_DATA(e);

			if (ifp->rp_filter != UINT_MAX) {
				rp_filter = get_sysctl("net/ipv4/conf", ifp->ifname, "rp_filter");
				if (rp_filter == all_rp_filter) {
					set_sysctl("net/ipv4/conf", ifp->ifname, "rp_filter", ifp->rp_filter);
					ifp->rp_filter = UINT_MAX;
				}
			}
		}
	}

	all_rp_filter = UINT_MAX;
}

void
set_interface_parameters(const interface_t *ifp, interface_t *base_ifp)
{
	if (all_rp_filter == UINT_MAX)
		clear_rp_filter();

#ifdef _HAVE_IPV4_DEVCONF_
#ifdef _LIBNL_DYNAMIC_
	if (use_nl)
#endif
	{
		set_interface_parameters_devconf(ifp, base_ifp);
		return;
	}
#endif

#if !defined _HAVE_IPV4_DEVCONF_ || defined _LIBNL_DYNAMIC_
	set_interface_parameters_sysctl(ifp, base_ifp);
#endif
}

void reset_interface_parameters(interface_t *base_ifp)
{
#ifdef _HAVE_IPV4_DEVCONF_
#ifdef _LIBNL_DYNAMIC_
	if (use_nl)
#endif
	{
		reset_interface_parameters_devconf(base_ifp);
		return;
	}
#endif

#if !defined _HAVE_IPV4_DEVCONF_ || defined _LIBNL_DYNAMIC_
	reset_interface_parameters_sysctl(base_ifp);
#endif
}
#endif

#ifdef _HAVE_VRRP_VMAC_
void link_set_ipv6(const interface_t* ifp, bool enable)
{
	/* libnl3, nor the kernel, support setting IPv6 options */
	set_sysctl("net/ipv6/conf", ifp->ifname, "disable_ipv6", enable ? 0 : 1);
}
#endif

bool get_ipv6_forwarding(const interface_t* ifp)
{
	return !!get_sysctl("net/ipv6/conf", ifp->ifname, "forwarding");
}
