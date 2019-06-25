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

typedef struct sysctl_opts {
	uint32_t	param;
	uint32_t	value;
} sysctl_opts_t;

#ifdef _HAVE_VRRP_VMAC_
static sysctl_opts_t parent_sysctl[] = {
	{ IPV4_DEVCONF_ARP_IGNORE, 1 },
	{ IPV4_DEVCONF_ARPFILTER, 1 },
	{ 0, 0 }
};

static sysctl_opts_t vmac_sysctl[] = {
	{ IPV4_DEVCONF_ARP_IGNORE, 1 },
	{ IPV4_DEVCONF_ACCEPT_LOCAL, 1 },
	{ IPV4_DEVCONF_RP_FILTER, 0 },
	{ IPV4_DEVCONF_PROMOTE_SECONDARIES, 1 },
	{ 0, 0}
};

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

#if !defined _HAVE_IPV4_DEVCONF_ || defined _HAVE_VRRP_VMAC_
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
#endif

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
	if (len <= 0 || buf[0] < '0' || buf[0] > '9')
		return UINT_MAX;

	/* Return the value of the string read */
	return (unsigned)buf[0] - '0';
}

#ifdef _HAVE_IPV4_DEVCONF_
static struct nlattr *
nest_start(struct nlmsghdr *nlh, unsigned short type)
{
	struct nlattr *nest = NLMSG_TAIL(nlh);

	nest->nla_type = type;
	nlh->nlmsg_len += sizeof(struct nlattr);

	return nest;
}

static size_t
nest_end(struct nlattr *nla, struct nlattr *nest)
{
	nest->nla_len = (unsigned short)((char *)nla - (char *)nest);

	return nest->nla_len;
}

static inline int
netlink_set_interface_flags(int ifindex, const sysctl_opts_t *sys_opts)
{
	int status = 0;
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[64];
	} req;
	struct nlattr *start;
	struct nlattr *inet_start;
	struct nlattr *conf_start;
	const sysctl_opts_t *so;

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = ifindex;

	start = nest_start(&req.n, IFLA_AF_SPEC);
	inet_start = nest_start(&req.n, AF_INET);
	conf_start = nest_start(&req.n, IFLA_INET_CONF);

	for (so = sys_opts; so->param; so++)
		addattr32(&req.n, sizeof req, so->param, so->value);

	nest_end(NLMSG_TAIL(&req.n), conf_start);
	nest_end(NLMSG_TAIL(&req.n), inet_start);
	nest_end(NLMSG_TAIL(&req.n), start);

	if (netlink_talk(&nl_cmd, &req.n) < 0)
		status = 1;

	return status;
}

#ifdef _HAVE_VRRP_VMAC_
static inline int
netlink_set_interface_parameters(const interface_t *ifp, interface_t *base_ifp)
{
	if (netlink_set_interface_flags(ifp->ifindex, vmac_sysctl))
		return -1;

	/* If the underlying interface is a MACVLAN that has been moved into
	 * a separate network namespace from the parent, we can't access the
	 * parent. */
	if (IS_VLAN(ifp) && ifp == base_ifp)
		return 0;

	/* Set arp_ignore and arp_filter on base interface if needed */
	if (base_ifp->reset_arp_config)
		base_ifp->reset_arp_config++;
	else {
		if (base_ifp->arp_ignore != 1 ||
		    base_ifp->arp_filter != 1) {
			/* We can't use libnl3 since if the base interface type is a bridge, libnl3 sets ifi_family
			 * to AF_BRIDGE, whereas it should be set to AF_UNSPEC. The kernel function that handles
			 * RTM_SETLINK messages for AF_BRIDGE doesn't know how to process the IFLA_AF_SPEC attribute. */
			if (netlink_set_interface_flags(base_ifp->ifindex, parent_sysctl)) {
				log_message(LOG_INFO, "Set base flags on %s failed for VMAC %s", base_ifp->ifname, ifp->ifname);
				return -1;
			}
			base_ifp->reset_arp_config = 1;
		}
	}

	return 0;
}

static inline int
netlink_reset_interface_parameters(const interface_t* ifp)
{
	int res;
	sysctl_opts_t reset_parent_sysctl[3];

	/* If the interface doesn't exist, there is nothing we can change */
	if (!ifp->ifindex)
		return 0;

	/* See netlink3_set_interface_parameters for why libnl3 can't be used */
	reset_parent_sysctl[0].param = IPV4_DEVCONF_ARP_IGNORE;
	reset_parent_sysctl[0].value = ifp->arp_ignore;
	reset_parent_sysctl[1].param = IPV4_DEVCONF_ARPFILTER;
	reset_parent_sysctl[1].value = ifp->arp_filter;
	reset_parent_sysctl[2].param = 0;

	if ((res = netlink_set_interface_flags(ifp->ifindex, reset_parent_sysctl)))
		log_message(LOG_INFO, "reset interface flags on %s failed", ifp->ifname);

	return res;
}

static inline void
set_interface_parameters_devconf(const interface_t *ifp, interface_t *base_ifp)
{
	if (netlink_set_interface_parameters(ifp, base_ifp))
		log_message(LOG_INFO, "Unable to set parameters for %s", ifp->ifname);
}

static inline void
reset_interface_parameters_devconf(interface_t *base_ifp)
{
	if (base_ifp->reset_arp_config && --base_ifp->reset_arp_config == 0) {
		if (netlink_reset_interface_parameters(base_ifp))
			log_message(LOG_INFO, "Unable to reset parameters for %s", base_ifp->ifname);
	}
}
#endif

static inline void
set_promote_secondaries_devconf(interface_t *ifp)
{
	sysctl_opts_t promote_secondaries_sysctl[] = { { IPV4_DEVCONF_PROMOTE_SECONDARIES, 1 }, { 0, 0} };

	if (ifp->promote_secondaries)
		return;

	netlink_set_interface_flags(ifp->ifindex, promote_secondaries_sysctl);
}

static inline void
reset_promote_secondaries_devconf(interface_t *ifp)
{
	sysctl_opts_t promote_secondaries_sysctl[] = { { IPV4_DEVCONF_PROMOTE_SECONDARIES, 0 }, { 0, 0} };

	netlink_set_interface_flags(ifp->ifindex, promote_secondaries_sysctl);
}

#else

#ifdef _HAVE_VRRP_VMAC_
static inline void
set_interface_parameters_sysctl(const interface_t *ifp, interface_t *base_ifp)
{
	unsigned val;

	set_sysctl("net/ipv4/conf", ifp->ifname, "arp_ignore", 1);
	set_sysctl("net/ipv4/conf", ifp->ifname, "accept_local", 1);
	set_sysctl("net/ipv4/conf", ifp->ifname, "rp_filter", 0);

	set_sysctl("net/ipv4/conf", ifp->ifname, "promote_secondaries", 1);

	/* If the underlying interface is a MACVLAN that has been moved into
	 * a separate network namespace from the parent, we can't access the
	 * parent. */
	if (IS_VLAN(ifp) && ifp == base_ifp)
		return;

	if (base_ifp->reset_arp_config)
		base_ifp->reset_arp_config++;
	else {
		if ((val = get_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_ignore")) != UINT_MAX &&
		    (base_ifp->arp_ignore = (uint32_t)val) != 1)
			set_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_ignore", 1);

		if ((val = get_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_filter")) != UINT_MAX &&
		    (base_ifp->arp_filter = (uint32_t)val) != 1)
			set_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_filter", 1);

		base_ifp->reset_arp_config = 1;
	}
}

static inline void
reset_interface_parameters_sysctl(interface_t *base_ifp)
{
	if (base_ifp->reset_arp_config && --base_ifp->reset_arp_config == 0) {
		set_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_ignore", (int)base_ifp->arp_ignore);
		set_sysctl("net/ipv4/conf", base_ifp->ifname, "arp_filter", (int)base_ifp->arp_filter);
	}
}
#endif

static inline void
set_promote_secondaries_sysctl(interface_t *ifp)
{
	if (get_sysctl("net/ipv4/conf", ifp->ifname, "promote_secondaries") == 1) {
		ifp->promote_secondaries = true;
		return;
	}
	set_sysctl("net/ipv4/conf", ifp->ifname, "promote_secondaries", 1);
}

static inline void
reset_promote_secondaries_sysctl(interface_t *ifp)
{
	set_sysctl("net/ipv4/conf", ifp->ifname, "promote_secondaries", 0);
}
#endif

void
set_promote_secondaries(interface_t *ifp)
{
	if (ifp->promote_secondaries)
		return;

	if (ifp->reset_promote_secondaries++)
		return;

#ifdef _HAVE_IPV4_DEVCONF_
	set_promote_secondaries_devconf(ifp);
#else
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
	reset_promote_secondaries_devconf(ifp);
#else
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
#ifdef _HAVE_IPV4_DEVCONF_
	sysctl_opts_t rpfilter_sysctl[] = { { IPV4_DEVCONF_RP_FILTER, 1 }, { 0, 0} };
#endif

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
		log_message(LOG_INFO, "NOTICE: setting sysctl net.ipv4.conf.default.rp_filter from %u to %u", rp_filter, all_rp_filter);
		set_sysctl("net/ipv4/conf", "default", "rp_filter", all_rp_filter);
		default_rp_filter = rp_filter;
	}

	/* Now ensure rp_filter for all interfaces is at least all/rp_filter. */
#ifdef _HAVE_IPV4_DEVCONF_
	rpfilter_sysctl[0].value = all_rp_filter;
#endif
	kernel_netlink_poll();		/* Update our view of interfaces first */
	ifs = get_if_list();
	LIST_FOREACH(ifs, ifp, e) {
		if (!ifp->ifindex)
			continue;
#ifndef _HAVE_IPV4_DEVCONF_
		if ((ifp->rp_filter = get_sysctl("net/ipv4/conf", ifp->ifname, "rp_filter")) == UINT_MAX)
			log_message(LOG_INFO, "Unable to read rp_filter for %s", ifp->ifname);
		else
#endif
		if (ifp->rp_filter < all_rp_filter) {
#ifdef _HAVE_IPV4_DEVCONF_
			netlink_set_interface_flags(ifp->ifindex, rpfilter_sysctl);
#else
			set_sysctl("net/ipv4/conf", ifp->ifname, "rp_filter", all_rp_filter);
#endif
		}
		else {
			/* Indicate we are not setting it */
			ifp->rp_filter = UINT_MAX;
		}
	}

	/* We have now made sure that all the interfaces have rp_filter >= all_rp_filter */
	log_message(LOG_INFO, "NOTICE: setting sysctl net.ipv4.conf.all.rp_filter from %u to 0", all_rp_filter);
	set_sysctl("net/ipv4/conf", "all", "rp_filter", 0);
}

void
restore_rp_filter(void)
{
	list ifs;
	element e;
	interface_t *ifp;
	unsigned rp_filter;
#ifdef _HAVE_IPV4_DEVCONF_
	sysctl_opts_t rpfilter_sysctl[] = { { IPV4_DEVCONF_RP_FILTER, 1 }, { 0, 0} };
#endif

	/* Restore the original settings of rp_filter, but only if they
	 * are the same as what we set them to */
	if (all_rp_filter == UINT_MAX)
		return;

	rp_filter = get_sysctl("net/ipv4/conf", "all", "rp_filter");
	if (rp_filter == 0) {
		log_message(LOG_INFO, "NOTICE: resetting sysctl net.ipv4.conf.all.rp_filter to %u", all_rp_filter);
		set_sysctl("net/ipv4/conf", "all", "rp_filter", all_rp_filter);
	}

	if (default_rp_filter != UINT_MAX) {
		rp_filter = get_sysctl("net/ipv4/conf", "default", "rp_filter");
		if (rp_filter == all_rp_filter) {
			log_message(LOG_INFO, "NOTICE: resetting sysctl net.ipv4.conf.default.rp_filter to %u", default_rp_filter);
			set_sysctl("net/ipv4/conf", "default", "rp_filter", default_rp_filter);
		}
		default_rp_filter = UINT_MAX;
	}

	ifs = get_if_list();
	LIST_FOREACH(ifs, ifp, e) {
		if (ifp->rp_filter != UINT_MAX) {
			rp_filter = get_sysctl("net/ipv4/conf", ifp->ifname, "rp_filter");
			if (rp_filter == all_rp_filter) {
#ifdef _HAVE_IPV4_DEVCONF_
				rpfilter_sysctl[0].value = ifp->rp_filter;
				netlink_set_interface_flags(ifp->ifindex, rpfilter_sysctl);
#else
				set_sysctl("net/ipv4/conf", ifp->ifname, "rp_filter", ifp->rp_filter);
#endif
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
	set_interface_parameters_devconf(ifp, base_ifp);
#else
	set_interface_parameters_sysctl(ifp, base_ifp);
#endif
}

void reset_interface_parameters(interface_t *base_ifp)
{
#ifdef _HAVE_IPV4_DEVCONF_
	reset_interface_parameters_devconf(base_ifp);
#else
	reset_interface_parameters_sysctl(base_ifp);
#endif
}

void link_set_ipv6(const interface_t* ifp, bool enable)
{
	/* There is no direct way to set IPv6 options */
	set_sysctl("net/ipv6/conf", ifp->ifname, "disable_ipv6", enable ? 0 : 1);
}
#endif

void
set_ipv6_forwarding(interface_t* ifp)
{
	ifp->gna_router = !!get_sysctl("net/ipv6/conf", ifp->ifname, "forwarding");
	ifp->last_gna_router_check = time_now;
}
