
/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        iptables management
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
 * Copyright (C) 2001-2018 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <errno.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <linux/magic.h>

#include "warnings.h"
#include "logger.h"
#include "vrrp_iptables.h"

#include "global_data.h"
#include "vrrp_ipaddress.h"
#include "vrrp.h"
#ifdef _HAVE_LIBIPTC_
#include "vrrp_iptables_lib.h"
#endif
#ifdef _USE_IPTABLES_CMD_
#include "vrrp_iptables_cmd.h"
#endif
#include "vrrp_firewall.h"


/* Element [0] is IPv4, element [1] is IPv6 */
static init_state_t setup[2];
static init_state_t setup_vips[2];
static init_state_t setup_igmp[2];
#ifdef _LIBIPTC_DYNAMIC_
static bool using_libiptc[2];
#endif

static init_state_t
check_chains_exist(int family)
{
#ifdef _HAVE_LIBIPTC_
#ifdef _LIBIPTC_DYNAMIC_
	if (using_libiptc[family != AF_INET])
#endif
		return check_chains_exist_lib(family);
#endif

#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
	return check_chains_exist_cmd(family);
#endif
}

/* return true if a given file exists within procfs */
/* Taken from iptables code */
static bool
proc_file_exists(const char *filename)
{
	struct stat s;
	struct statfs f;

	if (lstat(filename, &s))
		return false;
	if (!S_ISREG(s.st_mode))
		return false;
	if (statfs(filename, &f))
		return false;
	if (f.f_type != PROC_SUPER_MAGIC)
		return false;

	return true;
}

static bool
iptables_init(int family)
{
	if (family == AF_INET) {
		if (!proc_file_exists("/proc/net/ip_tables_names"))
		{
			log_message(LOG_INFO, "iptables chain not setup");
			setup[family != AF_INET] = INIT_FAILED;
			return false;
		}
	} else {
		if (!proc_file_exists("/proc/net/ip6_tables_names"))
		{
			log_message(LOG_INFO, "ip6tables chain not setup");
			setup[family != AF_INET] = INIT_FAILED;
			return false;
		}
	}

#ifdef _HAVE_LIBIPTC_
	setup[family != AF_INET] = iptables_init_lib(family);
#ifdef _LIBIPTC_DYNAMIC_
	using_libiptc[family != AF_INET] = setup[family != AF_INET] == INIT_SUCCESS;
#endif
#endif

#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
	if (setup[family != AF_INET] != INIT_SUCCESS)
		setup[family != AF_INET] = iptables_init_cmd(family);
#endif

	if (setup[family != AF_INET] != INIT_SUCCESS)
		return false;

	setup[family != AF_INET] = check_chains_exist(family);

	return setup[family != AF_INET] == INIT_SUCCESS;
}

RELAX_SUGGEST_ATTRIBUTE_CONST_START
void
iptables_fini(void)
{
#ifdef _HAVE_LIBIPTC_
	iptables_fini_lib();
#endif
#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
	iptables_fini_cmd();
#endif
}
RELAX_SUGGEST_ATTRIBUTE_CONST_END

static bool
do_setup_vips(int family)
{
	if (setup[family != AF_INET] == NOT_INIT)
		iptables_init(family);

	if (setup[family != AF_INET] == INIT_FAILED) {
		setup_vips[family != AF_INET] = INIT_FAILED;
		return false;
	}

	setup_vips[family != AF_INET] = INIT_SUCCESS;
	return true;
}

static bool
do_setup_igmp(int family)
{
	if (setup[family != AF_INET] == NOT_INIT) {
		iptables_init(family);
		return false;
	}

	if (setup[family != AF_INET] == INIT_FAILED) {
		setup_igmp[family != AF_INET] = INIT_FAILED;
		return false;
	}

	setup_igmp[family != AF_INET] = INIT_SUCCESS;
	return true;
}

static inline void
handle_iptable_rule_to_vip(ip_address_t *ipaddr, int cmd,
#ifdef _HAVE_LIBIPTC_
							     struct ipt_handle *h,
#else
							     __attribute__((unused)) void *unused,
#endif
												   bool force)
{
#ifdef _HAVE_LIBIPTC_
#ifdef _LIBIPTC_DYNAMIC_
	if (using_libiptc[ipaddr->ifa.ifa_family != AF_INET])
#endif
	{
		handle_iptable_rule_to_vip_lib(ipaddr, cmd, h, force);
		return;
	}
#endif

#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
	handle_iptable_rule_to_vip_cmd(ipaddr, cmd, force);
#endif
}

/* add/remove iptable drop rules to iplist */
static void
handle_iptable_vip_list(
#ifdef _HAVE_LIBIPTC_
		        struct ipt_handle **h,
#else
		        void **h,
#endif
			list ip_list, int cmd, bool force)
{
	ip_address_t *ipaddr;
	element e;

	LIST_FOREACH(ip_list, ipaddr, e) {
		if (setup_vips[ipaddr->ifa.ifa_family != AF_INET] == NOT_INIT)
			do_setup_vips(ipaddr->ifa.ifa_family);

		if (setup_vips[ipaddr->ifa.ifa_family != AF_INET] == INIT_FAILED)
			continue;

		if ((cmd == IPADDRESS_DEL) == ipaddr->iptable_rule_set || force)
		{
#if defined _HAVE_LIBIPTC_ && defined _LIBIPTC_DYNAMIC_
			if (!*h && using_libiptc[IP_IS6(ipaddr)])
				*h = iptables_open(cmd);
#endif
			handle_iptable_rule_to_vip(ipaddr, cmd, *h, force);
		}
	}
}

void
handle_iptable_rule_to_iplist(list ip_list1, list ip_list2, int cmd, bool force)
{
#ifdef _HAVE_LIBIPTC_
	struct ipt_handle *h = NULL;
	int tries = 0;
	int res = 0;
#else
	void *h = NULL;
#endif

	/* No addresses in this list */
	if (LIST_ISEMPTY(ip_list1) && LIST_ISEMPTY(ip_list2))
		return;

#ifdef _HAVE_LIBIPTC_
        do {
#ifndef _LIBIPTC_DYNAMIC_
		h = iptables_open(cmd);
#endif
#endif
		if (!LIST_ISEMPTY(ip_list1))
			handle_iptable_vip_list(&h, ip_list1, cmd, force);
		if (!LIST_ISEMPTY(ip_list2))
			handle_iptable_vip_list(&h, ip_list2, cmd, force);

#ifdef _HAVE_LIBIPTC_
#ifdef _LIBIPTC_DYNAMIC_
                if (h)
#endif
                        res = iptables_close(h);
		h = NULL;
        } while (res == EAGAIN && ++tries < IPTABLES_MAX_TRIES);
#endif
}

void
handle_iptables_accept_mode(vrrp_t *vrrp, int cmd, bool force)
{
	handle_iptable_rule_to_iplist(vrrp->vip, vrrp->evip, cmd, force);
}

#ifdef _HAVE_VRRP_VMAC_
static inline void
handle_iptable_rule_for_igmp(const char *ifname, int cmd, int family,
#ifdef _HAVE_LIBIPTC_
			     struct ipt_handle **h
#else
			     __attribute__((unused)) void *unused
#endif
								 )
{
	if (setup_igmp[family != AF_INET] == NOT_INIT)
		do_setup_igmp(family);

	if (setup_igmp[family != AF_INET] == INIT_FAILED)
		return;

#if defined _HAVE_LIBIPTC_ && defined _LIBIPTC_DYNAMIC_
	if (!*h && using_libiptc[family == AF_INET6])
		*h = iptables_open(cmd);
#endif

#ifdef _HAVE_LIBIPTC_
#ifdef _LIBIPTC_DYNAMIC_
	if (using_libiptc[family == AF_INET6])
#endif
	{
		handle_iptable_rule_for_igmp_lib(ifname, cmd, family, *h);
		return;
	}
#endif

#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
	handle_iptable_rule_for_igmp_cmd(ifname, cmd, family);
#endif
}

static void
iptables_update_vmac(const vrrp_t *vrrp, int cmd)
{
#ifdef _HAVE_LIBIPTC_
	struct ipt_handle *h = NULL;
	int tries = 0;
	int res = 0;
#else
	void *h = NULL;
#endif

#ifdef _HAVE_LIBIPTC_
        do {
// WHY ?
#ifndef _LIBIPTC_DYNAMIC_
		h = iptables_open(cmd);
#endif
#endif

		handle_iptable_rule_for_igmp(vrrp->ifp->ifname, cmd, vrrp->family, &h);

		if (vrrp->evip_other_family)
			handle_iptable_rule_for_igmp(vrrp->ifp->ifname, cmd, vrrp->family == AF_INET ? AF_INET6 : AF_INET, &h);
#ifdef _HAVE_LIBIPTC_
#ifdef _LIBIPTC_DYNAMIC_
                if (h)
#endif
                        res = iptables_close(h);
        } while (res == EAGAIN && ++tries < IPTABLES_MAX_TRIES);
#endif
}

void
iptables_add_vmac(const vrrp_t *vrrp)
{
	iptables_update_vmac(vrrp, IPADDRESS_ADD);
}

void
iptables_remove_vmac(const vrrp_t *vrrp)
{
	iptables_update_vmac(vrrp, IPADDRESS_DEL);
}
#endif
