/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        ipset manipulation used in conjunction with iptables
 *
 * Author:      Quentin Armitage, <quentin@armitage.org.uk>
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

/* We dynamically attempt to load the library "by hand", since keepalived
 * may have been built on a system with ipsets, but the target system may
 * not have the ipset libraries installed.
 *
 * If the ipset libraries are not installed, keepalived will fallback to
 * adding entries into iptables.
 */

#include "config.h"

#include <net/if.h>		/* Force inclusion of net/if.h before linux/if.h */
#define LIBIPSET_NFPROTO_H
#define LIBIPSET_NF_INET_ADDR_H
#if defined LIBIPSET_H_ADD_UAPI_IP_SET_H_GUARD || defined LIBIPSET_H_ADD_IP_SET_H_GUARD
#include <linux/netfilter/ipset/ip_set.h>
#if defined LIBIPSET_H_ADD_UAPI_IP_SET_H_GUARD
#define _UAPI_IP_SET_H
#else
#define _IP_SET_H
#endif
#endif
#include <libipset/session.h>
#include <libipset/types.h>
#ifndef LIBIPSET_PRE_V7_COMPAT
#include <libipset/ipset.h>
#endif
#include <netinet/in.h>
#include <linux/types.h>	/* For __beXX types in userland */
#include <linux/netfilter.h>	/* For nf_inet_addr */
#include <stdint.h>

#include "logger.h"
#include "global_data.h"
#include "vrrp_ipset.h"
#include "vrrp_firewall.h"
#include "vrrp_iptables_calls.h"
#include "main.h"
#include "utils.h"

#ifdef _LIBIPSET_DYNAMIC_
#include <dlfcn.h>

/* The addresses of the functions we want */
#ifdef LIBIPSET_PRE_V7_COMPAT
struct ipset_session* (*ipset_session_init_addr)(ipset_outfn outfn);
#else
struct ipset_session* (*ipset_session_init_addr)(ipset_print_outfn outfn, const void *p);
#endif
int (*ipset_session_fini_addr)(struct ipset_session *session);
struct ipset_data* (*ipset_session_data_addr)(const struct ipset_session *session);
#ifdef LIBIPSET_PRE_V7_COMPAT
int (*ipset_envopt_parse_addr)(struct ipset_session *session, int env, const char *str);
#else
void (*ipset_envopt_set_addr)(struct ipset_session *session, int env);
#endif
const struct ipset_type* (*ipset_type_get_addr)(struct ipset_session *session, enum ipset_cmd cmd);
int (*ipset_data_set_addr)(struct ipset_data *data, enum ipset_opt opt, const void *value);
int (*ipset_cmd_addr)(struct ipset_session *session, enum ipset_cmd cmd, uint32_t lineno);
void (*ipset_load_types_addr)(void);

/* We can (almost) make it look as though normal linking is being used */
#define ipset_session_init (*ipset_session_init_addr)
#define ipset_session_fini (*ipset_session_fini_addr)
#define ipset_session_data (*ipset_session_data_addr)
#ifdef LIBIPSET_PRE_V7_COMPAT
#define ipset_envopt_parse (*ipset_envopt_parse_addr)
#else
#define ipset_envopt_set (*ipset_envopt_set_addr)
#endif
#define ipset_type_get (*ipset_type_get_addr)
#define ipset_data_set (*ipset_data_set_addr)
/* Unfortunately ipset_cmd conflicts with struct ipset_cmd */
#define ipset_cmd1 (*ipset_cmd_addr)
#define ipset_load_types (*ipset_load_types_addr)

static void* libipset_handle;
#else
#define ipset_cmd1 ipset_cmd
#endif

static int
#ifdef LIBIPSET_PRE_V7_COMPAT
__attribute__ ((format(printf, 1, 2)))
ipset_printf(const char *fmt, ...)
#else
__attribute__ ((format(printf, 3, 4)))
ipset_printf(__attribute ((__unused__)) struct ipset_session *session, void *p, const char *fmt, ...)
#endif
{
	va_list args;

#ifndef LIBIPSET_PRE_V7_COMPAT
	log_message(LOG_INFO, "libipset message from %s", (const char *)p);
#endif

	va_start(args, fmt);
	vlog_message(LOG_INFO, fmt, args);
	va_end(args);

	return 0;
}

static bool
do_ipset_cmd(struct ipset_session* session, enum ipset_cmd cmd, const char *setname,
		const ip_address_t *addr, int cidr, uint32_t timeout, const char* iface)
{
	const struct ipset_type *type;
	uint8_t family;
	int r;

	ipset_session_data_set(session, IPSET_SETNAME, setname);

	type = ipset_type_get(session, cmd);
	if (type == NULL) {
		/* possible reasons for failure: set name does not exist */
		return false;
	}

	family = (addr->ifa.ifa_family == AF_INET) ? NFPROTO_IPV4 : NFPROTO_IPV6;
	ipset_session_data_set(session, IPSET_OPT_FAMILY, &family);
	ipset_session_data_set(session, IPSET_OPT_IP, &addr->u);
	if (cidr >= 0)
		ipset_session_data_set(session, IPSET_OPT_CIDR, &cidr);
	if (timeout)
		ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout);
	if (iface)
		ipset_session_data_set(session, IPSET_OPT_IFACE, iface);

	r = ipset_cmd1(session, cmd, 0);

	return r == 0;
}

static bool
ipset_create(struct ipset_session* session, const char *setname, const char *typename, uint8_t family)
{
	const struct ipset_type *type;
	int r;

	ipset_session_data_set(session, IPSET_SETNAME, setname);

	ipset_session_data_set(session, IPSET_OPT_TYPENAME, typename);

	type = ipset_type_get(session, IPSET_CMD_CREATE);
	if (type == NULL)
		return false;

	ipset_session_data_set(session, IPSET_OPT_TYPE, type);
	ipset_session_data_set(session, IPSET_OPT_FAMILY, &family);

	r = ipset_cmd1(session, IPSET_CMD_CREATE, 0);
	return r == 0;
}

static bool
ipset_destroy(struct ipset_session* session, const char *setname)
{
	int r;

	ipset_session_data_set(session, IPSET_SETNAME, setname);

	r = ipset_cmd1(session, IPSET_CMD_DESTROY, 0);
	return r == 0;
}

static bool
has_ipset_setname(struct ipset_session* session, const char *setname)
{
	ipset_session_data_set(session, IPSET_SETNAME, setname);

	return ipset_cmd1(session, IPSET_CMD_HEADER, 0) == 0;
}

static bool
create_sets(struct ipset_session **session, const char* addr4, const char* addr6, const char* addr_if6, const char *igmp, const char *mld, bool is_reload)
{
	if (!*session)
#ifdef LIBIPSET_PRE_V7_COMPAT
		*session = ipset_session_init(ipset_printf);
#else
		*session = ipset_session_init(ipset_printf, "create_sets");
#endif
	if (!*session) {
		log_message(LOG_INFO, "Cannot initialize ipset session.");
		return false;
	}

	/* If we aren't reloading, don't worry if sets already exists. With the
	 * IPSET_ENV_EXIST option set, any existing entries in the set are removed. */
	if (!is_reload)
#ifdef LIBIPSET_PRE_V7_COMPAT
		ipset_envopt_parse(*session, IPSET_ENV_EXIST, NULL);
#else
		ipset_envopt_set(*session, IPSET_ENV_EXIST);
#endif

	if (addr4) {
		if (!is_reload || !has_ipset_setname(*session, addr4))
			ipset_create(*session, addr4, "hash:ip", NFPROTO_IPV4);
	}

	if (addr6) {
		if (!is_reload || !has_ipset_setname(*session, addr6))
			ipset_create(*session, addr6, "hash:ip", NFPROTO_IPV6);
		if (!is_reload || !has_ipset_setname(*session, addr_if6)) {
#ifdef HAVE_IPSET_ATTR_IFACE
			/* hash:net,iface was introduced in Linux 3.1 */
			ipset_create(*session, addr_if6, "hash:net,iface", NFPROTO_IPV6);
#else
			ipset_create(*session, addr_if6, "hash:ip", NFPROTO_IPV6);
#endif
		}
	}

#ifdef HAVE_IPSET_ATTR_IFACE
	if (igmp) {
		if (!is_reload || !has_ipset_setname(*session, igmp))
			ipset_create(*session, igmp, "hash:net,iface", NFPROTO_IPV4);
	}

	if (mld) {
		if (!is_reload || !has_ipset_setname(*session, mld))
			ipset_create(*session, mld, "hash:net,iface", NFPROTO_IPV6);
	}
#endif

	return true;
}

static
bool set_match_loaded(void)
{
	char buf[XT_FUNCTION_MAXNAMELEN+1];
	FILE *fp;
	bool found = false;

	fp = fopen( "/proc/net/ip_tables_matches", "r");
	if (!fp)
		return false;

	while (fgets(buf, sizeof(buf), fp)) {
		if ((buf[3] == '\0' || buf[3] == '\n') &&
		    !strncmp(buf, "set", 3)) {
			found = true;
			break;
		}
	}

	fclose(fp);

	return found;
}

bool ipset_initialise(void)
{
#ifdef _LIBIPSET_DYNAMIC_
	if (libipset_handle)
		return true;
#endif

#if HAVE_DECL_CLONE_NEWNET
	/* Don't attempt to use ipsets if running in a namespace and the default
	 * set names have not been overridden and the kernel version is less
	 * than Linux 3.13, since ipsets didn't understand namespaces prior to that. */
	if (global_data->network_namespace &&
	    !global_data->namespace_with_ipsets &&
	    !strcmp(global_data->vrrp_ipset_address, DEFAULT_IPSET_NAME) &&
	    (os_major <= 2 ||
	     (os_major == 3 && os_minor < 13))) {
		log_message(LOG_INFO, "Not using ipsets with network namespace since not supported with kernel version < 3.13");
		return false;
	}
#endif

#ifdef _LIBIPSET_DYNAMIC_
	/* Attempt to open the ipset library */
	if (!(libipset_handle = dlopen("libipset.so", RTLD_NOW)) &&
	    !(libipset_handle = dlopen(IPSET_LIB_NAME, RTLD_NOW))) {
		log_message(LOG_INFO, "Unable to load ipset library - %s", dlerror());
		return false;
	}

	if (!(ipset_session_init_addr = dlsym(libipset_handle, "ipset_session_init")) ||
	    !(ipset_session_fini_addr = dlsym(libipset_handle, "ipset_session_fini")) ||
	    !(ipset_session_data_addr = dlsym(libipset_handle,"ipset_session_data")) ||
#ifdef LIBIPSET_PRE_V7_COMPAT
	    !(ipset_envopt_parse_addr = dlsym(libipset_handle,"ipset_envopt_parse")) ||
#else
	    !(ipset_envopt_set_addr = dlsym(libipset_handle,"ipset_envopt_set")) ||
#endif
	    !(ipset_type_get_addr = dlsym(libipset_handle,"ipset_type_get")) ||
	    !(ipset_data_set_addr = dlsym(libipset_handle,"ipset_data_set")) ||
	    !(ipset_cmd_addr = dlsym(libipset_handle,"ipset_cmd")) ||
	    !(ipset_load_types_addr = dlsym(libipset_handle,"ipset_load_types"))) {
		log_message(LOG_INFO, "Failed to dynamic link an ipset function - %s", dlerror());
		return false;
	}
#endif

	ipset_load_types();

	if (!set_match_loaded() && keepalived_modprobe("xt_set")) {
		log_message(LOG_INFO, "Unable to load module xt_set - not using ipsets");
		return false;
	}

	return true;
}

// TODO - just revert to single call to remove_ipsets
static bool
remove_ipsets(struct ipset_session **session, uint8_t family, bool vip_sets)
{
	if (!global_data->using_ipsets)
		return true;

#ifdef _LIBIPSET_DYNAMIC_
	if (!libipset_handle)
		return true;
#endif

	if (!*session)
#ifdef LIBIPSET_PRE_V7_COMPAT
		*session = ipset_session_init(ipset_printf);
#else
		*session = ipset_session_init(ipset_printf, "remove_ipsets");
#endif
	if (!*session) {
		log_message(LOG_INFO, "Cannot initialize ipset session.");
		return false;
	}

	if (vip_sets) {
		if (family == AF_INET)
			ipset_destroy(*session, global_data->vrrp_ipset_address);
		else {
			ipset_destroy(*session, global_data->vrrp_ipset_address6);
			ipset_destroy(*session, global_data->vrrp_ipset_address_iface6);
		}
	}
#ifdef HAVE_IPSET_ATTR_IFACE
	else {
		if (family == AF_INET)
			ipset_destroy(*session, global_data->vrrp_ipset_igmp);
		else
			ipset_destroy(*session, global_data->vrrp_ipset_mld);
	}
#endif

	return true;
}

bool
remove_vip_ipsets(struct ipset_session **session, uint8_t family)
{
	return remove_ipsets(session, family, true);
}

bool
remove_igmp_ipsets(struct ipset_session **session, uint8_t family)
{
	return remove_ipsets(session, family, false);
}

bool add_vip_ipsets(struct ipset_session **session, uint8_t family, bool is_reload)
{
	if (family == AF_INET)
		return create_sets(session, global_data->vrrp_ipset_address, NULL, NULL, NULL, NULL, is_reload);

	return create_sets(session, NULL, global_data->vrrp_ipset_address6, global_data->vrrp_ipset_address_iface6, NULL, NULL, is_reload);
}

#ifdef HAVE_IPSET_ATTR_IFACE
bool add_igmp_ipsets(struct ipset_session **session, uint8_t family, bool is_reload)
{
	if (family == AF_INET)
		return create_sets(session, NULL, NULL, NULL, global_data->vrrp_ipset_igmp, NULL, is_reload);

	return create_sets(session, NULL, NULL, NULL, NULL, global_data->vrrp_ipset_mld, is_reload);
}
#endif

void* ipset_session_start(void)
{
#ifdef LIBIPSET_PRE_V7_COMPAT
	return ipset_session_init(ipset_printf);
#else
	return ipset_session_init(ipset_printf, "session_start");
#endif
}

void ipset_session_end(void* vsession)
{
	struct ipset_session *session = vsession;

	ipset_session_fini(session);
}

void ipset_entry(void* vsession, int cmd, const ip_address_t* addr)
{
	const char* set;
	char *iface = NULL;
	struct ipset_session *session = vsession;


	if (addr->ifa.ifa_family == AF_INET)
		set = global_data->vrrp_ipset_address;
	else if (IN6_IS_ADDR_LINKLOCAL(&addr->u.sin6_addr)) {
		set = global_data->vrrp_ipset_address_iface6;
#ifdef HAVE_IPSET_ATTR_IFACE
		iface = addr->ifp->ifname;
#endif
	}
	else
		set = global_data->vrrp_ipset_address6;

	do_ipset_cmd(session, (cmd == IPADDRESS_DEL) ? IPSET_CMD_DEL : IPSET_CMD_ADD, set, addr, -1, 0, iface);
}

#ifdef HAVE_IPSET_ATTR_IFACE
void ipset_entry_igmp(void* vsession, int cmd, const char* ifname, uint8_t family)
{
	const char* set;
	struct ipset_session *session = vsession;
	ip_address_t addr = { .ifa.ifa_family = AF_INET };

	if (family == AF_INET) {
		set = global_data->vrrp_ipset_igmp;
	} else {
		set = global_data->vrrp_ipset_mld;
		addr.ifa.ifa_family = AF_INET6;
	}

	do_ipset_cmd(session, (cmd == IPADDRESS_DEL) ? IPSET_CMD_DEL : IPSET_CMD_ADD, set, &addr, 0, 0, ifname);
}
#endif
