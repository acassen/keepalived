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
 * Copyright (C) 2001-2016 Alexandre Cassen, <acassen@gmail.com>
 */

/* We dynamically attempt to load the library "by hand", since keepalived
 * may have been built on a system with ipsets, but the target system may
 * not have the ipset libraries installed.
 *
 * If the ipset libraries are not installed, keepalived will fallback to
 * adding entries into iptables.
 */

#include <unistd.h>
#include <libipset/types.h>
#include <libipset/session.h>
#include <libipset/data.h>
#include <stdint.h>
#include <dlfcn.h>

#include "logger.h"
#include "global_data.h"
#include "vrrp_iptables.h"
#include "vrrp_ipset.h"
#include "vrrp_ipaddress.h"

/* The addresses of the functions we want */
struct ipset_session* (*ipset_session_init_addr)(ipset_outfn outfn);
int (*ipset_session_fini_addr)(struct ipset_session *session);
struct ipset_data* (*ipset_session_data_addr)(const struct ipset_session *session);
const char* (*ipset_session_error_addr)(const struct ipset_session *session);
int (*ipset_envopt_parse_addr)(struct ipset_session *session, int env, const char *str);
const struct ipset_type* (*ipset_type_get_addr)(struct ipset_session *session, enum ipset_cmd cmd);
int (*ipset_data_set_addr)(struct ipset_data *data, enum ipset_opt opt, const void *value);
int (*ipset_cmd_addr)(struct ipset_session *session, enum ipset_cmd cmd, uint32_t lineno);
void (*ipset_load_types_addr)(void);

/* We can (almost) make it look as though normal linking is being used */
#define ipset_session_init (*ipset_session_init_addr)
#define ipset_session_fini (*ipset_session_fini_addr)
#define ipset_session_data (*ipset_session_data_addr)
#define ipset_session_error (*ipset_session_error_addr)
#define ipset_envopt_parse (*ipset_envopt_parse_addr)
#define ipset_type_get (*ipset_type_get_addr)
#define ipset_data_set (*ipset_data_set_addr)
/* Unfortunately ipset_cmd conflicts with struct ipset_cmd */
#define ipset_cmd1 (*ipset_cmd_addr)
#define ipset_load_types (*ipset_load_types_addr)

static void* libipset_handle;

static bool
do_ipset_cmd(struct ipset_session* session, enum ipset_cmd cmd, const char *setname,
		const ip_address_t *addr, uint32_t timeout, const char* iface)
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

bool
has_ipset_setname(struct ipset_session* session, const char *setname)
{
	ipset_session_data_set(session, IPSET_SETNAME, setname);

	return ipset_cmd1(session, IPSET_CMD_HEADER, 0) == 0;
}

static int create_sets(const char* addr4, const char* addr6, const char* addr_if6)
{
	struct ipset_session *session;

	session = ipset_session_init(printf);
	if (!session) {
		log_message(LOG_INFO, "Cannot initialize ipset session.");
		return false;
	}

	/* don't worry if sets already exist */
	ipset_envopt_parse(session, IPSET_ENV_EXIST, NULL);

	ipset_create(session, addr4, "hash:ip", NFPROTO_IPV4);
	ipset_create(session, addr6, "hash:ip", NFPROTO_IPV6);
	ipset_create(session, addr_if6, "hash:net,iface", NFPROTO_IPV6);

	ipset_session_fini(session);

	return true;
}

bool ipset_init(void)
{
	if (libipset_handle)
		return true;

	libipset_handle = dlopen("libipset.so", RTLD_NOW);

	if (!libipset_handle) {
		log_message(LOG_INFO, "Unable to load ipset library");
		return false;
	}

	ipset_session_init_addr = dlsym(libipset_handle, "ipset_session_init");
	ipset_session_fini_addr = dlsym(libipset_handle, "ipset_session_fini");
	ipset_session_data_addr = dlsym(libipset_handle,"ipset_session_data");
	ipset_session_error_addr = dlsym(libipset_handle,"ipset_session_error");
	ipset_envopt_parse_addr = dlsym(libipset_handle,"ipset_envopt_parse");
	ipset_type_get_addr = dlsym(libipset_handle,"ipset_type_get");
	ipset_data_set_addr = dlsym(libipset_handle,"ipset_data_set");
	ipset_cmd_addr = dlsym(libipset_handle,"ipset_cmd");
	ipset_load_types_addr = dlsym(libipset_handle,"ipset_load_types");

	ipset_load_types();

	if (!load_mod_xt_set())
		return false;

	return true;
}

int remove_ipsets(void)
{
	struct ipset_session *session;

	session = ipset_session_init(printf);
	if (!session) {
		log_message(LOG_INFO, "Cannot initialize ipset session.");
		return false;
	}

	ipset_destroy(session, global_data->vrrp_ipset_address);
	ipset_destroy(session, global_data->vrrp_ipset_address6);
	ipset_destroy(session, global_data->vrrp_ipset_address_iface6);

	ipset_session_fini(session);

	return true;
}

int add_ipsets(void)
{
	return create_sets(global_data->vrrp_ipset_address, global_data->vrrp_ipset_address6, global_data->vrrp_ipset_address_iface6);
}

struct ipset_session* ipset_session_start(void)
{
	return ipset_session_init(NULL);
}

void ipset_session_end(struct ipset_session* session)
{
	ipset_session_fini(session);
}

void ipset_entry(struct ipset_session* session, int cmd, const ip_address_t* addr, const char* iface)
{
	const char* set;

	if (addr->ifa.ifa_family == AF_INET)
		set = global_data->vrrp_ipset_address;
	else if (IN6_IS_ADDR_LINKLOCAL(&addr->u.sin6_addr))
		set = global_data->vrrp_ipset_address_iface6;
	else
		set = global_data->vrrp_ipset_address6;
	if (cmd == IPADDRESS_DEL)
		do_ipset_cmd(session, IPSET_CMD_DEL, set, addr, 0, iface);
	else
		do_ipset_cmd(session, IPSET_CMD_ADD, set, addr, 0, iface);
}
