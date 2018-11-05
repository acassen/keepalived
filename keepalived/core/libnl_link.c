/*
 * libnl_link:	Handle dynamic linking to netlink libraries
 *
 * Authors:	P. Quentin Armitage <Quentin@Armitage.org.uk>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *  Copyright (C) 2017-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#ifdef _LIBNL_DYNAMIC_

#include <stdbool.h>

#include <dlfcn.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>

#ifdef LIBIPVS_USE_NL
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#endif

#include "libnl_link.h"
#include "logger.h"


/* The addresses of the functions we want */
struct nl_sock * (*nl_socket_alloc_addr)(void);
void (*nl_socket_free_addr)(struct nl_sock *);
#ifdef LIBIPVS_USE_NL
int (*genl_connect_addr)(struct nl_sock *);
int (*genl_ctrl_resolve_addr)(struct nl_sock *, const char *);
int (*genlmsg_parse_addr)(struct nlmsghdr *, int, struct nlattr **, int, struct nla_policy *);
void * (*genlmsg_put_addr)(struct nl_msg *, uint32_t, uint32_t, int, int, int, uint8_t, uint8_t);
int (*nla_nest_end_addr)(struct nl_msg *, struct nlattr *);
struct nlattr * (*nla_nest_start_addr)(struct nl_msg *, int);
int (*nla_put_daddr)(struct nl_msg *, int, int, const void *);
struct nl_msg * (*nlmsg_alloc_addr)(void);
void (*nlmsg_free_addr)(struct nl_msg *);
struct nlmsghdr * (*nlmsg_hdr_addr)(struct nl_msg *);
int (*nl_recvmsgs_default_addr)(struct nl_sock *);
int (*nl_send_auto_complete_addr)(struct nl_sock *,  struct nl_msg *);
int (*nl_socket_modify_cb_addr)(struct nl_sock *, enum nl_cb_type, enum nl_cb_kind, nl_recvmsg_msg_cb_t, void *);
#ifdef _HAVE_LIBNL3_
void * (*nla_data_addr)(const struct nlattr *);
int32_t (*nla_get_s32_addr)(const struct nlattr *);
char * (*nla_get_string_addr)(const struct nlattr *);
uint16_t (*nla_get_u16_addr)(const struct nlattr *);
uint32_t (*nla_get_u32_addr)(const struct nlattr *);
uint64_t (*nla_get_u64_addr)(const struct nlattr *);
int (*nla_memcpy_addr)(void *, const struct nlattr *, int);
int (*nla_parse_nested_addr)(struct nlattr **, int, struct nlattr *, struct nla_policy *);
#endif
#endif


static void* libnl_handle;
#ifdef LIBIPVS_USE_NL
static void* libnl_genl_handle;
#endif

bool
libnl_init(void)
{
	if (libnl_handle)
		return true;

	/* Attempt to open the necessary libraries */
#ifdef _HAVE_LIBNL1_
#ifdef _WITH_LVS_
	if (!(libnl_handle = dlopen("libnl.so", RTLD_NOW)) &&
	    !(libnl_handle = dlopen(NL_LIB_NAME, RTLD_NOW))) {
		log_message(LOG_INFO, "Unable to load nl library - %s", dlerror());
		return false;
	}
	libnl_genl_handle = libnl_handle;
#endif
#else
	if (!(libnl_handle = dlopen("libnl-3.so", RTLD_NOW)) &&
	    !(libnl_handle = dlopen(NL3_LIB_NAME, RTLD_NOW))) {
		log_message(LOG_INFO, "Unable to load nl-3 library - %s", dlerror());
		return false;
	}
#ifdef _WITH_LVS_
	if (!(libnl_genl_handle = dlopen("libnl-genl-3.so", RTLD_NOW)) &&
	    !(libnl_genl_handle = dlopen(NL3_GENL_LIB_NAME, RTLD_NOW))) {
		log_message(LOG_INFO, "Unable to load nl-genl-3 library - %s", dlerror());
		return false;
	}
#endif
#endif

	if (
#ifdef _HAVE_LIBNL1_
	    !(nl_socket_alloc_addr = dlsym(libnl_handle, "nl_handle_alloc")) ||
	    !(nl_socket_free_addr = dlsym(libnl_handle, "nl_handle_destroy")) ||
#else
	    !(nl_socket_alloc_addr = dlsym(libnl_handle, "nl_socket_alloc")) ||
	    !(nl_socket_free_addr = dlsym(libnl_handle, "nl_socket_free")) ||
#endif
#ifdef _WITH_LVS_
	    !(genl_connect_addr = dlsym(libnl_genl_handle, "genl_connect")) ||
	    !(genl_ctrl_resolve_addr = dlsym(libnl_genl_handle, "genl_ctrl_resolve")) ||
	    !(genlmsg_parse_addr = dlsym(libnl_genl_handle, "genlmsg_parse")) ||
	    !(genlmsg_put_addr = dlsym(libnl_genl_handle, "genlmsg_put")) ||
	    !(nla_nest_end_addr = dlsym(libnl_handle, "nla_nest_end")) ||
	    !(nla_nest_start_addr = dlsym(libnl_handle, "nla_nest_start")) ||
	    !(nla_put_daddr = dlsym(libnl_handle, "nla_put")) ||
	    !(nlmsg_alloc_addr = dlsym(libnl_handle, "nlmsg_alloc")) ||
	    !(nlmsg_free_addr = dlsym(libnl_handle, "nlmsg_free")) ||
	    !(nlmsg_hdr_addr = dlsym(libnl_handle, "nlmsg_hdr")) ||
	    !(nl_recvmsgs_default_addr = dlsym(libnl_handle, "nl_recvmsgs_default")) ||
	    !(nl_send_auto_complete_addr = dlsym(libnl_handle, "nl_send_auto_complete")) ||
	    !(nl_socket_modify_cb_addr = dlsym(libnl_handle, "nl_socket_modify_cb")) ||
#ifdef _HAVE_LIBNL3_
	    !(nla_data_addr = dlsym(libnl_handle, "nla_data")) ||
	    !(nla_get_s32_addr = dlsym(libnl_handle, "nla_get_s32")) ||
	    !(nla_get_string_addr = dlsym(libnl_handle, "nla_get_string")) ||
	    !(nla_get_u16_addr = dlsym(libnl_handle, "nla_get_u16")) ||
	    !(nla_get_u32_addr = dlsym(libnl_handle, "nla_get_u32")) ||
	    !(nla_get_u64_addr = dlsym(libnl_handle, "nla_get_u64")) ||
	    !(nla_memcpy_addr = dlsym(libnl_handle, "nla_memcpy")) ||
	    !(nla_parse_nested_addr = dlsym(libnl_handle, "nla_parse_nested")) ||
#endif
#endif
	    false)
		log_message(LOG_INFO, "Failed to dynamic link a libnli/libnl-3 function");

	return true;
}
#endif
