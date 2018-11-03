/*
 * libnl_link: Handle dynamic linking to netlink libraries
 *
 * Authors:	P. Quentin Armitage <Quentin@Armitage.org.uk>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2017-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _LIBNL_LINK_H
#define _LIBNL_LINK_H

#include "config.h"

#include <stdbool.h>

#include <netlink/socket.h>
#include <netlink/netlink.h>
#ifdef LIBIPVS_USE_NL
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#endif

/* The addresses of the functions we want */
extern struct nl_sock * (*nl_socket_alloc_addr)(void);
extern void (*nl_socket_free_addr)(struct nl_sock *);
#ifdef LIBIPVS_USE_NL
extern int (*genl_connect_addr)(struct nl_sock *);
extern int (*genl_ctrl_resolve_addr)(struct nl_sock *, const char *);
extern int (*genlmsg_parse_addr)(struct nlmsghdr *, int, struct nlattr **, int, struct nla_policy *);
extern void * (*genlmsg_put_addr)(struct nl_msg *, uint32_t, uint32_t, int, int, int, uint8_t, uint8_t);
extern int (*nla_nest_end_addr)(struct nl_msg *, struct nlattr *);
extern struct nlattr * (*nla_nest_start_addr)(struct nl_msg *, int);
extern int (*nla_put_daddr)(struct nl_msg *, int, int, const void *);
extern struct nl_msg * (*nlmsg_alloc_addr)(void);
extern void (*nlmsg_free_addr)(struct nl_msg *);
extern struct nlmsghdr * (*nlmsg_hdr_addr)(struct nl_msg *);
extern int (*nl_recvmsgs_default_addr)(struct nl_sock *);
extern int (*nl_send_auto_complete_addr)(struct nl_sock *,  struct nl_msg *);
extern int (*nl_socket_modify_cb_addr)(struct nl_sock *, enum nl_cb_type, enum nl_cb_kind, nl_recvmsg_msg_cb_t, void *);
#ifdef _HAVE_LIBNL3_
extern void * (*nla_data_addr)(const struct nlattr *);
#ifdef NLA_PUT_S32
extern int32_t (*nla_get_s32_addr)(const struct nlattr *);
#endif
extern char * (*nla_get_string_addr)(const struct nlattr *);
extern uint16_t (*nla_get_u16_addr)(const struct nlattr *);
extern uint32_t (*nla_get_u32_addr)(const struct nlattr *);
extern uint64_t (*nla_get_u64_addr)(const struct nlattr *);
extern int (*nla_memcpy_addr)(void *, const struct nlattr *, int);
extern int (*nla_parse_nested_addr)(struct nlattr **, int, struct nlattr *, struct nla_policy *);
#endif
#endif

/* We can make it look as though normal linking is being used */
#define nl_socket_alloc (*nl_socket_alloc_addr)
#define nl_socket_free (*nl_socket_free_addr)
#ifdef LIBIPVS_USE_NL
#define genl_connect (*genl_connect_addr)
#define genl_ctrl_resolve (*genl_ctrl_resolve_addr)
#define genlmsg_parse (*genlmsg_parse_addr)
#define genlmsg_put (*genlmsg_put_addr)
#define nla_nest_end (*nla_nest_end_addr)
#define nla_nest_start (*nla_nest_start_addr)
#define nla_put (*nla_put_daddr)
#define nlmsg_alloc (*nlmsg_alloc_addr)
#define nlmsg_free (*nlmsg_free_addr)
#define nlmsg_hdr (*nlmsg_hdr_addr)
#define nl_recvmsgs_default (*nl_recvmsgs_default_addr)
#define nl_send_auto_complete (*nl_send_auto_complete_addr)
#define nl_socket_modify_cb (*nl_socket_modify_cb_addr)
#ifdef _HAVE_LIBNL3_
#define nla_data (*nla_data_addr)
#ifdef NLA_PUT_S32
#define nla_get_s32 (*nla_get_s32_addr)
#endif
#define nla_get_string (*nla_get_string_addr)
#define nla_get_u16 (*nla_get_u16_addr)
#define nla_get_u32 (*nla_get_u32_addr)
#define nla_get_u64 (*nla_get_u64_addr)
#define nla_memcpy (*nla_memcpy_addr)
#define nla_parse_nested (*nla_parse_nested_addr)
#endif
#endif

extern bool libnl_init(void);

#endif
