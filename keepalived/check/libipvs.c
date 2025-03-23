/*
 * libipvs:	Library for manipulating IPVS through netlink or [gs]etsockopt
 *
 *		This code is copied from the ipvsadm sources, with the unused
 *		code removed. It is available at:
 *		https://git.kernel.org/cgit/utils/kernel/ipvsadm/ipvsadm.git
 *
 *		The upstream code should periodically be checked for updates,
 *		which should then be applied to this code.
 *
 * Authors:	Wensong Zhang <wensong@linuxvirtualserver.org>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef LIBIPVS_USE_NL
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

//#define LIBNL_DEBUG

#ifdef _HAVE_LIBNL1_
#ifndef _LIBNL_DYNAMIC_
#define nl_socket_alloc	nl_handle_alloc
#define nl_socket_free	nl_handle_destroy
#endif
#endif

#ifdef _LIBNL_DYNAMIC_
#include "libnl_link.h"
#endif
#endif

#include "libipvs.h"

#include "memory.h"
#include "logger.h"
#include "utils.h"
#include "namespaces.h"
#include "global_data.h"

static int sockfd = -1;
static void* ipvs_func = NULL;
static ipvs_timeout_t orig_ipvs_timeouts;

#ifdef LIBIPVS_USE_NL
static struct nl_sock *sock = NULL;
static nl_recvmsg_msg_cb_t cur_nl_sock_cb_func;
static int family;
static bool try_nl = true;
static int nl_ack_flag;

/* Policy definitions */
static struct nla_policy ipvs_cmd_policy[IPVS_CMD_ATTR_MAX + 1] = {
	[IPVS_CMD_ATTR_SERVICE]		= { .type = NLA_NESTED },
	[IPVS_CMD_ATTR_DEST]		= { .type = NLA_NESTED },
	[IPVS_CMD_ATTR_DAEMON]		= { .type = NLA_NESTED },
	[IPVS_CMD_ATTR_TIMEOUT_TCP]	= { .type = NLA_U32 },
	[IPVS_CMD_ATTR_TIMEOUT_TCP_FIN]	= { .type = NLA_U32 },
	[IPVS_CMD_ATTR_TIMEOUT_UDP]	= { .type = NLA_U32 },
};

#ifdef _WITH_SNMP_CHECKER_
static struct nla_policy ipvs_service_policy[IPVS_SVC_ATTR_MAX + 1] = {
	[IPVS_SVC_ATTR_AF]		= { .type = NLA_U16 },
	[IPVS_SVC_ATTR_PROTOCOL]	= { .type = NLA_U16 },
	[IPVS_SVC_ATTR_ADDR]		= { .type = NLA_UNSPEC,
					    .maxlen = sizeof(struct in6_addr) },
	[IPVS_SVC_ATTR_PORT]		= { .type = NLA_U16 },
	[IPVS_SVC_ATTR_FWMARK]		= { .type = NLA_U32 },
	[IPVS_SVC_ATTR_SCHED_NAME]	= { .type = NLA_STRING,
					    .maxlen = IP_VS_SCHEDNAME_MAXLEN - 1 },
	[IPVS_SVC_ATTR_FLAGS]		= { .type = NLA_UNSPEC,
					    .minlen = sizeof(struct ip_vs_flags),
					    .maxlen = sizeof(struct ip_vs_flags) },
	[IPVS_SVC_ATTR_TIMEOUT]		= { .type = NLA_U32 },
	[IPVS_SVC_ATTR_NETMASK]		= { .type = NLA_U32 },
	[IPVS_SVC_ATTR_STATS]		= { .type = NLA_NESTED },
	[IPVS_SVC_ATTR_PE_NAME]		= { .type = NLA_STRING,
					    .maxlen = IP_VS_PENAME_MAXLEN },
#ifdef _WITH_LVS_64BIT_STATS_
	[IPVS_SVC_ATTR_STATS64]		= { .type = NLA_NESTED },
#endif
};

static struct nla_policy ipvs_dest_policy[IPVS_DEST_ATTR_MAX + 1] = {
	[IPVS_DEST_ATTR_ADDR]		= { .type = NLA_UNSPEC,
					    .maxlen = sizeof(struct in6_addr) },
	[IPVS_DEST_ATTR_PORT]		= { .type = NLA_U16 },
	[IPVS_DEST_ATTR_FWD_METHOD]	= { .type = NLA_U32 },
	[IPVS_DEST_ATTR_WEIGHT]		= { .type = NLA_U32 },
	[IPVS_DEST_ATTR_U_THRESH]	= { .type = NLA_U32 },
	[IPVS_DEST_ATTR_L_THRESH]	= { .type = NLA_U32 },
	[IPVS_DEST_ATTR_ACTIVE_CONNS]	= { .type = NLA_U32 },
	[IPVS_DEST_ATTR_INACT_CONNS]	= { .type = NLA_U32 },
	[IPVS_DEST_ATTR_PERSIST_CONNS]	= { .type = NLA_U32 },
	[IPVS_DEST_ATTR_STATS]		= { .type = NLA_NESTED },
#if HAVE_DECL_IPVS_DEST_ATTR_ADDR_FAMILY
	[IPVS_DEST_ATTR_ADDR_FAMILY]	= { .type = NLA_U16 },
#endif
#ifdef _HAVE_IPVS_TUN_TYPE_
	[IPVS_DEST_ATTR_TUN_TYPE]	= { .type = NLA_U8 },
	[IPVS_DEST_ATTR_TUN_PORT]	= { .type = NLA_U16 },
#endif
#ifdef _HAVE_IPVS_TUN_CSUM_
	[IPVS_DEST_ATTR_TUN_FLAGS]	= { .type = NLA_U16 },
#endif
#ifdef _WITH_LVS_64BIT_STATS_
	[IPVS_DEST_ATTR_STATS64]	= {.type = NLA_NESTED },
#endif
};

#ifdef _WITH_LVS_64BIT_STATS_
static struct nla_policy ipvs_stats64_policy[IPVS_STATS_ATTR_MAX + 1] = {
	[IPVS_STATS_ATTR_CONNS]		= { .type = NLA_U64 },
	[IPVS_STATS_ATTR_INPKTS]	= { .type = NLA_U64 },
	[IPVS_STATS_ATTR_OUTPKTS]	= { .type = NLA_U64 },
	[IPVS_STATS_ATTR_INBYTES]	= { .type = NLA_U64 },
	[IPVS_STATS_ATTR_OUTBYTES]	= { .type = NLA_U64 },
	[IPVS_STATS_ATTR_CPS]		= { .type = NLA_U64 },
	[IPVS_STATS_ATTR_INPPS]		= { .type = NLA_U64 },
	[IPVS_STATS_ATTR_OUTPPS]	= { .type = NLA_U64 },
	[IPVS_STATS_ATTR_INBPS]		= { .type = NLA_U64 },
	[IPVS_STATS_ATTR_OUTBPS]	= { .type = NLA_U64 },
};
#endif

static struct nla_policy ipvs_stats_policy[IPVS_STATS_ATTR_MAX + 1] = {
	[IPVS_STATS_ATTR_CONNS]		= { .type = NLA_U32 },
	[IPVS_STATS_ATTR_INPKTS]	= { .type = NLA_U32 },
	[IPVS_STATS_ATTR_OUTPKTS]	= { .type = NLA_U32 },
	[IPVS_STATS_ATTR_INBYTES]	= { .type = NLA_U64 },
	[IPVS_STATS_ATTR_OUTBYTES]	= { .type = NLA_U64 },
	[IPVS_STATS_ATTR_CPS]		= { .type = NLA_U32 },
	[IPVS_STATS_ATTR_INPPS]		= { .type = NLA_U32 },
	[IPVS_STATS_ATTR_OUTPPS]	= { .type = NLA_U32 },
	[IPVS_STATS_ATTR_INBPS]		= { .type = NLA_U32 },
	[IPVS_STATS_ATTR_OUTBPS]	= { .type = NLA_U32 },
};
#endif	/* _WITH_SNMP_CHECKER_ */

static struct nla_policy ipvs_info_policy[IPVS_INFO_ATTR_MAX + 1] = {
	[IPVS_INFO_ATTR_VERSION]	= { .type = NLA_U32 },
	[IPVS_INFO_ATTR_CONN_TAB_SIZE]  = { .type = NLA_U32 },
};
#endif

#ifdef LIBIPVS_USE_NL
#ifndef NLA_PUT_S32
#define NLA_PUT_S32(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, int32_t, attrtype, value)

static inline int32_t
nla_get_s32(struct nlattr *attr)
{
	return (int32_t)nla_get_u32(attr);
}
#endif

#ifndef _HAVE_LIBNL1_
static int nlerr2syserr(int err)
{
	switch (abs(err)) {
	case NLE_BAD_SOCK:	 return EBADF;
	case NLE_EXIST:		 return EEXIST;
	case NLE_NOADDR:	 return EADDRNOTAVAIL;
	case NLE_OBJ_NOTFOUND:	 return ENOENT;
	case NLE_INTR:		 return EINTR;
	case NLE_AGAIN:		 return EAGAIN;
	case NLE_INVAL:		 return EINVAL;
	case NLE_NOACCESS:	 return EACCES;
	case NLE_NOMEM:		 return ENOMEM;
	case NLE_AF_NOSUPPORT:	 return EAFNOSUPPORT;
	case NLE_PROTO_MISMATCH: return EPROTONOSUPPORT;
	case NLE_OPNOTSUPP:	 return EOPNOTSUPP;
	case NLE_PERM:		 return EPERM;
	case NLE_BUSY:		 return EBUSY;
	case NLE_RANGE:		 return ERANGE;
	case NLE_NODEV:		 return ENODEV;
	default:		 return err;
	}
}
#endif

static struct nl_msg *ipvs_nl_message(uint8_t cmd, int flags)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return NULL;

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, flags,
		    cmd, IPVS_GENL_VERSION);

	return msg;
}

#ifdef LIBNL_DEBUG
static void
dump_nl_msg(const char *msg, struct nl_msg *nlmsg)
{
	FILE *fp;
	const char *filename;

	filename = make_tmp_filename("nlmsg.dmp");
	fp = fopen(filename, "a");
	FREE_CONST(filename);

	fprintf(fp, "\n%s\n\n", msg);
	if (nlmsg)
		nl_msg_dump(nlmsg, fp);
	fclose(fp);
}
#endif

static int ipvs_nl_noop_cb(__attribute__((unused)) struct nl_msg *msg, __attribute__((unused)) void *arg)
{
#ifdef LIBNL_DEBUG
	dump_nl_msg("Noop CB", msg);
#endif

	return NL_OK;
}

#ifdef LIBNL_DEBUG
static int recv_cb(struct nl_msg *msg, __attribute__((unused)) void *arg)
{
	dump_nl_msg("Receive message", msg);

	return NL_OK;
}
#endif

static int recv_ack_cb(__attribute__((unused)) struct nl_msg *msg, void *arg)
{
	int *ack_flag = arg;

#ifdef LIBNL_DEBUG
	dump_nl_msg("That was an ACK message", NULL);
#endif

	*ack_flag = 1;

	return NL_STOP;
}

static int finish_cb(__attribute__((unused)) struct nl_msg *msg, void *arg)
{
	int *ack_flag = arg;

#ifdef LIBNL_DEBUG
	dump_nl_msg("That was a multi done message", NULL);
#endif

	*ack_flag = 1;

	return NL_STOP;
}

static int
ipvs_nl_err_cb(__attribute__((unused)) struct sockaddr_nl *nla, __attribute__((unused)) struct nlmsgerr *nlerr, void *arg)
{
	int *ack_flag = arg;

#ifdef LIBNL_DEBUG
	dump_nl_msg("That was an ERROR message", NULL);
#endif

	*ack_flag = 1;

	return NL_STOP;
}

static int
open_nl_sock(void)
{
	if (!(sock = nl_socket_alloc()))
		return -1;

	if (
	    nl_ipvs_connect(global_data->network_namespace_ipvs, sock) < 0 ||
	    (family = genl_ctrl_resolve(sock, IPVS_GENL_NAME)) < 0) {
		nl_socket_free(sock);
		sock = NULL;

		return -1;
	}

	/* We finish receiving if we get an error, an ACK, or a DONE for a multipart message */
#ifndef _HAVE_LIBNL1_
	if (nl_socket_modify_err_cb(sock, NL_CB_CUSTOM, ipvs_nl_err_cb, &nl_ack_flag))
#else
	if (nl_cb_err(nl_socket_get_cb(sock), NL_CB_CUSTOM, ipvs_nl_err_cb, &nl_ack_flag))
#endif
		log_message(LOG_INFO, "Setting err_cb failed");

	nl_socket_modify_cb(sock, NL_CB_ACK, NL_CB_CUSTOM, recv_ack_cb, &nl_ack_flag);
	nl_socket_modify_cb(sock, NL_CB_FINISH, NL_CB_CUSTOM, finish_cb, &nl_ack_flag);

#ifdef LIBNL_DEBUG
	nl_socket_modify_cb(sock, NL_CB_MSG_IN, NL_CB_CUSTOM, recv_cb, 0);
#endif

	return 0;
}

static int ipvs_nl_send_message(struct nl_msg *msg, nl_recvmsg_msg_cb_t func, void *arg)
{
	int err = EINVAL;
	int ret = 0;

	if (!msg)
		return 0;

	if (!sock && open_nl_sock()) {
		nlmsg_free(msg);
		return -1;
	}

	if (func != cur_nl_sock_cb_func) {
		if (!nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, func, arg))
			cur_nl_sock_cb_func = func;
		else
			log_message(LOG_INFO, "Setting libnl callback function failed");
	}

#ifdef LIBNL_DEBUG
	dump_nl_msg("Sending message", msg);
#endif

#ifndef _HAVE_LIBNL1_
	if (nl_send_auto(sock, msg) >= 0) {
#else
	if (nl_send_auto_complete(sock, msg) >= 0) {
#endif
		nl_ack_flag = 0;
		do {
			if ((err = -nl_recvmsgs_default(sock)) > 0) {
#ifdef _HAVE_LIBNL1_
				errno = err;
#else
				errno = nlerr2syserr(err);
#endif

				ret = -1;
			}
		} while (!nl_ack_flag);
	}

	nlmsg_free(msg);

	return ret;
}
#endif

#ifdef LIBIPVS_USE_NL
static int ipvs_getinfo_parse_cb(struct nl_msg *msg, __attribute__((unused)) void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[IPVS_INFO_ATTR_MAX + 1];

	if (genlmsg_parse(nlh, 0, attrs, IPVS_INFO_ATTR_MAX, ipvs_info_policy) != 0)
		return NL_STOP;

	if (!(attrs[IPVS_INFO_ATTR_VERSION] &&
	      attrs[IPVS_INFO_ATTR_CONN_TAB_SIZE]))
		return NL_STOP;

	return NL_OK;
}
#endif

static int ipvs_getinfo(bool retry)
{
	socklen_t len;
	struct ip_vs_getinfo ipvs_info;
	unsigned retries = retry ? 1 : 0;

	/* It appears that if we need to install the ip_vs module
	 * (via keepalived_modprobe), then the first ipvs_nl_send_message()
	 * call afterwards fails, but it succeeds thereafter.
	 *
	 * On some distros the call genl_ctrl_resolve(sock, IPVS_GENL_NAME) loads
	 * the ip_vs module, so we don't need to call keepalived_modprobe(), and
	 * we don't need to retry the ipvs_nl_send_message(). On the other hand,
	 * if genl_ctrl_resolve() does not load the ip_vs module, then we need to
	 * make the second call of ipvs_nl_send_message().
	 *
	 * It appears that if there is an entry:
	 *   alias net-pf-16-proto-16-family-IPVS ip_vs
	 * in /lib/modules/{KERNEL_VER}/modules.alias then genl_ctrl_resolve() causes
	 * the ip_vs module to be loaded, and if there is no such entry, then it does
	 * not load the ip_vs module. Whether this is cause and effect, or whether they
	 * are both caused by some other aspect of the configuration I do not know.
	 */

	ipvs_func = ipvs_getinfo;

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg;

		do {
			if (!(msg = ipvs_nl_message(IPVS_CMD_GET_INFO, 0)))
				return -1;

			if (!ipvs_nl_send_message(msg, ipvs_getinfo_parse_cb, NULL))
				return 0;
		} while (retries--);

		return -1;
	}
#endif

	len = sizeof(ipvs_info);
	return getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_INFO, &ipvs_info, &len);
}

int ipvs_init(bool retry)
{
	ipvs_func = ipvs_init;

#ifdef LIBIPVS_USE_NL
#ifdef _LIBNL_DYNAMIC_
	try_nl = libnl_init();
	if (!try_nl)
		log_message(LOG_INFO, "Note: IPVS with IPv6 will not be supported");
#endif

	if (try_nl)
		return ipvs_getinfo(retry);

	try_nl = false;
#else
	log_message(LOG_INFO, "Note: IPVS with IPv6 will not be supported");
#endif

	sockfd = socket_netns_name(global_data->network_namespace_ipvs, AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	if (sockfd == -1)
		return -1;

	if (ipvs_getinfo(false)) {
		close(sockfd);
		sockfd = -1;
		return -1;
	}

	return 0;
}

int ipvs_flush(void)
{
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_FLUSH, 0);
		if (msg && (ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL) == 0))
			return 0;

		return -1;
	}
#endif
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_FLUSH, NULL, 0);
}

#ifdef LIBIPVS_USE_NL
static int ipvs_nl_fill_service_attr(struct nl_msg *msg, ipvs_service_t *svc)
{
	struct nlattr *nl_service;
	struct ip_vs_flags flags = { .flags = svc->user.flags,
				     .mask = ~0U };

	nl_service = nla_nest_start(msg, IPVS_CMD_ATTR_SERVICE);
	if (!nl_service)
		return -1;

	NLA_PUT_U16(msg, IPVS_SVC_ATTR_AF, svc->af);

	if (svc->user.fwmark) {
		NLA_PUT_U32(msg, IPVS_SVC_ATTR_FWMARK, svc->user.fwmark);
	} else {
		NLA_PUT_U16(msg, IPVS_SVC_ATTR_PROTOCOL, svc->user.protocol);
		NLA_PUT(msg, IPVS_SVC_ATTR_ADDR, sizeof(svc->nf_addr), &(svc->nf_addr));
		NLA_PUT_U16(msg, IPVS_SVC_ATTR_PORT, svc->user.port);
	}

	NLA_PUT_STRING(msg, IPVS_SVC_ATTR_SCHED_NAME, svc->user.sched_name);
	if (svc->pe_name[0])
		NLA_PUT_STRING(msg, IPVS_SVC_ATTR_PE_NAME, svc->pe_name);
	NLA_PUT(msg, IPVS_SVC_ATTR_FLAGS, sizeof(flags), &flags);
	NLA_PUT_U32(msg, IPVS_SVC_ATTR_TIMEOUT, svc->user.timeout);
	NLA_PUT_U32(msg, IPVS_SVC_ATTR_NETMASK, svc->user.netmask);

	nla_nest_end(msg, nl_service);
	return 0;

nla_put_failure:
	return -1;
}
#endif

static int
ipvs_do_service(ipvs_service_t *svc, uint8_t cmd)
{
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(cmd, 0);
		if (!msg) return -1;
		if (ipvs_nl_fill_service_attr(msg, svc)) {
			nlmsg_free(msg);
			return -1;
		}
		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);
	}
#endif

	if (svc->af != AF_INET) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	svc->user.addr = svc->nf_addr.ip;

	return setsockopt(sockfd, IPPROTO_IP,
			  cmd == IPVS_CMD_NEW_SERVICE ? IP_VS_SO_SET_ADD :
#ifdef _INCLUDE_UNUSED_CODE_
			  cmd == IPVS_CMD_ZERO ? IP_VS_SO_SET_ZERO :
#endif
			  cmd == IPVS_CMD_DEL_SERVICE ? IP_VS_SO_SET_DEL : IP_VS_SO_SET_EDIT,
			  &svc->user, sizeof(svc->user));
}

int
ipvs_add_service(ipvs_service_t *svc)
{
	ipvs_func = ipvs_add_service;

	return ipvs_do_service(svc, IPVS_CMD_NEW_SERVICE);
}

int
ipvs_update_service(ipvs_service_t *svc)
{
	ipvs_func = ipvs_update_service;

	return ipvs_do_service(svc, IPVS_CMD_SET_SERVICE);
}

int
ipvs_del_service(ipvs_service_t *svc)
{
	ipvs_func = ipvs_del_service;

	return ipvs_do_service(svc, IPVS_CMD_DEL_SERVICE);
}

#ifdef _INCLUDE_UNUSED_CODE_
int ipvs_zero_service(ipvs_service_t *svc)
{
	ipvs_func = ipvs_zero_service;

	return ipvs_do_service(svc, IPVS_CMD_ZERO);
}
#endif

#ifdef LIBIPVS_USE_NL
static int ipvs_nl_fill_dest_attr(struct nl_msg *msg, ipvs_dest_t *dst)
{
	struct nlattr *nl_dest;

	nl_dest = nla_nest_start(msg, IPVS_CMD_ATTR_DEST);
	if (!nl_dest)
		return -1;

#if HAVE_DECL_IPVS_DEST_ATTR_ADDR_FAMILY
	NLA_PUT_U16(msg, IPVS_DEST_ATTR_ADDR_FAMILY, dst->af);
#endif
	NLA_PUT(msg, IPVS_DEST_ATTR_ADDR, sizeof(dst->nf_addr), &(dst->nf_addr));
	NLA_PUT_U16(msg, IPVS_DEST_ATTR_PORT, dst->user.port);
	NLA_PUT_U32(msg, IPVS_DEST_ATTR_FWD_METHOD, dst->user.conn_flags & IP_VS_CONN_F_FWD_MASK);
	NLA_PUT_U32(msg, IPVS_DEST_ATTR_WEIGHT, (uint32_t)dst->user.weight);
#ifdef _HAVE_IPVS_TUN_TYPE_
	if ((dst->user.conn_flags & IP_VS_CONN_F_FWD_MASK) == IP_VS_CONN_F_TUNNEL) {
		NLA_PUT_U8 (msg, IPVS_DEST_ATTR_TUN_TYPE, dst->tun_type);
		if (dst->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_GUE)
			NLA_PUT_U16(msg, IPVS_DEST_ATTR_TUN_PORT, dst->tun_port);
#ifdef _HAVE_IPVS_TUN_CSUM_
		if (dst->tun_type != IP_VS_CONN_F_TUNNEL_TYPE_IPIP)
			NLA_PUT_U16(msg, IPVS_DEST_ATTR_TUN_FLAGS, dst->tun_flags);
#endif
	}
#endif
	NLA_PUT_U32(msg, IPVS_DEST_ATTR_U_THRESH, dst->user.u_threshold);
	NLA_PUT_U32(msg, IPVS_DEST_ATTR_L_THRESH, dst->user.l_threshold);

	nla_nest_end(msg, nl_dest);
	return 0;

nla_put_failure:
	return -1;
}
#endif

static int
ipvs_do_dest(ipvs_service_t *svc, ipvs_dest_t *dest, uint8_t cmd)
{
	struct {
		struct ip_vs_service_user	svc;
		struct ip_vs_dest_user		dest;
	} svcdest;

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(cmd, 0);
		if (!msg)
			return -1;
		if (ipvs_nl_fill_service_attr(msg, svc))
			goto nla_put_failure;
		if (ipvs_nl_fill_dest_attr(msg, dest))
			goto nla_put_failure;
		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);

nla_put_failure:
		nlmsg_free(msg);
		return -1;
	}
#endif

	if (svc->af != AF_INET || dest->af != AF_INET) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	svcdest.svc = svc->user;
	svcdest.dest = dest->user;

	svcdest.svc.addr = svc->nf_addr.ip;
	svcdest.dest.addr = dest->nf_addr.ip;

	return setsockopt(sockfd, IPPROTO_IP,
			  cmd == IPVS_CMD_NEW_DEST ? IP_VS_SO_SET_ADDDEST :
			  cmd == IPVS_CMD_SET_DEST ? IP_VS_SO_SET_EDITDEST : IP_VS_SO_SET_DELDEST,
			  &svcdest, sizeof(svcdest));
}

int
ipvs_add_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	ipvs_func = ipvs_add_dest;

	return ipvs_do_dest(svc, dest, IPVS_CMD_NEW_DEST);
}

int
ipvs_update_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	ipvs_func = ipvs_update_dest;

	return ipvs_do_dest(svc, dest, IPVS_CMD_SET_DEST);
}

int
ipvs_del_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	ipvs_func = ipvs_del_dest;

	return ipvs_do_dest(svc, dest, IPVS_CMD_DEL_DEST);
}

#ifdef LIBIPVS_USE_NL
static int ipvs_timeout_parse_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[IPVS_CMD_ATTR_MAX + 1];
	ipvs_timeout_t *u = PTR_CAST(ipvs_timeout_t, arg);

	if (genlmsg_parse(nlh, 0, attrs, IPVS_CMD_ATTR_MAX, ipvs_cmd_policy) != 0)
		return -1;

	if (attrs[IPVS_CMD_ATTR_TIMEOUT_TCP])
		u->tcp_timeout = nla_get_u32(attrs[IPVS_CMD_ATTR_TIMEOUT_TCP]);
	if (attrs[IPVS_CMD_ATTR_TIMEOUT_TCP_FIN])
		u->tcp_fin_timeout = nla_get_u32(attrs[IPVS_CMD_ATTR_TIMEOUT_TCP_FIN]);
	if (attrs[IPVS_CMD_ATTR_TIMEOUT_UDP])
		u->udp_timeout = nla_get_u32(attrs[IPVS_CMD_ATTR_TIMEOUT_UDP]);

	return NL_OK;
}
#endif

static void
ipvs_get_timeout(void)
{
	socklen_t len;

	ipvs_func = ipvs_get_timeout;
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg;
		msg = ipvs_nl_message(IPVS_CMD_GET_CONFIG, 0);
		if (!msg || ipvs_nl_send_message(msg, ipvs_timeout_parse_cb, &orig_ipvs_timeouts))
			log_message(LOG_INFO, "Failed to get IPVS timeouts");

		return;
	}
#endif

	len = sizeof(orig_ipvs_timeouts);
	if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_TIMEOUT, &orig_ipvs_timeouts, &len)) {
		log_message(LOG_INFO, "Failed to get IPVS timeouts");
		return;
	}
}

int ipvs_set_timeout(const ipvs_timeout_t *to)
{
	ipvs_func = ipvs_set_timeout;

	/* If we are altering the timeouts, ensure we can restore the original values */
	if (!orig_ipvs_timeouts.tcp_timeout) {
		if (!to)
			return 0;

		ipvs_get_timeout();
	}

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_SET_CONFIG, 0);
		if (!msg) return -1;

		NLA_PUT_U32(msg, IPVS_CMD_ATTR_TIMEOUT_TCP, to && to->tcp_timeout ? (uint32_t)to->tcp_timeout : (uint32_t)orig_ipvs_timeouts.tcp_timeout);
		NLA_PUT_U32(msg, IPVS_CMD_ATTR_TIMEOUT_TCP_FIN, to && to->tcp_fin_timeout ? (uint32_t)to->tcp_fin_timeout : (uint32_t)orig_ipvs_timeouts.tcp_fin_timeout);
		NLA_PUT_U32(msg, IPVS_CMD_ATTR_TIMEOUT_UDP, to && to->udp_timeout ? (uint32_t)to->udp_timeout : (uint32_t)orig_ipvs_timeouts.udp_timeout);
		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);

nla_put_failure:
		nlmsg_free(msg);
		return -1;
	}
#endif
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_TIMEOUT, (const char *)( to ? to : &orig_ipvs_timeouts),
			  sizeof(ipvs_timeout_t));
}


int ipvs_start_daemon(ipvs_daemon_t *dm)
{
	ipvs_func = ipvs_start_daemon;

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nlattr *nl_daemon;
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_NEW_DAEMON, 0);
		if (!msg) return -1;

		nl_daemon = nla_nest_start(msg, IPVS_CMD_ATTR_DAEMON);
		if (!nl_daemon)
			goto nla_put_failure;

		NLA_PUT_S32(msg, IPVS_DAEMON_ATTR_STATE, dm->user.state);
		NLA_PUT_STRING(msg, IPVS_DAEMON_ATTR_MCAST_IFN, dm->user.mcast_ifn);
		NLA_PUT_S32(msg, IPVS_DAEMON_ATTR_SYNC_ID, dm->user.syncid);
#ifdef _HAVE_IPVS_SYNCD_ATTRIBUTES_
		if (dm->sync_maxlen)
			NLA_PUT_U16(msg, IPVS_DAEMON_ATTR_SYNC_MAXLEN, dm->sync_maxlen);
		if (dm->mcast_port)
			NLA_PUT_U16(msg, IPVS_DAEMON_ATTR_MCAST_PORT, dm->mcast_port);
		if (dm->mcast_ttl)
			NLA_PUT_U8(msg, IPVS_DAEMON_ATTR_MCAST_TTL, dm->mcast_ttl);
		if (dm->mcast_af == AF_INET6)
			NLA_PUT(msg, IPVS_DAEMON_ATTR_MCAST_GROUP6, sizeof(dm->mcast_group.in6), &dm->mcast_group.in6);
		else if (dm->mcast_af == AF_INET)
			NLA_PUT_U32(msg, IPVS_DAEMON_ATTR_MCAST_GROUP, dm->mcast_group.ip);
#endif

		nla_nest_end(msg, nl_daemon);

		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);

nla_put_failure:
		nlmsg_free(msg);
		return -1;
	}
#endif

	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_STARTDAEMON, &dm->user, sizeof(dm->user));
}


int ipvs_stop_daemon(ipvs_daemon_t *dm)
{
	ipvs_func = ipvs_stop_daemon;

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nlattr *nl_daemon;
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_DEL_DAEMON, 0);
		if (!msg) return -1;

		nl_daemon = nla_nest_start(msg, IPVS_CMD_ATTR_DAEMON);
		if (!nl_daemon)
			goto nla_put_failure;

		NLA_PUT_S32(msg, IPVS_DAEMON_ATTR_STATE, dm->user.state);
		NLA_PUT_S32(msg, IPVS_DAEMON_ATTR_SYNC_ID, dm->user.syncid);

		nla_nest_end(msg, nl_daemon);

		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);

nla_put_failure:
		nlmsg_free(msg);
		return -1;
	}
#endif

	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_STOPDAEMON, &dm->user, sizeof(dm->user));
}

#ifdef _WITH_SNMP_CHECKER_
#ifdef _WITH_LVS_64BIT_STATS_
static void
ipvs_copy_stats(ip_vs_stats_t *stats_out, const struct ip_vs_stats_user *stats_in)
{
	stats_out->conns = stats_in->conns;
	stats_out->inpkts = stats_in->inpkts;
	stats_out->outpkts = stats_in->outpkts;
	stats_out->inbytes = stats_in->inbytes;
	stats_out->outbytes = stats_in->outbytes;
	stats_out->cps = stats_in->cps;
	stats_out->inpps = stats_in->inpps;
	stats_out->outpps = stats_in->outpps;
	stats_out->inbps = stats_in->inbps;
	stats_out->outbps = stats_in->outbps;
}
#endif

#ifdef LIBIPVS_USE_NL
#ifdef _WITH_LVS_64BIT_STATS_
static int ipvs_parse_stats64(ip_vs_stats_t *stats, struct nlattr *nla)
{
	struct nlattr *attrs[IPVS_STATS_ATTR_MAX + 1];

	if (nla_parse_nested(attrs, IPVS_STATS_ATTR_MAX, nla, ipvs_stats64_policy))
		return -1;

	if (!(attrs[IPVS_STATS_ATTR_CONNS] &&
	      attrs[IPVS_STATS_ATTR_INPKTS] &&
	      attrs[IPVS_STATS_ATTR_OUTPKTS] &&
	      attrs[IPVS_STATS_ATTR_INBYTES] &&
	      attrs[IPVS_STATS_ATTR_OUTBYTES] &&
	      attrs[IPVS_STATS_ATTR_CPS] &&
	      attrs[IPVS_STATS_ATTR_INPPS] &&
	      attrs[IPVS_STATS_ATTR_OUTPPS] &&
	      attrs[IPVS_STATS_ATTR_INBPS] &&
	      attrs[IPVS_STATS_ATTR_OUTBPS]))
		return -1;

	stats->conns = nla_get_u64(attrs[IPVS_STATS_ATTR_CONNS]);
	stats->inpkts = nla_get_u64(attrs[IPVS_STATS_ATTR_INPKTS]);
	stats->outpkts = nla_get_u64(attrs[IPVS_STATS_ATTR_OUTPKTS]);
	stats->inbytes = nla_get_u64(attrs[IPVS_STATS_ATTR_INBYTES]);
	stats->outbytes = nla_get_u64(attrs[IPVS_STATS_ATTR_OUTBYTES]);
	stats->cps = nla_get_u64(attrs[IPVS_STATS_ATTR_CPS]);
	stats->inpps = nla_get_u64(attrs[IPVS_STATS_ATTR_INPPS]);
	stats->outpps = nla_get_u64(attrs[IPVS_STATS_ATTR_OUTPPS]);
	stats->inbps = nla_get_u64(attrs[IPVS_STATS_ATTR_INBPS]);
	stats->outbps = nla_get_u64(attrs[IPVS_STATS_ATTR_OUTBPS]);

	return 0;
}
#endif

static int ipvs_parse_stats(ip_vs_stats_t *stats, struct nlattr *nla)
{
	struct nlattr *attrs[IPVS_STATS_ATTR_MAX + 1];

	if (nla_parse_nested(attrs, IPVS_STATS_ATTR_MAX, nla, ipvs_stats_policy))
		return -1;

	if (!(attrs[IPVS_STATS_ATTR_CONNS] &&
	      attrs[IPVS_STATS_ATTR_INPKTS] &&
	      attrs[IPVS_STATS_ATTR_OUTPKTS] &&
	      attrs[IPVS_STATS_ATTR_INBYTES] &&
	      attrs[IPVS_STATS_ATTR_OUTBYTES] &&
	      attrs[IPVS_STATS_ATTR_CPS] &&
	      attrs[IPVS_STATS_ATTR_INPPS] &&
	      attrs[IPVS_STATS_ATTR_OUTPPS] &&
	      attrs[IPVS_STATS_ATTR_INBPS] &&
	      attrs[IPVS_STATS_ATTR_OUTBPS]))
		return -1;

	stats->conns = nla_get_u32(attrs[IPVS_STATS_ATTR_CONNS]);
	stats->inpkts = nla_get_u32(attrs[IPVS_STATS_ATTR_INPKTS]);
	stats->outpkts = nla_get_u32(attrs[IPVS_STATS_ATTR_OUTPKTS]);
	stats->inbytes = nla_get_u64(attrs[IPVS_STATS_ATTR_INBYTES]);
	stats->outbytes = nla_get_u64(attrs[IPVS_STATS_ATTR_OUTBYTES]);
	stats->cps = nla_get_u32(attrs[IPVS_STATS_ATTR_CPS]);
	stats->inpps = nla_get_u32(attrs[IPVS_STATS_ATTR_INPPS]);
	stats->outpps = nla_get_u32(attrs[IPVS_STATS_ATTR_OUTPPS]);
	stats->inbps = nla_get_u32(attrs[IPVS_STATS_ATTR_INBPS]);
	stats->outbps = nla_get_u32(attrs[IPVS_STATS_ATTR_OUTBPS]);

	return 0;
}

static int ipvs_services_parse_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[IPVS_CMD_ATTR_MAX + 1];
	struct nlattr *svc_attrs[IPVS_SVC_ATTR_MAX + 1];
	struct ip_vs_get_services_app **getp = PTR_CAST(struct ip_vs_get_services_app *, arg);
	struct ip_vs_get_services_app *get = *getp;
	struct ip_vs_flags flags;

	if (get->user.num_services) {
		log_message(LOG_INFO, "ipvs_services_parse_cb get->user.num_services = %u != 0", get->user.num_services);
		return -1;
	}

	if (genlmsg_parse(nlh, 0, attrs, IPVS_CMD_ATTR_MAX, ipvs_cmd_policy) != 0)
		return -1;

	if (!attrs[IPVS_CMD_ATTR_SERVICE])
		return -1;

	if (nla_parse_nested(svc_attrs, IPVS_SVC_ATTR_MAX, attrs[IPVS_CMD_ATTR_SERVICE], ipvs_service_policy))
		return -1;

	memset(&(get->user.entrytable[0]), 0, sizeof(get->user.entrytable[0]));

	if (!(svc_attrs[IPVS_SVC_ATTR_AF] &&
	      (svc_attrs[IPVS_SVC_ATTR_FWMARK] ||
	       (svc_attrs[IPVS_SVC_ATTR_PROTOCOL] &&
		svc_attrs[IPVS_SVC_ATTR_ADDR] &&
		svc_attrs[IPVS_SVC_ATTR_PORT])) &&
	      svc_attrs[IPVS_SVC_ATTR_SCHED_NAME] &&
	      svc_attrs[IPVS_SVC_ATTR_NETMASK] &&
	      svc_attrs[IPVS_SVC_ATTR_TIMEOUT] &&
	      svc_attrs[IPVS_SVC_ATTR_FLAGS]))
		return -1;

	get->user.entrytable[0].af = nla_get_u16(svc_attrs[IPVS_SVC_ATTR_AF]);

	if (svc_attrs[IPVS_SVC_ATTR_FWMARK])
		get->user.entrytable[0].user.fwmark = nla_get_u32(svc_attrs[IPVS_SVC_ATTR_FWMARK]);
	else {
		get->user.entrytable[0].user.protocol = nla_get_u16(svc_attrs[IPVS_SVC_ATTR_PROTOCOL]);
		memcpy(&(get->user.entrytable[0].nf_addr), nla_data(svc_attrs[IPVS_SVC_ATTR_ADDR]),
		       sizeof(get->user.entrytable[0].nf_addr));
		get->user.entrytable[0].user.port = nla_get_u16(svc_attrs[IPVS_SVC_ATTR_PORT]);
	}

	strcpy_safe(get->user.entrytable[0].user.sched_name,
		nla_get_string(svc_attrs[IPVS_SVC_ATTR_SCHED_NAME]));

	if (svc_attrs[IPVS_SVC_ATTR_PE_NAME])
		strcpy_safe(get->user.entrytable[0].pe_name,
			nla_get_string(svc_attrs[IPVS_SVC_ATTR_PE_NAME]));

	get->user.entrytable[0].user.netmask = nla_get_u32(svc_attrs[IPVS_SVC_ATTR_NETMASK]);
	get->user.entrytable[0].user.timeout = nla_get_u32(svc_attrs[IPVS_SVC_ATTR_TIMEOUT]);
	nla_memcpy(&flags, svc_attrs[IPVS_SVC_ATTR_FLAGS], sizeof(flags));
	get->user.entrytable[0].user.flags = flags.flags & flags.mask;

#ifdef _WITH_LVS_64BIT_STATS_
	if (svc_attrs[IPVS_SVC_ATTR_STATS64]) {
		if (ipvs_parse_stats64(&(get->user.entrytable[0].stats),
				     svc_attrs[IPVS_SVC_ATTR_STATS64]) != 0)
			return -1;
	} else if (svc_attrs[IPVS_SVC_ATTR_STATS])
#endif
	{
		if (ipvs_parse_stats(&(get->user.entrytable[0].ip_vs_stats),
				     svc_attrs[IPVS_SVC_ATTR_STATS]) != 0)
			return -1;
	}

	get->user.entrytable[0].user.num_dests = 0;

	get->user.num_services++;

	return 0;
}


static int ipvs_dests_parse_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[IPVS_CMD_ATTR_MAX + 1];
	struct nlattr *dest_attrs[IPVS_DEST_ATTR_MAX + 1];
	struct ip_vs_get_dests_app **dp = PTR_CAST(struct ip_vs_get_dests_app *, arg);
	struct ip_vs_get_dests_app *d = PTR_CAST(struct ip_vs_get_dests_app, *dp);
	unsigned i = d->user.num_dests;
	struct ip_vs_dest_entry_app *ent;

	if (genlmsg_parse(nlh, 0, attrs, IPVS_CMD_ATTR_MAX, ipvs_cmd_policy) != 0)
		return -1;

	if (!attrs[IPVS_CMD_ATTR_DEST])
		return -1;

	if (nla_parse_nested(dest_attrs, IPVS_DEST_ATTR_MAX, attrs[IPVS_CMD_ATTR_DEST], ipvs_dest_policy))
		return -1;

	if (!(dest_attrs[IPVS_DEST_ATTR_ADDR] &&
	      dest_attrs[IPVS_DEST_ATTR_PORT] &&
	      dest_attrs[IPVS_DEST_ATTR_FWD_METHOD] &&
	      dest_attrs[IPVS_DEST_ATTR_WEIGHT] &&
	      dest_attrs[IPVS_DEST_ATTR_U_THRESH] &&
	      dest_attrs[IPVS_DEST_ATTR_L_THRESH] &&
	      dest_attrs[IPVS_DEST_ATTR_ACTIVE_CONNS] &&
	      dest_attrs[IPVS_DEST_ATTR_INACT_CONNS] &&
	      dest_attrs[IPVS_DEST_ATTR_PERSIST_CONNS]))
		return -1;

	if (d->user.num_dests == d->num_entries) {
		/* There are more RS than we expected. Allow space for another 10. */
		d = REALLOC(d, sizeof(*d) + sizeof(ipvs_dest_entry_t) * (d->num_entries += 10));
		*dp = d;
	}

	ent = &d->user.entrytable[i];
	memset(ent, 0, sizeof(*ent));

	memcpy(&ent->nf_addr,
	       nla_data(dest_attrs[IPVS_DEST_ATTR_ADDR]),
	       nla_len(dest_attrs[IPVS_DEST_ATTR_ADDR]));
	ent->user.port = nla_get_u16(dest_attrs[IPVS_DEST_ATTR_PORT]);
	ent->user.conn_flags = nla_get_u32(dest_attrs[IPVS_DEST_ATTR_FWD_METHOD]);
	ent->user.weight = nla_get_s32(dest_attrs[IPVS_DEST_ATTR_WEIGHT]);
	ent->user.u_threshold = nla_get_u32(dest_attrs[IPVS_DEST_ATTR_U_THRESH]);
	ent->user.l_threshold = nla_get_u32(dest_attrs[IPVS_DEST_ATTR_L_THRESH]);
	ent->user.activeconns = nla_get_u32(dest_attrs[IPVS_DEST_ATTR_ACTIVE_CONNS]);
	ent->user.inactconns = nla_get_u32(dest_attrs[IPVS_DEST_ATTR_INACT_CONNS]);
	ent->user.persistconns = nla_get_u32(dest_attrs[IPVS_DEST_ATTR_PERSIST_CONNS]);
#if HAVE_DECL_IPVS_DEST_ATTR_ADDR_FAMILY
	if (dest_attrs[IPVS_DEST_ATTR_ADDR_FAMILY])
		ent->af = nla_get_u16(dest_attrs[IPVS_DEST_ATTR_ADDR_FAMILY]);
	else
#endif
		ent->af = d->af;

#ifdef _WITH_LVS_64BIT_STATS_
	if (dest_attrs[IPVS_DEST_ATTR_STATS64]) {
		if (ipvs_parse_stats64(&ent->ip_vs_stats, dest_attrs[IPVS_DEST_ATTR_STATS64]) != 0)
			return -1;
	} else if (dest_attrs[IPVS_DEST_ATTR_STATS])
#endif
	{
		if (ipvs_parse_stats(&ent->ip_vs_stats, dest_attrs[IPVS_DEST_ATTR_STATS]) != 0)
			return -1;
	}

	d->user.num_dests++;

	return 0;
}
#endif	/* LIBIPVS_USE_NL */

struct ip_vs_get_dests_app *ipvs_get_dests(__u32 fwmark, __u16 af, __u16 protocol, union nf_inet_addr *addr, __u16 port, unsigned num_dests)
{
	struct ip_vs_get_dests_app *d;
	struct ip_vs_get_dests *dk;
	socklen_t len;
	unsigned i;

	len = (socklen_t)(sizeof(*d) + sizeof(ipvs_dest_entry_t) * num_dests);

	if (!(d = MALLOC(len)))
		return NULL;

	d->num_entries = num_dests;

	ipvs_func = ipvs_get_dests;

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg;
		struct nlattr *nl_service;
		d->af = af;
		d->user.num_dests = 0;

		msg = ipvs_nl_message(IPVS_CMD_GET_DEST, NLM_F_DUMP);
		if (!msg)
			goto ipvs_nl_dest_failure;

		nl_service = nla_nest_start(msg, IPVS_CMD_ATTR_SERVICE);
		if (!nl_service)
			goto nla_put_failure;

		NLA_PUT_U16(msg, IPVS_SVC_ATTR_AF, af);

		if (fwmark) {
			NLA_PUT_U32(msg, IPVS_SVC_ATTR_FWMARK, fwmark);
		} else {
			NLA_PUT_U16(msg, IPVS_SVC_ATTR_PROTOCOL, protocol);
			NLA_PUT(msg, IPVS_SVC_ATTR_ADDR, af == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr), addr);
			NLA_PUT_U16(msg, IPVS_SVC_ATTR_PORT, port);
		}
		nla_nest_end(msg, nl_service);

		if (ipvs_nl_send_message(msg, ipvs_dests_parse_cb, &d))
			goto ipvs_nl_dest_failure;

		return d;

nla_put_failure:
		nlmsg_free(msg);
ipvs_nl_dest_failure:
		FREE(d);
		return NULL;
	}
#endif	/* LIBIPVS_USE_NL */

	if (af != AF_INET) {
		errno = EAFNOSUPPORT;
		FREE(d);
		return NULL;
	}

	len = (socklen_t)(sizeof(*dk) + sizeof(struct ip_vs_dest_entry) * num_dests);
	if (!(dk = MALLOC(len))) {
		FREE(d);
		return NULL;
	}

	dk->fwmark = fwmark;
	dk->protocol = protocol;
	if (addr)
		dk->addr = addr->ip;
	dk->port = port;

	if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_DESTS, dk, &len) < 0) {
		FREE(d);
		FREE(dk);
		return NULL;
	}

	d->user.num_dests = dk->num_dests;
	for (i = 0; i < dk->num_dests; i++) {
		d->user.entrytable[i].user = dk->entrytable[i];
		d->user.entrytable[i].af = AF_INET;
		d->user.entrytable[i].nf_addr.ip = d->user.entrytable[i].user.addr;
#ifdef _WITH_LVS_64BIT_STATS_
		ipvs_copy_stats(&d->user.entrytable[i].ip_vs_stats, &dk->entrytable[i].stats);
#endif
	}
	FREE(dk);
	return d;
}


ipvs_service_entry_t *
ipvs_get_service(__u32 fwmark, __u16 af, __u16 protocol, union nf_inet_addr *addr, __u16 port)
{
	ipvs_service_entry_t *svc;
	socklen_t len;

	ipvs_func = ipvs_get_service;

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct ip_vs_get_services_app *get;
		struct nlattr *nl_service;
		struct nl_msg *msg;

		svc = MALLOC(sizeof(*svc));
		if (!svc)
			return NULL;

		if (!(get = MALLOC(sizeof(*get) + sizeof(ipvs_service_entry_t))))
			goto ipvs_get_service_err2;

		get->user.num_services = 0;

		msg = ipvs_nl_message(IPVS_CMD_GET_SERVICE, 0);
		if (!msg)
			goto ipvs_get_service_err;
		nl_service = nla_nest_start(msg, IPVS_CMD_ATTR_SERVICE);
		if (!nl_service)
			goto nla_put_failure;

		NLA_PUT_U16(msg, IPVS_SVC_ATTR_AF, af);

		if (fwmark) {
			NLA_PUT_U32(msg, IPVS_SVC_ATTR_FWMARK, fwmark);
		} else {
			NLA_PUT_U16(msg, IPVS_SVC_ATTR_PROTOCOL, protocol);
			NLA_PUT(msg, IPVS_SVC_ATTR_ADDR, sizeof(*addr), addr);
			NLA_PUT_U16(msg, IPVS_SVC_ATTR_PORT, port);
		}
		nla_nest_end(msg, nl_service);

		if (ipvs_nl_send_message(msg, ipvs_services_parse_cb, &get))
			goto ipvs_get_service_err;

		*svc = get->user.entrytable[0];
		FREE(get);

		return svc;

nla_put_failure:
		nlmsg_free(msg);
ipvs_get_service_err:
		FREE(get);
ipvs_get_service_err2:
		FREE(svc);
		return NULL;
	}
#endif

	if (af != AF_INET) {
		errno = EAFNOSUPPORT;
		return NULL;
	}

	len = sizeof(*svc);
	svc = MALLOC(len);
	if (!svc)
		return NULL;

	svc->user.fwmark = fwmark;
	svc->af = AF_INET;
	svc->user.protocol = protocol;
	svc->user.addr = addr->ip;
	svc->user.port = port;

	if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_SERVICE, svc, &len)) {
		FREE(svc);
		return NULL;
	}
	svc->af = AF_INET;
	svc->nf_addr.ip = svc->user.addr;
	svc->pe_name[0] = '\0';
#ifdef _WITH_LVS_64BIT_STATS_
	ipvs_copy_stats(&svc->stats, &svc->user.stats);
#endif

	return svc;
}
#endif	/* _WITH_SNMP_CHECKER_ */

void ipvs_close(void)
{
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		if (sock) {
			nl_socket_free(sock);
			sock = NULL;
		}
		return;
	}
#endif
	if (sockfd != -1) {
		close(sockfd);
		sockfd = -1;
	}
}

static struct table_struct {
	void *func;
	int err;
	const char *message;
} table [] = {
	{ ipvs_add_service, EEXIST, "Service already exists" },
	{ ipvs_add_service, ENOENT, "Scheduler or persistence engine not found" },
	{ ipvs_update_service, ENOENT, "Scheduler or persistence engine not found" },
	{ ipvs_add_dest, EEXIST, "Destination already exists" },
	{ ipvs_update_dest, ENOENT, "No such destination" },
	{ ipvs_del_dest, ENOENT, "No such destination" },
	{ ipvs_start_daemon, EEXIST, "Daemon has already run" },
	{ ipvs_stop_daemon, ESRCH, "No daemon is running" },
	{ NULL, ESRCH, "No such service" },
	{ NULL, EPERM, "Permission denied (you must be root)" },
	{ NULL, EINVAL, "Invalid operation.  Possibly wrong module version, address not unicast, ..." },
	{ NULL, ENOPROTOOPT, "Protocol not available" },
	{ NULL, ENOMEM, "Memory allocation problem" },
	{ NULL, EOPNOTSUPP, "Operation not supported with IPv6" },
	{ NULL, EAFNOSUPPORT, "Operation not supported with specified address family" },
	{ NULL, EMSGSIZE, "Module is wrong version" },
};

const char *
ipvs_strerror(int err)
{
	unsigned int i;

	for (i = 0; i < sizeof(table)/sizeof(struct table_struct); i++) {
		if ((!table[i].func || table[i].func == ipvs_func)
		    && table[i].err == err)
			return table[i].message;
	}

	return strerror(err);
}
