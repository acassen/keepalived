/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        nftables.h
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
 * Copyright (C) 2020-2020 Alexandre Cassen, <acassen@gmail.com>
 */

/* Up to commit 0ec6c01f this used libnftnl/libmnl, but that had overheads,
 * and constructing the netlink packets directly works just as well.
 */

#ifndef _CORE_NFTABLES_H
#define _CORE_NFTABLES_H

#include "config.h"

#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>

#include <net/if.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>

#ifdef HAVE_NFTNL_UDATA
#include <libnftnl/udata.h>
#endif
#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/set.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

//#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <errno.h>

#include "vrrp_nftables.h"
#include "logger.h"
#include "vrrp.h"
#include "vrrp_ipaddress.h"
#include "global_data.h"
#include "list_head.h"
#include "utils.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_firewall.h"
#endif


/* nft supports ifnames in sets from commit 8c61fa7 (release v0.8.3, libnftnl v1.0.9 (but 0.8.2 also uses that, 0.8.4 uses v1.1.0)) */
/* nft supports concatenated ranges from commit	8ac2f3b (release v0.9.4, libnftnl v1.1.6 and kernel 5.6) */

/* The following are from nftables source code (include/datatype.h)
 * and are used for it to determine how to display the entries in
 * the set. */
#define NFT_TYPE_STRING		5
#define NFT_TYPE_IPADDR		7
#define NFT_TYPE_IP6ADDR	8
#define NFT_TYPE_INET_SERVICE	13	
#define NFT_TYPE_MARK		19
#define NFT_TYPE_IFINDEX	20
#define NFT_TYPE_ICMPV6_TYPE	29
#define NFT_TYPE_IFNAME		41

#define NFT_TYPE_BITS		6
#define NFT_TYPE_MASK		((1 << NFT_TYPE_BITS) - 1)

/* For kernels < 4.1 */
#ifndef NFT_TABLE_MAXNAMELEN
#define NFT_TABLE_MAXNAMELEN 32
#endif

#ifdef HAVE_NFTNL_UDATA
/* This should be declared in /usr/include/libnftnl/udata.h */
enum byteorder {
	BYTEORDER_INVALID,
	BYTEORDER_HOST_ENDIAN,
	BYTEORDER_BIG_ENDIAN,
};

#ifndef NFTNL_UDATA_SET_MAX
/* libnftnl declared this from v1.1.3 */
enum udata_set_type {
	NFTNL_UDATA_SET_KEYBYTEORDER,
	NFTNL_UDATA_SET_DATABYTEORDER,
	NFTNL_UDATA_SET_MERGE_ELEMENTS,
	__NFTNL_UDATA_SET_MAX,
};
/* #define NFTNL_UDATA_SET_MAX (__NFTNL_UDATA_SET_MAX - 1) */
#endif
#endif

/* Local definitions */
#define NO_REG (NFT_REG_MAX+1)

extern struct mnl_socket *nl;
extern uint32_t seq;

#ifdef _WITH_VRRP_
extern void exchange_nl_msg_single(struct nlmsghdr *, int (*)(const struct nlmsghdr *, void *), bool *);
#endif
extern void my_mnl_nlmsg_batch_next(struct mnl_nlmsg_batch *);
extern void add_payload(struct nftnl_rule *, uint32_t, uint32_t, uint32_t, uint32_t);
extern void add_meta(struct nftnl_rule *, uint32_t, uint32_t);
#ifdef _WITH_LVS_
extern void add_meta_sreg(struct nftnl_rule *, uint32_t, uint32_t);
#endif
extern void add_lookup(struct nftnl_rule *, uint32_t, uint32_t, const char *, uint32_t, bool);
#if defined _WITH_VRRP_ && defined _WITH_NFTABLES_ && HAVE_DECL_NFTA_DUP_MAX && defined _HAVE_VRRP_VMAC_
extern void add_dup(struct nftnl_rule *, uint32_t, uint32_t);
#endif
extern void add_immediate_verdict(struct nftnl_rule *, uint32_t, const char *);
extern void add_cmp(struct nftnl_rule *, uint32_t, uint32_t, const void *, uint32_t);
#ifdef _WITH_VRRP_
extern void add_bitwise(struct nftnl_rule *, uint32_t, uint32_t, uint32_t, const void *, const void *);
#endif
extern void add_counter(struct nftnl_rule *);
extern struct nftnl_table * table_add_parse(uint16_t, const char *);
extern struct nftnl_chain * chain_add_parse(const char *, const char *);
extern struct nftnl_set *setup_set(uint8_t, const char *, const char *, int, int, int);
extern struct mnl_nlmsg_batch * nft_start_batch(void);
extern void nft_end_batch(struct mnl_nlmsg_batch *, bool);
extern void nft_discard_batch(struct mnl_nlmsg_batch *);
extern int set_nf_ifname_type(void);
#endif
