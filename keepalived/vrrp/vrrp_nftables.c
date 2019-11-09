/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_nftables.c
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
 * Copyright (C) 2001-2018 Alexandre Cassen, <acassen@gmail.com>
 */

/* Up to commit 0ec6c01f this used libnftnl/libmnl, but that had overheads,
 * and constructing the netlink packets directly works just as well.
 */

#include "config.h"

#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>

#include <net/if.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>

#ifdef HAVE_LIBNFTNL_UDATA_H
#include <libnftnl/udata.h>
#endif
#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/set.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <errno.h>

#include "vrrp_nftables.h"
#include "logger.h"
#include "vrrp.h"
#include "vrrp_ipaddress.h"
#include "global_data.h"
#include "list.h"
#include "utils.h"


/* nft supports ifnames in sets from commit 8c61fa7 (release v0.8.3, libnftnl v1.0.9 (but 0.8.2 also uses that, 0.8.4 uses v1.1.0)) */

/* The following are from nftables source code (include/datatype.h)
 * and are used for it to determine how to display the entries in
 * the set. */
#define TYPE_STRING		5
#define TYPE_IPADDR		7
#define TYPE_IP6ADDR		8
#define TYPE_IFINDEX		20
#define TYPE_ICMPV6_TYPE	29
#define TYPE_IFNAME		41

#define TYPE_BITS               6
#define TYPE_MASK               ((1 << TYPE_BITS) - 1)

#ifdef HAVE_LIBNFTNL_UDATA_H
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

static const char vmac_map_name[] = "vmac_map";

static struct mnl_socket *nl;
static unsigned int portid;
static uint32_t seq;

static int ifname_type;

static bool ipv4_table_setup;
static bool ipv4_vips_setup;
static bool ipv6_table_setup;
static bool ipv6_vips_setup;
static bool setup_ll_ifname;
static bool setup_ll_ifindex;
#ifdef _HAVE_VRRP_VMAC_
static bool ipv4_igmp_setup;
static bool ipv6_igmp_setup;
#endif

#ifdef _INCLUDE_UNUSED_CODE_
static int
table_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = (const struct nlattr **)data;

	tb[attr->nla_type & NLA_TYPE_MASK] = attr;
	return MNL_CB_OK;
}

static void
new_table(const struct nlmsghdr *nlh)
{
	struct nlattr *tb[NFTA_TABLE_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);

	if (mnl_attr_parse(nlh, sizeof(*nfg), table_cb, tb) < 0) {
		log_message(LOG_INFO, "table parse failed");
		return;
	}

	if (tb[NFTA_TABLE_NAME] && tb[NFTA_TABLE_HANDLE])
		log_message(LOG_INFO, "Table %s: handle %lu", mnl_attr_get_str(tb[NFTA_TABLE_NAME]), be64toh(mnl_attr_get_u64(tb[NFTA_TABLE_HANDLE])));
}

static int
cb_func(const struct nlmsghdr *nlh, void *data)
{
	if (NFNL_SUBSYS_ID(nlh->nlmsg_type) != NFNL_SUBSYS_NFTABLES)
		return 1;
	switch NFNL_MSG_TYPE(nlh->nlmsg_type) {
		case NFT_MSG_NEWTABLE: log_message(LOG_INFO, "%s", "NFT_MSG_NEWTABLE"); new_table(nlh);break;
		case NFT_MSG_NEWCHAIN: log_message(LOG_INFO, "%s", "NFT_MSG_NEWCHAIN"); break;
		case NFT_MSG_NEWSET: log_message(LOG_INFO, "%s", "NFT_MSG_NEWSET"); break;
		case NFT_MSG_NEWRULE: log_message(LOG_INFO, "%s", "NFT_MSG_NEWRULE"); break;
		case NFT_MSG_NEWSETELEM: log_message(LOG_INFO, "%s", "NFT_MSG_NEWSETELEM"); break;
		default: log_message(LOG_INFO, "Unknown msg type"); break;
	}

	return 1;
}
#endif

#if defined HAVE_LIBNFTNL_UDATA_H && !defined HAVE_NFTNL_UDATA_PUT_U32
static uint8_t
nftnl_udata_put_u32(struct nftnl_udata_buf *buf, uint8_t type, uint32_t data)
{
	return nftnl_udata_put(buf, type, sizeof(data), &data);
}
#endif


static bool
nl_socket_open(void)
{
	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		log_message(LOG_INFO, "mnl_socket_open failed - %d", errno);
		return false;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		log_message(LOG_INFO, "mnl_socket_bind error - %d", errno);
		mnl_socket_close(nl);
		nl = NULL;
		return false;
	}

	portid = mnl_socket_get_portid(nl);

	return true;
}

static void
exchange_nl_msg(struct mnl_nlmsg_batch *batch)
{
	int ret;
	char *buf;
	size_t buf_size;
	long mnl_buf_size;

	if (mnl_nlmsg_batch_is_empty(batch))
		return;

#if 0
	FILE *fp = fopen("/tmp/nftrace", "a");
	mnl_nlmsg_fprintf(fp, (char *)mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch), sizeof( struct nfgenmsg));
	fclose(fp);
#endif
	if (!nl && !nl_socket_open())
		return;

	if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
			      mnl_nlmsg_batch_size(batch)) < 0) {
		log_message(LOG_INFO, "mnl_socket_send error - %d", errno);
		return;
	}

	mnl_buf_size = MNL_SOCKET_BUFFER_SIZE;
	if (mnl_buf_size < 1)
		buf_size = 8192L;
	else
		buf_size = (size_t)mnl_buf_size;

	buf = MALLOC(buf_size);
	while ((ret = mnl_socket_recvfrom(nl, buf, buf_size)) > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, NULL, NULL);
		if (ret <= 0)
			break;
	}
	FREE(buf);

	if (ret == -1)
		log_message(LOG_INFO, "mnl_socket_recvfrom error - %d", errno);
}

static int
table_cb(__attribute__((unused)) const struct nlmsghdr *nlh, void *data)
{
	*(bool *)data = true;

        return MNL_CB_OK;
}

static void
exchange_nl_msg_single(struct nlmsghdr *nlm, int (*cb_func)(const struct nlmsghdr *, void*), bool *success)
{
	int ret;
	char buf[256];

#if 0
	FILE *fp = fopen("/tmp/nftrace", "a");
	mnl_nlmsg_fprintf(fp, (char *)nlm, nlm->nlmsg_len, 0);
	fclose(fp);
#endif

	if (!nl && !nl_socket_open())
		return;

	if (mnl_socket_sendto(nl, nlm, nlm->nlmsg_len) < 0) {
		log_message(LOG_INFO, "mnl_socket_send error - %d", errno);
		return ;
	}

	*success = false;
	while ((ret = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, cb_func, success);
		if (ret <= 0)
			break;
	}

	if (ret == -1 && errno != ENOENT)
		log_message(LOG_INFO, "mnl_socket_recvfrom single error - %d", errno);
}

static void
my_mnl_nlmsg_batch_next(struct mnl_nlmsg_batch *batch)
{
	if (!mnl_nlmsg_batch_next(batch)) {
		exchange_nl_msg(batch);
		mnl_nlmsg_batch_reset(batch);
	}
}

static void
add_payload(struct nftnl_rule *r, uint32_t base, uint32_t dreg,
			uint32_t offset, uint32_t len)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("payload");
	if (e == NULL) {
		log_message(LOG_INFO, "expr payload oom error - %d", errno);
		return;
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, base);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, dreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);

	nftnl_rule_add_expr(r, e);
}

static void
add_meta(struct nftnl_rule *r, uint32_t ifindex, uint32_t dreg)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("meta");
	if (e == NULL) {
		log_message(LOG_INFO, "expr payload oom error - %d", errno);
		return;
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_META_DREG, dreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_META_KEY, ifindex);

	nftnl_rule_add_expr(r, e);
}

static void
add_lookup(struct nftnl_rule *r, uint32_t base, uint32_t dreg, const char *set_name,
			uint32_t set_id,
#ifndef HAVE_NFTNL_EXPR_LOOKUP_FLAGS
			__attribute__((unused))
#endif
						bool neg)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("lookup");
	if (e == NULL) {
		log_message(LOG_INFO, "expr lookup oom error - %d", errno);
		return;
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_SREG, base);
	if (dreg != NO_REG)
		nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_DREG, dreg);
#ifdef HAVE_NFTNL_EXPR_LOOKUP_FLAGS
	if (neg)
		nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_FLAGS, NFT_LOOKUP_F_INV);
#endif
	nftnl_expr_set_str(e, NFTNL_EXPR_LOOKUP_SET, set_name);
	if (set_id)
		nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_SET_ID, set_id);

	nftnl_rule_add_expr(r, e);
}

#if HAVE_DECL_NFTA_DUP_MAX
static void
add_dup(struct nftnl_rule *r, uint32_t addr_reg, uint32_t dev_reg)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("dup");
	if (e == NULL) {
		log_message(LOG_INFO, "dup payload oom error - %d", errno);
		return;
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_DUP_SREG_ADDR, addr_reg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_DUP_SREG_DEV, dev_reg);

	nftnl_rule_add_expr(r, e);
}
#endif

/* verdict shoud be NF_DROP, NF_ACCEPT, NFT_RETURN, ... */
/* "The nf_tables verdicts share their numeric space with the netfilter verdicts." */
static void
add_immediate_verdict(struct nftnl_rule *r, uint32_t verdict, const char *chain)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("immediate");
	if (e == NULL) {
		log_message(LOG_INFO, "expr immediate oom error - %d", errno);
		return;
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
	if (chain)
		nftnl_expr_set_str(e, NFTNL_EXPR_IMM_CHAIN, chain);
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_VERDICT, verdict);

	nftnl_rule_add_expr(r, e);
}

#if HAVE_DECL_NFTA_DUP_MAX
static void
add_immediate_data(struct nftnl_rule *r, uint32_t reg, const void *data, uint32_t data_len)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("immediate");
	if (e == NULL) {
		log_message(LOG_INFO, "expr immediate oom error - %d", errno);
		return;
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, reg);
	nftnl_expr_set(e, NFTNL_EXPR_IMM_DATA, data, data_len);

	nftnl_rule_add_expr(r, e);
}
#endif

static void
add_cmp(struct nftnl_rule *r, uint32_t sreg, uint32_t op,
		    const void *data, uint32_t data_len)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("cmp");
	if (e == NULL) {
		log_message(LOG_INFO, "expr cmp oom error - %d", errno);
		return;
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_SREG, sreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_OP, op);
	nftnl_expr_set(e, NFTNL_EXPR_CMP_DATA, data, data_len);

	nftnl_rule_add_expr(r, e);
}

static void
add_counter(struct nftnl_rule *r)
{
	struct nftnl_expr *e;

	if (!global_data->vrrp_nf_counters)
		return;

	e = nftnl_expr_alloc("counter");
	if (e == NULL) {
		log_message(LOG_INFO, "expr counter oom error - %d", errno);
		return;
	}

	nftnl_rule_add_expr(r, e);
}

static struct nftnl_table *
table_add_parse(uint16_t family, const char *table)
{
	struct nftnl_table *t;

	t = nftnl_table_alloc();
	if (t == NULL) {
		log_message(LOG_INFO, "OOM error - %d", errno);
		return NULL;
	}

	nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, family);
	nftnl_table_set_str(t, NFTNL_TABLE_NAME, table);

	return t;
}

static struct
nftnl_chain *chain_add_parse(const char *table, const char *name)
{
	struct nftnl_chain *t;

	t = nftnl_chain_alloc();
	if (t == NULL) {
		log_message(LOG_INFO, "OOM error - %d", errno);
		return NULL;
	}
	nftnl_chain_set(t, NFTNL_CHAIN_TABLE, table);
	nftnl_chain_set(t, NFTNL_CHAIN_NAME, name);

	return t;
}

/* For an anonymous set use set name "__set%d", and retrieve set_id with:
        set_id = nftnl_set_get_u32(s, NFTNL_SET_ID);
 *
 * To add a rule referencing the set, setname is "__set%d", and set set_id:
	if (set_id)
		nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_SET_ID, set_id);

 * It works similarly for maps
*/
static struct
nftnl_set *setup_set(uint8_t family, const char *table,
				 const char *name, int type,
				 int set_type, int data_type)
{
	struct nftnl_set *s = NULL;
#ifdef HAVE_LIBNFTNL_UDATA_H
	struct nftnl_udata_buf *udbuf;
#endif
	static int set_id = 0;
	int type_copy = type;
	int size = 0;
	int data_size = 0;

	s = nftnl_set_alloc();
	if (s == NULL) {
		log_message(LOG_INFO, "OOM error - %d", errno);
		return NULL;
	}

	while (type_copy) {
		switch (type_copy & TYPE_MASK)
		{
		case TYPE_IPADDR:
			size += sizeof(struct in_addr);
			break;
		case TYPE_IP6ADDR:
			size += sizeof(struct in6_addr);
			break;
		case TYPE_IFINDEX:
			size += sizeof(uint32_t);
			break;
		case TYPE_ICMPV6_TYPE:
			size++;
			break;
		case TYPE_IFNAME:
		case TYPE_STRING:	/* Used if nft doesn't support ifname type */
			size += IFNAMSIZ;
			break;
		default:
			log_message(LOG_INFO, "Unsupported type %d\n", type_copy & TYPE_MASK);
			break;
		}
		type_copy >>= TYPE_BITS;
	}

	if (set_type & NFT_SET_MAP) {
		switch (data_type)
		{
		case TYPE_IPADDR:
			data_size = sizeof(struct in_addr);
			break;
		case TYPE_IP6ADDR:
			data_size = sizeof(struct in6_addr);
			break;
		case TYPE_IFINDEX:
			data_size = sizeof(uint32_t);
			break;
		case TYPE_ICMPV6_TYPE:
			data_size = 1;
			break;
		case TYPE_IFNAME:
			data_size = IFNAMSIZ;
			break;
		default:
			log_message(LOG_INFO, "Unsupported type %d\n", data_type);
			break;
		}
	}

	nftnl_set_set_str(s, NFTNL_SET_TABLE, table);
	nftnl_set_set_str(s, NFTNL_SET_NAME, name);
	nftnl_set_set_u32(s, NFTNL_SET_FAMILY, family);
	nftnl_set_set_u32(s, NFTNL_SET_KEY_LEN, size);
	/* inet service type, see nftables/include/datatypes.h */
	nftnl_set_set_u32(s, NFTNL_SET_KEY_TYPE, type);
	if (set_type & NFT_SET_MAP) {
		nftnl_set_set_u32(s, NFTNL_SET_FLAGS, set_type);
		nftnl_set_set_u32(s, NFTNL_SET_DATA_TYPE, data_type);
		nftnl_set_set_u32(s, NFTNL_SET_DATA_LEN, data_size);
	}
	nftnl_set_set_u32(s, NFTNL_SET_ID, ++set_id);

#ifdef HAVE_LIBNFTNL_UDATA_H
	if (set_type & NFT_SET_MAP) {
		udbuf = nftnl_udata_buf_alloc(NFT_USERDATA_MAXLEN);
		if (!udbuf) {
			log_message(LOG_INFO, "OOM error - %d", errno);
			return NULL;
		}

		nftnl_udata_put_u32(udbuf, NFTNL_UDATA_SET_KEYBYTEORDER, BYTEORDER_HOST_ENDIAN);
		nftnl_udata_put_u32(udbuf, NFTNL_UDATA_SET_DATABYTEORDER, BYTEORDER_HOST_ENDIAN);

		nftnl_set_set_data(s, NFTNL_SET_USERDATA, nftnl_udata_buf_data(udbuf),
				   nftnl_udata_buf_len(udbuf));
		nftnl_udata_buf_free(udbuf);
	}
#endif

	return s;
}

static struct
nftnl_rule *setup_rule(uint8_t family, const char *table,
		   const char *chain, const char *handle,
		   const char *set, bool saddr, uint32_t verdict, bool neg)
{
	struct nftnl_rule *r = NULL;
	uint64_t handle_num;

	r = nftnl_rule_alloc();
	if (r == NULL) {
		log_message(LOG_INFO, "OOM error - %d", errno);
		return NULL;
	}

	nftnl_rule_set(r, NFTNL_RULE_TABLE, table);
	nftnl_rule_set(r, NFTNL_RULE_CHAIN, chain);
	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);

	if (handle != NULL) {
		handle_num = atoll(handle);
		nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, handle_num);
	}

	/* Use nft --debug netlink,mnl to see the netlink message for an nft command.
	 * nft --debug all gives more info
	 * nft monitor --debug all - allows monitoring of iptables-nft etc.
	 * mnl_nlmsg_fprintf is the function that prints it if
	 * we want to view what we have constructed
	 *
	 * The indentation is added to show the nesting. To indent a nested block,
	 * the number of lines to indent is (length / 4 - 1).
	 *
	----------------	------------------
	|  0000000020  |	| message length |
	| 00016 | R--- |	|  type | flags  |	NFNL_MSG_BATCH_BEGIN | REQUEST
	|  0000000003  |	| sequence number|
	|  0000000000  |	|     port ID    |
	----------------	------------------
	| 00 00 0a 00  |	|  extra header  |	family = AF_UNSPEC, version = NFNETLINK_V0 , res_id = NFNL_SUBSYS_NFTABLES
	----------------	------------------
	----------------	------------------
	|  0000000208  |	| message length |
	| 02566 | R--- |	|  type | flags  |	NEWRULE | REQUEST
	|  0000000004  |	| sequence number|
	|  0000000000  |	|     port ID    |
	----------------	------------------
	|00011|--|00001|	|len |flags| type|	NFTA_RULE_TABLE	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, str);
	| 66 69 6c 74  |	|      data      |	 f i l t
	| 65 72 00 00  |	|      data      |	 e r
	|00018|--|00002|	|len |flags| type|	NFTA_RULE_CHAIN
	| 6b 65 65 70  |	|      data      |	 k e e p
	| 61 6c 69 76  |	|      data      |	 a l i v
	| 65 64 5f 69  |	|      data      |	 e d _ i
	| 6e 00 00 00  |	|      data      |	 n
	|00156|N-|00004|	|len |flags| type|	NFT_RULE_EXPRESSIONS	(see nftnl_rule_nlmsg_build_payload, netlink_gen_expr)
	  |00052|N-|00001|	|len |flags| type|		NFTA_LIST_ELEM | NEST (to add - nftnl_rule_add_expr)
	    |00012|--|00001|	|len |flags| type|	NFTA_EXPR_NAME	(see netlink_gen_payload)
	    | 70 61 79 6c  |	|      data      |	 p a y l
	    | 6f 61 64 00  |	|      data      |	 o a d
	    |00036|N-|00002|	|len |flags| type| 	NFTA_EXPR_DATA | NEST
	      |00008|--|00001|	|len |flags| type|	NFTNL_EXPR_PAYLOAD_DREG
	      | 00 00 00 01  |	|      data      |	  NFT_REG_1
	      |00008|--|00002|	|len |flags| type|	NFTNL_EXPR_PAYLOAD_BASE
	      | 00 00 00 01  |	|      data      |	  NFT_PAYLOAD_NETWORK_HEADER
	      |00008|--|00003|	|len |flags| type|	NFTNL_EXPR_PAYLOAD_OFFSET
	      | 00 00 00 10  |	|      data      |	  offset 16
	      |00008|--|00004|	|len |flags| type|	NFTNL_EXPR_PAYLOAD_LEN
	      | 00 00 00 04  |	|      data      | 	  length 4
	  |00052|N-|00001|	|len |flags| type| 		NFTA_LIST_ELEM | NEST (netlink_gen_set_stmt)
	    |00011|--|00001|	|len |flags| type|	NFTA_EXPR_NAME	(see netlink_gen_lookup)
	    | 6c 6f 6f 6b  |	|      data      |	 l o o k
	    | 75 70 00 00  |	|      data      |	 u p
	    |00036|N-|00002|	|len |flags| type|	NFTA_EXPR_DATA | NEST
	      |00008|--|00002|	|len |flags| type|	NFTNL_EXPR_LOOKUP_SREG
	      | 00 00 00 01  |	|      data      |	  NFT_REG_1
	      |00015|--|00001|	|len |flags| type|	NFTNL_EXPR_LOOKUP_SET
	      | 6b 65 65 70  |	|      data      |	 k e e p
	      | 61 6c 69 76  |	|      data      |	 a l i v
	      | 65 64 00 00  |	|      data      |	 e d
	      |00008|--|00004|	|len |flags| type|	NFTNL_EXPR_LOOKUP_SET_ID
	      | 00 00 00 01  |	|      data      |	 set 1 (Appears not needed)
	  |00048|N-|00001|	|len |flags| type|		NFTA_LIST_ELEM | NEST (netlink_get_verdict_stmt from netlink_gen_stmt)
	    |00014|--|00001|	|len |flags| type|	NFTA_EXPR_NAME (see netlink_gen_immediate)
	    | 69 6d 6d 65  |	|      data      |	 i m m e
	    | 64 69 61 74  |	|      data      |	 d i a t
	    | 65 00 00 00  |	|      data      |	 e
	    |00028|N-|00002|	|len |flags| type|	NFTA_EXPR_DATA | NEST
	      |00008|--|00001|	|len |flags| type| NFTNL_EXPR_IMM_DREG = NFTA_IMMEDIATE_DREG
	      | 00 00 00 00  |	|      data      |  NFT_REG_VERDICT
	      |00016|N-|00002|	|len |flags| type| NFTNL_EXPR_IMM_VERDICT = NFTA_IMMEDIATE_DATA
	        |00012|N-|00002|	|len |flags| type|  NFTA_DATA_VERDICT
	          |00008|--|00001|	|len |flags| type|  NFTA_VERDICT_CODE
	          | 00 00 00 00  |	|      data      |  NF_DROP
	----------------	------------------
	----------------	------------------
	|  0000000020  |	| message length |
	| 00017 | R--- |	|  type | flags  |	NFNL_MSG_BATCH_END | REQUEST
	|  0000000005  |	| sequence number|
	|  0000000000  |	|     port ID    |
	----------------	------------------
	| 00 00 0a 00  |	|  extra header  |	family = AF_UNSPEC, version = NFNETLINK_V0 , res_id = NFNL_SUBSYS_NFTABLES
	----------------	------------------
	*/
	if (family == NFPROTO_IPV4)
		add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
			    saddr ? offsetof(struct iphdr, saddr) : offsetof(struct iphdr, daddr), sizeof(uint32_t));
	else
		add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
			    saddr ? offsetof(struct ip6_hdr, ip6_src) : offsetof(struct ip6_hdr, ip6_dst), sizeof(struct in6_addr));

	add_lookup(r, NFT_REG_1, NO_REG, set, 0, neg);

	add_counter(r);

	add_immediate_verdict(r, verdict, NULL);

	return r;
}

static struct
nftnl_rule *setup_rule_if(uint8_t family, const char *table,
				   const char *chain, const char *handle,
				   const char *set, bool saddr, bool use_name, uint32_t verdict, bool neg)
{
	struct nftnl_rule *r = NULL;
	uint64_t handle_num;

	/*
	----------------	------------------
	|  0000000264  |	| message length |
	| 02566 | R--- |	|  type | flags  |
	|  0000000004  |	| sequence number|
	|  0000000000  |	|     port ID    |
	----------------	------------------
	| 0a 00 00 00  |	|  extra header  |
	|00015|--|00001|	|len |flags| type| NFTA_RULE_TABLE
	| 6b 65 65 70  |	|      data      |	 k e e p
	| 61 6c 69 76  |	|      data      |	 a l i v
	| 65 64 00 00  |	|      data      |	 e d
	|00018|--|00002|	|len |flags| type| NFTA_RULE_CHAIN
	| 69 6e 5f 6c  |	|      data      |	 i n _ l
	| 69 6e 6b 5f  |	|      data      |	 i n k _
	| 6c 6f 63 61  |	|      data      |	 l o c a
	| 6c 00 00 00  |	|      data      |	 l
	|00208|N-|00004|	|len |flags| type| NFTA_RULE_EXPRESSIONS
	  |00052|N-|00001|	|len |flags| type| NFTA_LIST_ELEM
	    |00012|--|00001|	|len |flags| type| NFTA_EXPR_NAME
	      | 70 61 79 6c  |	|      data      |	 p a y l
	      | 6f 61 64 00  |	|      data      |	 o a d
	    |00036|N-|00002|	|len |flags| type| NFTA_EXPR_DATA
	      |00008|--|00001|	|len |flags| type| DREG
	      | 00 00 00 01  |	|      data      | NFT_REG_1
	      |00008|--|00002|	|len |flags| type| BASE
	      | 00 00 00 01  |	|      data      |  NFT_PAYLOAD_NETWORK_HEADER
	      |00008|--|00003|	|len |flags| type| OFFSET
	      | 00 00 00 18  |	|      data      |
	      |00008|--|00004|	|len |flags| type| LEN
	      | 00 00 00 10  |	|      data      |
	  |00036|N-|00001|	|len |flags| type| NFTA_LIST_ELEM
	    |00009|--|00001|	|len |flags| type| NFTA_EXPR_NAME
	    | 6d 65 74 61  |	|      data      |	 m e t a
	    | 00 00 00 00  |	|      data      |
	    |00020|N-|00002|	|len |flags| type| NFTA_EXPR_DATA
	      |00008|--|00002|	|len |flags| type| NFTA_META_KEY
	      | 00 00 00 06  |	|      data      | NFT_META_IIFNAME
	      |00008|--|00001|	|len |flags| type| NFTA_META_DREG
	      | 00 00 00 02  |	|      data      |NFT_REG_2
	  |00048|N-|00001|	|len |flags| type| NFTA_LIST_ELEM
	    |00011|--|00001|	|len |flags| type| NFTA_EXPR_NAME
	    | 6c 6f 6f 6b  |	|      data      |	 l o o k
	    | 75 70 00 00  |	|      data      |	 u p
	    |00032|N-|00002|	|len |flags| type| NFTA_EXPR_DATA
	      |00008|--|00002|	|len |flags| type| NFTA_LOOKUP_SREG
	      | 00 00 00 01  |	|      data      | NFT_REG_1
	      |00010|--|00001|	|len |flags| type| NFTA_LOOKUP_SET
	      | 69 66 5f 6c  |	|      data      |	 i f _ l
	      | 6c 00 00 00  |	|      data      |	 l
	      |00008|--|00004|	|len |flags| type| NFTA_LOOKUP_SET_ID
	      | 00 00 00 06  |	|      data      |
	  |00020|N-|00001|	|len |flags| type| NFTA_LIST_ELEM
	    |00012|--|00001|	|len |flags| type| NFTA_EXPR_NAME
	    | 63 6f 75 6e  |	|      data      |	 c o u n
	    | 74 65 72 00  |	|      data      |	 t e r
	    |00004|N-|00002|	|len |flags| type| NFTA_COUNTER_PACKETS
	  |00048|N-|00001|	|len |flags| type| NFTA_LIST_ELEM
	    |00014|--|00001|	|len |flags| type| NFTA_EXPR_NAME
	    | 69 6d 6d 65  |	|      data      |	 i m m e
	    | 64 69 61 74  |	|      data      |	 d i a t
	    | 65 00 00 00  |	|      data      |	 e
	    |00028|N-|00002|	|len |flags| type| NFTA_EXPR_DATA
	      |00008|--|00001|	|len |flags| type| NFTA_IMMEDIATE_DREG
	      | 00 00 00 00  |	|      data      | NFT_REG_VERDICT
	      |00016|N-|00002|	|len |flags| type| NFTA_IMMEDIATE_DATA
	        |00012|N-|00002|	|len |flags| type| NFTA_DATA_VERDICT
	          |00008|--|00001|	|len |flags| type| NFTA_VERDICT_CODE
	          | 00 00 00 00  |	|      data      | NF_DROP
	----------------	------------------
	*/
	r = nftnl_rule_alloc();
	if (r == NULL) {
		log_message(LOG_INFO, "OOM error - %d", errno);
		return NULL;
	}

	nftnl_rule_set(r, NFTNL_RULE_TABLE, table);
	nftnl_rule_set(r, NFTNL_RULE_CHAIN, chain);
	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);

	if (handle != NULL) {
		handle_num = atoll(handle);
		nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, handle_num);
	}

	if (family == NFPROTO_IPV4)
		add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
			    saddr ? offsetof(struct iphdr, saddr) : offsetof(struct iphdr, daddr), sizeof(uint32_t));
	else
		add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
			    saddr ? offsetof(struct ip6_hdr, ip6_src) : offsetof(struct ip6_hdr, ip6_dst), sizeof(struct in6_addr));

	if (saddr)
		add_meta(r, use_name ? NFT_META_OIFNAME : NFT_META_OIF, NFT_REG_2);
	else
		add_meta(r, use_name ? NFT_META_IIFNAME : NFT_META_IIF, NFT_REG_2);

	add_lookup(r, NFT_REG_1, NO_REG, set, 0, neg);

	add_counter(r);

	add_immediate_verdict(r, verdict, NULL);

	return r;
}

static struct nftnl_rule
*setup_rule_range_goto(uint8_t family, const char *table,
				   const char *chain, const char *handle,
				   const char *chain_dest, bool saddr)
{
	struct nftnl_rule *r = NULL;
	uint64_t handle_num;
	struct in6_addr ip6;

	r = nftnl_rule_alloc();
	if (r == NULL) {
		log_message(LOG_INFO, "OOM error - %d", errno);
		return NULL;
	}

	nftnl_rule_set(r, NFTNL_RULE_TABLE, table);
	nftnl_rule_set(r, NFTNL_RULE_CHAIN, chain);
	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);

	/*
	----------------	------------------
	|  0000000020  |	| message length |
	| 00016 | R--- |	|  type | flags  |
	|  0000000003  |	| sequence number|
	|  0000000000  |	|     port ID    |
	----------------	------------------
	| 00 00 0a 00  |	|  extra header  |
	----------------	------------------
	----------------	------------------
	|  0000000292  |	| message length |
	| 02566 | R--- |	|  type | flags  | NFT_MSG_NEWRULE
	|  0000000004  |	| sequence number|
	|  0000000000  |	|     port ID    |
	----------------	------------------
	| 0a 00 00 00  |	|  extra header  |
	|00011|--|00001|	|len |flags| type|
	| 66 69 6c 74  |	|      data      |	 f i l t
	| 65 72 00 00  |	|      data      |	 e r
	|00018|--|00002|	|len |flags| type|
	| 6b 65 65 70  |	|      data      |	 k e e p
	| 61 6c 69 76  |	|      data      |	 a l i v
	| 65 64 5f 69  |	|      data      |	 e d _ i
	| 6e 00 00 00  |	|      data      |	 n
	|00240|N-|00004|	|len |flags| type|
	  |00052|N-|00001|	|len |flags| type|
	  |00012|--|00001|	|len |flags| type|
	  | 70 61 79 6c  |	|      data      |	 p a y l
	  | 6f 61 64 00  |	|      data      |	 o a d
	    |00036|N-|00002|	|len |flags| type|     EXPR_DATA
	      |00008|--|00001|	|len |flags| type|	NFTNL_EXPR_PAYLOAD_DREG 1
	      | 00 00 00 01  |	|      data      |
	      |00008|--|00002|	|len |flags| type|	NFTNL_EXPR_PAYLOAD_BASE 1
	      | 00 00 00 01  |	|      data      |	NFT_PAYLOAD_NETWORK_HEADER
	      |00008|--|00003|	|len |flags| type|   NFTNL_EXPR_PAYLOAD_PAYLOAD OFFSET 24
	      | 00 00 00 18  |	|      data      |
	      |00008|--|00004|	|len |flags| type|	NFTNL_EXPR_PAYLOAD_PAYLOAD_LEN 16
	      | 00 00 00 10  |	|      data      |

	  |00056|N-|00001|	|len |flags| type|		LIST_ELEM
	    |00008|--|00001|	|len |flags| type|	NFTNL_EXPR_NAME
	    | 63 6d 70 00  |	|      data      |	 c m p
	    |00044|N-|00002|	|len |flags| type|	EXPR_DATA
	      |00008|--|00001|	|len |flags| type|	NFTNL_EXPR_CMP_SREG = NFTA_CMP_SREG - look at nftnl_expr_***_build
	      | 00 00 00 01  |	|      data      |	NFT_REG_1
	      |00008|--|00002|	|len |flags| type|	NFTNL_EXPR_CMP_OP = NFTA_CMP_OP
	      | 00 00 00 05  |	|      data      |	NFT_CMP_GTE
	      |00024|N-|00003|	|len |flags| type|	NFTNL_EXPR_CMP_DATA = NFTA_CMP_DATA
	        |00020|--|00001|	|len |flags| type| NFTA_DATA_VALUE
	        | fe 80 00 00  |	|      data      |
	        | 00 00 00 00  |	|      data      |
	        | 00 00 00 00  |	|      data      |
	        | 00 00 00 00  |	|      data      |
	  |00056|N-|00001|	|len |flags| type| NFTA_LIST_ELEM
	    |00008|--|00001|	|len |flags| type|
	    | 63 6d 70 00  |	|      data      |	 c m p
	    |00044|N-|00002|	|len |flags| type|
	      |00008|--|00001|	|len |flags| type|
	      | 00 00 00 01  |	|      data      |
	      |00008|--|00002|	|len |flags| type|
	      | 00 00 00 03  |	|      data      |	NFT_CMP_LTE
	      |00024|N-|00003|	|len |flags| type|
	        |00020|--|00001|	|len |flags| type|
	        | fe bf 00 00  |	|      data      |
	        | 00 00 00 00  |	|      data      |
	        | 00 00 00 00  |	|      data      |
	      | 00 00 ff ff  |	|      data      |
	|00072|N-|00001|	|len |flags| type| NFTA_LIST_ELEM
	    |00014|--|00001|	|len |flags| type|	NFTA_EXPR_NAME
	    | 69 6d 6d 65  |	|      data      |	 i m m e
	    | 64 69 61 74  |	|      data      |	 d i a t
	    | 65 00 00 00  |	|      data      |	 e

	    |00052|N-|00002|	|len |flags| type| NFTA_EXPR_DATA
	      |00008|--|00001|	|len |flags| type| NFTA_IMMEDIATE_DREG
	      | 00 00 00 00  |	|      data      | NFT_REG_VERDICT

	      |00040|N-|00002|	|len |flags| type| NFTNL_EXPR_IMM_VERDICT
	        |00036|N-|00002|	|len |flags| type| NFTA_DATA_VERDICT
	          |00008|--|00001|	|len |flags| type| NFTA_VERDICT_CODE
	          | ff ff ff fc  |	|      data      | NFT_GOTO
	          |00021|--|00002|	|len |flags| type| NFTA_VERDICT_DATA
	          | 6b 65 65 70  |	|      data      |	 k e e p
	          | 61 6c 69 76  |	|      data      |	 a l i v
	          | 65 64 5f 69  |	|      data      |	 e d _ i
	          | 6e 5f 6c 6c  |	|      data      |	 n _ l l
	          | 00 00 00 00  |	|      data      |
	----------------	------------------
	----------------	------------------
	|  0000000020  |	| message length |
	| 00017 | R--- |	|  type | flags  |
	|  0000000005  |	| sequence number|
	|  0000000000  |	|     port ID    |
	----------------	------------------
	| 00 00 0a 00  |	|  extra header  |
	----------------	------------------
	*/

	if (handle != NULL) {
		handle_num = atoll(handle);
		nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, handle_num);
	}

	add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
		    saddr ? offsetof(struct ip6_hdr, ip6_src) : offsetof(struct ip6_hdr, ip6_dst), sizeof(struct in6_addr));

	/* The following is interpreted as a range by nftables */
	ip6.s6_addr32[0] = htonl(0xfe800000);
	ip6.s6_addr32[1] = ip6.s6_addr32[2] = ip6.s6_addr32[3] = 0;
	add_cmp(r, NFT_REG_1, NFT_CMP_GTE, &ip6, sizeof(ip6));

	ip6.s6_addr32[0] = htonl(0xfebfffff);
	ip6.s6_addr32[1] = ip6.s6_addr32[2] = ip6.s6_addr32[3] = 0xffffffff;
	add_cmp(r, NFT_REG_1, NFT_CMP_LTE, &ip6, sizeof(ip6));

	add_counter(r);

	add_immediate_verdict(r, NFT_GOTO, chain_dest);

	return r;
}

static struct nftnl_rule *
setup_rule_icmpv6(uint8_t family, const char *table,
				   const char *chain, const char *handle,
				   const char *set, uint32_t set_id, uint32_t verdict, bool neg)
{
	struct nftnl_rule *r = NULL;
	uint64_t handle_num;
	struct ip6_hdr ip6;
	struct icmp6_hdr icmp6;

	r = nftnl_rule_alloc();
	if (r == NULL) {
		log_message(LOG_INFO, "OOM error - %d", errno);
		return NULL;
	}

	nftnl_rule_set(r, NFTNL_RULE_TABLE, table);
	nftnl_rule_set(r, NFTNL_RULE_CHAIN, chain);
	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);

	if (handle != NULL) {
		handle_num = atoll(handle);
		nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, handle_num);
	}

	ip6.ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_ICMPV6;
	add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
		    offsetof(struct ip6_hdr, ip6_ctlun.ip6_un1.ip6_un1_nxt), sizeof(ip6.ip6_ctlun.ip6_un1.ip6_un1_nxt));
	add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &ip6.ip6_ctlun.ip6_un1.ip6_un1_nxt, sizeof(ip6.ip6_ctlun.ip6_un1.ip6_un1_nxt));

	add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
		    offsetof(struct icmp6_hdr, icmp6_type), sizeof(icmp6.icmp6_type));
	add_lookup(r, NFT_REG_1, NO_REG, set, set_id, neg);

	add_counter(r);

	add_immediate_verdict(r, verdict, NULL);

	return r;
}

#ifdef _INCLUDE_UNUSED_CODE_
static struct nftnl_rule *setup_rule_simple(uint8_t family, const char *table,
				   const char *chain, const char *handle,
				   uint32_t verdict)
{
	struct nftnl_rule *r = NULL;
	uint64_t handle_num;

	r = nftnl_rule_alloc();
	if (r == NULL) {
		log_message(LOG_INFO, "OOM error - %d", errno);
		return NULL;
	}

	nftnl_rule_set(r, NFTNL_RULE_TABLE, table);
	nftnl_rule_set(r, NFTNL_RULE_CHAIN, chain);
	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);

	if (handle != NULL) {
		handle_num = atoll(handle);
		nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, handle_num);
	}

	add_counter(r);

	add_immediate_verdict(r, verdict, NULL);

	return r;
}
#endif

static void
setup_link_local_checks(struct mnl_nlmsg_batch *batch, bool concat_ifname)
{
	const char *set_name = concat_ifname ? "vips_link_local_name" : "vips_link_local";
	struct nlmsghdr *nlh;
	struct nftnl_set *s;
	struct nftnl_rule *r;
	int type_for_if = !concat_ifname ? TYPE_IFINDEX : ifname_type;

	s = setup_set(NFPROTO_IPV6, global_data->vrrp_nf_table_name, set_name, (TYPE_IP6ADDR << TYPE_BITS) | type_for_if, 0, 0);

	nlh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				      NFT_MSG_NEWSET, NFPROTO_IPV6,
				      NLM_F_CREATE|NLM_F_ACK, seq++);

	nftnl_set_nlmsg_build_payload(nlh, s);
	nftnl_set_free(s);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add rule ip6 keepalived in_link_local ip6 daddr . iifname @set_name drop */
	r = setup_rule_if(NFPROTO_IPV6, global_data->vrrp_nf_table_name, "in_link_local", NULL, set_name,
			false, concat_ifname, NF_DROP, false);
	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			NFT_MSG_NEWRULE,
			nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY),
			NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, seq++);

	nftnl_rule_nlmsg_build_payload(nlh, r);
	nftnl_rule_free(r);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add rule ip6 keepalived out_link_local ip6 saddr . oifname @set_name drop */
	r = setup_rule_if(NFPROTO_IPV6, global_data->vrrp_nf_table_name, "out_link_local", NULL, set_name,
			true, concat_ifname, NF_DROP, false);
	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			NFT_MSG_NEWRULE,
			nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY),
			NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, seq++);

	nftnl_rule_nlmsg_build_payload(nlh, r);
	nftnl_rule_free(r);
	my_mnl_nlmsg_batch_next(batch);
}

static struct mnl_nlmsg_batch *
nft_start_batch(void)
{
	struct mnl_nlmsg_batch *batch;
	char *buf = MALLOC(2 * MNL_SOCKET_BUFFER_SIZE);
	time_t time_ret;

	if (!seq) {
		time_ret = time(NULL);
		if (time_ret == -1)
			seq = 1;
		else
			seq = (uint32_t)time_ret;
	}

	batch = mnl_nlmsg_batch_start(buf, 2 * MNL_SOCKET_BUFFER_SIZE);

	nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
	my_mnl_nlmsg_batch_next(batch);

	return batch;
}

static void
nft_end_batch(struct mnl_nlmsg_batch *batch, bool more)
{
	void *buf;

	nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
	my_mnl_nlmsg_batch_next(batch);

	exchange_nl_msg(batch);

	if (more) {
		mnl_nlmsg_batch_reset(batch);

		nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
		my_mnl_nlmsg_batch_next(batch);
	}
	else {
		buf = mnl_nlmsg_batch_head(batch);
		FREE(buf);
		mnl_nlmsg_batch_stop(batch);
	}
}

static bool
check_table(uint8_t family, const char *table)
{
	struct nlmsghdr *nlh;
	struct nftnl_table *t;
	char buf[64];
	bool have_table = false;

	t = table_add_parse(family, table);
	nlh = nftnl_table_nlmsg_build_hdr(buf, NFT_MSG_GETTABLE, family, NLM_F_ACK, seq++);
	nftnl_table_nlmsg_build_payload(nlh, t);
	nftnl_table_free(t);

	exchange_nl_msg_single(nlh, table_cb, &have_table);

	return have_table;
}

static void
delete_table(struct mnl_nlmsg_batch *batch, uint8_t family, const char *table)
{
	struct nlmsghdr *nlh;
	struct nftnl_table *t;

	log_message(LOG_INFO, "Deleting old ip%s %s table", family == NFPROTO_IPV4 ? "" : "6", table);

	/* nft delete table ip keepalived - make sure there is no residue*/
	t = table_add_parse(family, table);
	nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					NFT_MSG_DELTABLE, family,
					NLM_F_ACK, seq++);
	nftnl_table_nlmsg_build_payload(nlh, t);
	nftnl_table_free(t);

	my_mnl_nlmsg_batch_next(batch);
}

static void
check_and_delete_tables(struct mnl_nlmsg_batch *batch, const char *table)
{
	bool have_ipv4_table;
	bool have_ipv6_table;

	/* We have to check the tables before adding the delete table entries
	 * into the batch in order to ensure that the seq number doesn't get
	 * out of step in the batch. */
	have_ipv4_table = check_table(NFPROTO_IPV4, table);
	have_ipv6_table = check_table(NFPROTO_IPV6, table);

	if (have_ipv4_table)
		delete_table(batch, NFPROTO_IPV4, table);
	if (have_ipv6_table)
		delete_table(batch, NFPROTO_IPV6, table);
}

/* To get the netlink message returned (with the handle), set NLM_F_ECHO in nftnl_..._nlmsg_build_hdr
 * For some reason, it isn't working for the second batch sent.
 */
static void
nft_setup_ipv4(struct mnl_nlmsg_batch *batch)
{
	struct nlmsghdr *nlh;
	struct nftnl_table *ta;
	struct nftnl_chain *t;

	if (!ipv6_table_setup)
		check_and_delete_tables(batch, global_data->vrrp_nf_table_name);

	/* nft add table ip keepalived */
	ta = table_add_parse(NFPROTO_IPV4, global_data->vrrp_nf_table_name);
	nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					NFT_MSG_NEWTABLE, NFPROTO_IPV4,
					NLM_F_CREATE|NLM_F_ACK, seq++);
	nftnl_table_nlmsg_build_payload(nlh, ta);
	nftnl_table_free(ta);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add chain ip keepalived out { type filter hook output priority -1; policy accept } */
	t = chain_add_parse(global_data->vrrp_nf_table_name, "out");
	if (t == NULL)
		exit(EXIT_FAILURE);

	nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					NFT_MSG_NEWCHAIN, NFPROTO_IPV4,
					NLM_F_CREATE|NLM_F_ACK, seq++);
	nftnl_chain_set_u32(t, NFTNL_CHAIN_HOOKNUM, NF_INET_LOCAL_OUT);
	nftnl_chain_set_str(t, NFTNL_CHAIN_TYPE, "filter");
	nftnl_chain_set_s32(t, NFTNL_CHAIN_PRIO, global_data->vrrp_nf_chain_priority);
	nftnl_chain_set_u32(t, NFTNL_CHAIN_POLICY, NF_ACCEPT);
	nftnl_chain_nlmsg_build_payload(nlh, t);
	nftnl_chain_free(t);
	my_mnl_nlmsg_batch_next(batch);

	ipv4_table_setup = true;
}

static void
nft_setup_ipv4_vips(struct mnl_nlmsg_batch *batch)
{
	struct nlmsghdr *nlh;
	struct nftnl_chain *t;
	struct nftnl_set *s;
	struct nftnl_rule *r;

	if (!ipv4_table_setup)
		nft_setup_ipv4(batch);

	/* nft add chain ip keepalived in { type filter hook input priority -1; policy accept; } */
	t = chain_add_parse(global_data->vrrp_nf_table_name, "in");
	if (t == NULL)
		exit(EXIT_FAILURE);

	nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					NFT_MSG_NEWCHAIN, NFPROTO_IPV4,
					NLM_F_CREATE|NLM_F_ACK, seq++);
	nftnl_chain_set_u32(t, NFTNL_CHAIN_HOOKNUM, NF_INET_LOCAL_IN);	// input
	nftnl_chain_set_str(t, NFTNL_CHAIN_TYPE, "filter");
	nftnl_chain_set_s32(t, NFTNL_CHAIN_PRIO, global_data->vrrp_nf_chain_priority);
	nftnl_chain_set_u32(t, NFTNL_CHAIN_POLICY, NF_ACCEPT);
	nftnl_chain_nlmsg_build_payload(nlh, t);
	nftnl_chain_free(t);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add set ip keepalived vips { type ipv4_addr; } */
	s = setup_set(NFPROTO_IPV4, global_data->vrrp_nf_table_name, "vips", TYPE_IPADDR, 0, 0);

	nlh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				      NFT_MSG_NEWSET, NFPROTO_IPV4,
				      NLM_F_CREATE|NLM_F_ACK, seq++);

	nftnl_set_nlmsg_build_payload(nlh, s);
	nftnl_set_free(s);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add rule ip keepalived in ip daddr @vips drop */
	r = setup_rule(NFPROTO_IPV4, global_data->vrrp_nf_table_name, "in", NULL, "vips", false, NF_DROP, false);
	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			NFT_MSG_NEWRULE,
			nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY),
			NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, seq++);

	nftnl_rule_nlmsg_build_payload(nlh, r);
	nftnl_rule_free(r);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add rule ip keepalived out ip saddr @vips drop */
	r = setup_rule(NFPROTO_IPV4, global_data->vrrp_nf_table_name, "out", NULL, "vips", true, NF_DROP, false);
	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			NFT_MSG_NEWRULE,
			nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY),
			NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, seq++);

	nftnl_rule_nlmsg_build_payload(nlh, r);
	nftnl_rule_free(r);
	my_mnl_nlmsg_batch_next(batch);

	ipv4_vips_setup = true;
}

static void
nft_setup_ipv6(struct mnl_nlmsg_batch *batch)
{
	struct nlmsghdr *nlh;
	struct nftnl_table *ta;
	struct nftnl_chain *t;
	const char *table = global_data->vrrp_nf_table_name;

	if (!ipv4_table_setup)
		check_and_delete_tables(batch, global_data->vrrp_nf_table_name);

	/* nft add table ip6 keepalived */
	ta = table_add_parse(NFPROTO_IPV6, table);
	nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					NFT_MSG_NEWTABLE, NFPROTO_IPV6,
					NLM_F_CREATE|NLM_F_ACK, seq++);
	nftnl_table_nlmsg_build_payload(nlh, ta);
	nftnl_table_free(ta);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add chain ip6 keepalived out { type filter hook output priority PRIORITY; policy accept; } */
	t = chain_add_parse(table, "out");
	if (t == NULL)
		exit(EXIT_FAILURE);

	nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					NFT_MSG_NEWCHAIN, NFPROTO_IPV6,
					NLM_F_CREATE|NLM_F_ACK, seq++);
	nftnl_chain_set_u32(t, NFTNL_CHAIN_HOOKNUM, NF_INET_LOCAL_OUT);
	nftnl_chain_set_str(t, NFTNL_CHAIN_TYPE, "filter");
	nftnl_chain_set_s32(t, NFTNL_CHAIN_PRIO, global_data->vrrp_nf_chain_priority);
	nftnl_chain_set_u32(t, NFTNL_CHAIN_POLICY, NF_ACCEPT);
	nftnl_chain_nlmsg_build_payload(nlh, t);
	nftnl_chain_free(t);
	my_mnl_nlmsg_batch_next(batch);

	ipv6_table_setup = true;
}

static void
nft_setup_ipv6_vips(struct mnl_nlmsg_batch *batch)
{
	struct nlmsghdr *nlh;
	struct nftnl_set *s;
	struct nftnl_rule *r;
	struct nftnl_chain *t;
	struct nftnl_set_elem *e;
	struct icmp6_hdr icmp6;

	if (!ipv6_table_setup)
		nft_setup_ipv6(batch);

	/* nft add chain ip6 keepalived in { type filter hook input priority PRIORITY; policy accept; } */
	t = chain_add_parse(global_data->vrrp_nf_table_name, "in");
	nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					NFT_MSG_NEWCHAIN, NFPROTO_IPV6,
					NLM_F_CREATE|NLM_F_ACK, seq++);
	nftnl_chain_set_u32(t, NFTNL_CHAIN_HOOKNUM, NF_INET_LOCAL_IN);
	nftnl_chain_set_str(t, NFTNL_CHAIN_TYPE, "filter");
	nftnl_chain_set_s32(t, NFTNL_CHAIN_PRIO, global_data->vrrp_nf_chain_priority);
	nftnl_chain_set_u32(t, NFTNL_CHAIN_POLICY, NF_ACCEPT);
	nftnl_chain_nlmsg_build_payload(nlh, t);
	nftnl_chain_free(t);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add chain ip6 keepalived in_link_local */
	t = chain_add_parse(global_data->vrrp_nf_table_name, "in_link_local");
	if (t == NULL)
		exit(EXIT_FAILURE);

	nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					NFT_MSG_NEWCHAIN, NFPROTO_IPV6,
					NLM_F_CREATE|NLM_F_ACK, seq++);
	nftnl_chain_nlmsg_build_payload(nlh, t);
	nftnl_chain_free(t);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add chain ip6 keepalived out_link_local */
	t = chain_add_parse(global_data->vrrp_nf_table_name, "out_link_local");
	nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					NFT_MSG_NEWCHAIN, NFPROTO_IPV6,
					NLM_F_CREATE|NLM_F_ACK, seq++);
	nftnl_chain_nlmsg_build_payload(nlh, t);
	nftnl_chain_free(t);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add set ip6 keepalived vips {type ipv6_addr; } */
	s = setup_set(NFPROTO_IPV6, global_data->vrrp_nf_table_name, "vips", TYPE_IP6ADDR, 0, 0);

	nlh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				      NFT_MSG_NEWSET, NFPROTO_IPV6,
				      NLM_F_CREATE|NLM_F_ACK, seq++);

	nftnl_set_nlmsg_build_payload(nlh, s);
	nftnl_set_free(s);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add set ip6 keepalived neighbor-discovery { type icmpv6_type; } */
	s = setup_set(NFPROTO_IPV6, global_data->vrrp_nf_table_name, "neighbor-discovery", TYPE_ICMPV6_TYPE, 0, 0);

	nlh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				      NFT_MSG_NEWSET, NFPROTO_IPV6,
				      NLM_F_CREATE|NLM_F_ACK, seq++);
	/* set_id = nftnl_set_get_u32(s, NFTNL_SET_ID); */

	nftnl_set_set_u32(s, NFTNL_SET_FLAGS, NFT_SET_CONSTANT);
	nftnl_set_set_u32(s, NFTNL_SET_KEY_LEN, sizeof(icmp6.icmp6_type));

	nftnl_set_nlmsg_build_payload(nlh, s);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add element ip6 keepalived neighbor-discovery { nd-neighbor-solicit, nd-neighbor-advert } */
	nlh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				      NFT_MSG_NEWSETELEM, NFPROTO_IPV6,
				      NLM_F_CREATE|NLM_F_ACK, seq++);
	e = nftnl_set_elem_alloc();
	icmp6.icmp6_type = ND_NEIGHBOR_SOLICIT;
	nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, &icmp6.icmp6_type, sizeof(icmp6.icmp6_type));
	nftnl_set_elem_add(s, e);

	e = nftnl_set_elem_alloc();
	icmp6.icmp6_type = ND_NEIGHBOR_ADVERT;
	nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, &icmp6.icmp6_type, sizeof(icmp6.icmp6_type));
	nftnl_set_elem_add(s, e);

	nftnl_set_elems_nlmsg_build_payload(nlh, s);
	nftnl_set_free(s);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add rule ip6 keepalived in icmpv6 @neighbor-discovery accept */
	r = setup_rule_icmpv6(NFPROTO_IPV6, global_data->vrrp_nf_table_name, "in", NULL,
			"neighbor-discovery", 0, NF_ACCEPT, false);
	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			NFT_MSG_NEWRULE,
			nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY),
			NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, seq++);

	nftnl_rule_nlmsg_build_payload(nlh, r);
	nftnl_rule_free(r);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add rule ip6 keepalived in ip6 daddr fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff goto in_link_local */
	r = setup_rule_range_goto(NFPROTO_IPV6, global_data->vrrp_nf_table_name, "in", NULL, "in_link_local", false);
	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			NFT_MSG_NEWRULE,
			nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY),
			NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, seq++);

	nftnl_rule_nlmsg_build_payload(nlh, r);
	nftnl_rule_free(r);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add rule ip6 keepalived in icmpv6 @neighbor-discovery accept */
	r = setup_rule_icmpv6(NFPROTO_IPV6, global_data->vrrp_nf_table_name, "out", NULL,
			"neighbor-discovery", 0, NF_ACCEPT, false);
	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			NFT_MSG_NEWRULE,
			nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY),
			NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, seq++);

	nftnl_rule_nlmsg_build_payload(nlh, r);
	nftnl_rule_free(r);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add rule ip6 keepalived out ip6 saddr fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff goto out_link_local */
	r = setup_rule_range_goto(NFPROTO_IPV6, global_data->vrrp_nf_table_name, "out", NULL, "out_link_local", true);
	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			NFT_MSG_NEWRULE,
			nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY),
			NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, seq++);

	nftnl_rule_nlmsg_build_payload(nlh, r);
	nftnl_rule_free(r);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add rule ip6 keepalived in ip6 daddr @vips drop */
	r = setup_rule(NFPROTO_IPV6, global_data->vrrp_nf_table_name, "in", NULL, "vips", false, NF_DROP, false);
	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			NFT_MSG_NEWRULE,
			nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY),
			NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, seq++);

	nftnl_rule_nlmsg_build_payload(nlh, r);
	nftnl_rule_free(r);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add rule ip6 keepalived out ip6 saddr @vips drop */
	r = setup_rule(NFPROTO_IPV6, global_data->vrrp_nf_table_name, "out", NULL, "vips", true, NF_DROP, false);
	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			NFT_MSG_NEWRULE,
			nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY),
			NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, seq++);

	nftnl_rule_nlmsg_build_payload(nlh, r);
	nftnl_rule_free(r);
	my_mnl_nlmsg_batch_next(batch);

	ipv6_vips_setup = true;
}

static void
nft_update_ipv4_address(struct mnl_nlmsg_batch *batch, ip_address_t *addr, struct nftnl_set **s)
{
	struct nftnl_set_elem *e;

	if (!ipv4_vips_setup)
		nft_setup_ipv4_vips(batch);

	if (!*s) {
		*s = nftnl_set_alloc();
		if (*s == NULL) {
			log_message(LOG_INFO, "OOM error - %d", errno);
			return;
		}

		nftnl_set_set(*s, NFTNL_SET_TABLE, global_data->vrrp_nf_table_name);
		nftnl_set_set(*s, NFTNL_SET_NAME, "vips");
	}

	/* nft add element ip keepalived vips { ADDR } */
	e = nftnl_set_elem_alloc();
	if (e == NULL) {
		log_message(LOG_INFO, "OOM error - %d", errno);
		return;
	}

	nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, &addr->u.sin.sin_addr.s_addr, sizeof(in_addr_t));
	nftnl_set_elem_add(*s, e);
}

static void
nft_update_ipv6_address(struct mnl_nlmsg_batch *batch, ip_address_t *addr, bool dont_track_primary, interface_t *ifp,
			struct nftnl_set **set_global, struct nftnl_set **set_ll, struct nftnl_set **set_ll_ifname)
{
	struct nftnl_set_elem *e;
	uint32_t data_buf[sizeof(struct in6_addr) + IFNAMSIZ];
	struct nftnl_set **s;
	const char *set_name;
	bool use_link_name = false;
	bool is_link_local;
	uint32_t len;

	if (!ipv6_vips_setup)
		nft_setup_ipv6_vips(batch);

	is_link_local = IN6_IS_ADDR_LINKLOCAL(&addr->u.sin6_addr);
	if (!is_link_local) {
		s = set_global;
		set_name = "vips";
	} else if (!global_data->vrrp_nf_ifindex &&
		   dont_track_primary &&
		   (addr->ifp == ifp || addr->dont_track)) {
		s = set_ll_ifname;
		set_name = "vips_link_local_name";
		use_link_name = true;
	} else {
		s = set_ll;
		set_name = "vips_link_local";
	}

	/* Create the specific set if not already done so */
	if (is_link_local) {
		if (use_link_name) {
			if (!setup_ll_ifname) {
				setup_link_local_checks(batch, true);
				setup_ll_ifname = true;
			}
		} else {
			if (!setup_ll_ifindex) {
				setup_link_local_checks(batch, false);
				setup_ll_ifindex = true;
			}
		}
	}

	/* Create set structure if it doesn't already exist */
	if (!*s) {
		*s = nftnl_set_alloc();
		if (*s == NULL) {
			log_message(LOG_INFO, "OOM error - %d", errno);
			return;
		}

		nftnl_set_set(*s, NFTNL_SET_TABLE, global_data->vrrp_nf_table_name);
		nftnl_set_set(*s, NFTNL_SET_NAME, set_name);
	}

	/* Add element to set
	 * nft add element ip6 keepalived vips ADDR or
	 * nft add element ip6 keepalived vips_link_local ADDR . IF or
	 * nft add element ip6 keepalived vips_link_local_name ADDR . IF */
	e = nftnl_set_elem_alloc();
	if (e == NULL) {
		log_message(LOG_INFO, "OOM error - %d", errno);
		return;
	}

	data_buf[0] = addr->u.sin6_addr.s6_addr32[0];
	data_buf[1] = addr->u.sin6_addr.s6_addr32[1];
	data_buf[2] = addr->u.sin6_addr.s6_addr32[2];
	data_buf[3] = addr->u.sin6_addr.s6_addr32[3];
	len = sizeof(struct in6_addr);

	if (is_link_local) {
		if (use_link_name) {
			memset(&data_buf[4], 0, IFNAMSIZ);
			memcpy(&data_buf[4], addr->ifp->ifname, strlen(addr->ifp->ifname));
			len += IFNAMSIZ;
		} else {
			data_buf[4] = addr->ifp->ifindex;
			len += sizeof(data_buf[4]);
		}
	}

	nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, &data_buf, len);
	nftnl_set_elem_add(*s, e);
}

static void
nft_update_addresses(vrrp_t *vrrp, int cmd)
{
	struct mnl_nlmsg_batch *batch;
	struct nlmsghdr *nlh;
	ip_address_t *ip_addr;
	element e;
	struct nftnl_set *ipv4_set = NULL;
	struct nftnl_set *ipv6_set = NULL;
	struct nftnl_set *ipv6_ll_index_set = NULL;
	struct nftnl_set *ipv6_ll_name_set = NULL;
	bool set_rule = (cmd == NFT_MSG_NEWSETELEM);
	uint16_t type = (cmd == NFT_MSG_NEWSETELEM) ? NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK : NLM_F_ACK;

	batch = nft_start_batch();

	LIST_FOREACH(vrrp->vip, ip_addr, e) {
		if (set_rule == ip_addr->nftable_rule_set)
			continue;

		if (ip_addr->ifa.ifa_family == AF_INET)
			nft_update_ipv4_address(batch, ip_addr, &ipv4_set);
		else
			nft_update_ipv6_address(batch, ip_addr, vrrp->dont_track_primary, vrrp->ifp,
					&ipv6_set, &ipv6_ll_index_set, &ipv6_ll_name_set);

		ip_addr->nftable_rule_set = set_rule;
	}

	LIST_FOREACH(vrrp->evip, ip_addr, e) {
		if (set_rule == ip_addr->nftable_rule_set)
			continue;

		if (ip_addr->ifa.ifa_family == AF_INET)
			nft_update_ipv4_address(batch, ip_addr, &ipv4_set);
		else
			nft_update_ipv6_address(batch, ip_addr, vrrp->dont_track_primary, vrrp->ifp,
					&ipv6_set, &ipv6_ll_index_set, &ipv6_ll_name_set);

		ip_addr->nftable_rule_set = set_rule;
	}

	if (ipv4_set) {
		nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					    cmd, NFPROTO_IPV4,
					    type,
					    seq++);
		nftnl_set_elems_nlmsg_build_payload(nlh, ipv4_set);
		nftnl_set_free(ipv4_set);
		my_mnl_nlmsg_batch_next(batch);
	}

	if (ipv6_set) {
		nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					    cmd, NFPROTO_IPV6,
					    type,
					    seq++);
		nftnl_set_elems_nlmsg_build_payload(nlh, ipv6_set);
		nftnl_set_free(ipv6_set);
		my_mnl_nlmsg_batch_next(batch);
	}

	if (ipv6_ll_index_set) {
		nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					    cmd, NFPROTO_IPV6,
					    type,
					    seq++);
		nftnl_set_elems_nlmsg_build_payload(nlh, ipv6_ll_index_set);
		nftnl_set_free(ipv6_ll_index_set);
		my_mnl_nlmsg_batch_next(batch);
	}

	if (ipv6_ll_name_set) {
		nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					    cmd, NFPROTO_IPV6,
					    type,
					    seq++);
		nftnl_set_elems_nlmsg_build_payload(nlh, ipv6_ll_name_set);
		nftnl_set_free(ipv6_ll_name_set);
		my_mnl_nlmsg_batch_next(batch);
	}

	nft_end_batch(batch, false);
}

void
nft_add_addresses(vrrp_t *vrrp)
{
	nft_update_addresses(vrrp, NFT_MSG_NEWSETELEM);
}

void
nft_remove_addresses(vrrp_t *vrrp)
{
if (!nl) return;	// Should delete tables
	nft_update_addresses(vrrp, NFT_MSG_DELSETELEM);
}

void
nft_remove_addresses_iplist(list l)
{
	vrrp_t vrrp = { .vip = l };

	nft_update_addresses(&vrrp, NFT_MSG_DELSETELEM);
}

#ifdef _HAVE_VRRP_VMAC_
static struct nftnl_rule
*setup_rule_move_igmp(uint8_t family, const char *table,
				   const char *chain, const char *handle,
				   const char *set_map)
{
	/* If have nft dup statement:
	     nft add rule ip keepalived out ip daddr 224.0.0.22 dup to 224.0.0.22 device oifname map @imap drop
	   otherwise:
	     nft add rule ip keepalived out ip daddr 224.0.0.22 oifname @imap drop
	 */
	struct nftnl_rule *r = NULL;
	struct in_addr ip;
	struct in6_addr ip6;
	uint64_t handle_num;

	r = nftnl_rule_alloc();
	if (r == NULL) {
		log_message(LOG_INFO, "OOM error - %d", errno);
		return NULL;
	}

	nftnl_rule_set(r, NFTNL_RULE_TABLE, table);
	nftnl_rule_set(r, NFTNL_RULE_CHAIN, chain);
	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);

	if (handle != NULL) {
		handle_num = atoll(handle);
		nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, handle_num);
	}

	if (family == NFPROTO_IPV4) {
		add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
			    offsetof(struct iphdr, daddr), sizeof(struct in_addr));

		ip.s_addr = htonl(0xe0000016);
		add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &ip, sizeof(ip));
#if HAVE_DECL_NFTA_DUP_MAX
		add_immediate_data(r, NFT_REG_1, &ip, sizeof(ip));
#endif
	} else {
		add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
			    offsetof(struct ip6_hdr, ip6_dst), sizeof(struct in6_addr));

		ip6.s6_addr32[0] = htonl(0xff020000);
		ip6.s6_addr32[1] = ip6.s6_addr32[2] = 0;
		ip6.s6_addr32[3] = htonl(0x00000016);
		add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &ip6, sizeof(ip6));
#if HAVE_DECL_NFTA_DUP_MAX
		add_immediate_data(r, NFT_REG_1, &ip6, sizeof(ip6));
#endif
	}

	add_meta(r, NFT_META_OIF, NFT_REG_2);
#if HAVE_DECL_NFTA_DUP_MAX
	add_lookup(r, NFT_REG_2, NFT_REG_2, set_map, 1, false);
	add_dup(r, NFT_REG_1, NFT_REG_2);
#else
	add_lookup(r, NFT_REG_2, NO_REG, set_map, 1, false);
#endif
	add_counter(r);
	add_immediate_verdict(r, NF_DROP, NULL);

	return r;
}

static void
nft_setup_igmp(struct mnl_nlmsg_batch *batch, struct nftnl_set **s, uint8_t nfproto)
{
	struct nlmsghdr *nlh;
	struct nftnl_rule *r;

	if (nfproto == NFPROTO_IPV4) {
		if (!ipv4_table_setup)
			nft_setup_ipv4(batch);
	} else {
		if (!ipv6_table_setup)
			nft_setup_ipv6(batch);
	}

	/* nft add map ip keepalived imap { type ifname : ifindex } */
#if HAVE_DECL_NFTA_DUP_MAX
	*s = setup_set(nfproto, global_data->vrrp_nf_table_name, vmac_map_name, TYPE_IFINDEX, NFT_SET_MAP, TYPE_IFINDEX);
#else
	*s = setup_set(nfproto, global_data->vrrp_nf_table_name, vmac_map_name, TYPE_IFINDEX, 0, 0);
#endif

	nlh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				      NFT_MSG_NEWSET, nfproto,
				      NLM_F_CREATE|NLM_F_ACK, seq++);

	nftnl_set_nlmsg_build_payload(nlh, *s);
	my_mnl_nlmsg_batch_next(batch);

	r = setup_rule_move_igmp(nfproto, global_data->vrrp_nf_table_name, "out", NULL, vmac_map_name);
	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			NFT_MSG_NEWRULE,
			nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY),
			NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, seq++);
	nftnl_rule_nlmsg_build_payload(nlh, r);
	nftnl_rule_free(r);
	my_mnl_nlmsg_batch_next(batch);

	if (nfproto == NFPROTO_IPV4)
		ipv4_igmp_setup = true;
	else
		ipv6_igmp_setup = true;
}

static void
nft_update_vmac_element(struct mnl_nlmsg_batch *batch, struct nftnl_set *s, ifindex_t vmac_ifindex,
#if !HAVE_DECL_NFTA_DUP_MAX
		__attribute__((unused))
#endif
					ifindex_t base_ifindex, int cmd, uint8_t nfproto)
{
	struct nlmsghdr *nlh;
	struct nftnl_set_elem *e;
	uint16_t type = cmd == NFT_MSG_NEWSETELEM ? NLM_F_CREATE | NLM_F_ACK : NLM_F_ACK;

	/* nft add element ip keepalived imap { "vrrp.253", "eth0" } */
	nlh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				      cmd, nfproto,
				      type, seq++);
	e = nftnl_set_elem_alloc();
	nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, &vmac_ifindex, sizeof(vmac_ifindex));
#if HAVE_DECL_NFTA_DUP_MAX
	nftnl_set_elem_set(e, NFTNL_SET_ELEM_DATA, &base_ifindex, sizeof(base_ifindex));
#endif
	nftnl_set_elem_add(s, e);

	nftnl_set_elems_nlmsg_build_payload(nlh, s);
	my_mnl_nlmsg_batch_next(batch);
}

static void
nft_update_vmac_family(struct mnl_nlmsg_batch *batch, const vrrp_t *vrrp, uint8_t nfproto, int cmd)
{
	struct nftnl_set *s;

	if ((nfproto == NFPROTO_IPV4 && !ipv4_igmp_setup) ||
	    (nfproto == NFPROTO_IPV6 && !ipv6_igmp_setup))
		nft_setup_igmp(batch, &s, nfproto);
	else {
		s = nftnl_set_alloc();
		if (s == NULL) {
			log_message(LOG_INFO, "OOM error - %d", errno);
			return;
		}

		nftnl_set_set(s, NFTNL_SET_TABLE, global_data->vrrp_nf_table_name);
		nftnl_set_set(s, NFTNL_SET_NAME, vmac_map_name);
	}

	nft_update_vmac_element(batch, s, vrrp->ifp->ifindex, vrrp->ifp->base_ifp->ifindex, cmd, nfproto);

	nftnl_set_free(s);
}

static void
nft_update_vmac(const vrrp_t *vrrp, int cmd)
{
	struct mnl_nlmsg_batch *batch;
	uint8_t nfproto = vrrp->family == AF_INET ? NFPROTO_IPV4 : NFPROTO_IPV6;

	batch = nft_start_batch();

	nft_update_vmac_family(batch, vrrp, nfproto, cmd);

	if (vrrp->evip_other_family)
		nft_update_vmac_family(batch, vrrp, nfproto == NFPROTO_IPV4 ? NFPROTO_IPV6 : NFPROTO_IPV4, cmd);

	nft_end_batch(batch, false);
}

void
nft_add_vmac(const vrrp_t *vrrp)
{
	nft_update_vmac(vrrp, NFT_MSG_NEWSETELEM);
}

void
nft_remove_vmac(const vrrp_t *vrrp)
{
	nft_update_vmac(vrrp, NFT_MSG_DELSETELEM);
}
#endif

void
nft_cleanup(void)
{
	/*
	----------------	------------------
	|  0000000020  |	| message length |
	| 00016 | R--- |	|  type | flags  |
	|  0000000003  |	| sequence number|
	|  0000000000  |	|     port ID    |
	----------------	------------------
	| 00 00 0a 00  |	|  extra header  |
	----------------	------------------
	----------------	------------------
	|  0000000036  |	| message length |
	| 02562 | R-A- |	|  type | flags  | NFT_MSG_DELTABLE
	|  0000000004  |	| sequence number|
	|  0000000000  |	|     port ID    |
	----------------	------------------
	| 02 00 00 00  |	|  extra header  |
	|00015|--|00001|	|len |flags| type|
	| 6b 65 65 70  |	|      data      |	 k e e p
	| 61 6c 69 76  |	|      data      |	 a l i v
	| 65 64 00 00  |	|      data      |	 e d
	----------------	------------------
	----------------	------------------
	|  0000000020  |	| message length |
	| 00017 | R--- |	|  type | flags  |
	|  0000000005  |	| sequence number|
	|  0000000000  |	|     port ID    |
	----------------	------------------
	| 00 00 0a 00  |	|  extra header  |
	----------------	------------------
	*/
	struct nftnl_table *t;
	struct nlmsghdr *nlh;
	struct mnl_nlmsg_batch *batch;

	if (!ipv4_table_setup && !ipv6_table_setup)
		return;

	batch = nft_start_batch();

	/* nft delete table ip keepalived */
	t = nftnl_table_alloc();
	nftnl_table_set_str(t, NFTNL_TABLE_NAME, global_data->vrrp_nf_table_name);

	if (ipv4_table_setup) {
		nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
						NFT_MSG_DELTABLE, NFPROTO_IPV4,
						NLM_F_ACK, seq++);
		nftnl_table_nlmsg_build_payload(nlh, t);

		my_mnl_nlmsg_batch_next(batch);
	}

	/* nft delete table ip6 keepalived */
	if (ipv6_table_setup) {
		nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
						NFT_MSG_DELTABLE, NFPROTO_IPV6,
						NLM_F_ACK, seq++);
		nftnl_table_nlmsg_build_payload(nlh, t);

		my_mnl_nlmsg_batch_next(batch);
	}

	nftnl_table_free(t);

	nft_end_batch(batch, false);

	ipv4_table_setup = false;
	ipv4_vips_setup = false;
	ipv4_igmp_setup = false;
	ipv6_table_setup = false;
	ipv6_vips_setup = false;
	ipv6_igmp_setup = false;
	setup_ll_ifname = false;
	setup_ll_ifindex = false;
}

void
nft_end(void)
{
	nft_cleanup();

	mnl_socket_close(nl);
	nl = NULL;
}

void
set_nf_ifname_type(void)
{
	if (global_data->nft_version)
		ifname_type = global_data->nft_version >= 0x000803 ? TYPE_IFNAME : TYPE_STRING;
	else
		ifname_type = LIBNFTNL_VERSION > 0x010009 ? TYPE_IFNAME : TYPE_STRING;

}
