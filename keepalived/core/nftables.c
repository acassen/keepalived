/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        nftables.c
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

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <errno.h>

#include "nftables.h"
#include "logger.h"
#include "global_data.h"
#include "list_head.h"
#include "utils.h"
#include "namespaces.h"


/* nft supports ifnames in sets from commit 8c61fa7 (release v0.8.3, libnftnl v1.0.9 (but 0.8.2 also uses that, 0.8.4 uses v1.1.0)) */
/* nft supports concatenated ranges from commit	8ac2f3b (release v0.9.4, libnftnl v1.1.6 and kernel 5.6) */

struct mnl_socket *nl;	/* lgtm [cpp/short-global-name] */
static unsigned int portid;
uint32_t seq;		/* lgtm [cpp/short-global-name] */

#ifdef MNL_DEBUG
unsigned msg_no;
#endif

#ifdef _INCLUDE_UNUSED_CODE_
static int
table_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = PTR_CAST_CONST(struct nlattr *, data);

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

#if defined HAVE_NFTNL_UDATA && !HAVE_DECL_NFTNL_UDATA_PUT_U32
static uint8_t
nftnl_udata_put_u32(struct nftnl_udata_buf *buf, uint8_t type, uint32_t data)
{
	return nftnl_udata_put(buf, type, sizeof(data), &data);
}
#endif

static bool
nl_socket_open(void)
{
	int cur_net_namespace = -1;

#if !defined _ONE_PROCESS_DEBUG_ && defined LIBIPVS_USE_NL
	if (prog_type == PROG_TYPE_CHECKER) {
		if (global_data->network_namespace_ipvs &&
		    (cur_net_namespace = set_netns_name(global_data->network_namespace_ipvs)) == -1) {
			log_message(LOG_INFO, "Unable to set network namespace %s", global_data->network_namespace_ipvs);
			return false;
		}
	}
#endif

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		log_message(LOG_INFO, "mnl_socket_open failed - %d", errno);

		if (cur_net_namespace >= 0)
			restore_net_namespace(cur_net_namespace);

		return false;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		log_message(LOG_INFO, "mnl_socket_bind error - %d", errno);
		mnl_socket_close(nl);
		nl = NULL;

		if (cur_net_namespace >= 0)
			restore_net_namespace(cur_net_namespace);

		return false;
	}

	portid = mnl_socket_get_portid(nl);

	if (cur_net_namespace >= 0)
		restore_net_namespace(cur_net_namespace);

	return true;
}

static void
exchange_nl_msg(struct mnl_nlmsg_batch *batch)
{
	int ret;
	int ret_cb;
	char *buf;
	size_t buf_size;
	long mnl_buf_size;
	int sav_errno = errno;

	if (mnl_nlmsg_batch_is_empty(batch))
		return;

#ifdef MNL_DEBUG
	FILE *fp = NULL;
	if (prog_type == PROG_TYPE_VRRP) {
		fp = fopen(KA_TMP_DIR "/nftrace", "a");
		unsigned char *p = mnl_nlmsg_batch_head(batch);
		size_t i;

		fprintf(fp, "mnl_nlmsg_batch_size (%u), %zu\n", msg_no, mnl_nlmsg_batch_size(batch));
		log_message(LOG_INFO, "exchange_nl_msg (%u), len %zu", msg_no, mnl_nlmsg_batch_size(batch));
		for (i = 0; i < mnl_nlmsg_batch_size(batch); i++, p++) {
			if (!(i % 16))
				fprintf(fp, "%4.4zx:  ", i);
			fprintf(fp, " %2.2x", *p);
			if (i % 16 == 15)
				fprintf(fp, "\n");
		}

		if (i % 16)
			fprintf(fp, "\n");

		mnl_nlmsg_fprintf(fp, PTR_CAST(char, mnl_nlmsg_batch_head(batch)), mnl_nlmsg_batch_size(batch), sizeof( struct nfgenmsg));
		fflush(fp);
	}
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
	ret_cb = 1;
	while ((ret = mnl_socket_recvfrom(nl, buf, buf_size)) > 0) {
#ifdef MNL_DEBUG
		if (fp) {
			log_message(LOG_INFO, "mnl_socket_recvfrom (%u) returned %d", msg_no, ret);
			fprintf(fp, "\n\nReply %u\n\n", msg_no++);
			mnl_nlmsg_fprintf(fp, buf, ret, sizeof( struct nfgenmsg));
			fflush(fp);
		}
#endif

		ret_cb = mnl_cb_run(buf, ret, 0, portid, NULL, NULL);
		if (ret_cb <= 0)
			break;
	}
	sav_errno = errno;

#ifdef MNL_DEBUG
	if (fp)
		fclose(fp);
#endif

	FREE(buf);

	if (ret == -1 || ret_cb < 0)
		log_message(LOG_INFO, "mnl_socket_recvfrom error ret %d - errno %d, ret_cb %d,", ret, sav_errno, ret_cb);
}

#ifdef _WITH_VRRP_
void
exchange_nl_msg_single(struct nlmsghdr *nlm, int (*cb_func)(const struct nlmsghdr *, void *), bool *success)
{
	int ret;
	char buf[256];

#ifdef MNL_DEBUG
	FILE *fp = fopen(KA_TMP_DIR "/nftrace", "a");
	mnl_nlmsg_fprintf(fp, PTR_CAST(char, nlm), nlm->nlmsg_len, 0);
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
#endif

void
my_mnl_nlmsg_batch_next(struct mnl_nlmsg_batch *batch)
{
	if (!mnl_nlmsg_batch_next(batch)) {
		exchange_nl_msg(batch);
		mnl_nlmsg_batch_reset(batch);
	}
}

void
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

void
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

#ifdef _WITH_LVS_
void
add_meta_sreg(struct nftnl_rule *r, uint32_t ifindex, uint32_t sreg)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("meta");
	if (e == NULL) {
		log_message(LOG_INFO, "expr payload oom error - %d", errno);
		return;
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_META_SREG, sreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_META_KEY, ifindex);

	nftnl_rule_add_expr(r, e);
}
#endif

void
add_lookup(struct nftnl_rule *r, uint32_t base, uint32_t dreg, const char *set_name,
			uint32_t set_id,
#ifndef HAVE_NFTNL_EXPR_LOOKUP_FLAG_INV
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
#ifdef HAVE_NFTNL_EXPR_LOOKUP_FLAG_INV
	if (neg)
		nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_FLAGS, NFT_LOOKUP_F_INV);
#endif
	nftnl_expr_set_str(e, NFTNL_EXPR_LOOKUP_SET, set_name);
	if (set_id)
		nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_SET_ID, set_id);

	nftnl_rule_add_expr(r, e);
}

#if defined _WITH_VRRP_ && HAVE_DECL_NFTA_DUP_MAX && defined _HAVE_VRRP_VMAC_
void
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

/* verdict should be NF_DROP, NF_ACCEPT, NFT_RETURN, ... */
/* "The nf_tables verdicts share their numeric space with the netfilter verdicts." */
void
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

#ifdef _INCLUDE_UNUSED_CODE_
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
	nftnl_expr_set_data(e, NFTNL_EXPR_IMM_DATA, data, data_len);

	nftnl_rule_add_expr(r, e);
}
#endif

void
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
	nftnl_expr_set_data(e, NFTNL_EXPR_CMP_DATA, data, data_len);

	nftnl_rule_add_expr(r, e);
}

#ifdef _WITH_VRRP_
void
add_bitwise(struct nftnl_rule *r, uint32_t sreg, uint32_t dreg,
		    uint32_t len, const void *mask, const void *xor)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("bitwise");
	if (e == NULL) {
		log_message(LOG_INFO, "expr cmp oom error - %d", errno);
		return;
	}

	nftnl_expr_set_u32(e, NFTA_BITWISE_SREG, sreg);
	nftnl_expr_set_u32(e, NFTA_BITWISE_DREG, dreg);
	nftnl_expr_set_u32(e, NFTA_BITWISE_LEN, len);
	nftnl_expr_set_data(e, NFTA_BITWISE_MASK, mask, len);
	nftnl_expr_set_data(e, NFTA_BITWISE_XOR, xor, len);

	nftnl_rule_add_expr(r, e);
}
#endif

void
add_counter(struct nftnl_rule *r)
{
	struct nftnl_expr *e;

	if (!global_data->nf_counters)
		return;

	e = nftnl_expr_alloc("counter");
	if (e == NULL) {
		log_message(LOG_INFO, "expr counter oom error - %d", errno);
		return;
	}

	nftnl_rule_add_expr(r, e);
}

struct nftnl_table *
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

struct nftnl_chain *
chain_add_parse(const char *table, const char *name)
{
	struct nftnl_chain *t;

	t = nftnl_chain_alloc();
	if (t == NULL) {
		log_message(LOG_INFO, "OOM error - %d", errno);
		return NULL;
	}
	nftnl_chain_set_str(t, NFTNL_CHAIN_TABLE, table);
	nftnl_chain_set_str(t, NFTNL_CHAIN_NAME, name);

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
struct
nftnl_set *setup_set(uint8_t family, const char *table,
				 const char *name, int type,
				 int set_type, int data_type)
{
	struct nftnl_set *s = NULL;
#ifdef HAVE_NFTNL_UDATA
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
		switch (type_copy & NFT_TYPE_MASK)
		{
		case NFT_TYPE_IPADDR:
			size += sizeof(struct in_addr);
			break;
		case NFT_TYPE_IP6ADDR:
			size += sizeof(struct in6_addr);
			break;
		case NFT_TYPE_IFINDEX:
		case NFT_TYPE_INET_SERVICE:
			size += sizeof(uint32_t);
			break;
		case NFT_TYPE_ICMPV6_TYPE:
			size++;
			break;
		case NFT_TYPE_IFNAME:
		case NFT_TYPE_STRING:	/* Used if nft doesn't support ifname type */
			size += IFNAMSIZ;
			break;
		default:
			log_message(LOG_INFO, "Unsupported type %d\n", type_copy & NFT_TYPE_MASK);
			break;
		}
		type_copy >>= NFT_TYPE_BITS;
	}

	if (set_type & NFT_SET_MAP) {
		switch (data_type)
		{
		case NFT_TYPE_IPADDR:
			data_size = sizeof(struct in_addr);
			break;
		case NFT_TYPE_IP6ADDR:
			data_size = sizeof(struct in6_addr);
			break;
		case NFT_TYPE_IFINDEX:
		case NFT_TYPE_MARK:
			data_size = sizeof(uint32_t);
			break;
		case NFT_TYPE_ICMPV6_TYPE:
			data_size = 1;
			break;
		case NFT_TYPE_IFNAME:
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

#ifdef HAVE_NFTNL_UDATA
	udbuf = nftnl_udata_buf_alloc(NFT_USERDATA_MAXLEN);
	if (!udbuf) {
		log_message(LOG_INFO, "OOM error - %d", errno);
		return NULL;
	}

	nftnl_udata_put_u32(udbuf, NFTNL_UDATA_SET_KEYBYTEORDER, type == NFT_TYPE_IPADDR || type == NFT_TYPE_IP6ADDR ? BYTEORDER_BIG_ENDIAN : BYTEORDER_HOST_ENDIAN);
	if (set_type & NFT_SET_MAP)
		nftnl_udata_put_u32(udbuf, NFTNL_UDATA_SET_DATABYTEORDER, BYTEORDER_HOST_ENDIAN);

	nftnl_set_set_data(s, NFTNL_SET_USERDATA, nftnl_udata_buf_data(udbuf),
			   nftnl_udata_buf_len(udbuf));
	nftnl_udata_buf_free(udbuf);
#endif

	return s;
}

struct mnl_nlmsg_batch *
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

void
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

void
nft_discard_batch(struct mnl_nlmsg_batch *batch)
{
	FREE(batch);
}

#ifdef _WITH_VRRP_
int
set_nf_ifname_type(void)
{
	FILE *fp;
	char nft_ver_buf[64];
	char *p;
	unsigned nft_major = 0, nft_minor = 0, nft_release = 0;
	unsigned nft_version = 0;
	int ifname_type;

	fp = popen("nft -v 2>/dev/null", "r");
	if (fp) {
		if (fgets(nft_ver_buf, sizeof(nft_ver_buf), fp)) {
			if (!(p = strchr(nft_ver_buf, ' ')))
				p = nft_ver_buf;
			while (*p == ' ')
				p++;
			if (*p == 'v')
				p++;

			if (sscanf(p, "%u.%u.%u", &nft_major, &nft_minor, &nft_release) >= 2)
				nft_version = (nft_major * 0x100 + nft_minor) * 0x100 + nft_release;
		}
		pclose(fp);
	}

	if (nft_version)
		ifname_type = nft_version >= 0x000803 ? NFT_TYPE_IFNAME : NFT_TYPE_STRING;
	else
		ifname_type = LIBNFTNL_VERSION > 0x010009 ? NFT_TYPE_IFNAME : NFT_TYPE_STRING;

	return ifname_type;
}
#endif
