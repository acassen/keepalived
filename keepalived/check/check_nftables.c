/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_nftables.c
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

#ifdef NEED_FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <errno.h>

#include "logger.h"
#include "global_data.h"
#include "list_head.h"
#include "utils.h"
#include "nftables.h"

#include "check_nftables.h"


struct sctphdr {
	__be16 sh_sport;
	__be16 sh_dport;
	__be32 sh_vtag;
	__be32 sh_checksum;
};

static bool ipvs_setup[2];
static bool ipvs_tcp_setup[2];
static bool ipvs_udp_setup[2];
static bool ipvs_sctp_setup[2];

static unsigned next_fwmark;

// Copy of nft_setup_ipv4()
static void
nft_ipvs_setup(struct mnl_nlmsg_batch *batch, int af)
{
	struct nlmsghdr *nlh;
	struct nftnl_table *ta;
	struct nftnl_chain *t;
	int	nfproto = af == AF_INET ? NFPROTO_IPV4 : NFPROTO_IPV6;

	/* nft add table ip keepalived */
	ta = table_add_parse(NFPROTO_IPV4, global_data->ipvs_nf_table_name);
	nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					NFT_MSG_NEWTABLE, nfproto,
					NLM_F_CREATE|NLM_F_ACK, seq++);
	nftnl_table_nlmsg_build_payload(nlh, ta);
	nftnl_table_free(ta);
	my_mnl_nlmsg_batch_next(batch);

	/* nft add chain ip keepalived_ipvs in { type filter hook input priority -1; policy accept } */
	t = chain_add_parse(global_data->ipvs_nf_table_name, "in");
	if (t == NULL)
		exit(EXIT_FAILURE);

	nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					NFT_MSG_NEWCHAIN, nfproto,
					NLM_F_CREATE|NLM_F_ACK, seq++);
	nftnl_chain_set_u32(t, NFTNL_CHAIN_HOOKNUM, NF_INET_LOCAL_IN);
	nftnl_chain_set_str(t, NFTNL_CHAIN_TYPE, "filter");
	nftnl_chain_set_s32(t, NFTNL_CHAIN_PRIO, global_data->ipvs_nf_chain_priority);
	nftnl_chain_set_u32(t, NFTNL_CHAIN_POLICY, NF_ACCEPT);
	nftnl_chain_nlmsg_build_payload(nlh, t);
	nftnl_chain_free(t);
	my_mnl_nlmsg_batch_next(batch);

	ipvs_setup[af == AF_INET6] = true;
}

static const char *
ipvs_map_name(uint16_t protocol)
{
	return protocol == IPPROTO_TCP ? "tcp_map" : protocol == IPPROTO_UDP ? "udp_map" : "sctp_map";
}

// Copied from setup_rule_move_igmp
static struct nftnl_rule *
setup_rule_set_mark(uint8_t family, const char *table,
		    const char *chain, const char *handle,
		    uint8_t l4_protocol, const char *set_map)
{
	/* nft add rule ip keepalived_ipvs in tcp meta l4proto tcp meta mark set ip daddr . tcp dport map @set_fwmark_tcp return */
	struct nftnl_rule *r = NULL;
	uint64_t handle_num;

	r = nftnl_rule_alloc();
	if (r == NULL) {
		log_message(LOG_INFO, "OOM error - %d", errno);
		return NULL;
	}

	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, table);
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain);
	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);

	if (handle != NULL) {
		handle_num = atoll(handle);
		nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, handle_num);
	}

#if HAVE_DECL_NFT_META_L4PROTO
	add_meta(r, NFT_META_L4PROTO, NFT_REG_1);	/* From Linux 3.14 */
#else
	if (family == NFPROTO_IPV4)
		add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
			    offsetof(struct iphdr, protocol), sizeof(((struct iphdr *)NULL)->protocol));
	else
		add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
			    offsetof(struct ip6_hdr, ip6_nxt), sizeof(((struct ip6_hdr *)NULL)->ip6_nxt));
#endif
	add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &l4_protocol, sizeof(l4_protocol));
	if (family == NFPROTO_IPV4)
		add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
			    offsetof(struct iphdr, daddr), sizeof(((struct iphdr *)NULL)->daddr));
	else
		add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
			    offsetof(struct ip6_hdr, ip6_dst), sizeof(((struct ip6_hdr *)NULL)->ip6_dst));
	if (l4_protocol == IPPROTO_TCP)
		add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, family == NFPROTO_IPV4 ? 9 : 2,
			    offsetof(struct tcphdr, th_dport), sizeof(((struct tcphdr*)NULL)->th_dport));
	else if (l4_protocol == IPPROTO_UDP)
		add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, family == NFPROTO_IPV4 ? 9 : 2,
			    offsetof(struct udphdr, uh_dport), sizeof(((struct udphdr*)NULL)->uh_dport));
	else if (l4_protocol == IPPROTO_SCTP)	/* Without this check gcc warns about identical branches */
		add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, family == NFPROTO_IPV4 ? 9 : 2,
			    offsetof(struct sctphdr, sh_dport), sizeof(((struct sctphdr*)NULL)->sh_dport));
	add_lookup(r, NFT_REG_1, NFT_REG_1, set_map, 1, false);
	add_meta_sreg(r, NFT_META_MARK, NFT_REG_1);
	add_counter(r);
	add_immediate_verdict(r, NFT_RETURN, NULL);

	return r;
}

static void
nft_ipvs_add_set_rule(struct mnl_nlmsg_batch *batch, int af, uint16_t l4_protocol, struct nftnl_set **s)
{
	const char *map_name = ipvs_map_name(l4_protocol);
	int nfproto = af == AF_INET ? NFPROTO_IPV4 : NFPROTO_IPV6;
	struct nftnl_rule *r;
	struct nlmsghdr *nlh;
	int set_flags = NFT_SET_MAP;
#ifdef NFT_RANGE_CONCATS
	uint8_t field_len[2];
#endif
#if HAVE_DECL_NFTNL_SET_EXPR
	struct nftnl_expr *nle = NULL;
#endif

	if (!ipvs_setup[af == AF_INET6])
		nft_ipvs_setup(batch, af);

#ifdef NFT_RANGE_CONCATS
	set_flags |= NFT_SET_CONCAT | NFT_SET_INTERVAL;
#endif
	*s = setup_set(af == AF_INET ? NFPROTO_IPV4 : NFPROTO_IPV6, global_data->ipvs_nf_table_name, map_name,
		       (af == AF_INET ? NFT_TYPE_IPADDR : NFT_TYPE_IP6ADDR ) << NFT_TYPE_BITS | NFT_TYPE_INET_SERVICE,
		       set_flags, NFT_TYPE_MARK);

#ifdef NFT_RANGE_CONCATS
	field_len[0] = af == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr);
	field_len[1] = sizeof(((struct tcphdr*)NULL)->th_dport);
	nftnl_set_set_data(*s, NFTNL_SET_DESC_CONCAT, field_len, sizeof(field_len));
#endif

#if HAVE_DECL_NFTNL_SET_EXPR
	/* From nft 0.9.5 can add "counter" to set definition */
        if (global_data->nf_counters) {
		nle = nftnl_expr_alloc("counter");
		nftnl_set_set_data(*s, NFTNL_SET_EXPR, nle, 0);
	}
#endif

	nlh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				      NFT_MSG_NEWSET, nfproto,
				      NLM_F_CREATE|NLM_F_ACK, seq++);

	nftnl_set_nlmsg_build_payload(nlh, *s);
	my_mnl_nlmsg_batch_next(batch);

	r = setup_rule_set_mark(nfproto, global_data->ipvs_nf_table_name, "in", NULL, l4_protocol, map_name);
	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			NFT_MSG_NEWRULE,
			nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY),
			NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, seq++);
	nftnl_rule_nlmsg_build_payload(nlh, r);
	nftnl_rule_free(r);
	my_mnl_nlmsg_batch_next(batch);

	if (l4_protocol == IPPROTO_TCP)
		ipvs_tcp_setup[af == AF_INET6] = true;
	else if (l4_protocol == IPPROTO_UDP)
		ipvs_udp_setup[af == AF_INET6] = true;
	else if (l4_protocol == IPPROTO_SCTP)
		ipvs_sctp_setup[af == AF_INET6] = true;
}

// Copied from nft_update_vmac_element
static void
nft_update_ipvs_element(struct mnl_nlmsg_batch *batch,
			struct nftnl_set *s,
			const sockaddr_t *addr,
#ifdef NFT_RANGE_CONCATS
			const sockaddr_t *addr_end,
#endif
			uint32_t fwmark,
			int cmd)
{
	struct nlmsghdr *nlh;
	struct nftnl_set_elem *e;
	uint16_t type = cmd == NFT_MSG_NEWSETELEM ? NLM_F_CREATE | NLM_F_ACK : NLM_F_ACK;
	char buf[sizeof(struct in6_addr) + sizeof(uint32_t)];
	unsigned len = 0;
	union {
		const struct sockaddr_in *in;
		const struct sockaddr_in6 *in6;
		const sockaddr_t *ss;
	} ss = { .ss = addr };
	int nfproto = addr->ss_family == AF_INET ? NFPROTO_IPV4 : NFPROTO_IPV6;

	/* nft add element ip keepalived in { addr . port : mark } */
	nlh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				      cmd, nfproto,
				      type, seq++);
	e = nftnl_set_elem_alloc();
	if (nfproto == NFPROTO_IPV4) {
		memcpy(buf, &ss.in->sin_addr, len = sizeof(ss.in->sin_addr));
		memcpy(buf + len, &ss.in->sin_port, sizeof(ss.in->sin_port));
		len += sizeof(ss.in->sin_port);
	} else {
		memcpy(buf, &ss.in6->sin6_addr, len = sizeof(ss.in6->sin6_addr));
		memcpy(buf + len, &ss.in6->sin6_port, sizeof(ss.in6->sin6_port));
		len += sizeof(ss.in6->sin6_port);
	}
	if (NLMSG_ALIGN(len) > len)
		memset(buf + len, 0, NLMSG_ALIGN(len) - len);
	len = NLMSG_ALIGN(len);

	nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, buf, len);
#ifdef NFT_RANGE_CONCATS
	ss.ss = addr_end;
	if (nfproto == NFPROTO_IPV4) {
		memcpy(buf, &ss.in->sin_addr, len = sizeof(ss.in->sin_addr));
		memcpy(buf + len, &ss.in->sin_port, sizeof(ss.in->sin_port));
		len += sizeof(ss.in->sin_port);
	} else {
		memcpy(buf, &ss.in6->sin6_addr, len = sizeof(ss.in6->sin6_addr));
		memcpy(buf + len, &ss.in6->sin6_port, sizeof(ss.in6->sin6_port));
		len += sizeof(ss.in6->sin6_port);
	}
	if (NLMSG_ALIGN(len) > len)
		memset(buf + len, 0, NLMSG_ALIGN(len) - len);
	len = NLMSG_ALIGN(len);
	nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY_END, buf, len);
#endif
	nftnl_set_elem_set(e, NFTNL_SET_ELEM_DATA, &fwmark, sizeof(fwmark));
	nftnl_set_elem_add(s, e);

	nftnl_set_elems_nlmsg_build_payload(nlh, s);
	my_mnl_nlmsg_batch_next(batch);
}

static void
nft_update_ipvs_entry(const sockaddr_t *addr,
#ifdef NFT_RANGE_CONCATS
		      const sockaddr_t *addr_end,
#endif
		      uint16_t l4_protocol, uint32_t fwmark, int cmd)
{
	struct nftnl_set *s;
	int setup_index = addr->ss_family == AF_INET6;
	struct mnl_nlmsg_batch *batch;

	batch = nft_start_batch();

	if (cmd == NFT_MSG_NEWSETELEM &&
	    ((l4_protocol == IPPROTO_TCP && !ipvs_tcp_setup[setup_index]) ||
	     (l4_protocol == IPPROTO_UDP && !ipvs_udp_setup[setup_index]) ||
	     (l4_protocol == IPPROTO_SCTP && !ipvs_sctp_setup[setup_index])))
		nft_ipvs_add_set_rule(batch, addr->ss_family, l4_protocol, &s);
	else {
		s = nftnl_set_alloc();
		if (s == NULL) {
			log_message(LOG_INFO, "OOM error - %d", errno);
			return;
		}

		nftnl_set_set_str(s, NFTNL_SET_TABLE, global_data->ipvs_nf_table_name);
		nftnl_set_set_str(s, NFTNL_SET_NAME, ipvs_map_name(l4_protocol));
	}

#ifdef NFT_RANGE_CONCATS
	nft_update_ipvs_element(batch, s, addr, addr_end, fwmark, cmd);
#else
	nft_update_ipvs_element(batch, s, addr, fwmark, cmd);
#endif
	nftnl_set_free(s);

	nft_end_batch(batch, false);
}

#ifdef _INCLUDE_UNUSED_CODE_
void
nft_add_ipvs_entry(const sockaddr_t *addr, uint16_t l4_protocol, uint32_t fwmark)
{
	nft_update_ipvs_entry(addr, l4_protocol, fwmark, NFT_MSG_NEWSETELEM);
}

void
nft_remove_ipvs_entry(const sockaddr_t *addr, uint16_t l4_protocol, uint32_t fwmark)
{
	nft_update_ipvs_entry(addr, l4_protocol, fwmark, NFT_MSG_DELSETELEM);
}
#endif

// copy of nft_cleanup()
static void
nft_ipvs_cleanup(void)
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

	if (!ipvs_setup[0] && !ipvs_setup[1])
		return;

	batch = nft_start_batch();

	/* nft delete table ip keepalived */
	t = nftnl_table_alloc();
	nftnl_table_set_str(t, NFTNL_TABLE_NAME, global_data->ipvs_nf_table_name);

	if (ipvs_setup[0]) {
		nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
						NFT_MSG_DELTABLE, NFPROTO_IPV4,
						NLM_F_ACK, seq++);
		nftnl_table_nlmsg_build_payload(nlh, t);

		my_mnl_nlmsg_batch_next(batch);

		ipvs_setup[0] = false;
		ipvs_tcp_setup[0] = false;
		ipvs_udp_setup[0] = false;
		ipvs_sctp_setup[0] = false;
	}

	/* nft delete table ip6 keepalived */
	if (ipvs_setup[1]) {
		nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
						NFT_MSG_DELTABLE, NFPROTO_IPV6,
						NLM_F_ACK, seq++);
		nftnl_table_nlmsg_build_payload(nlh, t);

		my_mnl_nlmsg_batch_next(batch);

		ipvs_setup[1] = false;
		ipvs_tcp_setup[1] = false;
		ipvs_udp_setup[1] = false;
		ipvs_sctp_setup[1] = false;
	}

	nftnl_table_free(t);

	nft_end_batch(batch, false);
}

// Copy of nft_end()
void
nft_ipvs_end(void)
{
	if (!nl)
		return;

	nft_ipvs_cleanup();

	mnl_socket_close(nl);
	nl = NULL;
}

static inline unsigned
get_next_fwmark(void)
{
	if (!next_fwmark)
		next_fwmark = global_data->ipvs_nftables_start_fwmark;

	return next_fwmark++;
}

static void
process_fwmark_vsge_range(const sockaddr_t *addr, const sockaddr_t *addr_end, uint16_t service_type, unsigned fwmark, int cmd)
{
#ifndef NFT_RANGE_CONCATS
	sockaddr_t sockaddr;
	struct sockaddr_in *sockaddr4 = PTR_CAST(struct sockaddr_in, &sockaddr);
	struct sockaddr_in6 *sockaddr6 = PTR_CAST(struct sockaddr_in6, &sockaddr);
	uint32_t end_addr = 0;		/* Stop GCC uninitialised warning */
	int i;
#endif

#ifdef NFT_RANGE_CONCATS
	nft_update_ipvs_entry(addr, addr_end, service_type, fwmark, cmd);
#else
	sockaddr = *addr;
	if (addr->ss_family == AF_INET)
		end_addr = PTR_CAST_CONST(struct sockaddr_in, addr_end)->sin_addr.s_addr;
	else
		sockaddr6->sin6_family = AF_INET6;

	do {
		nft_update_ipvs_entry(&sockaddr, service_type, fwmark, cmd);

		if (addr->ss_family == AF_INET) {
			if (sockaddr4->sin_addr.s_addr == end_addr)
				break;

			sockaddr4->sin_addr.s_addr += htonl(1);
		} else {
			if (!inet_sockaddrcmp(&sockaddr, addr_end))
				break;

			for (i = 7; i >= 0; i--) {
				if ((sockaddr6->sin6_addr.s6_addr16[i] = htons(ntohs(sockaddr6->sin6_addr.s6_addr16[i]) + 1)))
					break;
			}
		}
	} while (true);
#endif
}

static void
do_vs_fwmark(virtual_server_t *vs, unsigned fwmark, int cmd)
{
	virtual_server_group_t *vsg = vs->vsg;
	virtual_server_group_entry_t *vsg_entry;

	list_for_each_entry(vsg_entry, &vsg->addr_range, e_list) {
		/* Process the range */
		if (cmd == NFT_MSG_DELSETELEM || !vsg_entry->reloaded)
			process_fwmark_vsge_range(&vsg_entry->addr, &vsg_entry->addr_end, vs->service_type, fwmark, cmd);
	}
}

unsigned
set_vs_fwmark(virtual_server_t *vs)
{
	proto_index_t proto_index = protocol_to_index(vs->service_type);
	unsigned fwmark = vs->vsg->auto_fwmark[proto_index] ? vs->vsg->auto_fwmark[proto_index] : get_next_fwmark();

	do_vs_fwmark(vs, fwmark, NFT_MSG_NEWSETELEM);

	return fwmark;
}

void
clear_vs_fwmark(virtual_server_t *vs)
{
	do_vs_fwmark(vs, vs->vsg->auto_fwmark[protocol_to_index(vs->service_type)], NFT_MSG_DELSETELEM);
}

void
remove_vs_fwmark_entry(virtual_server_t *vs, virtual_server_group_entry_t *vsge)
{
	process_fwmark_vsge_range(&vsge->addr, &vsge->addr_end, vs->service_type, vs->vsg->auto_fwmark[protocol_to_index(vs->service_type)], NFT_MSG_DELSETELEM);
}
