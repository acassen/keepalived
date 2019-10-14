/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        iptables manipulation.
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

#include "config.h"

#ifdef _HAVE_LIBIPTC_LINUX_NET_IF_H_COLLISION_
/* Linux 4.5 introduced a namespace collision when including
 * libiptc/libiptc.h due to both net/if.h and linux/if.h
 * being included.
 *
 * See: http://bugzilla.netfilter.org/show_bug.cgi?id=1067
 *
 * Including net/if.h first stops the problem occuring.
 */
#include <net/if.h>
#endif

#include <libiptc/libiptc.h>
#include <libiptc/libip6tc.h>
#ifdef _HAVE_LIBIPSET_
#ifdef USE_LIBIPSET_LINUX_IP_SET_H
#include <libipset/linux_ip_set.h>
#else
#include <linux/netfilter/ipset/ip_set.h>
#endif
#include <linux/netfilter/xt_set.h>
#endif
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdint.h>

#include "vrrp_iptables_calls.h"
#include "memory.h"
#include "logger.h"
#if !HAVE_DECL_SOCK_CLOEXEC
#include "old_socket.h"
#endif
#ifdef _LIBIPTC_DYNAMIC_
#include "global_data.h"
#endif
#include "vrrp_iptables_lib.h"
#include "vrrp_firewall.h"
#include "utils.h"

/* We sometimes get a resource_busy on iptc_commit. This appears to happen
 * when someone else is also updating it.
 * Tests show that the EAGAIN error is generated if someone else did an
 * update via iptc_commit between us doing iptc_init and iptc_commit, i.e.
 * if there had been an update since out init prior to our commit.
 *
 * Documentation seems to suggest that iptc_init takes a snapshot of the
 * state of iptables. This fits with the tests, but also means that we could
 * be interferred with by anyone else doing an update.
 */

#ifdef _LIBIPTC_DYNAMIC_
#include <dlfcn.h>

/* The addresses of the functions we want */
struct iptc_handle *(*iptc_init_addr)(const char *tablename);
void (*iptc_free_addr)(struct iptc_handle *h);
int (*iptc_is_chain_addr)(const char *chain, struct iptc_handle *const handle);
int (*iptc_insert_entry_addr)(const ipt_chainlabel chain, const struct ipt_entry *e, unsigned int rulenum, struct iptc_handle *handle);
int (*iptc_append_entry_addr)(const ipt_chainlabel chain, const struct ipt_entry *e, struct iptc_handle *handle);
int (*iptc_delete_entry_addr)(const ipt_chainlabel chain, const struct ipt_entry *origfw, unsigned char *matchmask, struct iptc_handle *handle);
int (*iptc_commit_addr)(struct iptc_handle *handle);
const char *(*iptc_strerror_addr)(int err);

struct ip6tc_handle *(*ip6tc_init_addr)(const char *tablename);
void (*ip6tc_free_addr)(struct ip6tc_handle *h);
int (*ip6tc_is_chain_addr)(const char *chain, struct ip6tc_handle *const handle);
int (*ip6tc_insert_entry_addr)(const ip6t_chainlabel chain, const struct ip6t_entry *e, unsigned int rulenum, struct ip6tc_handle *handle);
int (*ip6tc_append_entry_addr)(const ip6t_chainlabel chain, const struct ip6t_entry *e, struct ip6tc_handle *handle);
int (*ip6tc_delete_entry_addr)(const ip6t_chainlabel chain, const struct ip6t_entry *origfw, unsigned char *matchmask, struct ip6tc_handle *handle);
int (*ip6tc_commit_addr)(struct ip6tc_handle *handle);
const char *(*ip6tc_strerror_addr)(int err);

/* We can make it look as though normal linking is being used */
#define iptc_init (*iptc_init_addr)
#define iptc_free (*iptc_free_addr)
#define iptc_is_chain (*iptc_is_chain_addr)
#define iptc_insert_entry (*iptc_insert_entry_addr)
#define iptc_append_entry (*iptc_append_entry_addr)
#define iptc_delete_entry (*iptc_delete_entry_addr)
#define iptc_commit (*iptc_commit_addr)
#define iptc_strerror (*iptc_strerror_addr)

#define ip6tc_init (*ip6tc_init_addr)
#define ip6tc_free (*ip6tc_free_addr)
#define ip6tc_is_chain (*ip6tc_is_chain_addr)
#define ip6tc_insert_entry (*ip6tc_insert_entry_addr)
#define ip6tc_append_entry (*ip6tc_append_entry_addr)
#define ip6tc_delete_entry (*ip6tc_delete_entry_addr)
#define ip6tc_commit (*ip6tc_commit_addr)
#define ip6tc_strerror (*ip6tc_strerror_addr)

static void* libip4tc_handle;
static void* libip6tc_handle;
#endif

static void
set_iface(char *vianame, unsigned char *mask, const char *iface)
{
	size_t vialen = strlen(iface);

	memset(vianame, 0, IFNAMSIZ);
	memset(mask, 0, IFNAMSIZ);

	strcpy(vianame, iface);
	if (!vialen)
		return;

	memset(mask, 0xFF, vialen + 1);
}

/* Initializes a new iptables instance and returns an iptables resource associated with the new iptables table */
struct iptc_handle* ip4tables_open ( const char* tablename )
{
	struct iptc_handle *h ;

	if ( !( h = iptc_init ( tablename ) ) )
		return NULL ;

	return h ;
}

int ip4tables_close ( struct iptc_handle* handle, int updated )
{
	int res = 1;
	int sav_errno ;

	if (updated) {
		if ( ( res = iptc_commit ( handle ) ) != 1 )
		{
			sav_errno = errno ;
			log_message(LOG_INFO, "iptc_commit returned %d: %s", res, iptc_strerror (sav_errno) );
		}
	}

	iptc_free ( handle ) ;

	if ( res == 1 )
		return 0 ;
	else
		return ( sav_errno ) ;
}

int ip4tables_is_chain(struct iptc_handle* handle, const char* chain_name)
{
	return iptc_is_chain(chain_name, handle);
}

int ip4tables_process_entry( struct iptc_handle* handle, const char* chain_name, unsigned int rulenum, const char* target_name, const ip_address_t* src_ip_address, const ip_address_t* dst_ip_address, const char* in_iface, const char* out_iface, uint16_t protocol, uint8_t type, int cmd, uint8_t flags, bool force)
{
	size_t size;
	struct ipt_entry *fw;
	struct xt_entry_target *target;
	struct xt_entry_match *match ;
	ipt_chainlabel chain;
	int res;
	int sav_errno;

	/* Add an entry */

	memset (chain, 0, sizeof (chain));

	size = XT_ALIGN (sizeof (struct ipt_entry)) +
			XT_ALIGN (sizeof (struct xt_entry_target) + 1);

	if ( protocol == IPPROTO_ICMP )
		size += XT_ALIGN ( sizeof(struct xt_entry_match) ) + XT_ALIGN ( sizeof(struct ipt_icmp) ) ;

	fw = (struct ipt_entry*)MALLOC(size);

	fw->target_offset = XT_ALIGN ( sizeof ( struct ipt_entry ) ) ;

	if ( src_ip_address && src_ip_address->ifa.ifa_family != AF_UNSPEC )
	{
		memcpy(&fw->ip.src, &src_ip_address->u.sin.sin_addr, sizeof ( src_ip_address->u.sin.sin_addr ) );
		memset ( &fw->ip.smsk, 0xff, sizeof(fw->ip.smsk));
	}

	if ( dst_ip_address && dst_ip_address->ifa.ifa_family != AF_UNSPEC )
	{
		memcpy(&fw->ip.dst, &dst_ip_address->u.sin.sin_addr, sizeof ( dst_ip_address->u.sin.sin_addr ) );
		memset ( &fw->ip.dmsk, 0xff, sizeof(fw->ip.dmsk));
	}

	fw->ip.invflags = flags;

	if (in_iface)
		set_iface(fw->ip.iniface, fw->ip.iniface_mask, in_iface);
	if (out_iface)
		set_iface(fw->ip.outiface, fw->ip.outiface_mask, out_iface);

	if ( protocol != IPPROTO_NONE ) {
		fw->ip.proto = protocol ;

//		fw->ip.flags |= IP6T_F_PROTO ;		// IPv6 only

		if ( protocol == IPPROTO_ICMP )
		{
			match = (struct xt_entry_match*)((char*)fw + fw->target_offset);
			match->u.match_size = XT_ALIGN(sizeof (struct xt_entry_match)) + XT_ALIGN(sizeof(struct ipt_icmp));
			match->u.user.revision = 0;
			fw->target_offset = (uint16_t)(fw->target_offset + match->u.match_size);
			strcpy ( match->u.user.name, "icmp" ) ;

			struct ipt_icmp *icmpinfo = (struct ipt_icmp *) match->data;
			icmpinfo->type = type ;		// type to match
			icmpinfo->code[0] = 0 ;		// code lower
			icmpinfo->code[1] = 0xff ;	// code upper
			icmpinfo->invflags = 0 ;	// don't invert
		}
	}

// target is XTC_LABEL_DROP/XTC_LABEL_ACCEPT
	fw->next_offset = (uint16_t)size;
	target = ipt_get_target(fw);
	target->u.user.target_size = XT_ALIGN (sizeof (struct xt_entry_target) + 1);
	strcpy_safe(target->u.user.name, target_name);
//	fw->ip.flags |= IPT_F_GOTO;
	strcpy_safe(chain, chain_name);
	// Use iptc_append_entry to add to the chain
	if (cmd == IPADDRESS_DEL) {
		unsigned char *matchmask = MALLOC(fw->next_offset);
		memset(matchmask, 0xff, fw->next_offset);
		res = iptc_delete_entry(chain, fw, matchmask, handle);
		FREE(matchmask);
	}
	else if (rulenum == APPEND_RULE)
		res = iptc_append_entry (chain, fw, handle ) ;
	else
		res = iptc_insert_entry (chain, fw, rulenum, handle ) ;

	sav_errno = errno ;

	FREE(fw);

	if (res !=  1 && (!force || sav_errno != ENOENT))
	{
		log_message(LOG_INFO, "ip4tables_process_entry for chain %s returned %d: %s", chain, res, iptc_strerror (sav_errno) ) ;

		return sav_errno ;
	}

	return 0 ;
}

/* Initializes a new iptables instance and returns an iptables resource associated with the new iptables table */
struct ip6tc_handle* ip6tables_open ( const char* tablename )
{
	struct ip6tc_handle *h ;

	if ( !( h = ip6tc_init ( tablename ) ) )
		return NULL ;

	return h ;
}

int ip6tables_close ( struct ip6tc_handle* handle, int updated )
{
	int res = 1;
	int sav_errno ;

	if (updated) {
		if ( ( res = ip6tc_commit ( handle ) ) != 1 )
		{
			sav_errno = errno ;
			log_message(LOG_INFO, "iptc_commit returned %d: %s", res, ip6tc_strerror (sav_errno) );
		}
	}

	ip6tc_free ( handle ) ;

	if ( res == 1 )
		return 0 ;
	else
		return ( sav_errno ) ;
}

int ip6tables_is_chain(struct ip6tc_handle* handle, const char* chain_name)
{
	return ip6tc_is_chain(chain_name, handle);
}

int ip6tables_process_entry( struct ip6tc_handle* handle, const char* chain_name, unsigned int rulenum, const char* target_name, const ip_address_t* src_ip_address, const ip_address_t* dst_ip_address, const char* in_iface, const char* out_iface, uint16_t protocol, uint8_t type, int cmd, uint8_t flags, bool force)
{
	size_t size;
	struct ip6t_entry *fw;
	struct xt_entry_target *target;
	struct xt_entry_match *match ;
	ip6t_chainlabel chain;
	int res;
	int sav_errno;

	/* Add an entry */

	memset (chain, 0, sizeof (chain));

	size = XT_ALIGN (sizeof (struct ip6t_entry)) +
			XT_ALIGN (sizeof (struct xt_entry_target) + 1);

	if ( protocol == IPPROTO_ICMPV6 )
		size += XT_ALIGN ( sizeof(struct xt_entry_match) ) + XT_ALIGN ( sizeof(struct ip6t_icmp) ) ;

	fw = (struct ip6t_entry*)MALLOC(size);

	fw->target_offset = XT_ALIGN ( sizeof ( struct ip6t_entry ) ) ;

	if ( src_ip_address && src_ip_address->ifa.ifa_family != AF_UNSPEC ) {
		memcpy(&fw->ipv6.src, &src_ip_address->u.sin6_addr, sizeof ( src_ip_address->u.sin6_addr ) );
		memset ( &fw->ipv6.smsk, 0xff, sizeof(fw->ipv6.smsk));
	}

	if ( dst_ip_address && dst_ip_address->ifa.ifa_family != AF_UNSPEC ) {
		memcpy(&fw->ipv6.dst, &dst_ip_address->u.sin6_addr, sizeof ( dst_ip_address->u.sin6_addr ) );
		memset ( &fw->ipv6.dmsk, 0xff, sizeof(fw->ipv6.dmsk));
	}

	fw->ipv6.invflags = flags;

	if (in_iface)
		set_iface(fw->ipv6.iniface, fw->ipv6.iniface_mask, in_iface);
	if (out_iface)
		set_iface(fw->ipv6.outiface, fw->ipv6.outiface_mask, out_iface);

	if ( protocol != IPPROTO_NONE ) {
		fw->ipv6.proto = protocol ;

		fw->ipv6.flags |= IP6T_F_PROTO ;		// IPv6 only

		if ( protocol == IPPROTO_ICMPV6 )
		{
			match = (struct xt_entry_match*)((char*)fw + fw->target_offset);
			match->u.match_size = XT_ALIGN ( sizeof (struct xt_entry_match) ) + XT_ALIGN ( sizeof (struct ip6t_icmp) ) ;
			match->u.user.revision = 0;
			fw->target_offset = (uint16_t)(fw->target_offset + match->u.match_size);
			strcpy ( match->u.user.name, "icmp6" ) ;

			struct ip6t_icmp *icmpinfo = (struct ip6t_icmp *) match->data;
			icmpinfo->type = type ;		// type to match
			icmpinfo->code[0] = 0 ;		// code lower
			icmpinfo->code[1] = 0xff ;	// code upper
			icmpinfo->invflags = 0 ;	// don't invert
		}
	}

// target is XTC_LABEL_DROP/XTC_LABEL_ACCEPT
	fw->next_offset = (uint16_t)size;
	target = ip6t_get_target ( fw ) ;
	target->u.user.target_size = XT_ALIGN (sizeof (struct xt_entry_target) + 1);
	strcpy_safe(target->u.user.name, target_name);
//	fw->ip.flags |= IPT_F_GOTO;
	strcpy_safe(chain, chain_name);

	// Use iptc_append_entry to add to the chain
	if (cmd == IPADDRESS_DEL) {
		unsigned char *matchmask = MALLOC(fw->next_offset);
		memset(matchmask, 0xff, fw->next_offset);
		res = ip6tc_delete_entry ( chain, fw, matchmask, handle);
		FREE(matchmask);
	}
	else if (rulenum == APPEND_RULE)
		res = ip6tc_append_entry (chain, fw, handle ) ;
	else
		res = ip6tc_insert_entry (chain, fw, rulenum, handle ) ;

	sav_errno = errno ;

	FREE(fw);

	if (res !=  1 && (!force || sav_errno != ENOENT))
	{
		log_message(LOG_INFO, "ip6tables_process_entry for chain %s returned %d: %s", chain, res, ip6tc_strerror (sav_errno) ) ;

		return sav_errno ;
	}

	return 0 ;
}

#ifdef _HAVE_LIBIPSET_
#ifndef IP_SET_OP_VERSION	/* Exposed to userspace from Linux 3.4 */
				/* Copied from <linux/netfilter/ipset/ip_set.h> */
#define SO_IP_SET	83
union ip_set_name_index {
 char name[IPSET_MAXNAMELEN];
 ip_set_id_t index;
};

#define IP_SET_OP_GET_BYNAME 0x00000006 /* Get set index by name */
struct ip_set_req_get_set {
 unsigned op;
 unsigned version;
 union ip_set_name_index set;
};

#define IP_SET_OP_VERSION 0x00000100 /* Ask kernel version */
struct ip_set_req_version {
 unsigned op;
 unsigned version;
};
#endif

static int
get_version(unsigned int* version)
{
	int sockfd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	struct ip_set_req_version req_version;
	socklen_t size = sizeof(req_version);
	int res;

	if (sockfd < 0) {
		log_message(LOG_INFO, "Can't open socket to ipset.");
		return -1;
	}

#if !HAVE_DECL_SOCK_CLOEXEC
	if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) == -1) {
		log_message(LOG_INFO, "Could not set close on exec: %s",
			      strerror(errno));
	}
#endif

	req_version.op = IP_SET_OP_VERSION;
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req_version, &size);
	if (res != 0)
		log_message(LOG_INFO, "Kernel module xt_set is not loaded in.");

	*version = req_version.version;

	return sockfd;
}

static void
get_set_byname_only(const char *setname, struct xt_set_info *info,
		    int sockfd, unsigned int version, bool ignore_errors)
{
	struct ip_set_req_get_set req = { .version = version };
	socklen_t size = sizeof(struct ip_set_req_get_set);
	int res;

	req.op = IP_SET_OP_GET_BYNAME;
	strncpy(req.set.name, setname, IPSET_MAXNAMELEN);
	req.set.name[IPSET_MAXNAMELEN - 1] = '\0';
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req, &size);

	if (res != 0) {
		if (!ignore_errors)
			log_message(LOG_INFO, "Problem when communicating with ipset, errno=%d.",
				errno);
	}
	else if (size != sizeof(struct ip_set_req_get_set)) {
		if (!ignore_errors)
			log_message(LOG_INFO, "Incorrect return size from kernel during ipset lookup, "
				"(want %zu, got %zu)",
				sizeof(struct ip_set_req_get_set), (size_t)size);
	}
	else if (req.set.index == IPSET_INVALID_ID) {
		if (!ignore_errors)
			log_message(LOG_INFO, "Set %s doesn't exist.", setname);
	}
	else
		info->index = req.set.index;
}

static void
get_set_byname(const char *setname, struct xt_set_info *info, unsigned family, bool ignore_errors)
{
#if defined IP_SET_OP_GET_FNAME
	struct ip_set_req_get_set_family req;
	socklen_t size = sizeof(struct ip_set_req_get_set_family);
	int res;
#else
	if (family) {};		/* Avoid compiler warning */
#endif
	int sockfd;
	unsigned int version;

	info->index = IPSET_INVALID_ID;

	if ((sockfd = get_version(&version)) == -1) {
		info->index = IPSET_INVALID_ID;
		return;
	}

#if defined IP_SET_OP_GET_FNAME		/* Since Linux 3.13 */
	req.version = version;
	req.op = IP_SET_OP_GET_FNAME;
	strncpy(req.set.name, setname, IPSET_MAXNAMELEN);
	req.set.name[IPSET_MAXNAMELEN - 1] = '\0';
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req, &size);

	if (res != 0 && errno == EBADMSG)
#endif
	{
		/* Backward compatibility */
		get_set_byname_only(setname, info, sockfd, version, ignore_errors);

		close(sockfd);
		return;
	}

#if defined IP_SET_OP_GET_FNAME
	close(sockfd);
	if (res != 0) {
		if (!ignore_errors)
			log_message(LOG_INFO, "Problem when communicating with ipset, errno=%d.",
				errno);
	}
	else if (size != sizeof(struct ip_set_req_get_set_family)) {
		if (!ignore_errors)
			log_message(LOG_INFO, "Incorrect return size from kernel during ipset lookup, "
				"(want %zu, got %zu)",
				sizeof(struct ip_set_req_get_set_family),
				(size_t)size);
	}
	else if (req.set.index == IPSET_INVALID_ID) {
		if (!ignore_errors)
			log_message(LOG_INFO, "Set %s doesn't exist.", setname);
	}
	else if (!(req.family == family ||
	      req.family == NFPROTO_UNSPEC)) {
		if (!ignore_errors)
			log_message(LOG_INFO, "The protocol family of set %s is %s, "
				      "which is not applicable.",
				      setname,
				      req.family == NFPROTO_IPV4 ? "IPv4" : "IPv6");
	}
	else
		info->index = req.set.index;
#endif
}

int ip4tables_add_rules(struct iptc_handle* handle, const char* chain_name, unsigned int rulenum, uint8_t dim, uint8_t src_dst, const char* target_name, const ip_address_t *src_ip_address, const ip_address_t *dst_ip_address, const char* set_name, uint16_t protocol, uint8_t param, int cmd, bool ignore_errors)
{
	size_t size;
	struct ipt_entry *fw;
	struct xt_entry_target *target;
	struct xt_entry_match *match;
#ifdef HAVE_XT_SET_INFO_MATCH_V4
	struct xt_set_info_match_v4 *setinfo;
#elif defined HAVE_XT_SET_INFO_MATCH_V3
	struct xt_set_info_match_v3 *setinfo;
#elif defined HAVE_XT_SET_INFO_MATCH_V1
	struct xt_set_info_match_v1 *setinfo;
#else
	struct xt_set_info_match *setinfo;
#endif
	ipt_chainlabel chain;
	int res;
	int sav_errno;

	/* Add an entry */
	size = XT_ALIGN(sizeof (struct ipt_entry)) +
			XT_ALIGN(sizeof(struct xt_entry_match)) +
			XT_ALIGN(sizeof(struct xt_entry_target) + 1) +
			XT_ALIGN(sizeof(*setinfo));

	if (protocol == IPPROTO_ICMP)
		size += XT_ALIGN(sizeof(struct xt_entry_match)) + XT_ALIGN(sizeof(struct ipt_icmp));

	fw = (struct ipt_entry*)MALLOC(size);

	fw->target_offset = XT_ALIGN(sizeof(struct ipt_entry));

	if (src_ip_address && src_ip_address->ifa.ifa_family != AF_UNSPEC)
	{
		fw->ip.src.s_addr = src_ip_address->u.sin.sin_addr.s_addr;
		fw->ip.smsk.s_addr = 0xffffffff;
	}

	if (dst_ip_address && dst_ip_address->ifa.ifa_family != AF_UNSPEC)
	{
		fw->ip.dst.s_addr = dst_ip_address->u.sin.sin_addr.s_addr;
		fw->ip.dmsk.s_addr = 0xffffffff;
	}

	// set
	match = (struct xt_entry_match*)((char*)fw + fw->target_offset);
	match->u.match_size = XT_ALIGN(sizeof(struct xt_entry_match)) + XT_ALIGN(sizeof(*setinfo));
#ifdef HAVE_XT_SET_INFO_MATCH_V4
	match->u.user.revision = 4;
#elif defined HAVE_XT_SET_INFO_MATCH_V3
	match->u.user.revision = 3;
#elif defined HAVE_XT_SET_INFO_MATCH_V1
	match->u.user.revision = 1;
#else
	match->u.user.revision = 0;
#endif
	fw->target_offset = (uint16_t)(fw->target_offset + match->u.match_size);
	strcpy(match->u.user.name, "set");

#ifdef HAVE_XT_SET_INFO_MATCH_V4
	setinfo = (struct xt_set_info_match_v4 *)match->data;
#elif defined HAVE_XT_SET_INFO_MATCH_V3
	setinfo = (struct xt_set_info_match_v3 *)match->data;
#elif defined HAVE_XT_SET_INFO_MATCH_V1
	setinfo = (struct xt_set_info_match_v1 *)match->data;
#else
	setinfo = (struct xt_set_info_match *)match->data;
#endif
	memset(setinfo, 0, sizeof (*setinfo));

	get_set_byname(set_name, &setinfo->match_set, NFPROTO_IPV4, ignore_errors);
	if (setinfo->match_set.index == IPSET_INVALID_ID) {
		FREE(fw);
		return -1;
	}

	setinfo->match_set.dim = dim;
	setinfo->match_set.flags = src_dst;

	if (protocol != IPPROTO_NONE) {
		fw->ip.proto = protocol;

//		fw->ip.flags |= IP6T_F_PROTO ;		// IPv6 only

		if (protocol == IPPROTO_ICMP)
		{
			match = (struct xt_entry_match*)((char*)fw + fw->target_offset);
			match->u.match_size = XT_ALIGN(sizeof(struct xt_entry_match)) + XT_ALIGN(sizeof(struct ipt_icmp));
			match->u.user.revision = 0;
			fw->target_offset = (uint16_t)(fw->target_offset + match->u.match_size);
			strcpy(match->u.user.name, "icmp");

			struct ipt_icmp *icmpinfo = (struct ipt_icmp *)match->data;
			icmpinfo->type = param;		// type to match
			icmpinfo->code[0] = 0;		// code lower
			icmpinfo->code[1] = 0xff;	// code upper
			icmpinfo->invflags = 0;		// don't invert
		}
	}

// target is XTC_LABEL_DROP/XTC_LABEL_ACCEPT
	fw->next_offset = (uint16_t)size;
	target = ipt_get_target(fw);
	target->u.user.target_size = XT_ALIGN(sizeof(struct xt_entry_target) + 1);
	strcpy_safe(target->u.user.name, target_name);
//	fw->ip.flags |= IPT_F_GOTO;
	strcpy_safe(chain, chain_name);

	// Use iptc_append_entry to add to the chain
	if (cmd == IPADDRESS_DEL) {
		unsigned char *matchmask = MALLOC(fw->next_offset);
		memset(matchmask, 0xff, fw->next_offset);
		res = iptc_delete_entry(chain, fw, matchmask, handle);
		FREE(matchmask);
	}
	else if (rulenum == APPEND_RULE)
		res = iptc_append_entry(chain, fw, handle) ;
	else
		res = iptc_insert_entry(chain, fw, rulenum, handle) ;

	sav_errno = errno;

	FREE(fw);

	if (res!= 1)
	{
		if (!ignore_errors)
			log_message(LOG_INFO, "iptc_insert_entry for chain %s returned %d: %s", chain_name, res, iptc_strerror(sav_errno)) ;

		return sav_errno;
	}

	return 0;
}

int ip6tables_add_rules(struct ip6tc_handle* handle, const char* chain_name, unsigned int rulenum, uint8_t dim, uint8_t src_dst, const char* target_name, const ip_address_t *src_ip_address, const ip_address_t *dst_ip_address, const char* set_name, uint16_t protocol, uint8_t param, int cmd, bool ignore_errors)
{
	size_t size;
	struct ip6t_entry *fw;
	struct xt_entry_target *target;
	struct xt_entry_match *match;
#ifdef HAVE_XT_SET_INFO_MATCH_V4
	struct xt_set_info_match_v4 *setinfo;
#elif defined HAVE_XT_SET_INFO_MATCH_V3
	struct xt_set_info_match_v3 *setinfo;
#elif defined HAVE_XT_SET_INFO_MATCH_V1
	struct xt_set_info_match_v1 *setinfo;
#else
	struct xt_set_info_match *setinfo;
#endif
	ip6t_chainlabel chain;
	int res;
	int sav_errno;

	/* Add an entry */

	memset(chain, 0, sizeof(chain));

	size = XT_ALIGN(sizeof (struct ip6t_entry)) +
			XT_ALIGN(sizeof(struct xt_entry_match)) +
			XT_ALIGN(sizeof(struct xt_entry_target) + 1) +
			XT_ALIGN(sizeof(*setinfo));

	if (protocol == IPPROTO_ICMPV6)
		size += XT_ALIGN(sizeof(struct xt_entry_match)) + XT_ALIGN(sizeof(struct ip6t_icmp));

	fw = (struct ip6t_entry*)MALLOC(size);

	if (src_ip_address && src_ip_address->ifa.ifa_family != AF_UNSPEC) {
//		memcpy(&fw->ipv6.src, &src_ip_address->u.sin6_addr, sizeof(src_ip_address->u.sin6_addr));
		fw->ipv6.src = src_ip_address->u.sin6_addr;
		memset(&fw->ipv6.smsk, 0xff, sizeof(fw->ipv6.smsk));
	}

	if ( dst_ip_address && dst_ip_address->ifa.ifa_family != AF_UNSPEC ) {
//		memcpy(&fw->ipv6.dst, &dst_ip_address->u.sin6_addr, sizeof ( dst_ip_address->u.sin6_addr ) );
		fw->ipv6.dst = dst_ip_address->u.sin6_addr;
		memset(&fw->ipv6.dmsk, 0xff, sizeof(fw->ipv6.dmsk));
	}

	fw->target_offset = XT_ALIGN(sizeof(struct ip6t_entry));

	// set
	match = (struct xt_entry_match*)((char*)fw + fw->target_offset);
	match->u.match_size = XT_ALIGN(sizeof(struct xt_entry_match)) + XT_ALIGN(sizeof(*setinfo));
#ifdef HAVE_XT_SET_INFO_MATCH_V4
	match->u.user.revision = 4;
#elif defined HAVE_XT_SET_INFO_MATCH_V3
	match->u.user.revision = 3;
#elif defined HAVE_XT_SET_INFO_MATCH_V1
	match->u.user.revision = 1;
#else
	match->u.user.revision = 0;
#endif
	fw->target_offset = (uint16_t)(fw->target_offset + match->u.match_size);
	strcpy(match->u.user.name, "set");

#ifdef HAVE_XT_SET_INFO_MATCH_V4
	setinfo = (struct xt_set_info_match_v4 *)match->data;
#elif defined HAVE_XT_SET_INFO_MATCH_V3
	setinfo = (struct xt_set_info_match_v3 *)match->data;
#elif defined HAVE_XT_SET_INFO_MATCH_V1
	setinfo = (struct xt_set_info_match_v1 *)match->data;
#else
	setinfo = (struct xt_set_info_match *)match->data;
#endif
	memset(setinfo, 0, sizeof(*setinfo));

	get_set_byname (set_name, &setinfo->match_set, NFPROTO_IPV6, ignore_errors);
	if (setinfo->match_set.index == IPSET_INVALID_ID) {
		FREE(fw);
		return -1;
	}

	setinfo->match_set.dim = dim;
	setinfo->match_set.flags = src_dst;

	if (protocol != IPPROTO_NONE) {
		fw->ipv6.proto = protocol;

		fw->ipv6.flags |= IP6T_F_PROTO ;		// IPv6 only

		if (protocol == IPPROTO_ICMPV6)
		{
			match = (struct xt_entry_match*)((char*)fw + fw->target_offset);
			match->u.match_size = XT_ALIGN(sizeof(struct xt_entry_match)) + XT_ALIGN(sizeof(struct ip6t_icmp));
			match->u.user.revision = 0;
			fw->target_offset = (uint16_t)(fw->target_offset + match->u.match_size);
			strcpy(match->u.user.name, "icmp6");

			struct ip6t_icmp *icmpinfo = (struct ip6t_icmp *)match->data;
			icmpinfo->type = param;		// type to match
			icmpinfo->code[0] = 0;		// code lower
			icmpinfo->code[1] = 0xff;	// code upper
			icmpinfo->invflags = 0;		// don't invert
		}
	}

// target is XTC_LABEL_DROP/XTC_LABEL_ACCEPT
	fw->next_offset = (uint16_t)size;
	target = ip6t_get_target(fw);
	target->u.user.target_size = XT_ALIGN(sizeof(struct xt_entry_target) + 1);
	strcpy_safe(target->u.user.name, target_name);
//	fw->ip.flags |= IP6T_F_GOTO;
	strcpy_safe(chain, chain_name);

	// Use iptc_append_entry to add to the chain
	if (cmd == IPADDRESS_DEL) {
		unsigned char *matchmask = MALLOC(fw->next_offset);
		memset(matchmask, 0xff, fw->next_offset);
		res = ip6tc_delete_entry(chain, fw, matchmask, handle);
		FREE(matchmask);
	}
	else if (rulenum == APPEND_RULE)
		res = ip6tc_append_entry(chain, fw, handle) ;
	else
		res = ip6tc_insert_entry(chain, fw, rulenum, handle) ;

	sav_errno = errno;

	FREE(fw);

	if (res!= 1)
	{
		if (!ignore_errors)
			log_message(LOG_INFO, "ip6tc_insert_entry for chain %s returned %d: %s", chain, res, ip6tc_strerror(sav_errno)) ;

		return sav_errno;
	}

	return 0;
}
#endif

#ifdef _LIBIPTC_DYNAMIC_
bool
iptables_lib_init(uint8_t family)
{
	if (family == AF_INET) {
		if (libip4tc_handle)
			return true;

		/* Attempt to open the ip4tc library */
		if (!(libip4tc_handle = dlopen("libip4tc.so", RTLD_NOW)) &&
		    !(libip4tc_handle = dlopen(IP4TC_LIB_NAME, RTLD_NOW))) {
			log_message(LOG_INFO, "Unable to load ip4tc library - %s", dlerror());
		}
		else if (!(iptc_init_addr = dlsym(libip4tc_handle, "iptc_init")) ||
			 !(iptc_free_addr = dlsym(libip4tc_handle, "iptc_free")) ||
			 !(iptc_is_chain_addr = dlsym(libip4tc_handle,"iptc_is_chain")) ||
			 !(iptc_insert_entry_addr = dlsym(libip4tc_handle,"iptc_insert_entry")) ||
			 !(iptc_append_entry_addr = dlsym(libip4tc_handle,"iptc_append_entry")) ||
			 !(iptc_delete_entry_addr = dlsym(libip4tc_handle,"iptc_delete_entry")) ||
			 !(iptc_commit_addr = dlsym(libip4tc_handle,"iptc_commit")) ||
			 !(iptc_strerror_addr = dlsym(libip4tc_handle,"iptc_strerror"))) {
			log_message(LOG_INFO, "Failed to dynamic link an iptc function - %s", dlerror());
			dlclose(libip4tc_handle);
			libip4tc_handle = NULL;
		}

		return !!libip4tc_handle;
	}

	if (libip6tc_handle)
		return true;

	/* Attempt to open the ip6tc library */
	if (!(libip6tc_handle = dlopen("libip6tc.so", RTLD_NOW)) &&
	    !(libip6tc_handle = dlopen(IP6TC_LIB_NAME, RTLD_NOW))) {
		log_message(LOG_INFO, "Unable to load ip6tc library - %s", dlerror());
	}
	else if (!(ip6tc_init_addr = dlsym(libip6tc_handle, "ip6tc_init")) ||
		 !(ip6tc_free_addr = dlsym(libip6tc_handle, "ip6tc_free")) ||
		 !(ip6tc_is_chain_addr = dlsym(libip6tc_handle,"ip6tc_is_chain")) ||
		 !(ip6tc_insert_entry_addr = dlsym(libip6tc_handle,"ip6tc_insert_entry")) ||
		 !(ip6tc_append_entry_addr = dlsym(libip6tc_handle,"ip6tc_append_entry")) ||
		 !(ip6tc_delete_entry_addr = dlsym(libip6tc_handle,"ip6tc_delete_entry")) ||
		 !(ip6tc_commit_addr = dlsym(libip6tc_handle,"ip6tc_commit")) ||
		 !(ip6tc_strerror_addr = dlsym(libip6tc_handle,"ip6tc_strerror"))) {
		log_message(LOG_INFO, "Failed to dynamic link an ip6tc function - %s", dlerror());
		dlclose(libip6tc_handle);
		libip6tc_handle = NULL;
	}

	return !!libip6tc_handle;
}
#endif
