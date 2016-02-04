/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        iptables manipulation directly without invoking iptables program.
 * 		This will use ipsets if they are available, in preference to
 * 		multiple entries in iptables.
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

/* The way iptables appears to work is that when we do an iptc_init, we get a
 * snapshot of the iptables table, which internally includes an update number.
 * When iptc_commit is called, it checks the update number, and if it has been
 * updated by someone else, returns EAGAIN.
 *
 * Note: iptc_commit only needs to be called if we are changing something. In
 *   all cases though, iptc_free must be called.
 *
 * Rules are numbered from 0 - despite what some documentation says
 *
 * Note: as insertions/deletions are made, rule numbers are changing.
 *
 * See http://www.tldp.org/HOWTO/Querying-libiptc-HOWTO/qfunction.html for
 *   some documentation
*/

#include <xtables.h>
#include <libiptc/libiptc.h>
#include <libiptc/libip6tc.h>
#include <libiptc/libxtc.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include <linux/if_addr.h>
#include <netinet/in.h>
#include <net/if.h>

#include "vrrp_iptables.h"
#include "vrrp_ipaddress.h"
#include "logger.h"
#include "memory.h"

struct ipt_handle {
	struct iptc_handle *h4;
	struct ip6tc_handle *h6;
} ;

/* Initializes a new iptables instance and returns an iptables resource associated with the new iptables table */
static struct iptc_handle* ip4tables_open ( const char* tablename )
{
	struct iptc_handle *h ;

	if ( !( h = iptc_init ( tablename ) ) )
		return NULL ;

	return h ;
}

/*
   close handle */
static int ip4tables_close ( struct iptc_handle* handle )
{
	int res;
	int sav_errno ;

	if ( ( res = iptc_commit ( handle ) ) != 1 )
	{
		sav_errno = errno ;
		log_message(LOG_INFO, "iptc_commit returned %d: %s\n", res, iptc_strerror (sav_errno) );
	}

	iptc_free ( handle ) ;

	if ( res == 1 )
		return 0 ;
	else
		return ( sav_errno ) ;
}

static int ip4tables_process_entry( struct iptc_handle* handle, const char* chain_name, int rulenum, const char* target_name, const ip_address_t* src_ip_address, const ip_address_t* dst_ip_address, const char* in_iface, const char* out_iface, uint16_t protocol, uint16_t type, int cmd)
{
	int size;
	struct ipt_entry *fw;
	struct xt_entry_target *target;
	struct xt_entry_match *match ;
	ipt_chainlabel chain;
	int res;
	int sav_errno;

	/* Add an entry */

	memset (chain, 0, sizeof (chain));

	size = XT_ALIGN (sizeof (struct ipt_entry)) +
			XT_ALIGN ( sizeof ( struct xt_entry_match ) ) +
			XT_ALIGN (sizeof (struct xt_entry_target) + 1);

	if ( protocol == IPPROTO_ICMP )
		size += XT_ALIGN ( sizeof(struct xt_entry_match) ) + XT_ALIGN ( sizeof(struct ipt_icmp) ) ;

	fw = (struct ipt_entry*)malloc(size);
	memset (fw, 0, size);

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

	if ( in_iface )
		strcpy ( fw->ip.iniface, in_iface ) ;
	if ( out_iface )
		strcpy ( fw->ip.outiface, out_iface ) ;

	if ( protocol != IPPROTO_NONE ) {
		fw->ip.proto = protocol ;

//		fw->ip.flags |= IP6T_F_PROTO ;		// IPv6 only

		if ( protocol == IPPROTO_ICMP )
		{
			match = (struct xt_entry_match*)((char*)fw + fw->target_offset);
			match->u.match_size = XT_ALIGN ( sizeof (struct xt_entry_match) ) + XT_ALIGN ( sizeof (struct ipt_icmp) ) ;
			match->u.user.revision = 0;
			fw->target_offset += match->u.match_size ;
			strcpy ( match->u.user.name, "icmpv" ) ;

			struct ipt_icmp *icmpinfo = (struct ipt_icmp *) match->data;
			icmpinfo->type = type ;	// type to match
			icmpinfo->code[0] = 0 ;	// code lower
			icmpinfo->code[1] = 0xff ;		// code upper
			icmpinfo->invflags = 0 ;	// don't invert
		}
	}

// target is XTC_LABEL_DROP/XTC_LABEL_ACCEPT
	fw->next_offset = size;
	target = ipt_get_target ( fw ) ;
	target->u.user.target_size = XT_ALIGN (sizeof (struct xt_entry_target) + 1);
	strcpy (target->u.user.name, target_name );
//	fw->ip.flags |= IPT_F_GOTO;
	strcpy (chain, chain_name);
	// Use iptc_append_entry to add to the chain
	if (cmd == IPADDRESS_DEL) {
		unsigned char matchmask[fw->next_offset];
		memset(matchmask, 0xff, fw->next_offset);
		res = iptc_delete_entry(chain, fw, matchmask, handle);
	}
	else if ( rulenum == -1 )
		res = iptc_append_entry (chain, fw, handle ) ;
	else
		res = iptc_insert_entry (chain, fw, rulenum, handle ) ;

	sav_errno = errno ;

	if (res!= 1)
	{
		log_message(LOG_INFO, "ip4tables_process_entry returned %d: %s\n", res, iptc_strerror (sav_errno) ) ;
		log_message(LOG_INFO, "\tChain %s \n", chain_name ) ;

		return sav_errno ;
	}

	return 0 ;
}

/* Initializes a new iptables instance and returns an iptables resource associated with the new iptables table */
static struct ip6tc_handle* ip6tables_open ( const char* tablename )
{
	struct ip6tc_handle *h ;

	if ( !( h = ip6tc_init ( tablename ) ) )
		return NULL ;

	return h ;
}

static int ip6tables_close ( struct ip6tc_handle* handle )
{
	int res;
	int sav_errno ;

	if ( ( res = ip6tc_commit ( handle ) ) != 1 )
	{
		sav_errno = errno ;
		log_message(LOG_INFO, "iptc_commit returned %d: %s\n", res, ip6tc_strerror (sav_errno) );
	}

	ip6tc_free ( handle ) ;

	if ( res == 1 )
		return 0 ;
	else
		return ( sav_errno ) ;
}

static int ip6tables_process_entry( struct ip6tc_handle* handle, const char* chain_name, int rulenum, const char* target_name, const ip_address_t* src_ip_address, const ip_address_t* dst_ip_address, const char* in_iface, const char* out_iface, uint16_t protocol, uint16_t type, int cmd)
{
	int size;
	struct ip6t_entry *fw;
	struct xt_entry_target *target;
	struct xt_entry_match *match ;
	ip6t_chainlabel chain;
	int res;
	int sav_errno;

	/* Add an entry */

	memset (chain, 0, sizeof (chain));

	size = XT_ALIGN (sizeof (struct ip6t_entry)) +
			XT_ALIGN ( sizeof ( struct xt_entry_match ) ) +
			XT_ALIGN (sizeof (struct xt_entry_target) + 1);

	if ( protocol == IPPROTO_ICMPV6 )
		size += XT_ALIGN ( sizeof(struct xt_entry_match) ) + XT_ALIGN ( sizeof(struct ip6t_icmp) ) ;

	fw = (struct ip6t_entry*)malloc(size);
	memset (fw, 0, size);

	fw->target_offset = XT_ALIGN ( sizeof ( struct ip6t_entry ) ) ;

	if ( src_ip_address && src_ip_address->ifa.ifa_family != AF_UNSPEC ) {
		memcpy(&fw->ipv6.src, &src_ip_address->u.sin6_addr, sizeof ( src_ip_address->u.sin6_addr ) );
		memset ( &fw->ipv6.smsk, 0xff, sizeof(fw->ipv6.smsk));
	}

	if ( dst_ip_address && dst_ip_address->ifa.ifa_family != AF_UNSPEC ) {
		memcpy(&fw->ipv6.dst, &dst_ip_address->u.sin6_addr, sizeof ( dst_ip_address->u.sin6_addr ) );
		memset ( &fw->ipv6.dmsk, 0xff, sizeof(fw->ipv6.smsk));
	}

	if ( in_iface )
		strcpy ( fw->ipv6.iniface, in_iface ) ;
	if ( out_iface )
		strcpy ( fw->ipv6.outiface, out_iface ) ;

	if ( protocol != IPPROTO_NONE ) {
		fw->ipv6.proto = protocol ;

		fw->ipv6.flags |= IP6T_F_PROTO ;		// IPv6 only

		if ( protocol == IPPROTO_ICMPV6 )
		{
			match = (struct xt_entry_match*)((char*)fw + fw->target_offset);
			match->u.match_size = XT_ALIGN ( sizeof (struct xt_entry_match) ) + XT_ALIGN ( sizeof (struct ip6t_icmp) ) ;
			match->u.user.revision = 0;
			fw->target_offset += match->u.match_size ;
			strcpy ( match->u.user.name, "icmp6" ) ;

			struct ip6t_icmp *icmpinfo = (struct ip6t_icmp *) match->data;
			icmpinfo->type = type ;		// type to match
			icmpinfo->code[0] = 0 ;		// code lower
			icmpinfo->code[1] = 0xff ;	// code upper
			icmpinfo->invflags = 0 ;	// don't invert
		}
	}

// target is XTC_LABEL_DROP/XTC_LABEL_ACCEPT
	fw->next_offset = size;
	target = ip6t_get_target ( fw ) ;
	target->u.user.target_size = XT_ALIGN (sizeof (struct xt_entry_target) + 1);
	strcpy (target->u.user.name, target_name );
//	fw->ip.flags |= IPT_F_GOTO;
	strcpy (chain, chain_name);

	// Use iptc_append_entry to add to the chain
	if (cmd == IPADDRESS_DEL) {
		unsigned char matchmask[fw->next_offset];
		memset(matchmask, 0xff, fw->next_offset);
		res = ip6tc_delete_entry ( chain, fw, matchmask, handle);
	}
	else if ( rulenum == -1 )
		res = ip6tc_append_entry (chain, fw, handle ) ;
	else
		res = ip6tc_insert_entry (chain, fw, rulenum, handle ) ;

	sav_errno = errno ;

	if (res != 1)
	{
		log_message(LOG_INFO, "ip6tables_process_entry returned %d: %s\n", res, ip6tc_strerror (sav_errno) ) ;
		log_message(LOG_INFO, "\tChain %s \n", chain_name ) ;

		return sav_errno ;
	}

	return 0 ;
}

struct ipt_handle *iptables_open()
{
	struct ipt_handle *h = MALLOC(sizeof(struct ipt_handle));

	return h;
}

int iptables_close(struct ipt_handle *h)
{
	int res = 0;

	if (h->h4)
		res = ip4tables_close(h->h4);
	if (h->h6)
		res = ip6tables_close(h->h6);

	FREE(h);

	return res;
}

int iptables_entry( struct ipt_handle* h, const char* chain_name, int rulenum, const char* target_name, const ip_address_t* src_ip_address, const ip_address_t* dst_ip_address, const char* in_iface, const char* out_iface, uint16_t protocol, uint16_t type, int cmd)
{
	if ((src_ip_address && src_ip_address->ifa.ifa_family == AF_INET) ||
	    (dst_ip_address && dst_ip_address->ifa.ifa_family == AF_INET )) {
		if (!h->h4)
			h->h4 = ip4tables_open ("filter");
		return ip4tables_process_entry( h->h4, chain_name, rulenum, target_name, src_ip_address, dst_ip_address, in_iface, out_iface, protocol, type, cmd);
	}
	else if ((src_ip_address && src_ip_address->ifa.ifa_family == AF_INET6) ||
		 (dst_ip_address && dst_ip_address->ifa.ifa_family == AF_INET6)) {
		if (!h->h6)
			h->h6 = ip6tables_open ("filter");

		return ip6tables_process_entry( h->h6, chain_name, rulenum, target_name, src_ip_address, dst_ip_address, in_iface, out_iface, protocol, type, cmd);
	}

	return 0;
}
