/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        VRRP implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
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

/* System includes */
#include <errno.h>
#include <openssl/md5.h>
#include <unistd.h>
#include <sys/time.h>
#ifdef _WITH_VRRP_AUTH_
#include <netinet/in.h>
#endif
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <net/if_arp.h>

/* local include */
#include "parser.h"

#include "vrrp_arp.h"
#include "vrrp_ndisc.h"
#include "vrrp_scheduler.h"
#include "vrrp_notify.h"
#include "vrrp.h"
#include "global_data.h"
#include "vrrp_data.h"
#include "vrrp_sync.h"
#include "vrrp_index.h"
#include "vrrp_track.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_vmac.h"
#endif
#include "vrrp_if_config.h"
#ifdef _HAVE_LIBIPTC_
#include "vrrp_iptables.h"
#endif
#if defined _WITH_SNMP_RFC_ || defined _WITH_SNMP_VRRP_
#include "vrrp_snmp.h"
#endif
#include "list.h"
#include "logger.h"
#include "main.h"
#include "utils.h"
#include "bitops.h"
#include "keepalived_netlink.h"
#if !HAVE_DECL_SOCK_CLOEXEC
#include "old_socket.h"
#endif
#ifdef _HAVE_FIB_ROUTING_
#include "vrrp_iprule.h"
#include "vrrp_iproute.h"
#endif
#ifdef _WITH_DBUS_
#include "vrrp_dbus.h"
#include "global_data.h"
#endif
#include "keepalived_magic.h"
#include "vrrp_static_track.h"

/* Set if need to block ip addresses and are able to do so */
bool block_ipv4;
bool block_ipv6;

/* If we don't have certain configuration, then we can optimise the
 * resources that keepalived uses. These are cleared by start_vrrp()
 * in clear_summary_flags() and set in vrrp_complete_instance()
 */
bool have_ipv4_instance;
bool have_ipv6_instance;
#ifdef _HAVE_FIB_ROUTING_
static bool monitor_ipv4_routes;
static bool monitor_ipv6_routes;
static bool monitor_ipv4_rules;
static bool monitor_ipv6_rules;
#endif

static int
vrrp_notify_fifo_script_exit(__attribute__((unused)) thread_t *thread)
{
	log_message(LOG_INFO, "vrrp notify fifo script terminated");

	return 0;
}

void
clear_summary_flags(void)
{
	have_ipv4_instance = false;
	have_ipv6_instance = false;
#ifdef _HAVE_FIB_ROUTING_
	monitor_ipv4_routes = false;
	monitor_ipv6_routes = false;
	monitor_ipv4_rules = false;
	monitor_ipv6_rules = false;
#endif
}

/* add/remove Virtual IP addresses */
static bool
vrrp_handle_ipaddress(vrrp_t * vrrp, int cmd, int type, bool force)
{
	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "(%s) %s %s", vrrp->iname,
		       (cmd == IPADDRESS_ADD) ? "setting" : "removing",
		       (type == VRRP_VIP_TYPE) ? "VIPs." : "E-VIPs.");
	return netlink_iplist((type == VRRP_VIP_TYPE) ? vrrp->vip : vrrp->evip, cmd, force);
}

#ifdef _HAVE_FIB_ROUTING_
/* add/remove Virtual routes */
static void
vrrp_handle_iproutes(vrrp_t * vrrp, int cmd)
{
	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "(%s) %s Virtual Routes",
		       vrrp->iname,
		       (cmd == IPROUTE_ADD) ? "setting" : "removing");
	netlink_rtlist(vrrp->vroutes, cmd);
}

/* add/remove Virtual rules */
static void
vrrp_handle_iprules(vrrp_t * vrrp, int cmd, bool force)
{
	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "(%s) %s Virtual Rules",
		       vrrp->iname,
		       (cmd == IPRULE_ADD) ? "setting" : "removing");
	netlink_rulelist(vrrp->vrules, cmd, force);
}
#endif

/* add/remove iptable drop rules based on accept mode */
static void
vrrp_handle_accept_mode(vrrp_t *vrrp, int cmd, bool force)
{
#ifdef _HAVE_LIBIPTC_
	int tries = 0;
	int res = 0;
#endif
	struct ipt_handle *h = NULL;

	if (vrrp->base_priority != VRRP_PRIO_OWNER && !vrrp->accept) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "(%s) %s %s", vrrp->iname,
				(cmd == IPADDRESS_ADD) ? "setting" : "removing", "iptable drop rule");

#ifdef _HAVE_LIBIPTC_
		do {
#ifdef _LIBIPTC_DYNAMIC_
			if ((vrrp->family == AF_INET && using_libip4tc) ||
			    (vrrp->family == AF_INET6 && using_libip6tc))
#endif
				h = iptables_open();
#endif
			/* As accept is false, add iptable rule to drop packets destinated to VIPs and eVIPs */
			if (!LIST_ISEMPTY(vrrp->vip))
				handle_iptable_rule_to_iplist(h, vrrp->vip, cmd, force);
			if (!LIST_ISEMPTY(vrrp->evip))
				handle_iptable_rule_to_iplist(h, vrrp->evip, cmd, force);
#ifdef _HAVE_LIBIPTC_
#ifdef _LIBIPTC_DYNAMIC_
			if (h)
#endif
				res = iptables_close(h);
		} while (res == EAGAIN && ++tries < IPTABLES_MAX_TRIES);
#endif
		vrrp->iptable_rules_set = (cmd == IPADDRESS_ADD);
	}
}

/* Check that the scripts are secure */
static int
check_track_script_secure(vrrp_script_t *script, magic_t magic)
{
	int flags;

	if (script->insecure)
		return 0;

	flags = check_script_secure(&script->script, magic);

	/* Mark not to run if needs inhibiting */
	if (flags & SC_INHIBIT) {
		log_message(LOG_INFO, "Disabling track script %s due to insecure", script->sname);
		script->insecure = true;
	}
	else if (flags & SC_NOTFOUND) {
		log_message(LOG_INFO, "Disabling track script %s since not found/accessible", script->sname);
		script->insecure = true;
	}
	else if (!(flags & (SC_EXECUTABLE | SC_SYSTEM)))
		script->insecure = true;

	return flags;
}

static void
check_vrrp_script_security(void)
{
	element e, e1, next;
	vrrp_t *vrrp;
	vrrp_sgroup_t *sg;
	tracked_sc_t *track_script;
	vrrp_script_t *vscript;
	int script_flags = 0;
	magic_t magic;

	if (LIST_ISEMPTY(vrrp_data->vrrp))
		return;

	magic = ka_magic_open();

	/* Set the insecure flag of any insecure scripts */
	if (!LIST_ISEMPTY(vrrp_data->vrrp_script)) {
		for (e = LIST_HEAD(vrrp_data->vrrp_script); e; ELEMENT_NEXT(e)) {
			vscript = ELEMENT_DATA(e);
			script_flags |= check_track_script_secure(vscript, magic);
		}
	}

	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		script_flags |= check_notify_script_secure(&vrrp->script_backup, magic);
		script_flags |= check_notify_script_secure(&vrrp->script_master, magic);
		script_flags |= check_notify_script_secure(&vrrp->script_fault, magic);
		script_flags |= check_notify_script_secure(&vrrp->script_stop, magic);
		script_flags |= check_notify_script_secure(&vrrp->script, magic);

		if (LIST_ISEMPTY(vrrp->track_script))
			continue;

		for (e1 = LIST_HEAD(vrrp->track_script); e1; e1 = next) {
			next = e1->next;
			track_script = ELEMENT_DATA(e1);

			if (track_script->scr->insecure) {
				/* Remove it from the vrrp instance's queue */
				free_list_element(vrrp->track_script, e1);
			}
		}
	}

	if (!LIST_ISEMPTY(vrrp_data->vrrp_sync_group)) {
		for (e = LIST_HEAD(vrrp_data->vrrp_sync_group); e; ELEMENT_NEXT(e)) {
			sg = ELEMENT_DATA(e);
			script_flags |= check_notify_script_secure(&sg->script_backup, magic);
			script_flags |= check_notify_script_secure(&sg->script_master, magic);
			script_flags |= check_notify_script_secure(&sg->script_fault, magic);
			script_flags |= check_notify_script_secure(&sg->script_stop, magic);
			script_flags |= check_notify_script_secure(&sg->script, magic);

			for (e1 = LIST_HEAD(sg->track_script); e1; e1 = next) {
				next = e1->next;
				track_script = ELEMENT_DATA(e1);

				if (track_script->scr->insecure) {
					/* Remove it from the vrrp sync group's queue */
					free_list_element(sg->track_script, e1);
				}
			}
		}
	}

	if (global_data->notify_fifo.script)
		script_flags |= check_notify_script_secure(&global_data->notify_fifo.script, magic);
	if (global_data->vrrp_notify_fifo.script)
		script_flags |= check_notify_script_secure(&global_data->vrrp_notify_fifo.script, magic);

	if (!script_security && script_flags & SC_ISSCRIPT) {
		log_message(LOG_INFO, "SECURITY VIOLATION - scripts are being executed but script_security not enabled.%s",
				script_flags & SC_INSECURE ? " There are insecure scripts." : "");
	}

	if (magic)
		ka_magic_close(magic);

	/* Now walk through the vrrp_script list, removing any that aren't used */
	for (e = LIST_HEAD(vrrp_data->vrrp_script); e; e = next) {
		next = e->next;
		vscript = ELEMENT_DATA(e);

		if (vscript->insecure)
			free_list_element(vrrp_data->vrrp_script, e);
	}
}

/* IP header length */
static inline size_t
vrrp_iphdr_len(void)
{
	return sizeof(struct iphdr);
}

#ifdef _WITH_VRRP_AUTH_
/* IPSEC AH header length */
static inline size_t
vrrp_ipsecah_len(void)
{
	return sizeof(ipsec_ah_t);
}
#endif

/* VRRP header length */
static size_t
vrrp_pkt_len(vrrp_t * vrrp)
{
	size_t len = sizeof(vrrphdr_t);

	/* Our implementation of IPv6 with VRRP version 2 doesn't include the 8 byte auth field */
	if (vrrp->family == AF_INET) {
		if (vrrp->version == VRRP_VERSION_2)
			len += VRRP_AUTH_LEN;
		len += ((!LIST_ISEMPTY(vrrp->vip)) ? LIST_SIZE(vrrp->vip) * sizeof(struct in_addr) : 0);
	}
	else if (vrrp->family == AF_INET6)
		len += ((!LIST_ISEMPTY(vrrp->vip)) ? LIST_SIZE(vrrp->vip) * sizeof(struct in6_addr) : 0);

	return len;
}

size_t
vrrp_adv_len(vrrp_t *vrrp)
{
	size_t len = vrrp_pkt_len(vrrp);

	if (vrrp->family == AF_INET) {
		len += vrrp_iphdr_len();
#ifdef _WITH_VRRP_AUTH_
		if (vrrp->auth_type == VRRP_AUTH_AH)
			len += vrrp_ipsecah_len();
#endif
	}

	return len;
}

/* VRRP header pointer from buffer */
vrrphdr_t *
vrrp_get_header(sa_family_t family, char *buf, unsigned *proto)
{
	struct iphdr *iph;
	vrrphdr_t *hd = NULL;

	if (family == AF_INET) {
		iph = (struct iphdr *) buf;

		/* Fill the VRRP header */
#ifdef _WITH_VRRP_AUTH_
		if (iph->protocol == IPPROTO_AH) {
			*proto = IPPROTO_AH;
			hd = (vrrphdr_t *) ((char *) iph + (iph->ihl << 2) +
					   vrrp_ipsecah_len());
		}
		else
#endif
		{
			*proto = IPPROTO_VRRP;
			hd = (vrrphdr_t *) ((char *) iph + (iph->ihl << 2));
		}
	} else if (family == AF_INET6) {
		*proto = IPPROTO_VRRP;
		hd = (vrrphdr_t *) buf;
	}

	return hd;
}

static void
vrrp_update_pkt(vrrp_t *vrrp, uint8_t prio, struct sockaddr_storage* addr)
{
	char *bufptr = vrrp->send_buffer;
	vrrphdr_t *hd;
#ifdef _WITH_VRRP_AUTH_
	bool final_update;
#endif
	uint32_t new_saddr = 0;
	uint32_t new_daddr;

#ifdef _WITH_VRRP_AUTH_
	/* We will need to be called again if there is more than one unicast peer, so don't calculate checksums */
	final_update = (LIST_ISEMPTY(vrrp->unicast_peer) || !LIST_HEAD(vrrp->unicast_peer)->next || addr);
#endif

	if (vrrp->family == AF_INET) {
		bufptr += vrrp_iphdr_len();

#ifdef _WITH_VRRP_AUTH_
		if (vrrp->auth_type == VRRP_AUTH_AH)
			bufptr += vrrp_ipsecah_len();
#endif
	}

	hd = (vrrphdr_t *)bufptr;
	if (hd->priority != prio) {
		if (vrrp->family == AF_INET) {
			/* HC' = ~(~HC + ~m + m') */
			uint16_t *prio_addr = (uint16_t *)((char *)&hd->priority - (((char *)hd -(char *)&hd->priority) & 1));
			uint16_t old_val = *prio_addr;

			hd->priority = prio;
			hd->chksum = csum_incremental_update16(hd->chksum, old_val, *prio_addr);
		}
		else
			hd->priority = prio;
	}

	if (vrrp->family == AF_INET) {
		struct iphdr *ip = (struct iphdr *) (vrrp->send_buffer);
		if (!addr) {
			/* kernel will fill in ID if left to 0, so we overflow to 1 */
			if (!++vrrp->ip_id)
				++vrrp->ip_id;
			ip->id = htons(vrrp->ip_id);
		}
		else {
			/* If unicast address */
			if (vrrp->version == VRRP_VERSION_2)
				ip->daddr = inet_sockaddrip4(addr);
			else {
				new_daddr = inet_sockaddrip4(addr);

				if (ip->daddr != new_daddr) {
#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
					if (vrrp->unicast_chksum_compat < CHKSUM_COMPATIBILITY_MIN_COMPAT)
#endif
						hd->chksum = csum_incremental_update32(hd->chksum, ip->daddr, new_daddr);
					ip->daddr = new_daddr;
				}
			}
		}

		/* Has the source address changed? */
		if (!vrrp->saddr_from_config &&
		    ip->saddr != ((struct sockaddr_in *)&vrrp->saddr)->sin_addr.s_addr) {
			if (vrrp->version == VRRP_VERSION_2)
				ip->saddr = ((struct sockaddr_in*)&vrrp->saddr)->sin_addr.s_addr;
			else {
				new_saddr = ((struct sockaddr_in*)&vrrp->saddr)->sin_addr.s_addr;
				hd->chksum = csum_incremental_update32(hd->chksum, ip->saddr, new_saddr);
				ip->saddr = new_saddr;
			}
		}

#ifdef _WITH_VRRP_AUTH_
		if (vrrp->auth_type == VRRP_AUTH_AH) {
			ICV_mutable_fields ip_mutable_fields;
			unsigned char digest[MD5_DIGEST_LENGTH];
			ipsec_ah_t *ah = (ipsec_ah_t *) (vrrp->send_buffer + sizeof (struct iphdr));

			if (new_saddr)
				ah->spi = new_saddr;

			if (!addr) {
				/* Processing sequence number.
				   Cycled assumed if 0xFFFFFFFD reached. So the MASTER state is free for another srv.
				   Here can result a flapping MASTER state owner when max seq_number value reached.
				   => We REALLY REALLY REALLY don't need to worry about this. We only use authentication
				   for VRRPv2, for which the adver_int is specified in whole seconds, therefore the minimum
				   adver_int is 1 second. 2^32-3 seconds is 4294967293 seconds, or in excess of 136 years,
				   so since the sequence number always starts from 0, we are not going to reach the limit.
				   In the current implementation if counter has cycled, we stop sending adverts and
				   become BACKUP. We are ever the optimist and think we might run continuously for over
				   136 years without someone redesigning their network!
				   If all the master are down we reset the counter for becoming MASTER.
				 */
				if (vrrp->ipsecah_counter.seq_number > 0xFFFFFFFD) {
					vrrp->ipsecah_counter.cycle = true;
				} else {
					vrrp->ipsecah_counter.seq_number++;
				}

				ah->seq_number = htonl(vrrp->ipsecah_counter.seq_number);
			}

			if (final_update) {
				/* backup the ip mutable fields */
				ip_mutable_fields.tos = ip->tos;
				ip_mutable_fields.ttl = ip->ttl;
				ip_mutable_fields.frag_off = ip->frag_off;

				/* zero the ip mutable fields */
				ip->tos = 0;
				ip->frag_off = 0;
				if (!LIST_ISEMPTY(vrrp->unicast_peer))
					ip->ttl = 0;
				/* Compute the ICV & trunc the digest to 96bits
				   => No padding needed.
				   -- rfc2402.3.3.3.1.1.1 & rfc2401.5
				 */
				memset(&ah->auth_data, 0, sizeof(ah->auth_data));
				hmac_md5((unsigned char *)vrrp->send_buffer, vrrp->send_buffer_size, vrrp->auth_data, sizeof (vrrp->auth_data), digest);
				memcpy(ah->auth_data, digest, HMAC_MD5_TRUNC);

				/* Restore the ip mutable fields */
				ip->tos = ip_mutable_fields.tos;
				ip->frag_off = ip_mutable_fields.frag_off;
				ip->ttl = ip_mutable_fields.ttl;
			}
		}
#endif
	}
}

#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
static void
vrrp_csum_mcast(vrrp_t *vrrp)
{
	char *bufptr = vrrp->send_buffer;
	vrrphdr_t *hd;

	bufptr += vrrp_iphdr_len();

#ifdef _WITH_VRRP_AUTH_
	if (vrrp->auth_type == VRRP_AUTH_AH)
		bufptr += vrrp_ipsecah_len();
#endif

	hd = (vrrphdr_t *)bufptr;

	struct iphdr *ip = (struct iphdr *) (vrrp->send_buffer);
	if (vrrp->unicast_chksum_compat == CHKSUM_COMPATIBILITY_AUTO &&
	    ip->daddr != global_data->vrrp_mcast_group4.sin_addr.s_addr) {
		/* The checksum is calculated using the standard multicast address */
		hd->chksum = csum_incremental_update32(hd->chksum, ip->daddr, global_data->vrrp_mcast_group4.sin_addr.s_addr);
	}
}
#endif

#ifdef _WITH_VRRP_AUTH_
/*
 * IPSEC AH incoming packet check.
 * return false for a valid pkt, true otherwise.
 */
static bool
vrrp_in_chk_ipsecah(vrrp_t * vrrp, char *buffer)
{
	struct iphdr *ip = (struct iphdr *) (buffer);
	ipsec_ah_t *ah = (ipsec_ah_t *) ((char *) ip + (ip->ihl << 2));
	unsigned char digest[MD5_DIGEST_LENGTH];
	char backup_auth_data[sizeof(ah->auth_data)];

	/*
	 * First compute an ICV to compare with the one present in AH pkt.
	 * If they don't match, we can't consider any fields in the received
	 * packet to be valid.
	 */

	/* zero the ip mutable fields */
	ip->tos = 0;
	ip->frag_off = 0;
	ip->check = 0;
	if (!LIST_ISEMPTY(vrrp->unicast_peer))
		ip->ttl = 0;
	memcpy(backup_auth_data, ah->auth_data, sizeof (ah->auth_data));
	memset(ah->auth_data, 0, sizeof (ah->auth_data));
	memset(digest, 0, MD5_DIGEST_LENGTH);

	/* Compute the ICV */
	hmac_md5((unsigned char *) buffer,
		 vrrp_iphdr_len() + vrrp_ipsecah_len() + vrrp_pkt_len(vrrp)
		 , vrrp->auth_data, sizeof (vrrp->auth_data)
		 , digest);

	if (memcmp(backup_auth_data, digest, HMAC_MD5_TRUNC) != 0) {
		log_message(LOG_INFO, "(%s) IPSEC-AH : invalid"
				      " IPSEC HMAC-MD5 value. Due to fields mutation"
				      " or bad password !",
			    vrrp->iname);
		return true;
	}

	/* Now verify that the SPI value is equal to src IP */
	if (ah->spi != ip->saddr) {
		log_message(LOG_INFO, "IPSEC AH : invalid IPSEC SPI value. %d and expect %d",
			    ip->saddr, ah->spi);
		return true;
	}

// TODO - If SPI doesn't match previous SPI, we are starting again
	/*
	 * then proceed with the sequence number to prevent against replay attack.
	 */
	if (ntohl(ah->seq_number) > vrrp->ipsecah_counter.seq_number)
		vrrp->ipsecah_counter.seq_number = ntohl(ah->seq_number);
	else {
		log_message(LOG_INFO, "(%s) IPSEC-AH : sequence number %d"
					" already processed. Packet dropped. Local(%d)",
					vrrp->iname, ntohl(ah->seq_number),
					vrrp->ipsecah_counter.seq_number);
		return true;
	}

	return false;
}
#endif

/* check if ipaddr is present in VIP buffer */
static int
vrrp_in_chk_vips(vrrp_t * vrrp, ip_address_t *ipaddress, unsigned char *buffer)
{
	size_t i;

	if (vrrp->family == AF_INET) {
		for (i = 0; i < LIST_SIZE(vrrp->vip); i++) {
			if (!memcmp(&ipaddress->u.sin.sin_addr.s_addr, buffer + i * sizeof(struct in_addr), sizeof (struct in_addr)))
				return 1;
		}
	} else if (vrrp->family == AF_INET6) {
		for (i = 0; i < LIST_SIZE(vrrp->vip); i++) {
			if (!memcmp(&ipaddress->u.sin6_addr, buffer + i * sizeof(struct in6_addr), sizeof (struct in6_addr)))
				return 1;
		}
	}

	return 0;
}

/*
 * VRRP incoming packet check.
 * return VRRP_PACKET_OK if the pkt is valid, or
 *	  VRRP_PACKET_KO if packet invalid or
 *	  VRRP_PACKET_DROP if packet not relevant to us
 *	  VRRP_PACKET_OTHER if packet has wrong vrid
 *
 * Note: If we return anything other that VRRP_PACKET_OK, we should log the reason why
 */
static int
vrrp_in_chk(vrrp_t * vrrp, char *buffer, ssize_t buflen_ret, bool check_vip_addr)
{
	struct iphdr *ip;
	int ihl;
	size_t vrrppkt_len;
	unsigned adver_int = 0;
#ifdef _WITH_VRRP_AUTH_
	ipsec_ah_t *ah;
#endif
	vrrphdr_t *hd;
	unsigned char *vips;
	ip_address_t *ipaddress;
	element e;
	char addr_str[INET6_ADDRSTRLEN];
	ipv4_phdr_t ipv4_phdr;
	uint32_t acc_csum = 0;
	ip = NULL;
	struct sockaddr_storage *up_addr;
	size_t buflen, expected_len;
#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
	bool chksum_error;
#endif

	if (buflen_ret < 0) {
		log_message(LOG_INFO, "recvmsg returned %zd", buflen_ret);
		return VRRP_PACKET_KO;
	}
	buflen = (size_t)buflen_ret;

	/* IPv4 related */
	if (vrrp->family == AF_INET) {
		/* To begin with, we just concern ourselves with the protocol headers */
		expected_len = vrrp_iphdr_len() + sizeof(vrrphdr_t);
#ifdef _WITH_VRRP_AUTH_
		if (vrrp->auth_type == VRRP_AUTH_AH)
			expected_len += vrrp_ipsecah_len();
#endif

		/*
		 * MUST verify that the received packet length is not shorter than
		 * the VRRP header
		 */
		if (buflen < expected_len) {
			log_message(LOG_INFO,
			       "(%s) ip/vrrp header too short. %zu and expect at least %zu",
			      vrrp->iname, buflen, expected_len);
			++vrrp->stats->packet_len_err;
			return VRRP_PACKET_KO;
		}

		ip = (struct iphdr *) (buffer);
		ihl = ip->ihl << 2;

#ifdef _WITH_VRRP_AUTH_
		if (vrrp->auth_type == VRRP_AUTH_AH) {
			ah = (ipsec_ah_t *) (buffer + ihl);
			hd = (vrrphdr_t *) ((char *) ah + vrrp_ipsecah_len());
		} else
#endif
			hd = (vrrphdr_t *) (buffer + ihl);

		/* Now calculate expected_len to include everything */
		expected_len += vrrp_pkt_len(vrrp) - sizeof(vrrphdr_t);

		/* MUST verify that the IP TTL is 255 */
		if (LIST_ISEMPTY(vrrp->unicast_peer) && ip->ttl != VRRP_IP_TTL) {
			log_message(LOG_INFO, "(%s) invalid ttl. %d and expect %d",
				vrrp->iname, ip->ttl, VRRP_IP_TTL);
			++vrrp->stats->ip_ttl_err;
#ifdef _WITH_SNMP_RFCV3_
			vrrp->stats->proto_err_reason = ipTtlError;
			vrrp_rfcv3_snmp_proto_err_notify(vrrp);
#endif
			return VRRP_PACKET_KO;
		}
	} else if (vrrp->family == AF_INET6) {
		/*
		 * MUST verify that the received packet length is greater than or
		 * equal to the VRRP header
		 */
		if (buflen < sizeof(vrrphdr_t)) {
			log_message(LOG_INFO,
			       "(%s) vrrp header too short. %zu and expect at least %zu",
			      vrrp->iname, buflen, sizeof(vrrphdr_t));
			++vrrp->stats->packet_len_err;
			return VRRP_PACKET_KO;
		}

		hd = (vrrphdr_t *) buffer;

		/* Set expected vrrp packet length */
		expected_len = sizeof(vrrphdr_t) + (LIST_ISEMPTY(vrrp->vip) ? 0 : LIST_SIZE(vrrp->vip)) * sizeof(struct in6_addr);
	} else {
		log_message(LOG_INFO, "(%s) configured address family is %d, which is neither AF_INET or AF_INET6. This is probably a bug - please report", vrrp->iname, vrrp->family);
		return VRRP_PACKET_KO;
	}

	if (vrrp->version == VRRP_VERSION_2) {
		/* Check that authentication of packet is correct */
		if (
#ifdef _WITH_VRRP_AUTH_
		    hd->v2.auth_type != VRRP_AUTH_AH &&
		    hd->v2.auth_type != VRRP_AUTH_PASS &&
#endif
		    hd->v2.auth_type != VRRP_AUTH_NONE) {
			log_message(LOG_INFO, "(%s) Invalid auth type: %d", vrrp->iname, hd->v2.auth_type);
			++vrrp->stats->invalid_authtype;
#ifdef _WITH_SNMP_RFCV2_
			vrrp_rfcv2_snmp_auth_err_trap(vrrp, ((struct sockaddr_in *)&vrrp->pkt_saddr)->sin_addr, invalidAuthType);
#endif
			return VRRP_PACKET_KO;
		}

#ifdef _WITH_VRRP_AUTH_
		/*
		 * MUST perform authentication specified by Auth Type
		 * check the authentication type
		 */
		if (vrrp->auth_type != hd->v2.auth_type) {
			log_message(LOG_INFO, "(%s) received a %d auth, expecting %d!",
			       vrrp->iname, hd->v2.auth_type, vrrp->auth_type);
			++vrrp->stats->authtype_mismatch;
#ifdef _WITH_SNMP_RFCV2_
			vrrp_rfcv2_snmp_auth_err_trap(vrrp, ((struct sockaddr_in *)&vrrp->pkt_saddr)->sin_addr, authTypeMismatch);
#endif
			return VRRP_PACKET_KO;
		}

		if (vrrp->auth_type == VRRP_AUTH_PASS) {
			/* check the authentication if it is a passwd */
			char *pw = (char *) ip + ntohs(ip->tot_len)
			    - sizeof (vrrp->auth_data);
			if (memcmp(pw, vrrp->auth_data, sizeof(vrrp->auth_data)) != 0) {
				log_message(LOG_INFO, "(%s) received an invalid passwd!", vrrp->iname);
				++vrrp->stats->auth_failure;
#ifdef _WITH_SNMP_RFCV2_
				vrrp_rfcv2_snmp_auth_err_trap(vrrp, ((struct sockaddr_in *)&vrrp->pkt_saddr)->sin_addr, authFailure);
#endif
				return VRRP_PACKET_KO;
			}
		}
		else if (hd->v2.auth_type == VRRP_AUTH_AH) {
			/* check the authentication if it is ipsec ah */
			if (vrrp_in_chk_ipsecah(vrrp, buffer)) {
				++vrrp->stats->auth_failure;
#ifdef _WITH_SNMP_RFCV2_
				vrrp_rfcv2_snmp_auth_err_trap(vrrp, ((struct sockaddr_in *)&vrrp->pkt_saddr)->sin_addr, authFailure);
#endif
				return VRRP_PACKET_KO;
			}

			/* NOTE: ah below is initialised above. Older versions of gcc may
			 * however warn that it may be used uninitialised. */
			if (vrrp->state == VRRP_STATE_BACK &&
			    ntohl(ah->seq_number) >= vrrp->ipsecah_counter.seq_number)
				vrrp->ipsecah_counter.cycle = false;
		}
#endif

		/*
		 * MUST verify that the Adver Interval in the packet is the same as
		 * the locally configured for this virtual router if VRRPv2
		 */
		if (vrrp->adver_int != hd->v2.adver_int * TIMER_HZ) {
			log_message(LOG_INFO, "(%s) advertisement interval mismatch mine=%d sec rcved=%d sec",
				vrrp->iname, vrrp->adver_int / TIMER_HZ, adver_int / TIMER_HZ);
			/* to prevent concurent VRID running => multiple master in 1 VRID */
			return VRRP_PACKET_DROP;
		}

	}

	/* MUST verify the VRRP version */
	if ((hd->vers_type >> 4) != vrrp->version) {
		log_message(LOG_INFO, "(%s) invalid version. %d and expect %d",
		       vrrp->iname, (hd->vers_type >> 4), vrrp->version);
#ifdef _WITH_SNMP_RFC_
		vrrp->stats->vers_err++;
#ifdef _WITH_SNMP_RFCV3_
		vrrp->stats->proto_err_reason = versionError;
		vrrp_rfcv3_snmp_proto_err_notify(vrrp);
#endif
#endif
		return VRRP_PACKET_KO;
	}

	/* verify packet type */
	if ((hd->vers_type & 0x0f) != VRRP_PKT_ADVERT) {
		log_message(LOG_INFO, "(%s) Invalid packet type. %d and expect %d",
			vrrp->iname, (hd->vers_type & 0x0f), VRRP_PKT_ADVERT);
		++vrrp->stats->invalid_type_rcvd;
		return VRRP_PACKET_KO;
	}

	/* MUST verify that the VRID is valid on the receiving interface_t */
	if (vrrp->vrid != hd->vrid) {
		log_message(LOG_INFO,
		       "(%s) received VRID mismatch. Received %d, Expected %d",
		       vrrp->iname, hd->vrid, vrrp->vrid);
#ifdef _WITH_SNMP_RFC_
		vrrp->stats->vrid_err++;
#ifdef _WITH_SNMP_RFCV3_
		vrrp->stats->proto_err_reason = vrIdError;
		vrrp_rfcv3_snmp_proto_err_notify(vrrp);
#endif
#endif
		return VRRP_PACKET_OTHER;
	}

	if ((LIST_ISEMPTY(vrrp->vip) && hd->naddr > 0) ||
	    (!LIST_ISEMPTY(vrrp->vip) && LIST_SIZE(vrrp->vip) != hd->naddr)) {
		log_message(LOG_INFO, "(%s) received an invalid ip number count %d, expected %d!",
			vrrp->iname, hd->naddr, LIST_ISEMPTY(vrrp->vip) ? 0 : LIST_SIZE(vrrp->vip));
		++vrrp->stats->addr_list_err;
		return VRRP_PACKET_KO;
	}

	if (vrrp->family == AF_INET && ntohs(ip->tot_len) != buflen) {
		log_message(LOG_INFO,
		       "(%s) ip_tot_len mismatch against received length. %d and received %zu",
		       vrrp->iname, ntohs(ip->tot_len), buflen);
		++vrrp->stats->packet_len_err;
		return VRRP_PACKET_KO;
	}

	if (expected_len != buflen) {
		log_message(LOG_INFO,
		       "(%s) Received packet length mismatch against expected. %zu and expect %zu",
		      vrrp->iname, buflen, expected_len);
		++vrrp->stats->packet_len_err;
		return VRRP_PACKET_KO;
	}

	/* MUST verify the VRRP checksum. Kernel takes care of checksum mismatch incase of IPv6. */
	if (vrrp->family == AF_INET) {
		vrrppkt_len = sizeof(vrrphdr_t) + hd->naddr * sizeof(struct in_addr);
		if (vrrp->version == VRRP_VERSION_3) {
			/* Create IPv4 pseudo-header */
			ipv4_phdr.src   = ip->saddr;
#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
			ipv4_phdr.dst   = vrrp->unicast_chksum_compat <= CHKSUM_COMPATIBILITY_MIN_COMPAT
					  ? ip->daddr : global_data->vrrp_mcast_group4.sin_addr.s_addr;
#else
			ipv4_phdr.dst	= ip->daddr;
#endif
			ipv4_phdr.zero  = 0;
			ipv4_phdr.proto = IPPROTO_VRRP;
			ipv4_phdr.len   = htons(vrrppkt_len);

			in_csum((uint16_t *) &ipv4_phdr, sizeof(ipv4_phdr), 0, &acc_csum);
			if (in_csum((uint16_t *) hd, vrrppkt_len, acc_csum, NULL)) {
#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
				chksum_error = true;
				if (!LIST_ISEMPTY(vrrp->unicast_peer) &&
				    vrrp->unicast_chksum_compat == CHKSUM_COMPATIBILITY_NONE &&
				    ipv4_phdr.dst != global_data->vrrp_mcast_group4.sin_addr.s_addr) {
					ipv4_phdr.dst = global_data->vrrp_mcast_group4.sin_addr.s_addr;
					in_csum((uint16_t *) &ipv4_phdr, sizeof(ipv4_phdr), 0, &acc_csum);
					if (!in_csum((uint16_t *)hd, vrrppkt_len, acc_csum, NULL)) {
						/* Update the checksum for the pseudo header IP address */
						vrrp_csum_mcast(vrrp);

						/* Now we can specify that we are going to use the compatibility mode */
						vrrp->unicast_chksum_compat = CHKSUM_COMPATIBILITY_AUTO;

						log_message(LOG_INFO, "(%s) Setting unicast VRRPv3 checksum to old version", vrrp->iname);
						chksum_error = false;
					}
				}

				if (chksum_error)
#endif
				{
					log_message(LOG_INFO, "(%s) Invalid VRRPv3 checksum", vrrp->iname);
#ifdef _WITH_SNMP_RFC_
					vrrp->stats->chk_err++;
#ifdef _WITH_SNMP_RFCV3_
					vrrp->stats->proto_err_reason = checksumError;
					vrrp_rfcv3_snmp_proto_err_notify(vrrp);
#endif
#endif
					return VRRP_PACKET_KO;
				}
			}
		} else {
			vrrppkt_len += VRRP_AUTH_LEN;
			if (in_csum((uint16_t *) hd, vrrppkt_len, 0, NULL)) {
				log_message(LOG_INFO, "(%s) Invalid VRRPv2 checksum", vrrp->iname);
#ifdef _WITH_SNMP_RFC_
				vrrp->stats->chk_err++;
#ifdef _WITH_SNMP_RFCV3_
				vrrp->stats->proto_err_reason = checksumError;
				vrrp_rfcv3_snmp_proto_err_notify(vrrp);
#endif
#endif
				return VRRP_PACKET_KO;
			}
		}
	}

	/* Correct type, version, and length. Count as VRRP advertisement */
	++vrrp->stats->advert_rcvd;

	/* pointer to vrrp vips pkt zone */
	vips = (unsigned char *) ((char *) hd + sizeof(vrrphdr_t));

	if (check_vip_addr) {
		if (vrrp->family == AF_INET) {
			if (!LIST_ISEMPTY(vrrp->vip)) {
				/*
				 * MAY verify that the IP address(es) associated with the
				 * VRID are valid
				 */
				for (e = LIST_HEAD(vrrp->vip); e; ELEMENT_NEXT(e)) {
					ipaddress = ELEMENT_DATA(e);
					if (!vrrp_in_chk_vips(vrrp, ipaddress, vips)) {
						log_message(LOG_INFO, "(%s) ip address associated with VRID %d"
						       " not present in MASTER advert : %s",
						       vrrp->iname, vrrp->vrid,
						       inet_ntop2(ipaddress->u.sin.sin_addr.s_addr));
						++vrrp->stats->addr_list_err;
						return VRRP_PACKET_KO;
					}
				}
			}

			/* check a unicast source address is in the unicast_peer list */
			if (global_data->vrrp_check_unicast_src && !LIST_ISEMPTY(vrrp->unicast_peer)) {
				for (e = LIST_HEAD(vrrp->unicast_peer); e; ELEMENT_NEXT(e)) {
					up_addr = ELEMENT_DATA(e);
					if (((struct sockaddr_in *)&vrrp->pkt_saddr)->sin_addr.s_addr == ((struct sockaddr_in *)up_addr)->sin_addr.s_addr)
						break;
				}
				if (!e) {
					log_message(LOG_INFO, "(%s) unicast source address %s not a unicast peer",
						vrrp->iname, inet_ntop2(((struct sockaddr_in*)&vrrp->pkt_saddr)->sin_addr.s_addr));
					return VRRP_PACKET_KO;
				}
			}
		} else {	/* IPv6 */
			if (!LIST_ISEMPTY(vrrp->vip)) {
				/*
				 * MAY verify that the IP address(es) associated with the
				 * VRID are valid
				 */
				if (hd->naddr != LIST_SIZE(vrrp->vip)) {
					log_message(LOG_INFO,
						"(%s) receive an invalid ip number count associated with VRID!", vrrp->iname);
					++vrrp->stats->addr_list_err;
					return VRRP_PACKET_KO;
				}

				for (e = LIST_HEAD(vrrp->vip); e; ELEMENT_NEXT(e)) {
					ipaddress = ELEMENT_DATA(e);
					if (!vrrp_in_chk_vips(vrrp, ipaddress, vips)) {
						log_message(LOG_INFO, "(%s) ip address associated with VRID %d"
							    " not present in MASTER advert : %s",
							    vrrp->iname, vrrp->vrid,
							    inet_ntop(AF_INET6, &ipaddress->u.sin6_addr,
							    addr_str, sizeof(addr_str)));
						++vrrp->stats->addr_list_err;
						return VRRP_PACKET_KO;
					}
				}
			}

			/* check a unicast source address is in the unicast_peer list */
			if (global_data->vrrp_check_unicast_src && !LIST_ISEMPTY(vrrp->unicast_peer)) {
				for (e = LIST_HEAD(vrrp->unicast_peer); e; ELEMENT_NEXT(e)) {
					up_addr = ELEMENT_DATA(e);
					if (IN6_ARE_ADDR_EQUAL(&((struct sockaddr_in6 *)&vrrp->pkt_saddr)->sin6_addr, &((struct sockaddr_in6 *)up_addr)->sin6_addr))
						break;
				}
				if (!e) {
					log_message(LOG_INFO, "(%s) unicast source address %s not a unicast peer",
						vrrp->iname, inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&vrrp->pkt_saddr)->sin6_addr,
							    addr_str, sizeof(addr_str)));
					return VRRP_PACKET_KO;
				}
			}
		}
	}

	if (hd->priority == 0)
		++vrrp->stats->pri_zero_rcvd;

	if (vrrp->version == VRRP_VERSION_3 && vrrp->state == VRRP_STATE_BACK) {
// TODO - is this the right place to do this? - Probably not, do it below
		/* In v3 when we are in BACKUP state, we set our
		 * advertisement interval to match the MASTER's. */
		adver_int = (ntohs(hd->v3.adver_int) & 0x0FFF) * TIMER_CENTI_HZ;
		if (vrrp->master_adver_int != adver_int) {
			log_message(LOG_INFO, "(%s) advertisement interval changed: mine=%d milli-sec, rcved=%d milli-sec",
				vrrp->iname, vrrp->master_adver_int / (TIMER_HZ / 1000), adver_int / (TIMER_HZ / 1000));
		}
	}

	return VRRP_PACKET_OK;
}

/* build IP header */
static void
vrrp_build_ip4(vrrp_t *vrrp, char *buffer)
{
	struct iphdr *ip = (struct iphdr *) (buffer);

	ip->ihl = sizeof(struct iphdr) >> 2;
	ip->version = 4;
	/* set tos to internet network control */
	ip->tos = 0xc0;
	ip->tot_len = (uint16_t)(sizeof (struct iphdr) + vrrp_pkt_len(vrrp));
	ip->tot_len = htons(ip->tot_len);
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = VRRP_IP_TTL;

	/* fill protocol type --rfc2402.2 */
#ifdef _WITH_VRRP_AUTH_
	ip->protocol = (vrrp->auth_type == VRRP_AUTH_AH) ? IPPROTO_AH : IPPROTO_VRRP;
#else
	ip->protocol = IPPROTO_VRRP;
#endif

	ip->saddr = VRRP_PKT_SADDR(vrrp);

	/* If using unicast peers, pick the first one */
	if (!LIST_ISEMPTY(vrrp->unicast_peer)) {
		struct sockaddr_storage* addr = ELEMENT_DATA(LIST_HEAD(vrrp->unicast_peer));
		ip->daddr = inet_sockaddrip4(addr);
	}
	else
		ip->daddr = global_data->vrrp_mcast_group4.sin_addr.s_addr;

	ip->check = 0;
}

#ifdef _WITH_VRRP_AUTH_
/* build IPSEC AH header */
static void
vrrp_build_ipsecah(vrrp_t * vrrp, char *buffer, size_t buflen)
{
	unsigned char digest[MD5_DIGEST_LENGTH];
	struct iphdr *ip = (struct iphdr *) (buffer);
	ipsec_ah_t *ah = (ipsec_ah_t *) (buffer + sizeof (struct iphdr));

	/* fill in next header filed --rfc2402.2.1 */
	ah->next_header = IPPROTO_VRRP;

	/* update IP header total length value */
	ip->tot_len = htons(ntohs(ip->tot_len) + vrrp_ipsecah_len());

	/* fill in the Payload len field */
	ah->payload_len = IPSEC_AH_PLEN;

	/* The SPI value is filled with the ip header source address.
	   SPI uniquely identify the Security Association (SA). This value
	   is chosen by the recipient itself when setting up the SA. In a
	   multicast environment, this becomes unfeasible.

	   If left to the sender, the choice of the SPI value should be done
	   so by the sender that it cannot possibly conflict with SPI values
	   chosen by other entities sending IPSEC traffic to any of the receivers.
	   To overpass this problem, the rule I have chosen to implement here is
	   that the SPI value chosen by the sender is based on unique information
	   such as its IP address.
	   -- INTERNET draft : <draft-paridaens-xcast-sec-framework-01.txt>
	 */
	ah->spi = ip->saddr;

	/* Compute the ICV & trunc the digest to 96bits
	   => No padding needed.
	   -- rfc2402.3.3.3.1.1.1 & rfc2401.5
	 */
	hmac_md5((unsigned char *) buffer, buflen, vrrp->auth_data, sizeof (vrrp->auth_data), digest);
	memcpy(ah->auth_data, digest, HMAC_MD5_TRUNC);
}
#endif

/* build VRRPv2 header */
static void
vrrp_build_vrrp_v2(vrrp_t *vrrp, char *buffer)
{
	int i = 0;
	vrrphdr_t *hd = (vrrphdr_t *) buffer;
	struct in_addr *iparr;
	struct in6_addr *ip6arr;
	element e;
	ip_address_t *ip_addr;

	/* Family independant */
	hd->vers_type = (VRRP_VERSION_2 << 4) | VRRP_PKT_ADVERT;
	hd->vrid = vrrp->vrid;
	hd->priority = vrrp->effective_priority;
	hd->naddr = (uint8_t)((!LIST_ISEMPTY(vrrp->vip)) ? (uint8_t)LIST_SIZE(vrrp->vip) : 0);
#ifdef _WITH_VRRP_AUTH_
	hd->v2.auth_type = vrrp->auth_type;
#else
	hd->v2.auth_type = VRRP_AUTH_NONE;
#endif
	hd->v2.adver_int = (uint8_t)(vrrp->adver_int / TIMER_HZ);

	/* Family specific */
	if (vrrp->family == AF_INET) {
		/* copy the ip addresses */
		iparr = (struct in_addr *) ((char *) hd + sizeof (*hd));
		if (!LIST_ISEMPTY(vrrp->vip)) {
			for (e = LIST_HEAD(vrrp->vip); e; ELEMENT_NEXT(e)) {
				ip_addr = ELEMENT_DATA(e);
				iparr[i++] = ip_addr->u.sin.sin_addr;
			}
		}

#ifdef _WITH_VRRP_AUTH_
		/* copy the passwd if the authentication is VRRP_AH_PASS */
		if (vrrp->auth_type == VRRP_AUTH_PASS) {
			unsigned vip_count = (!LIST_ISEMPTY(vrrp->vip)) ? LIST_SIZE(vrrp->vip) : 0;
			char *pw = (char *) hd + sizeof (*hd) + vip_count * 4;
			memcpy(pw, vrrp->auth_data, sizeof (vrrp->auth_data));
		}
#endif

		/* finally compute vrrp checksum */
		hd->chksum = 0;
		hd->chksum = in_csum((uint16_t *)hd, vrrp_pkt_len(vrrp), 0, NULL);
	} else if (vrrp->family == AF_INET6) {
		ip6arr = (struct in6_addr *)((char *) hd + sizeof(*hd));
		if (!LIST_ISEMPTY(vrrp->vip)) {
			for (e = LIST_HEAD(vrrp->vip); e; ELEMENT_NEXT(e)) {
				ip_addr = ELEMENT_DATA(e);
				ip6arr[i++] = ip_addr->u.sin6_addr;
			}
		}
		/* Kernel will update checksum field. let it be 0 now. */
		hd->chksum = 0;
	}
}

/* build VRRPv3 header */
static void
vrrp_build_vrrp_v3(vrrp_t *vrrp, char *buffer, struct iphdr *ip)
{
	int i = 0;
	vrrphdr_t *hd = (vrrphdr_t *) buffer;
	struct in_addr *iparr;
	struct in6_addr *ip6arr;
	element e;
	ip_address_t *ip_addr;
	ipv4_phdr_t ipv4_phdr;

	/* Family independant */
	hd->vers_type = (VRRP_VERSION_3 << 4) | VRRP_PKT_ADVERT;
	hd->vrid = vrrp->vrid;
	hd->priority = vrrp->effective_priority;
	hd->naddr = (uint8_t)((!LIST_ISEMPTY(vrrp->vip)) ? LIST_SIZE(vrrp->vip) : 0);
	hd->v3.adver_int  = htons((vrrp->adver_int / TIMER_CENTI_HZ) & 0x0FFF); /* interval in centiseconds, reserved bits zero */

	/* For IPv4 to calculate the checksum, the value must start as 0.
	 * For IPv6, the kernel will update checksum field. */
	hd->chksum = 0;

	/* Family specific */
	if (vrrp->family == AF_INET) {
		/* copy the ip addresses */
		iparr = (struct in_addr *) ((char *) hd + sizeof(*hd));
		LIST_FOREACH(vrrp->vip, ip_addr, e)
			iparr[i++] = ip_addr->u.sin.sin_addr;

		/* Create IPv4 pseudo-header */
		ipv4_phdr.src   = VRRP_PKT_SADDR(vrrp);
#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
		if (vrrp->unicast_chksum_compat >= CHKSUM_COMPATIBILITY_MIN_COMPAT)
			ipv4_phdr.dst = global_data->vrrp_mcast_group4.sin_addr.s_addr;
		else
#endif
			ipv4_phdr.dst = ip->daddr;
		ipv4_phdr.zero  = 0;
		ipv4_phdr.proto = IPPROTO_VRRP;
		ipv4_phdr.len   = htons(vrrp_pkt_len(vrrp));

		/* finally compute vrrp checksum */
		in_csum((uint16_t *)&ipv4_phdr, sizeof(ipv4_phdr), 0, &vrrp->ipv4_csum);
		hd->chksum = in_csum((uint16_t *) hd, vrrp_pkt_len(vrrp), vrrp->ipv4_csum, NULL);
	} else if (vrrp->family == AF_INET6) {
		ip6arr = (struct in6_addr *)((char *) hd + sizeof(*hd));
		if (!LIST_ISEMPTY(vrrp->vip)) {
			for (e = LIST_HEAD(vrrp->vip); e; ELEMENT_NEXT(e)) {
				ip_addr = ELEMENT_DATA(e);
				ip6arr[i++] = ip_addr->u.sin6_addr;
			}
		}
	}
}

/* build VRRP header */
static void
vrrp_build_vrrp(vrrp_t *vrrp, char *buffer, struct iphdr *ip_hdr)
{
	if (vrrp->version == VRRP_VERSION_3)
		vrrp_build_vrrp_v3(vrrp, buffer, ip_hdr);
	else
		vrrp_build_vrrp_v2(vrrp, buffer);
}

/* build VRRP packet */
static void
vrrp_build_pkt(vrrp_t * vrrp)
{
	char *bufptr;

	if (vrrp->family == AF_INET) {
		/* save reference values */
		bufptr = vrrp->send_buffer;

		/* build the ip header */
		vrrp_build_ip4(vrrp, vrrp->send_buffer);

		/* build the vrrp header */
		bufptr += vrrp_iphdr_len();

#ifdef _WITH_VRRP_AUTH_
		if (vrrp->auth_type == VRRP_AUTH_AH)
			bufptr += vrrp_ipsecah_len();
#endif
		vrrp_build_vrrp(vrrp, bufptr, (struct iphdr *)vrrp->send_buffer);

#ifdef _WITH_VRRP_AUTH_
		/* build the IPSEC AH header */
		if (vrrp->auth_type == VRRP_AUTH_AH)
			vrrp_build_ipsecah(vrrp, vrrp->send_buffer, vrrp->send_buffer_size);
#endif
	}
	else if (vrrp->family == AF_INET6)
		vrrp_build_vrrp(vrrp, vrrp->send_buffer, NULL);
}

/* send VRRP packet */
static int
vrrp_build_ancillary_data(struct msghdr *msg, char *cbuf, struct sockaddr_storage *src, const vrrp_t *vrrp)
{
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pkt;

	if (src->ss_family != AF_INET6)
		return -1;

	msg->msg_control = cbuf;
	msg->msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

	cmsg = CMSG_FIRSTHDR(msg);
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

	pkt = (struct in6_pktinfo *) CMSG_DATA(cmsg);
	memset(pkt, 0, sizeof(struct in6_pktinfo));
	pkt->ipi6_addr = ((struct sockaddr_in6 *) src)->sin6_addr;
#ifdef _HAVE_VRRP_VMAC_
	if (__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags))
		pkt->ipi6_ifindex = vrrp->ifp->base_ifp->ifindex;
	else
#endif
		pkt->ipi6_ifindex = vrrp->ifp->ifindex;

	return 0;
}

static ssize_t
vrrp_send_pkt(vrrp_t * vrrp, struct sockaddr_storage *addr)
{
	struct sockaddr_storage *src = &vrrp->saddr;
	struct msghdr msg;
	struct iovec iov;
	char cbuf[256];

	/* Build the message data */
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = vrrp->send_buffer;
	iov.iov_len = vrrp->send_buffer_size;

	/* Unicast sending path */
	if (addr && addr->ss_family == AF_INET) {
		msg.msg_name = addr;
		msg.msg_namelen = sizeof(struct sockaddr_in);
	} else if (addr && addr->ss_family == AF_INET6) {
		msg.msg_name = addr;
		msg.msg_namelen = sizeof(struct sockaddr_in6);
		vrrp_build_ancillary_data(&msg, cbuf, src, vrrp);
	} else if (vrrp->family == AF_INET) { /* Multicast sending path */
		msg.msg_name = &global_data->vrrp_mcast_group4;
		msg.msg_namelen = sizeof(struct sockaddr_in);
	} else if (vrrp->family == AF_INET6) {
		msg.msg_name = &global_data->vrrp_mcast_group6;
		msg.msg_namelen = sizeof(struct sockaddr_in6);
		vrrp_build_ancillary_data(&msg, cbuf, src, vrrp);
	}

	/* Send the packet */
	return sendmsg(vrrp->sockets->fd_out, &msg, (addr) ? 0 : MSG_DONTROUTE);
}

/* Allocate the sending buffer */
static void
vrrp_alloc_send_buffer(vrrp_t * vrrp)
{
	vrrp->send_buffer_size = vrrp_adv_len(vrrp);

	vrrp->send_buffer = MALLOC(vrrp->send_buffer_size);
}

/* send VRRP advertisement */
void
vrrp_send_adv(vrrp_t * vrrp, uint8_t prio)
{
	struct sockaddr_storage *addr;
	element e;

	/* build the packet */
	vrrp_update_pkt(vrrp, prio, NULL);

	if (LIST_ISEMPTY(vrrp->unicast_peer))
		vrrp_send_pkt(vrrp, NULL);
	else {
		LIST_FOREACH(vrrp->unicast_peer, addr, e) {
			if (vrrp->family == AF_INET)
				vrrp_update_pkt(vrrp, prio, addr);
			if (vrrp_send_pkt(vrrp, addr) < 0)
				log_message(LOG_INFO, "(%s) Cant send advert to %s (%m)"
						    , vrrp->iname, inet_sockaddrtos(addr));
		}
	}

	++vrrp->stats->advert_sent;
}

/* Received packet processing */
static int
vrrp_check_packet(vrrp_t * vrrp, char *buf, ssize_t buflen, bool check_vip_addr)
{
	if (!buflen)
		return VRRP_PACKET_NULL;

	return vrrp_in_chk(vrrp, buf, buflen, check_vip_addr);
}

/* Gratuitous ARP on each VIP */
static void
vrrp_send_update(vrrp_t * vrrp, ip_address_t * ipaddress, bool log_msg)
{
	char *msg;
	char addr_str[INET6_ADDRSTRLEN];

	if (!IP_IS6(ipaddress))
		send_gratuitous_arp(vrrp, ipaddress);
	else
		ndisc_send_unsolicited_na(vrrp, ipaddress);

	if (log_msg && __test_bit(LOG_DETAIL_BIT, &debug)) {
		if (!IP_IS6(ipaddress)) {
			msg = "gratuitous ARPs";
			inet_ntop(AF_INET, &ipaddress->u.sin.sin_addr, addr_str, sizeof(addr_str));
		} else {
			msg = "Unsolicited Neighbour Adverts";
			inet_ntop(AF_INET6, &ipaddress->u.sin6_addr, addr_str, sizeof(addr_str));
		}

		log_message(LOG_INFO, "(%s) Sending/queueing %s on %s for %s",
			    vrrp->iname, msg, IF_NAME(ipaddress->ifp), addr_str);
	}
}

void
vrrp_send_link_update(vrrp_t * vrrp, unsigned rep)
{
	unsigned j;
	ip_address_t *ipaddress;
	element e;

	/* Only send gratuitous ARP if VIP are set */
	if (!VRRP_VIP_ISSET(vrrp))
		return;

	/* If the interface doesn't support ARP, then don't send
	 * any ARP messages. */
	if (vrrp->ifp->ifi_flags & IFF_NOARP)
		return;

	/* send gratuitous arp for each virtual ip */
	for (j = 0; j < rep; j++) {
		if (!LIST_ISEMPTY(vrrp->vip)) {
			for (e = LIST_HEAD(vrrp->vip); e; ELEMENT_NEXT(e)) {
				ipaddress = ELEMENT_DATA(e);
				vrrp_send_update(vrrp, ipaddress, !j);
			}
		}

		if (!LIST_ISEMPTY(vrrp->evip)) {
			for (e = LIST_HEAD(vrrp->evip); e; ELEMENT_NEXT(e)) {
				ipaddress = ELEMENT_DATA(e);
				vrrp_send_update(vrrp, ipaddress, !j);
			}
		}
	}
}

static void
vrrp_remove_delayed_arp(vrrp_t *vrrp)
{
	ip_address_t *ipaddress;
	element e;

	if (!LIST_ISEMPTY(vrrp->vip)) {
		for (e = LIST_HEAD(vrrp->vip); e; ELEMENT_NEXT(e)) {
			ipaddress = ELEMENT_DATA(e);
			ipaddress->garp_gna_pending = false;
		}
	}

	if (!LIST_ISEMPTY(vrrp->evip)) {
		for (e = LIST_HEAD(vrrp->evip); e; ELEMENT_NEXT(e)) {
			ipaddress = ELEMENT_DATA(e);
			ipaddress->garp_gna_pending = false;
		}
	}
	vrrp->garp_pending = false;
	vrrp->gna_pending = false;
}

/* becoming master */
static void
vrrp_state_become_master(vrrp_t * vrrp)
{
	interface_t *ifp ;

	++vrrp->stats->become_master;

	if (vrrp->version == VRRP_VERSION_3)
		log_message(LOG_INFO, "(%s) using locally configured advertisement interval (%d milli-sec)",
					vrrp->iname, vrrp->adver_int / (TIMER_HZ / 1000));

	/* add the ip addresses */
	vrrp_handle_accept_mode(vrrp, IPADDRESS_ADD, false);
	if (!LIST_ISEMPTY(vrrp->vip))
		vrrp_handle_ipaddress(vrrp, IPADDRESS_ADD, VRRP_VIP_TYPE, false);
	if (!LIST_ISEMPTY(vrrp->evip))
		vrrp_handle_ipaddress(vrrp, IPADDRESS_ADD, VRRP_EVIP_TYPE, false);
	vrrp->vipset = 1;

#ifdef _HAVE_FIB_ROUTING_
	/* add virtual routes */
	if (!LIST_ISEMPTY(vrrp->vroutes))
		vrrp_handle_iproutes(vrrp, IPROUTE_ADD);

	/* add virtual rules */
	if (!LIST_ISEMPTY(vrrp->vrules))
		vrrp_handle_iprules(vrrp, IPRULE_ADD, false);
#endif

	kernel_netlink_poll();

	/* remotes neighbour update */
	if (vrrp->family == AF_INET6) {
		/* Refresh whether we are acting as a router for NA messages */
		ifp = IF_BASE_IFP(vrrp->ifp);
		ifp->gna_router = get_ipv6_forwarding(ifp);
	}
	vrrp_send_link_update(vrrp, vrrp->garp_rep);

	/* set refresh timer */
	if (timerisset(&vrrp->garp_refresh)) {
		vrrp->garp_refresh_timer = timer_add_now(vrrp->garp_refresh);
	}

	/* Check if notify is needed */
	send_instance_notifies(vrrp);

#ifdef _WITH_LVS_
	/* Check if sync daemon handling is needed */
	if (global_data->lvs_syncd.vrrp == vrrp)
		ipvs_syncd_master(&global_data->lvs_syncd);
#endif
	vrrp->last_transition = timer_now();
}

void
vrrp_state_goto_master(vrrp_t * vrrp)
{
	if (vrrp->sync && !vrrp_sync_can_goto_master(vrrp))
	{
		vrrp->wantstate = VRRP_STATE_MAST;
		return;
	}

#if defined _WITH_VRRP_AUTH_
	/* If becoming MASTER in IPSEC AH AUTH, we reset the anti-replay */
	if (vrrp->ipsecah_counter.cycle) {
		vrrp->ipsecah_counter.cycle = false;
		vrrp->ipsecah_counter.seq_number = 0;
	}
#endif

#ifdef _WITH_SNMP_RFCV3_
	vrrp->stats->master_reason = vrrp->stats->next_master_reason;
#endif

	vrrp->state = VRRP_STATE_MAST;
	vrrp_init_instance_sands(vrrp);
	vrrp_state_master_tx(vrrp);
}

/* leaving master state */
void
vrrp_restore_interface(vrrp_t * vrrp, bool advF, bool force)
{
	/* if we stop vrrp, warn the other routers to speed up the recovery */
	if (advF) {
		vrrp_send_adv(vrrp, VRRP_PRIO_STOP);
		++vrrp->stats->pri_zero_sent;
		log_message(LOG_INFO, "(%s) sent 0 priority", vrrp->iname);
	}

#ifdef _HAVE_FIB_ROUTING_
	/* remove virtual rules */
	if (!LIST_ISEMPTY(vrrp->vrules))
		vrrp_handle_iprules(vrrp, IPRULE_DEL, force);

	/* remove virtual routes */
	if (!LIST_ISEMPTY(vrrp->vroutes))
		vrrp_handle_iproutes(vrrp, IPROUTE_DEL);
#endif

	/* empty the delayed arp list */
	vrrp_remove_delayed_arp(vrrp);

	/*
	 * Remove the ip addresses.
	 *
	 * If started with "--dont-release-vrrp" then try to remove
	 * addresses even if we didn't add them during this run.
	 *
	 * If "--release-vips" is set then try to release any virtual addresses.
	 * kill -1 tells keepalived to reread its config.  If a config change
	 * (such as lower priority) causes a state transition to backup then
	 * keepalived doesn't remove the VIPs.  Then we have duplicate IP addresses
	 * on both master/backup.
	 */
	if (force ||
	    VRRP_VIP_ISSET(vrrp) ||
	    __test_bit(DONT_RELEASE_VRRP_BIT, &debug) ||
	    __test_bit(RELEASE_VIPS_BIT, &debug)) {
		if (!LIST_ISEMPTY(vrrp->vip))
			vrrp_handle_ipaddress(vrrp, IPADDRESS_DEL, VRRP_VIP_TYPE, force);
		if (!LIST_ISEMPTY(vrrp->evip))
			vrrp_handle_ipaddress(vrrp, IPADDRESS_DEL, VRRP_EVIP_TYPE, force);
		vrrp_handle_accept_mode(vrrp, IPADDRESS_DEL, force);
		vrrp->vipset = 0;
	}
}

void
vrrp_state_leave_master(vrrp_t * vrrp, bool advF)
{
#ifdef _WITH_LVS_
	if (VRRP_VIP_ISSET(vrrp)) {
		/* Check if sync daemon handling is needed */
		if (global_data->lvs_syncd.vrrp == vrrp)
			ipvs_syncd_backup(&global_data->lvs_syncd);
	}
#endif

	/* set the new vrrp state */
	if (vrrp->wantstate == VRRP_STATE_BACK) {
		log_message(LOG_INFO, "(%s) Entering BACKUP STATE", vrrp->iname);
		vrrp->preempt_time.tv_sec = 0;
// TODO - if we are called due to receiving a higher priority advert, do we overwrite master adver int ?
		vrrp->master_adver_int = vrrp->adver_int;
	}
	else if (vrrp->wantstate == VRRP_STATE_FAULT) {
		log_message(LOG_INFO, "(%s) Entering FAULT STATE", vrrp->iname);
		vrrp_send_adv(vrrp, VRRP_PRIO_STOP);
	}
	else {
		log_message(LOG_INFO, "(%s) vrrp_state_leave_master called with invalid wantstate %d", vrrp->iname, vrrp->wantstate);
		return;
	}

	vrrp_restore_interface(vrrp, advF, false);
	vrrp->state = vrrp->wantstate;

	send_instance_notifies(vrrp);

	/* Set the down timer */
	vrrp->ms_down_timer = 3 * vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);
	vrrp_init_instance_sands(vrrp);
	++vrrp->stats->release_master;
	vrrp->last_transition = timer_now();
}

void
vrrp_state_leave_fault(vrrp_t * vrrp)
{
	/* set the new vrrp state */
	if (vrrp->wantstate == VRRP_STATE_MAST)
		vrrp_state_goto_master(vrrp);
	else {
		log_message(LOG_INFO, "(%s) Entering %s STATE", vrrp->iname, vrrp->wantstate == VRRP_STATE_BACK ? "BACKUP" : "FAULT");
		if (vrrp->wantstate == VRRP_STATE_FAULT && vrrp->state == VRRP_STATE_MAST) {
			vrrp_send_adv(vrrp, VRRP_PRIO_STOP);
			vrrp_restore_interface(vrrp, false, false);
		}
		vrrp->state = vrrp->wantstate;
		send_instance_notifies(vrrp);

		if (vrrp->state == VRRP_STATE_BACK) {
			vrrp->preempt_time.tv_sec = 0;
			vrrp->master_adver_int = vrrp->adver_int;
		}
	}

	/* Set the down timer */
	vrrp->master_adver_int = vrrp->adver_int;
	vrrp->ms_down_timer = 3 * vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);
	vrrp_init_instance_sands(vrrp);
	vrrp->last_transition = timer_now();
}

/* BACKUP state processing */
void
vrrp_state_backup(vrrp_t * vrrp, char *buf, ssize_t buflen)
{
	vrrphdr_t *hd;
	ssize_t ret = 0;
	unsigned master_adver_int, proto;
	bool check_addr = false;
	timeval_t new_ms_down_timer;
	bool ignore_advert = false;

	/* Process the incoming packet */
	hd = vrrp_get_header(vrrp->family, buf, &proto);
	if (!vrrp->skip_check_adv_addr ||
	    vrrp->master_saddr.ss_family != vrrp->pkt_saddr.ss_family)
		check_addr = true;
	else {
		/* Check if the addresses are different */
		if (vrrp->pkt_saddr.ss_family == AF_INET) {
			if (((struct sockaddr_in*)&vrrp->pkt_saddr)->sin_addr.s_addr != ((struct sockaddr_in*)&vrrp->master_saddr)->sin_addr.s_addr)
				check_addr = true ;
		} else {
			if (!IN6_ARE_ADDR_EQUAL(&((struct sockaddr_in6*)&vrrp->pkt_saddr)->sin6_addr, &((struct sockaddr_in6*)&vrrp->master_saddr)->sin6_addr))
				check_addr = true;
		}
	}
	ret = vrrp_check_packet(vrrp, buf, buflen, check_addr);

	if (ret != VRRP_PACKET_OK)
		ignore_advert = true;
	else if (hd->priority == 0) {
		log_message(LOG_INFO, "(%s) Backup received priority 0 advertisement", vrrp->iname);
		vrrp->ms_down_timer = VRRP_TIMER_SKEW(vrrp);
#ifdef _WITH_SNMP_RFCV3_
		vrrp->stats->next_master_reason = VRRPV3_MASTER_REASON_PRIORITY;
#endif
	} else if (vrrp->nopreempt ||
		   hd->priority >= vrrp->effective_priority ||
		   (vrrp->preempt_delay &&
		    (!vrrp->preempt_time.tv_sec ||
		     timercmp(&vrrp->preempt_time, &time_now, >)))) {
// TODO - why all the above checks - in particular what would preempt_time == 0 && preempt_delay mean?
		if (vrrp->version == VRRP_VERSION_3) {
			master_adver_int = (ntohs(hd->v3.adver_int) & 0x0FFF) * TIMER_CENTI_HZ;
			/* As per RFC5798, set Master_Adver_Interval to Adver Interval contained
			 * in the ADVERTISEMENT
			 */
			if (vrrp->master_adver_int != master_adver_int) {
				log_message(LOG_INFO, "(%s) advertisement interval updated to %d milli-sec from %d milli-sec",
						vrrp->iname, master_adver_int / (TIMER_HZ / 1000), vrrp->master_adver_int / (TIMER_HZ / 1000));
				vrrp->master_adver_int = master_adver_int;
			}
		}
		vrrp->ms_down_timer = 3 * vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);
		vrrp->master_saddr = vrrp->pkt_saddr;
		vrrp->master_priority = hd->priority;

#ifdef _WITH_SNMP_RFCV3_
		vrrp->stats->next_master_reason = VRRPV3_MASTER_REASON_MASTER_NO_RESPONSE;
#endif
		if (vrrp->preempt_delay) {
			if (hd->priority >= vrrp->effective_priority) {
				if (vrrp->preempt_time.tv_sec) {
					log_message(LOG_INFO,
						"%s(%s) stop preempt delay",
						"VRRP_Instance", vrrp->iname);
					vrrp->preempt_time.tv_sec = 0;
				}
			} else if (!vrrp->preempt_time.tv_sec) {
				log_message(LOG_INFO,
					"%s(%s) start preempt delay(%ld)",
					"VRRP_Instance", vrrp->iname,
					vrrp->preempt_delay / TIMER_HZ);
				vrrp->preempt_time = timer_add_long(timer_now(), vrrp->preempt_delay);
			}
		}
	} else {
		/* !nopreempt and lower priority advert and any preempt delay timer has expired */
		log_message(LOG_INFO, "(%s) received lower priority (%d) advert from %s - discarding", vrrp->iname, hd->priority, inet_sockaddrtos(&vrrp->pkt_saddr));

		ignore_advert = true;

#ifdef _WITH_SNMP_RFCV3_
		vrrp->stats->next_master_reason = VRRPV3_MASTER_REASON_PREEMPTED;
#endif

		/* We still want to record the master's address for SNMP purposes */
		vrrp->master_saddr = vrrp->pkt_saddr;
	}

	if (ignore_advert) {
		/* We need to reduce the down timer since we have ignored the advert */
		set_time_now();
		timersub(&vrrp->sands, &time_now, &new_ms_down_timer);
		vrrp->ms_down_timer = new_ms_down_timer.tv_sec < 0 ? 0 : (uint32_t)(new_ms_down_timer.tv_sec * TIMER_HZ + new_ms_down_timer.tv_usec);
	}
}

/* MASTER state processing */
void
vrrp_state_master_tx(vrrp_t * vrrp)
{
	if (!VRRP_VIP_ISSET(vrrp)) {
		log_message(LOG_INFO, "(%s) Entering MASTER STATE"
				    , vrrp->iname);
		vrrp_state_become_master(vrrp);
		/*
		 * If we catch the master transition
		 * register a gratuitous arp thread delayed to garp_delay secs.
		 */
		if (vrrp->garp_delay)
			thread_add_timer(master, vrrp_gratuitous_arp_thread,
					 vrrp, vrrp->garp_delay);
	} else if (timerisset(&vrrp->garp_refresh) &&
		   timercmp(&time_now, &vrrp->garp_refresh_timer, >)) {
		vrrp_send_link_update(vrrp, vrrp->garp_refresh_rep);
		vrrp->garp_refresh_timer = timer_add_now(vrrp->garp_refresh);
	}

	vrrp_send_adv(vrrp, vrrp->effective_priority);
}

static int
vrrp_saddr_cmp(struct sockaddr_storage *addr, vrrp_t *vrrp)
{
	interface_t *ifp = vrrp->ifp;

	/* Simple sanity */
	if (vrrp->saddr.ss_family && addr->ss_family != vrrp->saddr.ss_family)
		return 0;

	/* Configured source IP address */
	if (vrrp->saddr.ss_family)
		return inet_sockaddrcmp(addr, &vrrp->saddr);

	/* Default interface source IP address */
	if (addr->ss_family == AF_INET)
		return inet_inaddrcmp(addr->ss_family,
				      &((struct sockaddr_in *) addr)->sin_addr,
				      &ifp->sin_addr);
	if (addr->ss_family == AF_INET6)
		return inet_inaddrcmp(addr->ss_family,
				      &((struct sockaddr_in6 *) addr)->sin6_addr,
				      &ifp->sin6_addr);
	return 0;
}

// TODO Return true to leave master state, false to remain master
// TODO check all uses of master_adver_int (and simplify for VRRPv2)
// TODO check all uses of effective_priority
// TODO wantstate must be >= state
// TODO SKEW_TIME should use master_adver_int USUALLY!!!
// TODO check all use of ipsecah_counter, including cycle, and when we set seq_number
bool
vrrp_state_master_rx(vrrp_t * vrrp, char *buf, ssize_t buflen)
{
	vrrphdr_t *hd;
	ssize_t ret;
	unsigned proto = 0;
#ifdef _WITH_VRRP_AUTH_
	ipsec_ah_t *ah;
#endif
	unsigned master_adver_int;
	int addr_cmp;

// TODO - could we get here with wantstate == FAULT and STATE != FAULT?
	/* return on link failure */
// TODO - not needed???
	if (vrrp->wantstate == VRRP_STATE_FAULT) {
		vrrp->master_adver_int = vrrp->adver_int;
		vrrp->ms_down_timer = 3 * vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);
		vrrp->state = VRRP_STATE_FAULT;
		send_instance_notifies(vrrp);
		vrrp->last_transition = timer_now();
		return true;
	}

	/* Process the incoming packet */
	hd = vrrp_get_header(vrrp->family, buf, &proto);
	ret = vrrp_check_packet(vrrp, buf, buflen, true);

	if (ret != VRRP_PACKET_OK)
		return false;

	addr_cmp = vrrp_saddr_cmp(&vrrp->pkt_saddr, vrrp);

	if (hd->priority == 0 ||
	    (vrrp->higher_prio_send_advert &&
	     (hd->priority > vrrp->effective_priority ||
	      (hd->priority == vrrp->effective_priority && addr_cmp > 0)))) {
		log_message(LOG_INFO, "(%s) Master received priority 0 message", vrrp->iname);
		vrrp_send_adv(vrrp, vrrp->effective_priority);

		if (hd->priority == 0)
			return false;
	}

	if (hd->priority == vrrp->effective_priority) {
		if (addr_cmp == 0)
			log_message(LOG_INFO, "(%s) WARNING - equal priority advert received from remote host with our IP address.", vrrp->iname);
		else if (vrrp->effective_priority == VRRP_PRIO_OWNER) {
			/* If we are configured as the address owner (priority == 255), and we receive an advertisement
			 * from another system indicating it is also the address owner, then there is a clear conflict.
			 * Report a configuration error, and drop our priority as a workaround. */
			log_message(LOG_INFO, "(%s) CONFIGURATION ERROR: local instance and a remote instance are both configured as address owner, please fix - reducing local priority", vrrp->iname);
			vrrp->effective_priority = VRRP_PRIO_OWNER - 1;
			vrrp->base_priority = VRRP_PRIO_OWNER - 1;
		}
	}

	if (hd->priority < vrrp->effective_priority ||
	    (hd->priority == vrrp->effective_priority &&
	     addr_cmp < 0)) {
		/* We receive a lower prio adv we just refresh remote ARP cache */
		log_message(LOG_INFO, "(%s) Received advert from %s with lower priority %d, ours %d%s",
					vrrp->iname,
					inet_sockaddrtos(&vrrp->pkt_saddr),
					hd->priority,
					vrrp->effective_priority,
					!vrrp->lower_prio_no_advert ? ", forcing new election" : "");
#ifdef _WITH_VRRP_AUTH_
		if (proto == IPPROTO_AH) {
			ah = (ipsec_ah_t *) (buf + sizeof(struct iphdr));
			log_message(LOG_INFO, "(%s) IPSEC-AH : Syncing seq_num"
					      " - Increment seq"
					    , vrrp->iname);
// TODO - why is seq_number taken from lower priority advert?
			vrrp->ipsecah_counter.seq_number = ntohl(ah->seq_number) + 1;
			vrrp->ipsecah_counter.cycle = false;
		}
#endif
		if (!vrrp->lower_prio_no_advert)
			vrrp_send_adv(vrrp, vrrp->effective_priority);
		if (vrrp->garp_lower_prio_rep) {
			vrrp_send_link_update(vrrp, vrrp->garp_lower_prio_rep);
			if (vrrp->garp_lower_prio_delay)
				thread_add_timer(master, vrrp_lower_prio_gratuitous_arp_thread,
						 vrrp, vrrp->garp_lower_prio_delay);
		}
		return false;
	}

	if (hd->priority > vrrp->effective_priority ||
	    (hd->priority == vrrp->effective_priority && addr_cmp > 0)) {
		if (hd->priority > vrrp->effective_priority)
			log_message(LOG_INFO, "(%s) Master received advert from %s with higher priority %d, ours %d",
						vrrp->iname,
						inet_sockaddrtos(&vrrp->pkt_saddr),
						hd->priority,
						vrrp->effective_priority);
		else
			log_message(LOG_INFO, "(%s) Master received advert from %s with same priority %d but higher IP address than ours",
						vrrp->iname,
						inet_sockaddrtos(&vrrp->pkt_saddr),
						hd->priority);
#ifdef _WITH_VRRP_AUTH_
		if (proto == IPPROTO_AH) {
			ah = (ipsec_ah_t *) (buf + sizeof(struct iphdr));
			vrrp->ipsecah_counter.cycle = false;
		}
#endif

		if (vrrp->version == VRRP_VERSION_3) {
			master_adver_int = (ntohs(hd->v3.adver_int) & 0x0FFF) * TIMER_CENTI_HZ;
			/* As per RFC5798, set Master_Adver_Interval to Adver Interval contained
			 * in the ADVERTISEMENT
			 */
			if (vrrp->master_adver_int != master_adver_int) {
				log_message(LOG_INFO, "(%s) advertisement interval updated from %d to %d milli-sec from higher priority master",
						vrrp->iname, vrrp->master_adver_int / (TIMER_HZ / 1000), master_adver_int / (TIMER_HZ / 1000));
				vrrp->master_adver_int = master_adver_int;
			}
		}
		vrrp->ms_down_timer = 3 * vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);
		vrrp->master_priority = hd->priority;
		vrrp->wantstate = VRRP_STATE_BACK;
		vrrp->state = VRRP_STATE_BACK;
		return true;
	}

	return false;
}

bool
vrrp_state_fault_rx(vrrp_t * vrrp, char *buf, ssize_t buflen)
{
	vrrphdr_t *hd;
	ssize_t ret = 0;
	unsigned proto;

	/* Process the incoming packet */
	hd = vrrp_get_header(vrrp->family, buf, &proto);
	ret = vrrp_check_packet(vrrp, buf, buflen, true);

	if (ret != VRRP_PACKET_OK)
		return false;

	if (vrrp->base_priority == VRRP_PRIO_OWNER ||
	    (vrrp->effective_priority > hd->priority && !vrrp->nopreempt))
		return true;

	return false;
}

static void
free_tracking_vrrp(void *data)
{
	FREE(data);
}

void
add_vrrp_to_interface(vrrp_t *vrrp, interface_t *ifp, int weight, bool log_addr, track_t type)
{
	tracking_vrrp_t *etvp = NULL;
	element e;
	char addr_str[INET6_ADDRSTRLEN];

	if (!LIST_EXISTS(ifp->tracking_vrrp)) {
		ifp->tracking_vrrp = alloc_list(free_tracking_vrrp, dump_tracking_vrrp);

		if (log_addr && __test_bit(LOG_DETAIL_BIT, &debug)) {
			if (ifp->sin_addr.s_addr) {
				inet_ntop(AF_INET, &ifp->sin_addr, addr_str, sizeof(addr_str));
				log_message(LOG_INFO, "Assigned address %s for interface %s"
						    , addr_str, ifp->ifname);
			}
			if (ifp->sin6_addr.s6_addr32[0]) {
				inet_ntop(AF_INET6, &ifp->sin6_addr, addr_str, sizeof(addr_str));
				log_message(LOG_INFO, "Assigned address %s for interface %s"
						    , addr_str, ifp->ifname);
			}
		}
	}
	else {
		/* Check if this is already in the list, and adjust the weight appropriately */
		LIST_FOREACH(ifp->tracking_vrrp, etvp, e) {
			if (etvp->vrrp == vrrp) {
				if (etvp->type & (TRACK_VRRP | TRACK_IF | TRACK_SG) &&
				    type == TRACK_VRRP && type == TRACK_IF && type == TRACK_SG)
					log_message(LOG_INFO, "(%s) track_interface %s is configured on VRRP instance and sync group. Remove vrrp instance or sync group config",
							vrrp->iname, ifp->ifname);

				/* Update the weight appropriately. We will use the sync group's
				 * weight unless the vrrp setting is unweighted. */
				if (etvp->weight && weight != VRRP_NOT_TRACK_IF)
					etvp->weight = weight;

				etvp->type |= type;

				return;
			}
		}
	}

	/* Not in list so add */
	etvp = MALLOC(sizeof *etvp);
	etvp->vrrp = vrrp;
	etvp->weight = weight;
	etvp->type = type;

	list_add(ifp->tracking_vrrp, etvp);

	/* if vrrp->num_if_script_fault needs incrementing, it will be
	 * done in initialise_tracking_priorities() */
}

/* check for minimum configuration requirements */
static bool
chk_min_cfg(vrrp_t * vrrp)
{
	if (vrrp->vrid == 0) {
		log_message(LOG_INFO, "(%s) the virtual id must be set!", vrrp->iname);
		return false;
	}
	if (!vrrp->ifp) {
		log_message(LOG_INFO, "(%s) Unknown interface!", vrrp->iname);
		return false;
	}

	return true;
}

/* open a VRRP sending socket */
int
open_vrrp_send_socket(sa_family_t family, int proto, interface_t *ifp, bool unicast, int rx_buf_size)
{
	int fd = -1;
	int val = rx_buf_size;
	socklen_t len = sizeof(val);

	if (family != AF_INET && family != AF_INET6) {
		log_message(LOG_INFO, "cant open raw socket. unknown family=%d"
				    , family);
		return -1;
	}

	/* Create and init socket descriptor */
	fd = socket(family, SOCK_RAW | SOCK_CLOEXEC, proto);
	if (fd < 0) {
		log_message(LOG_INFO, "cant open raw socket. errno=%d", errno);
		return -1;
	}
#if !HAVE_DECL_SOCK_CLOEXEC
	set_sock_flags(fd, F_SETFD, FD_CLOEXEC);
#endif

	if (rx_buf_size || (global_data->vrrp_rx_bufs_policy & RX_BUFS_NO_SEND_RX))
	{
		/* If we are not receiving on the send socket, there is no
		 * point allocating any buffers to it */
		if (global_data->vrrp_rx_bufs_policy & RX_BUFS_NO_SEND_RX)
			val = 0;
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, len))
			log_message(LOG_INFO, "vrrp set send socket buffer size error %d", errno);
	}

	if (family == AF_INET) {
		/* Set v4 related */
		if_setsockopt_mcast_all(family, &fd);
		if_setsockopt_hdrincl(&fd);
		if (unicast)
			if_setsockopt_bindtodevice(&fd, ifp);
	} else if (family == AF_INET6) {
		/* Set v6 related */
		if_setsockopt_ipv6_checksum(&fd);
		if (!unicast)
			if_setsockopt_mcast_hops(family, &fd);
	}

	if (!unicast) {
		if_setsockopt_mcast_if(family, &fd, ifp);
		if_setsockopt_mcast_loop(family, &fd);
	}

	if_setsockopt_priority(&fd, family);

	if (fd < 0)
		return -1;

	return fd;
}

/* open a VRRP socket and join the multicast group. */
int
open_vrrp_read_socket(sa_family_t family, int proto, interface_t *ifp, bool unicast, int rx_buf_size)
{
	int fd = -1;
	int val = rx_buf_size;
	socklen_t len = sizeof(val);

	/* open the socket */
	fd = socket(family, SOCK_RAW | SOCK_CLOEXEC, proto);
	if (fd < 0) {
		int err = errno;
		log_message(LOG_INFO, "cant open raw socket. errno=%d", err);
		return -1;
	}
#if !HAVE_DECL_SOCK_CLOEXEC
	set_sock_flags(fd, F_SETFD, FD_CLOEXEC);
#endif

	if (rx_buf_size) {
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, len))
			log_message(LOG_INFO, "vrrp set receive socket buffer size error %d", errno);
	}

	/* Ensure no unwanted multicast packets are queued to this interface */
	if (family == AF_INET)
		if_setsockopt_mcast_all(family, &fd);

	if (!unicast) {
		/* Join the VRRP multicast group */
		if_join_vrrp_group(family, &fd, ifp);
	}

	/* Need to bind read socket so only process packets for interface we're
	 * interested in.
	 *
	 * This is applicable for both unicast and multicast operation as well as
	 * IPv4 and IPv6.
	 */
	if_setsockopt_bindtodevice(&fd, ifp);

	if (fd < 0)
		return -1;

	if (family == AF_INET6) {
		/* Let kernel calculate checksum. */
		if_setsockopt_ipv6_checksum(&fd);
	}

	return fd;
}

#ifdef _INCLUDE_UNUSED_CODE_
static void
close_vrrp_socket(vrrp_t * vrrp)
{
	if (LIST_ISEMPTY(vrrp->unicast_peer))
		if_leave_vrrp_group(vrrp->family, vrrp->fd_in, vrrp->ifp);

	close(vrrp->fd_in);
	close(vrrp->fd_out);
}

int
new_vrrp_socket(vrrp_t * vrrp)
{
	int old_fd = vrrp->fd_in;
	int proto;
	interface_t *ifp;
	bool unicast;

	/* close the desc & open a new one */
	close_vrrp_socket(vrrp);
	remove_vrrp_fd_bucket(vrrp);
#ifdef _WITH_VRRP_AUTH_
	if (vrrp->version == VRRP_VERSION_2)
		proto =(vrrp->auth_type == VRRP_AUTH_AH) ? IPPROTO_AH :
				IPPROTO_VRRP;
	else
#endif
		proto = IPPROTO_VRRP;
#ifdef _HAVE_VRRP_VMAC_
	ifp = __test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags) ? IF_BASE_IFP(vrrp->ifp) : vrrp->ifp;
#else
	ifp = vrrp->ifp;
#endif
	unicast = !LIST_ISEMPTY(vrrp->unicast_peer);
	vrrp->fd_in = open_vrrp_read_socket(vrrp->family, proto, ifp, unicast, vrrp->sockets->rx_buf_size);
	vrrp->fd_out = open_vrrp_send_socket(vrrp->family, proto, ifp, unicast, vrrp->sockets->rx_buf_size);
	alloc_vrrp_fd_bucket(vrrp);

	/* Sync the other desc */
	set_vrrp_fd_bucket(old_fd, vrrp);

	return vrrp->fd_in;
}
#endif

/* Try to find a VRRP instance */
static vrrp_t *
vrrp_exist(vrrp_t *old_vrrp)
{
	element e;
	vrrp_t *vrrp;

	if (LIST_ISEMPTY(vrrp_data->vrrp))
		return NULL;

	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (vrrp->vrid != old_vrrp->vrid ||
		    vrrp->family != old_vrrp->family)
			continue;

#ifndef _HAVE_VRRP_VMAC_
		if (vrrp->ifp->ifindex == old_vrrp->ifp->ifindex)
			return vrrp;
#else
		if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags) != __test_bit(VRRP_VMAC_BIT, &old_vrrp->vmac_flags))
			continue;
		if (!__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags)) {
			if (vrrp->ifp->ifindex == old_vrrp->ifp->ifindex)
				return vrrp;
			continue;
		}

		if (vrrp->ifp->base_ifp->ifindex == old_vrrp->ifp->base_ifp->ifindex)
			return vrrp;
#endif
	}

	return NULL;
}

/* handle terminate state phase 1 */
void
restore_vrrp_interfaces(void)
{
	element e;
	vrrp_t *vrrp;

	/* Ensure any interfaces are in backup mode,
	 * sending a priority 0 vrrp message
	 */
	LIST_FOREACH(vrrp_data->vrrp, vrrp, e) {
		/* Remove VIPs/VROUTEs/VRULEs */
		if (vrrp->state == VRRP_STATE_MAST)
			vrrp_restore_interface(vrrp, true, false);
	}
}

/* handle terminate state */
void
shutdown_vrrp_instances(void)
{
	element e;
	vrrp_t *vrrp;

#ifdef _HAVE_VRRP_VMAC_
	restore_rp_filter();
#endif

	LIST_FOREACH(vrrp_data->vrrp, vrrp, e) {
		/* We may not have an ifp if we are aborting at startup */
		if (vrrp->ifp) {
#ifdef _HAVE_VRRP_VMAC_
			/* Remove VMAC. If we are shutting down due to a configuration
			 * error, the VMACs may not be set up yet, and vrrp->ifp may
			 * still point to the physical interface. */
			if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags) && vrrp->ifp->vmac)
				netlink_link_del_vmac(vrrp);
#endif

			if (vrrp->ifp->reset_promote_secondaries)
				reset_promote_secondaries(vrrp->ifp);
		}

#ifdef _WITH_LVS_
		/*
		 * Stop stalled syncd. IPVS syncd state is the
		 * same as VRRP instance one. We need here to
		 * stop stalled syncd thread according to last
		 * VRRP instance state.
		 */
		if (global_data->lvs_syncd.vrrp == vrrp)
			ipvs_syncd_cmd(IPVS_STOPDAEMON, &global_data->lvs_syncd,
				       (vrrp->state == VRRP_STATE_MAST) ? IPVS_MASTER: IPVS_BACKUP,
				       true, false);
#endif
	}
}

static void
add_vrrp_to_track_script(vrrp_t *vrrp, tracked_sc_t *sc)
{
	tracking_vrrp_t *tvp, *etvp;
	element e;

	if (!LIST_EXISTS(sc->scr->tracking_vrrp))
		sc->scr->tracking_vrrp = alloc_list(free_tracking_vrrp, dump_tracking_vrrp);
	else {
		/* Is this script already tracking the vrrp instance directly?
		 * For this to be the case, the script was added directly on the vrrp instance,
		 * and now we are adding it for a sync group. */
		for (e = LIST_HEAD(sc->scr->tracking_vrrp); e; ELEMENT_NEXT(e)) {
			etvp = ELEMENT_DATA(e);
			if (etvp->vrrp == vrrp) {
				/* Update the weight appropriately. We will use the sync group's
				 * weight unless the vrrp setting is unweighted. */
				log_message(LOG_INFO, "(%s) track_script %s is configured on VRRP instance and sync group. Remove vrrp instance config",
						vrrp->iname, sc->scr->sname);

				if (etvp->weight)
					etvp->weight = sc->weight;
				return;
			}
		}
	}

	tvp = MALLOC(sizeof(tracking_vrrp_t));
	tvp->vrrp = vrrp;
	tvp->weight = sc->weight;
	list_add(sc->scr->tracking_vrrp, tvp);
}

static void
add_vrrp_to_track_file(vrrp_t *vrrp, tracked_file_t *tfl)
{
	tracking_vrrp_t *tvp, *etvp;
	element e;

	if (!LIST_EXISTS(tfl->file->tracking_vrrp))
		tfl->file->tracking_vrrp = alloc_list(free_tracking_vrrp, dump_tracking_vrrp);
	else {
		/* Is this file already tracking the vrrp instance directly?
		 * For this to be the case, the file was added directly on the vrrp instance,
		 * and now we are adding it for a sync group. */
		for (e = LIST_HEAD(tfl->file->tracking_vrrp); e; ELEMENT_NEXT(e)) {
			etvp = ELEMENT_DATA(e);
			if (etvp->vrrp == vrrp) {
				/* Update the weight appropriately. We will use the sync group's
				 * weight unless the vrrp setting is unweighted. */
				log_message(LOG_INFO, "(%s) track_file %s is configured on VRRP instance and sync group. Remove vrrp instance config",
						vrrp->iname, tfl->file->fname);

				if (etvp->weight)
					etvp->weight = tfl->weight;
				return;
			}
		}
	}

	tvp = MALLOC(sizeof(tracking_vrrp_t));
	tvp->vrrp = vrrp;
	tvp->weight = tfl->weight;
	list_add(tfl->file->tracking_vrrp, tvp);
}

#ifdef _WITH_BFD_
static void
add_vrrp_to_track_bfd(vrrp_t *vrrp, tracked_bfd_t *tbfd)
{
	tracking_vrrp_t *tvp, *etvp;
	element e;

	if (!LIST_EXISTS(tbfd->bfd->tracking_vrrp))
		tbfd->bfd->tracking_vrrp = alloc_list(free_tracking_vrrp, dump_tracking_vrrp);
	else {
		/* Is this bfd already tracking the vrrp instance directly?
		 * For this to be the case, the bfd was added directly on the vrrp instance,
		 * and now we are adding it for a sync group. */
		LIST_FOREACH(tbfd->bfd->tracking_vrrp, etvp, e) {
			if (etvp->vrrp == vrrp) {
				/* Update the weight appropriately. We will use the sync group's
				 * weight unless the vrrp setting is unweighted. */
				log_message(LOG_INFO, "(%s) track_bfd %s is configured on VRRP instance and sync group. Remove vrrp instance config",
						vrrp->iname, tbfd->bfd->bname);

				if (etvp->weight)
					etvp->weight = tbfd->weight;
				return;
			}
		}
	}

	PMALLOC(tvp);
	tvp->vrrp = vrrp;
	tvp->weight = tbfd->weight;
	list_add(tbfd->bfd->tracking_vrrp, tvp);
}
#endif

/* complete vrrp structure */
static bool
vrrp_complete_instance(vrrp_t * vrrp)
{
#ifdef _HAVE_VRRP_VMAC_
	char ifname[IFNAMSIZ];
	interface_t *ifp;
#endif
	element e;
	ip_address_t *vip;
	size_t hdr_len;
	size_t max_addr;
	size_t i;
	element next;
	bool interface_already_existed = false;
	tracked_sc_t *sc;
	tracked_if_t *tip;
	tracked_file_t *tfl;
#ifdef _WITH_BFD_
	tracked_bfd_t *tbfd;
#endif
#ifdef _HAVE_FIB_ROUTING_
	ip_route_t *vroute;
	ip_rule_t *vrule;
#endif

	if (vrrp->strict_mode == PARAMETER_UNSET)
		vrrp->strict_mode = global_data->vrrp_strict;

	if (vrrp->family == AF_INET6) {
		if (vrrp->version == VRRP_VERSION_2 && vrrp->strict_mode) {
			log_message(LOG_INFO,"(%s) cannot use IPv6 with VRRP version 2; setting version 3", vrrp->iname);
			vrrp->version = VRRP_VERSION_3;
		}
		else if (!vrrp->version)
			vrrp->version = VRRP_VERSION_3;
	}

	/* Default to IPv4. This can only happen if no VIPs are specified. */
	if (vrrp->family == AF_UNSPEC)
		vrrp->family = AF_INET;

	if (vrrp->family == AF_INET)
		have_ipv4_instance = true;
	else
		have_ipv6_instance = true;

	if (vrrp->version == 0) {
		if (vrrp->family == AF_INET6)
			vrrp->version = VRRP_VERSION_3;
		else
			vrrp->version = global_data->vrrp_version;
	}

	if (LIST_ISEMPTY(vrrp->vip) && (vrrp->version == VRRP_VERSION_3 || vrrp->family == AF_INET6 || vrrp->strict_mode)) {
		log_message(LOG_INFO, "(%s) No VIP specified; at least one is required", vrrp->iname);
		return false;
	}

	/* If no priority has been set, derive it from the initial state */
	if (vrrp->base_priority == 0) {
		if (vrrp->wantstate == VRRP_STATE_MAST)
			vrrp->base_priority = VRRP_PRIO_OWNER;
		else
			vrrp->base_priority = VRRP_PRIO_DFL;
	}

	/* If no initial state has been set, derive it from the priority */
	if (vrrp->wantstate == VRRP_STATE_INIT)
		vrrp->wantstate = (vrrp->base_priority == VRRP_PRIO_OWNER ? VRRP_STATE_MAST : VRRP_STATE_BACK);
	else if (vrrp->strict_mode &&
		 ((vrrp->wantstate == VRRP_STATE_MAST) != (vrrp->base_priority == VRRP_PRIO_OWNER))) {
			log_message(LOG_INFO,"(%s) State MASTER must match being address owner", vrrp->iname);
			vrrp->wantstate = (vrrp->base_priority == VRRP_PRIO_OWNER ? VRRP_STATE_MAST : VRRP_STATE_BACK);
	}

#ifdef _WITH_VRRP_AUTH_
	if (vrrp->strict_mode && vrrp->auth_type != VRRP_AUTH_NONE) {
		log_message(LOG_INFO, "(%s) Strict mode does not support authentication. Ignoring.", vrrp->iname);
		vrrp->auth_type = VRRP_AUTH_NONE;
	}
	else if (vrrp->version == VRRP_VERSION_3 && vrrp->auth_type != VRRP_AUTH_NONE) {
		log_message(LOG_INFO, "(%s) VRRP version 3 does not support authentication. Ignoring.", vrrp->iname);
		vrrp->auth_type = VRRP_AUTH_NONE;
	}
	else if (vrrp->auth_type != VRRP_AUTH_NONE && !vrrp->auth_data[0]) {
		log_message(LOG_INFO, "(%s) Authentication specified but no password given. Ignoring", vrrp->iname);
		vrrp->auth_type = VRRP_AUTH_NONE;
	}
	else if (vrrp->family == AF_INET6 && vrrp->auth_type == VRRP_AUTH_AH) {
		log_message(LOG_INFO, "(%s) Cannot use AH authentication with IPv6 - ignoring", vrrp->iname);
		vrrp->auth_type = VRRP_AUTH_NONE;
	}
	else if (vrrp->auth_type == VRRP_AUTH_AH && vrrp->wantstate == VRRP_STATE_MAST && vrrp->base_priority != VRRP_PRIO_OWNER) {
		/* We need to have received an advert to get the AH sequence no before taking over, if possible */
		log_message(LOG_INFO, "(%s) Initial state master is incompatible with AH authentication - clearing", vrrp->iname);
		vrrp->wantstate = VRRP_STATE_BACK;
	}
#endif

	if (!chk_min_cfg(vrrp))
		return false;

	/* unicast peers aren't allowed in strict mode if the interface supports multicast */
	if (vrrp->strict_mode && vrrp->ifp->ifindex && (vrrp->ifp->ifi_flags & IFF_MULTICAST) && !LIST_ISEMPTY(vrrp->unicast_peer)) {
		log_message(LOG_INFO, "(%s) Unicast peers are not supported in strict mode", vrrp->iname);
		return false;
	}

#ifdef _HAVE_VRRP_VMAC_
	/* Check that the underlying interface type is Ethernet if using a VMAC */
	if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags) && vrrp->ifp->ifindex && vrrp->ifp->hw_type != ARPHRD_ETHER) {
		__clear_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags);
		log_message(LOG_INFO, "(%s): vmacs are only supported on Ethernet type interfaces", vrrp->iname);
		vrrp->num_script_if_fault++;	/* Stop the vrrp instance running */
	}
#endif

	/* If the interface doesn't support multicast, then we need to use unicast */
	if (vrrp->ifp->ifindex && !(vrrp->ifp->ifi_flags & IFF_MULTICAST) && LIST_ISEMPTY(vrrp->unicast_peer)) {
		log_message(LOG_INFO, "(%s) interface %s does not support multicast, specify unicast peers - disabling", vrrp->iname, vrrp->ifp->ifname);
		vrrp->num_script_if_fault++;	/* Stop the vrrp instance running */
	}

	/* Warn if ARP not supported on interface */
	if (__test_bit(LOG_DETAIL_BIT, &debug) &&
	    vrrp->ifp->ifindex &&
	    (vrrp->ifp->ifi_flags & IFF_NOARP) &&
	    !(vrrp->ifp->ifi_flags & IFF_POINTOPOINT))
		log_message(LOG_INFO, "(%s) disabling ARP since interface does not support it", vrrp->iname);

	/* If the addresses are IPv6, then the first one must be link local */
	if (vrrp->family == AF_INET6 && LIST_ISEMPTY(vrrp->unicast_peer) &&
		  !IN6_IS_ADDR_LINKLOCAL(&((ip_address_t *)LIST_HEAD(vrrp->vip)->data)->u.sin6_addr)) {
		log_message(LOG_INFO, "(%s) the first IPv6 VIP address must be link local", vrrp->iname);
	}

	/* Check we can fit the VIPs into a packet */
	if (vrrp->family == AF_INET) {
		hdr_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(vrrphdr_t);

		if (vrrp->version == VRRP_VERSION_2) {
			hdr_len += VRRP_AUTH_LEN;

#ifdef _WITH_VRRP_AUTH_
			if (vrrp->auth_type == VRRP_AUTH_AH)
				hdr_len += vrrp_ipsecah_len();
#endif
		}

		max_addr = (vrrp->ifp->mtu - hdr_len) / sizeof(struct in_addr);
	} else {
		hdr_len = sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(vrrphdr_t);
		max_addr = (vrrp->ifp->mtu - hdr_len) / sizeof(struct in6_addr);
	}

	/* Count IP addrs field is 8 bits wide, giving a maximum address count of 255 */
	if (max_addr > VRRP_MAX_ADDR)
		max_addr = VRRP_MAX_ADDR;

	/* Move any extra addresses to be evips. We won't advertise them, but at least we can respond to them */
	if (!LIST_ISEMPTY(vrrp->vip) && LIST_SIZE(vrrp->vip) > max_addr) {
		log_message(LOG_INFO, "(%s) Number of VIPs (%d) exceeds maximum/space available in packet (max %zu addresses) - excess moved to eVIPs",
				vrrp->iname, LIST_SIZE(vrrp->vip), max_addr);
		for (i = 0, e = LIST_HEAD(vrrp->vip); e; i++, e = next) {
			next = e->next;
			if (i < max_addr)
				continue;
			vip = ELEMENT_DATA(e);
			list_del(vrrp->vip, vip);
			if (!LIST_EXISTS(vrrp->evip))
				vrrp->evip = alloc_list(free_ipaddress, dump_ipaddress);
			list_add(vrrp->evip, vip);
		}
	}

	if (vrrp->base_priority == VRRP_PRIO_OWNER && vrrp->nopreempt) {
		log_message(LOG_INFO, "(%s) nopreempt is incompatible with priority %d - resetting nopreempt", vrrp->iname, VRRP_PRIO_OWNER);
		vrrp->nopreempt = false;
	}

	vrrp->effective_priority = vrrp->base_priority;
	vrrp->total_priority = vrrp->base_priority;

	if (vrrp->wantstate == VRRP_STATE_MAST) {
		if (vrrp->nopreempt) {
			log_message(LOG_INFO, "(%s) Warning - nopreempt will not work with initial state MASTER - clearing", vrrp->iname);
			vrrp->nopreempt = false;
		}
		if (vrrp->preempt_delay) {
			log_message(LOG_INFO, "(%s) Warning - preempt delay will not work with initial state MASTER - clearing", vrrp->iname);
			vrrp->preempt_delay = false;
		}
	}
	if (vrrp->preempt_delay) {
		if (vrrp->strict_mode) {
			log_message(LOG_INFO, "(%s) preempt_delay is incompatible with strict mode - resetting", vrrp->iname);
			vrrp->preempt_delay = 0;
		}
		if (vrrp->nopreempt) {
			log_message(LOG_INFO, "(%s) preempt_delay is incompatible with nopreempt mode - resetting", vrrp->iname);
			vrrp->preempt_delay = 0;
		}
	}

	vrrp->state = VRRP_STATE_INIT;
#ifdef _WITH_SNMP_VRRP_
	vrrp->configured_state = vrrp->wantstate;
#endif

	/* Set default for accept mode if not specified. If we are running in strict mode,
	 * default is to disable accept mode, otherwise default is to enable it.
	 * At some point we might want to change this to make non accept_mode the default,
	 * to comply with the RFCs. */
	if (vrrp->accept == PARAMETER_UNSET)
		vrrp->accept = !vrrp->strict_mode;

	if (vrrp->accept &&
	    vrrp->base_priority != VRRP_PRIO_OWNER &&
	    vrrp->strict_mode &&
	    vrrp->version == VRRP_VERSION_2) {
		log_message(LOG_INFO, "(%s) warning - accept mode for VRRP version 2 does not comply with RFC3768 - resetting", vrrp->iname);
		vrrp->accept = 0;
	}

	if (vrrp->garp_lower_prio_rep == PARAMETER_UNSET)
		vrrp->garp_lower_prio_rep = vrrp->strict_mode ? 0 : global_data->vrrp_garp_lower_prio_rep;
	else if (vrrp->strict_mode && vrrp->garp_lower_prio_rep) {
		log_message(LOG_INFO, "(%s) Strict mode requires no repeat garps - resetting", vrrp->iname);
		vrrp->garp_lower_prio_rep = 0;
	}
	if (vrrp->garp_lower_prio_delay == PARAMETER_UNSET)
		vrrp->garp_lower_prio_delay = vrrp->strict_mode ? 0 : global_data->vrrp_garp_lower_prio_delay;
	else if (vrrp->strict_mode && vrrp->garp_lower_prio_delay) {
		log_message(LOG_INFO, "(%s) Strict mode requires no repeat garp delay - resetting", vrrp->iname);
		vrrp->garp_lower_prio_delay = 0;
	}
	if (vrrp->lower_prio_no_advert == PARAMETER_UNSET)
		vrrp->lower_prio_no_advert = vrrp->strict_mode ? true : global_data->vrrp_lower_prio_no_advert;
	else if (vrrp->strict_mode && !vrrp->lower_prio_no_advert) {
		log_message(LOG_INFO, "(%s) Strict mode requires no lower priority advert - resetting", vrrp->iname);
		vrrp->lower_prio_no_advert = true;
	}
	if (vrrp->higher_prio_send_advert == PARAMETER_UNSET)
		vrrp->higher_prio_send_advert = vrrp->strict_mode ? false : global_data->vrrp_higher_prio_send_advert;
	else if (vrrp->strict_mode && vrrp->higher_prio_send_advert) {
		log_message(LOG_INFO, "(%s) strict mode requires higherer_prio_send_advert to be clear - resetting", vrrp->iname);
		vrrp->higher_prio_send_advert = false;
	}

	if (vrrp->smtp_alert == -1) {
		if (global_data->smtp_alert_vrrp != -1)
			vrrp->smtp_alert = global_data->smtp_alert_vrrp;
		else if (global_data->smtp_alert != -1)
			vrrp->smtp_alert = global_data->smtp_alert;
		else
			vrrp->smtp_alert = false;
	}

	/* Check that the advertisement interval is valid */
	if (!vrrp->adver_int)
		vrrp->adver_int = VRRP_ADVER_DFL * TIMER_HZ;
	if (vrrp->version == VRRP_VERSION_2) {
		if (vrrp->adver_int >= (1<<8) * TIMER_HZ) {
			log_message(LOG_INFO, "(%s) VRRPv2 advertisement interval %.2fs is out of range. Must be less than %ds. Setting to %ds",
					vrrp->iname, (float)vrrp->adver_int / TIMER_HZ, 1<<8, (1<<8) - 1);
			vrrp->adver_int = ((1<<8) - 1) * TIMER_HZ;
		}
		else if (vrrp->adver_int % TIMER_HZ) {
			log_message(LOG_INFO, "(%s) VRRPv2 advertisement interval %fs must be an integer - rounding",
					vrrp->iname, (float)vrrp->adver_int / TIMER_HZ);
			vrrp->adver_int = vrrp->adver_int + (TIMER_HZ / 2);
			vrrp->adver_int -= vrrp->adver_int % TIMER_HZ;
			if (vrrp->adver_int == 0)
				vrrp->adver_int = TIMER_HZ;
		}
	}
	else
	{
		if (vrrp->adver_int >= (1<<12) * TIMER_CENTI_HZ) {
			log_message(LOG_INFO, "(%s) VRRPv3 advertisement interval %.2fs is out of range. Must be less than %.2fs. Setting to %.2fs",
					vrrp->iname, (float)vrrp->adver_int / TIMER_HZ, (float)(1<<12) / 100, (float)((1<<12) - 1) / 100);
			vrrp->adver_int = ((1<<12) - 1) * TIMER_CENTI_HZ;
		}
		else if (vrrp->adver_int % TIMER_CENTI_HZ) {
			log_message(LOG_INFO, "(%s) VRRPv3 advertisement interval %fs must be in units of 10ms - rounding",
					vrrp->iname, (float)vrrp->adver_int / TIMER_HZ);
			vrrp->adver_int = vrrp->adver_int + (TIMER_CENTI_HZ / 2);
			vrrp->adver_int -= vrrp->adver_int % TIMER_CENTI_HZ;

			if (vrrp->adver_int == 0)
				vrrp->adver_int = TIMER_CENTI_HZ;
		}
	}
	vrrp->master_adver_int = vrrp->adver_int;

	/* Set linkbeat polling on interface if wanted */
	if (vrrp->linkbeat_use_polling || global_data->linkbeat_use_polling)
		vrrp->ifp->linkbeat_use_polling = true;

	/* Clear track_saddr if no saddr specified */
	if (!vrrp->saddr_from_config)
		vrrp->track_saddr = false;

#ifdef _HAVE_VRRP_VMAC_
	/* Set a default interface name for the vmac if needed */
	if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags)) {
		/* The same vrid can be used for both IPv4 and IPv6, and also on multiple underlying
		 * interfaces. */

		/* Look to see if an existing interface matches. If so, use that name */
		list if_list = get_if_list();
		if (!LIST_ISEMPTY(if_list)) {		/* If the list were empty we would have a real problem! */
			for (e = LIST_HEAD(if_list); e; ELEMENT_NEXT(e)) {
				ifp = ELEMENT_DATA(e);
				/* Check if this interface could be the macvlan for this vrrp */
				if (ifp->vmac &&
				    !memcmp(ifp->hw_addr, ll_addr, sizeof(ll_addr) - 2) &&
				    ((vrrp->family == AF_INET && ifp->hw_addr[sizeof(ll_addr) - 2] == 0x01) ||
				     (vrrp->family == AF_INET6 && ifp->hw_addr[sizeof(ll_addr) - 2] == 0x02)) &&
				    ifp->hw_addr[sizeof(ll_addr) - 1] == vrrp->vrid &&
				    ifp->base_ifp == vrrp->ifp)
				{
					log_message(LOG_INFO, "(%s) Found matching interface %s", vrrp->iname, ifp->ifname);
					if (vrrp->vmac_ifname[0] &&
					    strcmp(vrrp->vmac_ifname, ifp->ifname))
						log_message(LOG_INFO, "(%s) vmac name mismatch %s <=> %s; changing to %s.", vrrp->iname, vrrp->vmac_ifname, ifp->ifname, ifp->ifname);

					strcpy(vrrp->vmac_ifname, ifp->ifname);
					vrrp->ifp = ifp;
					__set_bit(VRRP_VMAC_UP_BIT, &vrrp->vmac_flags);

					/* The interface existed, so it may have config set on it */
					interface_already_existed = true;

					break;
				}
			}

			if (!interface_already_existed &&
			    vrrp->vmac_ifname[0] &&
			    (ifp = if_get_by_ifname(vrrp->vmac_ifname, IF_NO_CREATE)) &&
			     ifp->ifindex) {
				/* An interface with the same name exists, but it doesn't match */
				if (ifp->vmac)
					log_message(LOG_INFO, "(%s) VMAC %s already exists but is incompatible. It will be deleted", vrrp->iname, vrrp->vmac_ifname);
				else {
					log_message(LOG_INFO, "(%s) VMAC interface name %s already exists as a non VMAC interface - ignoring configured name",
						    vrrp->iname, vrrp->vmac_ifname);
					vrrp->vmac_ifname[0] = 0;
				}
			}
		}

		/* No interface found, find an unused name */
		if (!vrrp->vmac_ifname[0]) {
			unsigned short num=0;
			snprintf(ifname, IFNAMSIZ, "vrrp.%d", vrrp->vrid);

			while (true) {
				/* If there is no VMAC with the name and no existing
				 * interface with the name, we can use it.
				 * It we are using dynamic interfaces, the interface entry
				 * may have been created by the configuration, but in that
				 * case the ifindex will be 0. */
				if (!e && (!(ifp = if_get_by_ifname(ifname, IF_NO_CREATE)) || !ifp->ifindex))
					break;

				/* For IPv6 try vrrp6 as second attempt */
				if (vrrp->family == AF_INET6) {
					if (num == 0)
						num = 6;
					else if (num == 6)
						num = 1;
					else if (++num == 6)
						num++;
				}
				else
					num++;

				snprintf(ifname, IFNAMSIZ, "vrrp%d.%d", num, vrrp->vrid);
			}

			/* We've found a unique name */
			strncpy(vrrp->vmac_ifname, ifname, IFNAMSIZ);
		}

		if (!interface_already_existed) {
			ifp = if_get_by_ifname(vrrp->vmac_ifname, IF_CREATE_ALWAYS);
			ifp->base_ifp = vrrp->ifp;
			vrrp->ifp = ifp;
		}

		if (vrrp->strict_mode && __test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags)) {
			log_message(LOG_INFO, "(%s) xmit_base is incompatible with strict mode - resetting", vrrp->iname);
			__clear_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags);
		}

		if (vrrp->promote_secondaries) {
			log_message(LOG_INFO, "(%s) promote_secondaries is automatically set for vmacs - ignoring", vrrp->iname);
			vrrp->promote_secondaries = false;
		}
	}
	else
#endif
	{
		/* We are using a "physical" interface, so it may have configuration on it
		 * left over from a previous run. */
		interface_already_existed = true;
	}

	/* Make sure we have an IP address as needed */
	if (vrrp->ifp->base_ifp->ifindex && vrrp->saddr.ss_family == AF_UNSPEC) {
		/* Check the physical interface has a suitable address we can use.
		 * We don't need an IPv6 address on the underlying interface if it is
		 * a VMAC since we can create our own. */
		bool addr_missing = false;

		if (vrrp->family == AF_INET) {
			if (!IF_BASE_IFP(vrrp->ifp)->sin_addr.s_addr)
				addr_missing = true;
		}
		else {
#ifdef _HAVE_VRRP_VMAC_
			if (!__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags))
#endif
				if (!IF_BASE_IFP(vrrp->ifp)->sin6_addr.s6_addr32[0])
					addr_missing = true;
		}

		if (addr_missing) {
			log_message(LOG_INFO, "(%s) Cannot find an IP address to use for interface %s", vrrp->iname, IF_BASE_IFP(vrrp->ifp)->ifname);
		}
		else if (vrrp->family == AF_INET)
			inet_ip4tosockaddr(&IF_BASE_IFP(vrrp->ifp)->sin_addr, &vrrp->saddr);
		else if (vrrp->family == AF_INET6)
			inet_ip6tosockaddr(&IF_BASE_IFP(vrrp->ifp)->sin6_addr, &vrrp->saddr);
	}

	/* Add us to the interfaces we are tracking */
	LIST_FOREACH_NEXT(vrrp->track_ifp, tip, e, next) {
		/* Check the configuration doesn't explicitly state to track our own interface */
		if (tip->ifp == IF_BASE_IFP(vrrp->ifp)) {
			log_message(LOG_INFO, "(%s) Ignoring track_interface %s since own interface", vrrp->iname, IF_BASE_IFP(vrrp->ifp)->ifname);
			free_list_element(vrrp->track_ifp, e);
		}
		else
			add_vrrp_to_interface(vrrp, tip->ifp, tip->weight, false, TRACK_IF);
	}

	/* Add this instance to the physical interface and vice versa */
	add_vrrp_to_interface(vrrp, IF_BASE_IFP(vrrp->ifp), vrrp->dont_track_primary ? VRRP_NOT_TRACK_IF : 0, true, TRACK_VRRP);

#ifdef _HAVE_VRRP_VMAC_
	if (__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags) &&
	    !__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags)) {
		log_message(LOG_INFO, "(%s) vmac_xmit_base is only valid with a vmac", vrrp->iname);
		__clear_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags);
	}

	if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags))
	{
		/* We need to know if we need to allow IPv6 just for eVIPs */
		if (vrrp->family == AF_INET && !LIST_ISEMPTY(vrrp->evip)) {
			for (e = LIST_HEAD(vrrp->evip); e; ELEMENT_NEXT(e)) {
				vip = ELEMENT_DATA(e);
				if (vip->ifa.ifa_family == AF_INET6) {
					vrrp->evip_add_ipv6 = true;
					break;
				}
			}
		}

		/* Create the interface if it doesn't already exist and
		 * the underlying interface does exist */
		if (vrrp->ifp->base_ifp->ifindex &&
		    !__test_bit(VRRP_VMAC_UP_BIT, &vrrp->vmac_flags) &&
		    !__test_bit(CONFIG_TEST_BIT, &debug))
			netlink_link_add_vmac(vrrp);

		/* Add this instance to the vmac interface */
		add_vrrp_to_interface(vrrp, vrrp->ifp, vrrp->dont_track_primary ? VRRP_NOT_TRACK_IF : 0, true, TRACK_VRRP);
	}
#endif

	/* Spin through all our addresses, setting ifindex and ifp.
	   We also need to know what addresses we might block */
	if (vrrp->base_priority != VRRP_PRIO_OWNER && !vrrp->accept) {
//TODO = we have a problem since SNMP may change accept mode
//it can also change priority
		if (!global_data->vrrp_iptables_inchain[0])
			log_message(LOG_INFO, "(%s) Unable to set no_accept mode since iptables chain name unset", vrrp->iname);
		else if (vrrp->family == AF_INET)
			block_ipv4 = true;
		else
			block_ipv6 = true;
	}

	/* Add each VIP/eVIP's interface to the interface list, unless we aren't tracking it.
	 * If the interface goes down, then we will not be able to re-add the address, and so
	 * we should go to fault state. */
	LIST_FOREACH(vrrp->vip, vip, e) {
		if (!vip->ifp)
			vip->ifp = vrrp->ifp;
		if (!vip->dont_track)
			add_vrrp_to_interface(vrrp, vip->ifp, 0, false, TRACK_ADDR);
	}
	LIST_FOREACH(vrrp->evip, vip, e) {
		if (!vip->ifp)
			vip->ifp = vrrp->ifp;
		if (!vip->dont_track)
			add_vrrp_to_interface(vrrp, vip->ifp, 0, false, TRACK_ADDR);

		if (vip->ifa.ifa_family == AF_INET)
			have_ipv4_instance = true;
		else
			have_ipv6_instance = true;
	}

	/* In case of VRRP SYNC, we have to carefully check that we are
	 * not running floating priorities on any VRRP instance, unless
	 * sgroup_tracking_weight is set.
	 * If address owner, then we must totally ignore weights.
	 */
	if ((vrrp->sync && !vrrp->sync->sgroup_tracking_weight) ||
	    vrrp->base_priority == VRRP_PRIO_OWNER) {
		bool sync_no_tracking_weight = (vrrp->sync && !vrrp->sync->sgroup_tracking_weight);

		/* Set weight to 0 of any interface we are tracking,
		 * unless we are the address owner, in which case stop tracking it */
		LIST_FOREACH_NEXT(vrrp->track_ifp, tip, e, next) {
			if (tip->weight && tip->weight != VRRP_NOT_TRACK_IF) {
				log_message(LOG_INFO, "(%s) ignoring %s"
						 "tracked interface %s due to %s",
						 vrrp->iname, tip->ifp->ifname,
						 sync_no_tracking_weight ? "weight of " : "",
						 sync_no_tracking_weight ? "SYNC group" : "address owner");
				if (sync_no_tracking_weight)
					tip->weight = 0;
				else
					free_list_element(vrrp->track_ifp, e);
			}
		}
		if (LIST_ISEMPTY(vrrp->track_ifp))
			free_list(&vrrp->track_ifp);

		/* Ignore any weighted script */
		LIST_FOREACH_NEXT(vrrp->track_script, sc, e, next) {
			if (sc->weight) {
				log_message(LOG_INFO, "(%s) ignoring "
						 "tracked script %s with weights due to %s",
						 vrrp->iname, sc->scr->sname,
						 sync_no_tracking_weight ? "SYNC group" : "address_owner");
				free_list_element(vrrp->track_script, e);
			}
		}
		if (LIST_ISEMPTY(vrrp->track_script))
			free_list(&vrrp->track_script);

		/* Set tracking files to unweighted if weight not explicitly set, otherwise ignore */
		LIST_FOREACH_NEXT(vrrp->track_file, tfl, e, next) {
			if (tfl->weight == 1) {		/* weight == 1 is the default */
				log_message(LOG_INFO, "(%s) ignoring weight from "
						 "tracked file %s due to %s - specify weight 0",
						 vrrp->iname, tfl->file->fname,
						 sync_no_tracking_weight ? "SYNC group" : "address_owner");
				tfl->weight = 0;
			}
			else if (tfl->weight) {
				log_message(LOG_INFO, "(%s) ignoring "
						 "tracked file %s with weight %d due to %s",
						 vrrp->iname, tfl->file->fname, tfl->weight,
						 sync_no_tracking_weight ? "SYNC group" : "address_owner");
				free_list_element(vrrp->track_file, e);
			}
		}
		if (LIST_ISEMPTY(vrrp->track_file))
			free_list(&vrrp->track_file);

#ifdef _WITH_BFD_
		/* Ignore any weighted tracked bfd */
		LIST_FOREACH_NEXT(vrrp->track_bfd, tbfd, e, next) {
			if (tbfd->weight) {
				log_message(LOG_INFO, "(%s) ignoring "
						 "tracked bfd %s with weight %d due to %s",
						 vrrp->iname, tbfd->bfd->bname, tbfd->weight,
						 sync_no_tracking_weight ? "SYNC group" : "address_owner");
				free_list_element(vrrp->track_bfd, e);
			}
		}
		if (LIST_ISEMPTY(vrrp->track_bfd))
			free_list(&vrrp->track_bfd);
#endif
	}

	/* Add us to the vrrp list of the script, and update
	 * effective_priority and num_script_if_fault */
	LIST_FOREACH_NEXT(vrrp->track_script, sc, e, next) {
		vrrp_script_t *vsc = sc->scr;

		if (vrrp->base_priority == VRRP_PRIO_OWNER && sc->weight) {
			log_message(LOG_INFO, "(%s) Cannot have weighted track script '%s' with priority %d", vrrp->iname, vsc->sname, VRRP_PRIO_OWNER);
			list_del(vrrp->track_script, sc);
			continue;
		}

		add_vrrp_to_track_script(vrrp, sc);
	}

	/* Add our track files to the tracking file tracking_vrrp list */
	LIST_FOREACH(vrrp->track_file, tfl, e)
		add_vrrp_to_track_file(vrrp, tfl);

#ifdef _WITH_BFD_
	/* Add our track bfd to the tracking bfd tracking_vrrp list */
	LIST_FOREACH(vrrp->track_bfd, tbfd, e)
		add_vrrp_to_track_bfd(vrrp, tbfd);
#endif

	if (vrrp->ifp->ifindex) {
		if (!reload && interface_already_existed) {
			vrrp->vipset = true;	/* Set to force address removal */
		}

		/* See if we need to set promote_secondaries */
		if (vrrp->promote_secondaries &&
		    !vrrp->ifp->promote_secondaries_already_set &&
		    !__test_bit(CONFIG_TEST_BIT, &debug))
			set_promote_secondaries(vrrp->ifp);
	}

#ifdef _HAVE_FIB_ROUTING_
	/* Check if there are any route/rules we need to monitor */
	LIST_FOREACH(vrrp->vroutes, vroute, e) {
		if (!vroute->dont_track) {
			if (vroute->family == AF_INET)
				monitor_ipv4_routes = true;
			else
				monitor_ipv6_routes = true;

			/* If the route specifies an interface, this vrrp instance should track the interface */
			if (vroute->oif)
				add_vrrp_to_interface(vrrp, vroute->oif, 0, false, TRACK_ROUTE);
		}
	}
	LIST_FOREACH(vrrp->vrules, vrule, e) {
		if (!vrule->dont_track) {
			if (vrule->family == AF_INET)
				monitor_ipv4_rules = true;
			else
				monitor_ipv6_rules = true;

			/* If the rule specifies an interface, this vrrp instance should track the interface */
			if (vrule->iif)
				add_vrrp_to_interface(vrrp, vrule->iif, 0, false, TRACK_RULE);
#if HAVE_DECL_FRA_OIFNAME
			if (vrule->oif)
				add_vrrp_to_interface(vrrp, vrule->oif, 0, false, TRACK_RULE);
#endif
		}
	}
#endif

	/* alloc send buffer */
	vrrp_alloc_send_buffer(vrrp);
	vrrp_build_pkt(vrrp);

	return true;
}

static void
sync_group_tracking_init(void)
{
	element e, e1, e2;
	vrrp_sgroup_t *sgroup;
	tracked_sc_t *sc;
	vrrp_script_t *vsc;
	tracked_if_t *tif;
	tracked_file_t *tfl;
#ifdef _WITH_BFD_
	tracked_bfd_t *tbfd;
#endif
	vrrp_t *vrrp;
	bool sgroup_has_prio_owner;

	if (LIST_ISEMPTY(vrrp_data->vrrp_sync_group))
		return;

	/* Add sync group members to the vrrp list of the script, file, i/f,
	 * and update effective_priority and num_script_if_fault */
	LIST_FOREACH(vrrp_data->vrrp_sync_group, sgroup, e) {
		if (LIST_ISEMPTY(sgroup->vrrp_instances))
			continue;

		/* Find out if any of the sync group members are address owners, since then
		 * we cannot have weights */
		sgroup_has_prio_owner = false;
		LIST_FOREACH(sgroup->vrrp_instances, vrrp, e1) {
			if (vrrp->base_priority == VRRP_PRIO_OWNER) {
				sgroup_has_prio_owner = true;
				break;
			}
		}

		LIST_FOREACH(sgroup->track_script, sc, e1) {
			vsc = sc->scr;

			if (sgroup_has_prio_owner && sc->weight) {
				log_message(LOG_INFO, "(%s) Cannot have weighted track script '%s' with member having priority %d - clearing weight", sgroup->gname, vsc->sname, VRRP_PRIO_OWNER);
				sc->weight = 0;
			}

			LIST_FOREACH(sgroup->vrrp_instances, vrrp, e2)
				add_vrrp_to_track_script(vrrp, sc);
		}

		/* tracked files */
		LIST_FOREACH(sgroup->track_file, tfl, e1) {
			if (sgroup_has_prio_owner && tfl->weight) {
				log_message(LOG_INFO, "(%s) Cannot have weighted track file '%s' with member having priority %d - setting weight 0", sgroup->gname, tfl->file->fname, VRRP_PRIO_OWNER);
				tfl->weight = 0;
			}

			LIST_FOREACH(sgroup->vrrp_instances, vrrp, e2)
				add_vrrp_to_track_file(vrrp, tfl);
		}

#ifdef _WITH_BFD_
		/* tracked files */
		LIST_FOREACH(sgroup->track_bfd, tbfd, e1) {
			if (sgroup_has_prio_owner && tbfd->weight) {
				log_message(LOG_INFO, "(%s) Cannot have weighted track bfd '%s' with member having priority %d - setting weight 0", sgroup->gname, tbfd->bfd->bname, VRRP_PRIO_OWNER);
				tbfd->weight = 0;
			}

			LIST_FOREACH(sgroup->vrrp_instances, vrrp, e2)
				add_vrrp_to_track_bfd(vrrp, tbfd);
		}
#endif

		/* tracked interfaces */
		LIST_FOREACH(sgroup->track_ifp, tif, e1) {
			if (sgroup_has_prio_owner && tif->weight) {
				log_message(LOG_INFO, "(%s) Cannot have weighted track interface '%s' with member having priority %d - clearing weight", sgroup->gname, tif->ifp->ifname, VRRP_PRIO_OWNER);
				tif->weight = 0;
			}

			LIST_FOREACH(sgroup->vrrp_instances, vrrp, e2)
				add_vrrp_to_interface(vrrp, tif->ifp, tif->weight, true, TRACK_SG);
		}

		/* Set default smtp_alert */
		if (sgroup->smtp_alert == -1) {
			if (global_data->smtp_alert_vrrp != -1)
				sgroup->smtp_alert = global_data->smtp_alert_vrrp;
			else if (global_data->smtp_alert != -1)
				sgroup->smtp_alert = global_data->smtp_alert;
			else
				sgroup->smtp_alert = false;
		}
	}
}

#if _HAVE_FIB_ROUTING_
static void
process_static_entries(void)
{
	element e;
	ip_route_t *sroute;
	ip_rule_t *srule;

	LIST_FOREACH(vrrp_data->static_routes, sroute, e) {
		if (!sroute->track_group)
			continue;

		if (sroute->family == AF_INET)
			monitor_ipv4_routes = true;
		else
			monitor_ipv6_routes = true;
	}
	LIST_FOREACH(vrrp_data->static_rules, srule, e) {
		if (!srule->track_group)
			continue;

		if (srule->family == AF_INET)
			monitor_ipv4_rules = true;
		else
			monitor_ipv6_rules = true;
	}
}
#endif

bool
vrrp_complete_init(void)
{
	/*
	 * e - Element equal to a specific VRRP instance
	 * eo- Element equal to a specific group within old global group list
	 */
	element e, e1;
	vrrp_t *vrrp, *old_vrrp;
	vrrp_sgroup_t *sgroup;
	list l_o;
	element e_o;
	element next;
	vrrp_t *vrrp_o;
	interface_t *ifp;
	ifindex_t ifindex_o;
	size_t max_mtu_len = 0;
	bool have_master, have_backup;

	/* Set defaults of not specified, depending on strict mode */
	if (global_data->vrrp_garp_lower_prio_rep == PARAMETER_UNSET)
		global_data->vrrp_garp_lower_prio_rep = global_data->vrrp_garp_rep;
	if (global_data->vrrp_garp_lower_prio_delay == PARAMETER_UNSET)
		global_data->vrrp_garp_lower_prio_delay = global_data->vrrp_garp_delay;

	/* Add the FIFO name to the end of the parameter list */
	if (global_data->notify_fifo.script)
		add_script_param(global_data->notify_fifo.script, global_data->notify_fifo.name);
	if (global_data->vrrp_notify_fifo.script)
		add_script_param(global_data->vrrp_notify_fifo.script, global_data->vrrp_notify_fifo.name);

	/* Mark any scripts as insecure */
	check_vrrp_script_security();

#if !defined _DEBUG_ && defined _WITH_LVS_
	/* Only one process must run the script to process the global fifo,
	 * so let the checker process do so. */
	if (running_checker())
		free_notify_script(&global_data->notify_fifo.script);
#endif

	/* Create a notify FIFO if needed, and open it */
	notify_fifo_open(&global_data->notify_fifo, &global_data->vrrp_notify_fifo, vrrp_notify_fifo_script_exit, "vrrp_");

	/* Make sure don't have same vrid on same interface with same address family */
	LIST_FOREACH(vrrp_data->vrrp, vrrp, e) {
		l_o = &vrrp_data->vrrp_index[vrrp->vrid];
#ifdef _HAVE_VRRP_VMAC_
		if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags))
			ifp = vrrp->ifp->base_ifp;
		else
#endif
			ifp = vrrp->ifp;

		/* Check if any other entries with same vrid conflict */
		if (!LIST_ISEMPTY(l_o) && LIST_SIZE(l_o) > 1) {
			/* Can't have same vrid with same family on same interface */
			LIST_FOREACH(l_o, vrrp_o, e_o) {
				if (vrrp_o != vrrp &&
				    vrrp_o->family == vrrp->family) {
#ifdef _HAVE_VRRP_VMAC_
					if (__test_bit(VRRP_VMAC_BIT, &vrrp_o->vmac_flags))
						ifindex_o = vrrp_o->ifp->base_ifp->ifindex;
					else
#endif
						ifindex_o = vrrp_o->ifp->ifindex;

					if (ifp->ifindex == ifindex_o)
					{
						log_message(LOG_INFO, "VRID %d is duplicated on interface %s", vrrp->vrid, ifp->ifname);
						return false;
					}
				}
			}
		}
	}

	/* Build synchronization group index, and remove any
	 * empty groups */
	LIST_FOREACH_NEXT(vrrp_data->vrrp_sync_group, sgroup, e, next) {
		if (!sgroup->iname) {
			log_message(LOG_INFO, "Sync group %s has no virtual router(s) - removing", sgroup->gname);
			free_list_element(vrrp_data->vrrp_sync_group, e);
			continue;
		}

		vrrp_sync_set_group(sgroup);

		if (!sgroup->vrrp_instances) {
			free_list_element(vrrp_data->vrrp_sync_group, e);
			continue;
		}
	}

	/* Complete VRRP instance initialization */
	LIST_FOREACH(vrrp_data->vrrp, vrrp, e) {
		if (!vrrp_complete_instance(vrrp))
			return false;

		if (vrrp->ifp->mtu > max_mtu_len)
			max_mtu_len = vrrp->ifp->mtu;
	}

	/* Build static track groups and remove empty groups */
	static_track_group_init();

	/* Add pointers from sync group tracked scripts, file and interfaces
	 * to members of the sync groups.
	 * This must be called after vrrp_complete_instance() since this adds
	 * (possibly weighted) tracking objects to vrrp instances, but any
	 * weighted tracking objects configured directly against a vrrp instance
	 * in a sync group must have the tracking objects removed unless
	 * sgroup_tracking_weight is set */
	sync_group_tracking_init();

	/* All the checks that can be done without actually loading the config
	 * have been done now */
	if (__test_bit(CONFIG_TEST_BIT, &debug))
		return true;

	/* If we have a global garp_delay add it to any interfaces without a garp_delay */
	if (global_data->vrrp_garp_interval || global_data->vrrp_gna_interval)
		set_default_garp_delay();

#ifdef _HAVE_FIB_ROUTING_
	/* See if any static routes or rules need monitoring */
	process_static_entries();

	/* If we are tracking any routes/rules, ask netlink to monitor them */
	set_extra_netlink_monitoring(monitor_ipv4_routes, monitor_ipv6_routes, monitor_ipv4_rules, monitor_ipv6_rules);
#endif

#ifdef _HAVE_LIBIPTC_
	/* Make sure we don't have any old iptables/ipsets settings left around */
	if (!reload)
		iptables_cleanup();
#endif

	/* We need to know the state of interfaces for the next loop */
	init_interface_linkbeat();

	/* Check for instance down due to an interface */
	initialise_interface_tracking_priorities();

	/* Now check for tracking scripts, files, bfd etc */
	LIST_FOREACH(vrrp_data->vrrp, vrrp, e) {
		/* Set effective priority and fault state */
		initialise_tracking_priorities(vrrp);

		if (vrrp->sync) {
			if (vrrp->state == VRRP_STATE_FAULT) {
				if (vrrp->sync->state != VRRP_STATE_FAULT) {
					vrrp->sync->state = VRRP_STATE_FAULT;
					log_message(LOG_INFO, "VRRP_Group(%s): Syncing instances to FAULT state", vrrp->sync->gname);
				}

				vrrp->sync->num_member_fault++;
			}
			if (vrrp->num_script_init) {
				/* Update init count on sync group if needed */
				vrrp->sync->num_member_init++;
				if (vrrp->sync->state != VRRP_STATE_FAULT)
					vrrp->sync->state = VRRP_STATE_INIT;
			}
		}
	}

	/* Make sure that if any sync group has member wanting to start in
	 * master state, then all can start in master state. */
	LIST_FOREACH(vrrp_data->vrrp_sync_group, sgroup, e1) {
		have_backup = false;
		have_master = false;
		LIST_FOREACH(sgroup->vrrp_instances, vrrp, e) {
			if (vrrp->wantstate == VRRP_STATE_BACK || vrrp->base_priority != VRRP_PRIO_OWNER)
				have_backup = true;
			if (vrrp->wantstate == VRRP_STATE_MAST)
				have_master = true;
			if (have_master && have_backup) {
				/* This looks wrong using the same loop variables as a containing
				 * loop, but we break out of the outer loop after this loop */
				LIST_FOREACH(sgroup->vrrp_instances, vrrp, e) {
					if (vrrp->wantstate == VRRP_STATE_MAST)
						vrrp->wantstate = VRRP_STATE_BACK;
				}
				break;
			}
		}
	}

// What we want to do is make all the settings for vrrp instances, including scripts in init
// Then copy old vrrp master/backup in !fault or num_script_init
//   and then go through and set up sync groups in fault or init with counts
// TODO-PQA
	/* Set all sync group members to fault state if sync group is in fault state */
	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		if (vrrp->state == VRRP_STATE_FAULT ||
		    (vrrp->sync && vrrp->sync->state == VRRP_STATE_FAULT)) {
			vrrp->state = VRRP_STATE_FAULT;

			log_message(LOG_INFO, "(%s) entering FAULT state", vrrp->iname);

			send_instance_notifies(vrrp);
		}
	}

	if (reload) {
		/* Now step through the old vrrp to set the status on matching new instances */
		for (e = LIST_HEAD(old_vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
			old_vrrp = ELEMENT_DATA(e);
			vrrp = vrrp_exist(old_vrrp);
			if (vrrp) {
				/* If we have detected a fault, don't override it */
				if (vrrp->state == VRRP_STATE_FAULT || vrrp->num_script_init)
					continue;

				vrrp->state = old_vrrp->state;
				vrrp->wantstate = old_vrrp->state;
			}
		}
	}

#ifdef _WITH_LVS_
	/* Set up the lvs_syncd vrrp */
	if (global_data->lvs_syncd.vrrp_name) {
		for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
			vrrp = ELEMENT_DATA(e);
			if (!strcmp(global_data->lvs_syncd.vrrp_name, vrrp->iname)) {
				global_data->lvs_syncd.vrrp = vrrp;

				break;
			}
		}

		if (!global_data->lvs_syncd.vrrp) {
			log_message(LOG_INFO, "Unable to find vrrp instance %s for lvs_syncd - clearing lvs_syncd config", global_data->lvs_syncd.vrrp_name);
			FREE_PTR(global_data->lvs_syncd.ifname);
			global_data->lvs_syncd.ifname = NULL;
			global_data->lvs_syncd.syncid = PARAMETER_UNSET;
		}
		else if (global_data->lvs_syncd.syncid == PARAMETER_UNSET) {
			/* If no syncid configured, use vrid */
			global_data->lvs_syncd.syncid = global_data->lvs_syncd.vrrp->vrid;
		}

		/* vrrp_name is no longer used */
		FREE_PTR(global_data->lvs_syncd.vrrp_name);
		global_data->lvs_syncd.vrrp_name = NULL;
	}
#endif

	/* Identify and remove any unused tracking scripts */
	if (!LIST_ISEMPTY(vrrp_data->vrrp_script)) {
		for (e = LIST_HEAD(vrrp_data->vrrp_script); e; e = next) {
			next = e->next;
			vrrp_script_t *scr = ELEMENT_DATA(e);
			if (LIST_ISEMPTY(scr->tracking_vrrp)) {
				log_message(LOG_INFO, "Warning - script %s is not used", scr->sname);
				free_list_element(vrrp_data->vrrp_script, e);
			}
		}
	}

	alloc_vrrp_buffer(max_mtu_len);

	return true;
}

void vrrp_restore_interfaces_startup(void)
{
	element e;
	vrrp_t *vrrp;

	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (vrrp->vipset)
			vrrp_restore_interface(vrrp, false, true);
	}
}

/* Clear VIP|EVIP not present into the new data */
static void
clear_diff_vrrp_vip_list(vrrp_t *vrrp, struct ipt_handle* h, list l, list n)
{
	clear_diff_address(h, l, n);

	if (LIST_ISEMPTY(n))
		return;

	/* Clear iptable rule to VIP if needed. */
	if (vrrp->base_priority == VRRP_PRIO_OWNER || vrrp->accept) {
		handle_iptable_rule_to_iplist(h, n, IPADDRESS_DEL, false);
		vrrp->iptable_rules_set = false;
	} else
		vrrp->iptable_rules_set = true;
}

static void
clear_diff_vrrp_vip(vrrp_t *old_vrrp, vrrp_t *vrrp)
{
#ifdef _HAVE_LIBIPTC_
	int tries = 0;
	int res = 0;
#endif
	struct ipt_handle *h = NULL;

	if (!old_vrrp->vipset)
		return;

#ifdef _HAVE_LIBIPTC_
	do {
#ifdef _LIBIPTC_DYNAMIC_
		if ((vrrp->family == AF_INET && using_libip4tc) ||
		    (vrrp->family == AF_INET6 && using_libip6tc))
#endif
			h = iptables_open();
#endif
		clear_diff_vrrp_vip_list(vrrp, h, old_vrrp->vip, vrrp->vip);
		clear_diff_vrrp_vip_list(vrrp, h, old_vrrp->evip, vrrp->evip);
#ifdef _HAVE_LIBIPTC_
#ifdef _LIBIPTC_DYNAMIC_
		if (h)
#endif
			res = iptables_close(h);
	} while (res == EAGAIN && ++tries < IPTABLES_MAX_TRIES);
#endif
}

#ifdef _HAVE_FIB_ROUTING_
/* Clear virtual routes not present in the new data */
static void
clear_diff_vrrp_vroutes(vrrp_t *old_vrrp, vrrp_t *vrrp)
{
	clear_diff_routes(old_vrrp->vroutes, vrrp->vroutes);
}

/* Clear virtual rules not present in the new data */
static void
clear_diff_vrrp_vrules(vrrp_t *old_vrrp, vrrp_t *vrrp)
{
	clear_diff_rules(old_vrrp->vrules, vrrp->vrules);
}
#endif

/* Keep the state from before reload */
static bool
restore_vrrp_state(vrrp_t *old_vrrp, vrrp_t *vrrp)
{
	bool added_ip_addr = false;

	/* Keep VRRP state, ipsec AH seq_number */
	vrrp->state = old_vrrp->state;
	vrrp->reload_master = old_vrrp->state == VRRP_STATE_MAST;
	vrrp->wantstate = old_vrrp->wantstate;
	if (!old_vrrp->sync && vrrp->base_priority != VRRP_PRIO_OWNER) {
		vrrp->total_priority = old_vrrp->total_priority + vrrp->base_priority - old_vrrp->base_priority;
		vrrp->effective_priority = (vrrp->total_priority < 0) ? 0 :
					   (vrrp->total_priority >= VRRP_PRIO_OWNER) ? VRRP_PRIO_OWNER - 1 :
					   (uint8_t)vrrp->total_priority;
	}

	/* Save old stats */
	memcpy(vrrp->stats, old_vrrp->stats, sizeof(vrrp_stats));

#ifdef _WITH_VRRP_AUTH_
	memcpy(&vrrp->ipsecah_counter, &old_vrrp->ipsecah_counter, sizeof(seq_counter_t));
#endif

	/* Remember if we had vips up and add new ones if needed */
	vrrp->vipset = old_vrrp->vipset;
	if (vrrp->vipset) {
		vrrp_handle_accept_mode(vrrp, IPADDRESS_ADD, false);
		if (!LIST_ISEMPTY(vrrp->vip))
			added_ip_addr = vrrp_handle_ipaddress(vrrp, IPADDRESS_ADD, VRRP_VIP_TYPE, false);
		if (!LIST_ISEMPTY(vrrp->evip)) {
			if (vrrp_handle_ipaddress(vrrp, IPADDRESS_ADD, VRRP_EVIP_TYPE, false))
				added_ip_addr = true;
		}
#ifdef _HAVE_FIB_ROUTING_
		if (!LIST_ISEMPTY(vrrp->vroutes))
			vrrp_handle_iproutes(vrrp, IPROUTE_ADD);
		if (!LIST_ISEMPTY(vrrp->vrules))
			vrrp_handle_iprules(vrrp, IPRULE_ADD, false);
#endif
	}

	return added_ip_addr;
}

/* Diff when reloading configuration */
void
clear_diff_vrrp(void)
{
	element e;
	list l = old_vrrp_data->vrrp;
	vrrp_t *vrrp;

	if (LIST_ISEMPTY(l))
		return;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		vrrp_t *new_vrrp;

		/*
		 * Try to find this vrrp in the new conf data
		 * reloaded.
		 */
		new_vrrp = vrrp_exist(vrrp);
		if (!new_vrrp) {
			vrrp_restore_interface(vrrp, true, false);

#ifdef _HAVE_VRRP_VMAC_
// TODO - the vmac may be being used by another instance
			/* Remove VMAC if one was created */
			if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags))
				netlink_link_del_vmac(vrrp);
#endif
#ifdef _WITH_DBUS_
			/* Remove DBus object */
			if (global_data->enable_dbus)
				dbus_remove_object(vrrp);
#endif
		} else {
			/*
			 * If this vrrp instance exist in new
			 * data, then perform a VIP|EVIP diff.
			 */
			clear_diff_vrrp_vip(vrrp, new_vrrp);

#ifdef _HAVE_FIB_ROUTING_
			/* virtual routes diff */
			clear_diff_vrrp_vroutes(vrrp, new_vrrp);

			/* virtual rules diff */
			clear_diff_vrrp_vrules(vrrp, new_vrrp);
#endif

#ifdef _HAVE_VRRP_VMAC_
			/*
			 * Remove VMAC if it existed in old vrrp instance,
			 * but not the new one.
			 */
			if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags) &&
			    !__test_bit(VRRP_VMAC_BIT, &new_vrrp->vmac_flags)) {
// TODO - the vmac may be being used by another instance
				netlink_link_del_vmac(vrrp);
			}
#endif

			/* reset the state */
			if (restore_vrrp_state(vrrp, new_vrrp)) {
				/* There were addresses added, so set GARP/GNA for them.
				 * This is a bit over the top since it will send GARPs/GNAs for
				 * all the addresses, but at least we will do so for the new addresses. */
				vrrp_send_link_update(new_vrrp, new_vrrp->garp_rep);

				/* set refresh timer */
				if (timerisset(&new_vrrp->garp_refresh))
					new_vrrp->garp_refresh_timer = timer_add_now(new_vrrp->garp_refresh);
			}
		}
	}
}

/* Set script status to a sensible value on reload */
void
clear_diff_script(void)
{
	element e;
	vrrp_script_t *vscript, *nvscript;

	LIST_FOREACH(old_vrrp_data->vrrp_script, vscript, e) {
		nvscript = find_script_by_name(vscript->sname);
		if (nvscript) {
			/* Set the script result to match the previous result */
			if (vscript->result < vscript->rise) {
				if (!vscript->result)
					nvscript->result = 0;
				else {
					nvscript->result = nvscript->rise - (vscript->rise - vscript->result);
					if (nvscript->result < 0)
						nvscript->result = 0;
				}
				log_message(LOG_INFO, "VRRP_Script(%s) considered unsuccessful on reload", nvscript->sname);
			} else {
				if (vscript->result == vscript->rise + vscript->fall - 1)
					nvscript->result = nvscript->rise + nvscript->fall - 1;
				else {
					nvscript->result = nvscript->rise + (vscript->result - vscript->rise);
					if (nvscript->result >= nvscript->rise + nvscript->fall)
						nvscript->result = nvscript->rise + nvscript->fall - 1;
				}
				log_message(LOG_INFO, "VRRP_Script(%s) considered successful on reload", nvscript->sname);
			}
			nvscript->last_status = vscript->last_status;
			nvscript->init_state = SCRIPT_INIT_STATE_DONE;
		}
	}
}

#ifdef _WITH_BFD_
/* Set bfd status to match old instance */
void
clear_diff_bfd(void)
{
	element e;
	vrrp_tracked_bfd_t *vbfd, *nvbfd;

	LIST_FOREACH(old_vrrp_data->vrrp_track_bfds, vbfd, e) {
		nvbfd = find_vrrp_tracked_bfd_by_name(vbfd->bname);
		if (nvbfd)
			vbfd->bfd_up = nvbfd->bfd_up;
	}
}
#endif
