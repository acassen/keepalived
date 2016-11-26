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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

/* local include */
#include "vrrp_arp.h"
#include "vrrp_ndisc.h"
#include "vrrp_scheduler.h"
#include "vrrp_notify.h"
#include "ipvswrapper.h"
#include "vrrp.h"
#include "vrrp_data.h"
#include "vrrp_sync.h"
#include "vrrp_index.h"
#include "vrrp_if.h"
#ifdef _HAVE_VRRP_VMAC_
#include "vrrp_vmac.h"
#endif
#include "vrrp_if_config.h"
#ifdef _HAVE_LIBIPTC_
#include "vrrp_iptables.h"
#endif
#ifdef _WITH_SNMP_
#include "vrrp_snmp.h"
#endif
#include "memory.h"
#include "list.h"
#include "logger.h"
#include "main.h"
#include "utils.h"
#include "notify.h"
#include "bitops.h"
#include "vrrp_netlink.h"
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

#include <netinet/ip.h>
#include <netinet/ip6.h>

/* add/remove Virtual IP addresses */
static bool
vrrp_handle_ipaddress(vrrp_t * vrrp, int cmd, int type)
{
	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "VRRP_Instance(%s) %s protocol %s", vrrp->iname,
		       (cmd == IPADDRESS_ADD) ? "setting" : "removing",
		       (type == VRRP_VIP_TYPE) ? "VIPs." : "E-VIPs.");
	return netlink_iplist((type == VRRP_VIP_TYPE) ? vrrp->vip : vrrp->evip, cmd);
}

#ifdef _HAVE_FIB_ROUTING_
/* add/remove Virtual routes */
static void
vrrp_handle_iproutes(vrrp_t * vrrp, int cmd)
{
	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "VRRP_Instance(%s) %s protocol Virtual Routes",
		       vrrp->iname,
		       (cmd == IPROUTE_ADD) ? "setting" : "removing");
	netlink_rtlist(vrrp->vroutes, cmd);
}

/* add/remove Virtual rules */
static void
vrrp_handle_iprules(vrrp_t * vrrp, int cmd, bool force)
{
	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "VRRP_Instance(%s) %s protocol Virtual Rules",
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
			log_message(LOG_INFO, "VRRP_Instance(%s) %s protocol %s", vrrp->iname,
				(cmd == IPADDRESS_ADD) ? "setting" : "removing", "iptable drop rule");

#ifdef _HAVE_LIBIPTC_
		do {
			h = iptables_open();
#endif
			/* As accept is false, add iptable rule to drop packets destinated to VIPs and eVIPs */
			if (!LIST_ISEMPTY(vrrp->vip))
				handle_iptable_rule_to_iplist(h, vrrp->vip, cmd, force);
			if (!LIST_ISEMPTY(vrrp->evip))
				handle_iptable_rule_to_iplist(h, vrrp->evip, cmd, force);
#ifdef _HAVE_LIBIPTC_
			res = iptables_close(h);
		} while (res == EAGAIN && ++tries < IPTABLES_MAX_TRIES);
#endif
		vrrp->iptable_rules_set = (cmd == IPADDRESS_ADD);
	}
}

/* Check that the scripts are secure */
static int
check_track_script_secure(tracked_sc_t *script)
{
	notify_script_t ns;
	int flags;

	if (script->scr->insecure)
		return 0;

	ns.name = script->scr->script;
	ns.uid = script->scr->uid;
	ns.gid = script->scr->gid;

	flags = check_script_secure(&ns, global_data->script_security, false);

	/* Mark not to run if needs inhibiting */
	if (flags & SC_INHIBIT) {
		log_message(LOG_INFO, "Disabling track script %s due to insecure", script->scr->sname);
		script->scr->insecure = true;
	}
	else if (flags & SC_NOTFOUND) {
		log_message(LOG_INFO, "Disabling track script %s since not found", script->scr->sname);
		script->scr->insecure = true;
	}
	else if (!(flags & SC_EXECUTABLE))
		script->scr->insecure = true;

	return flags;
}

static void
check_vrrp_script_security(void)
{
	element e, e1;
	vrrp_t *vrrp;
	vrrp_sgroup_t *sg;
	tracked_sc_t *track_script;
	int script_flags = 0;

	if (LIST_ISEMPTY(vrrp_data->vrrp))
		return;

	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		script_flags |= check_notify_script_secure(&vrrp->script_backup, global_data->script_security, false);
		script_flags |= check_notify_script_secure(&vrrp->script_master, global_data->script_security, false);
		script_flags |= check_notify_script_secure(&vrrp->script_fault, global_data->script_security, false);
		script_flags |= check_notify_script_secure(&vrrp->script_stop, global_data->script_security, false);
		script_flags |= check_notify_script_secure(&vrrp->script, global_data->script_security, true);

		if (LIST_ISEMPTY(vrrp->track_script))
			continue;

		for (e1 = LIST_HEAD(vrrp->track_script); e1; ELEMENT_NEXT(e1)) {
			track_script = ELEMENT_DATA(e1);
			script_flags |= check_track_script_secure(track_script);
		}
	}

	if (!LIST_ISEMPTY(vrrp_data->vrrp_sync_group)) {
		for (e = LIST_HEAD(vrrp_data->vrrp_sync_group); e; ELEMENT_NEXT(e)) {
			sg = ELEMENT_DATA(e);
			script_flags |= check_notify_script_secure(&sg->script_backup, global_data->script_security, false);
			script_flags |= check_notify_script_secure(&sg->script_master, global_data->script_security, false);
			script_flags |= check_notify_script_secure(&sg->script_fault, global_data->script_security, false);
			script_flags |= check_notify_script_secure(&sg->script, global_data->script_security, true);
		}
	}

	if (!global_data->script_security && script_flags & SC_ISSCRIPT) {
		log_message(LOG_INFO, "SECURITY VIOLATION - scripts are being executed but script_security not enabled.%s",
				script_flags & SC_INSECURE ? " There are insecure scripts." : "");
	}
}

/* IP header length */
static size_t
vrrp_iphdr_len(void)
{
	return sizeof(struct iphdr);
}

#ifdef _WITH_VRRP_AUTH_
/* IPSEC AH header length */
static size_t
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
		if (iph->protocol == IPPROTO_IPSEC_AH) {
			*proto = IPPROTO_IPSEC_AH;
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

#ifdef _WITH_VRRP_AUTH_
/*
 * IPSEC AH incoming packet check.
 * return 0 for a valid pkt, != 0 otherwise.
 */
static int
vrrp_in_chk_ipsecah(vrrp_t * vrrp, char *buffer)
{
	struct iphdr *ip = (struct iphdr *) (buffer);
	ipsec_ah_t *ah = (ipsec_ah_t *) ((char *) ip + (ip->ihl << 2));
	unsigned char digest[MD5_DIGEST_LENGTH];
	uint32_t backup_auth_data[3];

	/* first verify that the SPI value is equal to src IP */
	if (ah->spi != ip->saddr) {
		log_message(LOG_INFO, "IPSEC AH : invalid IPSEC SPI value. %d and expect %d",
			    ip->saddr, ah->spi);
		++vrrp->stats->auth_failure;
		return 1;
	}

	/*
	 * then proceed with the sequence number to prevent against replay attack.
	 * For inbound processing, we increment seq_number counter to audit
	 * sender counter.
	 */
	vrrp->ipsecah_counter->seq_number++;
	if (ntohl(ah->seq_number) >= vrrp->ipsecah_counter->seq_number ||
	    vrrp->sync
#ifdef _HAVE_VRRP_VMAC_
	    || __test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags)
#endif
							) {
		vrrp->ipsecah_counter->seq_number = ntohl(ah->seq_number);
	} else {
		log_message(LOG_INFO, "VRRP_Instance(%s) IPSEC-AH : sequence number %d"
					" already proceeded. Packet dropped. Local(%d)",
					vrrp->iname, ntohl(ah->seq_number),
					vrrp->ipsecah_counter->seq_number);
		++vrrp->stats->auth_failure;
		return 1;
	}

	/*
	 * then compute a ICV to compare with the one present in AH pkt.
	 * alloc a temp memory space to stock the ip mutable fields
	 */

	/* zero the ip mutable fields */
	ip->tos = 0;
	ip->frag_off = 0;
	ip->check = 0;
	if (!LIST_ISEMPTY(vrrp->unicast_peer))
		ip->ttl = 0;
	memcpy(backup_auth_data, ah->auth_data, sizeof (ah->auth_data));
	memset(ah->auth_data, 0, sizeof (ah->auth_data));
	memset(digest, 0, 16);

	/* Compute the ICV */
	hmac_md5((unsigned char *) buffer,
		 vrrp_iphdr_len() + vrrp_ipsecah_len() + vrrp_pkt_len(vrrp)
		 , vrrp->auth_data, sizeof (vrrp->auth_data)
		 , digest);

	if (memcmp(backup_auth_data, digest, HMAC_MD5_TRUNC) != 0) {
		log_message(LOG_INFO, "VRRP_Instance(%s) IPSEC-AH : invalid"
				      " IPSEC HMAC-MD5 value. Due to fields mutation"
				      " or bad password !",
			    vrrp->iname);
		++vrrp->stats->auth_failure;
		return 1;
	}

	return 0;
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
			       "(%s): ip/vrrp header too short. %zu and expect at least %zu",
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
			log_message(LOG_INFO, "(%s): invalid ttl. %d and expect %d",
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
			       "(%s): vrrp header too short. %zu and expect at least %zu",
			      vrrp->iname, buflen, sizeof(vrrphdr_t));
			++vrrp->stats->packet_len_err;
			return VRRP_PACKET_KO;
		}

		hd = (vrrphdr_t *) buffer;

		/* Set expected vrrp packet length */
		expected_len = sizeof(vrrphdr_t) + (LIST_ISEMPTY(vrrp->vip) ? 0 : LIST_SIZE(vrrp->vip)) * sizeof(struct in6_addr);
	} else {
		log_message(LOG_INFO, "(%s): configured address family is %d, which is neither AF_INET or AF_INET6. This is probably a bug - please report", vrrp->iname, vrrp->family);
		return VRRP_PACKET_KO;
	}

	/* MUST verify the VRRP version */
	if ((hd->vers_type >> 4) != vrrp->version) {
		log_message(LOG_INFO, "(%s): invalid version. %d and expect %d",
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
		log_message(LOG_INFO, "(%s): Invalid packet type. %d and expect %d",
			vrrp->iname, (hd->vers_type & 0x0f), VRRP_PKT_ADVERT);
		++vrrp->stats->invalid_type_rcvd;
		return VRRP_PACKET_KO;
	}

	/* MUST verify that the VRID is valid on the receiving interface_t */
	if (vrrp->vrid != hd->vrid) {
		log_message(LOG_INFO,
		       "(%s): received VRID mismatch. Received %d, Expected %d",
		       vrrp->iname, hd->vrid, vrrp->vrid);
#ifdef _WITH_SNMP_RFC_
		vrrp->stats->vrid_err++;
#ifdef _WITH_SNMP_RFCV3_
		vrrp->stats->proto_err_reason = vrIdError;
		vrrp_rfcv3_snmp_proto_err_notify(vrrp);
#endif
#endif
		return VRRP_PACKET_DROP;
	}

	/* Check that auth type of packet is one of the supported auth types */
	if (vrrp->version == VRRP_VERSION_2 &&
#ifdef _WITH_VRRP_AUTH_
		hd->v2.auth_type != VRRP_AUTH_AH &&
		hd->v2.auth_type != VRRP_AUTH_PASS &&
#endif
		hd->v2.auth_type != VRRP_AUTH_NONE) {
		log_message(LOG_INFO, "(%s): Invalid auth type: %d", vrrp->iname, hd->v2.auth_type);
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
	if (vrrp->version == VRRP_VERSION_2 &&
	    vrrp->auth_type != hd->v2.auth_type) {
		log_message(LOG_INFO, "(%s): received a %d auth, expecting %d!",
		       vrrp->iname, hd->v2.auth_type, vrrp->auth_type);
		++vrrp->stats->authtype_mismatch;
#ifdef _WITH_SNMP_RFCV2_
		vrrp_rfcv2_snmp_auth_err_trap(vrrp, ((struct sockaddr_in *)&vrrp->pkt_saddr)->sin_addr, authTypeMismatch);
#endif
		return VRRP_PACKET_KO;
	}

	if (vrrp->version == VRRP_VERSION_2 && vrrp->family == AF_INET) {
		/* check the authentication if it is a passwd */
		if (hd->v2.auth_type == VRRP_AUTH_PASS) {
			char *pw = (char *) ip + ntohs(ip->tot_len)
			    - sizeof (vrrp->auth_data);
			if (memcmp(pw, vrrp->auth_data, sizeof(vrrp->auth_data)) != 0) {
				log_message(LOG_INFO, "(%s): received an invalid passwd!", vrrp->iname);
				++vrrp->stats->auth_failure;
#ifdef _WITH_SNMP_RFCV2_
				vrrp_rfcv2_snmp_auth_err_trap(vrrp, ((struct sockaddr_in *)&vrrp->pkt_saddr)->sin_addr, authFailure);
#endif
				return VRRP_PACKET_KO;
			}
		}

		/* check the authenicaion if it is ipsec ah */
		else if (hd->v2.auth_type == VRRP_AUTH_AH) {
			if (vrrp_in_chk_ipsecah(vrrp, buffer)) {
#ifdef _WITH_SNMP_RFCV2_
				vrrp_rfcv2_snmp_auth_err_trap(vrrp, ((struct sockaddr_in *)&vrrp->pkt_saddr)->sin_addr, authFailure);
#endif
				return VRRP_PACKET_KO;
			}
		}
	}
#endif

	if ((LIST_ISEMPTY(vrrp->vip) && hd->naddr > 0) ||
	    (!LIST_ISEMPTY(vrrp->vip) && LIST_SIZE(vrrp->vip) != hd->naddr)) {
		log_message(LOG_INFO, "(%s): received an invalid ip number count %d, expected %d!",
			vrrp->iname, hd->naddr, LIST_ISEMPTY(vrrp->vip) ? 0 : LIST_SIZE(vrrp->vip));
		++vrrp->stats->addr_list_err;
		return VRRP_PACKET_KO;
	}

	/*
	 * MUST verify that the Adver Interval in the packet is the same as
	 * the locally configured for this virtual router if VRRPv2
	 */
	if (vrrp->version == VRRP_VERSION_2) {
		adver_int = hd->v2.adver_int * TIMER_HZ;
		if (vrrp->adver_int != adver_int) {
			log_message(LOG_INFO, "(%s): advertisement interval mismatch mine=%d sec rcved=%d sec",
				vrrp->iname, vrrp->adver_int / TIMER_HZ, adver_int / TIMER_HZ);
			/* to prevent concurent VRID running => multiple master in 1 VRID */
			return VRRP_PACKET_DROP;
		}
	}

	if (vrrp->family == AF_INET && ntohs(ip->tot_len) != buflen) {
		log_message(LOG_INFO,
		       "(%s): ip_tot_len mismatch against received length. %d and received %zu",
		       vrrp->iname, ntohs(ip->tot_len), buflen);
		++vrrp->stats->packet_len_err;
		return VRRP_PACKET_KO;
	}

	if (expected_len != buflen) {
		log_message(LOG_INFO,
		       "(%s): Received packet length mismatch against expected. %zu and expect %zu",
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
			ipv4_phdr.dst   = htonl(INADDR_VRRP_GROUP);
			ipv4_phdr.zero  = 0;
			ipv4_phdr.proto = IPPROTO_VRRP;
			ipv4_phdr.len   = htons(vrrppkt_len);

			in_csum((u_short *) &ipv4_phdr, sizeof(ipv4_phdr), 0, &acc_csum);
			if (in_csum((u_short *) hd, vrrppkt_len, acc_csum, NULL)) {
				log_message(LOG_INFO, "(%s): Invalid VRRPv3 checksum", vrrp->iname);
#ifdef _WITH_SNMP_RFC_
				vrrp->stats->chk_err++;
#ifdef _WITH_SNMP_RFCV3_
				vrrp->stats->proto_err_reason = checksumError;
				vrrp_rfcv3_snmp_proto_err_notify(vrrp);
#endif
#endif
				return VRRP_PACKET_KO;
			}
		} else {
			vrrppkt_len += VRRP_AUTH_LEN;
			if (in_csum((u_short *) hd, vrrppkt_len, 0, NULL)) {
				log_message(LOG_INFO, "(%s): Invalid VRRPv2 checksum", vrrp->iname);
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
						log_message(LOG_INFO, "(%s): ip address associated with VRID %d"
						       " not present in MASTER advert : %s",
						       vrrp->iname, vrrp->vrid,
						       inet_ntop2(ipaddress->u.sin.sin_addr.s_addr));
						++vrrp->stats->addr_list_err;
						return VRRP_PACKET_KO;
					}
				}
			}

			// check a unicast source address is in the unicast_peer list
			if (global_data->vrrp_check_unicast_src && !LIST_ISEMPTY(vrrp->unicast_peer)) {
				for (e = LIST_HEAD(vrrp->unicast_peer); e; ELEMENT_NEXT(e)) {
					up_addr = ELEMENT_DATA(e);
					if (((struct sockaddr_in *)&vrrp->pkt_saddr)->sin_addr.s_addr == ((struct sockaddr_in *)up_addr)->sin_addr.s_addr)
						break;
				}
				if (!e) {
					log_message(LOG_INFO, "(%s): unicast source address %s not a unicast peer",
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
						"(%s): receive an invalid ip number count associated with VRID!", vrrp->iname);
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
					log_message(LOG_INFO, "(%s): unicast source address %s not a unicast peer",
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
		/* In v3 when we are in BACKUP state, we set our
		 * advertisement interval to match the MASTER's. */
		adver_int = (ntohs(hd->v3.adver_int) & 0x0FFF) * TIMER_CENTI_HZ;
		if (vrrp->master_adver_int != adver_int)
			log_message(LOG_INFO, "(%s): advertisement interval changed: mine=%d milli-sec, rcved=%d milli-sec",
				vrrp->iname, vrrp->master_adver_int / (TIMER_HZ / 1000), adver_int / (TIMER_HZ / 1000));
	}

	return VRRP_PACKET_OK;
}

/* build IP header */
static void
vrrp_build_ip4(vrrp_t * vrrp, char *buffer, uint32_t dst)
{
	struct iphdr *ip = (struct iphdr *) (buffer);

	ip->ihl = sizeof(struct iphdr) >> 2;
	ip->version = 4;
	/* set tos to internet network control */
	ip->tos = 0xc0;
	ip->tot_len = (uint16_t)(sizeof (struct iphdr) + vrrp_pkt_len(vrrp));
	ip->tot_len = htons(ip->tot_len);
	ip->id = htons(++vrrp->ip_id);
	/* kernel will fill in ID if left to 0, so we overflow to 1 */
	if (vrrp->ip_id == 65535)
		vrrp->ip_id = 1;
	ip->frag_off = 0;
	ip->ttl = VRRP_IP_TTL;

	/* fill protocol type --rfc2402.2 */
#ifdef _WITH_VRRP_AUTH_
	ip->protocol = (vrrp->auth_type == VRRP_AUTH_AH) ? IPPROTO_IPSEC_AH : IPPROTO_VRRP;
#else
	ip->protocol = IPPROTO_VRRP;
#endif

	ip->saddr = VRRP_PKT_SADDR(vrrp);
	ip->daddr = dst;

	/* checksum must be done last */
	ip->check = in_csum((u_short *) ip, ip->ihl * 4U, 0, NULL);
}

#ifdef _WITH_VRRP_AUTH_
/* build IPSEC AH header */
static void
vrrp_build_ipsecah(vrrp_t * vrrp, char *buffer, size_t buflen)
{
	ICV_mutable_fields ip_mutable_fields;
	unsigned char digest[MD5_DIGEST_LENGTH];
	struct iphdr *ip = (struct iphdr *) (buffer);
	ipsec_ah_t *ah = (ipsec_ah_t *) (buffer + sizeof (struct iphdr));

	/* fill in next header filed --rfc2402.2.1 */
	ah->next_header = IPPROTO_VRRP;

	/* update IP header total length value */
	ip->tot_len = htons(ntohs(ip->tot_len) + vrrp_ipsecah_len());

	/* update ip checksum */
	ip->check = 0;
	ip->check = in_csum((u_short *) ip, ip->ihl * 4U, 0, NULL);

	/* backup the ip mutable fields */
	ip_mutable_fields.tos = ip->tos;
	ip_mutable_fields.ttl = ip->ttl;
	ip_mutable_fields.frag_off = ip->frag_off;
	ip_mutable_fields.check = ip->check;

	/* zero the ip mutable fields */
	ip->tos = 0;
	ip->frag_off = 0;
	ip->check = 0;
	if (!LIST_ISEMPTY(vrrp->unicast_peer))
		ip->ttl = 0;

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

	/* Processing sequence number.
	   Cycled assumed if 0xFFFFFFFD reached. So the MASTER state is free for another srv.
	   Here can result a flapping MASTER state owner when max seq_number value reached.
	   => Much work needed here.
	   In the current implementation if counter has cycled, we stop sending adverts and
	   become BACKUP. If all the master are down we reset the counter for becoming MASTER.
	 */
	if (vrrp->ipsecah_counter->seq_number > 0xFFFFFFFD) {
		vrrp->ipsecah_counter->cycle = 1;
	} else {
		vrrp->ipsecah_counter->seq_number++;
	}

	ah->seq_number = htonl(vrrp->ipsecah_counter->seq_number);

	/* Compute the ICV & trunc the digest to 96bits
	   => No padding needed.
	   -- rfc2402.3.3.3.1.1.1 & rfc2401.5
	 */
	hmac_md5((unsigned char *) buffer, buflen, vrrp->auth_data, sizeof (vrrp->auth_data)
		 , digest);
	memcpy(ah->auth_data, digest, HMAC_MD5_TRUNC);

	/* Restore the ip mutable fields */
	ip->tos = ip_mutable_fields.tos;
	ip->frag_off = ip_mutable_fields.frag_off;
	ip->check = ip_mutable_fields.check;
	ip->ttl = ip_mutable_fields.ttl;
}
#endif

/* build VRRPv2 header */
static int
vrrp_build_vrrp_v2(vrrp_t *vrrp, uint8_t prio, char *buffer)
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
	hd->priority = prio;
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

		/* finaly compute vrrp checksum */
		hd->chksum = 0;
		hd->chksum = in_csum((u_short *) hd, vrrp_pkt_len(vrrp), 0, NULL);
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

	return 0;
}

/* build VRRPv3 header */
static int
vrrp_build_vrrp_v3(vrrp_t *vrrp, uint8_t prio, char *buffer)
{
	int i = 0;
	vrrphdr_t *hd = (vrrphdr_t *) buffer;
	struct in_addr *iparr;
	struct in6_addr *ip6arr;
	element e;
	ip_address_t *ip_addr;
	ipv4_phdr_t ipv4_phdr;
	uint32_t acc_csum;

	/* Family independant */
	hd->vers_type = (VRRP_VERSION_3 << 4) | VRRP_PKT_ADVERT;
	hd->vrid = vrrp->vrid;
	hd->priority = prio;
	hd->naddr = (uint8_t)((!LIST_ISEMPTY(vrrp->vip)) ? LIST_SIZE(vrrp->vip) : 0);
	hd->v3.adver_int  = htons((vrrp->adver_int / TIMER_CENTI_HZ) & 0x0FFF); /* interval in centiseconds, reserved bits zero */

	/* Family specific */
	if (vrrp->family == AF_INET) {
		/* copy the ip addresses */
		iparr = (struct in_addr *) ((char *) hd + sizeof(*hd));
		if (!LIST_ISEMPTY(vrrp->vip)) {
			for (e = LIST_HEAD(vrrp->vip); e; ELEMENT_NEXT(e)) {
				ip_addr = ELEMENT_DATA(e);
				iparr[i++] = ip_addr->u.sin.sin_addr;
			}
		}

		/* Create IPv4 pseudo-header */
		ipv4_phdr.src   = VRRP_PKT_SADDR(vrrp);
		ipv4_phdr.dst   = htonl(INADDR_VRRP_GROUP);
		ipv4_phdr.zero  = 0;
		ipv4_phdr.proto = IPPROTO_VRRP;
		ipv4_phdr.len   = htons(vrrp_pkt_len(vrrp));

		/* finaly compute vrrp checksum */
		in_csum((u_short *) &ipv4_phdr, sizeof(ipv4_phdr), 0, &acc_csum);
		hd->chksum = in_csum((u_short *) hd, vrrp_pkt_len(vrrp), acc_csum, NULL);
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

	return 0;
}

/* build VRRP header */
static int
vrrp_build_vrrp(vrrp_t *vrrp, uint8_t prio, char *buffer)
{
	if (vrrp->version == VRRP_VERSION_3)
		return vrrp_build_vrrp_v3(vrrp, prio, buffer);

	return vrrp_build_vrrp_v2(vrrp, prio, buffer);
}

/* build VRRP packet */
static void
vrrp_build_pkt(vrrp_t * vrrp, uint8_t prio, struct sockaddr_storage *addr)
{
	char *bufptr;
	uint32_t dst;
	size_t len;

	/* save reference values */
	bufptr = VRRP_SEND_BUFFER(vrrp);
	len = VRRP_SEND_BUFFER_SIZE(vrrp);

	if (vrrp->family == AF_INET) {
		/* build the ip header */
		dst = (addr) ? inet_sockaddrip4(addr) :
			       ((struct sockaddr_in *) &global_data->vrrp_mcast_group4)->sin_addr.s_addr;
		vrrp_build_ip4(vrrp, bufptr, dst);

		/* build the vrrp header */
		vrrp->send_buffer += vrrp_iphdr_len();

#ifdef _WITH_VRRP_AUTH_
		if (vrrp->auth_type == VRRP_AUTH_AH)
			vrrp->send_buffer += vrrp_ipsecah_len();
#endif
		vrrp->send_buffer_size -= vrrp_iphdr_len();

#ifdef _WITH_VRRP_AUTH_
		if (vrrp->auth_type == VRRP_AUTH_AH)
			vrrp->send_buffer_size -= vrrp_ipsecah_len();
#endif
		vrrp_build_vrrp(vrrp, prio, vrrp->send_buffer);

#ifdef _WITH_VRRP_AUTH_
		/* build the IPSEC AH header */
		if (vrrp->auth_type == VRRP_AUTH_AH) {
			vrrp->send_buffer_size += vrrp_iphdr_len() + vrrp_ipsecah_len();
			vrrp_build_ipsecah(vrrp, bufptr, VRRP_SEND_BUFFER_SIZE(vrrp));
		}
#endif
	} else if (vrrp->family == AF_INET6) {
		vrrp_build_vrrp(vrrp, prio, VRRP_SEND_BUFFER(vrrp));
	}

	/* restore reference values */
	vrrp->send_buffer = bufptr;
	vrrp->send_buffer_size = len;
}

/* send VRRP packet */
static int
vrrp_build_ancillary_data(struct msghdr *msg, char *cbuf, struct sockaddr_storage *src)
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
	pkt->ipi6_ifindex = ((struct sockaddr_in6 *) src)->sin6_scope_id;

	return 0;
}

static ssize_t
vrrp_send_pkt(vrrp_t * vrrp, struct sockaddr_storage *addr)
{
	struct sockaddr_storage *src = &vrrp->saddr;
	struct sockaddr_in6 dst6;
	struct sockaddr_in dst4;
	struct msghdr msg;
	struct iovec iov;
	char cbuf[256];

	/* Build the message data */
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = VRRP_SEND_BUFFER(vrrp);
	iov.iov_len = VRRP_SEND_BUFFER_SIZE(vrrp);

	/* Unicast sending path */
	if (addr && addr->ss_family == AF_INET) {
		msg.msg_name = (struct sockaddr_in *) addr;
		msg.msg_namelen = sizeof(struct sockaddr_in);
	} else if (addr && addr->ss_family == AF_INET6) {
		msg.msg_name = (struct sockaddr_in6 *) addr;
		msg.msg_namelen = sizeof(struct sockaddr_in6);
		vrrp_build_ancillary_data(&msg, cbuf, src);
	} else if (vrrp->family == AF_INET) { /* Multicast sending path */
		memset(&dst4, 0, sizeof(dst4));
		dst4.sin_family = AF_INET;
		dst4.sin_addr = ((struct sockaddr_in *) &global_data->vrrp_mcast_group4)->sin_addr;
		msg.msg_name = &dst4;
		msg.msg_namelen = sizeof(dst4);
	} else if (vrrp->family == AF_INET6) {
		memset(&dst6, 0, sizeof(dst6));
		dst6.sin6_family = AF_INET6;
		dst6.sin6_addr = ((struct sockaddr_in6 *) &global_data->vrrp_mcast_group6)->sin6_addr;
		msg.msg_name = &dst6;
		msg.msg_namelen = sizeof(dst6);
		vrrp_build_ancillary_data(&msg, cbuf, src);
	}

	/* Send the packet */
	return sendmsg(vrrp->fd_out, &msg, (addr) ? 0 : MSG_DONTROUTE);
}

/* Allocate the sending buffer */
static void
vrrp_alloc_send_buffer(vrrp_t * vrrp)
{
	vrrp->send_buffer_size = vrrp_pkt_len(vrrp);

	if (vrrp->family == AF_INET) {
		vrrp->send_buffer_size += vrrp_iphdr_len();
#ifdef _WITH_VRRP_AUTH_
		if (vrrp->auth_type == VRRP_AUTH_AH)
			vrrp->send_buffer_size += vrrp_ipsecah_len();
#endif
	}

	vrrp->send_buffer = MALLOC(VRRP_SEND_BUFFER_SIZE(vrrp));
}

/* send VRRP advertisement */
int
vrrp_send_adv(vrrp_t * vrrp, uint8_t prio)
{
	struct sockaddr_storage *addr;
	list l = vrrp->unicast_peer;
	element e;
	ssize_t ret;

	/* alloc send buffer */
	if (!vrrp->send_buffer)
		vrrp_alloc_send_buffer(vrrp);
	else
		memset(vrrp->send_buffer, 0, VRRP_SEND_BUFFER_SIZE(vrrp));

	/* build the packet */
	if (!LIST_ISEMPTY(l)) {
		for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
			addr = ELEMENT_DATA(e);
			vrrp_build_pkt(vrrp, prio, addr);
			ret = vrrp_send_pkt(vrrp, addr);
			if (ret < 0) {
				log_message(LOG_INFO, "VRRP_Instance(%s) Cant send advert to %s (%m)"
						    , vrrp->iname, inet_sockaddrtos(addr));
			}
		}
	} else {
		vrrp_build_pkt(vrrp, prio, NULL);
		vrrp_send_pkt(vrrp, NULL);
	}

	++vrrp->stats->advert_sent;
	/* sent it */
	return 0;
}

/* Received packet processing */
static int
vrrp_check_packet(vrrp_t * vrrp, char *buf, ssize_t buflen, bool check_vip_addr)
{
	int ret;

	if (buflen > 0) {
		ret = vrrp_in_chk(vrrp, buf, buflen, check_vip_addr);

		if (ret == VRRP_PACKET_DROP) {
			log_message(LOG_INFO, "Sync instance needed on %s !!!",
			       IF_NAME(vrrp->ifp));
		}

		else if (ret == VRRP_PACKET_KO)
			log_message(LOG_INFO, "bogus VRRP packet received on %s !!!",
			       IF_NAME(vrrp->ifp));
		return ret;
	}

	return VRRP_PACKET_NULL;
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

		log_message(LOG_INFO, "VRRP_Instance(%s) Sending/queueing %s on %s for %s",
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
		log_message(LOG_INFO, "VRRP_Instance(%s) using locally configured advertisement interval (%d milli-sec)",
					vrrp->iname, vrrp->adver_int / (TIMER_HZ / 1000));

	/* add the ip addresses */
	vrrp_handle_accept_mode(vrrp, IPADDRESS_ADD, false);
	if (!LIST_ISEMPTY(vrrp->vip))
		vrrp_handle_ipaddress(vrrp, IPADDRESS_ADD, VRRP_VIP_TYPE);
	if (!LIST_ISEMPTY(vrrp->evip))
		vrrp_handle_ipaddress(vrrp, IPADDRESS_ADD, VRRP_EVIP_TYPE);
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
	if (!timer_isnull(vrrp->garp_refresh)) {
		vrrp->garp_refresh_timer = timer_add_now(vrrp->garp_refresh);
	}

	/* Check if notify is needed */
	notify_instance_exec(vrrp, VRRP_STATE_MAST);

#ifdef _WITH_SNMP_KEEPALIVED_
	vrrp_snmp_instance_trap(vrrp);
#endif
#ifdef _WITH_SNMP_RFCV2_
	vrrp_rfcv2_snmp_new_master_trap(vrrp);
#endif
#ifdef _WITH_SNMP_RFCV3_
	vrrp_rfcv3_snmp_new_master_notify(vrrp);
#endif

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
	/* check sync-group status */
	if (vrrp->sync && !vrrp_sync_goto_master(vrrp))
		return;

	/*
	 * Send an advertisement. To force a new master
	 * election.
	 */
	if (vrrp->sync && !vrrp_sync_goto_master(vrrp)) {
		/*
		 * Set quick sync flag to enable faster transition, i.e. check
		 * again in the next interval instead of waiting three.
		 */
		vrrp->quick_sync = 1;
		return;
	}

	vrrp_send_adv(vrrp, vrrp->effective_priority);

	vrrp->state = VRRP_STATE_MAST;
	log_message(LOG_INFO, "VRRP_Instance(%s) Transition to MASTER STATE"
			    , vrrp->iname);
}

/* leaving master state */
void
vrrp_restore_interface(vrrp_t * vrrp, bool advF, bool force)
{
	/* if we stop vrrp, warn the other routers to speed up the recovery */
	if (advF) {
		vrrp_send_adv(vrrp, VRRP_PRIO_STOP);
		++vrrp->stats->pri_zero_sent;
		syslog(LOG_INFO, "VRRP_Instance(%s) sent 0 priority",
		       vrrp->iname);
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
	 * (such as lower priority) causes astate transition to backup then
	 * keepalived doesn't remove the VIPs.  Then we have duplicate IP addresses
	 * on both master/backup.
	 */
	if (force ||
	    VRRP_VIP_ISSET(vrrp) ||
	    __test_bit(DONT_RELEASE_VRRP_BIT, &debug) ||
	    __test_bit(RELEASE_VIPS_BIT, &debug)) {
		if (!LIST_ISEMPTY(vrrp->vip))
			vrrp_handle_ipaddress(vrrp, IPADDRESS_DEL, VRRP_VIP_TYPE);
		if (!LIST_ISEMPTY(vrrp->evip))
			vrrp_handle_ipaddress(vrrp, IPADDRESS_DEL, VRRP_EVIP_TYPE);
		vrrp_handle_accept_mode(vrrp, IPADDRESS_DEL, force);
		vrrp->vipset = 0;
	}
}

void
vrrp_state_leave_master(vrrp_t * vrrp)
{
	if (VRRP_VIP_ISSET(vrrp)) {
#ifdef _WITH_LVS_
		/* Check if sync daemon handling is needed */
		if (global_data->lvs_syncd.vrrp == vrrp)
			ipvs_syncd_backup(&global_data->lvs_syncd);
#endif
	}

	/* set the new vrrp state */
	switch (vrrp->wantstate) {
	case VRRP_STATE_BACK:
		log_message(LOG_INFO, "VRRP_Instance(%s) Entering BACKUP STATE", vrrp->iname);
		vrrp_restore_interface(vrrp, false, false);
		vrrp->state = vrrp->wantstate;
		notify_instance_exec(vrrp, VRRP_STATE_BACK);
		vrrp->preempt_time.tv_sec = 0;
#ifdef _WITH_SNMP_KEEPALIVED_
		vrrp_snmp_instance_trap(vrrp);
#endif
		break;
	case VRRP_STATE_GOTO_FAULT:
		log_message(LOG_INFO, "VRRP_Instance(%s) Entering FAULT STATE", vrrp->iname);
		vrrp_restore_interface(vrrp, false, false);
		vrrp->state = VRRP_STATE_FAULT;
		notify_instance_exec(vrrp, VRRP_STATE_FAULT);
		vrrp_send_adv(vrrp, VRRP_PRIO_STOP);
#ifdef _WITH_SNMP_KEEPALIVED_
		vrrp_snmp_instance_trap(vrrp);
#endif
		break;
	}

	/* Set the down timer */
	vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
	++vrrp->stats->release_master;
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

	if (ret == VRRP_PACKET_KO || ret == VRRP_PACKET_NULL) {
		log_message(LOG_INFO, "VRRP_Instance(%s) ignoring received advertisment..."
				    ,  vrrp->iname);
		if (vrrp->version == VRRP_VERSION_3)
			vrrp->ms_down_timer = 3 * vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);
		else
			vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
	} else if (hd->priority == 0) {
		vrrp->ms_down_timer = VRRP_TIMER_SKEW(vrrp);
#ifdef _WITH_SNMP_RFCV3_
		vrrp->stats->master_reason = VRRPV3_MASTER_REASON_PRIORITY;
#endif
	} else if (vrrp->nopreempt ||
		   hd->priority >= vrrp->effective_priority ||
		   (vrrp->preempt_delay &&
		    (!vrrp->preempt_time.tv_sec ||
		     timer_cmp(vrrp->preempt_time, timer_now()) > 0))) {
		if (vrrp->version == VRRP_VERSION_3) {
			master_adver_int = (ntohs(hd->v3.adver_int) & 0x0FFF) * TIMER_CENTI_HZ;
			/* As per RFC5798, set Master_Adver_Interval to Adver Interval contained
			 * in the ADVERTISEMENT
			 */
			if (vrrp->master_adver_int != master_adver_int) {
				vrrp->master_adver_int = master_adver_int;
				log_message(LOG_INFO, "VRRP_Instance(%s) advertisement interval updated to %d milli-sec",
							vrrp->iname, vrrp->master_adver_int / (TIMER_HZ / 1000));
			}
			vrrp->ms_down_timer = 3 * vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);
		}
		else {
			vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
		}
		vrrp->master_saddr = vrrp->pkt_saddr;
		vrrp->master_priority = hd->priority;

		if (vrrp->preempt_delay) {
			if (hd->priority > vrrp->effective_priority) {
				if (vrrp->preempt_time.tv_sec) {
					log_message(LOG_INFO,
						"%s(%s) reset preempt delay",
						"VRRP_Instance", vrrp->iname);
					vrrp->preempt_time.tv_sec = 0;
				}
			} else {
				if (!vrrp->preempt_time.tv_sec) {
					log_message(LOG_INFO,
						"%s(%s) start preempt delay(%ld)",
						"VRRP_Instance", vrrp->iname,
						vrrp->preempt_delay / TIMER_HZ);
					vrrp->preempt_time = timer_add_long(timer_now(), vrrp->preempt_delay);
				}
			}
		}
	} else {
		log_message(LOG_INFO, "VRRP_Instance(%s) forcing a new MASTER election" , vrrp->iname);
		vrrp->wantstate = VRRP_STATE_GOTO_MASTER;
		vrrp_send_adv(vrrp, vrrp->effective_priority);
#ifdef _WITH_SNMP_RFCV3_
		vrrp->stats->master_reason = VRRPV3_MASTER_REASON_PREEMPTED;
#endif
	}
}

/* MASTER state processing */
int
vrrp_state_master_tx(vrrp_t * vrrp, const int prio)
{
	int ret = 0;

	if (!VRRP_VIP_ISSET(vrrp)) {
		log_message(LOG_INFO, "VRRP_Instance(%s) Entering MASTER STATE"
				    , vrrp->iname);
		vrrp_state_become_master(vrrp);
		ret = 1;
	} else if (!timer_isnull(vrrp->garp_refresh) &&
		   timer_cmp(time_now, vrrp->garp_refresh_timer) > 0) {
		vrrp_send_link_update(vrrp, vrrp->garp_refresh_rep);
		vrrp->garp_refresh_timer = timer_add_now(vrrp->garp_refresh);
	}

	vrrp_send_adv(vrrp,
		      (prio == VRRP_PRIO_OWNER) ? VRRP_PRIO_OWNER :
						  vrrp->effective_priority);
	return ret;
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

int
vrrp_state_master_rx(vrrp_t * vrrp, char *buf, ssize_t buflen)
{
	vrrphdr_t *hd;
	ssize_t ret;
	unsigned proto = 0;
	ipsec_ah_t *ah;
	unsigned master_adver_int;
	int addr_cmp;

	/* return on link failure */
	if (vrrp->wantstate == VRRP_STATE_GOTO_FAULT) {
		vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
		vrrp->state = VRRP_STATE_FAULT;
		notify_instance_exec(vrrp, VRRP_STATE_FAULT);
		vrrp->last_transition = timer_now();
		return 1;
	}

	/* Process the incoming packet */
	hd = vrrp_get_header(vrrp->family, buf, &proto);
	ret = vrrp_check_packet(vrrp, buf, buflen, true);

	if (ret == VRRP_PACKET_KO ||
	    ret == VRRP_PACKET_NULL || ret == VRRP_PACKET_DROP) {
		log_message(LOG_INFO,
		       "VRRP_Instance(%s) Dropping received VRRP packet...",
		       vrrp->iname);
		return 0;
	}

	if (hd->priority == 0) {
		vrrp_send_adv(vrrp, vrrp->effective_priority);
		return 0;
	}

	addr_cmp = vrrp_saddr_cmp(&vrrp->pkt_saddr, vrrp);

	if (hd->priority == vrrp->effective_priority && addr_cmp == 0)
			log_message(LOG_INFO, "(%s): WARNING - equal priority advert received from remote host with our IP address.", vrrp->iname);

	if (hd->priority < vrrp->effective_priority ||
		   (hd->priority == vrrp->effective_priority &&
		    addr_cmp < 0)) {
		/* We receive a lower prio adv we just refresh remote ARP cache */
		log_message(LOG_INFO, "VRRP_Instance(%s) Received advert with lower priority %d, ours %d"
				      ", forcing new election", vrrp->iname, hd->priority, vrrp->effective_priority);
		if (proto == IPPROTO_IPSEC_AH) {
			ah = (ipsec_ah_t *) (buf + sizeof(struct iphdr));
			log_message(LOG_INFO, "VRRP_Instance(%s) IPSEC-AH : Syncing seq_num"
					      " - Increment seq"
					    , vrrp->iname);
			vrrp->ipsecah_counter->seq_number = ntohl(ah->seq_number) + 1;
			vrrp->ipsecah_counter->cycle = 0;
		}
		if (!vrrp->lower_prio_no_advert)
			vrrp_send_adv(vrrp, vrrp->effective_priority);
		if (vrrp->garp_lower_prio_rep) {
			vrrp_send_link_update(vrrp, vrrp->garp_lower_prio_rep);
			if (vrrp->garp_lower_prio_delay)
				thread_add_timer(master, vrrp_lower_prio_gratuitous_arp_thread,
						 vrrp, vrrp->garp_lower_prio_delay);
		}
		return 0;
	}

	/* If we are configured as the address owner (priority == 255), and we receive an advertisement 
	 * from another system indicating it is also the address owner, then there is a clear conflict.
	 * Report a configuration error, and drop our priority as a workaround. */
	if (hd->priority == VRRP_PRIO_OWNER &&
	    vrrp->effective_priority == VRRP_PRIO_OWNER) {
		log_message(LOG_INFO, "(%s): CONFIGURATION ERROR: local instance and a remote instance are both configured as address owner, please fix - reducing local priority", vrrp->iname);
		vrrp->effective_priority--;
		if (vrrp->base_priority > 1)
			vrrp->base_priority--;
	}

	if (hd->priority > vrrp->effective_priority ||
		   (hd->priority == vrrp->effective_priority &&
		    addr_cmp > 0)) {

		log_message(LOG_INFO, "VRRP_Instance(%s) Received advert with higher priority %d, ours %d"
				    , vrrp->iname, hd->priority, vrrp->effective_priority);
		if (proto == IPPROTO_IPSEC_AH) {
			ah = (ipsec_ah_t *) (buf + sizeof(struct iphdr));
			log_message(LOG_INFO, "VRRP_Instance(%s) IPSEC-AH : Syncing seq_num"
					      " - Decrement seq"
					    , vrrp->iname);
			vrrp->ipsecah_counter->seq_number = ntohl(ah->seq_number) - 1;
			vrrp->ipsecah_counter->cycle = 0;
		}

		if (vrrp->version == VRRP_VERSION_3) {
			master_adver_int = (ntohs(hd->v3.adver_int) & 0x0FFF) * TIMER_CENTI_HZ;
			/* As per RFC5798, set Master_Adver_Interval to Adver Interval contained
			 * in the ADVERTISEMENT
			 */
			if (vrrp->master_adver_int != master_adver_int) {
				vrrp->master_adver_int = master_adver_int;
				log_message(LOG_INFO, "VRRP_Instance(%s) advertisement interval updated to %d milli-sec from higher priority master",
							vrrp->iname, vrrp->master_adver_int / (TIMER_HZ / 1000));
			}
			vrrp->ms_down_timer = 3 * vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);
		}
		else
			vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
		vrrp->master_priority = hd->priority;
		vrrp->wantstate = VRRP_STATE_BACK;
		vrrp->state = VRRP_STATE_BACK;
		return 1;
	}

	return 0;
}

int
vrrp_state_fault_rx(vrrp_t * vrrp, char *buf, ssize_t buflen)
{
	vrrphdr_t *hd;
	ssize_t ret = 0;
	unsigned proto;

	/* Process the incoming packet */
	hd = vrrp_get_header(vrrp->family, buf, &proto);
	ret = vrrp_check_packet(vrrp, buf, buflen, true);

	if (ret == VRRP_PACKET_KO || ret == VRRP_PACKET_NULL || ret == VRRP_PACKET_DROP) {
		log_message(LOG_INFO, "VRRP_Instance(%s) Dropping received VRRP packet..."
				    , vrrp->iname);
		return 0;
	} else if (vrrp->effective_priority > hd->priority) {
		if (!vrrp->nopreempt)
			return 1;
	}

	return 0;
}

/* check for minimum configuration requirements */
static bool
chk_min_cfg(vrrp_t * vrrp)
{
	if (vrrp->vrid == 0) {
		log_message(LOG_INFO, "VRRP_Instance(%s) the virtual id must be set!",
		       vrrp->iname);
		return false;
	}
	if (!vrrp->ifp) {
		log_message(LOG_INFO, "VRRP_Instance(%s) Unknown interface !",
		       vrrp->iname);
		return false;
	}

	return true;
}

/* open a VRRP sending socket */
int
open_vrrp_send_socket(sa_family_t family, int proto, ifindex_t idx, bool unicast)
{
	interface_t *ifp;
	int fd = -1;

	if (family != AF_INET && family != AF_INET6) {
		log_message(LOG_INFO, "cant open raw socket. unknown family=%d"
				    , family);
		return -1;
	}

	/* Retreive interface_t */
	ifp = if_get_by_ifindex(idx);

	/* Create and init socket descriptor */
	fd = socket(family, SOCK_RAW | SOCK_CLOEXEC, proto);
	if (fd < 0) {
		log_message(LOG_INFO, "cant open raw socket. errno=%d", errno);
		return -1;
	}
#if !HAVE_DECL_SOCK_CLOEXEC
	set_sock_flags(fd, F_SETFD, FD_CLOEXEC);
#endif

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
open_vrrp_read_socket(sa_family_t family, int proto, ifindex_t idx, bool unicast)
{
	interface_t *ifp;
	int fd = -1;

	/* Retreive interface_t */
	ifp = if_get_by_ifindex(idx);

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
	ifindex_t ifindex;
	bool unicast;

	/* close the desc & open a new one */
	close_vrrp_socket(vrrp);
	remove_vrrp_fd_bucket(vrrp);
#ifdef _WITH_VRRP_AUTH_
	if (vrrp->version == VRRP_VERSION_2)
		proto =(vrrp->auth_type == VRRP_AUTH_AH) ? IPPROTO_IPSEC_AH :
				IPPROTO_VRRP;
	else
#endif
		proto = IPPROTO_VRRP;
	ifindex =
#ifdef _HAVE_VRRP_VMAC_
		 (__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags)) ? IF_BASE_INDEX(vrrp->ifp) :
#endif
									    IF_INDEX(vrrp->ifp);
	unicast = !LIST_ISEMPTY(vrrp->unicast_peer);
	vrrp->fd_in = open_vrrp_read_socket(vrrp->family, proto, ifindex, unicast);
	vrrp->fd_out = open_vrrp_send_socket(vrrp->family, proto, ifindex, unicast);
	alloc_vrrp_fd_bucket(vrrp);

	/* Sync the other desc */
	set_vrrp_fd_bucket(old_fd, vrrp);

	return vrrp->fd_in;
}

/* handle terminate state phase 1 */
void
restore_vrrp_interfaces(void)
{
	list l = vrrp_data->vrrp;
	element e;
	vrrp_t *vrrp;

	/* Ensure any interfaces are in backup mode,
	 * sending a priority 0 vrrp message
	 */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		/* Remove VIPs/VROUTEs/VRULEs */
		if (vrrp->state == VRRP_STATE_MAST)
			vrrp_restore_interface(vrrp, true, false);
	}
}

/* handle terminate state */
void
shutdown_vrrp_instances(void)
{
	list l = vrrp_data->vrrp;
	element e;
	vrrp_t *vrrp;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		/* We may not have an ifp if we are aborting at startup */
		if (vrrp->ifp) {
#ifdef _HAVE_VRRP_VMAC_
			/* Remove VMAC */
			if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags))
				netlink_link_del_vmac(vrrp);
#endif

			if (vrrp->ifp->reset_promote_secondaries)
				reset_promote_secondaries(vrrp->ifp);
		}

		/* Run stop script */
		if (vrrp->script_stop)
			notify_exec(vrrp->script_stop);

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

/* complete vrrp structure */
static bool
vrrp_complete_instance(vrrp_t * vrrp)
{
#ifdef _HAVE_VRRP_VMAC_
	char ifname[IFNAMSIZ];
	vrrp_t *vrrp_o;
	interface_t *ifp;
#endif
	interface_t *base_ifp;
	element e;
	ip_address_t *vip;
	size_t hdr_len;
	size_t max_addr;
	size_t i;
	element next;
	bool interface_already_existed = false;

	if (vrrp->strict_mode == PARAMETER_UNSET)
		vrrp->strict_mode = global_data->vrrp_strict;

	if (vrrp->family == AF_INET6) {
		if (vrrp->version == VRRP_VERSION_2 && vrrp->strict_mode) {
			log_message(LOG_INFO,"(%s): cannot use IPv6 with VRRP version 2; setting version 3", vrrp->iname);
			vrrp->version = VRRP_VERSION_3;
		}
		else if (!vrrp->version)
			vrrp->version = VRRP_VERSION_3;
	}

	/* Default to IPv4. This can only happen if no VIPs are specified. */
	if (vrrp->family == AF_UNSPEC)
		vrrp->family = AF_INET;

	if (vrrp->version == 0) {
		if (vrrp->family == AF_INET6)
			vrrp->version = VRRP_VERSION_3;
		else
			vrrp->version = global_data->vrrp_version;
	}

	if (LIST_ISEMPTY(vrrp->vip) && (vrrp->version == VRRP_VERSION_3 || vrrp->family == AF_INET6 || vrrp->strict_mode)) {
		log_message(LOG_INFO, "(%s): No VIP specified; at least one is required", vrrp->iname);
		return false;
	}

#ifdef _WITH_VRRP_AUTH_
	if (vrrp->version == VRRP_VERSION_3 && vrrp->auth_type != VRRP_AUTH_NONE) {
		log_message(LOG_INFO, "(%s): VRRP version 3 does not support authentication. Ignoring.", vrrp->iname);
		vrrp->auth_type = VRRP_AUTH_NONE;
	}

	if (vrrp->auth_type != VRRP_AUTH_NONE && !vrrp->auth_data[0]) {
		log_message(LOG_INFO, "(%s): Authentication specified but no password given. Ignoring", vrrp->iname);
		vrrp->auth_type = VRRP_AUTH_NONE;
	}

	if (!vrrp->strict_mode) {
		/* The following can only happen if we are not in strict mode */
		if (vrrp->version == VRRP_VERSION_2 && vrrp->family == AF_INET6 && vrrp->auth_type == VRRP_AUTH_AH) {
			log_message(LOG_INFO, "(%s): Cannot use AH authentication with VRRPv2 and IPv6 - ignoring", vrrp->iname);
			vrrp->auth_type = VRRP_AUTH_NONE;
		}
	}
#endif

	if (!chk_min_cfg(vrrp))
		return false;

	/* unicast peers aren't allowed in strict mode */
	if (vrrp->strict_mode && !LIST_ISEMPTY(vrrp->unicast_peer)) {
		log_message(LOG_INFO, "(%s): Unicast peers are not supported in strict mode", vrrp->iname);
		return false;
	}

	/* If the addresses are IPv6, then the first one must be link local */
	if (vrrp->family == AF_INET6 && LIST_ISEMPTY(vrrp->unicast_peer) &&
		  !IN6_IS_ADDR_LINKLOCAL(&((ip_address_t *)LIST_HEAD(vrrp->vip)->data)->u.sin6_addr)) {
		log_message(LOG_INFO, "(%s): the first IPv6 VIP address must be link local", vrrp->iname);
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
		log_message(LOG_INFO, "(%s): Number of VIPs (%d) exceeds maximum/space available in packet (max %zu addresses) - excess moved to eVIPs",
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

	if (vrrp->base_priority == 0) {
		if (vrrp->init_state == VRRP_STATE_MAST)
			vrrp->base_priority = VRRP_PRIO_OWNER;
		else
			vrrp->base_priority = VRRP_PRIO_DFL;

		vrrp->effective_priority = vrrp->base_priority;
	}
	else if (vrrp->strict_mode && (vrrp->init_state == VRRP_STATE_MAST) && (vrrp->base_priority != VRRP_PRIO_OWNER)) {
		log_message(LOG_INFO,"(%s): Cannot start in MASTER state if not address owner", vrrp->iname);
		vrrp->init_state = VRRP_STATE_BACK;
		vrrp->wantstate = VRRP_STATE_BACK;
	}
	else if (vrrp->base_priority == VRRP_PRIO_OWNER && !vrrp->nopreempt) {
		/* Act as though state MASTER had been specified, to speed transition to master state */
		vrrp->init_state = VRRP_STATE_MAST;
		vrrp->wantstate = VRRP_STATE_MAST;
	}

	if (vrrp->nopreempt && vrrp->init_state == VRRP_STATE_MAST)
		log_message(LOG_INFO, "(%s): Warning - nopreempt will not work with initial state MASTER", vrrp->iname);
	if (vrrp->strict_mode && vrrp->preempt_delay) {
		log_message(LOG_INFO, "(%s): preempt_delay is incompatible with strict mode - resetting", vrrp->iname);
		vrrp->preempt_delay = 0;
	}
	if (vrrp->nopreempt && vrrp->preempt_delay) {
		log_message(LOG_INFO, "(%s): preempt_delay is incompatible with nopreempt mode - resetting", vrrp->iname);
		vrrp->preempt_delay = 0;
	}

	vrrp->state = VRRP_STATE_INIT;

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
		log_message(LOG_INFO, "(%s): warning - accept mode for VRRP version 2 does not comply with RFC3768 - resetting", vrrp->iname);
		vrrp->accept = 0;
	}

	if (vrrp->garp_lower_prio_rep == PARAMETER_UNSET)
		vrrp->garp_lower_prio_rep = vrrp->strict_mode ? 0 : global_data->vrrp_garp_lower_prio_rep;
	if (vrrp->garp_lower_prio_delay == PARAMETER_UNSET)
		vrrp->garp_lower_prio_delay = vrrp->strict_mode ? 0 : global_data->vrrp_garp_lower_prio_delay;
	if (vrrp->lower_prio_no_advert == PARAMETER_UNSET)
		vrrp->lower_prio_no_advert = vrrp->strict_mode ? true : global_data->vrrp_lower_prio_no_advert;

	/* Check that the advertisement interval is valid */
	if (!vrrp->adver_int)
		vrrp->adver_int = VRRP_ADVER_DFL * TIMER_HZ;
	if (vrrp->version == VRRP_VERSION_2) {
		if (vrrp->adver_int >= (1<<8) * TIMER_HZ) {
			log_message(LOG_INFO, "(%s): VRRPv2 advertisement interval %.2fs is out of range. Must be less than %ds. Setting to %ds",
					vrrp->iname, (float)vrrp->adver_int / TIMER_HZ, 1<<8, (1<<8) - 1);
			vrrp->adver_int = ((1<<8) - 1) * TIMER_HZ;
		}
		else if (vrrp->adver_int % TIMER_HZ) {
			log_message(LOG_INFO, "(%s): VRRPv2 advertisement interval %fs must be an integer - rounding",
					vrrp->iname, (float)vrrp->adver_int / TIMER_HZ);
			vrrp->adver_int = vrrp->adver_int + (TIMER_HZ / 2);
			vrrp->adver_int -= vrrp->adver_int % TIMER_HZ;
		}
	}
	else
	{
		if (vrrp->adver_int >= (1<<12) * TIMER_CENTI_HZ) {
			log_message(LOG_INFO, "(%s): VRRPv3 advertisement interval %.2fs is out of range. Must be less than %.2fs. Setting to %.2fs",
					vrrp->iname, (float)vrrp->adver_int / TIMER_HZ, (float)(1<<12) / 100, (float)((1<<12) - 1) / 100);
			vrrp->adver_int = ((1<<12) - 1) * TIMER_CENTI_HZ;
		}
		else if (vrrp->adver_int % TIMER_CENTI_HZ) {
			log_message(LOG_INFO, "(%s): VRRPv3 advertisement interval %fs must be in units of 10ms - rounding",
					vrrp->iname, (float)vrrp->adver_int / TIMER_HZ);
			vrrp->adver_int = vrrp->adver_int + (TIMER_CENTI_HZ / 2);
			vrrp->adver_int -= vrrp->adver_int % TIMER_CENTI_HZ;
		}
	}
	vrrp->master_adver_int = vrrp->adver_int;

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
				    ifp->base_ifindex == vrrp->ifp->ifindex)
				{
					log_message(LOG_INFO, "(%s): Found matching interface %s", vrrp->iname, ifp->ifname);
					if (vrrp->vmac_ifname[0] &&
					    strcmp(vrrp->vmac_ifname, ifp->ifname))
						log_message(LOG_INFO, "(%s): vmac name mismatch %s <=> %s; changing to %s.", vrrp->iname, vrrp->vmac_ifname, ifp->ifname, ifp->ifname);

					strcpy(vrrp->vmac_ifname, ifp->ifname);
					vrrp->ifp = ifp;
					vrrp->vmac_ifindex = ifp->ifindex;
					__set_bit(VRRP_VMAC_UP_BIT, &vrrp->vmac_flags);

					/* The interface existed, so it may have config set on it */
					interface_already_existed = true;

					break;
				}
			}

			if (!interface_already_existed &&
			    vrrp->vmac_ifname[0] &&
			    (ifp = if_get_by_ifname(vrrp->vmac_ifname))) {
				/* An interface with the same name exists, but it doesn't match */
				if (ifp->vmac)
					log_message(LOG_INFO, "(%s): VMAC %s already exists but is incompatible. It will be deleted", vrrp->iname, vrrp->vmac_ifname);
				else {
					log_message(LOG_INFO, "(%s): VMAC interface name %s already exists as a non VMAC interface - ignoring configured name",
						    vrrp->iname, vrrp->vmac_ifname);
					vrrp->vmac_ifname[0] = 0;
				}
			}
		}

		/* No interface found, find an unused name */
		if (!vrrp->vmac_ifname[0]) {
			int num=0;
			snprintf(ifname, IFNAMSIZ, "vrrp.%d", vrrp->vrid);

			while (true) {
				for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
					vrrp_o = ELEMENT_DATA(e);
					if (!strcmp(vrrp_o->vmac_ifname, ifname))
						break;
				}
				/* If there is no VMAC with the name and no existing
				 * interface with the name, we can use it */
				if (!e && !if_get_by_ifname(ifname))
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
		if (vrrp->strict_mode && __test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags)) {
			log_message(LOG_INFO, "(%s): xmit_base is incompatible with strict mode - resetting", vrrp->iname);
			__clear_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags);
		}

		if (vrrp->promote_secondaries) {
			log_message(LOG_INFO, "(%s): promote_secondaries is automatically set for vmacs - ignoring", vrrp->iname);
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

	base_ifp = base_if_get_by_ifp(vrrp->ifp);

	/* Make sure we have an IP address as needed */
	if (vrrp->saddr.ss_family == AF_UNSPEC) {
		/* Check the physical interface has a suitable address we can use.
		 * We don't need an IPv6 address on the underlying interface if it is
		 * a VMAC since we can create our own. */
		bool addr_missing = false;

		if (vrrp->family == AF_INET) {
			if (!base_ifp->sin_addr.s_addr)
				addr_missing = true;
		}
#ifdef _HAVE_VRRP_VMAC_
		else if (!__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags)) {
			if (!base_ifp->sin6_addr.s6_addr32[0])
				addr_missing = true;
		}
#endif

		if (addr_missing) {
			log_message(LOG_INFO, "(%s): Cannot find an IP address to use for interface %s", vrrp->iname, base_ifp->ifname);
			return false;
		}

		if (vrrp->family == AF_INET) {
			inet_ip4tosockaddr(&base_ifp->sin_addr, &vrrp->saddr);
		} else if (vrrp->family == AF_INET6) {
			inet_ip6tosockaddr(&base_ifp->sin6_addr, &vrrp->saddr);
			/* IPv6 use-case: Binding to link-local address requires an interface */
			inet_ip6scopeid(IF_INDEX(vrrp->ifp), &vrrp->saddr);
		}
	}

#ifdef _HAVE_VRRP_VMAC_
	if (__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags) &&
	    !__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags)) {
		log_message(LOG_INFO, "(%s): vmac_xmit_base is only valid with a vmac", vrrp->iname);
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

		/* Create the interface if it doesn't already exist */
		if (!__test_bit(VRRP_VMAC_UP_BIT, &vrrp->vmac_flags))
			netlink_link_add_vmac(vrrp);

		/* set scopeid of source address if IPv6 */
		if (vrrp->saddr.ss_family == AF_INET6)
			inet_ip6scopeid(vrrp->vmac_ifindex, &vrrp->saddr);
	}
#endif

	/* Spin through all our addresses, setting ifindex and ifp.
	   We also need to know what addresses we might block */
	if (vrrp->base_priority != VRRP_PRIO_OWNER && !vrrp->accept) {
//TODO = we have a problem since SNMP may change accept mode
//it can also change priority
		if (vrrp->saddr.ss_family == AF_INET)
			global_data->block_ipv4 = true;
		else
			global_data->block_ipv6 = true;
	}
	if (!LIST_ISEMPTY(vrrp->vip)) {
		for (e = LIST_HEAD(vrrp->vip); e; ELEMENT_NEXT(e)) {
			vip = ELEMENT_DATA(e);
			if (!vip->ifa.ifa_index) {
				vip->ifa.ifa_index = vrrp->ifp->ifindex;
				vip->ifp = vrrp->ifp;
			}
		}
	}
	if (!LIST_ISEMPTY(vrrp->evip)) {
		for (e = LIST_HEAD(vrrp->evip); e; ELEMENT_NEXT(e)) {
			vip = ELEMENT_DATA(e);
			if (!vip->ifa.ifa_index) {
				vip->ifa.ifa_index = vrrp->ifp->ifindex;
				vip->ifp = vrrp->ifp;
			}

			if (vrrp->base_priority != VRRP_PRIO_OWNER && !vrrp->accept) {
				if (vip->ifa.ifa_family == AF_INET)
					global_data->block_ipv4 = true;
				else
					global_data->block_ipv6 = true;
			}
		}
	}

	if (!reload && interface_already_existed) {
// TODO - consider reload
		vrrp->vipset = true;	/* Set to force address removal */
		vrrp_restore_interface(vrrp, false, true);
	}

	/* See if we need to set promote_secondaries */
	if (vrrp->promote_secondaries &&
	    !vrrp->ifp->promote_secondaries_already_set &&
	    !vrrp->ifp->reset_promote_secondaries)
		set_promote_secondaries(vrrp->ifp);

	/* If we are adding a large number of interfaces, the netlink socket
	 * may run out of buffers if we don't receive the netlink messages
	 * as we progress */
	kernel_netlink_poll();

	return true;
}

bool
vrrp_complete_init(void)
{
	/*
	 * l - List of VRRP instances to complete
	 * ol- List of VRRP sync-groups to restore state
	 * sl- List of VRRP instances within a sync-group
	 *
	 * e - Element equal to a specific VRRP instance
	 * eo- Element equal to a specific group within old global group list
	 * se- Element equal to a specific VRRP instance within sync group
	 */
	list l, ol, sl;
	element e, oe, se;
	vrrp_t *vrrp;
	vrrp_sgroup_t *sgroup, *old_sgroup;
	list l_o;
	element e_o;
	element next;
	vrrp_t *vrrp_o;
	ifindex_t ifindex;
	ifindex_t ifindex_o;
	size_t max_mtu_len = 0;

	/* Set defaults of not specified, depending on strict mode */
	if (global_data->vrrp_garp_lower_prio_rep == PARAMETER_UNSET)
		global_data->vrrp_garp_lower_prio_rep = global_data->vrrp_garp_rep;
	if (global_data->vrrp_garp_lower_prio_delay == PARAMETER_UNSET)
		global_data->vrrp_garp_lower_prio_delay = global_data->vrrp_garp_delay;

	/* Complete VRRP instance initialization */
	l = vrrp_data->vrrp;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (!vrrp_complete_instance(vrrp))
			return false;

		if (vrrp->ifp->mtu > max_mtu_len)
			max_mtu_len = vrrp->ifp->mtu;
	}

	/* If we have a global garp_delay add it to any interfaces without a garp_delay */
	if (global_data->vrrp_garp_interval || global_data->vrrp_gna_interval)
		set_default_garp_delay();

#ifdef _HAVE_LIBIPTC_
	/* Make sure we don't have any old iptables/ipsets settings left around */
	if (!reload)
		iptables_cleanup();
#endif

	/* Mark any scripts as insecure */
	check_vrrp_script_security();

	/* Make sure don't have same vrid on same interface with same address family */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		l_o = &vrrp_data->vrrp_index[vrrp->vrid];
#ifdef _HAVE_VRRP_VMAC_
		if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags))
			ifindex = vrrp->ifp->base_ifindex;
		else
#endif
			ifindex = vrrp->ifp->ifindex;

		/* Check if any other entries with same vrid conflict */
		if (!LIST_ISEMPTY(l_o) && LIST_SIZE(l_o) > 1) {
			/* Can't have same vrid with same family an interface */
			for (e_o = LIST_HEAD(l_o); e_o; ELEMENT_NEXT(e_o)) {
				vrrp_o = ELEMENT_DATA(e_o);
				if (vrrp_o != vrrp &&
				    vrrp_o->family == vrrp->family) {
#ifdef _HAVE_VRRP_VMAC_
					if (__test_bit(VRRP_VMAC_BIT, &vrrp_o->vmac_flags))
						ifindex_o = vrrp_o->ifp->base_ifindex;
					else
#endif
						ifindex_o = vrrp_o->ifp->ifindex;

					if (ifindex == ifindex_o)
					{
						log_message(LOG_INFO, "VRID %d is duplicated on interface %s", vrrp->vrid, if_get_by_ifindex(ifindex)->ifname);
						return false;
					}
				}
			}
		}
	}

	/* Build synchronization group index, and remove any
	 * empty groups, or groups with only one member */
	for (e = LIST_HEAD(vrrp_data->vrrp_sync_group); e; e = next) {
		next = e->next;
		sgroup = ELEMENT_DATA(e);
		vrrp_sync_set_group(sgroup);
		if (LIST_ISEMPTY(sgroup->index_list) ||
			LIST_SIZE(sgroup->index_list) <= 1) {
			free_list_element(vrrp_data->vrrp_sync_group, e);
			continue;
		}

		if (reload) {
			ol = old_vrrp_data->vrrp_sync_group;
			for (oe = LIST_HEAD(ol); oe; ELEMENT_NEXT(oe)) {
				old_sgroup = ELEMENT_DATA(oe);
				log_message(LOG_INFO,
					"VRRP_Group(%s) - Found saved old sync-group called %s",
					GROUP_NAME(sgroup), GROUP_NAME(old_sgroup));

				if (strcmp(old_sgroup->gname, sgroup->gname) == 0) {
					/* Old Sync group matches current Sync group */

					/* Check for instances that have been removed from the
					 * sync-group. If this is the case, and the sync-group
					 * was previously in the MASTER state, then we should
					 * fall-back to BACKUP, to allow a new MASTER
					 * for any removed instances.
					 */
					if (LIST_SIZE(sgroup->index_list) <
						LIST_SIZE(old_sgroup->index_list)) {
						sgroup->state = VRRP_STATE_BACK;
						log_message(LOG_INFO,
							"VRRP_Group(%s) Detected instance removed from sync-group, forcing BACKUP",
							GROUP_NAME(sgroup));
					} else {
						sgroup->state = old_sgroup->state;
					}

					log_message(LOG_INFO,
						"VRRP_Group(%s) Restoring saved sync State : %d",
						GROUP_NAME(sgroup), sgroup->state);

					sl = sgroup->index_list;
					for (se = LIST_HEAD(sl); se; ELEMENT_NEXT(se)) {
						vrrp = ELEMENT_DATA(se);
						log_message(LOG_INFO,
							"VRRP_Instance(%s) used for VRRP_Group(%s) refresh sync",
							vrrp->iname, GROUP_NAME(sgroup));

						switch (sgroup->state) {
						case VRRP_STATE_INIT:
							/* Do nothing */
							break;

						case VRRP_STATE_BACK:
							if (vrrp->state != VRRP_STATE_BACK) {
								vrrp->wantstate = VRRP_STATE_BACK;
							}
							break;

						case VRRP_STATE_MAST:
							if (vrrp->state != VRRP_STATE_MAST) {
								vrrp->wantstate = VRRP_STATE_MAST;
							}
							break;

						case VRRP_STATE_FAULT:
							if (vrrp->state != VRRP_STATE_FAULT) {
								if (vrrp->state == VRRP_STATE_MAST)
									vrrp->wantstate = VRRP_STATE_GOTO_FAULT;
								if (vrrp->state == VRRP_STATE_BACK)
									vrrp->state = VRRP_STATE_FAULT;
							}
							break;

						default:
							/* Do nothing */
							break;
						}
					}

					notify_group_exec(sgroup, sgroup->state);
#ifdef _WITH_SNMP_KEEPALIVED_
					vrrp_snmp_group_trap(sgroup);
#endif
				}
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

	alloc_vrrp_buffer(max_mtu_len);

	return true;
}

#ifdef _WITH_LVS_
bool
vrrp_ipvs_needed(void)
{
	return !!(global_data->lvs_syncd.ifname);
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

		if (vrrp->ifp->base_ifindex == old_vrrp->ifp->base_ifindex)
			return vrrp;
#endif
	}

	return NULL;
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
		h = iptables_open();
#endif
		clear_diff_vrrp_vip_list(vrrp, h, old_vrrp->vip, vrrp->vip);
		clear_diff_vrrp_vip_list(vrrp, h, old_vrrp->evip, vrrp->evip);
#ifdef _HAVE_LIBIPTC_
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
	vrrp->init_state = old_vrrp->state;
	vrrp->wantstate = old_vrrp->state;
	if (!old_vrrp->sync)
		vrrp->effective_priority = old_vrrp->effective_priority;
	/* Save old stats */
	memcpy(vrrp->stats, old_vrrp->stats, sizeof(vrrp_stats));

	memcpy(vrrp->ipsecah_counter, old_vrrp->ipsecah_counter, sizeof(seq_counter_t));

	/* Remember if we had vips up and add new ones if needed */
	vrrp->vipset = old_vrrp->vipset;
	if (vrrp->vipset) {
		vrrp_handle_accept_mode(vrrp, IPADDRESS_ADD, false);
		if (!LIST_ISEMPTY(vrrp->vip))
			added_ip_addr = vrrp_handle_ipaddress(vrrp, IPADDRESS_ADD, VRRP_VIP_TYPE);
		if (!LIST_ISEMPTY(vrrp->evip)) {
			if (vrrp_handle_ipaddress(vrrp, IPADDRESS_ADD, VRRP_EVIP_TYPE))
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
	interface_t *ifp;

	if (LIST_ISEMPTY(l))
		return;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		vrrp_t *new_vrrp;

		/*
		 * Try to find this vrrp into the new conf data
		 * reloaded.
		 */
		new_vrrp = vrrp_exist(vrrp);
		if (!new_vrrp) {
			vrrp_restore_interface(vrrp, true, false);

#ifdef _HAVE_VRRP_VMAC_
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
				netlink_link_del_vmac(vrrp);
			}
#endif

			/* reset the state */
			if (restore_vrrp_state(vrrp, new_vrrp)) {
				/* There were addresses added, so set GARP/GNA for them.
				 * This is a bit over the top since it will send GARPs/GNAs for
				 * all the addresses, but at least we will do so for the new addresses. */

				/* remotes neighbour update */
				if (new_vrrp->family == AF_INET6) {
					/* Refresh whether we are acting as a router for NA messages */
					ifp = IF_BASE_IFP(new_vrrp->ifp);
					ifp->gna_router = get_ipv6_forwarding(ifp);
				}
				vrrp_send_link_update(new_vrrp, new_vrrp->garp_rep);

				/* set refresh timer */
				if (!timer_isnull(new_vrrp->garp_refresh)) {
					new_vrrp->garp_refresh_timer = timer_add_now(new_vrrp->garp_refresh);
				}
			}
		}
	}
}

/* Set script status to a sensible value on reload */
void
clear_diff_script(void)
{
	element e;
	list l = old_vrrp_data->vrrp_script;
	vrrp_script_t *vscript, *nvscript;

	if (LIST_ISEMPTY(l))
		return;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vscript = ELEMENT_DATA(e);
		if (vscript->result >= vscript->rise) {
			nvscript = find_script_by_name(vscript->sname);
			if (nvscript) {
				log_message(LOG_INFO, "VRRP_Script(%s) considered successful on reload",
					   nvscript->sname);
				nvscript->result = VRRP_SCRIPT_STATUS_INIT_GOOD;
			}
		}
	}
}

