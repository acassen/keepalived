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

/* local include */
#include <ctype.h>
#include <sys/uio.h>
#include "vrrp_arp.h"
#include "vrrp_ndisc.h"
#include "vrrp_scheduler.h"
#include "vrrp_notify.h"
#include "ipvswrapper.h"
#include "vrrp.h"
#include "vrrp_data.h"
#include "vrrp_sync.h"
#include "vrrp_index.h"
#include "vrrp_vmac.h"
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

/* add/remove Virtual IP addresses */
static int
vrrp_handle_ipaddress(vrrp_t * vrrp, int cmd, int type)
{
	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "VRRP_Instance(%s) %s protocol %s", vrrp->iname,
		       (cmd == IPADDRESS_ADD) ? "setting" : "removing",
		       (type == VRRP_VIP_TYPE) ? "VIPs." : "E-VIPs.");
	netlink_iplist((type == VRRP_VIP_TYPE) ? vrrp->vip : vrrp->evip, cmd);
	return 1;
}

/* add/remove Virtual routes */
static int
vrrp_handle_iproutes(vrrp_t * vrrp, int cmd)
{
	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "VRRP_Instance(%s) %s protocol Virtual Routes",
		       vrrp->iname,
		       (cmd == IPROUTE_ADD) ? "setting" : "removing");
	netlink_rtlist(vrrp->vroutes, cmd);
	return 1;
}

/* add/remove iptable drop rules based on accept mode */
static void
vrrp_handle_accept_mode(vrrp_t *vrrp, int cmd)
{
	if ((vrrp->version == VRRP_VERSION_3) &&
	    (vrrp->base_priority != VRRP_PRIO_OWNER) &&
	    !vrrp->accept) {
		if (debug & 32)
			log_message(LOG_INFO, "VRRP_Instance(%s) %s protocol %s", vrrp->iname,
				(cmd == IPADDRESS_ADD) ? "setting" : "removing", " iptable drop rule to VIP");

		/* As accept is false, add iptable rule to drop packets destinated to VIP */
		handle_iptable_rule_to_iplist(vrrp->vip, cmd, IF_NAME(vrrp->ifp));
		vrrp->iptable_rules_set = (cmd == IPADDRESS_ADD) ? true : false;
	}
}

/* IP header length */
static int
vrrp_iphdr_len(vrrp_t * vrrp)
{
	return sizeof(struct iphdr);
}

/* IPSEC AH header length */
int
vrrp_ipsecah_len(void)
{
	return sizeof(ipsec_ah_t);
}

/* VRRP header length */
static int
vrrp_hd_len(vrrp_t * vrrp)
{
	int len = sizeof(vrrphdr_t);
	if (vrrp->family == AF_INET) {
		if (vrrp->version == VRRP_VERSION_2)
			len += VRRP_AUTH_LEN;
		len += ((!LIST_ISEMPTY(vrrp->vip)) ? LIST_SIZE(vrrp->vip) * sizeof(uint32_t) : 0);
	} else if (vrrp->family == AF_INET6) {
		len += ((!LIST_ISEMPTY(vrrp->vip)) ? LIST_SIZE(vrrp->vip) * sizeof(uint32_t) * 4 : 0);
	}

	return len;
}

/* VRRP header pointer from buffer */
vrrphdr_t *
vrrp_get_header(sa_family_t family, char *buf, int *proto)
{
	struct iphdr *iph;
	vrrphdr_t *hd = NULL;

	if (family == AF_INET) {
		iph = (struct iphdr *) buf;

		/* Fill the VRRP header */
		switch (iph->protocol) {
		case IPPROTO_IPSEC_AH:
			*proto = IPPROTO_IPSEC_AH;
			hd = (vrrphdr_t *) ((char *) iph + (iph->ihl << 2) +
					   vrrp_ipsecah_len());
			break;
		case IPPROTO_VRRP:
			*proto = IPPROTO_VRRP;
			hd = (vrrphdr_t *) ((char *) iph + (iph->ihl << 2));
			break;
		}
	} else if (family == AF_INET6) {
		*proto = IPPROTO_VRRP;
		hd = (vrrphdr_t *) buf;
	}

	return hd;
}

/*
 * IPSEC AH incoming packet check.
 * return 0 for a valid pkt, != 0 otherwise.
 */
static int
vrrp_in_chk_ipsecah(vrrp_t * vrrp, char *buffer)
{
	struct iphdr *ip = (struct iphdr *) (buffer);
	ipsec_ah_t *ah = (ipsec_ah_t *) ((char *) ip + (ip->ihl << 2));
	unsigned char digest[16]; /*MD5_DIGEST_LENGTH */
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
	    vrrp->sync || __test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags)) {
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
		 vrrp_iphdr_len(vrrp) + vrrp_ipsecah_len() + vrrp_hd_len(vrrp)
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

/* check if ipaddr is present in VIP buffer */
static int
vrrp_in_chk_vips(vrrp_t * vrrp, ip_address_t *ipaddress, unsigned char *buffer)
{
	int i;
	uint32_t ipbuf;
	struct in6_addr ip6buf;

	if (vrrp->family == AF_INET) {
		/* Just skip IPv6 address, when we are using a mixed v4/v6 vips
		 * set inside the same VRRP instance.
		 */
		if (IP_IS6(ipaddress))
			return 1;

		for (i = 0; i < LIST_SIZE(vrrp->vip); i++) {
			bcopy(buffer + i * sizeof(uint32_t), &ipbuf,
			      sizeof(uint32_t));
			if (ipaddress->u.sin.sin_addr.s_addr == ipbuf)
				return 1;
		}
	} else if (vrrp->family == AF_INET6) {
		/* Just skip IPv4 address, when we are using a mixed v4/v6 vips
		 * set inside the same VRRP instance.
		 */
		if (IP_IS4(ipaddress))
			return 1;

		for (i = 0; i < LIST_SIZE(vrrp->vip); i++) {
			bcopy(buffer + i * sizeof(struct in6_addr), &ip6buf,
			      sizeof(struct in6_addr));
			if (IN6_ARE_ADDR_EQUAL(&ipaddress->u.sin6_addr, &ip6buf))
				return 1;
		}
	}

	return 0;
}

/*
 * VRRP incoming packet check.
 * return 0 if the pkt is valid, != 0 otherwise.
 */
static int
vrrp_in_chk(vrrp_t * vrrp, char *buffer)
{
	struct iphdr *ip;
	int ihl, vrrphdr_len;
	int adver_int = 0;
	ipsec_ah_t *ah;
	vrrphdr_t *hd;
	unsigned char *vips;
	ip_address_t *ipaddress;
	element e;
	char addr_str[INET6_ADDRSTRLEN];
	ipv4_phdr_t ipv4_phdr;
	int acc_csum = 0;
	ip = NULL;

	/* IPv4 related */
	if (vrrp->family == AF_INET) {

		ip = (struct iphdr *) (buffer);
		ihl = ip->ihl << 2;

		if (vrrp->version == VRRP_VERSION_2 &&
		    vrrp->auth_type == VRRP_AUTH_AH) {
			ah = (ipsec_ah_t *) (buffer + ihl);
			hd = (vrrphdr_t *) ((char *) ah + vrrp_ipsecah_len());
		} else {
			hd = (vrrphdr_t *) (buffer + ihl);
		}
	
		/* pointer to vrrp vips pkt zone */
		vips = (unsigned char *) ((char *) hd + sizeof(vrrphdr_t));
	
		/* MUST verify that the IP TTL is 255 */
		if (LIST_ISEMPTY(vrrp->unicast_peer) && ip->ttl != VRRP_IP_TTL) {
			log_message(LOG_INFO, "invalid ttl. %d and expect %d", ip->ttl,
			       VRRP_IP_TTL);
			++vrrp->stats->ip_ttl_err;
			return VRRP_PACKET_KO;
		}

		/*
		 * MUST verify that the received packet length is greater than or
		 * equal to the VRRP header
		 */
		if ((ntohs(ip->tot_len) - ihl) <= sizeof(vrrphdr_t)) {
			log_message(LOG_INFO,
			       "ip payload too short. %d and expect at least %lu",
			       ntohs(ip->tot_len) - ihl, sizeof(vrrphdr_t));
			++vrrp->stats->packet_len_err;
			return VRRP_PACKET_KO;
		}

		/* Correct type, version, and length. Count as VRRP advertisement */
		++vrrp->stats->advert_rcvd;

		if (!LIST_ISEMPTY(vrrp->vip)) {
			/*
			 * MAY verify that the IP address(es) associated with the
			 * VRID are valid
			 */
			if (hd->naddr != LIST_SIZE(vrrp->vip)) {
				log_message(LOG_INFO,
				       "receive an invalid ip number count associated with VRID!");
				++vrrp->stats->addr_list_err;
				return VRRP_PACKET_KO;
			}

			for (e = LIST_HEAD(vrrp->vip); e; ELEMENT_NEXT(e)) {
				ipaddress = ELEMENT_DATA(e);
				if (!vrrp_in_chk_vips(vrrp, ipaddress, vips)) {
					log_message(LOG_INFO, "ip address associated with VRID"
					       " not present in received packet : %s",
					       inet_ntop2(ipaddress->u.sin.sin_addr.s_addr));
					log_message(LOG_INFO,
					       "one or more VIP associated with"
					       " VRID mismatch actual MASTER advert");
					++vrrp->stats->addr_list_err;
					return VRRP_PACKET_KO;
				}
			}
		}

		/* check the authentication if it is a passwd */
		if (vrrp->version == VRRP_VERSION_2 && hd->v2.auth_type == VRRP_AUTH_PASS) {
			char *pw = (char *) ip + ntohs(ip->tot_len)
			    - sizeof (vrrp->auth_data);
			if (memcmp(pw, vrrp->auth_data, sizeof(vrrp->auth_data)) != 0) {
				log_message(LOG_INFO, "receive an invalid passwd!");
				++vrrp->stats->auth_failure;
				return VRRP_PACKET_KO;
			}
		}

		/* check the authenicaion if it is ipsec ah */
		if (vrrp->version == VRRP_VERSION_2 && hd->v2.auth_type == VRRP_AUTH_AH) {
			if (vrrp_in_chk_ipsecah(vrrp, buffer))
				return VRRP_PACKET_KO;
		}

		/* Set expected vrrp packet lenght */
		vrrphdr_len = sizeof(vrrphdr_t) + VRRP_AUTH_LEN + hd->naddr * sizeof(uint32_t);

	} else if (vrrp->family == AF_INET6) { /* IPv6 related */

		hd = (vrrphdr_t *) buffer;
		vrrphdr_len = sizeof(vrrphdr_t);

		/* pointer to vrrp vips pkt zone */
		vips = (unsigned char *) ((char *) hd + sizeof(vrrphdr_t));

		/* Correct type, version, and length. Count as VRRP advertisement */
		++vrrp->stats->advert_rcvd;

		if (!LIST_ISEMPTY(vrrp->vip)) {
			/*
			 * MAY verify that the IP address(es) associated with the
			 * VRID are valid
			 */
			if (hd->naddr != LIST_SIZE(vrrp->vip)) {
				log_message(LOG_INFO,
					"receive an invalid ip number count associated with VRID!");
				++vrrp->stats->addr_list_err;
				return VRRP_PACKET_KO;
			}

			for (e = LIST_HEAD(vrrp->vip); e; ELEMENT_NEXT(e)) {
				ipaddress = ELEMENT_DATA(e);
				if (!vrrp_in_chk_vips(vrrp, ipaddress, vips)) {
					log_message(LOG_INFO, "ip address associated with VRID "
						    " not present in received packet : %s",
						    inet_ntop(AF_INET6, &ipaddress->u.sin6_addr,
						    addr_str, sizeof(addr_str)));
					log_message(LOG_INFO, "one or more VIP associated with"
						    " VRID mismatch actual MASTER advert");
					++vrrp->stats->addr_list_err;
					return VRRP_PACKET_KO;
				}
			}
		}

		/* Set expected vrrp packet lenght */
		vrrphdr_len = sizeof(vrrphdr_t) + hd->naddr * sizeof(struct in6_addr);
	} else {
		return VRRP_PACKET_KO;
	}

	/* MUST verify the VRRP version */
	if ((hd->vers_type >> 4) != vrrp->version) {
		log_message(LOG_INFO, "invalid version. %d and expect %d",
		       (hd->vers_type >> 4), vrrp->version);
		return VRRP_PACKET_KO;
	}

	/* verify packet type */
	if ((hd->vers_type & 0x0f) != VRRP_PKT_ADVERT) {
		log_message(LOG_INFO, "Invalid packet type. %d and expect %d",
			(hd->vers_type & 0x0f), VRRP_PKT_ADVERT);
		++vrrp->stats->invalid_type_rcvd;
		return VRRP_PACKET_KO;
	}

	/* MUST verify that the VRID is valid on the receiving interface_t */
	if (vrrp->vrid != hd->vrid) {
		log_message(LOG_INFO,
		       "received VRID mismatch. Received %d, Expected %d",
		       hd->vrid, vrrp->vrid);
		return VRRP_PACKET_DROP;
	}

	/* MUST verify the VRRP checksum */
	if (vrrp->version == VRRP_VERSION_3) {
		if (vrrp->family == AF_INET) {
			/* Create IPv4 pseudo-header */
			ipv4_phdr.src   = ip->saddr;
			ipv4_phdr.dst   = htonl(INADDR_VRRP_GROUP);
			ipv4_phdr.zero  = 0;
			ipv4_phdr.proto = IPPROTO_VRRP;
			ipv4_phdr.len   = htons(vrrp_hd_len(vrrp));

			in_csum((u_short *) &ipv4_phdr, sizeof(ipv4_phdr), 0, &acc_csum);
			if (in_csum((u_short *) hd, vrrphdr_len, acc_csum, NULL)) {
				log_message(LOG_INFO, "Invalid VRRPv3 checksum");
				return VRRP_PACKET_KO;
			}
		}
		/* Kernel takes care of checksum mismatch incase of IPv6. */
	} else {
		if (vrrp->family == AF_INET) {
			if (in_csum((u_short *) hd, vrrphdr_len, 0, NULL)){
				log_message(LOG_INFO, "Invalid VRRPv2 checksum");
				return VRRP_PACKET_KO;
			}
		}
		/* Kernel takes care of checksum mismatch incase of IPv6. */
        }

	/* Check that auth type of packet is one of the supported auth types */
	if (vrrp->version == VRRP_VERSION_2 &&
		hd->v2.auth_type != VRRP_AUTH_AH &&
		hd->v2.auth_type != VRRP_AUTH_PASS &&
		hd->v2.auth_type != VRRP_AUTH_NONE) {
		log_message(LOG_INFO, "Invalid auth type: %d", hd->v2.auth_type);
		++vrrp->stats->invalid_authtype;
		return VRRP_PACKET_KO;
	}

	/*
	 * MUST perform authentication specified by Auth Type 
	 * check the authentication type
	 */
	if (vrrp->version == VRRP_VERSION_2 &&
	    vrrp->auth_type != hd->v2.auth_type) {
		log_message(LOG_INFO, "receive a %d auth, expecting %d!",
		       hd->v2.auth_type, vrrp->auth_type);
		++vrrp->stats->authtype_mismatch;
		return VRRP_PACKET_KO;
	}

	if (LIST_ISEMPTY(vrrp->vip) && hd->naddr > 0) {
		log_message(LOG_INFO, "receive an invalid ip number count associated with VRID!");
		++vrrp->stats->addr_list_err;
		return VRRP_PACKET_KO;
	}

	/*
	 * MUST verify that the Adver Interval in the packet is the same as
	 * the locally configured for this virtual router
	 */
	if (vrrp->version == VRRP_VERSION_2) {
		adver_int = hd->v2.adver_int * TIMER_HZ;
		if (vrrp->adver_int != adver_int) {
			log_message(LOG_INFO, "advertisement interval mismatch mine=%d sec rcved=%d sec",
				vrrp->adver_int / TIMER_HZ, adver_int / TIMER_HZ);
			/* to prevent concurent VRID running => multiple master in 1 VRID */
			return VRRP_PACKET_DROP;
		}
	}
	/* In v3 we do not drop the packet. Instead, when we are in BACKUP
	 * state, we set our advertisement interval to match the MASTER's.
	 */
	if (vrrp->version == VRRP_VERSION_3 && vrrp->state == VRRP_STATE_BACK) {
		adver_int = (ntohs(hd->v3.adver_int) & 0x0FFF) * TIMER_HZ / 100;
		if (vrrp->master_adver_int != adver_int)
			log_message(LOG_INFO, "advertisement interval mismatch: mine=%d milli-sec, rcved=%d milli-sec",
				(vrrp->adver_int * 1000) / TIMER_HZ, (adver_int * 1000) / TIMER_HZ);
 	}

	if (hd->priority == 0)
		++vrrp->stats->pri_zero_rcvd;

	return VRRP_PACKET_OK;
}

/* build IP header */
static void
vrrp_build_ip4(vrrp_t * vrrp, char *buffer, int buflen, uint32_t dst)
{
	struct iphdr *ip = (struct iphdr *) (buffer);

	ip->ihl = 5;
	ip->version = 4;
	/* set tos to internet network control */
	ip->tos = 0xc0;
	ip->tot_len = ip->ihl * 4 + vrrp_hd_len(vrrp);
	ip->tot_len = htons(ip->tot_len);
	ip->id = htons(++vrrp->ip_id);
	/* kernel will fill in ID if left to 0, so we overflow to 1 */
	if (vrrp->ip_id == 65535)
		vrrp->ip_id = 1;
	ip->frag_off = 0;
	ip->ttl = VRRP_IP_TTL;

	/* fill protocol type --rfc2402.2 */
	if (vrrp->version == VRRP_VERSION_2)
		ip->protocol = (vrrp->auth_type == VRRP_AUTH_AH) ? IPPROTO_IPSEC_AH : IPPROTO_VRRP;
	else
		ip->protocol = IPPROTO_VRRP;

	ip->saddr = VRRP_PKT_SADDR(vrrp);
	ip->daddr = dst;

	/* checksum must be done last */
	ip->check = in_csum((u_short *) ip, ip->ihl * 4, 0, NULL);
}

/* build IPSEC AH header */
static void
vrrp_build_ipsecah(vrrp_t * vrrp, char *buffer, int buflen)
{
	ICV_mutable_fields *ip_mutable_fields;
	unsigned char *digest;
	struct iphdr *ip = (struct iphdr *) (buffer);
	ipsec_ah_t *ah = (ipsec_ah_t *) (buffer + sizeof (struct iphdr));

	/* alloc a temp memory space to stock the ip mutable fields */
	ip_mutable_fields = (ICV_mutable_fields *) MALLOC(sizeof (ICV_mutable_fields));

	/* fill in next header filed --rfc2402.2.1 */
	ah->next_header = IPPROTO_VRRP;

	/* update IP header total length value */
	ip->tot_len = ip->ihl * 4 + vrrp_ipsecah_len() + vrrp_hd_len(vrrp);
	ip->tot_len = htons(ip->tot_len);

	/* update ip checksum */
	ip->check = 0;
	ip->check = in_csum((u_short *) ip, ip->ihl * 4, 0, NULL);

	/* backup the ip mutable fields */
	ip_mutable_fields->tos = ip->tos;
	ip_mutable_fields->ttl = ip->ttl;
	ip_mutable_fields->frag_off = ip->frag_off;
	ip_mutable_fields->check = ip->check;

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
	digest = (unsigned char *) MALLOC(16); /*MD5_DIGEST_LENGTH */
	hmac_md5((unsigned char *) buffer, buflen, vrrp->auth_data, sizeof (vrrp->auth_data)
		 , digest);
	memcpy(ah->auth_data, digest, HMAC_MD5_TRUNC);

	/* Restore the ip mutable fields */
	ip->tos = ip_mutable_fields->tos;
	ip->frag_off = ip_mutable_fields->frag_off;
	ip->check = ip_mutable_fields->check;
	if (!LIST_ISEMPTY(vrrp->unicast_peer))
		ip->ttl = ip_mutable_fields->ttl;

	FREE(ip_mutable_fields);
	FREE(digest);
}

/* build VRRPv2 header */
static int
vrrp_build_vrrp_v2(vrrp_t *vrrp, int prio, char *buffer)
{
	int i = 0;
	vrrphdr_t *hd = (vrrphdr_t *) buffer;
	uint32_t *iparr;
	element e;
	ip_address_t *ip_addr;

	/* Family independant */
	hd->vers_type = (VRRP_VERSION_2 << 4) | VRRP_PKT_ADVERT;
	hd->vrid = vrrp->vrid;
	hd->priority = prio;
	hd->naddr = (!LIST_ISEMPTY(vrrp->vip)) ? LIST_SIZE(vrrp->vip) : 0;
	hd->v2.auth_type = vrrp->auth_type;
	hd->v2.adver_int = vrrp->adver_int / TIMER_HZ;

	/* Family specific */
	if (vrrp->family == AF_INET) {
		/* copy the ip addresses */
		iparr = (uint32_t *) ((char *) hd + sizeof (*hd));
		if (!LIST_ISEMPTY(vrrp->vip)) {
			for (e = LIST_HEAD(vrrp->vip); e; ELEMENT_NEXT(e)) {
				ip_addr = ELEMENT_DATA(e);
				if (IP_IS6(ip_addr))
					continue;
				else
					iparr[i++] = ip_addr->u.sin.sin_addr.s_addr;
			}
		}

		/* copy the passwd if the authentication is VRRP_AH_PASS */
		if (vrrp->auth_type == VRRP_AUTH_PASS) {
			int vip_count = (!LIST_ISEMPTY(vrrp->vip)) ? LIST_SIZE(vrrp->vip) : 0;
			char *pw = (char *) hd + sizeof (*hd) + vip_count * 4;
			memcpy(pw, vrrp->auth_data, sizeof (vrrp->auth_data));
		}

		/* finaly compute vrrp checksum */
		hd->chksum = 0;
		hd->chksum = in_csum((u_short *) hd, vrrp_hd_len(vrrp), 0, NULL);
	} else if (vrrp->family == AF_INET6) {
		iparr = (uint32_t *)((char *) hd + sizeof(*hd));
		if (!LIST_ISEMPTY(vrrp->vip)) {
			for (e = LIST_HEAD(vrrp->vip); e; ELEMENT_NEXT(e)) {
				ip_addr = ELEMENT_DATA(e);
				if (!IP_IS6(ip_addr))
					continue;
				else {
					iparr[i++] = ip_addr->u.sin6_addr.s6_addr32[0];
					iparr[i++] = ip_addr->u.sin6_addr.s6_addr32[1];
					iparr[i++] = ip_addr->u.sin6_addr.s6_addr32[2];
					iparr[i++] = ip_addr->u.sin6_addr.s6_addr32[3];
				}
			}
		}
		/* Kernel will update checksum field. let it be 0 now. */
		hd->chksum = 0;
	}

	return 0;
}

/* build VRRPv3 header */
static int
vrrp_build_vrrp_v3(vrrp_t *vrrp, int prio, char *buffer)
{
	int i = 0;
	vrrphdr_t *hd = (vrrphdr_t *) buffer;
	uint32_t *iparr;
	element e;
	ip_address_t *ip_addr;
	ipv4_phdr_t ipv4_phdr;
	int acc_csum = 0;

	/* Family independant */
	hd->vers_type = (VRRP_VERSION_3 << 4) | VRRP_PKT_ADVERT;
	hd->vrid = vrrp->vrid;
	hd->priority = prio;
	hd->naddr = (!LIST_ISEMPTY(vrrp->vip)) ? LIST_SIZE(vrrp->vip) : 0;
	hd->v3.adver_int  = htons((vrrp->adver_int / TIMER_CENTI_HZ) & 0x0FFF); /* interval in centiseconds, reserved bits zero */

	/* Family specific */
	if (vrrp->family == AF_INET) {
		/* copy the ip addresses */
		iparr = (uint32_t *) ((char *) hd + sizeof(*hd));
		if (!LIST_ISEMPTY(vrrp->vip)) {
			for (e = LIST_HEAD(vrrp->vip); e; ELEMENT_NEXT(e)) {
				ip_addr = ELEMENT_DATA(e);
				if (IP_IS6(ip_addr))
					continue;
				else
					iparr[i++] = ip_addr->u.sin.sin_addr.s_addr;
			}
		}

		/* Create IPv4 pseudo-header */
		ipv4_phdr.src   = VRRP_PKT_SADDR(vrrp);
		ipv4_phdr.dst   = htonl(INADDR_VRRP_GROUP);
		ipv4_phdr.zero  = 0;
		ipv4_phdr.proto = IPPROTO_VRRP;
		ipv4_phdr.len   = htons(vrrp_hd_len(vrrp));

		/* finaly compute vrrp checksum */
		in_csum((u_short *) &ipv4_phdr, sizeof(ipv4_phdr), 0, &acc_csum);
		hd->chksum = in_csum((u_short *) hd, vrrp_hd_len(vrrp), acc_csum, NULL);
	} else if (vrrp->family == AF_INET6) {
		iparr = (uint32_t *)((char *) hd + sizeof(*hd));
		if (!LIST_ISEMPTY(vrrp->vip)) {
			for (e = LIST_HEAD(vrrp->vip); e; ELEMENT_NEXT(e)) {
				ip_addr = ELEMENT_DATA(e);
				if (!IP_IS6(ip_addr))
					continue;
				else {
					iparr[i++] = ip_addr->u.sin6_addr.s6_addr32[0];
					iparr[i++] = ip_addr->u.sin6_addr.s6_addr32[1];
					iparr[i++] = ip_addr->u.sin6_addr.s6_addr32[2];
					iparr[i++] = ip_addr->u.sin6_addr.s6_addr32[3];
				}
			}
		}
		/* Kernel will update checksum field. let it be 0 now. */
		hd->chksum = 0;
	}

	return 0;
}

/* build VRRP header */
static int
vrrp_build_vrrp(vrrp_t *vrrp, int prio, char *buffer)
{
	if (vrrp->version == VRRP_VERSION_3)
		return vrrp_build_vrrp_v3(vrrp, prio, buffer);

	return vrrp_build_vrrp_v2(vrrp, prio, buffer);
}

/* build VRRP packet */
static void
vrrp_build_pkt(vrrp_t * vrrp, int prio, struct sockaddr_storage *addr)
{
	char *bufptr;
	uint32_t dst;
	int len;

	/* save reference values */
	bufptr = VRRP_SEND_BUFFER(vrrp);
	len = VRRP_SEND_BUFFER_SIZE(vrrp);

	if (vrrp->family == AF_INET) {
		/* build the ip header */
		dst = (addr) ? inet_sockaddrip4(addr) : 
			       ((struct sockaddr_in *) &global_data->vrrp_mcast_group4)->sin_addr.s_addr;
		vrrp_build_ip4(vrrp, bufptr, len, dst);

		/* build the vrrp header */
		vrrp->send_buffer += vrrp_iphdr_len(vrrp);

		if (vrrp->version == VRRP_VERSION_2 && vrrp->auth_type == VRRP_AUTH_AH)
			vrrp->send_buffer += vrrp_ipsecah_len();
		vrrp->send_buffer_size -= vrrp_iphdr_len(vrrp);

		if (vrrp->version == VRRP_VERSION_2 && vrrp->auth_type == VRRP_AUTH_AH)
			vrrp->send_buffer_size -= vrrp_ipsecah_len();
		vrrp_build_vrrp(vrrp, prio, vrrp->send_buffer);

		/* build the IPSEC AH header */
		if (vrrp->version == VRRP_VERSION_2 && vrrp->auth_type == VRRP_AUTH_AH) {
			vrrp->send_buffer_size += vrrp_iphdr_len(vrrp) + vrrp_ipsecah_len();
			vrrp_build_ipsecah(vrrp, bufptr, VRRP_SEND_BUFFER_SIZE(vrrp));
		}
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

static int
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
	vrrp->send_buffer_size = vrrp_hd_len(vrrp);

	if (vrrp->family == AF_INET) {
		vrrp->send_buffer_size = vrrp_iphdr_len(vrrp) + vrrp_hd_len(vrrp);
		if (vrrp->version == VRRP_VERSION_2 && vrrp->auth_type == VRRP_AUTH_AH)
			vrrp->send_buffer_size += vrrp_ipsecah_len();
	}

	vrrp->send_buffer = MALLOC(VRRP_SEND_BUFFER_SIZE(vrrp));
}

/* send VRRP advertissement */
int
vrrp_send_adv(vrrp_t * vrrp, int prio)
{
	struct sockaddr_storage *addr;
	list l = vrrp->unicast_peer;
	element e;
	int ret;

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
				log_message(LOG_INFO, "VRRP_Instance(%s) Cant sent advert to %s (%m)"
						    , vrrp->iname, inet_sockaddrtos(addr));
			}
		}
	} else {
		vrrp_build_pkt(vrrp, prio, NULL);
		vrrp_send_pkt(vrrp, NULL);
	}

	++vrrp->stats->advert_sent;
	/* send it */
	return 0;
}

/* Received packet processing */
int
vrrp_check_packet(vrrp_t * vrrp, char *buf, int buflen)
{
	int ret;

	if (buflen > 0) {
		ret = vrrp_in_chk(vrrp, buf);

		if (ret == VRRP_PACKET_DROP) {
			log_message(LOG_INFO, "Sync instance needed on %s !!!",
			       IF_NAME(vrrp->ifp));
		}

		if (ret == VRRP_PACKET_KO)
			log_message(LOG_INFO, "bogus VRRP packet received on %s !!!",
			       IF_NAME(vrrp->ifp));
		return ret;
	}

	return VRRP_PACKET_NULL;
}

/* Gratuitous ARP on each VIP */
static void
vrrp_send_update(vrrp_t * vrrp, ip_address_t * ipaddress, int idx)
{
	char *msg;
	char addr_str[41];

	if (!IP_IS6(ipaddress)) {
		msg = "gratuitous ARPs";
		inet_ntop(AF_INET, &ipaddress->u.sin.sin_addr, addr_str, 41);
		send_gratuitous_arp(ipaddress);
	} else {
		msg = "Unsolicited Neighbour Adverts";
		inet_ntop(AF_INET6, &ipaddress->u.sin6_addr, addr_str, 41);
		ndisc_send_unsolicited_na(ipaddress);
	}

	if (idx == 0 && __test_bit(LOG_DETAIL_BIT, &debug)) {
		log_message(LOG_INFO, "VRRP_Instance(%s) Sending %s on %s for %s",
			    vrrp->iname, msg, IF_NAME(ipaddress->ifp), addr_str);
	}
}

void
vrrp_send_link_update(vrrp_t * vrrp, int rep)
{
	int j;
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
				vrrp_send_update(vrrp, ipaddress, j);
			}
		}

		if (!LIST_ISEMPTY(vrrp->evip)) {
			for (e = LIST_HEAD(vrrp->evip); e; ELEMENT_NEXT(e)) {
				ipaddress = ELEMENT_DATA(e);
				vrrp_send_update(vrrp, ipaddress, j);
			}
		}
	}
}

/* becoming master */
void
vrrp_state_become_master(vrrp_t * vrrp)
{
	++vrrp->stats->become_master;

	if (vrrp->version == VRRP_VERSION_3)
		log_message(LOG_INFO, "VRRP_Instance(%s) using locally configured advertisement interval (%d milli-sec)",
					vrrp->iname, (vrrp->adver_int * 1000) / TIMER_HZ);

	/* add the ip addresses */
	if (!LIST_ISEMPTY(vrrp->vip)) {
		vrrp_handle_ipaddress(vrrp, IPADDRESS_ADD, VRRP_VIP_TYPE);
		vrrp_handle_accept_mode(vrrp, IPADDRESS_ADD);
	}
	if (!LIST_ISEMPTY(vrrp->evip))
		vrrp_handle_ipaddress(vrrp, IPADDRESS_ADD, VRRP_EVIP_TYPE);
	vrrp->vipset = 1;

	/* add virtual routes */
	if (!LIST_ISEMPTY(vrrp->vroutes))
		vrrp_handle_iproutes(vrrp, IPROUTE_ADD);

	/* remotes neighbour update */
	vrrp_send_link_update(vrrp, vrrp->garp_rep);

	/* set refresh timer */
	if (!timer_isnull(vrrp->garp_refresh)) {
		vrrp->garp_refresh_timer = timer_add_now(vrrp->garp_refresh);
	}

	/* Check if notify is needed */
	notify_instance_exec(vrrp, VRRP_STATE_MAST);

#ifdef _WITH_SNMP_
	vrrp_snmp_instance_trap(vrrp);
	vrrp_rfc_snmp_new_master_trap(vrrp);
#endif

#ifdef _HAVE_IPVS_SYNCD_
	/* Check if sync daemon handling is needed */
	if (vrrp->lvs_syncd_if)
		ipvs_syncd_master(vrrp->lvs_syncd_if, vrrp->vrid);
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
vrrp_restore_interface(vrrp_t * vrrp, int advF)
{
        /* if we stop vrrp, warn the other routers to speed up the recovery */
	if (advF) {
	        syslog(LOG_INFO, "VRRP_Instance(%s) sending 0 priority",
		       vrrp->iname);
		vrrp_send_adv(vrrp, VRRP_PRIO_STOP);
		++vrrp->stats->pri_zero_sent;
	}

	/* remove virtual routes */
	if (!LIST_ISEMPTY(vrrp->vroutes))
		vrrp_handle_iproutes(vrrp, IPROUTE_DEL);

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
	if (__test_bit(DONT_RELEASE_VRRP_BIT, &debug) || VRRP_VIP_ISSET(vrrp) ||
	    __test_bit(RELEASE_VIPS_BIT, &debug)) {
		if (!LIST_ISEMPTY(vrrp->vip)) {
			vrrp_handle_ipaddress(vrrp, IPADDRESS_DEL, VRRP_VIP_TYPE);
			vrrp_handle_accept_mode(vrrp, IPADDRESS_DEL);
		}
		if (!LIST_ISEMPTY(vrrp->evip))
			vrrp_handle_ipaddress(vrrp, IPADDRESS_DEL, VRRP_EVIP_TYPE);
		vrrp->vipset = 0;
	}

}

void
vrrp_state_leave_master(vrrp_t * vrrp)
{
	if (VRRP_VIP_ISSET(vrrp)) {
#ifdef _HAVE_IPVS_SYNCD_
		/* Check if sync daemon handling is needed */
		if (vrrp->lvs_syncd_if)
			ipvs_syncd_backup(vrrp->lvs_syncd_if, vrrp->vrid);
#endif
	}

	/* set the new vrrp state */
	switch (vrrp->wantstate) {
	case VRRP_STATE_BACK:
		log_message(LOG_INFO, "VRRP_Instance(%s) Entering BACKUP STATE", vrrp->iname);
		vrrp_restore_interface(vrrp, 0);
		vrrp->state = vrrp->wantstate;
		notify_instance_exec(vrrp, VRRP_STATE_BACK);
#ifdef _WITH_SNMP_
		vrrp_snmp_instance_trap(vrrp);
#endif
		break;
	case VRRP_STATE_GOTO_FAULT:
		log_message(LOG_INFO, "VRRP_Instance(%s) Entering FAULT STATE", vrrp->iname);
		vrrp_restore_interface(vrrp, 0);
		vrrp->state = VRRP_STATE_FAULT;
		notify_instance_exec(vrrp, VRRP_STATE_FAULT);
		vrrp_send_adv(vrrp, VRRP_PRIO_STOP);
#ifdef _WITH_SNMP_
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
vrrp_state_backup(vrrp_t * vrrp, char *buf, int buflen)
{
	vrrphdr_t *hd;
	int ret = 0, master_adver_int, proto;

	/* Process the incoming packet */
	hd = vrrp_get_header(vrrp->family, buf, &proto);
	ret = vrrp_check_packet(vrrp, buf, buflen);

	if (ret == VRRP_PACKET_KO || ret == VRRP_PACKET_NULL) {
		log_message(LOG_INFO, "VRRP_Instance(%s) ignoring received advertisment..."
			            ,  vrrp->iname);
		if (vrrp->version == VRRP_VERSION_3)
			vrrp->ms_down_timer = 3 * vrrp->master_adver_int + VRRP_TIMER_SKEW(vrrp);
		else
			vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
	} else if (hd->priority == 0) {
		vrrp->ms_down_timer = VRRP_TIMER_SKEW(vrrp);
	} else if (vrrp->nopreempt || hd->priority >= vrrp->effective_priority ||
		   timer_cmp(vrrp->preempt_time, timer_now()) > 0) {
		if (vrrp->version == VRRP_VERSION_3) {
			master_adver_int = (ntohs(hd->v3.adver_int) & 0x0FFF) * TIMER_HZ / 100;
			/* As per RFC5798, set Master_Adver_Interval to Adver Interval contained
		 	 * in the ADVERTISEMENT
			 */
			if (vrrp->master_adver_int != master_adver_int) {
				vrrp->master_adver_int = master_adver_int;
				log_message(LOG_INFO, "VRRP_Instance(%s) advertisement interval updated to %d milli-sec",
							vrrp->iname, (vrrp->master_adver_int * 1000) / TIMER_HZ);
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
				vrrp->preempt_time = timer_add_long(timer_now(),
							vrrp->preempt_delay);
				if (vrrp->preempt_delay_active) {
					log_message(LOG_INFO,
						"%s(%s) reset preempt delay",
						"VRRP_Instance", vrrp->iname);
					vrrp->preempt_delay_active = 0;
		        	}
			} else {
				if (!vrrp->preempt_delay_active) {
					log_message(LOG_INFO,
						"%s(%s) start preempt delay(%ld)",
						"VRRP_Instance", vrrp->iname,
						vrrp->preempt_delay / TIMER_HZ);
					vrrp->preempt_delay_active = 1;
				}
			}
		}
	} else if (hd->priority < vrrp->effective_priority) {
		log_message(LOG_INFO, "VRRP_Instance(%s) forcing a new MASTER election"
				    , vrrp->iname);
		vrrp->wantstate = VRRP_STATE_GOTO_MASTER;
		vrrp_send_adv(vrrp, vrrp->effective_priority);
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

int
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
vrrp_state_master_rx(vrrp_t * vrrp, char *buf, int buflen)
{
	vrrphdr_t *hd = NULL;
	int ret = 0, proto = 0;
	ipsec_ah_t *ah;

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
	ret = vrrp_check_packet(vrrp, buf, buflen);

	if (ret == VRRP_PACKET_KO ||
	    ret == VRRP_PACKET_NULL || ret == VRRP_PACKET_DROP) {
		log_message(LOG_INFO,
		       "VRRP_Instance(%s) Dropping received VRRP packet...",
		       vrrp->iname);
		return 0;
	} else if (hd->priority < vrrp->effective_priority) {
		/* We receive a lower prio adv we just refresh remote ARP cache */
		log_message(LOG_INFO, "VRRP_Instance(%s) Received lower prio advert"
				      ", forcing new election", vrrp->iname);
		if (proto == IPPROTO_IPSEC_AH) {
			ah = (ipsec_ah_t *) (buf + sizeof(struct iphdr));
			log_message(LOG_INFO, "VRRP_Instance(%s) IPSEC-AH : Syncing seq_num"
					      " - Increment seq"
					    , vrrp->iname);
			vrrp->ipsecah_counter->seq_number = ntohl(ah->seq_number) + 1;
			vrrp->ipsecah_counter->cycle = 0;
		}
		vrrp_send_adv(vrrp, vrrp->effective_priority);
		vrrp_send_link_update(vrrp, vrrp->garp_rep);
		return 0;
	} else if (hd->priority == 0) {
		vrrp_send_adv(vrrp, vrrp->effective_priority);
		return 0;
	} else if (hd->priority > vrrp->effective_priority ||
		   (hd->priority == vrrp->effective_priority &&
		    vrrp_saddr_cmp(&vrrp->pkt_saddr, vrrp) > 0)) {
		/* We send a last advert here in order to refresh remote MASTER
		 * coming up to force link update at MASTER side.
		 */
		vrrp_send_adv(vrrp, vrrp->effective_priority);

		log_message(LOG_INFO, "VRRP_Instance(%s) Received higher prio advert"
				    , vrrp->iname);
		if (proto == IPPROTO_IPSEC_AH) {
			ah = (ipsec_ah_t *) (buf + sizeof(struct iphdr));
			log_message(LOG_INFO, "VRRP_Instance(%s) IPSEC-AH : Syncing seq_num"
					      " - Decrement seq"
					    , vrrp->iname);
			vrrp->ipsecah_counter->seq_number = ntohl(ah->seq_number) - 1;
			vrrp->ipsecah_counter->cycle = 0;
		}

		vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
		vrrp->master_priority = hd->priority;
		vrrp->wantstate = VRRP_STATE_BACK;
		vrrp->state = VRRP_STATE_BACK;
		return 1;
	}

	return 0;
}

int
vrrp_state_fault_rx(vrrp_t * vrrp, char *buf, int buflen)
{
	vrrphdr_t *hd;
	int ret = 0, proto;

	/* Process the incoming packet */
	hd = vrrp_get_header(vrrp->family, buf, &proto);
	ret = vrrp_check_packet(vrrp, buf, buflen);

	if (ret == VRRP_PACKET_KO || ret == VRRP_PACKET_NULL || ret == VRRP_PACKET_DROP) {
		log_message(LOG_INFO, "VRRP_Instance(%s) Dropping received VRRP packet..."
				    , vrrp->iname);
		return 0;
	} else if (vrrp->effective_priority > hd->priority ||
		   hd->priority == VRRP_PRIO_OWNER) {
		if (!vrrp->nopreempt)
			return 1;
	}

	return 0;
}

/* check for minimum configuration requirements */
static int
chk_min_cfg(vrrp_t * vrrp)
{
	if (vrrp->vrid == 0) {
		log_message(LOG_INFO, "VRRP_Instance(%s) the virtual id must be set!",
		       vrrp->iname);
		return 0;
	}
	if (!vrrp->ifp) {
		log_message(LOG_INFO, "VRRP_Instance(%s) Unknown interface !",
		       vrrp->iname);
		return 0;
	}

	if ((vrrp->version == VRRP_VERSION_2 && vrrp->adver_int < TIMER_HZ) ||
	    (vrrp->version == VRRP_VERSION_2 && (vrrp->adver_int % 100))) {
		log_message(LOG_INFO, "VRRP_Instance(%s): sub-second advertisement interval not supported in version 2!",
			    vrrp->iname);
		return 0;
	}

	return 1;
}

/* open a VRRP sending socket */
int
open_vrrp_send_socket(sa_family_t family, int proto, int idx, int unicast)
{
	interface_t *ifp;
	int fd = -1;

	/* Retreive interface_t */
	ifp = if_get_by_ifindex(idx);

	/* Create and init socket descriptor */
	fd = socket(family, SOCK_RAW, proto);
	if (fd < 0) {
		log_message(LOG_INFO, "cant open raw socket. errno=%d", errno);
		return -1;
	}

	if (family == AF_INET) {
		/* Set v4 related */
		if_setsockopt_hdrincl(&fd);
		if_setsockopt_bindtodevice(&fd, ifp);
		if (!unicast)
			if_setsockopt_mcast_loop(family, &fd);
		if_setsockopt_priority(&fd);
		if (fd < 0)
			return -1;
	} else if (family == AF_INET6) {
		/* Set v6 related */
		if_setsockopt_ipv6_checksum(&fd);
		if (!unicast) {
			if_setsockopt_mcast_hops(family, &fd);
			if_setsockopt_mcast_if(family, &fd, ifp);
			if_setsockopt_mcast_loop(family, &fd);
		}
		if_setsockopt_priority(&fd);
		if (fd < 0)
			return -1;
	} else {
		log_message(LOG_INFO, "cant open raw socket. unknow family=%d"
				    , family);
		close(fd);
		return -1;
	}

	return fd;
}

/* open a VRRP socket and join the multicast group. */
int
open_vrrp_socket(sa_family_t family, int proto, int idx,
		 int unicast)
{
	interface_t *ifp;
	int fd = -1;

	/* Retreive interface_t */
	ifp = if_get_by_ifindex(idx);

	/* open the socket */
	fd = socket(family, SOCK_RAW, proto);
	if (fd < 0) {
		int err = errno;
		log_message(LOG_INFO, "cant open raw socket. errno=%d", err);
		return -1;
	}

	/* Join the VRRP MCAST group */
	if (!unicast) {
		if_join_vrrp_group(family, &fd, ifp, proto);
	}
	if (fd < 0)
		return -1;

	if (family == AF_INET) {
		/* Bind inbound stream */
		if_setsockopt_bindtodevice(&fd, ifp);
	} else if (family == AF_INET6) {
		/* Let kernel calculate checksum. */
		if_setsockopt_ipv6_checksum(&fd);
	}

	return fd;
}

void
close_vrrp_socket(vrrp_t * vrrp)
{
	if (LIST_ISEMPTY(vrrp->unicast_peer)) {
		if_leave_vrrp_group(vrrp->family, vrrp->fd_in, vrrp->ifp);
	} else {
		close(vrrp->fd_in);
	}
	close(vrrp->fd_out);
}

int
new_vrrp_socket(vrrp_t * vrrp)
{
	int old_fd = vrrp->fd_in;
	int proto, ifindex, unicast;

	/* close the desc & open a new one */
	close_vrrp_socket(vrrp);
	remove_vrrp_fd_bucket(vrrp);
	if (vrrp->version == VRRP_VERSION_2)
		proto = (vrrp->auth_type == VRRP_AUTH_AH) ? IPPROTO_IPSEC_AH :
				IPPROTO_VRRP;
	else
		proto = IPPROTO_VRRP;
	ifindex = (__test_bit(VRRP_VMAC_XMITBASE_BIT, &vrrp->vmac_flags)) ? IF_BASE_INDEX(vrrp->ifp) :
									    IF_INDEX(vrrp->ifp);
	unicast = !LIST_ISEMPTY(vrrp->unicast_peer);
	vrrp->fd_in = open_vrrp_socket(vrrp->family, proto, ifindex, unicast);
	vrrp->fd_out = open_vrrp_send_socket(vrrp->family, proto, ifindex, unicast);
	alloc_vrrp_fd_bucket(vrrp);

	/* Sync the other desc */
	set_vrrp_fd_bucket(old_fd, vrrp);

	return vrrp->fd_in;
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

		/* Remove VIPs/VROUTEs */
		if (vrrp->state == VRRP_STATE_MAST)
			vrrp_restore_interface(vrrp, 1);

		/* Remove VMAC */
		if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags))
			netlink_link_del_vmac(vrrp);

		/* Run stop script */
		if (vrrp->script_stop)
			notify_exec(vrrp->script_stop);

#ifdef _HAVE_IPVS_SYNCD_
		/*
		 * Stop stalled syncd. IPVS syncd state is the
		 * same as VRRP instance one. We need here to
		 * stop stalled syncd thread according to last
		 * VRRP instance state.
		 */
		if (vrrp->lvs_syncd_if)
			ipvs_syncd_cmd(IPVS_STOPDAEMON, NULL,
				       (vrrp->state == VRRP_STATE_MAST) ? IPVS_MASTER:
									  IPVS_BACKUP,
				       vrrp->vrid);
#endif
	}
}

/* complete vrrp structure */
static int
vrrp_complete_instance(vrrp_t * vrrp)
{
	vrrp->state = VRRP_STATE_INIT;
	if (!vrrp->adver_int)
		vrrp->adver_int = VRRP_ADVER_DFL * TIMER_HZ;
	vrrp->master_adver_int = vrrp->adver_int;
	if (!vrrp->effective_priority)
		vrrp->effective_priority = VRRP_PRIO_DFL;

	if (!vrrp->version)
		vrrp->version = VRRP_VERSION_2;

	return (chk_min_cfg(vrrp));
}

int
vrrp_complete_init(void)
{
	list l;
	element e;
	vrrp_t *vrrp;
	vrrp_sgroup_t *sgroup;

	/* Complete VRRP instance initialization */
	l = vrrp_data->vrrp;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (!vrrp_complete_instance(vrrp))
			return 0;
	}

	/* Build synchronization group index */
	l = vrrp_data->vrrp_sync_group;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		sgroup = ELEMENT_DATA(e);
		vrrp_sync_set_group(sgroup);
	}

	return 1;
}

int
vrrp_ipvs_needed(void)
{
	vrrp_t *vrrp;
	element e;

	if (!vrrp_data)
		return 0;

	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (vrrp->lvs_syncd_if) {
			return 1;
		}
	}

	return 0;
}

/* Try to find a VRRP instance */
static vrrp_t *
vrrp_exist(vrrp_t * old_vrrp)
{
	element e;
	list l = vrrp_data->vrrp;
	vrrp_t *vrrp;

	if (LIST_ISEMPTY(l))
		return NULL;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		if (!strcmp(vrrp->iname, old_vrrp->iname))
			return vrrp;
	}

	return NULL;
}

/* Clear VIP|EVIP not present into the new data */
static void
clear_diff_vrrp_vip(vrrp_t * old_vrrp, int type)
{
	vrrp_t *vrrp = vrrp_exist(old_vrrp);
	list l = (type == VRRP_VIP_TYPE) ? old_vrrp->vip : old_vrrp->evip;
	list n = (type == VRRP_VIP_TYPE) ? vrrp->vip : vrrp->evip;
	clear_diff_address(l, n);

	/* Clear iptable rule to VIP if needed. */
	if ((type == VRRP_VIP_TYPE) && !LIST_ISEMPTY(n) && old_vrrp->iptable_rules_set) {
		if ((vrrp->version == VRRP_VERSION_2) || vrrp->accept ||
		    (vrrp->base_priority == VRRP_PRIO_OWNER)) {
			handle_iptable_rule_to_iplist(n, IPADDRESS_DEL, IF_NAME(vrrp->ifp));
			vrrp->iptable_rules_set = false;
		} else
			vrrp->iptable_rules_set = true;
	}
}

/* Clear virtual routes not present in the new data */
static void
clear_diff_vrrp_vroutes(vrrp_t * old_vrrp)
{
	vrrp_t *vrrp = vrrp_exist(old_vrrp);
	clear_diff_routes(old_vrrp->vroutes, vrrp->vroutes);
}

/* Keep the state from before reload */
static void
reset_vrrp_state(vrrp_t * old_vrrp)
{
	/* Keep VRRP state, ipsec AH seq_number */
	vrrp_t *vrrp = vrrp_exist(old_vrrp);
	vrrp->state = old_vrrp->state;
	vrrp->init_state = old_vrrp->state;
	vrrp->wantstate = old_vrrp->state;
	if (!old_vrrp->sync)
		vrrp->effective_priority = old_vrrp->effective_priority;
	/* Save old stats */
	memcpy(vrrp->stats, old_vrrp->stats, sizeof(vrrp_stats));

	memcpy(vrrp->ipsecah_counter, old_vrrp->ipsecah_counter, sizeof(seq_counter_t));

#ifdef _HAVE_IPVS_SYNCD_
	if (old_vrrp->lvs_syncd_if)
		ipvs_syncd_cmd(IPVS_STOPDAEMON, NULL,
			       (old_vrrp->state == VRRP_STATE_MAST) ? IPVS_MASTER:
								      IPVS_BACKUP,
			       old_vrrp->vrid);
	if (vrrp->lvs_syncd_if)
		ipvs_syncd_cmd(IPVS_STARTDAEMON, NULL,
			       (vrrp->state == VRRP_STATE_MAST) ? IPVS_MASTER:
								  IPVS_BACKUP,
			       vrrp->vrid);
#endif

	/* Remember if we had vips up and add new ones if needed */
	vrrp->vipset = old_vrrp->vipset;
	if (vrrp->vipset) {
		if (!LIST_ISEMPTY(vrrp->vip)) {
			vrrp_handle_ipaddress(vrrp, IPADDRESS_ADD, VRRP_VIP_TYPE);
			vrrp_handle_accept_mode(vrrp, IPADDRESS_ADD);
		}
		if (!LIST_ISEMPTY(vrrp->evip))
			vrrp_handle_ipaddress(vrrp, IPADDRESS_ADD, VRRP_EVIP_TYPE);
		if (!LIST_ISEMPTY(vrrp->vroutes))
			vrrp_handle_iproutes(vrrp, IPROUTE_ADD);
	}
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
		 * Try to find this vrrp into the new conf data
		 * reloaded.
		 */
		new_vrrp = vrrp_exist(vrrp);
		if (!new_vrrp) {
			vrrp_restore_interface(vrrp, 1);

			/* Remove VMAC if one was created */
			if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags)) 
				netlink_link_del_vmac(vrrp);
		} else {
			/*
			 * If this vrrp instance exist in new
			 * data, then perform a VIP|EVIP diff.
			 */
			clear_diff_vrrp_vip(vrrp, VRRP_VIP_TYPE);
			clear_diff_vrrp_vip(vrrp, VRRP_EVIP_TYPE);

			/* virtual routes diff */
			clear_diff_vrrp_vroutes(vrrp);

			/* 
			 * Remove VMAC if it existed in old vrrp instance,
			 * but not the new one.
			 */
			if (__test_bit(VRRP_VMAC_BIT, &vrrp->vmac_flags) &&
			    !__test_bit(VRRP_VMAC_BIT, &new_vrrp->vmac_flags)) {
				netlink_link_del_vmac(vrrp);
			}

			/* reset the state */
			reset_vrrp_state(vrrp);
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

