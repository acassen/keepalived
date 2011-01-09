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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
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
#include "memory.h"
#include "list.h"
#include "logger.h"
#include "main.h"
#include "utils.h"
#include "notify.h"

/* add/remove Virtual IP addresses */
static int
vrrp_handle_ipaddress(vrrp_rt * vrrp, int cmd, int type)
{
	if (debug & 32)
		log_message(LOG_INFO, "VRRP_Instance(%s) %s protocol %s", vrrp->iname,
		       (cmd == IPADDRESS_ADD) ? "setting" : "removing",
		       (type == VRRP_VIP_TYPE) ? "VIPs." : "E-VIPs.");
	netlink_iplist((type == VRRP_VIP_TYPE) ? vrrp->vip : vrrp->evip, cmd);
	return 1;
}

/* add/remove Virtual routes */
static int
vrrp_handle_iproutes(vrrp_rt * vrrp, int cmd)
{
	if (debug & 32)
		log_message(LOG_INFO, "VRRP_Instance(%s) %s protocol Virtual Routes",
		       vrrp->iname,
		       (cmd == IPROUTE_ADD) ? "setting" : "removing");
	netlink_rtlist_ipv4(vrrp->vroutes, cmd);
	return 1;
}

/* IP header length */
static int
vrrp_iphdr_len(vrrp_rt * vrrp)
{
	return sizeof (struct iphdr);
}

/* IPSEC AH header length */
int
vrrp_ipsecah_len(void)
{
	return sizeof (ipsec_ah);
}

/* VRRP header length */
static int
vrrp_hd_len(vrrp_rt * vrrp)
{
	int len = sizeof (vrrp_pkt);
	if (vrrp->family == AF_INET)
		len += VRRP_AUTH_LEN + ((!LIST_ISEMPTY(vrrp->vip)) ? LIST_SIZE(vrrp->vip) * sizeof (uint32_t) : 0);
        return len;
}

/* VRRP header pointer from buffer */
vrrp_pkt *
vrrp_get_header(sa_family_t family, char *buf, int *proto, uint32_t *saddr)
{
	struct iphdr *iph;
	vrrp_pkt *hd = NULL;

	if (family == AF_INET) {
		iph = (struct iphdr *) buf;
		*saddr = iph->saddr;

		/* Fill the VRRP header */
		switch (iph->protocol) {
		case IPPROTO_IPSEC_AH:
			*proto = IPPROTO_IPSEC_AH;
			hd = (vrrp_pkt *) ((char *) iph + (iph->ihl << 2) +
					   vrrp_ipsecah_len());
			break;
		case IPPROTO_VRRP:
			*proto = IPPROTO_VRRP;
			hd = (vrrp_pkt *) ((char *) iph + (iph->ihl << 2));
			break;
		}
	} else if (family == AF_INET6) {
		*proto = IPPROTO_VRRP;
		*saddr = 0;
		hd = (vrrp_pkt *) buf;
	}

	return hd;
}

/*
 * IPSEC AH incoming packet check.
 * return 0 for a valid pkt, != 0 otherwise.
 */
static int
vrrp_in_chk_ipsecah(vrrp_rt * vrrp, char *buffer)
{
	struct iphdr *ip = (struct iphdr *) (buffer);
	ipsec_ah *ah = (ipsec_ah *) ((char *) ip + (ip->ihl << 2));
	unsigned char *digest;
	uint32_t backup_auth_data[3];

	/* first verify that the SPI value is equal to src IP */
	if (ah->spi != ip->saddr) {
		log_message(LOG_INFO,
		       "IPSEC AH : invalid IPSEC SPI value. %d and expect %d",
		       ip->saddr, ah->spi);
		return 1;
	}

	/*
	 * then proceed with the sequence number to prevent against replay attack.
	 * For inbound processing, we increment seq_number counter to audit 
	 * sender counter.
	 */
	vrrp->ipsecah_counter->seq_number++;
	if (ntohl(ah->seq_number) >= vrrp->ipsecah_counter->seq_number || vrrp->sync) {
		vrrp->ipsecah_counter->seq_number = ntohl(ah->seq_number);
	} else {
		log_message(LOG_INFO,
		       "VRRP_Instance(%s) IPSEC-AH : sequence number %d"
		       " already proceeded. Packet dropped. Local(%d)", vrrp->iname
		       , ntohl(ah->seq_number), vrrp->ipsecah_counter->seq_number);
		return 1;
	}

	/*
	 * then compute a ICV to compare with the one present in AH pkt.
	 * alloc a temp memory space to stock the ip mutable fields
	 */
	digest = (unsigned char *) MALLOC(16 * sizeof (unsigned char *));

	/* zero the ip mutable fields */
	ip->tos = 0;
	ip->frag_off = 0;
	ip->check = 0;
	memcpy(backup_auth_data, ah->auth_data, sizeof (ah->auth_data));
	memset(ah->auth_data, 0, sizeof (ah->auth_data));

	/* Compute the ICV */
	hmac_md5((unsigned char *) buffer,
		 vrrp_iphdr_len(vrrp) + vrrp_ipsecah_len() + vrrp_hd_len(vrrp)
		 , vrrp->auth_data, sizeof (vrrp->auth_data)
		 , digest);

	if (memcmp(backup_auth_data, digest, HMAC_MD5_TRUNC) != 0) {
		log_message(LOG_INFO, "VRRP_Instance(%s) IPSEC-AH : invalid"
		       " IPSEC HMAC-MD5 value. Due to fields mutation"
		       " or bad password !", vrrp->iname);
		return 1;
	}

	FREE(digest);
	return 0;
}

/* check if ipaddr is present in VIP buffer */
static int
vrrp_in_chk_vips(vrrp_rt * vrrp, ip_address *ipaddress, unsigned char *buffer)
{
	int i;
	uint32_t ipbuf;

	/* Just skip IPv6 address, when we are using a mixed v4/v6 vips
	 * set inside se same VRRP instance.
	 */
	if (IP_IS6(ipaddress))
		return 1;

	for (i = 0; i < LIST_SIZE(vrrp->vip); i++) {
		bcopy(buffer + i * sizeof (uint32_t), &ipbuf,
		      sizeof (uint32_t));
		if (ipaddress->u.sin.sin_addr.s_addr == ipbuf)
			return 1;
	}

	return 0;
}

/*
 * VRRP incoming packet check.
 * return 0 if the pkt is valid, != 0 otherwise.
 */
static int
vrrp_in_chk(vrrp_rt * vrrp, char *buffer)
{
	struct iphdr *ip;
	int ihl, vrrp_pkt_len;
	ipsec_ah *ah;
	vrrp_pkt *hd;
	unsigned char *vips;
	ip_address *ipaddress;
	element e;

	/* IPv4 related */
	if (vrrp->family == AF_INET) {

		ip = (struct iphdr *) (buffer);
		ihl = ip->ihl << 2;

		if (vrrp->auth_type == VRRP_AUTH_AH) {
			ah = (ipsec_ah *) (buffer + sizeof (struct iphdr));
			hd = (vrrp_pkt *) (buffer + ihl + vrrp_ipsecah_len());
		} else {
			hd = (vrrp_pkt *) (buffer + ihl);
		}
	
		/* pointer to vrrp vips pkt zone */
		vips = (unsigned char *) ((char *) hd + sizeof (vrrp_pkt));
	
		/* MUST verify that the IP TTL is 255 */
		if (ip->ttl != VRRP_IP_TTL) {
			log_message(LOG_INFO, "invalid ttl. %d and expect %d", ip->ttl,
			       VRRP_IP_TTL);
			return VRRP_PACKET_KO;
		}
	
		/*
		 * MUST verify that the received packet length is greater than or
		 * equal to the VRRP header
		 */
		if ((ntohs(ip->tot_len) - ihl) <= sizeof (vrrp_pkt)) {
			log_message(LOG_INFO,
			       "ip payload too short. %d and expect at least %d",
			       ntohs(ip->tot_len) - ihl, sizeof (vrrp_pkt));
			return VRRP_PACKET_KO;
		}

		if (!LIST_ISEMPTY(vrrp->vip)) {
			/*
			 * MAY verify that the IP address(es) associated with the
			 * VRID are valid
			 */
			if (hd->naddr != LIST_SIZE(vrrp->vip)) {
				log_message(LOG_INFO,
				       "receive an invalid ip number count associated with VRID!");
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
					return VRRP_PACKET_KO;
				}
			}
		}

		/* check the authentication if it is a passwd */
		if (hd->auth_type == VRRP_AUTH_PASS) {
			char *pw = (char *) ip + ntohs(ip->tot_len)
			    - sizeof (vrrp->auth_data);
			if (memcmp(pw, vrrp->auth_data, sizeof(vrrp->auth_data)) != 0) {
				log_message(LOG_INFO, "receive an invalid passwd!");
				return VRRP_PACKET_KO;
			}
		}

		/* check the authenicaion if it is ipsec ah */
		if (hd->auth_type == VRRP_AUTH_AH)
			return (vrrp_in_chk_ipsecah(vrrp, buffer));

		/* Set expected vrrp packet lenght */
		vrrp_pkt_len = sizeof(vrrp_pkt) + VRRP_AUTH_LEN + hd->naddr * sizeof(uint32_t);

	} else if (vrrp->family == AF_INET6) { /* IPv6 related */

		hd = (vrrp_pkt *) buffer;
		vrrp_pkt_len = sizeof(vrrp_pkt);

	} else {
		return VRRP_PACKET_KO;
	}

	/* MUST verify the VRRP version */
	if ((hd->vers_type >> 4) != VRRP_VERSION) {
		log_message(LOG_INFO, "invalid version. %d and expect %d",
		       (hd->vers_type >> 4), VRRP_VERSION);
		return VRRP_PACKET_KO;
	}

	/* MUST verify the VRRP checksum */
	if (in_csum((u_short *) hd, vrrp_pkt_len, 0)) {
		log_message(LOG_INFO, "Invalid vrrp checksum");
		return VRRP_PACKET_KO;
	}

	/*
	 * MUST perform authentication specified by Auth Type 
	 * check the authentication type
	 */
	if (vrrp->auth_type != hd->auth_type) {
		log_message(LOG_INFO, "receive a %d auth, expecting %d!",
		       vrrp->auth_type, hd->auth_type);
		return VRRP_PACKET_KO;
	}

	/* MUST verify that the VRID is valid on the receiving interface */
	if (vrrp->vrid != hd->vrid) {
		log_message(LOG_INFO,
		       "received VRID mismatch. Received %d, Expected %d",
		       hd->vrid, vrrp->vrid);
		return VRRP_PACKET_DROP;
	}

	if (LIST_ISEMPTY(vrrp->vip) && hd->naddr > 0) {
		log_message(LOG_INFO, "receive an invalid ip number count associated with VRID!");
		return VRRP_PACKET_KO;
	}

	/*
	 * MUST verify that the Adver Interval in the packet is the same as
	 * the locally configured for this virtual router
	 */
	if (vrrp->adver_int / TIMER_HZ != hd->adver_int) {
		log_message(LOG_INFO, "advertissement interval mismatch mine=%d rcved=%d",
		       vrrp->adver_int, hd->adver_int);
		/* to prevent concurent VRID running => multiple master in 1 VRID */
		return VRRP_PACKET_DROP;
	}

	return VRRP_PACKET_OK;
}

/* build IP header */
static void
vrrp_build_ip(vrrp_rt * vrrp, char *buffer, int buflen)
{
	struct iphdr *ip = (struct iphdr *) (buffer);

	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = ip->ihl * 4 + vrrp_hd_len(vrrp);
	ip->tot_len = htons(ip->tot_len);
	ip->id = htons(++vrrp->ip_id);
	/* kernel will fill in ID if left to 0, so we overflow to 1 */
	if (vrrp->ip_id == 65535)
		vrrp->ip_id = 1;
	ip->frag_off = 0;
	ip->ttl = VRRP_IP_TTL;

	/* fill protocol type --rfc2402.2 */
	ip->protocol =
	    (vrrp->auth_type == VRRP_AUTH_AH) ? IPPROTO_IPSEC_AH : IPPROTO_VRRP;
	ip->saddr = VRRP_PKT_SADDR(vrrp);
	ip->daddr = htonl(INADDR_VRRP_GROUP);

	/* checksum must be done last */
	ip->check = in_csum((u_short *) ip, ip->ihl * 4, 0);
}

/* build IPSEC AH header */
static void
vrrp_build_ipsecah(vrrp_rt * vrrp, char *buffer, int buflen)
{
	ICV_mutable_fields *ip_mutable_fields;
	unsigned char *digest;
	struct iphdr *ip = (struct iphdr *) (buffer);
	ipsec_ah *ah = (ipsec_ah *) (buffer + sizeof (struct iphdr));

	/* alloc a temp memory space to stock the ip mutable fields */
	ip_mutable_fields = (ICV_mutable_fields *) MALLOC(sizeof (ICV_mutable_fields));

	/* fill in next header filed --rfc2402.2.1 */
	ah->next_header = IPPROTO_VRRP;

	/* update IP header total length value */
	ip->tot_len = ip->ihl * 4 + vrrp_ipsecah_len() + vrrp_hd_len(vrrp);
	ip->tot_len = htons(ip->tot_len);

	/* update ip checksum */
	ip->check = 0;
	ip->check = in_csum((u_short *) ip, ip->ihl * 4, 0);

	/* backup the ip mutable fields */
	ip_mutable_fields->tos = ip->tos;
	ip_mutable_fields->frag_off = ip->frag_off;
	ip_mutable_fields->check = ip->check;

	/* zero the ip mutable fields */
	ip->tos = 0;
	ip->frag_off = 0;
	ip->check = 0;

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
	digest = (unsigned char *) MALLOC(16 * sizeof (unsigned char *));
	hmac_md5((unsigned char *) buffer, buflen, vrrp->auth_data, sizeof (vrrp->auth_data)
		 , digest);
	memcpy(ah->auth_data, digest, HMAC_MD5_TRUNC);

	/* Restore the ip mutable fields */
	ip->tos = ip_mutable_fields->tos;
	ip->frag_off = ip_mutable_fields->frag_off;
	ip->check = ip_mutable_fields->check;

	FREE(ip_mutable_fields);
	FREE(digest);
}

/* build VRRP header */
static int
vrrp_build_vrrp(vrrp_rt * vrrp, int prio, char *buffer)
{
	int i = 0;
	vrrp_pkt *hd = (vrrp_pkt *) buffer;
	uint32_t *iparr;
	element e;
	ip_address *ip_addr;

	/* Family independant */
	hd->vers_type = (VRRP_VERSION << 4) | VRRP_PKT_ADVERT;
	hd->vrid = vrrp->vrid;
	hd->priority = prio;
	hd->naddr = (!LIST_ISEMPTY(vrrp->vip)) ? LIST_SIZE(vrrp->vip) : 0;
	hd->auth_type = vrrp->auth_type;
	hd->adver_int = vrrp->adver_int / TIMER_HZ;

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
	}

	/* finaly compute vrrp checksum */
	hd->chksum = in_csum((u_short *) hd, vrrp_hd_len(vrrp), 0);

	return 0;
}

/* build VRRP packet */
static void
vrrp_build_pkt(vrrp_rt * vrrp, int prio)
{
	char *bufptr;
	int len;

	/* save reference values */
	bufptr = VRRP_SEND_BUFFER(vrrp);
	len = VRRP_SEND_BUFFER_SIZE(vrrp);

	if (vrrp->family == AF_INET) {
		/* build the ip header */
		vrrp_build_ip(vrrp, VRRP_SEND_BUFFER(vrrp), VRRP_SEND_BUFFER_SIZE(vrrp));

		/* build the vrrp header */
		vrrp->send_buffer += vrrp_iphdr_len(vrrp);

		if (vrrp->auth_type == VRRP_AUTH_AH)
			vrrp->send_buffer += vrrp_ipsecah_len();
		vrrp->send_buffer_size -= vrrp_iphdr_len(vrrp);

		if (vrrp->auth_type == VRRP_AUTH_AH)
			vrrp->send_buffer_size -= vrrp_ipsecah_len();
		vrrp_build_vrrp(vrrp, prio, vrrp->send_buffer);

		/* build the IPSEC AH header */
		if (vrrp->auth_type == VRRP_AUTH_AH) {
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
vrrp_send_pkt(vrrp_rt * vrrp)
{
	struct sockaddr_in6 dst6;
	struct sockaddr_in dst4;
	struct msghdr msg;
	struct iovec iov;

	/* Build the message data */
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = VRRP_SEND_BUFFER(vrrp);
	iov.iov_len = VRRP_SEND_BUFFER_SIZE(vrrp);

	/* Sending path */
	if (vrrp->family == AF_INET) {
		memset(&dst4, 0, sizeof(dst4));
		dst4.sin_family = AF_INET;
		dst4.sin_addr.s_addr = htonl(INADDR_VRRP_GROUP);

		msg.msg_name = &dst4;
		msg.msg_namelen = sizeof(dst4);
	} else if (vrrp->family == AF_INET6) {
		memset(&dst6, 0, sizeof(dst6));
		dst6.sin6_family = AF_INET6;
		dst6.sin6_port = htons(IPPROTO_VRRP);
		dst6.sin6_addr.s6_addr16[0] = htons(0xff02);
		dst6.sin6_addr.s6_addr16[7] = htons(0x12);

		msg.msg_name = &dst6;
		msg.msg_namelen = sizeof(dst6);
	}

	/* Send the packet */
	return sendmsg(vrrp->fd_out, &msg, MSG_DONTROUTE);
}

/* Allocate the sending buffer */
static void
vrrp_alloc_send_buffer(vrrp_rt * vrrp)
{
	vrrp->send_buffer_size = vrrp_hd_len(vrrp);

	if (vrrp->family == AF_INET) {
		vrrp->send_buffer_size = vrrp_iphdr_len(vrrp) + vrrp_hd_len(vrrp);
		if (vrrp->auth_type == VRRP_AUTH_AH)
			vrrp->send_buffer_size += vrrp_ipsecah_len();
	}

	vrrp->send_buffer = MALLOC(VRRP_SEND_BUFFER_SIZE(vrrp));
}

/* send VRRP advertissement */
int
vrrp_send_adv(vrrp_rt * vrrp, int prio)
{
	/* alloc send buffer */
	if (!vrrp->send_buffer)
		vrrp_alloc_send_buffer(vrrp);
	else
		memset(vrrp->send_buffer, 0, VRRP_SEND_BUFFER_SIZE(vrrp));

	/* build the packet */
	vrrp_build_pkt(vrrp, prio);

	/* send it */
	return vrrp_send_pkt(vrrp);
}

/* Received packet processing */
int
vrrp_check_packet(vrrp_rt * vrrp, char *buf, int buflen)
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
vrrp_send_update(vrrp_rt * vrrp, ip_address * ipaddress, int idx)
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

	if (0 == idx && debug & 32) {
		log_message(LOG_INFO, "VRRP_Instance(%s) Sending %s on %s for %s",
			    vrrp->iname, msg, IF_NAME(ipaddress->ifp), addr_str);
	}
}

void
vrrp_send_link_update(vrrp_rt * vrrp)
{
	int j;
	ip_address *ipaddress;
	element e;

	/* Only send gratuitous ARP if VIP are set */
	if (!VRRP_VIP_ISSET(vrrp))
		return;

	/* send gratuitous arp for each virtual ip */
	for (j = 0; j < 5; j++) {
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
vrrp_state_become_master(vrrp_rt * vrrp)
{
	/* add the ip addresses */
	if (!LIST_ISEMPTY(vrrp->vip))
		vrrp_handle_ipaddress(vrrp, IPADDRESS_ADD, VRRP_VIP_TYPE);
	if (!LIST_ISEMPTY(vrrp->evip))
		vrrp_handle_ipaddress(vrrp, IPADDRESS_ADD, VRRP_EVIP_TYPE);
	vrrp->vipset = 1;

	/* add virtual routes */
	if (!LIST_ISEMPTY(vrrp->vroutes))
		vrrp_handle_iproutes(vrrp, IPROUTE_ADD);

	/* remotes neighbour update */
	vrrp_send_link_update(vrrp);

	/* Check if notify is needed */
	notify_instance_exec(vrrp, VRRP_STATE_MAST);

#ifdef _HAVE_IPVS_SYNCD_
	/* Check if sync daemon handling is needed */
	if (vrrp->lvs_syncd_if)
		ipvs_syncd_master(vrrp->lvs_syncd_if, vrrp->vrid);
#endif
}

void
vrrp_state_goto_master(vrrp_rt * vrrp)
{
	/*
	 * Send an advertisement. To force a new master
	 * election.
	 */
	vrrp_send_adv(vrrp, vrrp->effective_priority);

	vrrp->state = VRRP_STATE_MAST;
	log_message(LOG_INFO, "VRRP_Instance(%s) Transition to MASTER STATE",
	       vrrp->iname);
}

/* leaving master state */
void
vrrp_restore_interface(vrrp_rt * vrrp, int advF)
{
	/* remove virtual routes */
	if (!LIST_ISEMPTY(vrrp->vroutes))
		vrrp_handle_iproutes(vrrp, IPROUTE_DEL);

	/*
	 * Remove the ip addresses.
	 *
	 * If started with "--dont-release-vrrp" (debug & 8) then try to remove
	 * addresses even if we didn't add them during this run.
	 */
	if (debug & 8 || VRRP_VIP_ISSET(vrrp)) {
		if (!LIST_ISEMPTY(vrrp->vip))
			vrrp_handle_ipaddress(vrrp, IPADDRESS_DEL,
					      VRRP_VIP_TYPE);
		if (!LIST_ISEMPTY(vrrp->evip))
			vrrp_handle_ipaddress(vrrp, IPADDRESS_DEL,
					      VRRP_EVIP_TYPE);
		vrrp->vipset = 0;
	}


	/* if we stop vrrp, warn the other routers to speed up the recovery */
	if (advF)
		vrrp_send_adv(vrrp, VRRP_PRIO_STOP);
}

void
vrrp_state_leave_master(vrrp_rt * vrrp)
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
		break;
	case VRRP_STATE_GOTO_FAULT:
		log_message(LOG_INFO, "VRRP_Instance(%s) Entering FAULT STATE", vrrp->iname);
		vrrp_restore_interface(vrrp, 0);
		vrrp->state = VRRP_STATE_FAULT;
		notify_instance_exec(vrrp, VRRP_STATE_FAULT);
		break;
	}

	/* Set the down timer */
	vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
}

/* BACKUP state processing */
void
vrrp_state_backup(vrrp_rt * vrrp, char *buf, int buflen)
{
	vrrp_pkt *hd;
	uint32_t saddr;
	int ret = 0, proto;

	/* Process the incoming packet */
	hd = vrrp_get_header(vrrp->family, buf, &proto, &saddr);
	ret = vrrp_check_packet(vrrp, buf, buflen);

	if (ret == VRRP_PACKET_KO || ret == VRRP_PACKET_NULL) {
		log_message(LOG_INFO, "VRRP_Instance(%s) ignoring received advertisment..."
			            ,  vrrp->iname);
		vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
	} else if (hd->priority == 0) {
		vrrp->ms_down_timer = VRRP_TIMER_SKEW(vrrp);
	} else if (vrrp->nopreempt || hd->priority >= vrrp->effective_priority ||
		   timer_cmp(vrrp->preempt_time, timer_now()) > 0) {
		vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
	} else if (hd->priority < vrrp->effective_priority) {
		log_message(LOG_INFO, "VRRP_Instance(%s) forcing a new MASTER election"
				    , vrrp->iname);
		vrrp->wantstate = VRRP_STATE_GOTO_MASTER;
		vrrp_send_adv(vrrp, vrrp->effective_priority);
	}
}

/* MASTER state processing */
int
vrrp_state_master_tx(vrrp_rt * vrrp, const int prio)
{
	int ret = 0;

	if (!VRRP_VIP_ISSET(vrrp)) {
		log_message(LOG_INFO, "VRRP_Instance(%s) Entering MASTER STATE"
				    , vrrp->iname);
		vrrp_state_become_master(vrrp);
		ret = 1;
	}

	vrrp_send_adv(vrrp,
		      (prio == VRRP_PRIO_OWNER) ? VRRP_PRIO_OWNER :
						  vrrp->effective_priority);
	return ret;
}

int
vrrp_state_master_rx(vrrp_rt * vrrp, char *buf, int buflen)
{
	vrrp_pkt *hd = NULL;
	int ret = 0, proto = 0;
	uint32_t saddr = 0;
	ipsec_ah *ah;

	/* return on link failure */
	if (vrrp->wantstate == VRRP_STATE_GOTO_FAULT) {
		vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
		vrrp->state = VRRP_STATE_FAULT;
		notify_instance_exec(vrrp, VRRP_STATE_FAULT);
		return 1;
	}

	/* Process the incoming packet */
	hd = vrrp_get_header(vrrp->family, buf, &proto, &saddr);
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
			ah = (ipsec_ah *) (buf + sizeof(struct iphdr));
			log_message(LOG_INFO, "VRRP_Instance(%s) IPSEC-AH : Syncing seq_num"
					      " - Increment seq"
					    , vrrp->iname);
			vrrp->ipsecah_counter->seq_number = ntohl(ah->seq_number) + 1;
			vrrp->ipsecah_counter->cycle = 0;
		}
		vrrp_send_adv(vrrp, vrrp->effective_priority);
		vrrp_send_link_update(vrrp);
		return 0;
	} else if (hd->priority == 0) {
		vrrp_send_adv(vrrp, vrrp->effective_priority);
		return 0;
	} else if (vrrp->family == AF_INET) {
		if (hd->priority > vrrp->effective_priority ||
		    (hd->priority == vrrp->effective_priority &&
		     ntohl(saddr) > VRRP_PKT_SADDR(vrrp))) {
			log_message(LOG_INFO, "VRRP_Instance(%s) Received higher prio advert"
					    , vrrp->iname);
			if (proto == IPPROTO_IPSEC_AH) {
				ah = (ipsec_ah *) (buf + sizeof(struct iphdr));
				log_message(LOG_INFO, "VRRP_Instance(%s) IPSEC-AH : Syncing seq_num"
						      " - Decrement seq"
						    , vrrp->iname);
				vrrp->ipsecah_counter->seq_number = ntohl(ah->seq_number) - 1;
				vrrp->ipsecah_counter->cycle = 0;
			}
			vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
			vrrp->wantstate = VRRP_STATE_BACK;
			vrrp->state = VRRP_STATE_BACK;
			return 1;
		}
	} else if (vrrp->family == AF_INET6) {
		/* FIXME: compare v6 saddr to link local when prio are equal !!! */
		if (hd->priority > vrrp->effective_priority) {
			log_message(LOG_INFO, "VRRP_Instance(%s) Received higher prio advert"
					    , vrrp->iname);
			vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
			vrrp->wantstate = VRRP_STATE_BACK;
			vrrp->state = VRRP_STATE_BACK;
			return 1;
		}
	}

	return 0;
}

int
vrrp_state_fault_rx(vrrp_rt * vrrp, char *buf, int buflen)
{
	vrrp_pkt *hd;
	uint32_t saddr;
	int ret = 0, proto;

	/* Process the incoming packet */
	hd = vrrp_get_header(vrrp->family, buf, &proto, &saddr);
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
chk_min_cfg(vrrp_rt * vrrp)
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

	return 1;
}

/* open a VRRP sending socket */
int
open_vrrp_send_socket(sa_family_t family, int proto, int idx)
{
	interface *ifp;
	int fd = -1;

	/* Retreive interface */
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
		if_setsockopt_mcast_loop(family, &fd);
		if (fd < 0)
			return -1;
	} else if (family == AF_INET6) {
		/* Set v6 related */
		if_setsockopt_mcast_hops(family, &fd);
		if_setsockopt_mcast_if(family, &fd, ifp);
		if_setsockopt_mcast_loop(family, &fd);
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
open_vrrp_socket(sa_family_t family, int proto, int idx)
{
	interface *ifp;
	int fd = -1;

	/* Retreive interface */
	ifp = if_get_by_ifindex(idx);

	/* open the socket */
	fd = socket(family, SOCK_RAW, proto);
	if (fd < 0) {
		int err = errno;
		log_message(LOG_INFO, "cant open raw socket. errno=%d", err);
		return -1;
	}

	/* Join the VRRP MCAST group */
	if_join_vrrp_group(family, &fd, ifp, proto);
	if (fd < 0)
		return -1;

	if (family == AF_INET) {
		/* Bind inbound stream */
		if_setsockopt_bindtodevice(&fd, ifp);
	}

	return fd;
}

void
close_vrrp_socket(vrrp_rt * vrrp)
{
	if_leave_vrrp_group(vrrp->family, vrrp->fd_in, vrrp->ifp);
	close(vrrp->fd_out);
}

int
new_vrrp_socket(vrrp_rt * vrrp)
{
	int old_fd = vrrp->fd_in;
	int proto;

	/* close the desc & open a new one */
	close_vrrp_socket(vrrp);
	remove_vrrp_fd_bucket(vrrp);
	proto = (vrrp->auth_type == VRRP_AUTH_AH) ? IPPROTO_IPSEC_AH : IPPROTO_VRRP;
	vrrp->fd_in = open_vrrp_socket(vrrp->family, proto, IF_INDEX(vrrp->ifp));
	vrrp->fd_out = open_vrrp_send_socket(vrrp->family, proto, IF_INDEX(vrrp->ifp));
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
	vrrp_rt *vrrp;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		/* remove VIPs */
		if (vrrp->state == VRRP_STATE_MAST)
			vrrp_restore_interface(vrrp, 1);

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
vrrp_complete_instance(vrrp_rt * vrrp)
{
	vrrp->state = VRRP_STATE_INIT;
	if (!vrrp->adver_int)
		vrrp->adver_int = VRRP_ADVER_DFL * TIMER_HZ;
	if (!vrrp->effective_priority)
		vrrp->effective_priority = VRRP_PRIO_DFL;

	return (chk_min_cfg(vrrp));
}

int
vrrp_complete_init(void)
{
	list l;
	element e;
	vrrp_rt *vrrp;
	vrrp_sgroup *sgroup;

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

/* Try to find a VRRP instance */
static vrrp_rt *
vrrp_exist(vrrp_rt * old_vrrp)
{
	element e;
	list l = vrrp_data->vrrp;
	vrrp_rt *vrrp;

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
clear_diff_vrrp_vip(vrrp_rt * old_vrrp, int type)
{
	vrrp_rt *vrrp = vrrp_exist(old_vrrp);
	list l = (type == VRRP_VIP_TYPE) ? old_vrrp->vip : old_vrrp->evip;
	list n = (type == VRRP_VIP_TYPE) ? vrrp->vip : vrrp->evip;
	clear_diff_address(l, n);
}

/* Clear virtual routes not present in the new data */
static void
clear_diff_vrrp_vroutes(vrrp_rt * old_vrrp)
{
	vrrp_rt *vrrp = vrrp_exist(old_vrrp);
	clear_diff_routes(old_vrrp->vroutes, vrrp->vroutes);
}

/* Keep the state from before reload */
static void
reset_vrrp_state(vrrp_rt * old_vrrp)
{
	/* Keep VRRP state, ipsec AH seq_number */
	vrrp_rt *vrrp = vrrp_exist(old_vrrp);
	vrrp->state = old_vrrp->state;
	vrrp->init_state = old_vrrp->state;
	vrrp->wantstate = old_vrrp->state;
	vrrp->effective_priority = old_vrrp->effective_priority;
	memcpy(vrrp->ipsecah_counter, old_vrrp->ipsecah_counter, sizeof(seq_counter));

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
		if (!LIST_ISEMPTY(vrrp->vip))
			vrrp_handle_ipaddress(vrrp, IPADDRESS_ADD, VRRP_VIP_TYPE);
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
	vrrp_rt *vrrp;

	if (LIST_ISEMPTY(l))
		return;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		/*
		 * Try to find this vrrp into the new conf data
		 * reloaded.
		 */
		if (!vrrp_exist(vrrp)) {
			vrrp_restore_interface(vrrp, 0);
		} else {
			/*
			 * If this vrrp instance exist in new
			 * data, then perform a VIP|EVIP diff.
			 */
			clear_diff_vrrp_vip(vrrp, VRRP_VIP_TYPE);
			clear_diff_vrrp_vip(vrrp, VRRP_EVIP_TYPE);

			/* virtual routes diff */
			clear_diff_vrrp_vroutes(vrrp);

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
	vrrp_script *vscript, *nvscript;

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
