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
 * Version:     $Id: vrrp.c,v 0.6.4 2002/06/25 20:18:34 acassen Exp $
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
 */

/* local include */
#include <ctype.h>
#include "vrrp_scheduler.h"
#include "vrrp_notify.h"
#include "ipvswrapper.h"
#include "vrrp.h"
#include "memory.h"
#include "list.h"
#include "data.h"

extern data *conf_data;

/* compute checksum */
static u_short in_csum( u_short *addr, int len, u_short csum)
{
  register int nleft = len;
  const u_short *w = addr;
  register u_short answer;
  register int sum = csum;

  /*
   *  Our algorithm is simple, using a 32 bit accumulator (sum),
   *  we add sequential 16 bit words to it, and at the end, fold
   *  back all the carry bits from the top 16 bits into the lower
   *  16 bits.
   */
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1)
    sum += htons(*(u_char *)w << 8);

  /*
   * add back carry outs from top 16 bits to low 16 bits
   */
  sum = (sum >> 16) + (sum & 0xffff);  /* add hi 16 to low 16 */
  sum += (sum >> 16);      /* add carry */
  answer = ~sum;        /* truncate to 16 bits */
  return (answer);
}

/*
 * add/remove VIP
 * retry must clear for each vip address Hoj:-
 */
static int vrrp_handle_ipaddress(vrrp_rt *vrrp, int cmd, int type)
{
  int i, err = 0;
  int retry = 0;
  int num;
  int ifindex = IF_INDEX(vrrp->ifp);

  syslog(LOG_INFO, "VRRP_Instance(%s) %s protocol %s"
                 , vrrp->iname
                 , (cmd == VRRP_IPADDRESS_ADD)?"setting":"removing"
                 , (type == VRRP_VIP_TYPE)?"VIPs.":"E-VIPs");

  num = (type == VRRP_VIP_TYPE)?vrrp->naddr:vrrp->neaddr;
  for(i = 0; i < num; i++ ) {
    vip_addr *vadd = (type == VRRP_VIP_TYPE)?&vrrp->vaddr[i]:&vrrp->evaddr[i];
    if(!cmd && !vadd->set) continue;
retry:
    if (netlink_address_ipv4(ifindex , vadd->addr, vadd->mask, cmd) < 0) {
      err = 1;
      vadd->set = 0;
      syslog(LOG_INFO, "cant %s the address %s to %s\n"
                     , cmd ? "set" : "remove"
                     , inet_ntop2(vadd->addr)
                     , IF_NAME(vrrp->ifp));
      if (cmd == VRRP_IPADDRESS_ADD) {
        syslog(LOG_INFO, "try to delete eventual stalled ip");
        netlink_address_ipv4(ifindex, vadd->addr, vadd->mask, VRRP_IPADDRESS_DEL);
        if (retry < 4) {
          retry++;
          goto retry;
        }
      }
    } else {
      vadd->set = 1;
    }
  }
  return err;
}

/* ARP header length */
static int vrrp_dlt_len( vrrp_rt *rt )
{
  return ETHER_HDR_LEN;  /* hardcoded for ethernet */
}

/* IP header length */
static int vrrp_iphdr_len(vrrp_rt *vrrp)
{
  return sizeof(struct iphdr);
}

/* IPSEC AH header length */
int vrrp_ipsecah_len(void)
{
  return sizeof(ipsec_ah);
}

/* VRRP header length */
static int vrrp_hd_len(vrrp_rt *vrrp)
{
  return sizeof(vrrp_pkt)
         + vrrp->naddr * sizeof(uint32_t)
         + VRRP_AUTH_LEN;
}

/*
 * IPSEC AH incoming packet check.
 * return 0 for a valid pkt, != 0 otherwise.
 */
static int vrrp_in_chk_ipsecah(vrrp_rt *vrrp, char *buffer)
{
  struct iphdr *ip = (struct iphdr*)(buffer);
  ipsec_ah *ah = (ipsec_ah *)((char *)ip + (ip->ihl<<2));
  unsigned char *digest;
  uint32_t backup_auth_data[3];

  /* first verify that the SPI value is equal to src IP */
  if(ah->spi != ip->saddr) {
    syslog(LOG_INFO, "IPSEC AH : invalid IPSEC SPI value. %d and expect %d"
                   , ip->saddr, ah->spi);
    return 1;
  }

  /*
   * then proceed with the sequence number to prevent against replay attack.
   * in inbound processing, we increment seq_number counter to audit 
   * sender counter.
   */
  vrrp->ipsecah_counter->seq_number++;
  if (ah->seq_number >= vrrp->ipsecah_counter->seq_number) {
    vrrp->ipsecah_counter->seq_number = ah->seq_number;
  } else {
    syslog(LOG_INFO, "IPSEC AH : sequence number %d already proceeded."
                     " Packet droped", ah->seq_number);
    return 1;
  }
 
  /*
   * then compute a ICV to compare with the one present in AH pkt.
   * alloc a temp memory space to stock the ip mutable fields
   */
  digest = (unsigned char *)MALLOC(16*sizeof(unsigned char *));

  /* zero the ip mutable fields */
  ip->tos = 0;
  ip->id = 0;
  ip->frag_off = 0;
  ip->check = 0;
  memcpy(backup_auth_data, ah->auth_data, sizeof(ah->auth_data));
  memset(ah->auth_data, 0, sizeof(ah->auth_data));

  /* Compute the ICV */
  hmac_md5(buffer, vrrp_iphdr_len(vrrp) + vrrp_ipsecah_len() + vrrp_hd_len(vrrp)
                 , vrrp->auth_data
                 , sizeof(vrrp->auth_data)
                 , digest);

  if (memcmp(backup_auth_data, digest, HMAC_MD5_TRUNC) != 0) {
    syslog(LOG_INFO, "IPSEC AH : invalid IPSEC HMAC-MD5 value."
                     " Due to fields mutation or bad password !");
    return 1;
  }

  FREE(digest);
  return 0;
}

/* check if ipaddr is present in VIP buffer */
static int vrrp_in_chk_vips(vrrp_rt *vrrp, uint32_t ipaddr, unsigned char *buffer)
{
  int i;
  uint32_t ipbuf;

  for (i=0; i < vrrp->naddr; i++) {
    bcopy(buffer+i*sizeof(uint32_t), &ipbuf, sizeof(uint32_t));
    if (ipaddr == ntohl(ipbuf)) return 1;
  }

  return 0;
}

/*
 * VRRP incoming packet check.
 * return 0 if the pkt is valid, != 0 otherwise.
 */
static int vrrp_in_chk(vrrp_rt *vrrp, char *buffer)
{
  struct iphdr *ip = (struct iphdr*)(buffer);
  int ihl = ip->ihl << 2;
  ipsec_ah *ah;
  vrrp_pkt *hd;
  unsigned char *vips;
  int i;

  if (vrrp->auth_type == VRRP_AUTH_AH) {
    ah = (ipsec_ah *)(buffer + sizeof(struct iphdr));
    hd = (vrrp_pkt *)(buffer + ihl + vrrp_ipsecah_len());
  } else {
    hd = (vrrp_pkt *)(buffer + ihl);
  }

  /* pointer to vrrp vips pkt zone */
  vips = (unsigned char *)((char *)hd + sizeof(vrrp_pkt));

  /* MUST verify that the IP TTL is 255 */
  if( ip->ttl != VRRP_IP_TTL ) {
    syslog(LOG_INFO, "invalid ttl. %d and expect %d"
                   , ip->ttl, VRRP_IP_TTL);
    return VRRP_PACKET_KO;
  }

  /* MUST verify the VRRP version */
  if ((hd->vers_type >> 4) != VRRP_VERSION) {
    syslog(LOG_INFO, "invalid version. %d and expect %d"
                   , (hd->vers_type >> 4), VRRP_VERSION);
    return VRRP_PACKET_KO;
  }

  /*
   * MUST verify that the received packet length is greater than or
   * equal to the VRRP header
   */
  if ((ntohs(ip->tot_len)-ihl) <= sizeof(vrrp_pkt)) {
    syslog(LOG_INFO, "ip payload too short. %d and expect at least %d"
                   , ntohs(ip->tot_len)-ihl, sizeof(vrrp_pkt));
    return VRRP_PACKET_KO;
  }

  /* MUST verify the VRRP checksum */
  if (in_csum( (u_short*)hd, vrrp_hd_len(vrrp), 0)) {
    syslog(LOG_INFO, "Invalid vrrp checksum");
    return VRRP_PACKET_KO;
  }

  /*
   * MUST perform authentication specified by Auth Type 
   * check the authentication type
   */
  if (vrrp->auth_type != hd->auth_type) {    
    syslog(LOG_INFO, "receive a %d auth, expecting %d!", vrrp->auth_type
                   , hd->auth_type);
    return VRRP_PACKET_KO;
  }

  /* check the authentication if it is a passwd */
  if (hd->auth_type == VRRP_AUTH_PASS) {
    char *pw = (char *)ip + ntohs(ip->tot_len)
                          - sizeof(vrrp->auth_data);
    if (strncmp(pw, vrrp->auth_data, strlen(vrrp->auth_data)) != 0) {
      syslog(LOG_INFO, "receive an invalid passwd!");
      return VRRP_PACKET_KO;
    }
  }

  /* MUST verify that the VRID is valid on the receiving interface */
  if (vrrp->vrid != hd->vrid) {
    syslog(LOG_INFO, "received VRID mismatch. Received %d, Expected %d"
                   , hd->vrid
                   , vrrp->vrid);
    return VRRP_PACKET_DROP;
  }

  /*
   * MAY verify that the IP address(es) associated with the
   * VRID are valid
   */
  if (vrrp->naddr != hd->naddr) {
    syslog(LOG_INFO, "receive an invalid ip number count associated with VRID!");
    return VRRP_PACKET_KO;
  }

  for (i=0; i < vrrp->naddr; i++)
    if (!vrrp_in_chk_vips(vrrp, vrrp->vaddr[i].addr,vips)) {
      syslog(LOG_INFO, "ip address associated with VRID"
                       " not present in received packet : %d"
                     , vrrp->vaddr[i].addr);
      syslog(LOG_INFO, "one or more VIP associated with"
                       " VRID mismatch actual MASTER advert");
      return VRRP_PACKET_KO;
    }

  /*
   * MUST verify that the Adver Interval in the packet is the same as
   * the locally configured for this virtual router
   */
  if (vrrp->adver_int/TIMER_HZ != hd->adver_int) {
    syslog(LOG_INFO, "advertissement interval mismatch mine=%d rcved=%d"
                   , vrrp->adver_int
                   , hd->adver_int);
    /* to prevent concurent VRID running => multiple master in 1 VRID */
    return VRRP_PACKET_DROP;
  }

  /* check the authenicaion if it is ipsec ah */
  if(hd->auth_type == VRRP_AUTH_AH)
    return(vrrp_in_chk_ipsecah(vrrp, buffer));

  return VRRP_PACKET_OK;
}

/* build ARP header */
static void vrrp_build_arp(vrrp_rt *vrrp, char *buffer, int buflen)
{
  /* hardcoded for ethernet */
  struct ether_header * eth = (struct ether_header *)buffer;

  /* destination address --rfc1122.6.4*/
  eth->ether_dhost[0] = 0x01;
  eth->ether_dhost[1] = 0x00;
  eth->ether_dhost[2] = 0x5E;
  eth->ether_dhost[3] = (INADDR_VRRP_GROUP >> 16) & 0x7F;
  eth->ether_dhost[4] = (INADDR_VRRP_GROUP >>  8) & 0xFF;
  eth->ether_dhost[5] = INADDR_VRRP_GROUP & 0xFF;

  /* source address -- rfc2338.7.3 */
  memcpy(eth->ether_shost, vrrp->hwaddr, sizeof(vrrp->hwaddr));

  /* type */
  eth->ether_type = htons(ETHERTYPE_IP);
}

/* build IP header */
static void vrrp_build_ip(vrrp_rt *vrrp, char *buffer, int buflen)
{
  struct iphdr *ip = (struct iphdr *)(buffer);

  ip->ihl      = 5;
  ip->version  = 4;
  ip->tos      = 0;
  ip->tot_len  = ip->ihl*4 + vrrp_hd_len(vrrp);
  ip->tot_len  = htons(ip->tot_len);
  ip->id       = ++vrrp->ip_id;
  ip->frag_off = 0;
  ip->ttl      = VRRP_IP_TTL;

  /* fill protocol type --rfc2402.2 */
  ip->protocol = (vrrp->auth_type == VRRP_AUTH_AH)?IPPROTO_IPSEC_AH:IPPROTO_VRRP;
  ip->saddr    = VRRP_PKT_SADDR(vrrp);
  ip->daddr    = htonl(INADDR_VRRP_GROUP);

  /* checksum must be done last */
  ip->check = in_csum((u_short*)ip, ip->ihl*4, 0);
}

/* build IPSEC AH header */
static void vrrp_build_ipsecah(vrrp_rt *vrrp, char *buffer, int buflen)
{
  ICV_mutable_fields *ip_mutable_fields;
  unsigned char *digest;
  struct iphdr *ip = (struct iphdr *)(buffer);
  ipsec_ah *ah = (ipsec_ah *)(buffer + sizeof(struct iphdr));

  /* alloc a temp memory space to stock the ip mutable fields */
  ip_mutable_fields = (ICV_mutable_fields *)MALLOC(sizeof(ICV_mutable_fields));

  /* fill in next header filed --rfc2402.2.1 */
  ah->next_header = IPPROTO_VRRP;

  /* update IP header total length value */
  ip->tot_len = ip->ihl*4 + vrrp_ipsecah_len() + vrrp_hd_len(vrrp);
  ip->tot_len = htons(ip->tot_len);

  /* update ip checksum */
  ip->check = 0;
  ip->check = in_csum((u_short*)ip, ip->ihl*4, 0);

  /* backup the ip mutable fields */
  ip_mutable_fields->tos      = ip->tos;
  ip_mutable_fields->id       = ip->id;
  ip_mutable_fields->frag_off = ip->frag_off;
  ip_mutable_fields->check    = ip->check;

  /* zero the ip mutable fields */
  ip->tos      = 0;
  ip->id       = 0;
  ip->frag_off = 0;
  ip->check    = 0;

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
//  if (vrrp->ipsecah_counter->seq_number > 5) {
  if (vrrp->ipsecah_counter->seq_number > 0xFFFFFFFD) {
    vrrp->ipsecah_counter->cycle = 1;
  } else {
    vrrp->ipsecah_counter->seq_number++;
  }

  ah->seq_number = vrrp->ipsecah_counter->seq_number;

  /* Compute the ICV & trunc the digest to 96bits
     => No padding needed.
     -- rfc2402.3.3.3.1.1.1 & rfc2401.5
  */
  digest = (unsigned char *)MALLOC(16*sizeof(unsigned char *));
  hmac_md5(buffer, buflen
                 , vrrp->auth_data
                 , sizeof(vrrp->auth_data)
                 , digest);
  memcpy(ah->auth_data, digest, HMAC_MD5_TRUNC);

  /* Restore the ip mutable fields */
  ip->tos      = ip_mutable_fields->tos;
  ip->id       = ip_mutable_fields->id;
  ip->frag_off = ip_mutable_fields->frag_off;
  ip->check    = ip_mutable_fields->check;

  FREE(ip_mutable_fields);
  FREE(digest);
}

/* build VRRP header */
static int vrrp_build_vrrp(vrrp_rt *vrrp, int prio, char *buffer, int buflen)
{
  int  i;
  vrrp_pkt *hd  = (vrrp_pkt *)buffer;
  uint32_t *iparr  = (uint32_t *)((char *)hd+sizeof(*hd));
  
  hd->vers_type  = (VRRP_VERSION<<4) | VRRP_PKT_ADVERT;
  hd->vrid       = vrrp->vrid;
  hd->priority   = prio;
  hd->naddr      = vrrp->naddr;
  hd->auth_type  = vrrp->auth_type;
  hd->adver_int  = vrrp->adver_int/TIMER_HZ;

  /* copy the ip addresses */
  for( i = 0; i < vrrp->naddr; i++ ){
    iparr[i] = htonl(vrrp->vaddr[i].addr);
  }

  /* copy the passwd if the authentication is VRRP_AH_PASS */
  if (vrrp->auth_type == VRRP_AUTH_PASS) {
    char *pw = (char *)hd + sizeof(*hd) + vrrp->naddr*4;
    memcpy(pw, vrrp->auth_data, sizeof(vrrp->auth_data));
  }

  /* finaly compute vrrp checksum */
  hd->chksum  = in_csum( (u_short*)hd, vrrp_hd_len(vrrp), 0);

  return(0);
}

/* build VRRP packet */
static void vrrp_build_pkt(vrrp_rt *vrrp, int prio, char *buffer, int buflen)
{
  char *bufptr;

  bufptr = buffer;

  /* build the ethernet header */
  vrrp_build_arp(vrrp, buffer, buflen);

  /* build the ip header */
  buffer += vrrp_dlt_len(vrrp);
  buflen -= vrrp_dlt_len(vrrp);
  vrrp_build_ip(vrrp, buffer, buflen);

  /* build the vrrp header */
  buffer += vrrp_iphdr_len(vrrp);

  if (vrrp->auth_type == VRRP_AUTH_AH)
    buffer += vrrp_ipsecah_len();
  buflen -= vrrp_iphdr_len(vrrp);

  if (vrrp->auth_type == VRRP_AUTH_AH)
    buflen -= vrrp_ipsecah_len();
  vrrp_build_vrrp(vrrp, prio, buffer, buflen);

  /* build the IPSEC AH header */
  if (vrrp->auth_type == VRRP_AUTH_AH) {
    bufptr += vrrp_dlt_len(vrrp);
    buflen += vrrp_ipsecah_len() + vrrp_iphdr_len(vrrp);;
    vrrp_build_ipsecah(vrrp, bufptr, buflen);
  }
}

/* send VRRP packet */
static int vrrp_send_pkt(vrrp_rt *vrrp, char *buffer, int buflen)
{
  struct sockaddr from;
  int len;
  int fd = socket(PF_PACKET, SOCK_PACKET, 0x300); /* 0x300 is magic */

  if( fd < 0 ){
    syslog(LOG_INFO, "VRRP Error : socket creation");
    return -1;
  }

  /* build the address */
  memset(&from, 0 , sizeof(from));
  strcpy(from.sa_data, IF_NAME(vrrp->ifp));

//print_buffer(buflen, buffer);

  /* send the data */
  len = sendto(fd, buffer, buflen, 0, &from, sizeof(from));

  close(fd);
  return len;
}

/* send VRRP advertissement */
int vrrp_send_adv(vrrp_rt *vrrp, int prio)
{
  int buflen, ret;
  char *buffer;

  /* alloc the memory */
  buflen = vrrp_dlt_len(vrrp) + vrrp_iphdr_len(vrrp) + vrrp_hd_len(vrrp);
  if (vrrp->auth_type == VRRP_AUTH_AH)
    buflen += vrrp_ipsecah_len();

  buffer = MALLOC(buflen);

  /* build the packet  */
  vrrp_build_pkt(vrrp, prio, buffer, buflen);

  /* send it */
  ret = vrrp_send_pkt(vrrp, buffer, buflen);

  /* free the memory */
  FREE(buffer);
  return ret;
}

/* Received packet processing */
int vrrp_check_packet(vrrp_rt *vrrp, char *buf, int buflen)
{
  int ret;

  if (buflen > 0) {
    ret = vrrp_in_chk(vrrp, buf);

    if (ret == VRRP_PACKET_DROP) {
      syslog(LOG_INFO, "Sync instance needed on %s !!!"
                     , IF_NAME(vrrp->ifp));
    }

    if (ret == VRRP_PACKET_KO)
      syslog(LOG_INFO, "bogus VRRP packet received on %s !!!"
                     , IF_NAME(vrrp->ifp));
    return ret;
  }

  return VRRP_PACKET_NULL;
}

/* send a gratuitous ARP packet */
static int send_gratuitous_arp(vrrp_rt *vrrp, int addr)
{
  struct m_arphdr {
    unsigned short int ar_hrd;          /* Format of hardware address.  */
    unsigned short int ar_pro;          /* Format of protocol address.  */
    unsigned char ar_hln;               /* Length of hardware address.  */
    unsigned char ar_pln;               /* Length of protocol address.  */
    unsigned short int ar_op;           /* ARP opcode (command).  */
    /* Ethernet looks like this : This bit is variable sized however...  */
    unsigned char __ar_sha[ETH_ALEN];   /* Sender hardware address.  */
    unsigned char __ar_sip[4];          /* Sender IP address.  */
    unsigned char __ar_tha[ETH_ALEN];   /* Target hardware address.  */
    unsigned char __ar_tip[4];          /* Target IP address.  */
  };

  char buf[sizeof(struct m_arphdr) + ETHER_HDR_LEN];
  char buflen = sizeof(struct m_arphdr) + ETHER_HDR_LEN;
  struct ether_header *eth = (struct ether_header *)buf;
  struct m_arphdr *arph = (struct m_arphdr *)(buf + vrrp_dlt_len(vrrp));
  char  *hwaddr = IF_HWADDR(vrrp->ifp);
  int  hwlen = ETH_ALEN;

  /* hardcoded for ethernet */
  memset(eth->ether_dhost, 0xFF, ETH_ALEN);
  memcpy(eth->ether_shost, hwaddr, hwlen);
  eth->ether_type = htons(ETHERTYPE_ARP);

  /* build the arp payload */
  memset(arph, 0, sizeof(*arph));
  arph->ar_hrd = htons(ARPHRD_ETHER);
  arph->ar_pro = htons(ETHERTYPE_IP);
  arph->ar_hln = 6;
  arph->ar_pln = 4;
  arph->ar_op  = htons(ARPOP_REQUEST);
  memcpy(arph->__ar_sha, hwaddr, hwlen);
  memcpy(arph->__ar_sip, &addr, sizeof(addr));
  memcpy(arph->__ar_tip, &addr, sizeof(addr));

  return vrrp_send_pkt(vrrp, buf, buflen);
}

/* Gratuitous ARP on each VIP */
void vrrp_send_gratuitous_arp(vrrp_rt *vrrp)
{
  int  i, j;

  /* send gratuitous arp for each virtual ip */
  syslog(LOG_INFO, "VRRP_Instance(%s) Sending gratuitous ARP on %s"
                 , vrrp->iname
                 , IF_NAME(vrrp->ifp));

  for (j = 0; j < 5; j++) {
    for (i = 0; i < vrrp->naddr; i++)
      send_gratuitous_arp(vrrp, vrrp->vaddr[i].addr);
    for (i = 0; i < vrrp->neaddr; i++)
      send_gratuitous_arp(vrrp, vrrp->evaddr[i].addr);
  }
}

/* becoming master */
void vrrp_state_become_master(vrrp_rt *vrrp)
{
  /* add the ip addresses */
  if (vrrp->naddr)
    vrrp_handle_ipaddress(vrrp, VRRP_IPADDRESS_ADD, VRRP_VIP_TYPE);
  if (vrrp->neaddr)
    vrrp_handle_ipaddress(vrrp, VRRP_IPADDRESS_ADD, VRRP_EVIP_TYPE);
  vrrp->vipset = 1;

  /* remotes arp tables update */
  vrrp_send_gratuitous_arp(vrrp);

  /* Check if notify is needed */
  notify_instance_exec(vrrp, VRRP_STATE_MAST);

#ifdef _HAVE_IPVS_SYNCD_
  /* Check if sync daemon handling is needed */
  if (vrrp->lvs_syncd_if)
    ipvs_syncd_master(vrrp->lvs_syncd_if);
#endif
}

void vrrp_state_goto_master(vrrp_rt *vrrp)
{
  /*
   * Send an advertisement. To force a new master
   * election.
   */
  vrrp_send_adv(vrrp, vrrp->priority);

  if (vrrp->wantstate == VRRP_STATE_MAST) {
    vrrp->state = VRRP_STATE_MAST;
    syslog(LOG_INFO, "VRRP_Instance(%s) Transition to MASTER STATE"
                   , vrrp->iname);
  } else {
    vrrp->state = VRRP_STATE_DUMMY_MAST;
    syslog(LOG_INFO, "VRRP_Instance(%s) Transition to DUMMY_MASTER STATE"
                   , vrrp->iname);
  }
}

/* leaving master state */
static void vrrp_restore_interface(vrrp_rt *vrrp, int advF)
{
  /* remove the ip addresses */
  if (VRRP_VIP_ISSET(vrrp)) {
    if (vrrp->naddr)
      vrrp_handle_ipaddress(vrrp, VRRP_IPADDRESS_DEL, VRRP_VIP_TYPE);
    if (vrrp->neaddr)
      vrrp_handle_ipaddress(vrrp, VRRP_IPADDRESS_DEL, VRRP_EVIP_TYPE);
    vrrp->vipset = 0;
  }

  /* if we stop vrrp, warn the other routers to speed up the recovery */
  if (advF)
    vrrp_send_adv(vrrp, VRRP_PRIO_STOP);
}

void vrrp_state_leave_master(vrrp_rt *vrrp)
{
  if (VRRP_VIP_ISSET(vrrp)) {
#ifdef _HAVE_IPVS_SYNCD_
    /* Check if sync daemon handling is needed */
    if (vrrp->lvs_syncd_if)
      ipvs_syncd_backup(vrrp->lvs_syncd_if);
#endif
  }

  /* set the new vrrp state */
  switch (vrrp->wantstate) {
    case VRRP_STATE_BACK:
      syslog(LOG_INFO, "VRRP_Instance(%s) Entering BACKUP STATE"
                     , vrrp->iname);
      vrrp_restore_interface(vrrp, 0);
      vrrp->state = vrrp->wantstate;
      notify_instance_exec(vrrp, VRRP_STATE_BACK);
      break;
    case VRRP_STATE_GOTO_FAULT:
      syslog(LOG_INFO, "VRRP_Instance(%s) Entering FAULT STATE"
                     , vrrp->iname);
      vrrp_restore_interface(vrrp, 0);
      vrrp->state = VRRP_STATE_FAULT;
      notify_instance_exec(vrrp, VRRP_STATE_FAULT);
      break;
  }
}

/* BACKUP state processing */
void vrrp_state_backup(vrrp_rt *vrrp, char *buf, int buflen)
{
  struct iphdr *iph = (struct iphdr *)buf;
  vrrp_pkt     *hd  = NULL;
  int ret           = 0;

  /* Fill the VRRP header */
  switch (iph->protocol) {
    case IPPROTO_IPSEC_AH:
      hd  = (vrrp_pkt *)((char *)iph + (iph->ihl<<2) + vrrp_ipsecah_len());
      break;
    case IPPROTO_VRRP:
      hd  = (vrrp_pkt *)((char *)iph + (iph->ihl<<2));
      break;
  }

  /* Process the incoming packet */
  ret = vrrp_check_packet(vrrp, buf, buflen);

  if (ret == VRRP_PACKET_KO   || 
      ret == VRRP_PACKET_NULL) {
    syslog(LOG_INFO, "VRRP_Instance(%s) ignoring received advertisment..."
                   , vrrp->iname);
    vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
  } else if (hd->priority == 0) {
    vrrp->ms_down_timer = VRRP_TIMER_SKEW(vrrp);
  } else if (!vrrp->preempt || hd->priority >= vrrp->priority) {
    vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
  } else if (hd->priority < vrrp->priority) {
    vrrp->wantstate = VRRP_STATE_GOTO_MASTER;
  }
}

/* MASTER state processing */
void vrrp_state_master_tx(vrrp_rt *vrrp, const int prio)
{
  if (!VRRP_VIP_ISSET(vrrp)) {
    syslog(LOG_INFO, "VRRP_Instance(%s) Entering MASTER STATE"
                   , vrrp->iname);
    vrrp_state_become_master(vrrp);
  }

  vrrp_send_adv(vrrp, (prio==VRRP_PRIO_OWNER)?VRRP_PRIO_OWNER:vrrp->priority);
}

int vrrp_state_master_rx(vrrp_rt *vrrp, char *buf, int buflen)
{
  int ret            = 0;
  struct iphdr *iph  = (struct iphdr *)buf;
  vrrp_pkt     *hd   = NULL; 

  /* return on link failure */
  if (vrrp->wantstate == VRRP_STATE_GOTO_FAULT) {
    vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
    vrrp->state = VRRP_STATE_FAULT;
    return 1;
  }

  /* Fill the VRRP header */
  switch (iph->protocol) {
    case IPPROTO_IPSEC_AH:
      hd  = (vrrp_pkt *)((char *)iph + (iph->ihl<<2) + vrrp_ipsecah_len());
      break;
    case IPPROTO_VRRP:
      hd  = (vrrp_pkt *)((char *)iph + (iph->ihl<<2));
      break;
  }

  /* Process the incoming packet */
  ret = vrrp_check_packet(vrrp, buf, buflen);

  if (ret == VRRP_PACKET_KO   ||
      ret == VRRP_PACKET_NULL ||
      ret == VRRP_PACKET_DROP) {
    syslog(LOG_INFO, "VRRP_Instance(%s) Dropping received VRRP packet..."
                   , vrrp->iname);
    vrrp_send_adv(vrrp, vrrp->priority);
    return 0;
  } else if (hd->priority < vrrp->priority) {
    /* We receive a lower prio adv we just refresh remote ARP cache */
    syslog(LOG_INFO, "VRRP_Instance(%s) Received lower prio advert"
                     ", forcing new election"
                   , vrrp->iname);
    vrrp_send_adv(vrrp, vrrp->priority);
    vrrp_send_gratuitous_arp(vrrp);
    return 0;
  } else if (hd->priority == 0) {
    vrrp_send_adv(vrrp, vrrp->priority);
    return 0;
  } else if (hd->priority > vrrp->priority   ||
             (hd->priority == vrrp->priority &&
             ntohl(iph->saddr) > VRRP_PKT_SADDR(vrrp))) {
    syslog(LOG_INFO, "VRRP_Instance(%s) Received higher prio advert"
                   , vrrp->iname);
    vrrp->ms_down_timer = 3 * vrrp->adver_int + VRRP_TIMER_SKEW(vrrp);
    vrrp->state = VRRP_STATE_BACK;
    return 1;
  }

  return 0;
}

int vrrp_state_fault_rx(vrrp_rt *vrrp, char *buf, int buflen)
{
  int ret            = 0;
  struct iphdr *iph  = (struct iphdr *)buf;
  vrrp_pkt     *hd   = NULL; 

  /* Fill the VRRP header */
  switch (iph->protocol) {
    case IPPROTO_IPSEC_AH:
      hd  = (vrrp_pkt *)((char *)iph + (iph->ihl<<2) + vrrp_ipsecah_len());
      break;
    case IPPROTO_VRRP:
      hd  = (vrrp_pkt *)((char *)iph + (iph->ihl<<2));
      break;
  }

  /* Process the incoming packet */
  ret = vrrp_check_packet(vrrp, buf, buflen);

  if (ret == VRRP_PACKET_KO   ||
      ret == VRRP_PACKET_NULL ||
      ret == VRRP_PACKET_DROP) {
    syslog(LOG_INFO, "VRRP_Instance(%s) Dropping received VRRP packet..."
                   , vrrp->iname);
    vrrp_send_adv(vrrp, vrrp->priority);
    return 0;
  } else if (vrrp->priority > hd->priority ||
             hd->priority == VRRP_PRIO_OWNER)
    return 1;

  return 0;
}

/* check for minimum configuration requirements */
static int chk_min_cfg(vrrp_rt *vrrp)
{
  if (vrrp->naddr == 0) {
    syslog(LOG_INFO, "provide at least one ip for the virtual server");
    return 0;
  }
  if (vrrp->vrid == 0) {
    syslog(LOG_INFO, "the virtual id must be set!");
    return 0;
  }
  if (!vrrp->ifp) {
    syslog(LOG_INFO, "Unknown interface for instance %s !"
                   , vrrp->iname);
    return 0;
  }

  return 1;
}

/* open the socket and join the multicast group. */
int open_vrrp_socket(const int proto, const int index)
{
  struct ip_mreqn req_add;
  interface *ifp;
  int fd;
  int ret;
  int retry_num = 0;

  /* Retreive interface */
  ifp = if_get_by_ifindex(index);

  if (!IF_ISUP(ifp)) {
    syslog(LOG_INFO, "Kernel is reporting: Interface %s is DOWN"
                   , IF_NAME(ifp));
    return -1;
  }

  /* open the socket */
  fd = socket(AF_INET, SOCK_RAW, proto);

  if (fd < 0) {
    int err = errno;
    syslog(LOG_INFO, "cant open raw socket. errno=%d. (try to run it as root)"
                   , err);
    return -1;
  }

  /* -> inbound processing option
   * Specify the bound_dev_if.
   * why IP_ADD_MEMBERSHIP & IP_MULTICAST_IF doesnt set
   * sk->bound_dev_if themself ??? !!!
   * Needed for filter multicasted advert per interface.
   * 
   * -- If you read this !!! and know the answer to the question
   *    please feel free to answer me ! :)
   */
  ret = setsockopt(fd, SOL_SOCKET
                     , SO_BINDTODEVICE
                     , IF_NAME(ifp)
                     , strlen(IF_NAME(ifp))+1);
  if (ret < 0) {
    int  err = errno;
    syslog(LOG_INFO, "cant bind to device %s. errno=%d. (try to run it as root)"
                   , IF_NAME(ifp)
                   , err);
    close(fd);
    return -1;
  }

  /* -> outbound processing option
   * join the multicast group.
   * binding the socket to the interface for outbound multicast
   * traffic.
   */
  memset(&req_add, 0, sizeof (req_add));
  req_add.imr_multiaddr.s_addr = htonl(INADDR_VRRP_GROUP);
  req_add.imr_address.s_addr   = IF_ADDR(ifp);
  req_add.imr_ifindex          = IF_INDEX(ifp);

  /* -> Need to handle multicast convergance after takeover.
   * We retry until multicast is available on the interface.
   * After VRRP_MCAST_RETRY we assume interface doesn't support
   * multicast then exist with error.
   * -> This can sound a little nasty since it degrade a little
   * the global scheduling timers.
   */
moretry:
  ret = setsockopt(fd, IPPROTO_IP
                     , IP_ADD_MEMBERSHIP
                     , (char *)&req_add
                     , sizeof(struct ip_mreqn));
  if (ret < 0) {
    syslog(LOG_INFO, "cant do IP_ADD_MEMBERSHIP errno=%s (%d)"
                   , strerror(errno)
                   , errno);
    if (errno == 19) {
      retry_num++;
      if (retry_num > VRRP_MCAST_RETRY) {
        syslog(LOG_INFO, "cant do IP_ADD_MEMBERSHIP after %d retry errno=%s"
                       , VRRP_MCAST_RETRY
                       , strerror(errno));
        return -1;
      }
      sleep(1); /* FIXME: Beurk... Very nasty... !!! */
      goto moretry;
    }
    return -1;
  }

  return fd;
}

void close_vrrp_socket(vrrp_rt *vrrp)
{
  struct ip_mreqn req_add;
  int ret = 0;

  /* Leaving the VRRP multicast group */
  memset(&req_add, 0, sizeof (req_add));
  req_add.imr_multiaddr.s_addr = htonl(INADDR_VRRP_GROUP);
  req_add.imr_address.s_addr   = IF_ADDR(vrrp->ifp);
  req_add.imr_ifindex          = IF_INDEX(vrrp->ifp);
  ret = setsockopt(vrrp->fd, IPPROTO_IP
                           , IP_DROP_MEMBERSHIP
                           , (char *)&req_add
                           , sizeof(struct ip_mreqn));
  if (ret < 0) {
    syslog(LOG_INFO, "cant do IP_DROP_MEMBERSHIP errno=%s (%d)"
                   , strerror(errno)
                   , errno);
    return;
  }

  /* Finally close the desc */
  close(vrrp->fd);
}

void new_vrrp_socket(vrrp_rt *vrrp)
{
  int old_fd = vrrp->fd;
  list p = conf_data->vrrp;
  vrrp_rt *vrrp_ptr;
  element e;

  /* close the desc & open a new one */
  close_vrrp_socket(vrrp);
  if (vrrp->auth_type == VRRP_AUTH_AH)
    vrrp->fd = open_vrrp_socket(IPPROTO_IPSEC_AH, IF_INDEX(vrrp->ifp));
  else
    vrrp->fd = open_vrrp_socket(IPPROTO_VRRP, IF_INDEX(vrrp->ifp));

  /* Sync the other desc */
  for (e = LIST_HEAD(p); e; ELEMENT_NEXT(e)) {
    vrrp_ptr = ELEMENT_DATA(e);
    if (vrrp_ptr->fd == old_fd)
      vrrp_ptr->fd = vrrp->fd;
  }
}

/* handle terminate state */
void shutdown_vrrp_instances(void)
{
  list l = conf_data->vrrp;
  element e;
  vrrp_rt *vrrp;

  for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
    vrrp = ELEMENT_DATA(e);

    /* remove VIPs */
    if (vrrp->state == VRRP_STATE_MAST ||
        vrrp->state == VRRP_STATE_DUMMY_MAST)
      vrrp_restore_interface(vrrp, 1);

#ifdef _HAVE_IPVS_SYNCD_
    /* Stop stalled syncd */
    if (vrrp->lvs_syncd_if)
      ipvs_syncd_cmd(IPVS_STOPDAEMON, NULL, 0);
#endif
  }
}

/* complete vrrp structure */
static int vrrp_complete_instance(vrrp_rt *vrrp)
{
  /* complete the VMAC address */
  vrrp->hwaddr[0] = 0x00;
  vrrp->hwaddr[1] = 0x00;
  vrrp->hwaddr[2] = 0x5E;
  vrrp->hwaddr[3] = 0x00;
  vrrp->hwaddr[4] = 0x01;
  vrrp->hwaddr[5] = vrrp->vrid;

  vrrp->state                           = VRRP_STATE_INIT;
  if (!vrrp->adver_int) vrrp->adver_int = VRRP_ADVER_DFL * TIMER_HZ;
  if (!vrrp->priority) vrrp->priority   = VRRP_PRIO_DFL;
  if (!vrrp->preempt) vrrp->preempt     = VRRP_PREEMPT_DFL;

  return(chk_min_cfg(vrrp));
}

int vrrp_complete_init(void)
{
  list l = conf_data->vrrp;
  element e;
  vrrp_rt *vrrp;

  for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
    vrrp = ELEMENT_DATA(e);
    if (!vrrp_complete_instance(vrrp))
      return 0;
  }
  return 1;
}
