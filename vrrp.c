/*
 * Soft:        Vrrpd is an implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Version:     $Id: vrrp.c,v 0.4.8 2001/11/20 15:26:11 acassen Exp $
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
#include "vrrp_scheduler.h"
#include "vrrp.h"

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

/* retrieve MAC address from interface name */
static int hwaddr_get(char *ifname, char *addr, int addrlen)
{
  struct ifreq ifr;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  int ret;

  if (fd < 0) return (-1);
  strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
  ret = ioctl(fd, SIOCGIFHWADDR, (char *)&ifr);
  memcpy(addr, ifr.ifr_hwaddr.sa_data, addrlen);
  close(fd);
  return ret;
}

/* resolve ipaddress from interface name */
static uint32_t ifname_to_ip(const char *ifname)
{
  struct ifreq ifr;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  uint32_t addr = 0;

  if (fd < 0) return (-1);
  strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
  if (ioctl(fd, SIOCGIFADDR, (char *)&ifr) == 0) {
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    addr = ntohl(sin->sin_addr.s_addr);
  }

  close(fd);
  return addr;
}

/* resolve interface index from interface name */
int ifname_to_idx(const char *ifname)
{
  struct ifreq ifr;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  int ifindex = -1;

  if (fd < 0) return (-1);
  strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
  if (ioctl(fd, SIOCGIFINDEX, (char *)&ifr) == 0)
    ifindex = ifr.ifr_ifindex;

  close(fd);
  return ifindex;
}

/* resolve ifname from index */
static void index_to_ifname(const int ifindex, char *ifname)
{
  struct ifreq ifr;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);

  if (fd < 0) return;

  /* get interface name */
  ifr.ifr_ifindex = ifindex;
  if (ioctl(fd, SIOCGIFNAME, (char *)&ifr) == 0)
    strncpy(ifname, ifr.ifr_name, sizeof(ifr.ifr_name));
  close(fd);
}

/* resolve ipaddress from interface index */
static uint32_t index_to_ip(const int ifindex)
{
  char ifname[IFNAMSIZ];

  memset(&ifname, 0, IFNAMSIZ);
  index_to_ifname(ifindex, ifname);

  return(ifname_to_ip(ifname));
}

/* add/remove VIP */
static int vrrp_handle_ipaddress(vrrp_rt *vsrv, int cmd)
{
  int i, err = 0;
  int retry = 0;
  int ifidx = ifname_to_idx(vsrv->vif->ifname);
  struct in_addr in;

  for(i = 0; i < vsrv->naddr; i++ ) {
    vip_addr *vadd = &vsrv->vaddr[i];
    if(!cmd && !vadd->deletable) continue;
retry:
    if (netlink_address_ipv4(ifidx , vadd->addr, cmd) < 0) {
      err = 1;
      vadd->deletable = 0;
      in.s_addr = htonl(vadd->addr);
      syslog(LOG_INFO, "cant %s the address %s to %s\n"
                     , cmd ? "set" : "remove"
                     , inet_ntoa(in)
                     , vsrv->vif->ifname);
      if (cmd == VRRP_IPADDRESS_ADD) {
        syslog(LOG_INFO, "try to delete eventual stalled ip");
        netlink_address_ipv4(ifidx, vadd->addr, VRRP_IPADDRESS_DEL);
        if (!retry) {
          retry++;
          goto retry;
        }
      }
    } else {
      vadd->deletable = 1;
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
static int vrrp_iphdr_len(vrrp_rt *vsrv)
{
  return sizeof(struct iphdr);
}

/* IPSEC AH header length */
int vrrp_ipsecah_len()
{
  return sizeof(ipsec_ah);
}

/* VRRP header length */
static int vrrp_hd_len(vrrp_rt *vsrv)
{
  return sizeof(vrrp_pkt)
         + vsrv->naddr*sizeof(uint32_t)
         + VRRP_AUTH_LEN;
}

/*
 * IPSEC AH incoming packet check.
 * return 0 for a valid pkt, != 0 otherwise.
 */
static int vrrp_in_chk_ipsecah(vrrp_rt *vsrv, char *buffer)
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
  vsrv->ipsecah_counter->seq_number++;
  if (ah->seq_number >= vsrv->ipsecah_counter->seq_number) {
#ifdef DEBUG
//  syslog(LOG_DEBUG, "IPSEC AH : SEQUENCE NUMBER : %d\n", ah->seq_number);
#endif
    vsrv->ipsecah_counter->seq_number = ah->seq_number;
  } else {
    syslog(LOG_INFO, "IPSEC AH : sequence number %d already proceeded."
                     " Packet droped", ah->seq_number);
    return 1;
  }
 
  /*
   * then compute a ICV to compare with the one present in AH pkt.
   * alloc a temp memory space to stock the ip mutable fields
   */
  digest=(unsigned char *)malloc(16*sizeof(unsigned char *));
  memset(digest, 0, 16*sizeof(unsigned char *));

  /* zero the ip mutable fields */
  ip->tos = 0;
  ip->id = 0;
  ip->frag_off = 0;
  ip->check = 0;
  memcpy(backup_auth_data, ah->auth_data, sizeof(ah->auth_data));
  memset(ah->auth_data, 0, sizeof(ah->auth_data));

  /* Compute the ICV */
  hmac_md5(buffer, vrrp_iphdr_len(vsrv)+vrrp_ipsecah_len()+vrrp_hd_len(vsrv),
           vsrv->vif->auth_data, sizeof(vsrv->vif->auth_data), digest);

  if (memcmp(backup_auth_data, digest, HMAC_MD5_TRUNC) != 0) {
    syslog(LOG_INFO, "IPSEC AH : invalid IPSEC HMAC-MD5 value."
                     " Due to fields mutation or bad password !");
    return 1;
  }

  free(digest);
  return 0;
}

/* check if ipaddr is present in VIP buffer */
static int vrrp_in_chk_vips(vrrp_rt *vsrv, uint32_t ipaddr, unsigned char *buffer)
{
  int i;
  uint32_t ipbuf;

  for (i=0; i < vsrv->naddr; i++) {
    bcopy(buffer+i*sizeof(uint32_t), &ipbuf, sizeof(uint32_t));
    if (ipaddr == ntohl(ipbuf)) return 1;
  }

  return 0;
}

/*
 * VRRP incoming packet check.
 * return 0 if the pkt is valid, != 0 otherwise.
 */
static int vrrp_in_chk(vrrp_rt *vsrv, char *buffer)
{
  struct iphdr *ip = (struct iphdr*)(buffer);
  int ihl = ip->ihl << 2;
  vrrp_if *vif = vsrv->vif;
  ipsec_ah *ah;
  vrrp_pkt *hd;
  unsigned char *vips;
  int i;

  if (vif->auth_type == VRRP_AUTH_AH) {
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
  if (in_csum( (u_short*)hd, vrrp_hd_len(vsrv), 0)) {
    syslog(LOG_INFO, "Invalid vrrp checksum");
    return VRRP_PACKET_KO;
  }

  /*
   * MUST perform authentication specified by Auth Type 
   * check the authentication type
   */
  if (vif->auth_type != hd->auth_type) {    
    syslog(LOG_INFO, "receive a %d auth, expecting %d!", vif->auth_type
                   , hd->auth_type);
    return VRRP_PACKET_KO;
  }

  /* check the authentication if it is a passwd */
  if (hd->auth_type == VRRP_AUTH_PASS) {
    char *pw = (char *)ip + ntohs(ip->tot_len)
                - sizeof(vif->auth_data);
    if (memcmp( pw, vif->auth_data, sizeof(vif->auth_data))){
      syslog(LOG_INFO, "receive an invalid passwd!");
      return VRRP_PACKET_KO;
    }
  }

  /* MUST verify that the VRID is valid on the receiving interface */
  if (vsrv->vrid != hd->vrid) {
    syslog(LOG_INFO, "received VRID mismatch. Received %d, Expected %d", 
                     hd->vrid, vsrv->vrid);
    return VRRP_PACKET_DROP;
  }

  /*
   * MAY verify that the IP address(es) associated with the
   * VRID are valid
   */
  if (vsrv->naddr != hd->naddr) {
    syslog(LOG_INFO, "receive an invalid ip number count associated with VRID!");
    return VRRP_PACKET_KO;
  }

  for (i=0; i < vsrv->naddr; i++)
    if (!vrrp_in_chk_vips(vsrv,vsrv->vaddr[i].addr,vips)) {
      syslog(LOG_INFO, "ip address associated with VRID"
                       " not present in received packet : %d"
                     , vsrv->vaddr[i].addr);
      syslog(LOG_INFO, "one or more VIP associated with"
                       " VRID mismatch actual MASTER advert");
      return VRRP_PACKET_KO;
    }

  /*
   * MUST verify that the Adver Interval in the packet is the same as
   * the locally configured for this virtual router
   */
  if (vsrv->adver_int/VRRP_TIMER_HZ != hd->adver_int) {
    syslog(LOG_INFO, "advertissement interval mismatch mine=%d rcved=%d"
                   , vsrv->adver_int, hd->adver_int);
    /* to prevent concurent VRID running => multiple master in 1 VRID */
    return VRRP_PACKET_DROP;
  }

  /* check the authenicaion if it is ipsec ah */
  if(hd->auth_type == VRRP_AUTH_AH)
    return(vrrp_in_chk_ipsecah(vsrv, buffer));

  return VRRP_PACKET_OK;
}

/* build ARP header */
static void vrrp_build_dlt(vrrp_rt *vsrv, char *buffer, int buflen)
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
  memcpy(eth->ether_shost, vsrv->hwaddr, sizeof(vsrv->hwaddr));

  /* type */
  eth->ether_type = htons(ETHERTYPE_IP);
}

/* build IP header */
static void vrrp_build_ip(vrrp_rt *vsrv, char *buffer, int buflen)
{
  struct iphdr *ip = (struct iphdr *)(buffer);

  ip->ihl      = 5;
  ip->version  = 4;
  ip->tos      = 0;
  ip->tot_len  = ip->ihl*4 + vrrp_hd_len(vsrv);
  ip->tot_len  = htons(ip->tot_len);
  ip->id       = ++vsrv->vif->ip_id;
  ip->frag_off = 0;
  ip->ttl      = VRRP_IP_TTL;

  /* fill protocol type --rfc2402.2 */
  ip->protocol = (vsrv->vif->auth_type == VRRP_AUTH_AH)?IPPROTO_IPSEC_AH:IPPROTO_VRRP;
  ip->saddr    = htonl(vsrv->vif->ipaddr);
  ip->daddr    = htonl(INADDR_VRRP_GROUP);

  /* checksum must be done last */
  ip->check = in_csum((u_short*)ip, ip->ihl*4, 0);
}

/* build IPSEC AH header */
static void vrrp_build_ipsecah(vrrp_rt *vsrv, char *buffer, int buflen)
{
  ICV_mutable_fields *ip_mutable_fields;
  unsigned char *digest;
  struct iphdr *ip = (struct iphdr *)(buffer);
  ipsec_ah *ah = (ipsec_ah *)(buffer + sizeof(struct iphdr));

  /* alloc a temp memory space to stock the ip mutable fields */
  ip_mutable_fields=calloc(sizeof(ICV_mutable_fields), 1);
  memset(ip_mutable_fields, 0, sizeof(ICV_mutable_fields));

  /* fill in next header filed --rfc2402.2.1 */
  ah->next_header = IPPROTO_VRRP;

  /* update IP header total length value */
  ip->tot_len = ip->ihl*4 + vrrp_ipsecah_len() + vrrp_hd_len(vsrv);
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
//  if (vsrv->ipsecah_counter->seq_number > 5) {
  if (vsrv->ipsecah_counter->seq_number > 0xFFFFFFFD) {
    vsrv->ipsecah_counter->cycle = 1;
  } else {
    vsrv->ipsecah_counter->seq_number++;
  }

  ah->seq_number = vsrv->ipsecah_counter->seq_number;

  /* Compute the ICV & trunc the digest to 96bits
     => No padding needed.
     -- rfc2402.3.3.3.1.1.1 & rfc2401.5
  */
  digest=(unsigned char *)malloc(16*sizeof(unsigned char *));
  memset(digest, 0, 16*sizeof(unsigned char *));
  hmac_md5(buffer, buflen,vsrv->vif->auth_data, sizeof(vsrv->vif->auth_data), digest);
  memcpy(ah->auth_data, digest, HMAC_MD5_TRUNC);

  /* Restore the ip mutable fields */
  ip->tos      = ip_mutable_fields->tos;
  ip->id       = ip_mutable_fields->id;
  ip->frag_off = ip_mutable_fields->frag_off;
  ip->check    = ip_mutable_fields->check;

  free(ip_mutable_fields);
  free(digest);
}

/* build VRRP header */
static int vrrp_build_vrrp(vrrp_rt *vsrv, int prio, char *buffer, int buflen)
{
  int  i;
  vrrp_if *vif = vsrv->vif;
  vrrp_pkt *hd  = (vrrp_pkt *)buffer;
  uint32_t *iparr  = (uint32_t *)((char *)hd+sizeof(*hd));
  
  hd->vers_type  = (VRRP_VERSION<<4) | VRRP_PKT_ADVERT;
  hd->vrid  = vsrv->vrid;
  hd->priority  = prio;
  hd->naddr  = vsrv->naddr;
  hd->auth_type  = vsrv->vif->auth_type;
  hd->adver_int  = vsrv->adver_int/VRRP_TIMER_HZ;

  /* copy the ip addresses */
  for( i = 0; i < vsrv->naddr; i++ ){
    iparr[i] = htonl(vsrv->vaddr[i].addr);
  }
  hd->chksum  = in_csum( (u_short*)hd, vrrp_hd_len(vsrv), 0);

  /* copy the passwd if the authentication is VRRP_AH_PASS */
  if( vif->auth_type == VRRP_AUTH_PASS ){
    char *pw = (char *)hd + sizeof(*hd) + vsrv->naddr*4;
    memcpy(pw, vif->auth_data, sizeof(vif->auth_data));
  }

  return(0);
}

/* build VRRP packet */
static void vrrp_build_pkt(vrrp_rt *vsrv, int prio, char *buffer, int buflen)
{
  char *bufptr;

  bufptr = buffer;

  /* build the ethernet header */
  vrrp_build_dlt(vsrv, buffer, buflen);

  /* build the ip header */
  buffer += vrrp_dlt_len(vsrv);
  buflen -= vrrp_dlt_len(vsrv);
  vrrp_build_ip(vsrv, buffer, buflen);

  /* build the vrrp header */
  buffer += vrrp_iphdr_len(vsrv);

  if (vsrv->vif->auth_type == VRRP_AUTH_AH)
    buffer += vrrp_ipsecah_len();
  buflen -= vrrp_iphdr_len(vsrv);

  if (vsrv->vif->auth_type == VRRP_AUTH_AH)
    buflen -= vrrp_ipsecah_len();
  vrrp_build_vrrp(vsrv, prio, buffer, buflen);

  /* build the IPSEC AH header */
  if (vsrv->vif->auth_type == VRRP_AUTH_AH) {
    bufptr += vrrp_dlt_len(vsrv);
    buflen += vrrp_ipsecah_len() + vrrp_iphdr_len(vsrv);;
    vrrp_build_ipsecah(vsrv, bufptr, buflen);
  }
}

/* send VRRP packet */
static int vrrp_send_pkt(vrrp_rt *vsrv, char *buffer, int buflen)
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
  strcpy(from.sa_data, vsrv->vif->ifname);

  /* send the data */
  len = sendto(fd, buffer, buflen, 0, &from, sizeof(from));

  close(fd);
  return len;
}

/* send VRRP advertissement */
static int vrrp_send_adv(vrrp_rt *vsrv, int prio)
{
  int buflen, ret;
  char *buffer;

  /* alloc the memory */
  buflen = vrrp_dlt_len(vsrv) + vrrp_iphdr_len(vsrv) + vrrp_hd_len(vsrv);
  if (vsrv->vif->auth_type == VRRP_AUTH_AH)
    buflen += vrrp_ipsecah_len();
  buffer = calloc(buflen, 1);
  memset(buffer,0,buflen);

  /* build the packet  */
  vrrp_build_pkt(vsrv, prio, buffer, buflen);

  /* send it */
  ret = vrrp_send_pkt(vsrv, buffer, buflen);

  /* free the memory */
  free(buffer);
  return ret;
}

/* Received packet processing */
int vrrp_check_packet(vrrp_rt *vsrv, char *buf, int buflen)
{
  int ret;

  if (buflen > 0) {
    ret = vrrp_in_chk(vsrv, buf);

    if (ret == VRRP_PACKET_DROP) {
      syslog(LOG_INFO, "Sync instance needed on %s !!!",
                       vsrv->vif->ifname);
    }

    if (ret == VRRP_PACKET_KO)
      syslog(LOG_INFO, "bogus VRRP packet received on %s !!!",
                       vsrv->vif->ifname);
//    else
//      syslog(LOG_INFO, "Success receiving VRRP packet on %s.",
//                       vsrv->vif->ifname);
    return ret;
  }

  return VRRP_PACKET_NULL;
}

/* send a gratuitous ARP packet */
static int send_gratuitous_arp(vrrp_rt *vsrv, int addr)
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
  struct m_arphdr *arph = (struct m_arphdr *)(buf + vrrp_dlt_len(vsrv));
  char  *hwaddr = vsrv->vif->hwaddr;
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
  addr = htonl(addr);
  memcpy(arph->__ar_sip, &addr, sizeof(addr));
  memcpy(arph->__ar_tip, &addr, sizeof(addr));
  return vrrp_send_pkt(vsrv, buf, buflen);
}

/* Gratuitous ARP on each VIP */
void vrrp_send_gratuitous_arp(vrrp_instance *vrrp_instance)
{
  int  i, j;
  vrrp_rt *vsrv = vrrp_instance->vsrv;

  /* send gratuitous arp for each virtual ip */
  for (j = 0; j < 5; j++)
    for (i = 0; i < vsrv->naddr; i++)
      send_gratuitous_arp(vsrv, vsrv->vaddr[i].addr);
}

/* becoming master */
void vrrp_state_goto_master(vrrp_instance *vrrp_instance)
{
  vrrp_rt *vsrv = vrrp_instance->vsrv;

  /* add the ip addresses */
  vrrp_handle_ipaddress(vsrv, VRRP_IPADDRESS_ADD);

  /* send an advertisement */
  vrrp_send_adv(vsrv, vsrv->priority);

  /* remotes arp tables update */
  vrrp_send_gratuitous_arp(vrrp_instance);

  syslog(LOG_INFO, "VRRP_Instance(%s) Entering MASTER STATE"
                 , vrrp_instance->iname);

  vsrv->state = VRRP_STATE_MAST;
}

/* leaving master state */
static void vrrp_restore_interface(vrrp_rt *vsrv, int advF)
{
  /* remove the ip addresses */
  vrrp_handle_ipaddress(vsrv, VRRP_IPADDRESS_DEL);

  /* if we stop vrrp, warn the other routers to speed up the recovery */
  if (advF)
    vrrp_send_adv(vsrv, VRRP_PRIO_STOP);
}

void vrrp_state_leave_master(vrrp_instance *instance)
{
  vrrp_rt *vsrv = instance->vsrv;

  /* Remove VIPs */
  vrrp_restore_interface(vsrv, 0);

  syslog(LOG_INFO, "VRRP_Instance(%s) Entering BACKUP STATE"
                 , instance->iname);

  /* register the vrrp backup handler */
  vsrv->state = VRRP_STATE_BACK;
}

/* BACKUP state processing */
void vrrp_state_backup(vrrp_instance *instance, char *buf, int buflen)
{
  int ret = 0;
  vrrp_rt *vsrv = instance->vsrv;
  struct iphdr *iph = (struct iphdr *)buf;
  vrrp_pkt *hd;

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
  ret = vrrp_check_packet(vsrv, buf, buflen);

  if (ret == VRRP_PACKET_KO   || 
      ret == VRRP_PACKET_NULL) {
    syslog(LOG_INFO, "VRRP_Instance(%s) ignoring received advertisment..."
                   , instance->iname);
    vsrv->ms_down_timer = 3 * vsrv->adver_int + VRRP_TIMER_SKEW(vsrv);
  } else if (hd->priority == 0) {
    vsrv->ms_down_timer = VRRP_TIMER_SKEW(vsrv);
  } else if( !vsrv->preempt || hd->priority >= vsrv->priority ) {
    vsrv->ms_down_timer = 3 * vsrv->adver_int + VRRP_TIMER_SKEW(vsrv);
  }
}

/* MASTER state processing */
void vrrp_state_master_tx(vrrp_instance *instance, const int prio)
{
  vrrp_rt *vsrv = instance->vsrv;

  if (prio == VRRP_PRIO_OWNER)
    vrrp_send_adv(vsrv, VRRP_PRIO_OWNER);
  else
    vrrp_send_adv(vsrv, vsrv->priority);
}

int vrrp_state_master_rx(vrrp_instance *instance, char *buf, int buflen)
{
  int ret = 0;
  vrrp_rt *vsrv = instance->vsrv;
  struct iphdr *iph = (struct iphdr *)buf;
  vrrp_pkt *hd;

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
  ret = vrrp_check_packet(vsrv, buf, buflen);

  if (ret == VRRP_PACKET_KO   ||
      ret == VRRP_PACKET_NULL ||
      ret == VRRP_PACKET_DROP) {
    syslog(LOG_INFO, "VRRP_Instance(%s) Dropping received VRRP packet..."
                   , instance->iname);
    vrrp_send_adv(vsrv, vsrv->priority);
    return 0;
  } else if (hd->priority == 0) {
    vrrp_send_adv(vsrv, vsrv->priority);
    return 0;
  } else if( hd->priority > vsrv->priority ||
            (hd->priority == vsrv->priority &&
            ntohl(iph->saddr) > vsrv->vif->ipaddr)) {
    vsrv->ms_down_timer = 3 * vsrv->adver_int + VRRP_TIMER_SKEW(vsrv);
    vsrv->state = VRRP_STATE_BACK;
    return 1;
  }

  return 0;
}

/* check for minimum configuration requirements */
static int chk_min_cfg(vrrp_rt *vsrv)
{
  if( vsrv->naddr == 0 ){
    syslog(LOG_INFO, "provide at least one ip for the virtual server");
    return 0;
  }
  if( vsrv->vrid == 0 ){
    syslog(LOG_INFO, "the virtual id must be set!");
    return 0;
  }
  if( vsrv->vif->ipaddr == 0 ){
    syslog(LOG_INFO, "the interface ipaddr must be set!");
    return 0;
  }

  return 1;
}

/* compute vrrp structure */
int complete_vrrp_init(vrrp_rt *vsrv)
{
  vrrp_if *vif = vsrv->vif;

  /* complete the VMAC address */
  vsrv->hwaddr[0] = 0x00;
  vsrv->hwaddr[1] = 0x00;
  vsrv->hwaddr[2] = 0x5E;
  vsrv->hwaddr[3] = 0x00;
  vsrv->hwaddr[4] = 0x01;
  vsrv->hwaddr[5] = vsrv->vrid;

  /* get the ip address */
  vif->ipaddr = ifname_to_ip(vif->ifname);
  if (!vif->ipaddr) {
    syslog(LOG_INFO, "VRRP Error : no interface found : %s !\n", vif->ifname);
    return 0;
  }
  /* get the hwaddr */
  if (hwaddr_get(vif->ifname, vif->hwaddr, sizeof(vif->hwaddr))) {
    syslog(LOG_INFO, "VRRP Error : Unreadable MAC"
                     "address for interface : %s !\n", vif->ifname);
    return 0;
  }

  vsrv->state = VRRP_STATE_INIT;
  if (!vsrv->adver_int) vsrv->adver_int = VRRP_ADVER_DFL * VRRP_TIMER_HZ;
  if (!vsrv->priority) vsrv->priority = VRRP_PRIO_DFL;
  if (!vsrv->preempt) vsrv->preempt = VRRP_PREEMPT_DFL;

  return(chk_min_cfg(vsrv));
}

/* open the socket and join the multicast group. */
int open_vrrp_socket(const int proto, const int index)
{
  struct ip_mreqn req_add;
  char ifname[IFNAMSIZ];
  int fd;
  int ret;

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
   *    please feal free to answer me ! :)
   */
  memset(ifname, 0, IFNAMSIZ);
  index_to_ifname(index, ifname);
  ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                   ifname, strlen(ifname)+1);
  if (ret < 0) {
    int  err = errno;
    syslog(LOG_INFO, "cant bind to device %s. errno=%d. (try to run it as root)",
                     ifname, err);
    close(fd); /* sd leak handle */
    return -1;
  }

  /* -> outbound processing option
   * join the multicast group.
   * binding the socket to the interface for outbound multicast
   * traffic.
   */
  memset(&req_add, 0, sizeof (req_add));
  req_add.imr_multiaddr.s_addr = htonl(INADDR_VRRP_GROUP);
  req_add.imr_address.s_addr = htonl(index_to_ip(index));
  req_add.imr_ifindex = index;
  ret = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   (char *)&req_add, sizeof(struct ip_mreqn));
  if (ret < 0) {
    int  err = errno;
    syslog(LOG_INFO, "cant do IP_ADD_MEMBERSHIP errno=%d", err);
    return -1;
  }

  return fd;
}

/* handle terminate state */
void vrrp_state_stop_instance(vrrp_rt *vsrv)
{
  /* restore MAC, routing table & remove VIPs */
  if (vsrv->state == VRRP_STATE_MAST)
    vrrp_restore_interface(vsrv, 1);
}
