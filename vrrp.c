/*
 * Soft:        Vrrpd is an implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Version:     $Id: vrrp.c,v 0.4.1 2001/09/14 00:37:56 acassen Exp $
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *              Based on the Jerome Etienne, <jetienne@arobas.net> code.
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
#include "scheduler.h"
#include "cfreader.h"
#include "utils.h"
#include "vrrp.h"

/* local prototypes */
static int vrrp_state_goto_master_thread(struct thread *thread);
static int vrrp_state_master_thread(struct thread *thread);
int vrrp_state_backup_thread(struct thread *thread);

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

/* resolve ipaddress from interface name */
static uint32_t ifname_to_ip(char *ifname)
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
static int ifname_to_idx(char *ifname)
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

/* retrieve MAC options */
static int rcvhwaddr_op(char *ifname, char *addr, int addrlen, int addF)
{
  struct ifreq ifr;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  int ret;

  if (fd < 0) return (-1);

  strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
  memcpy( ifr.ifr_hwaddr.sa_data, addr, addrlen );
  ifr.ifr_hwaddr.sa_family = AF_UNSPEC;

  ret = ioctl(fd, addF ? SIOCADDMULTI : SIOCDELMULTI, (char *)&ifr);
  if (ret) {
    syslog(LOG_INFO, "Can't %s on %s. errno=%d"
                   , addF ? "SIOCADDMULTI" : "SIOCDELMULTI"
                   , ifname, errno );
  }
  close(fd);
  return ret;
}

/* Set MAC address - need to shutdown the interface before */
static int hwaddr_set(char *ifname, char *addr, int addrlen)
{
  struct ifreq ifr;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  int ret;
  unsigned long flags;

  if (fd < 0) return (-1);
  strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

  /* get the flags */
  ret = ioctl(fd, SIOCGIFFLAGS, (char *)&ifr);
  if (ret) goto end;
  flags = ifr.ifr_flags;

  /* set the interface down */
  ifr.ifr_flags &= ~IFF_UP;
  ret = ioctl(fd, SIOCSIFFLAGS, (char *)&ifr);
  if(ret) goto end;

  /* change the hwaddr */
  memcpy(ifr.ifr_hwaddr.sa_data, addr, addrlen);
  ifr.ifr_hwaddr.sa_family = AF_UNIX;
  ret = ioctl(fd, SIOCSIFHWADDR, (char *)&ifr);
  if(ret) goto end;

  /* set the interface up */
  ifr.ifr_flags = flags;
  ret = ioctl(fd, SIOCSIFFLAGS, (char *)&ifr);
  if(ret) goto end;

end:;
  if (ret) syslog(LOG_INFO, "MAC set : error errno=%d", errno);

  close(fd);
  return ret;
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

/* add/remove VIP */
static int ipaddr_ops(vrrp_rt *vsrv, int addF)
{
  int i, err = 0;
  int ifidx = ifname_to_idx(vsrv->vif->ifname);
  struct in_addr in;

  for(i = 0; i < vsrv->naddr; i++ ) {
    vip_addr *vadd = &vsrv->vaddr[i];
    if(!addF && !vadd->deletable) continue;

    if (ipaddr_op(ifidx , vadd->addr, addF)) {
      err = 1;
      vadd->deletable = 0;
      in.s_addr = htonl(vadd->addr);
      syslog(LOG_INFO, "cant %s the address %s to %s\n"
                     , addF ? "set" : "remove"
                     , inet_ntoa(in)
                     , vsrv->vif->ifname);
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
static int vrrp_ipsecah_len(vrrp_rt *vsrv)
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
static int vrrp_in_chk_ipsecah( vrrp_rt *vsrv, char *buffer)
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
  syslog(LOG_DEBUG, "IPSEC AH : SEQUENCE NUMBER : %d\n", ah->seq_number);
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
  hmac_md5(buffer, vrrp_iphdr_len(vsrv)+vrrp_ipsecah_len(vsrv)+vrrp_hd_len(vsrv),
           vsrv->vif->auth_data, sizeof(vsrv->vif->auth_data), digest);

  if (memcmp(backup_auth_data,digest,HMAC_MD5_TRUNC) != 0) {
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
    bcopy(buffer+i*sizeof(uint32_t),&ipbuf,sizeof(uint32_t));
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
    hd = (vrrp_pkt *)(buffer + ihl + vrrp_ipsecah_len(vsrv));
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
  if (vsrv->vrid != hd->vrid)
    return VRRP_PACKET_KO;

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
      return VRRP_PACKET_DROP;
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
    return(vrrp_in_chk_ipsecah(vsrv,buffer));

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
  ip->tot_len  = ip->ihl*4 + vrrp_hd_len( vsrv );
  ip->tot_len  = htons(ip->tot_len);
  ip->id       = ++vsrv->vif->ip_id;
  ip->frag_off = 0;
  ip->ttl      = VRRP_IP_TTL;

  /* fill protocol type --rfc2402.2 */
  ip->protocol = (vsrv->vif->auth_type == VRRP_AUTH_AH)?IPPROTO_IPSEC_AH:IPPROTO_VRRP;
  ip->saddr    = htonl(vsrv->vif->ipaddr);
  ip->daddr    = htonl(INADDR_VRRP_GROUP);

  /* checksum must be done last */
  ip->check = in_csum( (u_short*)ip, ip->ihl*4, 0 );
}

/* build IPSEC AH header */
static void vrrp_build_ipsecah(vrrp_rt *vsrv, char *buffer, int buflen)
{
  ICV_mutable_fields *ip_mutable_fields;
  unsigned char *digest;
  struct iphdr *ip = (struct iphdr *)(buffer);
  ipsec_ah *ah = (ipsec_ah *)(buffer+sizeof(struct iphdr));

  /* alloc a temp memory space to stock the ip mutable fields */
  ip_mutable_fields=calloc(sizeof(ICV_mutable_fields),1);
  memset(ip_mutable_fields,0,sizeof(ICV_mutable_fields));

  /* fill in next header filed --rfc2402.2.1 */
  ah->next_header = IPPROTO_VRRP;

  /* update IP header total length value */
  ip->tot_len = ip->ihl*4 + vrrp_ipsecah_len( vsrv ) + vrrp_hd_len( vsrv );
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
    iparr[i] = htonl( vsrv->vaddr[i].addr );
  }
  hd->chksum  = in_csum( (u_short*)hd, vrrp_hd_len(vsrv), 0);

  /* copy the passwd if the authentication is VRRP_AH_PASS */
  if( vif->auth_type == VRRP_AUTH_PASS ){
    char  *pw  = (char *)hd+sizeof(*hd)+vsrv->naddr*4;
    memcpy( pw, vif->auth_data, sizeof(vif->auth_data));
  }

  return(0);
}

/* build VRRP packet */
static void vrrp_build_pkt( vrrp_rt *vsrv, int prio, char *buffer, int buflen )
{
  char *bufptr;

  bufptr = buffer;

  /* build the ethernet header */
  vrrp_build_dlt(vsrv, buffer, buflen);

  /* build the ip header */
  buffer += vrrp_dlt_len(vsrv);
  buflen -= vrrp_dlt_len(vsrv);
  vrrp_build_ip( vsrv, buffer, buflen );

  /* build the vrrp header */
  buffer += vrrp_iphdr_len(vsrv);

  if (vsrv->vif->auth_type == VRRP_AUTH_AH)
    buffer += vrrp_ipsecah_len(vsrv);
  buflen -= vrrp_iphdr_len(vsrv);

  if (vsrv->vif->auth_type == VRRP_AUTH_AH)
    buflen -= vrrp_ipsecah_len(vsrv);
  vrrp_build_vrrp(vsrv, prio, buffer, buflen);

  /* build the IPSEC AH header */
  if (vsrv->vif->auth_type == VRRP_AUTH_AH) {
    bufptr += vrrp_dlt_len(vsrv);
    buflen += vrrp_ipsecah_len(vsrv) + vrrp_iphdr_len(vsrv);;
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
    syslog(LOG_DEBUG, "VRRP Error : socket creation");
    return -1;
  }

  /* build the address */
  memset(&from, 0 , sizeof(from));
  strcpy( from.sa_data, vsrv->vif->ifname );

  /* send the data */
  len = sendto(fd, buffer, buflen, 0, &from, sizeof(from));

  close( fd );
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
    buflen += vrrp_ipsecah_len(vsrv);
  buffer = calloc(buflen, 1);
  memset(buffer,0,buflen);

  /* build the packet  */
  vrrp_build_pkt(vsrv, prio, buffer, buflen);

  /* send it */
  ret = vrrp_send_pkt(vsrv, buffer, buflen);
#ifdef DEBUG
  syslog(LOG_DEBUG, "Sending VRRP Advert on %s", vsrv->vif->ifname);
//  printf("Sending on : %s : fd :%d\n", vsrv->vif->ifname,vsrv->sockfd);
//  print_buffer(buflen,buffer);
#endif

  /* free the memory */
  free(buffer);
  return ret;
}


/* Received packet processing */
static int vrrp_read(vrrp_rt *vsrv, char *buf, int buflen)
{
  int len = 0;
  int ret;

  len = read(vsrv->sockfd, buf, buflen);

#ifdef DEBUG
  syslog(LOG_DEBUG, "VRRP packet received (%d bytes)", len);
//  print_buffer(buflen,buf);
#endif

  if (len > 0) {
    ret = vrrp_in_chk(vsrv, buf);

    if (ret == VRRP_PACKET_KO || ret == VRRP_PACKET_DROP)
      syslog(LOG_INFO, "bogus VRRP packet received !!!");

    return ret;
  }

  return VRRP_PACKET_NULL;
}

/* send a gratuitous ARP packet */
static int send_gratuitous_arp(vrrp_rt *vsrv, int addr, int vAddrF)
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

  char buf[sizeof(struct m_arphdr)+ETHER_HDR_LEN];
  char buflen = sizeof(struct m_arphdr)+ETHER_HDR_LEN;
  struct ether_header *eth = (struct ether_header *)buf;
  struct m_arphdr *arph = (struct m_arphdr *)(buf+vrrp_dlt_len(vsrv));
  char  *hwaddr = vAddrF ? vsrv->hwaddr : vsrv->vif->hwaddr;
  int  hwlen = ETH_ALEN;

  /* hardcoded for ethernet */
  memset(eth->ether_dhost, 0xFF, ETH_ALEN);
  memcpy(eth->ether_shost, hwaddr, hwlen);
  eth->ether_type = htons(ETHERTYPE_ARP);

  /* build the arp payload */
  memset(arph, 0, sizeof( *arph ));
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

/* becoming master */
static int vrrp_state_goto_master_thread(struct thread *thread)
{
  int  i;
  vrrp_instance *vrrp_instance = THREAD_ARG(thread);
  vrrp_rt *vsrv = vrrp_instance->vsrv;
  vrrp_if *vif = vsrv->vif;
  struct rt_entry *rt_table;

  /* set the VRRP MAC address -- rfc2338.7.3 */
  if(!vsrv->no_vmac) {
    /* backup the routing table */
    rt_table = iproute_list(vif->ifname);

    hwaddr_set(vif->ifname, vsrv->hwaddr, sizeof(vsrv->hwaddr));
    rcvhwaddr_op(vif->ifname, vif->hwaddr, sizeof(vif->hwaddr), 1);

    /* restore routing table */
    iproute_restore(rt_table, vif->ifname);
    iproute_clear(rt_table);
  }

  /* add the ip addresses */
  ipaddr_ops(vsrv, 1);

  /* send an advertisement */
  vrrp_send_adv(vsrv, vsrv->priority);

  /* send gratuitous arp for each virtual ip */
  for (i = 0; i < vsrv->naddr; i++)
    send_gratuitous_arp(vsrv, vsrv->vaddr[i].addr, 1);

  syslog(LOG_INFO, "VRRP_Instance(%s) entering MASTER STATE"
                 , vrrp_instance->iname);

  /* register master state thread */
  vsrv->state = VRRP_STATE_MAST;
  thread_add_read(thread->master, vrrp_state_master_thread, vrrp_instance, 
                  vsrv->sockfd, vsrv->adver_int);

  return 0;
}

/* leaving master state */
static void vrrp_restore_interface(vrrp_rt *vsrv, int advF)
{
  uint32_t addr[1024];
  vrrp_if *vif = vsrv->vif;
  struct rt_entry *rt_table;

  /* restore the original MAC addresses */
  if (!vsrv->no_vmac) {
    /* backup the routing table */
    rt_table = iproute_list(vif->ifname);

    hwaddr_set(vif->ifname, vif->hwaddr, sizeof(vif->hwaddr));
    rcvhwaddr_op(vif->ifname, vif->hwaddr, sizeof(vif->hwaddr), 0);

    /* restore routing table */
    iproute_restore(rt_table, vif->ifname);
    iproute_clear(rt_table);
  }

  /* remove the ip addresses */
  ipaddr_ops(vsrv, 0);

  /* if we stop vrrpd, warn the other routers to speed up the recovery */
  if (advF) {
    vrrp_send_adv(vsrv, VRRP_PRIO_STOP);
  }

  /*
   * Send gratuitous ARP for all the non-vrrp ip addresses to update
   * the cache of remote hosts using these addresses
   */
  if (!vsrv->no_vmac) {
    int i, naddr;
    naddr = ipaddr_list(ifname_to_idx(vif->ifname), addr
                        , sizeof(addr)/sizeof(addr[0]));
    for (i = 0; i < naddr; i++)
      send_gratuitous_arp(vsrv, addr[i], 0);
  }
}

static int vrrp_state_leave_master_thread(struct thread *thread)
{
  vrrp_instance *vrrp_instance = THREAD_ARG(thread);
  vrrp_rt *vsrv = vrrp_instance->vsrv;

  /* restore the routing table & remove VIPs */
  vrrp_restore_interface(vsrv, 0);

  syslog(LOG_INFO, "VRRP_Instance(%s) Entering BACKUP STATE"
                 , vrrp_instance->iname);

  /* register the vrrp backup handler */
  vsrv->state = VRRP_STATE_BACK;
  thread_add_read(thread->master, vrrp_state_backup_thread, vrrp_instance,
                  vsrv->sockfd, vsrv->ms_down_timer);
  return 0;
}

/* BACKUP state processing */
int vrrp_state_backup_thread(struct thread *thread)
{
  char *buf;
  int ret = 0;
  int buflen = 0;
  struct iphdr *iph;
  vrrp_pkt *hd;
  vrrp_instance *vrrp_instance = THREAD_ARG(thread);
  vrrp_rt *vsrv = vrrp_instance->vsrv;

//printf("-----[ %s ]------\nBACKUP STATE fd : %d\n", vrrp_instance->iname, thread->u.fd);

  if (thread->type == THREAD_READ_TIMEOUT) {

    /* If becoming MASTER in IPSEC AH AUTH, we reset the anti-replay */
    if (vsrv->ipsecah_counter->cycle) {
      vsrv->ipsecah_counter->cycle = 0;
      vsrv->ipsecah_counter->seq_number = 0;
    }

    /* register the vrrp transit backup state */
    vsrv->state = VRRP_STATE_BACK;
    thread_add_event(thread->master, vrrp_state_goto_master_thread, 
                     vrrp_instance, VRRP_STATE_MAST);

    syslog(LOG_INFO, "VRRP_Instance(%s) becoming MASTER"
                   , vrrp_instance->iname);
  } else {
    /* buffer allocation */
    if(vsrv->vif->auth_type == VRRP_AUTH_AH) {
      buflen = vrrp_iphdr_len(vsrv) + vrrp_ipsecah_len(vsrv) + vrrp_hd_len(vsrv);
      buf = calloc(buflen,1); 
      memset(buf,0,buflen);

      /* fill the header structure */
      ret = vrrp_read(vsrv, buf, buflen);
      iph = (struct iphdr *)buf;
      hd  = (vrrp_pkt *)((char *)iph + (iph->ihl<<2) + vrrp_ipsecah_len(vsrv));
    } else {
      buflen = vrrp_iphdr_len(vsrv) + vrrp_hd_len(vsrv);
      buf = calloc(buflen, 1);
      memset(buf,0,buflen);

      /* fill the header structure */
      ret = vrrp_read( vsrv, buf, buflen );
      iph = (struct iphdr *)buf;
      hd = (vrrp_pkt *)((char *)iph + (iph->ihl<<2));
    }

    if (ret == VRRP_PACKET_KO   || 
        ret == VRRP_PACKET_NULL ||
        ret == VRRP_PACKET_DROP) {
      syslog(LOG_INFO, "Dropping received advertisment...\n");
      vsrv->ms_down_timer = 3 * vsrv->adver_int + VRRP_TIMER_SKEW(vsrv);
    } else if (hd->priority == 0) {
      vsrv->ms_down_timer = VRRP_TIMER_SKEW(vsrv);
    } else if( !vsrv->preempt || hd->priority >= vsrv->priority ) {
      vsrv->ms_down_timer = 3 * vsrv->adver_int + VRRP_TIMER_SKEW(vsrv);
    }

    /* register next vrrp master thread */
    thread_add_read(thread->master, vrrp_state_backup_thread, vrrp_instance,
                    thread->u.fd, vsrv->ms_down_timer);

    free(buf);
  }

  return 0;
}

/* MASTER state processing */
static int vrrp_state_master_thread(struct thread *thread)
{
  char *buf;
  int ret = 0;
  int buflen = 0;
  struct iphdr *iph;
  vrrp_pkt *hd;
  vrrp_instance *vrrp_instance = THREAD_ARG(thread);
  vrrp_rt *vsrv = vrrp_instance->vsrv;

//printf("-----[ %s ]------\nMASTER STATE fd : %d\n", vrrp_instance->iname, thread->u.fd);

  if (thread->type == THREAD_READ_TIMEOUT) {

    if (vsrv->wantstate == VRRP_STATE_BACK ||
        vsrv->ipsecah_counter->cycle) {
      vsrv->ms_down_timer = 3 * vsrv->adver_int + VRRP_TIMER_SKEW(vsrv);

      /* register the vrrp transit backup state */
      vsrv->state  = VRRP_STATE_BACK;
      thread_add_event(thread->master, vrrp_state_leave_master_thread, 
                       vrrp_instance, VRRP_STATE_BACK);

      syslog(LOG_INFO, "VRRP_Instance(%s) becoming BACKUP"
                     , vrrp_instance->iname);
    }

    vrrp_send_adv(vsrv, vsrv->priority);

    /* register next vrrp master thread */
    thread_add_read(thread->master, vrrp_state_master_thread, vrrp_instance,
                    thread->u.fd, vsrv->adver_int);
  } else {
    /* buffer allocation */
    if (vsrv->vif->auth_type == VRRP_AUTH_AH) {
      buflen = vrrp_iphdr_len(vsrv) + vrrp_ipsecah_len(vsrv) + vrrp_hd_len(vsrv);
      buf = calloc(buflen,1); 
      memset(buf,0,buflen);

      /* fill the header structure */
      ret = vrrp_read(vsrv, buf, buflen);
      iph = (struct iphdr *)buf;
      hd  = (vrrp_pkt *)((char *)iph + (iph->ihl<<2) + vrrp_ipsecah_len(vsrv));
    } else {
      buflen = vrrp_iphdr_len(vsrv) + vrrp_hd_len(vsrv);
      buf = calloc(buflen, 1);
      memset(buf,0,buflen);

      /* fill the header structure */
      ret = vrrp_read(vsrv, buf, buflen);
      iph = (struct iphdr *)buf;
      hd = (vrrp_pkt *)((char *)iph + (iph->ihl<<2));
    }

    if (ret == VRRP_PACKET_KO   || 
        ret == VRRP_PACKET_NULL ||
        ret == VRRP_PACKET_DROP) {
      syslog(LOG_INFO, "Dropping received VRRP packet...\n");
      vrrp_send_adv(vsrv, vsrv->priority);

      /* register next vrrp master thread */
      thread_add_read(thread->master, vrrp_state_master_thread, vrrp_instance,
                      thread->u.fd, vsrv->adver_int);

    } else if (hd->priority == 0) {
      vrrp_send_adv(vsrv, vsrv->priority);

      /* register next vrrp master thread */
      thread_add_read(thread->master, vrrp_state_master_thread, vrrp_instance,
                      thread->u.fd, vsrv->adver_int);

    } else if( hd->priority > vsrv->priority ||
              (hd->priority == vsrv->priority &&
              ntohl(iph->saddr) > vsrv->vif->ipaddr)) {

      vsrv->ms_down_timer = 3 * vsrv->adver_int + VRRP_TIMER_SKEW(vsrv);

      /* register the vrrp transit backup state */
      vsrv->state  = VRRP_STATE_BACK;
      thread_add_event(thread->master, vrrp_state_leave_master_thread, 
                       vrrp_instance, VRRP_STATE_BACK);
    }
    free(buf);
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

  /* vrrp structure is completed */
  vsrv->initF = 1;

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
static int open_vrrp_socket(vrrp_rt *vsrv)
{
  struct ip_mreq req;
  struct ip_mreqn interface;
  u_char loop;
  int fd;
  int ret;

  /* open the socket */
  if (vsrv->vif->auth_type == VRRP_AUTH_AH)
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_IPSEC_AH);
  else
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_VRRP);

  if(fd < 0){
    int err = errno;
    syslog(LOG_INFO, "cant open raw socket. errno=%d. (try to run it as root)"
                   , err);
    return -1;
  }

  /* join the multicast group */
  memset(&req, 0, sizeof (req));
  req.imr_multiaddr.s_addr = htonl(INADDR_VRRP_GROUP);
  req.imr_interface.s_addr = htonl(vsrv->vif->ipaddr);
  ret = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   (char *)&req, sizeof(struct ip_mreq));

  /* disable loop back to local socket */
  loop = 0;
//  setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));

  if (ret < 0) {
    int  err = errno;
    syslog(LOG_INFO, "cant do IP_ADD_MEMBERSHIP errno=%d", err);
    return -1;
  }
#ifdef DEBUG
    else {
    syslog(LOG_DEBUG, "VRRP socket successfully created...");
  }
#endif

  /* binding the socket to the local interface */
  memset(&interface, 0, sizeof(interface));
  interface.imr_multiaddr.s_addr = htonl(INADDR_VRRP_GROUP);
  interface.imr_address.s_addr = htonl(vsrv->vif->ipaddr);
  interface.imr_ifindex = ifname_to_idx(vsrv->vif->ifname);
  ret = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF,
                   &interface, sizeof(struct ip_mreqn));

  if (ret < 0) {
    int  err = errno;
    syslog(LOG_INFO, "cant bind socket to interface errno=%d", err);
    return -1;
  }

  return fd;
}

/* 
 * Initialize state handling
 * --rfc2338.6.4.1
 */
int vrrp_state_init_thread(struct thread *thread)
{
  vrrp_instance *vrrp_instance = THREAD_ARG(thread);
  vrrp_rt *vsrv = vrrp_instance->vsrv;
  int fd;

  /* create the socket */
  fd = open_vrrp_socket(vsrv);
  if (fd < 0) return -1;

  vsrv->sockfd = fd;

  if (vsrv->priority == VRRP_PRIO_OWNER ||
      vsrv->wantstate == VRRP_STATE_MAST){
    thread_add_event(thread->master, vrrp_state_goto_master_thread, 
                     vrrp_instance, VRRP_STATE_MAST);
  } else {
    vsrv->ms_down_timer = 3 * vsrv->adver_int + VRRP_TIMER_SKEW(vsrv);

    syslog(LOG_INFO, "VRRP_Instance(%s) Entering BACKUP STATE"
                   , vrrp_instance->iname);

    /* register the vrrp backup handler */
    vsrv->state = VRRP_STATE_BACK;
    thread_add_read(thread->master, vrrp_state_backup_thread,
                    vrrp_instance, fd, vsrv->ms_down_timer);
  }

  return 0;
}

/* handle terminate state */
void vrrp_state_stop_instance(vrrp_rt *vsrv)
{
  /* restore MAC, routing table & remove VIPs */
  vrrp_restore_interface(vsrv, 1);
}
