/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        TCP CHECK. Build a TCP/IP packet and send it to a remote
 *              server. This check implement the tcp half open connection
 *              check.
 *  
 * Version:     $Id: keepalived.c,v 0.2.1 2000/12/09 $
 * 
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *              
 * Changes:     
 *              Alexandre Cassen      :       Initial release
 *              
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#include "tcpcheck.h"

#define SEQUENCE 0x28376839

int TCP_SEND_PACKET(char *IP_SRC,char *IP_DST,char *PORT_DST,char *FLAG)
{
  register int rawsock;
  struct linger li = { 0 };

  /* Packet Data representation */
  struct iphdr *packet_ip;
  struct tcphdr *packet_tcp;
  struct tcphdr_pseudo packet_tcppseudo;
  struct sockaddr dest;
  char *packet;

  /* Packet pointer affectation */
  packet=(char *)malloc(SYNPACKET_LENGTH);
  bzero(packet,SYNPACKET_LENGTH);
  packet_ip=(struct iphdr *)packet;
  packet_tcp=(struct tcphdr *)(packet_ip+1);

  if ( (rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1 ) {
    free(packet);
    return (SOCKET_ERROR);
  }

  /* free the tcp port after closing the socket descriptor */
  li.l_onoff=1;
  li.l_linger=0;
  setsockopt(rawsock,SOL_SOCKET,SO_LINGER,(char *)&li,sizeof(struct linger));

  /* Fill in the IP header structure */
  packet_ip->version  = 4;
  packet_ip->ihl      = 5;
  packet_ip->tos      = 0 ;
  packet_ip->tot_len  = sizeof(struct iphdr) + sizeof(struct tcphdr);
  packet_ip->id       = htons(random());
  packet_ip->frag_off = 0;
  packet_ip->ttl      = 30;              /* 30 Hops Max */
  packet_ip->protocol = IPPROTO_TCP;
  packet_ip->saddr    = inet_addr(IP_SRC);
  packet_ip->daddr    = inet_addr(IP_DST);
  packet_ip->check    = in_cksum((unsigned short *)packet_ip, sizeof(struct iphdr));

  /* Fill in the TCP header structure */
  packet_tcp->source  = htons(STCP);
  packet_tcp->dest    = htons(atoi(PORT_DST));
  packet_tcp->seq     = htonl(SEQUENCE);
  packet_tcp->doff    = sizeof(struct tcphdr)/4;
  packet_tcp->ack_seq = 0;
  packet_tcp->res1    = 0;
  packet_tcp->fin     = (strstr(FLAG,"FIN"))?1:0;
  packet_tcp->syn     = (strstr(FLAG,"SYN"))?1:0;
  packet_tcp->rst     = (strstr(FLAG,"RST"))?1:0;
  packet_tcp->psh     = (strstr(FLAG,"PSH"))?1:0;
  packet_tcp->ack     = (strstr(FLAG,"ACK"))?1:0;
  packet_tcp->urg     = (strstr(FLAG,"URG"))?1:0;
  packet_tcp->res2    = 0;
  packet_tcp->window  = htons(65535);
  packet_tcp->check   = 0;
  packet_tcp->urg_ptr = 0;

  /* Fill in the TCP pseudo structure */
  packet_tcppseudo.saddr = packet_ip->saddr;
  packet_tcppseudo.daddr = packet_ip->daddr;
  packet_tcppseudo.zero = 0;
  packet_tcppseudo.proto = packet_ip->protocol;
  packet_tcppseudo.tcplen = htons(sizeof(struct tcphdr));
  bcopy((char *)packet_tcp, (char *)&packet_tcppseudo.tcp, sizeof(struct tcphdr));

  packet_tcp->check = in_cksum((unsigned short *)&packet_tcppseudo, 
                             sizeof(struct tcphdr_pseudo));

  /* Fill in the Sockaddr structure */
  dest.sa_family = AF_INET;
  bcopy(&packet_ip->daddr,&dest.sa_data[2],4);
  bcopy(&packet_tcp->source,&dest.sa_data[0],2);

  if (sendto(rawsock,packet,sizeof(struct iphdr) + sizeof(struct tcphdr),
             0,&dest,sizeof(dest)) < 0) {
    close(rawsock);
    free(packet);
    return(SOCKET_ERROR);
  }
  free(packet);
  return(SOCKET_SUCCESS);
}

int TCP_RCV_SYNACK_PACKET()
{
  register int rawsock;
  struct linger li = { 0 };

  /* Packet Data representation */
  struct iphdr *packet_ip;
  struct tcphdr *packet_tcp;
  struct tcphdr_pseudo packet_tcppseudo;
  struct sockaddr dest;
  char *packet;
  int fromlen=0;

  fromlen=sizeof(struct sockaddr);

  /* Packet pointer affectation */
  packet=(char *)malloc(SYNPACKET_LENGTH);
  bzero(packet,SYNPACKET_LENGTH);
  packet_ip=(struct iphdr *)packet;
  packet_tcp=(struct tcphdr *)(packet_ip+1);

  if ( (rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1 ) {
    free(packet);
    return (SOCKET_ERROR);
  }

  /* free the tcp port after closing the socket descriptor */
  li.l_onoff=1;
  li.l_linger=0;
  setsockopt(rawsock,SOL_SOCKET,SO_LINGER,(char *)&li,sizeof(struct linger));

  if (recvfrom(rawsock,packet,SYNPACKET_LENGTH,
               0,(struct sockaddr *)&dest,&fromlen) < 0) {
    free(packet);
    close(rawsock);
    return(SOCKET_ERROR);
  }

  close(rawsock);

  if ( packet_tcp->syn && packet_tcp->ack) {
    free(packet);
    return(SOCKET_SUCCESS);
  } else {
    free(packet);
    return(SOCKET_ERROR);
  }
}

int TCP_CHECK(char *IP_SRC, char *IP_DST, char *PORT_DST)
{
  register int tcpsock;
  char *debugmsg;

  /* Memory allocation for the data structures */
  debugmsg=(char *)malloc(LOGBUFFER_LENGTH);
  bzero(debugmsg,LOGBUFFER_LENGTH);

  if(!TCP_SEND_PACKET(IP_SRC,IP_DST,PORT_DST,"SYN")) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"TCP_CHECK : Can't send SYN request to [%s:%s]\n",IP_DST,PORT_DST);
    logmessage(debugmsg,getpid());
#endif
    free(debugmsg);
    return(SOCKET_ERROR);
  }

  if(!TCP_RCV_SYNACK_PACKET()) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"TCP_CHECK : Didn't recieve SYN response from [%s:%s]\n",IP_DST,PORT_DST);
    logmessage(debugmsg,getpid());
#endif
    free(debugmsg);
    return(SOCKET_ERROR);
  }

  if(!TCP_SEND_PACKET(IP_SRC,IP_DST,PORT_DST,"RST ACK")) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"TCP_CHECK : Can't send RST to [%s:%s]\n",IP_DST,PORT_DST);
    logmessage(debugmsg,getpid());
#endif
    free(debugmsg);
    return(SOCKET_ERROR);
  }

  free(debugmsg);
  return(SOCKET_SUCCESS);
}
