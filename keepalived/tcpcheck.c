/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        TCP CHECK. Build a TCP/IP packet and send it to a remote
 *              server. This check implement the tcp half open connection
 *              check.
 *  
 * Version:     $Id: tcpcheck.c,v 0.2.3 2000/12/29 $
 * 
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *              
 * Changes:     
 *         Alexandre Cassen : 2000/12/29 :
 *          <+> Added recvfrom_to() function to handle recvfrom timeouted connection.
 *              Call this function in TCP_RCV_SYNACK_PACKET with 1s timeout.
 *          <+> Added a timer (2s timeouted) in TCP_RCV_SYNACK_PACKET to check
 *              SYN|ACK packet. Check perform on tcp sequence, remote tcp port number,
 *              tcp SYN|ACK flag, remote ip address.
 *          <+> Added a 3 time SYN packet send retry.
 *
 *         Alexandre Cassen : 2000/12/09 : Initial release
 *
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#include "tcpcheck.h"

int recvfrom_to(int s, char *buf, int len, struct sockaddr *saddr, int timo)
{
  int nfound,slen,n;
  struct timeval to;
  fd_set readset,writeset;

  to.tv_sec  = timo/1000;
  to.tv_usec = 0;

  FD_ZERO(&readset);
  FD_ZERO(&writeset);
  FD_SET(s,&readset);
  nfound = select(s+1,&readset,&writeset,NULL,&to);
  if (nfound<0) {
#ifdef DEBUG
    logmessage("TCP_CHECK : Select socket descriptor error...\n",getpid());
#endif
    return(-1);
  }
  if (nfound==0) {
#ifdef DEBUG
    logmessage("TCP_CHECK : Timeout receiving SYN response...\n",getpid());
#endif
    return -1;
  }
  slen=sizeof(struct sockaddr_in);
  n=recvfrom(s,buf,len,0,saddr,&slen);
  if (n<0) {
#ifdef DEBUG
    logmessage("TCP_CHECK : recvfrom error...\n",getpid());
#endif
    return -1;
  }
  return n;
}

int TCP_SEND_PACKET(char *IP_SRC,char *IP_DST,char *PORT_DST,char *FLAG,unsigned long int SEQ)
{
  register int rawsock;
  struct linger li = { 0 };

  /* Packet Data representation */
  struct iphdr *packet_ip;
  struct tcphdr *packet_tcp;
  struct tcphdr_pseudo packet_tcppseudo;
  struct sockaddr_in dest;
  char *packet;

  /* Packet pointer affectation */
  packet=(char *)malloc(SYNPACKET_LENGTH);
  memset(packet,0,SYNPACKET_LENGTH);
  memset(&dest,0,sizeof(struct sockaddr_in));
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
  packet_tcp->seq     = SEQ;
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
  /* A little fake, IP & PORT are in IP & TCP headers */
  dest.sin_family = AF_INET;
  dest.sin_port  = packet_tcp->dest;
  dest.sin_addr.s_addr = packet_ip->daddr;

  if (sendto(rawsock,packet,sizeof(struct iphdr) + sizeof(struct tcphdr),
             0,&dest,sizeof(dest)) < 0) {
    close(rawsock);
    free(packet);
    return(SOCKET_ERROR);
  }

  close(rawsock);
  free(packet);
  return(SOCKET_SUCCESS);
}

int TCP_RCV_SYNACK_PACKET(char *IP_DST, char *PORT_DST, unsigned long int SEQ)
{
  register int rawsock;
  struct linger li = { 0 };
  time_t hint;
  struct tm *date;
  int timer_before, timer_after;
  int loop = 1;
  char *debugmsg;

  /* Packet Data representation */
  struct iphdr *packet_ip;
  struct tcphdr *packet_tcp;
  struct tcphdr_pseudo packet_tcppseudo;
  struct sockaddr_in dest;
  char *packet;

  /* Packet pointer affectation */
  debugmsg=(char *)malloc(LOGBUFFER_LENGTH);
  packet=(char *)malloc(SYNPACKET_LENGTH);
  memset(packet,0,SYNPACKET_LENGTH);
  memset(debugmsg,0,LOGBUFFER_LENGTH);
  memset(&dest,0,sizeof(struct sockaddr_in));
  packet_ip=(struct iphdr *)packet;
  packet_tcp=(struct tcphdr *)(packet_ip+1);

  if ( (rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1 ) {
    free(debugmsg);
    free(packet);
    return (SOCKET_ERROR);
  }

  /* free the tcp port after closing the socket descriptor */
  li.l_onoff=1;
  li.l_linger=0;
  setsockopt(rawsock,SOL_SOCKET,SO_LINGER,(char *)&li,sizeof(struct linger));

  /* Fill in the Sockaddr structure */
  memset(&dest,0,sizeof(struct sockaddr_in));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(atoi(PORT_DST));
  dest.sin_addr.s_addr = inet_addr(IP_DST);

  /* Timer initialization */
  /* We can also use a signal SIGALRM and catch this signal with handler to break the loop */
  hint = time((long*)0);
  date = localtime(&hint);
  timer_before = date->tm_sec;

  while(loop) {
    if (recvfrom_to(rawsock,packet,SYNPACKET_LENGTH,(struct sockaddr *)&dest,1000) < 0) {
      close(rawsock);
      free(debugmsg);
      free(packet);
      return(SOCKET_ERROR);
    }

    if ( packet_tcp->syn && packet_tcp->ack && 
        (packet_tcp->ack_seq == SEQ) &&
        (packet_ip->saddr == dest.sin_addr.s_addr) &&
        (packet_tcp->source == htons(atoi(PORT_DST))) ) {
      close(rawsock);
      free(debugmsg);
      free(packet);
      return(SOCKET_SUCCESS);
    }

#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"TCP_CHECK : SYN|ACK packet not recieved from [%s:%s]. Retry\n",IP_DST,PORT_DST);
    logmessage(debugmsg,getpid());
#endif

    /* timer to evaluate packet loosed */
    hint = time((long*)0);
    date = localtime(&hint);
    timer_after = date->tm_sec;

    if(abs(timer_after-timer_before)>1) loop=0;
  }

#ifdef DEBUG
  memset(debugmsg,0,LOGBUFFER_LENGTH);
  sprintf(debugmsg,"TCP_CHECK : SYN|ACK packet loosed from [%s:%s]\n",IP_DST,PORT_DST);
  logmessage(debugmsg,getpid());
#endif

  close(rawsock);
  free(debugmsg);
  free(packet);
  return(SOCKET_ERROR);
}

int TCP_CHECK(char *IP_SRC, char *IP_DST, char *PORT_DST)
{
  register int tcpsock;
  char *debugmsg;
  int loop=1;
  int retry=0;
  unsigned long int SEQTCP=0;

  /* Memory allocation for the data structures */
  debugmsg=(char *)malloc(LOGBUFFER_LENGTH);

  while(loop) {
    SEQTCP = random() & 0xffff;

    if(!TCP_SEND_PACKET(IP_SRC,IP_DST,PORT_DST,"SYN",htonl(SEQTCP-1))) {
#ifdef DEBUG
      memset(debugmsg,0,LOGBUFFER_LENGTH);
      sprintf(debugmsg,"TCP_CHECK : Can't send SYN request to [%s:%s]\n",IP_DST,PORT_DST);
      logmessage(debugmsg,getpid());
#endif
      free(debugmsg);
      return(SOCKET_ERROR);
    }
    if(TCP_RCV_SYNACK_PACKET(IP_DST,PORT_DST,htonl(SEQTCP))) {
      loop=0;
    } else {
      retry++;
#ifdef DEBUG
      memset(debugmsg,0,LOGBUFFER_LENGTH);
      sprintf(debugmsg,"TCP_CHECK : Reexpedite SYN request to [%s:%s]\n",IP_DST,PORT_DST);
      logmessage(debugmsg,getpid());
#endif
      loop=(retry==NB_RETRY)?0:1;
    }
  }

  if (retry==NB_RETRY) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"TCP_CHECK : SYN|ACK response not recieved from [%s:%s] after 3 try\n",IP_DST,PORT_DST);
    logmessage(debugmsg,getpid());
#endif
    free(debugmsg);
    return(SOCKET_ERROR);
  }

  /* The we send a RST TCP packet to be sure that the remote host */
  /* close the communication channel.                             */
  /* Needed some time by MS Windows .... damned...                */

  if(!TCP_SEND_PACKET(IP_SRC,IP_DST,PORT_DST,"RST ACK",SEQTCP)) {
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
