/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        ICMP CHECK. Build an ICMP packet and send it to a remote
 *              server.
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

#include "icmpcheck.h"

int recvfrom_wto(int s, char *buf, int len, struct sockaddr *saddr, int timo)
{
  int nfound,slen,n;
  struct timeval to;
  fd_set readset,writeset;

  to.tv_sec  = timo/100000;
  to.tv_usec = (timo - (to.tv_sec*100000))*10;

  FD_ZERO(&readset);
  FD_ZERO(&writeset);
  FD_SET(s,&readset);
  nfound = select(s+1,&readset,&writeset,NULL,&to);
  if (nfound<0) { 
    //printf("select failed !!!\n"); 
    return(-1);
  }
  if (nfound==0) return -1;  /* timeout */
  slen=sizeof(struct sockaddr);
  n=recvfrom(s,buf,len,0,saddr,&slen);
  if (n<0) return -1; // printf("Error recvfrom");
  return n;
}

int ICMP_CHECK(char dst_ip[16])
{
  struct iphdr *ipHdr;
  struct icmphdr *icmpHdr;
  struct sockaddr_in addr ;
  struct sockaddr_in response_addr ;
  struct ip *ip;
  struct icmp *icp;
  unsigned char *sendbuff;
  unsigned char *recvbuff;
  char *debugmsg;
  char on = 1;
  int hlen;
  int result;
  int sockfd;
	
  unsigned long tmp;

  debugmsg=(char *)malloc(LOGBUFFER_LENGTH);	
  sendbuff = (unsigned char *)malloc(BUFFSIZE);

  bzero(sendbuff,BUFFSIZE);
	
  if( (sockfd = socket( AF_INET , SOCK_RAW , IPPROTO_ICMP )) < 0 ) {
    free(debugmsg);
    free(sendbuff);
    return(0);
  }
	
  if( setsockopt(sockfd , IPPROTO_IP , IP_HDRINCL , &on , sizeof(on)) < 0 ) {
    free(debugmsg);
    free(sendbuff);
    close(sockfd);
    return(0);
  }

  ipHdr = (struct iphdr *)sendbuff;

  ipHdr->ihl = 5;			 /* No options Feild */
  ipHdr->version = 0x4;
  ipHdr->tos =  0 ;			/* Low Delay */
  ipHdr->tot_len = sizeof(struct iphdr) + sizeof( struct icmphdr );
  ipHdr->id = htons( getpid() );
  ipHdr->frag_off = 0;
  ipHdr->ttl = 30;			/* 30 Hops max */
  ipHdr->protocol = IPPROTO_ICMP;
  ipHdr->check = 0 ;

  if( hostToaddr(dst_ip, &tmp) < 0 ) {
    // perror("Host to addr conversion failed!");
    close(sockfd);
    free(sendbuff);
    free(debugmsg);
    return(0);
  }

  ipHdr->daddr = tmp;
  ipHdr->check = in_cksum( (unsigned short *)ipHdr , sizeof(struct iphdr) );
  icmpHdr = (struct icmphdr *)( sendbuff + sizeof(struct iphdr) );
  icmpHdr->type = ICMP_ECHO;
  icmpHdr->code = 0;
  icmpHdr->un.echo.id = getpid();
  icmpHdr->un.echo.sequence = getpid();
  icmpHdr->checksum = in_cksum( (unsigned short *)icmpHdr , sizeof(struct icmphdr) );

  bzero( (char *)&addr, sizeof(addr) );
  addr.sin_addr.s_addr = ipHdr->daddr;
  addr.sin_family = AF_INET;

  /* Add the icmp data part */
  bcopy(ICMP_DATA,sendbuff+HDRBUFFSIZE,sizeof(ICMP_DATA));
	
  if( sendto(sockfd, sendbuff , sizeof(struct iphdr)+sizeof(struct icmphdr) , 0 , (struct sockaddr *)&addr , sizeof(addr)) < 0 ) {
    //perror("SendTo Error:");
    close(sockfd);
    free(sendbuff);
    free(debugmsg);
    return(0);
  }

  /* Handle arp request */
  sleep(DELAY_TIME);

  /* Echo reply test */
  recvbuff=(char *)malloc(BUFFSIZE);
  bzero((char *)recvbuff,BUFFSIZE);

  result=recvfrom_wto(sockfd,recvbuff,BUFFSIZE,(struct sockaddr *)&response_addr,select_time);

#ifdef DEBUG
  if (result<0) { 
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"ICMP_CHECK : icmp timeout to %s...\n",dst_ip);
    logmessage(debugmsg,getpid());
  }
#endif

  ip = (struct ip *)recvbuff;

  hlen = ip->ip_hl << 2;

  if (result < hlen+ICMP_MINLEN) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"ICMP_CHECK : Received packet too short according to ICMP protocol to %s...\n",dst_ip);
    logmessage(debugmsg,getpid());
#endif
    close(sockfd);
    free(sendbuff);
    free(debugmsg);
    return(0);
  }

  icp = (struct icmp *)(recvbuff + hlen);
  if (icp->icmp_type != ICMP_ECHOREPLY) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"ICMP_CHECK : ICMP ECHO REPLY not received from %s !!!\n",dst_ip);
    logmessage(debugmsg,getpid());
#endif
    close(sockfd);
    free(sendbuff);
    free(debugmsg);
    return(0);
  } else {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"ICMP_CHECK : ICMP ECHO REPLY recived from %s...\n",dst_ip);
    logmessage(debugmsg,getpid());
#endif
  }

  free(sendbuff);
  free(recvbuff);
  free(debugmsg);

  close(sockfd);
  return(1);
}
