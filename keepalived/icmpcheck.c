/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        ICMP CHECK. Build an ICMP packet and send it to a remote
 *              server.
 *  
 * Version:     $Id: icmpcheck.c,v 0.2.3 2001/01/01 $
 * 
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *              
 * Changes:     
 *         Alexandre Cassen : 2001/01/01 :
 *          <+> Added recvfrom_to() function to handle recvfrom timeouted connection.
 *              Call this function in ICMP_RCV_ECHOREPLY with 1s timeout.
 *          <+> Added a timer (2s timeouted) in ICMP_RCV_ECHOREPLY to check
 *              ECHO_REPLY. Check perform on icmp type flag, remote ip address.
 *          <+> Added a 3 time ECHO_REQUEST send retry.
 *
 *         Alexandre Cassen : 2000/12/09 : Initial release
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

  to.tv_sec  = timo/1000;
  to.tv_usec = 0;

  FD_ZERO(&readset);
  FD_ZERO(&writeset);
  FD_SET(s,&readset);
  nfound = select(s+1,&readset,&writeset,NULL,&to);
  if (nfound<0) { 
    return(-1);
  }
  if (nfound==0) return -1;
  slen=sizeof(struct sockaddr);
  n=recvfrom(s,buf,len,0,saddr,&slen);
  if (n<0) return -1;
  return n;
}

int ICMP_SEND_ECHOREQUEST(char *IP_DST)
{
  struct iphdr *ipHdr;
  struct icmphdr *icmpHdr;
  struct sockaddr_in addr;
  unsigned char *sendbuff;
  char *debugmsg;
  char on = 1;
  int hlen;
  int result;
  int sockfd;
	
  unsigned long tmp;

  debugmsg=(char *)malloc(LOGBUFFER_LENGTH);	
  sendbuff = (unsigned char *)malloc(BUFFSIZE);

  memset(debugmsg,0,BUFFSIZE);
  memset(sendbuff,0,BUFFSIZE);
	
  if((sockfd = socket( AF_INET , SOCK_RAW , IPPROTO_ICMP )) < 0) {
    free(debugmsg);
    free(sendbuff);
    return(SOCKET_ERROR);
  }
	
  if(setsockopt(sockfd , IPPROTO_IP , IP_HDRINCL , &on , sizeof(on)) < 0) {
    free(debugmsg);
    free(sendbuff);
    close(sockfd);
    return(SOCKET_ERROR);
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

  if( hostToaddr(IP_DST, &tmp) < 0 ) {
    close(sockfd);
    free(sendbuff);
    free(debugmsg);
    return(SOCKET_ERROR);
  }

  ipHdr->daddr = tmp;
  ipHdr->check = in_cksum( (unsigned short *)ipHdr , sizeof(struct iphdr) );
  icmpHdr = (struct icmphdr *)( sendbuff + sizeof(struct iphdr) );
  icmpHdr->type = ICMP_ECHO;
  icmpHdr->code = 0;
  icmpHdr->un.echo.id = getpid();
  icmpHdr->un.echo.sequence = getpid();
  icmpHdr->checksum = in_cksum( (unsigned short *)icmpHdr , sizeof(struct icmphdr) );

  memset((char *)&addr,0,sizeof(addr));
  addr.sin_addr.s_addr = ipHdr->daddr;
  addr.sin_family = AF_INET;

  /* Add the icmp data part 
  memcpy(sendbuff+HDRBUFFSIZE,ICMP_DATA,sizeof(ICMP_DATA)); */
	
  if( sendto(sockfd, sendbuff , sizeof(struct iphdr)+sizeof(struct icmphdr) , 0 , (struct sockaddr *)&addr , sizeof(addr)) < 0 ) {
    close(sockfd);
    free(sendbuff);
    free(debugmsg);
    return(SOCKET_ERROR);
  }

  close(sockfd);
  free(sendbuff);
  free(debugmsg);
  return(SOCKET_SUCCESS);
}

int ICMP_RCV_ECHOREPLY(char *IP_DST)
{
  struct sockaddr_in response_addr ;
  struct iphdr *ip;
  struct icmphdr *icp;
  unsigned char *recvbuff;
  char *debugmsg;
  time_t hint;
  struct tm *date;
  int timer_before, timer_after;
  char on = 1;
  int hlen;
  int result;
  int sockfd;
  int loop=1;

  /* Packet pointer affectation */
  debugmsg=(char *)malloc(LOGBUFFER_LENGTH);	
  recvbuff=(char *)malloc(BUFFSIZE);
  memset((char *)recvbuff,0,BUFFSIZE);

  if((sockfd = socket( AF_INET , SOCK_RAW , IPPROTO_ICMP )) < 0) {
    free(debugmsg);
    free(recvbuff);
    return(SOCKET_ERROR);
  }
	
  if(setsockopt(sockfd , IPPROTO_IP , IP_HDRINCL , &on , sizeof(on)) < 0) {
    free(debugmsg);
    free(recvbuff);
    close(sockfd);
    return(SOCKET_ERROR);
  }

  /* Timer initialization */
  /* We can also use a signal SIGALRM and catch this signal with handler to break the loop */
  hint = time((long*)0);
  date = localtime(&hint);
  timer_before = date->tm_sec;

  while(loop) {
    result=recvfrom_wto(sockfd,recvbuff,BUFFSIZE,(struct sockaddr *)&response_addr,select_time);

#ifdef DEBUG
    if (result<0) { 
      memset(debugmsg,0,LOGBUFFER_LENGTH);
      sprintf(debugmsg,"ICMP_CHECK : icmp timeout to [%s]...\n",IP_DST);
      logmessage(debugmsg,getpid());
    }
#endif

    ip = (struct iphdr *)recvbuff;
    hlen = ip->ihl << 2;

    if (result < hlen+ICMP_MINLEN) {
#ifdef DEBUG
      memset(debugmsg,0,LOGBUFFER_LENGTH);
      sprintf(debugmsg,"ICMP_CHECK : Received packet too short according to ICMP protocol from [%s]...\n",IP_DST);
      logmessage(debugmsg,getpid());
#endif
    }

    icp = (struct icmphdr *)(recvbuff + hlen);
    if ( (icp->type == ICMP_ECHOREPLY) && 
         (ip->saddr == inet_addr(IP_DST)) &&
         (result >= hlen+ICMP_MINLEN) ) {
      close(sockfd);
      free(recvbuff);
      free(debugmsg);
      return(SOCKET_SUCCESS);
    }

#ifdef DEBUG
      memset(debugmsg,0,LOGBUFFER_LENGTH);
      sprintf(debugmsg,"ICMP_CHECK : ECHO_REPLY not received from [%s] retry\n",IP_DST);
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
  sprintf(debugmsg,"ICMP_CHECK : ECHO_REPLY not received from [%s] packet losed\n",IP_DST);
  logmessage(debugmsg,getpid());
#endif

  close(sockfd);
  free(recvbuff);
  free(debugmsg);
  return(SOCKET_ERROR);
}

int ICMP_CHECK(char *IP_DST)
{
  char *debugmsg;
  int loop=1;
  int retry=0;

  /* Memory allocation for the data structures */
  debugmsg=(char *)malloc(LOGBUFFER_LENGTH);

  while(loop) {

    if(!ICMP_SEND_ECHOREQUEST(IP_DST)) {
#ifdef DEBUG
      memset(debugmsg,0,LOGBUFFER_LENGTH);
      sprintf(debugmsg,"ICMP_CHECK : Can't send ECHO_REQUEST to [%s]\n",IP_DST);
      logmessage(debugmsg,getpid());
#endif
      free(debugmsg);
      return(SOCKET_ERROR);
    }
    if(ICMP_RCV_ECHOREPLY(IP_DST)) {
      loop=0;
    } else {
      retry++;
#ifdef DEBUG
      memset(debugmsg,0,LOGBUFFER_LENGTH);
      sprintf(debugmsg,"ICMP_CHECK : Reexpedite ECHO_REQUEST to [%s]\n",IP_DST);
      logmessage(debugmsg,getpid());
#endif
      loop=(retry==NB_RETRY)?0:1;
    }
  }

  if(retry==NB_RETRY) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"ICMP_CHECK : ECHO_REPLY not received from [%s] after 3 try\n",IP_DST);
    logmessage(debugmsg,getpid());
#endif
    free(debugmsg);
    return(SOCKET_ERROR);
  }

  free(debugmsg);
  return(SOCKET_SUCCESS);
}
