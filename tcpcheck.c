/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        TCP CHECK. Build a TCP/IP packet and send it to a remote
 *              server. This check implement the tcp half open connection
 *              check.
 *  
 * Version:     $Id: tcpcheck.c,v 0.2.5 2001/02/16 $
 * 
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *              
 * Changes:     
 *         Alexandre Cassen : 2001/02/16 :
 *          <-> Suppress the whole RAW_SOCKET tcpcheck level initial implementation.
 *          <+> Replace the RAW_SOCKET initial implementation by a vanilla tcpcheck.
 *              Using non blocking & no_linger socket. Use a timeval to set socket
 *              descriptor timeout.
 *
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

int TCP_CHECK(const char *IP_DST, const char *PORT_DST)
{
  register int sdesc;
  int long_inet;
  char *debugmsg;
  struct hostent *ip_serv;
  struct sockaddr_in adr_serv;
  struct linger li = { 0 };
  struct timeval tv;
  fd_set wfds;
  int rc, val;
  int arglen;

  /* Memory allocation for the data structures */
  debugmsg=(char *)malloc(LOGBUFFER_LENGTH);
  memset(debugmsg,0,LOGBUFFER_LENGTH);

  if ( (sdesc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1 ) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"TCP_CHECK : Can not bind remote address %s:%s\n",IP_DST,PORT_DST);
    logmessage(debugmsg);
#endif
    free(debugmsg);
    return(SOCKET_ERROR);
  }

  /* free the tcp port after closing the socket descriptor */
  li.l_onoff=1;
  li.l_linger=0;
  setsockopt(sdesc,SOL_SOCKET,SO_LINGER,(char *)&li,sizeof(struct linger));

  long_inet = sizeof(struct sockaddr_in);

  if ( (ip_serv=gethostbyname(IP_DST)) == NULL) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"TCP_CHECK : Can not resolve remote host %s\n",IP_DST);
    logmessage(debugmsg);
#endif
    free(debugmsg);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  memset(&adr_serv,0,long_inet);
  adr_serv.sin_family=ip_serv->h_addrtype;
  bcopy(ip_serv->h_addr, &adr_serv.sin_addr.s_addr,ip_serv->h_length);
  adr_serv.sin_port=htons(atoi(PORT_DST));

  /* Set read/write socket timeout */
  val=fcntl(sdesc, F_GETFL);
  fcntl(sdesc, F_SETFL, val | O_NONBLOCK);

  /* Connect the remote host */
  if ( (rc=connect(sdesc, (struct sockaddr *)&adr_serv, long_inet)) == -1) {
    switch (errno) {
      case ETIMEDOUT:
      case EINTR:
      case EHOSTUNREACH:
#ifdef DEBUG
        memset(debugmsg,0,LOGBUFFER_LENGTH);
        sprintf(debugmsg,"TCP_CHECK : Connection timeout to %s:%s\n",IP_DST,PORT_DST);
        logmessage(debugmsg);
#endif
        break;
      case ECONNREFUSED:
#ifdef DEBUG
        memset(debugmsg,0,LOGBUFFER_LENGTH);
        sprintf(debugmsg,"TCP_CHECK : Connection refused to %s:%s\n",IP_DST,PORT_DST);
        logmessage(debugmsg);
#endif
        break;
      case ENETUNREACH:
#ifdef DEBUG
        memset(debugmsg,0,LOGBUFFER_LENGTH);
        sprintf(debugmsg,"TCP_CHECK : Network unreachable to %s:%s\n",IP_DST,PORT_DST);
        logmessage(debugmsg);
#endif
        break;
      case EINPROGRESS: // NONBLOCK socket connection in progress
        goto next;
      default:
#ifdef DEBUG
        memset(debugmsg,0,LOGBUFFER_LENGTH);
        sprintf(debugmsg,"TCP_CHECK : Network error [%s] to %s:%s\n",strerror(errno),IP_DST,PORT_DST);
        logmessage(debugmsg);
#endif
    }

    free(debugmsg);
    close(sdesc);
    return(SOCKET_ERROR);
  }

next:
  /* Timeout settings */
  tv.tv_sec=SOCKET_TIMEOUT;
  tv.tv_usec=0;
  FD_ZERO(&wfds);
  FD_SET(sdesc,&wfds);

  rc = select(sdesc+1,NULL,&wfds,NULL,&tv);
  if (!FD_ISSET(sdesc,&wfds)) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"TCP_CHECK : Timeout writing data to %s:%s\n",IP_DST,PORT_DST);
    logmessage(debugmsg);
#endif
    free(debugmsg);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  if (rc < 0) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"TCP_CHECK : Select returned descriptor error to %s:%s\n",IP_DST,PORT_DST);
    logmessage(debugmsg);
#endif
    free(debugmsg);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  rc = 0;
  arglen=sizeof(int);
  if (getsockopt(sdesc,SOL_SOCKET,SO_ERROR,&rc,&arglen) < 0)
    rc = errno;

  if (rc) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"TCP_CHECK : Connection failed to %s:%s (%s)\n",IP_DST,PORT_DST,strerror(rc));
    logmessage(debugmsg);
#endif
    free(debugmsg);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  free(debugmsg);
  return(SOCKET_SUCCESS);
}
