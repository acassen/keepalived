/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        HTTP GET CHECK. Perform an http get query to a specified 
 *              url, compute a MD5 over this result and match it to the
 *              expected value.
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

#include "httpget.h"

int GET(char *IP_SRC,char *IP_DST, char *PORT_DST, char *URL, char *buffer)
{
  register int sdesc;
  int long_inet;
  int rcv_buffer_size=0;
  char *str_request;
  struct hostent *ip_serv;
  struct sockaddr_in adr_serv;
  struct linger li = { 0 };
  char *debugmsg;

  if (!TCP_CHECK(IP_SRC,IP_DST,PORT_DST)) {
#ifdef DEBUG
    logmessage("HTTP_GET : TCP check failed...\n",getpid());
#endif
    return 0;
  }

  debugmsg=(char *)malloc(LOGBUFFER_LENGTH);
  str_request=(char *)malloc(GET_REQUEST_BUFFER_LENGTH);
  strcpy(str_request,"GET ");
  strcat(str_request,URL);
  strcat(str_request,"\n");

  if ( (sdesc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1 ) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"HTTP_GET : Can not bind remote address %s:%s\n",IP_DST,PORT_DST);
    logmessage(debugmsg,getpid());
#endif
    free(str_request);
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
    sprintf(debugmsg,"HTTP_GET : Can not resolve remote host %s\n",IP_DST);
    logmessage(debugmsg,getpid());
#endif
    free(str_request);
    free(debugmsg);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  bzero(&adr_serv,long_inet);
  adr_serv.sin_family=ip_serv->h_addrtype;
  bcopy(ip_serv->h_addr, &adr_serv.sin_addr.s_addr,ip_serv->h_length);
  adr_serv.sin_port=htons(atoi(PORT_DST));

  if ( connect(sdesc, (struct sockaddr *)&adr_serv, long_inet) == -1) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"HTTP_GET : Can not connect remote host %s:%s\n",IP_DST,PORT_DST);
    logmessage(debugmsg,getpid());
#endif
    free(str_request);
    free(debugmsg);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  if (send(sdesc,str_request,strlen(str_request),0) == -1) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"HTTP_GET : Can not send data to remote host %s:%s\n",IP_DST,PORT_DST);
    logmessage(debugmsg,getpid());
#endif
    free(str_request);
    free(debugmsg);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  rcv_buffer_size=recv(sdesc,buffer,GET_BUFFER_LENGTH,0);
  if ( rcv_buffer_size == -1 ) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"HTTP_GET : Can not recieve data from remote host %s:%s\n",IP_DST,PORT_DST);
    logmessage(debugmsg,getpid());
#endif
    free(str_request);
    free(debugmsg);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  close(sdesc);
  free(str_request);
  free(debugmsg);
  return(rcv_buffer_size);
}

int HTTP_GET(char *IP_SRC,char *IP_DST,char *PORT_DST,char *URL,char MDResult[0x40])
{
  char *bufferget;
  int retcode=0;

  bufferget=(char *)malloc(GET_BUFFER_LENGTH);
  bzero(bufferget,GET_BUFFER_LENGTH);

  if ((retcode=GET(IP_SRC,IP_DST,PORT_DST,URL,bufferget))!=0) {
    MD5Data(bufferget,retcode,MDResult);
    free(bufferget);
    return(1);
  } else {
    free(bufferget);
    return(0);
  }
  free(bufferget);
}
