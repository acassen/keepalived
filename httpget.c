/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        HTTP GET CHECK. Perform an http get query to a specified 
 *              url, compute a MD5 over this result and match it to the
 *              expected value.
 *  
 * Version:     $Id: httpget.c,v 0.2.6 2001/03/01 $
 * 
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *              
 * Changes:     
 *              Alexandre Cassen : 2001/03/01 :
 *               <+> Use a non blocking timeouted tcp connection.
 *               <+> Adding support for multi-url. Can perform a HTTP GET
 *                   over multiple url on the same tcp service (usefull for
 *                   HTTP server owning multiple applications servers).
 *               <+> Adding HTTP GET retry.
 *               <+> Remove the libmd call, use the L. Peter Deutsch
 *                   independant md5 implementation.
 *               <+> Parse the whole HTTP get reply, computing a md5sum
 *                   over the html response part.
 *               <+> Adding delay support between HTTP get retry.
 *
 *              Alexandre Cassen : Initial release : 2000/12/09
 *              
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#include "httpget.h"

char *extract_html(char *buffer, int size_buffer)
{
  char *end=buffer+size_buffer;

  while ( buffer < end && 
          !(*buffer++ == '\n' && 
            (*buffer == '\n' || (*buffer ++ == '\r' && *buffer =='\n'))));

  if (*buffer == '\n') return buffer+1;
  return NULL;
}

int GET(char *IP_DST, char *PORT_DST, char *URL, char *buffer,int ctimeout)
{
  register int sdesc;
  int long_inet;
  int rcv_buffer_size=0;
  long total_length=0;
  char *str_request;
  struct hostent *ip_serv;
  struct sockaddr_in adr_serv;
  struct linger li = { 0 };
  char *debugmsg;
  char *buffertmp;
  struct timeval tv;
  fd_set rfds, wfds;
  int rc, flags;
  int arglen;

  debugmsg=(char *)malloc(LOGBUFFER_LENGTH);
  buffertmp=(char *)malloc(GET_BUFFER_LENGTH);
  str_request=(char *)malloc(GET_REQUEST_BUFFER_LENGTH);
  memset(buffertmp,0,GET_BUFFER_LENGTH);
  memset(debugmsg,0,LOGBUFFER_LENGTH);
  memset(str_request,0,GET_REQUEST_BUFFER_LENGTH);

  sprintf(str_request,GETCMD,URL);

  if ( (sdesc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1 ) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"HTTP_GET : Can not bind remote address %s:%s\n",IP_DST,PORT_DST);
    logmessage(debugmsg);
#endif
    free(str_request);
    free(debugmsg);
    free(buffertmp);
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
    logmessage(debugmsg);
#endif
    free(str_request);
    free(debugmsg);
    free(buffertmp);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  memset(&adr_serv,0,long_inet);
  adr_serv.sin_family=ip_serv->h_addrtype;
  bcopy(ip_serv->h_addr, &adr_serv.sin_addr.s_addr,ip_serv->h_length);
  adr_serv.sin_port=htons(atoi(PORT_DST));

  /* Set read/write socket timeout */
  flags=fcntl(sdesc, F_GETFL);
  fcntl(sdesc, F_SETFL, flags | O_NONBLOCK);

  /* Connect the remote host */
  if ( (rc=connect(sdesc, (struct sockaddr *)&adr_serv, long_inet)) == -1) {
    switch (errno) {
      case ETIMEDOUT:
      case EINTR:
      case EHOSTUNREACH:
#ifdef DEBUG
        memset(debugmsg,0,LOGBUFFER_LENGTH);
        sprintf(debugmsg,"HTTP_GET : Connection timeout to %s:%s\n",IP_DST,PORT_DST);
        logmessage(debugmsg);
#endif
        break;
      case ECONNREFUSED:
#ifdef DEBUG
        memset(debugmsg,0,LOGBUFFER_LENGTH);
        sprintf(debugmsg,"HTTP_GET : Connection refused to %s:%s\n",IP_DST,PORT_DST);
        logmessage(debugmsg);
#endif
        break;
      case ENETUNREACH:
#ifdef DEBUG
        memset(debugmsg,0,LOGBUFFER_LENGTH);
        sprintf(debugmsg,"HTTP_GET : Network unreachable to %s:%s\n",IP_DST,PORT_DST);
        logmessage(debugmsg);
#endif
        break;
      case EINPROGRESS: // NONBLOCK socket connection in progress
        goto next;
      default:
#ifdef DEBUG
        memset(debugmsg,0,LOGBUFFER_LENGTH);
        sprintf(debugmsg,"HTTP_GET : Network error [%s] to %s:%s\n",strerror(errno),IP_DST,PORT_DST);
        logmessage(debugmsg);
#endif
    }

    free(str_request);
    free(debugmsg);
    free(buffertmp);
    close(sdesc);
    return(SOCKET_ERROR);
  }

next:
  /* Timeout settings */
  tv.tv_sec=ctimeout;
  tv.tv_usec=0;
  FD_ZERO(&rfds);
  FD_ZERO(&wfds);
  FD_SET(sdesc,&rfds);
  FD_SET(sdesc,&wfds);

  rc = select(sdesc+1,NULL,&wfds,NULL,&tv);
  if (!FD_ISSET(sdesc,&wfds)) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"HTTP_GET : Timeout writing data to %s:%s\n",IP_DST,PORT_DST);
    logmessage(debugmsg);
#endif
    free(str_request);
    free(debugmsg);
    free(buffertmp);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  if (rc < 0) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"HTTP_GET : Select returned descriptor error to %s:%s\n",IP_DST,PORT_DST);
    logmessage(debugmsg);
#endif
    free(str_request);
    free(debugmsg);
    free(buffertmp);
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
    sprintf(debugmsg,"HTTP_GET : Connection failed to %s:%s (%s)\n",IP_DST,PORT_DST,strerror(rc));
    logmessage(debugmsg);
#endif
    free(str_request);
    free(debugmsg);
    free(buffertmp);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  /* Sending the http get request */
  if (send(sdesc,str_request,strlen(str_request),0) == -1) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"HTTP_GET : Can not send data to remote host %s:%s\n",IP_DST,PORT_DST);
    logmessage(debugmsg);
#endif
    free(str_request);
    free(debugmsg);
    free(buffertmp);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  /* Proceed the HTTP server reply */
  select(sdesc+1,&rfds,NULL,NULL,&tv);
  if (!FD_ISSET(sdesc,&rfds)) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"HTTP_GET : Timeout reading data from %s:%s\n",IP_DST,PORT_DST);
    logmessage(debugmsg);
#endif
    free(str_request);
    free(buffertmp);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  while((rcv_buffer_size = read(sdesc,buffertmp,GET_BUFFER_LENGTH)) != 0) {
    if ( rcv_buffer_size == -1 ) {
      if(errno == EAGAIN) goto end;
#ifdef DEBUG
      memset(debugmsg,0,LOGBUFFER_LENGTH);
      sprintf(debugmsg,"HTTP_GET : Can not recieve data from remote host %s:%s\n",IP_DST,PORT_DST);
      logmessage(debugmsg);
#endif
      free(str_request);
      free(debugmsg);
      free(buffertmp);
      close(sdesc);
      return(SOCKET_ERROR);
    }
    memcpy(buffer+total_length,buffertmp,rcv_buffer_size);
    memset(buffertmp,0,GET_BUFFER_LENGTH);
    total_length += rcv_buffer_size;
  }

end:
  close(sdesc);
  free(str_request);
  free(debugmsg);
  free(buffertmp);
  return(total_length);
}

int HTTP_GET(char *IP_DST,char *PORT_DST,char *URL,char *MDResult,int ctimeout,int getretry,int rdelay)
{
  char *buffer_http;
  char *buffer_html;
  char *debugmsg;
  md5_state_t state;
  md5_byte_t digest[16];
  int buffer_http_size=0;
  int split_offset=0;
  int nb_retry=0;
  int di;


  buffer_http=(char *)malloc(GET_BUFFER_LENGTH);
  debugmsg=(char *)malloc(LOGBUFFER_LENGTH);

  while (nb_retry < getretry) {
    sleep(rdelay);
    memset(buffer_http,0,GET_BUFFER_LENGTH);

    buffer_http_size=GET(IP_DST,PORT_DST,URL,buffer_http,ctimeout);
    buffer_html=extract_html(buffer_http,buffer_http_size);

    if (buffer_http_size > 0) {
      if ((buffer_http_size-(buffer_html-buffer_http)) == 0) {
#ifdef DEBUG
        memset(debugmsg,0,LOGBUFFER_LENGTH);
        sprintf(debugmsg,"HTTP_GET : No html buffer received from %s:%s. Retry\n",IP_DST,PORT_DST);
        logmessage(debugmsg);
#endif
        nb_retry++;
      } else {
        md5_init(&state);
        md5_append(&state, buffer_html,buffer_http_size-(buffer_html-buffer_http));
        md5_finish(&state,digest);
        for (di=0; di < 16; ++di)
          sprintf(MDResult+2*di,"%02x",digest[di]);
        free(debugmsg);
        free(buffer_http);
        return(1);
      }
    } else {
      free(debugmsg);
      free(buffer_http);
      return(0);
    }
  }

#ifdef DEBUG
  memset(debugmsg,0,LOGBUFFER_LENGTH);
  sprintf(debugmsg,"HTTP_GET : No html buffer received from %s:%s after %d retry\n",IP_DST,PORT_DST,getretry);
  logmessage(debugmsg);
#endif

  free(debugmsg);
  free(buffer_http);
  return(0);
}
