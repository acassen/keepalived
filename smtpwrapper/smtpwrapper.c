/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        SMTP WRAPPER connect to a specified smtp server and send mail
 *              using the smtp protocol according to the RFC 822. A non blocking 
 *              timeouted connection is used to handle smtp protocol.
 *  
 * Version:     $Id: smtpwrapper.c,v 0.2.6 2001/03/01 $
 * 
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *              
 * Changes:     
 *         Alexandre Cassen : 2001/03/01 : Initial release
 *
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#include "smtpwrapper.h"

int send_to(register int sdesc, fd_set wfds, struct timeval tv, char *buffer)
{
  select(sdesc+1,NULL,&wfds,NULL,&tv);
  if (!FD_ISSET(sdesc,&wfds)) {
#ifdef DEBUG
    logmessage("SMTP_SENDMAIL : Timeout writing data to smtp server\n");
#endif
    return(SOCKET_ERROR);
  }

  if (send(sdesc,buffer,strlen(buffer),0) == -1) {
#ifdef DEBUG
    logmessage("SMTP_SENDMAIL : Can not send data to remote smtp server\n");
#endif
    return(SOCKET_ERROR);
  }

  return(SOCKET_SUCCESS);
}

int read_to(register int sdesc, fd_set rfds, struct timeval tv, char *buffer)
{
  int rcv_buffer_size=0;
  long total_length=0;
  char *buffertmp;

  buffertmp=(char *)malloc(BUFFER_LENGTH);
  memset(buffertmp,0,BUFFER_LENGTH);

  select(sdesc+1,&rfds,NULL,NULL,&tv);
  if (!FD_ISSET(sdesc,&rfds)) {
#ifdef DEBUG
    logmessage("SMTP_SENDMAIL : Timeout receiving data from smtp server\n");
#endif
    free(buffertmp);
    return(SOCKET_ERROR);
  }

  while((rcv_buffer_size = read(sdesc,buffertmp,BUFFER_LENGTH)) != 0) {
    if ( rcv_buffer_size == -1 ) {
      if(errno == EAGAIN) goto end;
#ifdef DEBUG
      logmessage("SMTP_SENDMAIL : Can not recieve data from remote smtp server\n");
#endif
      free(buffertmp);
      return(SOCKET_ERROR);
    }
    memcpy(buffer+total_length,buffertmp,rcv_buffer_size);
    memset(buffertmp,0,BUFFER_LENGTH);
    total_length += rcv_buffer_size;
  }

end:
  free(buffertmp);
  return(SOCKET_SUCCESS);
}

int smtp_cmd(register int sdesc,fd_set rfds,fd_set wfds,struct timeval tv,char *smtpcmd,char *retcode)
{
  char *buffer;
  char *smtpcode;

  buffer=(char *)malloc(BUFFER_LENGTH);
  smtpcode=(char *)malloc(SMTP_ERROR_CODE_LENGTH);

  /* Sending SMTP command to remote smtp server */
  if (!send_to(sdesc,wfds,tv,smtpcmd)) {
#ifdef DEBUG
    logmessage("SMTP_SENDMAIL : Error sending EHLO.\n");
#endif
    free(buffer);
    free(smtpcode);
    return(SOCKET_ERROR);
  }

  /* Processing SMTP server reply */
  memset(buffer,0,BUFFER_LENGTH);
  if(!read_to(sdesc,rfds,tv,buffer)) {
#ifdef DEBUG
    logmessage("SMTP_SENDMAIL : Error receiving data from smtp server.\n");
#endif
    free(buffer);
    free(smtpcode);
    return(SOCKET_ERROR);
  }
  /* Look for response code */
  memset(smtpcode,0,SMTP_ERROR_CODE_LENGTH);
  memcpy(smtpcode,buffer,SMTP_ERROR_CODE_LENGTH-1);
  if(strcmp(smtpcode,retcode) != 0) {
#ifdef DEBUG
    logmessage(buffer);
#endif
    free(buffer);
    free(smtpcode);
    return(SOCKET_ERROR);
  }

  free(buffer);
  free(smtpcode);
  return(SOCKET_SUCCESS);
}

int SMTP_SENDMAIL(char *IP_DST, char *PORT_DST, char *from, char *to,char *subject,char *body,int ctimeout)
{
  register int sdesc;
  int long_inet;
  struct hostent *ip_serv;
  struct sockaddr_in adr_serv;
  struct linger li = { 0 };
  char *debugmsg;
  char *buffer;
  char *smtpcode;
  char *smtpcmd;
  struct timeval tv;
  fd_set rfds, wfds;
  int rc, flags;
  int arglen;

  debugmsg=(char *)malloc(LOGBUFFER_LENGTH);
  buffer=(char *)malloc(BUFFER_LENGTH);
  smtpcode=(char *)malloc(SMTP_ERROR_CODE_LENGTH);
  smtpcmd=(char *)malloc(SMTP_CMD_LENGTH);
  memset(buffer,0,BUFFER_LENGTH);
  memset(debugmsg,0,LOGBUFFER_LENGTH);
  memset(smtpcode,0,SMTP_ERROR_CODE_LENGTH);
  memset(smtpcmd,0,SMTP_CMD_LENGTH);

  if ( (sdesc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1 ) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"SMTP_SENDMAIL : Can not bind remote address %s:%s\n",IP_DST,PORT_DST);
    logmessage(debugmsg);
#endif
    free(debugmsg);
    free(buffer);
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
    sprintf(debugmsg,"SMTP_SENDMAIL : Can not resolve remote host %s\n",IP_DST);
    logmessage(debugmsg);
#endif
    free(debugmsg);
    free(buffer);
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
        sprintf(debugmsg,"SMTP_SENDMAIL : Connection timeout to %s:%s\n",IP_DST,PORT_DST);
        logmessage(debugmsg);
#endif
        break;
      case ECONNREFUSED:
#ifdef DEBUG
        memset(debugmsg,0,LOGBUFFER_LENGTH);
        sprintf(debugmsg,"SMTP_SENDMAIL : Connection refused to %s:%s\n",IP_DST,PORT_DST);
        logmessage(debugmsg);
#endif
        break;
      case ENETUNREACH:
#ifdef DEBUG
        memset(debugmsg,0,LOGBUFFER_LENGTH);
        sprintf(debugmsg,"SMTP_SENDMAIL : Network unreachable to %s:%s\n",IP_DST,PORT_DST);
        logmessage(debugmsg);
#endif
        break;
      case EINPROGRESS: // NONBLOCK socket connection in progress
        goto next;
      default:
#ifdef DEBUG
        memset(debugmsg,0,LOGBUFFER_LENGTH);
        sprintf(debugmsg,"SMTP_SENDMAIL : Network error [%s] to %s:%s\n",strerror(errno),IP_DST,PORT_DST);
        logmessage(debugmsg);
#endif
    }

    free(debugmsg);
    free(buffer);
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

  rc = select(sdesc+1,&rfds,NULL,NULL,&tv);
  if (!FD_ISSET(sdesc,&rfds)) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"SMTP_SENDMAIL : Timeout reading data to %s:%s\n",IP_DST,PORT_DST);
    logmessage(debugmsg);
#endif
    free(debugmsg);
    free(buffer);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  if (rc < 0) {
#ifdef DEBUG
    memset(debugmsg,0,LOGBUFFER_LENGTH);
    sprintf(debugmsg,"SMTP_SENDMAIL : Select returned descriptor error to %s:%s\n",IP_DST,PORT_DST);
    logmessage(debugmsg);
#endif
    free(debugmsg);
    free(buffer);
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
    sprintf(debugmsg,"SMTP_SENDMAIL : Connection failed to %s:%s (%s)\n",IP_DST,PORT_DST,strerror(rc));
    logmessage(debugmsg);
#endif
    free(debugmsg);
    free(buffer);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  /* Proceed the SMTP server reply */
  if(!read_to(sdesc,rfds,tv,buffer)) {
#ifdef DEBUG
    logmessage("SMTP_SENDMAIL : Error receiving data from smtp server.\n");
#endif
    free(debugmsg);
    free(buffer);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  /* Look for connect code */
  memset(smtpcode,0,SMTP_ERROR_CODE_LENGTH);
  memcpy(smtpcode,buffer,SMTP_ERROR_CODE_LENGTH-1);
  if(strcmp(smtpcode,SMTP_CONNECT) != 0) {
#ifdef DEBUG
    logmessage("Can not connect remote smtp server.\n");
#endif
  }

  /* Sending host identification */
  memset(buffer,0,BUFFER_LENGTH);
  if(gethostname(buffer,500)) {
#ifdef DEBUG
    logmessage("SMTP_SENDMAIL : Error resolving local hostname\n");
#endif
    free(debugmsg);
    free(buffer);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  /* Sending EHLO command to remote smtp server */
  memset(smtpcmd,0,SMTP_CMD_LENGTH);
  sprintf(smtpcmd,"EHLO %s\n",buffer);
  if(!smtp_cmd(sdesc,wfds,rfds,tv,smtpcmd,SMTP_EHLO)) {
#ifdef DEBUG
    logmessage("SMTP_SENDMAIL : Error sending EHLO.\n");
#endif
    free(debugmsg);
    free(buffer);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  /* Sending MAIL FROM command to remote smtp server */
  memset(smtpcmd,0,SMTP_CMD_LENGTH);
  sprintf(smtpcmd,"MAIL FROM:%s\n",from);
  if(!smtp_cmd(sdesc,wfds,rfds,tv,smtpcmd,SMTP_MAIL_FROM)) {
#ifdef DEBUG
    logmessage("SMTP_SENDMAIL : Error sending MAIL FROM.\n");
#endif
    free(debugmsg);
    free(buffer);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  /* Sending RCPT TO command to remote smtp server */
  memset(smtpcmd,0,SMTP_CMD_LENGTH);
  sprintf(smtpcmd,"RCPT TO:%s\n",to);
  if(!smtp_cmd(sdesc,wfds,rfds,tv,smtpcmd,SMTP_RCPT_TO)) {
#ifdef DEBUG
    logmessage("SMTP_SENDMAIL : Error sending RCPT TO.\n");
#endif
    free(debugmsg);
    free(buffer);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  /* Sending DATA command to remote smtp server */
  memset(smtpcmd,0,SMTP_CMD_LENGTH);
  sprintf(smtpcmd,"DATA\n");
  if(!smtp_cmd(sdesc,wfds,rfds,tv,smtpcmd,SMTP_DATA)) {
#ifdef DEBUG
    logmessage("SMTP_SENDMAIL : Error sending DATA.\n");
#endif
    free(debugmsg);
    free(buffer);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  /* Sending smtp header to remote smtp server */
  memset(smtpcmd,0,SMTP_CMD_LENGTH);
  sprintf(smtpcmd,"Subject: %s\nX-Mailer: Keepalived SmtpWrapper\n\n",subject);
  if(!send_to(sdesc,wfds,tv,smtpcmd)) {
#ifdef DEBUG
    logmessage("SMTP_SENDMAIL : Error sending smtp header.\n");
#endif
    free(debugmsg);
    free(buffer);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  /* Sending smtp body to remote smtp server */
  memset(smtpcmd,0,SMTP_CMD_LENGTH);
  sprintf(smtpcmd,"\n\n%s\n\n",body);
  if(!send_to(sdesc,wfds,tv,smtpcmd)) {
#ifdef DEBUG
    logmessage("SMTP_SENDMAIL : Error sending smtp body.\n");
#endif
    free(debugmsg);
    free(buffer);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  /* Sending DATA command to remote smtp server */
  memset(smtpcmd,0,SMTP_CMD_LENGTH);
  sprintf(smtpcmd,"\n.\n");
  if(!smtp_cmd(sdesc,wfds,rfds,tv,smtpcmd,SMTP_DOT)) {
#ifdef DEBUG
    logmessage("SMTP_SENDMAIL : Error sending trailing DOT.\n");
#endif
    free(debugmsg);
    free(buffer);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  /* Sending quit to remote smtp server */
  memset(smtpcmd,0,SMTP_CMD_LENGTH);
  sprintf(smtpcmd,"QUIT\n",body);
  if(!send_to(sdesc,wfds,tv,smtpcmd)) {
#ifdef DEBUG
    logmessage("SMTP_SENDMAIL : Error sending smtp quit.\n");
#endif
    free(debugmsg);
    free(buffer);
    close(sdesc);
    return(SOCKET_ERROR);
  }

  close(sdesc);
  free(debugmsg);
  free(buffer);
  return(SOCKET_SUCCESS);
}
