/* 
 * Soft:        Genhash compute MD5 digest from a HTTP get result. This
 *              program is use to compute hash value that you will add
 *              into the /etc/keepalived/keepalived.conf for the 
 *              HTTP_GET_CHECK.
 *  
 * Version:     $Id: keepalived.c,v 0.3.0 2001/02/10 $
 * 
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *
 * Changes:
 *              Alexandre Cassen : 2001/03/27 :
 *               <+> Use non blocking socket.
 *
 *              Alexandre Cassen : 2000/12/09      Initial release
 *               
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */     

#include "genhash.h"

void print_buffer(int count, char *buff)
{
  int i,j,c;
  int printnext=1;

  if(count) {
    if(count%16)
      c=count+(16-count%16);
    else c=count;
  } else
    c=count;

  for(i=0;i<c;i++) {
    if(printnext) { 
      printnext--;
      printf("%.4x ",i&0xffff);
    }
    if(i<count)
      printf("%3.2x",buff[i]&0xff);
    else
      printf("   ");
    if(!((i+1)%8)) {
      if((i+1)%16)
        printf(" -");
      else {
        printf("   ");
        for(j=i-15;j<=i;j++)
          if(j<count) {
            if( (buff[j]&0xff) >= 0x20 && (buff[j]&0xff)<=0x7e)
              printf("%c",buff[j]&0xff);
            else printf(".");
          } else printf(" ");
        printf("\n"); printnext=1;
      }
    }
  }
}

char *extract_html(char *buffer, int size_buffer)
{
  char *end=buffer+size_buffer;

  while ( buffer < end && !(*buffer++ == '\n' &&
                          (*buffer == '\n' || (*buffer++ == '\r' && *buffer =='\n'))));

  if (*buffer == '\n') return buffer+1;
  return NULL;
}

int new_sock(int type)
{
  int sd;
  struct sockaddr_in adr_local;
  if ( (sd = socket(AF_INET, type, 0)) == -1 ) return (-1);

  bzero(&adr_local, sizeof(struct sockaddr_in));
  adr_local.sin_family = AF_INET;
  adr_local.sin_port = htons(0);
  adr_local.sin_addr.s_addr = htonl(INADDR_ANY);

  if ( bind(sd, (struct sockaddr *)&adr_local, sizeof(struct sockaddr_in)) ) return (-1);

  return (sd);
}

int HTTP_GET(char *IP_DST, unsigned short int PORT_DST, char *URL, char *buffer)
{
  register int sdesc;
  int long_inet;
  int rcv_buffer_size=0;
  long total_length=0;
  char *str_request;
  char *buffertmp;
  struct hostent *ip_serv;
  struct sockaddr_in adr_serv;
  struct timeval tv;
  fd_set rfds, wfds;
  int rc,val;
  int arglen;
 
  str_request=(char *)malloc(GET_BUFFER_LENGTH);
  buffertmp=(char *)malloc(RCV_BUFFER_LENGTH);
  memset(buffertmp,0,RCV_BUFFER_LENGTH);

  sprintf(str_request,GETCMD,URL);

  if ( (sdesc=new_sock(SOCK_STREAM)) == -1 ) {
    printf("-[ Can not bind remote address ]-\n");
    free(str_request);
    free(buffertmp);
    return(ERROR_SOCKET);
  }

  long_inet = sizeof(struct sockaddr_in);

  if ( (ip_serv=gethostbyname(IP_DST)) == NULL) {
    printf("-[ Can not resolve remote host ]-\n");
    free(str_request);
    free(buffertmp);
    close(sdesc);
    return(ERROR_SOCKET);
  }

  bzero(&adr_serv,long_inet);
  adr_serv.sin_family=ip_serv->h_addrtype;
  bcopy(ip_serv->h_addr, &adr_serv.sin_addr.s_addr,ip_serv->h_length);
  adr_serv.sin_port=htons(PORT_DST);

  /* Set read/write socket timeout */
  val=fcntl(sdesc, F_GETFL);
  fcntl(sdesc, F_SETFL, val | O_NONBLOCK);

  /* Connect the remote host */
  if ( (rc=connect(sdesc, (struct sockaddr *)&adr_serv, long_inet)) == -1 ) {
    switch (errno) {
      case ETIMEDOUT:
      case EINTR:
      case EHOSTUNREACH:
        printf("-[ Connect error : Timeout ]-\n");
        break;
      case ECONNREFUSED:
        printf("-[ Connect error : Connectiono refused ]-\n");
        break;
      case ENETUNREACH:
        printf("-[ Connect error : Network unreachable ]-\n");
        break;
      case EINPROGRESS:
        printf("-[ NONBLOCK socket connection in progress ]-\n");
        goto next;
      default:
        printf("-[ Connect error : Error code %d (%s) ]-\n",errno,strerror(errno));
    }

    free(str_request);
    free(buffertmp);
    close(sdesc);
    return(ERROR_SOCKET);
  }

next:
  /* Timeout settings */
  tv.tv_sec=SOCKET_TIMEOUT_READ;
  tv.tv_usec=0;
  FD_ZERO(&rfds);
  FD_ZERO(&wfds);
  FD_SET(sdesc,&rfds);
  FD_SET(sdesc,&wfds);

  rc = select(sdesc+1,NULL,&wfds,NULL,&tv);
  if (!FD_ISSET(sdesc,&wfds)) {
    printf("-[ Timeout writing data ]-\n");
    free(str_request);
    free(buffertmp);
    close(sdesc);
    return(ERROR_SOCKET);
  }

  if (rc <= 0) {
    printf("-[ select() bad returned descriptor ]-\n");
    free(str_request);
    free(buffertmp);
    close(sdesc);
    return(ERROR_SOCKET);
  }

  rc = 0;
  arglen=sizeof(int);
  if (getsockopt(sdesc,SOL_SOCKET,SO_ERROR,&rc,&arglen) < 0)
    rc = errno;

  if (rc) {
    printf("-[ Connection failed - error : %d (%s) ]-\n",rc,strerror(rc));
    free(str_request);
    free(buffertmp);
    close(sdesc);
    return(ERROR_SOCKET);
  }

  if (send(sdesc,str_request,strlen(str_request),0) == -1) {
    printf("-[ Can not send data to remote host ]-\n");
    free(str_request);
    free(buffertmp);
    close(sdesc);
    return(ERROR_SOCKET);
  }

  /* Proceed the HTTP server reply */
  select(sdesc+1,&rfds,NULL,NULL,&tv);
  if (!FD_ISSET(sdesc,&rfds)) {
    printf("-[ Timeout reading data ]-\n");
    free(str_request);
    free(buffertmp);
    close(sdesc);
    return(ERROR_SOCKET);
  }

  while((rcv_buffer_size = read(sdesc,buffertmp,RCV_BUFFER_LENGTH)) != 0) {
    if (rcv_buffer_size == -1) {
      if(errno == EAGAIN) goto end;
      free(str_request);
      free(buffertmp);
      close(sdesc);
      return(ERROR_SOCKET);
    }
    printf("-[ Reading data from remote host ]-\n");
    memcpy(buffer+total_length,buffertmp,rcv_buffer_size);
    memset(buffertmp,0,RCV_BUFFER_LENGTH);
    total_length += rcv_buffer_size;
  }

end:
  close(sdesc);
  free(str_request);
  free(buffertmp);
  return(total_length);
}


int main(int argc, char **argv)
{
  char *buffer_http;
  char *buffer_html;
  int buffer_http_size=0;
  char *MDResult;
  md5_state_t state;
  md5_byte_t digest[16];
  int di;

  printf(PROG" v"VERSION"\n");
  if (argc < 4) {
      printf("Usage: %s <IP address> <TCP port> <url path>\n", argv[0]);
      return(0);
  }

  buffer_http=(char *)malloc(RCV_BUFFER_LENGTH);
  MDResult=(char *)malloc(16*2*sizeof(char *));
  memset(buffer_http,0,RCV_BUFFER_LENGTH);
  memset(MDResult,0,16*2*sizeof(char *));

  buffer_http_size=HTTP_GET(argv[1],atoi(argv[2]),argv[3],buffer_http);
  buffer_html=extract_html(buffer_http,buffer_http_size);

  if(buffer_http_size > 0) {
    printf("---------------------------[ Received Buffer ]----------------------------\n");
    printf("%s\n",buffer_http);

    printf("--------------------------[ HTTP Header Buffer ]--------------------------\n");
    print_buffer(buffer_html-buffer_http,buffer_http);

    printf("------------------------------[ HTML Buffer ]-----------------------------\n");
    print_buffer(buffer_http_size-(buffer_html-buffer_http),buffer_html);

    printf("----------------------------[ HTML MD5 resulting ]------------------------\n");
    md5_init(&state);
    md5_append(&state, buffer_html,buffer_http_size-(buffer_html-buffer_http));
    md5_finish(&state,digest);

    for (di=0; di < 16; ++di)
      sprintf(MDResult+2*di,"%02x",digest[di]);

    printf("MD5 Digest : %s\n",MDResult);
  } else {
    printf("No buffer returned...\n");
  }

  free(MDResult);
  free(buffer_http);
  return(1);
}
