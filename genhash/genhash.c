/* 
 * Soft:        Genhash compute MD5 digest from a HTTP get result. This
 *              program is use to compute hash value that you will add
 *              into the /etc/keepalived/keepalived.conf for the 
 *              HTTP_GET_CHECK.
 *  
 * Version:     $Id: keepalived.c,v 0.2.0 2000/12/09 $
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
  char *str_request;
  struct hostent *ip_serv;
  struct sockaddr_in adr_serv;
 
  str_request=(char *)malloc(GET_BUFFER_LENGTH);
  strcpy(str_request,"GET ");
  strcat(str_request,URL);
  strcat(str_request,"\n");

  if ( (sdesc=new_sock(SOCK_STREAM)) == -1 ) {
    printf("Can not bind remote address\n");
    return(ERROR_SOCKET);
  }

  long_inet = sizeof(struct sockaddr_in);

  if ( (ip_serv=gethostbyname(IP_DST)) == NULL) {
    printf("Can not resolve remote host\n");
    return(ERROR_SOCKET);
  }

  bzero(&adr_serv,long_inet);
  adr_serv.sin_family=ip_serv->h_addrtype;
  bcopy(ip_serv->h_addr, &adr_serv.sin_addr.s_addr,ip_serv->h_length);
  adr_serv.sin_port=htons(PORT_DST);

  if ( connect(sdesc, (struct sockaddr *)&adr_serv, long_inet) == -1) {
    printf("Can not connect remote host\n");
    return(ERROR_SOCKET);
  }

  if (send(sdesc,str_request,strlen(str_request),0) == -1) {
    printf("Can not send data to remote host\n");
    return(ERROR_SOCKET);
  }

  rcv_buffer_size=recv(sdesc,buffer,RCV_BUFFER_LENGTH,0);
  if ( rcv_buffer_size == -1 ) {
    printf("Can not recieve data from remote host\n");
    return(ERROR_SOCKET);
  }

  close(sdesc);
  free(str_request);
  return(rcv_buffer_size);
}

int main(int argc, char **argv)
{
  char *buffer_http;
  int retcode=0;
  char MDResult[0x40];

  printf(PROG" v"VERSION"\n");
  if (argc < 4) {
      printf("Usage: %s <IP address> <TCP port> <url path>\n", argv[0]);
      return 0;
  }

  buffer_http=(char *)malloc(RCV_BUFFER_LENGTH);

  retcode=HTTP_GET(argv[1],atoi(argv[2]),argv[3],buffer_http);

  if(retcode > 0) {
    printf("\n----[ Buffer Text representation ]----\n");
    printf("%s\n",buffer_http);

    printf("\n----[ Buffer Hexa representation ]----\n");
    printf("Buffer length : %d\n",retcode);
    if(retcode!=0) print_buffer(retcode,buffer_http);

    printf("\n----[ MD5 resulting ]----\n");
    MD5Data(buffer_http,retcode,MDResult);
    printf("MD5 256 bits Digest : %s\n",MDResult);
  } else {
    printf("No buffer returned...\n");
  }

  free(buffer_http);
  return 1;
}
