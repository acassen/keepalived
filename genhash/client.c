/*
 * Soft:        Genhash compute MD5 digest from a HTTP get result. This
 *              program is use to compute hash value that you will add
 *              into the /etc/keepalived/keepalived.conf for HTTP_GET
 *              & SSL_GET keepalive method.
 *
 * Part:        Layer4 global functions.
 *
 * Version:     $Id: client.c,v 0.4.9 2001/11/28 11:50:23 acassen Exp $
 *
 * Authors:     Alexandre Cassen, <acassen@linux-vs.org>
 *              Jan Holmberg, <jan@artech.se>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#include "client.h"

int tcp_connect(int fd, char *host, int port)
{
  int long_inet = sizeof(struct sockaddr_in);
  struct sockaddr_in adr_serv;
  struct hostent *ip_serv;
  int arglen;
  struct timeval tv;
  fd_set wfds;
  int rc, val;

  /* Proceed remote hostname */
  memset(&ip_serv, 0, sizeof(struct hostent));
  if ((ip_serv = gethostbyname(host)) == NULL)
    return TCP_RESOLV_ERROR;

  /* Fill in connection structure */
  memset(&adr_serv, 0, long_inet);
  adr_serv.sin_family = AF_INET;
  adr_serv.sin_port = htons(port);
  adr_serv.sin_addr = *(struct in_addr*)ip_serv->h_addr;

  /* Set read/write socket nonblock */
  val = fcntl(fd, F_GETFL);
  fcntl(fd, F_SETFL, val | O_NONBLOCK);

  /* Connect the remote host */
  rc = connect(fd, (struct sockaddr *)&adr_serv, long_inet);
  if (rc == -1) {
    if (errno !=  EINPROGRESS) {
      rc = errno;
      return TCP_CONNECT_ERROR;
    }
  }

  /* Timeout settings */
  tv.tv_sec = SOCKET_TIMEOUT_READ;
  tv.tv_usec = 0;
  FD_ZERO(&wfds);
  FD_SET(fd, &wfds);

  rc = select(fd+1, NULL, &wfds, NULL, &tv);
  if (!FD_ISSET(fd, &wfds)) 
    return TCP_WRITE_TIMEOUT;

  if (rc <= 0) return TCP_SELECT_ERROR;

  rc = 0;
  arglen = sizeof(int);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &rc, &arglen) < 0)
    rc = errno;
  if (rc) return TCP_CONNECT_FAILED;

  /* Restore socket parameters */
  fcntl(fd, F_SETFL, val);

  return TCP_CONNECT_SUCCESS;
}

int tcp_send(int fd, char *request, int len)
{
  if (send(fd, request, len, 0) == -1)
    return TCP_SEND_ERROR;
  return 0;
}

int tcp_read_to(int fd)
{
  struct timeval tv;
  fd_set rfds;

  /* Timeout settings */
  tv.tv_sec = SOCKET_TIMEOUT_READ;
  tv.tv_usec = 0;
  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);

  /* attempt read data */
  select(fd+1, &rfds, NULL, NULL, &tv);
  if (!FD_ISSET(fd, &rfds)) 
    return TCP_READ_TIMEOUT;
  return 0;
}

int tcp_sock(void)
{
  int fd;
  struct sockaddr_in adr_local;

  if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) return (-1);
  memset(&adr_local, 0, sizeof(struct sockaddr_in));
  adr_local.sin_family = AF_INET;
  adr_local.sin_port = htons(0);
  adr_local.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(fd, (struct sockaddr *)&adr_local, sizeof(struct sockaddr_in))) return (-1);

  return(fd);
}
