/*
 * Soft:        Genhash compute MD5 digest from a HTTP get result. This
 *              program is use to compute hash value that you will add
 *              into the /etc/keepalived/keepalived.conf for HTTP_GET
 *              & SSL_GET keepalive method.
 *
 * Part:        main.c include file.
 *
 * Version:     $Id: main.h,v 0.4.9 2001/11/28 11:50:23 acassen Exp $
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

#ifndef _MAIN_H
#define _MAIN_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/md5.h>
#include <popt.h>

/* Build version */
#define PROG    "genhash"
#define VERSION "0.6.2 (06/14, 2002)"

/* HTTP/HTTPS GET command */
#define REQUEST_TEMPLATE "GET %s HTTP/1.0\r\n" \
                         "User-Agent:KeepAliveClient\r\n" \
                         "Host: %s:%d\r\n\r\n"

/* HTTP/HTTPS request structure */
typedef struct {
  char *host;
  char *buffer;
  int error;
  int max;
  int len;
  char *url;
  unsigned short int port;
  int fd;
  int ssl;
  char *keyfile;
  char *password;
  char *virtualhost;
  char *cafile;
} REQ;

/* Output delimiters */
#define DELIM_BEGIN "-----------------------["
#define DELIM_END   "]-----------------------\n"
#define HTTP_HEADER_HEXA  DELIM_BEGIN"    HTTP Header Buffer    "DELIM_END
#define HTTP_HEADER_ASCII DELIM_BEGIN" HTTP Header Ascii Buffer "DELIM_END
#define HTML_HEADER_HEXA  DELIM_BEGIN"       HTML Buffer        "DELIM_END
#define HTML_MD5          DELIM_BEGIN"    HTML MD5 resulting    "DELIM_END
#define HTML_MD5_FINAL    DELIM_BEGIN" HTML MD5 final resulting "DELIM_END

/* Data buffer length description */
#define RCV_BUFFER_LENGTH   512
#define BUFSIZE             1024

/* Command line error handling */
#define CMD_LINE_ERROR   0
#define CMD_LINE_SUCCESS 1

#endif
