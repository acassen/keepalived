/*
 * Soft:        Genhash compute MD5 digest from a HTTP get result. This
 *              program is use to compute hash value that you will add
 *              into the /etc/keepalived/keepalived.conf for HTTP_GET
 *              & SSL_GET keepalive method.
 *
 * Part:        common.c include file.
 *
 * Version:     $Id: common.h,v 0.4.9 2001/11/28 11:50:23 acassen Exp $
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

#ifndef _COMMON_H
#define _COMMON_H

/* System includes */
#include <string.h>
#include <signal.h>
#include <openssl/ssl.h>

/* prototypes */
extern int berr_exit(char *string);
extern int err_exit(char *string);
extern SSL_CTX *initialize_ctx(char *keyfile, char *password, char *cafile);
extern void destroy_ctx(SSL_CTX *ctx);

#ifndef ALLOW_OLD_VERSIONS
#if(OPENSSL_VERSION_NUMBER < 0x00905100L)
#error "Must use OpenSSL 0.9.6 or later"
#endif
#endif

#endif
