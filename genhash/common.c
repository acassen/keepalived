/*
 * Soft:        Genhash compute MD5 digest from a HTTP get result. This
 *              program is use to compute hash value that you will add
 *              into the /etc/keepalived/keepalived.conf for HTTP_GET
 *              & SSL_GET keepalive method.
 *
 * Part:        Common SSL functions.
 *
 * Version:     $Id: common.c,v 0.4.9 2001/11/28 11:50:23 acassen Exp $
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

#include <openssl/err.h>
#include "common.h"

static BIO *bio_err = 0;
static char *pass;

/* A simple error and exit routine*/
int err_exit(char *string)
{
  fprintf(stderr, "%s\n", string);
  exit(0);
}

/* Print SSL errors and exit*/
int berr_exit(char *string)
{
  BIO_printf(bio_err, "%s\n", string);
  ERR_print_errors(bio_err);
  exit(0);
}

/*The password code is not thread safe*/
static int password_cb(char *buf, int num, int rwflag, void *userdata)
{
  if (num < strlen(pass)+1)
    return(0);

  strcpy(buf, pass);
  return(strlen(pass));
}

static void sigpipe_handle(int x) {
}

/* SSL context initializer */
SSL_CTX *initialize_ctx(char *keyfile, char *password, char *cafile)
{
  SSL_METHOD *meth;
  SSL_CTX *ctx;
    
  if (!bio_err){
    /* Global system initialization*/
    SSL_library_init();
    SSL_load_error_strings();
      
    /* An error write context */
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
  }

  /* Set up a SIGPIPE handler */
  signal(SIGPIPE, sigpipe_handle);
    
  /* Create our context*/
  meth = SSLv23_method();
  ctx = SSL_CTX_new(meth);

  /* Load our keys and certificates*/
  if (keyfile)
    if(!(SSL_CTX_use_certificate_chain_file(ctx, keyfile)))
      berr_exit("Can't read certificate file");

  if (password) {
    pass = password;
    SSL_CTX_set_default_passwd_cb(ctx, password_cb);
  }
 
  if (keyfile)
    if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM)))
      berr_exit("Can't read key file");

  /* Load the CAs we trust*/
  if (cafile)
    if(!(SSL_CTX_load_verify_locations(ctx, cafile, 0)))
      berr_exit("Can't read CA list");
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
  SSL_CTX_set_verify_depth(ctx,1);
#endif

  return ctx;
}
     
void destroy_ctx(SSL_CTX *ctx)
{
  SSL_CTX_free(ctx);
}
