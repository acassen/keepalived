/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        Hash-related declarations (to break circular deps).
 *
 * Version:     hash.h 2013/07/22
 *
 * Authors:     Jan Pokorny, <jpokorny@redhat.com>
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
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef _HASH_H
#define _HASH_H

/* system includes */
#include <openssl/md5.h>
#ifdef FEAT_SHA1
#include <openssl/sha.h>
#endif

/* available hashes enumeration */
enum feat_hashes {
	hash_first,
	hash_md5 = hash_first,
#ifdef FEAT_SHA1
	hash_sha1,
#endif
	hash_guard,
	hash_default = hash_md5,
};

typedef union {
	MD5_CTX         	md5;
#ifdef FEAT_SHA1
	SHA_CTX         	sha;
#endif
	/* this is due to poor C standard/draft wording (wrapped):
	   https://groups.google.com/forum/#!msg/comp.lang.c/
	   1kQMGXhgn4I/0VBEYG_ji44J */
	char            	*dummy;
} hash_context_t;

typedef void (*hash_init_f)(hash_context_t *);
typedef void (*hash_update_f)(hash_context_t *, const void *, unsigned long);
typedef void (*hash_final_f)(unsigned char *, hash_context_t *);

typedef struct {
	hash_init_f		init;
	hash_update_f		update;
	hash_final_f		final;
	unsigned char		length;		/* length of the digest */
	const char		*id;		/* command-line handing + help */
	const char		*label;		/* final output */
} hash_t;

#endif
