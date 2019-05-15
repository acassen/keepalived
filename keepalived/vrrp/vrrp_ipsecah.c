/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        IPSEC AH implementation according to RFC 2402. Processing
 *              authentication data encryption using HMAC MD5 according to
 *              RFCs 2085 & 2104.
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <openssl/md5.h>
#include <string.h>

#include "vrrp_ipsecah.h"

#define	BLOCK_SIZE	64

/* hmac_md5 computation according to the RFCs 2085 & 2104 */
void
hmac_md5(const unsigned char *buffer1, size_t buffer1_len, const unsigned char *buffer2, size_t buffer2_len,
	 const unsigned char *key, size_t key_len, unsigned char *digest)
{
	MD5_CTX context;
	unsigned char k_ipad[BLOCK_SIZE+1];	/* inner padding - key XORd with ipad */
	unsigned char k_opad[BLOCK_SIZE+1];	/* outer padding - key XORd with opad */
	unsigned char tk[MD5_DIGEST_LENGTH];
	int i;

	/* Initialize data */
	memset(k_ipad, 0, sizeof (k_ipad));
	memset(k_opad, 0, sizeof (k_opad));
	memset(tk, 0, sizeof (tk));

	/* If the key is longer than 64 bytes => set it to key=MD5(key) */
	if (key_len > BLOCK_SIZE) {
		MD5_CTX tctx;

		/* Compute the MD5 digest */
		MD5_Init(&tctx);
		MD5_Update(&tctx, key, key_len);
		MD5_Final(tk, &tctx);

		key = tk;
		key_len = MD5_DIGEST_LENGTH;
	}

	/* The global HMAC_MD5 algo looks like (rfc2085.2.2) :
	   MD5(K XOR opad, MD5(K XOR ipad, buffer))
	   K : an n byte key
	   ipad : byte 0x36 repeated 64 times
	   opad : byte 0x5c repeated 64 times
	   buffer : buffer being protected
	 */
	memset(k_ipad, 0, sizeof (k_ipad));
	memset(k_opad, 0, sizeof (k_opad));
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);

	/* XOR key with ipad and opad values */
	for (i = 0; i < BLOCK_SIZE; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/* Compute inner MD5 */
	MD5_Init(&context);				/* Init context for 1st pass */
	MD5_Update(&context, k_ipad, BLOCK_SIZE);	/* start with inner pad */
	MD5_Update(&context, buffer1, buffer1_len);	/* next with buffer datagram */
	if (buffer2)
		MD5_Update(&context, buffer2, buffer2_len); /* next with buffer datagram */
	MD5_Final(digest, &context);			/* Finish 1st pass */

	/* Compute outer MD5 */
	MD5_Init(&context);				/* Init context for 2nd pass */
	MD5_Update(&context, k_opad, BLOCK_SIZE);	/* start with inner pad */
	MD5_Update(&context, digest, MD5_DIGEST_LENGTH); /* next result of 1st pass */
	MD5_Final(digest, &context);			/* Finish 2nd pass */
}
