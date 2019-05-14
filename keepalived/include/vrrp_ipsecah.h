/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_ipsecah.c include file.
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

#ifndef _VRRP_IPSEC_AH_H
#define _VRRP_IPSEC_AH_H

#include <sys/types.h>
#include <stdint.h>
#include <openssl/md5.h>
#include <stdbool.h>

/* Predefined values */
#define HMAC_MD5_TRUNC 0x0C	/* MD5 digest truncate value : 96-bit
				   -- rfc2403.2 & rfc2104.5 */
#define IPSEC_AH_PLEN  0x04	/* Const for a 96-bit auth value :
				   Computed in 32-bit words minus 2
				   => (HMAC_MD5_TRUNC*8+3*32)/32 - 2
				   -- rfc2402.2.2 */

typedef struct _ipsec_ah {				/* rfc2402.2 */
	uint8_t			next_header;	/* Next header field */
	uint8_t			payload_len;	/* Payload Lenght */
	uint16_t		reserved;	/* Reserved field */
	uint32_t		spi;		/* Security Parameter Index */
	uint32_t		seq_number;	/* Sequence number */
	char			auth_data[HMAC_MD5_TRUNC];
						/* Authentication data 128-bit MD5 digest trucated */
} ipsec_ah_t;

typedef struct _seq_counter {
	bool			cycle;
	uint32_t		seq_number;
} seq_counter_t;

extern void hmac_md5(const unsigned char *, size_t, const unsigned char *, size_t, const unsigned char *, size_t, unsigned char *);

#endif
