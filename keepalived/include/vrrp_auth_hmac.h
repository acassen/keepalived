/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_auth_hmac.c include file. Modern VRRP advert
 *              authentication extension providing origin authentication,
 *              integrity and replay protection for unicast and multicast.
 *
 * Author:      Alexandre Cassen, <acassen@gmail.com>
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
 * Copyright (C) 2001-2024 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_AUTH_HMAC_H
#define _VRRP_AUTH_HMAC_H

#include "config.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "list_head.h"
#include "sockaddr.h"

/* Extension scheme identifiers carried in the trailer ext_type field */
#define VRRP_AUTH_HMAC_TYPE_SHA256	1	/* HMAC SHA256 truncated to 128 bits */
#define VRRP_AUTH_HMAC_LEN		16	/* truncated HMAC length */

/* Key material bounds, the 32 byte floor keeps a 128 bit margin under quantum search */
#define VRRP_AUTH_HMAC_KEY_MIN		32
#define VRRP_AUTH_HMAC_KEY_MAX		64

/* Freshness window bounds, seconds */
#define VRRP_AUTH_HMAC_WINDOW_MIN	1
#define VRRP_AUTH_HMAC_WINDOW_MAX	300
#define VRRP_AUTH_HMAC_WINDOW_FLOOR	5	/* lower bound when derived from advert interval */

/*
 * Per instance multicast sender replay slots. Concurrent legitimate
 * senders per VRID only occur during contention so a few slots suffice.
 */
#define VRRP_AUTH_HMAC_MCAST_SENDERS	4

/* Pseudo header bound into the HMAC: family, version, vrid, zero, address */
#define VRRP_AUTH_HMAC_PSEUDO_LEN	20

/*
 * Authenticated trailer appended after the VRRP PDU. The 64 bit sequence is
 * split into seconds, subseconds and counter, keeping the 28 byte layout.
 */
typedef struct _vrrp_auth_ext {
	uint8_t			ext_type;	/* scheme identifier */
	uint8_t			key_id;		/* selects the verifying key */
	uint16_t		reserved;	/* zero on send */
	uint32_t		sec;		/* UTC seconds since the Unix epoch, network order */
	uint16_t		subsec;		/* binary fraction of a second, network order */
	uint16_t		ctr;		/* tie breaker within one timestamp, network order */
	uint8_t			hmac[VRRP_AUTH_HMAC_LEN];
} vrrp_auth_ext_t;

/* Per sender anti replay high water mark */
typedef struct _vrrp_replay_state {
	bool			valid;
	uint64_t		seq;		/* last accepted 64 bit sequence */
} vrrp_replay_state_t;

/*
 * Multicast sender table entry. Bound to a source address since multicast
 * has no configured peer list to anchor the replay state on.
 */
typedef struct _vrrp_mcast_sender {
	sockaddr_t		addr;
	vrrp_replay_state_t	replay;
	unsigned		last_used;	/* LRU rank, zero means empty */
} vrrp_mcast_sender_t;

/* A configured key, addressed by id for live rotation */
typedef struct _vrrp_auth_key {
	uint8_t			id;
	uint8_t			len;
	uint8_t			data[VRRP_AUTH_HMAC_KEY_MAX];

	list_head_t		e_list;
} vrrp_auth_key_t;

/* Per instance authentication state, allocated only when configured */
typedef struct _vrrp_auth_hmac {
	list_head_t		keys;		/* vrrp_auth_key_t */
	uint8_t			active_key;	/* key id used when sending */
	uint8_t			ext_type;	/* scheme used when sending */
	bool			enforce;	/* false accepts legacy adverts during migration */
	bool			anti_replay_time;	/* true enforces the freshness window */
	unsigned		time_window;	/* freshness window, seconds */

	/* send sequence state, the last 64 bit sequence emitted */
	uint64_t		send_seq;

	/* multicast receive replay state */
	unsigned		lru_clock;	/* monotonic rank source for eviction */
	vrrp_mcast_sender_t	mcast_senders[VRRP_AUTH_HMAC_MCAST_SENDERS];
} vrrp_auth_hmac_t;

/* Outcome of verifying a received trailer */
typedef enum {
	VRRP_AUTH_HMAC_OK,
	VRRP_AUTH_HMAC_MALFORMED,
	VRRP_AUTH_HMAC_UNKNOWN_KEY,
	VRRP_AUTH_HMAC_BAD_HMAC,
	VRRP_AUTH_HMAC_STALE,
	VRRP_AUTH_HMAC_REPLAY,
} vrrp_auth_hmac_result_t;

/* Forward declaration, the full type lives in vrrp.h */
struct _vrrp_t;

/* prototypes */
extern vrrp_auth_key_t *vrrp_auth_hmac_add_key(vrrp_auth_hmac_t *, unsigned, const uint8_t *, size_t);
extern vrrp_auth_key_t *vrrp_auth_hmac_find_key(const vrrp_auth_hmac_t *, uint8_t) __attribute__ ((pure));
extern void vrrp_auth_hmac_free(vrrp_auth_hmac_t *);
extern size_t vrrp_auth_hmac_trailer_len(const struct _vrrp_t *) __attribute__ ((pure));
extern void vrrp_auth_hmac_sign(struct _vrrp_t *);
extern vrrp_auth_hmac_result_t vrrp_auth_hmac_check(struct _vrrp_t *, const void *, size_t, const vrrp_auth_ext_t *, vrrp_replay_state_t *, int *);

#endif
