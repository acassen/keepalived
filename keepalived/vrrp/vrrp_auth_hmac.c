/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Modern VRRP advert authentication extension. An authenticated
 *              trailer carrying an HMAC SHA256 and a time based sequence number
 *              protects adverts against injection and replay, for both unicast
 *              and multicast, independently of the legacy VRRPv2 mechanisms.
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

#include "config.h"

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <string.h>
#include <time.h>

#include "vrrp.h"
#include "vrrp_auth_hmac.h"
#include "memory.h"
#include "utils.h"

#define SHA256_BLOCK_SIZE	64
#define SHA256_DIGEST_LEN	32

/* One HMAC input segment, substitution happens by segmenting the message */
typedef struct _hmac_seg {
	const uint8_t		*data;
	size_t			len;
} hmac_seg_t;

/*
 * HMAC SHA256 over a segmented message following rfc2104. The manual
 * ipad/opad construction mirrors the legacy hmac_md5 so it stays portable
 * across the OpenSSL versions keepalived already supports.
 */
static bool
compute_hmac(const uint8_t *key, size_t key_len,
	     const hmac_seg_t *seg, unsigned nseg, uint8_t *digest)
{
	EVP_MD_CTX *ctx;
	unsigned char k_ipad[SHA256_BLOCK_SIZE];
	unsigned char k_opad[SHA256_BLOCK_SIZE];
	unsigned char tk[SHA256_DIGEST_LEN];
	bool ret = false;
	unsigned n;
	int i;

	/* A failure leaves a zero digest, but so can a sender, so check the
	 * return code rather than the digest */
	memset(digest, 0, SHA256_DIGEST_LEN);

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return false;

	/* Reduce an oversized key to its digest */
	if (key_len > SHA256_BLOCK_SIZE) {
		if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
		    !EVP_DigestUpdate(ctx, key, key_len) ||
		    !EVP_DigestFinal_ex(ctx, tk, NULL) ||
		    !EVP_MD_CTX_reset(ctx)) {
			EVP_MD_CTX_free(ctx);
			return false;
		}
		key = tk;
		key_len = SHA256_DIGEST_LEN;
	}

	memset(k_ipad, 0, sizeof(k_ipad));
	memset(k_opad, 0, sizeof(k_opad));
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);
	for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/* inner pass: H(K xor ipad, message) */
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
	    EVP_DigestUpdate(ctx, k_ipad, SHA256_BLOCK_SIZE)) {
		ret = true;
		for (n = 0; n < nseg; n++)
			if (!EVP_DigestUpdate(ctx, seg[n].data, seg[n].len)) {
				ret = false;
				break;
			}
	}

	/* outer pass: H(K xor opad, inner) */
	if (ret)
		ret = EVP_DigestFinal_ex(ctx, digest, NULL) &&
		      EVP_MD_CTX_reset(ctx) &&
		      EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
		      EVP_DigestUpdate(ctx, k_opad, SHA256_BLOCK_SIZE) &&
		      EVP_DigestUpdate(ctx, digest, SHA256_DIGEST_LEN) &&
		      EVP_DigestFinal_ex(ctx, digest, NULL);

	if (!ret)
		memset(digest, 0, SHA256_DIGEST_LEN);

	EVP_MD_CTX_free(ctx);
	OPENSSL_cleanse(k_ipad, sizeof(k_ipad));
	OPENSSL_cleanse(k_opad, sizeof(k_opad));
	OPENSSL_cleanse(tk, sizeof(tk));

	return ret;
}

/*
 * Synthetic header bound into the HMAC. Binding family, version and vrid stops
 * splicing between instances that share a key, binding the source ties the
 * packet to its claimed sender. The IP header is deliberately excluded.
 */
static void
build_pseudo(uint8_t *out, sa_family_t family, uint8_t version, uint8_t vrid, const sockaddr_t *sa)
{
	memset(out, 0, VRRP_AUTH_HMAC_PSEUDO_LEN);
	out[0] = (family == AF_INET6) ? 6 : 4;
	out[1] = version;
	out[2] = vrid;

	if (family == AF_INET6)
		memcpy(out + 4, &PTR_CAST_CONST(struct sockaddr_in6, sa)->sin6_addr, 16);
	else
		memcpy(out + 4, &PTR_CAST_CONST(struct sockaddr_in, sa)->sin_addr, 4);
}

/*
 * HMAC input of the draft: pseudo header, then the PDU through the trailer
 * prefix with the VRRP checksum field read as zero, then a zeroed HMAC field.
 * Segmenting substitutes the zeros without touching the packet, so the kernel
 * written IPv6 checksum no longer desynchronizes sender and receiver.
 */
static bool
pdu_hmac(const vrrp_auth_key_t *key, const uint8_t *pseudo,
	 const uint8_t *pdu, size_t len, uint8_t *digest)
{
	static const uint8_t zero[VRRP_AUTH_HMAC_LEN];
	size_t csum_off = offsetof(vrrphdr_t, chksum);
	hmac_seg_t seg[5] = {
		{ pseudo, VRRP_AUTH_HMAC_PSEUDO_LEN },
		{ pdu, csum_off },
		{ zero, sizeof(uint16_t) },
		{ pdu + csum_off + sizeof(uint16_t), len - csum_off - sizeof(uint16_t) },
		{ zero, sizeof(zero) },
	};

	return compute_hmac(key->data, key->len, seg, 5, digest);
}

const char *
vrrp_auth_hmac_mode_str(vrrp_auth_hmac_mode_t mode)
{
	switch (mode) {
	case VRRP_AUTH_HMAC_RECEIVE_ONLY:
		return "receive-only";
	case VRRP_AUTH_HMAC_PERMISSIVE:
		return "permissive";
	default:
		return "enforce";
	}
}

vrrp_auth_key_t *
vrrp_auth_hmac_find_key(const vrrp_auth_hmac_t *ah, uint8_t id)
{
	vrrp_auth_key_t *key;

	list_for_each_entry(key, &ah->keys, e_list) {
		if (key->id == id)
			return key;
	}

	return NULL;
}

/* Append a key. Returns NULL on a duplicate id so the parser can report it. */
vrrp_auth_key_t *
vrrp_auth_hmac_add_key(vrrp_auth_hmac_t *ah, unsigned id, const uint8_t *data, size_t len)
{
	vrrp_auth_key_t *key;

	if (vrrp_auth_hmac_find_key(ah, id))
		return NULL;

	PMALLOC(key);
	key->id = id;
	key->len = len;
	memcpy(key->data, data, len);
	INIT_LIST_HEAD(&key->e_list);
	list_add_tail(&key->e_list, &ah->keys);

	return key;
}

void
vrrp_auth_hmac_free(vrrp_auth_hmac_t *ah)
{
	vrrp_auth_key_t *key, *key_tmp;

	if (!ah)
		return;

	list_for_each_entry_safe(key, key_tmp, &ah->keys, e_list) {
		list_del_init(&key->e_list);
		OPENSSL_cleanse(key->data, sizeof(key->data));
		FREE(key);
	}

	FREE(ah);
}

size_t
vrrp_auth_hmac_trailer_len(const vrrp_t *vrrp)
{
	if (!vrrp->auth_hmac || vrrp->auth_hmac->mode == VRRP_AUTH_HMAC_RECEIVE_ONLY)
		return 0;

	return sizeof(vrrp_auth_ext_t);
}

/*
 * Monotonic rank for the multicast table, never zero so it stays distinct from
 * an empty slot.
 */
static unsigned
next_lru(vrrp_auth_hmac_t *ah)
{
	if (!++ah->lru_clock)
		ah->lru_clock = 1;

	return ah->lru_clock;
}

/* RFC1982 serial number arithmetic over the 64 bit sequence */
static inline bool
seq_after(uint64_t a, uint64_t b)
{
	return (int64_t)(a - b) > 0;
}

/*
 * Pack a realtime clock reading into the 64 bit sequence with the counter
 * cleared: seconds in the high 32 bits, a 1/2^16 second fraction in the next 16.
 */
static uint64_t
clock_seq(void)
{
	struct timespec ts;
	uint64_t subsec;

	clock_gettime(CLOCK_REALTIME, &ts);
	subsec = ((uint64_t)ts.tv_nsec << 16) / 1000000000U;

	return ((uint64_t)(uint32_t)ts.tv_sec << 32) | (subsec << 16);
}

/*
 * Time based sequence, the larger of the clock and the last value plus one. The
 * increment carries into the timestamp on overflow so the sequence grows even
 * when the clock has not, and serial arithmetic keeps it correct across the
 * field wrap. No state is persisted, a restarted sender stays monotonic as long
 * as the clock advances across the restart.
 */
static uint64_t
next_seq(vrrp_auth_hmac_t *ah)
{
	uint64_t clk = clock_seq();
	int32_t ahead;

	if (seq_after(clk, ah->send_seq)) {
		ah->send_seq = clk;
		return ah->send_seq;
	}

	/*
	 * A corrected clock step strands the timestamp beyond what receivers
	 * accept, so time mode restarts from the clock once past the window.
	 * Monotonic mode keeps strict growth, its only freshness guarantee.
	 */
	ahead = (int32_t)((uint32_t)(ah->send_seq >> 32) - (uint32_t)(clk >> 32));
	if (ah->anti_replay_time && ahead > (int32_t)ah->time_window)
		ah->send_seq = clk;
	else
		ah->send_seq++;

	return ah->send_seq;
}

/*
 * Fill and sign the trailer at the tail of the send buffer. Called once per
 * logical advertisement, the copies replicated to unicast peers carry the
 * same sequence and HMAC since the HMAC input excludes the destination.
 */
void
vrrp_auth_hmac_sign(vrrp_t *vrrp)
{
	vrrp_auth_hmac_t *ah = vrrp->auth_hmac;
	vrrp_auth_key_t *key;
	vrrp_auth_ext_t *tr;
	uint8_t pseudo[VRRP_AUTH_HMAC_PSEUDO_LEN];
	uint8_t digest[SHA256_DIGEST_LEN];
	size_t pdu_off;
	uint64_t seq;

	if (!ah || ah->mode == VRRP_AUTH_HMAC_RECEIVE_ONLY)
		return;

	pdu_off = (vrrp->family == AF_INET) ? sizeof(struct iphdr) : 0;
	tr = PTR_CAST(vrrp_auth_ext_t, vrrp->send_buffer + vrrp->send_buffer_size - sizeof(*tr));

	tr->ext_type = ah->ext_type;
	tr->key_id = ah->active_key;
	tr->reserved = 0;
	seq = next_seq(ah);
	tr->sec = htonl((uint32_t)(seq >> 32));
	tr->subsec = htons((uint16_t)(seq >> 16));
	tr->ctr = htons((uint16_t)seq);
	memset(tr->hmac, 0, sizeof(tr->hmac));

	key = vrrp_auth_hmac_find_key(ah, ah->active_key);
	if (!key)
		return;		/* a zero hmac is rejected by every receiver */

	build_pseudo(pseudo, vrrp->family, vrrp->version, vrrp->vrid, &vrrp->saddr);
	if (!pdu_hmac(key, pseudo, PTR_CAST(uint8_t, vrrp->send_buffer) + pdu_off,
		      vrrp->send_buffer_size - pdu_off - VRRP_AUTH_HMAC_LEN, digest))
		return;		/* leave the zero hmac, which a receiver rejects */
	memcpy(tr->hmac, digest, VRRP_AUTH_HMAC_LEN);
}

/*
 * Locate the replay slot for a multicast source, allocating or evicting the
 * least recently used entry. Only reached once the HMAC has verified so a flood
 * of forged sources cannot churn the table.
 */
static vrrp_replay_state_t *
mcast_state(vrrp_auth_hmac_t *ah, const sockaddr_t *addr)
{
	vrrp_mcast_sender_t *slot, *victim = NULL;
	int i;

	for (i = 0; i < VRRP_AUTH_HMAC_MCAST_SENDERS; i++) {
		slot = &ah->mcast_senders[i];
		if (slot->last_used && !inet_sockaddrcmp(&slot->addr, addr)) {
			slot->last_used = next_lru(ah);
			return &slot->replay;
		}
		if (!victim || slot->last_used < victim->last_used)
			victim = slot;
	}

	victim->addr = *addr;
	victim->replay.valid = false;
	victim->last_used = next_lru(ah);

	return &victim->replay;
}

/*
 * Reject a non growing sequence from a known sender, then raise the high water
 * mark. The window check has already run, so only strict growth remains, ordered
 * under serial number arithmetic so it survives the field wrap.
 */
static bool
replay_ok(vrrp_auth_hmac_t *ah, vrrp_replay_state_t *state, uint64_t seq)
{
	struct timespec ts;
	int32_t age;

	/*
	 * A mark outside the window only orders packets the window already
	 * rejects, expiring it recovers a sender reset after a clock step.
	 */
	if (state->valid && ah->anti_replay_time) {
		clock_gettime(CLOCK_REALTIME, &ts);
		age = (int32_t)((uint32_t)ts.tv_sec - (uint32_t)(state->seq >> 32));
		if (age > (int)ah->time_window || age < -(int)ah->time_window)
			state->valid = false;
	}

	if (state->valid && !seq_after(seq, state->seq))
		return false;

	state->valid = true;
	state->seq = seq;

	return true;
}

/*
 * Verify a received trailer. The unicast caller passes the peer replay slot,
 * the multicast caller passes NULL and the table is consulted after the HMAC.
 */
vrrp_auth_hmac_result_t
vrrp_auth_hmac_check(vrrp_t *vrrp, const void *pdu, size_t pdu_len,
		     const vrrp_auth_ext_t *tr, vrrp_replay_state_t *uni_state, int *skew)
{
	vrrp_auth_hmac_t *ah = vrrp->auth_hmac;
	vrrp_auth_key_t *key;
	vrrp_replay_state_t *state;
	uint8_t pseudo[VRRP_AUTH_HMAC_PSEUDO_LEN];
	uint8_t digest[SHA256_DIGEST_LEN];
	uint32_t sec;
	uint64_t seq;

	if (tr->ext_type != ah->ext_type || tr->reserved != 0)
		return VRRP_AUTH_HMAC_MALFORMED;

	sec = ntohl(tr->sec);
	seq = ((uint64_t)sec << 32) | ((uint64_t)ntohs(tr->subsec) << 16) | ntohs(tr->ctr);

	/*
	 * Drop a stale sequence before the costly HMAC so a flood of replayed
	 * captures cannot force a digest per packet. The timestamp is not yet
	 * authenticated so this only rejects, it never grants trust. The replay
	 * high water mark stays after the HMAC, it must never move on forged data.
	 */
	if (ah->anti_replay_time) {
		struct timespec ts;
		int32_t delta;

		clock_gettime(CLOCK_REALTIME, &ts);
		delta = (int32_t)((uint32_t)ts.tv_sec - sec);
		*skew = delta;
		if (delta > (int)ah->time_window || delta < -(int)ah->time_window)
			return VRRP_AUTH_HMAC_STALE;
	}

	key = vrrp_auth_hmac_find_key(ah, tr->key_id);
	if (!key)
		return VRRP_AUTH_HMAC_UNKNOWN_KEY;

	build_pseudo(pseudo, vrrp->family, vrrp->version, vrrp->vrid, &vrrp->pkt_saddr);
	if (!pdu_hmac(key, pseudo, pdu, pdu_len + offsetof(vrrp_auth_ext_t, hmac), digest))
		return VRRP_AUTH_HMAC_BAD_HMAC;
	if (memcmp_constant_time(tr->hmac, digest, VRRP_AUTH_HMAC_LEN))
		return VRRP_AUTH_HMAC_BAD_HMAC;

	state = uni_state ? uni_state : mcast_state(ah, &vrrp->pkt_saddr);
	if (!replay_ok(ah, state, seq))
		return VRRP_AUTH_HMAC_REPLAY;

	return VRRP_AUTH_HMAC_OK;
}
