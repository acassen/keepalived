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

/*
 * HMAC SHA256 over up to three message segments following rfc2104. The manual
 * ipad/opad construction mirrors the legacy hmac_md5 so it stays portable
 * across the OpenSSL versions keepalived already supports.
 */
static void
compute_hmac(const uint8_t *key, size_t key_len,
	     const uint8_t *s1, size_t l1, const uint8_t *s2, size_t l2,
	     const uint8_t *s3, size_t l3, uint8_t *digest)
{
	EVP_MD_CTX *ctx;
	unsigned char k_ipad[SHA256_BLOCK_SIZE];
	unsigned char k_opad[SHA256_BLOCK_SIZE];
	unsigned char tk[SHA256_DIGEST_LEN];
	int i;

	/* A failed allocation leaves a zero digest so verification fails safely */
	memset(digest, 0, SHA256_DIGEST_LEN);

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return;

	/* Reduce an oversized key to its digest */
	if (key_len > SHA256_BLOCK_SIZE) {
		EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
		EVP_DigestUpdate(ctx, key, key_len);
		EVP_DigestFinal_ex(ctx, tk, NULL);
		EVP_MD_CTX_reset(ctx);
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
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(ctx, k_ipad, SHA256_BLOCK_SIZE);
	EVP_DigestUpdate(ctx, s1, l1);
	EVP_DigestUpdate(ctx, s2, l2);
	if (s3)
		EVP_DigestUpdate(ctx, s3, l3);
	EVP_DigestFinal_ex(ctx, digest, NULL);

	/* outer pass: H(K xor opad, inner) */
	EVP_MD_CTX_reset(ctx);
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(ctx, k_opad, SHA256_BLOCK_SIZE);
	EVP_DigestUpdate(ctx, digest, SHA256_DIGEST_LEN);
	EVP_DigestFinal_ex(ctx, digest, NULL);

	EVP_MD_CTX_free(ctx);
	OPENSSL_cleanse(k_ipad, sizeof(k_ipad));
	OPENSSL_cleanse(k_opad, sizeof(k_opad));
	OPENSSL_cleanse(tk, sizeof(tk));
}

/*
 * Synthetic header bound into the MAC. Binding family, version and vrid stops
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
	return vrrp->auth_hmac ? sizeof(vrrp_auth_ext_t) : 0;
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

/*
 * Time based sequence. The seconds value is clamped to its own last value so a
 * backward clock step never breaks strict monotonicity. No state is persisted,
 * a restarted sender stays monotonic because the clock has moved on.
 */
static void
next_seq(vrrp_auth_hmac_t *ah, uint32_t *sec, uint32_t *ctr)
{
	struct timespec ts;
	uint32_t now;

	clock_gettime(CLOCK_REALTIME, &ts);
	now = (uint32_t)ts.tv_sec;

	if (now > ah->send_sec) {
		ah->send_sec = now;
		ah->send_ctr = 0;
	} else if (!++ah->send_ctr)
		ah->send_sec++;		/* counter wrapped within a second, borrow one */

	*sec = ah->send_sec;
	*ctr = ah->send_ctr;
}

/*
 * Fill and sign the trailer at the tail of the send buffer. Called per
 * transmitted packet so each receiver observes a strictly growing sequence.
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
	uint32_t sec, ctr;

	if (!ah)
		return;

	pdu_off = (vrrp->family == AF_INET) ? sizeof(struct iphdr) : 0;
	tr = PTR_CAST(vrrp_auth_ext_t, vrrp->send_buffer + vrrp->send_buffer_size - sizeof(*tr));

	tr->ext_type = ah->ext_type;
	tr->key_id = ah->active_key;
	tr->reserved = 0;
	next_seq(ah, &sec, &ctr);
	tr->sec = htonl(sec);
	tr->ctr = htonl(ctr);
	memset(tr->mac, 0, sizeof(tr->mac));

	key = vrrp_auth_hmac_find_key(ah, ah->active_key);
	if (!key)
		return;		/* a zero mac is rejected by every receiver */

	build_pseudo(pseudo, vrrp->family, vrrp->version, vrrp->vrid, &vrrp->saddr);
	compute_hmac(key->data, key->len, pseudo, sizeof(pseudo),
		     PTR_CAST(uint8_t, vrrp->send_buffer) + pdu_off,
		     vrrp->send_buffer_size - pdu_off, NULL, 0, digest);
	memcpy(tr->mac, digest, VRRP_AUTH_HMAC_MAC_LEN);
}

/*
 * Locate the replay slot for a multicast source, allocating or evicting the
 * least recently used entry. Only reached once the MAC has verified so a flood
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
 * mark. The window check has already run, so only strict growth remains.
 */
static bool
replay_ok(vrrp_replay_state_t *state, uint32_t sec, uint32_t ctr)
{
	if (state->valid && (sec < state->sec || (sec == state->sec && ctr <= state->ctr)))
		return false;

	state->valid = true;
	state->sec = sec;
	state->ctr = ctr;

	return true;
}

/*
 * Verify a received trailer. The unicast caller passes the peer replay slot,
 * the multicast caller passes NULL and the table is consulted after the MAC.
 */
vrrp_auth_hmac_result_t
vrrp_auth_hmac_check(vrrp_t *vrrp, const void *pdu, size_t pdu_len,
		     const vrrp_auth_ext_t *tr, vrrp_replay_state_t *uni_state, int *skew)
{
	static const uint8_t zero_mac[VRRP_AUTH_HMAC_MAC_LEN];
	vrrp_auth_hmac_t *ah = vrrp->auth_hmac;
	vrrp_auth_key_t *key;
	vrrp_replay_state_t *state;
	uint8_t pseudo[VRRP_AUTH_HMAC_PSEUDO_LEN];
	uint8_t digest[SHA256_DIGEST_LEN];
	uint32_t sec, ctr;

	if (tr->ext_type != ah->ext_type || tr->reserved != 0)
		return VRRP_AUTH_HMAC_MALFORMED;

	sec = ntohl(tr->sec);
	ctr = ntohl(tr->ctr);

	/*
	 * Drop a stale sequence before the costly HMAC so a flood of replayed
	 * captures cannot force a digest per packet. The timestamp is not yet
	 * authenticated so this only rejects, it never grants trust. The replay
	 * high water mark stays after the MAC, it must never move on forged data.
	 */
	if (ah->anti_replay_time) {
		struct timespec ts;
		int delta;

		clock_gettime(CLOCK_REALTIME, &ts);
		delta = (int)((int64_t)ts.tv_sec - (int64_t)sec);
		*skew = delta;
		if (delta > (int)ah->time_window || delta < -(int)ah->time_window)
			return VRRP_AUTH_HMAC_STALE;
	}

	key = vrrp_auth_hmac_find_key(ah, tr->key_id);
	if (!key)
		return VRRP_AUTH_HMAC_UNKNOWN_KEY;

	build_pseudo(pseudo, vrrp->family, vrrp->version, vrrp->vrid, &vrrp->pkt_saddr);
	compute_hmac(key->data, key->len, pseudo, sizeof(pseudo),
		     pdu, pdu_len + offsetof(vrrp_auth_ext_t, mac),
		     zero_mac, sizeof(zero_mac), digest);
	if (memcmp_constant_time(tr->mac, digest, VRRP_AUTH_HMAC_MAC_LEN))
		return VRRP_AUTH_HMAC_BAD_MAC;

	state = uni_state ? uni_state : mcast_state(ah, &vrrp->pkt_saddr);
	if (!replay_ok(state, sec, ctr))
		return VRRP_AUTH_HMAC_REPLAY;

	return VRRP_AUTH_HMAC_OK;
}
