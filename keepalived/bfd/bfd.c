/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        BFD implementation as specified by RFC5880, RFC5881
 *              Bidirectional Forwarding Detection (BFD) is a protocol
 *              which can provide failure detection on bidirectional path
 *              between two hosts. A pair of host creates BFD session for
 *              the communications path. During the communication, hosts
 *              transmit BFD packets periodically over the path between
 *              them, and if one host stops receiving BFD packets for
 *              long enough, some component in the path to the correspondent
 *              peer is assumed to have failed
 *
 * Author:      Ilya Voronin, <ivoronin@gmail.com>
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
 * Copyright (C) 2015-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <string.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "bitops.h"
#include "bfd.h"
#include "bfd_data.h"
#include "logger.h"
#include "utils.h"
#include "assert_debug.h"

/* Initial state */
const bfd_t bfd0 = {
	.local_state = BFD_STATE_DOWN,
	.remote_state = BFD_STATE_DOWN,
	.local_discr = 0,	/* ! */
	.remote_discr = 0,
	.local_diag = BFD_DIAG_NO_DIAG,
	.remote_diag = BFD_DIAG_NO_DIAG,
	.remote_min_tx_intv = 0,
	.remote_min_rx_intv = 0,
	.local_demand = 0,
	.remote_demand = 0,
	.remote_detect_mult = 0,
	.poll = 0,
	.final = 0,
	.local_tx_intv = 0,
	.remote_tx_intv = 0,
	.local_detect_time = 0,
	.remote_detect_time = 0,
	.last_seen = (struct timeval) {0},
};

void
bfd_update_local_tx_intv(bfd_t *bfd)
{
	bfd->local_tx_intv = bfd->local_min_tx_intv > bfd->remote_min_rx_intv ?
	    bfd->local_min_tx_intv : bfd->remote_min_rx_intv;
}

void
bfd_update_remote_tx_intv(bfd_t *bfd)
{
	bfd->remote_tx_intv = bfd->local_min_rx_intv > bfd->remote_min_tx_intv ?
	    bfd->local_min_rx_intv : bfd->remote_min_tx_intv;
}

void
bfd_idle_local_tx_intv(bfd_t *bfd)
{
	bfd->local_tx_intv = bfd->local_idle_tx_intv > bfd->remote_min_rx_intv ?
	    bfd->local_idle_tx_intv : bfd->remote_min_rx_intv;
}

void
bfd_set_poll(bfd_t *bfd)
{
	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "BFD_Instance(%s) Starting poll sequence",
			    bfd->iname);
	/*
	 * RFC5880:
	 * ... If the timing is such that a system receiving a Poll Sequence
	 * wishes to change the parameters described in this paragraph, the
	 * new parameter values MAY be carried in packets with the Final (F)
	 * bit set, even if the Poll Sequence has not yet been sent.
	 */
	if (bfd->final != 1)
		bfd->poll = 1;
}

/* Copies BFD state */
void
bfd_copy_state(bfd_t *bfd, const bfd_t *bfd_old, bool all_fields)
{
	assert(bfd_old);
	assert(bfd);

	/* Copy state variables */
	bfd->local_state = bfd_old->local_state;
	bfd->remote_state = bfd_old->remote_state;
	bfd->remote_discr = bfd_old->remote_discr;
	bfd->remote_diag = bfd_old->remote_diag;
	bfd->local_demand = bfd_old->local_demand;
	bfd->remote_demand = bfd_old->remote_demand;
	bfd->poll = bfd_old->poll;
	bfd->final = bfd_old->final;

	/*
	 * RFC5880:
	 * When the text refers to initializing a state variable, this takes
	 * place only at the time that the session (and the corresponding state
	 * variables) is created.  The state variables are subsequently
	 * manipulated by the state machine and are never reinitialized, even if
	 * the session fails and is reestablished.
	 */
	if (all_fields) {
		bfd->local_diag = bfd_old->local_diag;
		bfd->local_discr = bfd_old->local_discr;
		bfd->remote_min_tx_intv = bfd_old->remote_min_tx_intv;
		bfd->remote_min_rx_intv = bfd_old->remote_min_rx_intv;
		bfd->remote_detect_mult = bfd_old->remote_detect_mult;
		bfd->local_tx_intv = bfd_old->local_tx_intv;
		bfd->remote_tx_intv = bfd_old->remote_tx_intv;
		bfd->local_detect_time = bfd_old->local_detect_time;
		bfd->remote_detect_time = bfd_old->remote_detect_time;

		bfd->last_seen = bfd_old->last_seen;
	}
}

/* Copies thread sands */
void
bfd_copy_sands(bfd_t *bfd, const bfd_t *bfd_old)
{
	bfd->sands_out = bfd_old->sands_out;
	bfd->sands_exp = bfd_old->sands_exp;
	bfd->sands_rst = bfd_old->sands_rst;
}

/* Resets BFD instance to initial state */
void
bfd_init_state(bfd_t *bfd)
{
	assert(bfd);

	bfd_copy_state(bfd, &bfd0, true);
	bfd->local_discr = bfd_get_random_discr(bfd_data);
	bfd->local_tx_intv = bfd->local_idle_tx_intv;
}

void
bfd_reset_state(bfd_t *bfd)
{
	assert(bfd);

	bfd_copy_state(bfd, &bfd0, false);
	bfd_idle_local_tx_intv(bfd);
}

/*
 * Builds BFD packet
 */
void
bfd_build_packet(bfdpkt_t *pkt, bfd_t *bfd, char *buf,
		 const ssize_t bufsz)
{
	ssize_t len = sizeof (bfdhdr_t);

	memset(buf, 0, bufsz);
	pkt->hdr = (bfdhdr_t *) buf;

	/* If we are responding to a poll, but also wanted
	 * to send a poll, we can send the parameters now */
	if (bfd->poll && bfd->final)
		bfd->poll = false;

	pkt->hdr->diag = bfd->local_diag;
	pkt->hdr->version = BFD_VERSION_1;
	pkt->hdr->state = bfd->local_state;
	pkt->hdr->poll = bfd->poll;
	pkt->hdr->final = bfd->final;
	pkt->hdr->cplane = 0;
	pkt->hdr->auth = 0;	/* Auth is not supported */
	pkt->hdr->demand = bfd->local_demand;
	pkt->hdr->multipoint = 0;
	pkt->hdr->detect_mult = bfd->local_detect_mult;
	pkt->hdr->len = len;
	pkt->hdr->local_discr = htonl(bfd->local_discr);
	pkt->hdr->remote_discr = htonl(bfd->remote_discr);
	pkt->hdr->min_tx_intv = bfd->local_state == BFD_STATE_UP ? htonl(bfd->local_min_tx_intv) : htonl(bfd->local_idle_tx_intv);
	pkt->hdr->min_rx_intv = htonl(bfd->local_min_rx_intv);
	pkt->hdr->min_echo_rx_intv = 0;	/* Echo function is not supported */

	pkt->len = len;
	pkt->dst_addr = bfd->nbr_addr;
	pkt->buf = buf;
}

/*
 * Performs sanity checks on a packet
 */
bool
bfd_check_packet(const bfdpkt_t *pkt)
{
	/* Preliminary sanity checks */
	if (sizeof (bfdhdr_t) > pkt->len) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_ERR, "Packet is too small: %u bytes",
				    pkt->len);
		return true;
	}

	if (pkt->hdr->len != pkt->len) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_ERR, "Packet size mismatch:"
				    " length field: %u bytes"
				    ", buffer size: %u bytes",
				    pkt->hdr->len, pkt->len);
		return true;
	}

	/* Main Checks (RFC5880) */
	if (pkt->hdr->version != BFD_VERSION_1) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_ERR, "Packet is of unsupported"
				    " version: %d", pkt->hdr->version);
		return true;
	}

	if (!pkt->hdr->detect_mult) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_ERR, "Packet 'detection multiplier'"
				    " field is zero");
		return true;
	}

	if (pkt->hdr->multipoint) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_ERR, "Packet has 'multipoint' flag");
		return true;
	}

	if (!pkt->hdr->local_discr) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_ERR, "Packet 'my discriminator'"
				    " field is zero");
		return true;
	}

	if (!pkt->hdr->remote_discr
	    && pkt->hdr->state != BFD_STATE_DOWN
	    && pkt->hdr->state != BFD_STATE_ADMINDOWN) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_ERR,
				    "Packet 'your discriminator' field is"
				    " zero and 'state' field is not"
				    " Down or AdminDown");
		return true;
	}

	/* Additional sanity checks */
	if (pkt->hdr->poll && pkt->hdr->final) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_ERR, "Packet has both poll and final"
				    "  flags set");
		return true;
	}

	if (!BFD_VALID_DIAG(pkt->hdr->diag)) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_ERR, "Packet has invalid 'diag'"
				    " field: %d", pkt->hdr->diag);
		return true;
	}

	return false;
}

bool
bfd_check_packet_ttl(const bfdpkt_t *pkt, const bfd_t *bfd)
{
	/* Generalized TTL Security Mechanism Check (RFC5881)
	 * - extended so we can specify a maximum number of hops */
	if (pkt->ttl && bfd->max_hops + pkt->ttl < bfd->ttl) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_ERR, "Packet %s(%u) < %d - discarding",
				    pkt->src_addr.ss_family == AF_INET ? "ttl" : "hop_limit",
				    pkt->ttl,
				    bfd->ttl - bfd->max_hops);

		return true;
	}

	return false;
}
