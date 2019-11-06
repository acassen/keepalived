/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Scheduling framework for bfd code
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

#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <inttypes.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>

#include "bfd.h"
#include "bfd_data.h"
#include "bfd_scheduler.h"
#include "bfd_event.h"
#include "parser.h"
#include "logger.h"
#include "memory.h"
#include "main.h"
#include "bitops.h"
#include "utils.h"
#include "signals.h"
#include "assert_debug.h"

/* RFC5881 section 4 */
#define	BFD_MIN_PORT	49152
#define	BFD_MAX_PORT	65535

static int bfd_send_packet(int, bfdpkt_t *, bool);
static void bfd_sender_schedule(bfd_t *);

static void bfd_state_down(bfd_t *, u_char diag);
static void bfd_state_admindown(bfd_t *);
static void bfd_state_up(bfd_t *);
static void bfd_dump_timers(FILE *fp, bfd_t *);

/*
 * Session sender thread
 *
 * Runs every local_tx_intv, or after reception of a packet
 * with Poll bit set
 */

inline static long
thread_time_to_wakeup(thread_ref_t thread)
{
	struct timeval tmp_time;

	timersub(&thread->sands, &time_now, &tmp_time);

	return timer_long(tmp_time);
}

/* Sends one BFD control packet and reschedules itself if needed */
static int
bfd_sender_thread(thread_ref_t thread)
{
	bfd_t *bfd;
	bfdpkt_t pkt;

	assert(thread);
	bfd = THREAD_ARG(thread);
	assert(bfd);
	assert(!BFD_ISADMINDOWN(bfd));

	if (thread->type != THREAD_EVENT)
		bfd->thread_out = NULL;

	bfd_build_packet(&pkt, bfd, bfd_buffer, BFD_BUFFER_SIZE);
	if (bfd_send_packet(bfd->fd_out, &pkt, !bfd->send_error) == -1) {
		if (!bfd->send_error) {
			log_message(LOG_ERR, "BFD_Instance(%s) Error sending packet", bfd->iname);
			bfd->send_error = true;
		}
	} else
		bfd->send_error = false;

	/* Reset final flag if set */
	bfd->final = 0;

	/* Schedule next run if not called as an event thread */
	if (thread->type != THREAD_EVENT)
		bfd_sender_schedule(bfd);

	return 0;
}

/* Schedules bfd_sender_thread to run in local_tx_intv minus applied jitter */
static uint32_t
get_jitter(bfd_t * bfd)
{
	uint32_t min_jitter;

	/*
	 * RFC5880:
	 * The periodic transmission of BFD Control packets MUST be jittered
	 * on a per-packet basis by up to 25%, that is, the interval MUST be
	 * reduced by a random value of 0 to 25% <...>
	 *
	 * If bfd.DetectMult is equal to 1, the interval between transmitted
	 * BFD Control packets MUST be no more than 90% of the negotiated
	 * transmission interval, and MUST be no less than 75% of the
	 * negotiated transmission interval.
	 */
	if (bfd->local_detect_mult)
		min_jitter = bfd->local_tx_intv / 10;	/* 10% <=> / 10 */
	else
		min_jitter = 0;

	return rand_intv(min_jitter, bfd->local_tx_intv / 4);	/* 25% <=> / 4 */
}

/* Schedules bfd_sender_thread to run in local_tx_intv minus applied jitter */
static void
bfd_sender_schedule(bfd_t *bfd)
{
	assert(bfd);
	assert(!bfd->thread_out);

	bfd->thread_out =
	    thread_add_timer(master, bfd_sender_thread, bfd,
			     bfd->local_tx_intv - get_jitter(bfd));
}

/* Cancels bfd_sender_thread run */
static void
bfd_sender_cancel(bfd_t *bfd)
{
	assert(bfd);
	assert(bfd->thread_out);

	thread_cancel(bfd->thread_out);
	bfd->thread_out = NULL;
}

/* Reschedules bfd_sender_thread run (usually after local_tx_intv change) */
static void
bfd_sender_reschedule(bfd_t *bfd)
{
	assert(bfd);
	assert(bfd->thread_out);

	timer_thread_update_timeout(bfd->thread_out, bfd->local_tx_intv - get_jitter(bfd));
}

/* Returns 1 if bfd_sender_thread is scheduled to run, 0 otherwise */
static int __attribute__ ((pure))
bfd_sender_scheduled(bfd_t *bfd)
{
	assert(bfd);

	return bfd->thread_out != NULL;
}

/* Suspends sender thread. Needs freshly updated time_now */
static void
bfd_sender_suspend(bfd_t * bfd)
{
	assert(bfd);
	assert(bfd->thread_out);
	assert(bfd->sands_out == -1);

	bfd->sands_out = thread_time_to_wakeup(bfd->thread_out);
	bfd_sender_cancel(bfd);
}

/* Resumes sender thread */
static void
bfd_sender_resume(bfd_t *bfd)
{
	assert(bfd);
	assert(!bfd->thread_out);
	assert(bfd->sands_out != -1);

	if (!bfd->passive || bfd->local_state == BFD_STATE_UP)
		bfd->thread_out =
		    thread_add_timer(master, bfd_sender_thread, bfd, bfd->sands_out);
	bfd->sands_out = -1;
}

/* Returns 1 if bfd_sender_thread is suspended, 0 otherwise */
static int __attribute__ ((pure))
bfd_sender_suspended(bfd_t *bfd)
{
	assert(bfd);

	return bfd->sands_out != -1;
}

static void
bfd_sender_discard(bfd_t *bfd)
{
	assert(bfd);
	assert(bfd->sands_out != -1);

	bfd->sands_out = -1;
}

/*
 * Session expiration thread
 *
 * Runs after local_detect_time has passed since receipt of last
 * BFD control packet from neighbor
 */

/* Marks session as down because of Control Detection Time Expiration */
static int
bfd_expire_thread(thread_ref_t thread)
{
	bfd_t *bfd;
	uint32_t dead_time, overdue_time;
	timeval_t dead_time_tv;

	assert(thread);

	bfd = THREAD_ARG(thread);
	assert(bfd);

	/* Session cannot expire while not in Up or Init states */
	assert(BFD_ISUP(bfd) || BFD_ISINIT(bfd));

	bfd->thread_exp = NULL;

	/* Time since last received control packet */
	timersub(&time_now, &bfd->last_seen, &dead_time_tv);
	dead_time = timer_long(dead_time_tv);

	/* Difference between expected and actual failure detection time */
	overdue_time = dead_time - bfd->local_detect_time;

	if (bfd->local_state == BFD_STATE_UP ||
	    __test_bit(LOG_EXTRA_DETAIL_BIT, &debug))
		log_message(LOG_WARNING, "BFD_Instance(%s) Expired after"
			    " %" PRIu32 " ms (%" PRIu32 " usec overdue)",
			    bfd->iname, dead_time / 1000, overdue_time);

	/*
	 * RFC5880:
	 * <...> If a period of a Detection Time passes without the
	 * receipt of a valid, authenticated BFD packet from the remote
	 * system, this <bfd.RemoteDiscr> variable MUST be set to zero.
	 */
	bfd->remote_discr = 0;
	bfd_state_down(bfd, BFD_DIAG_EXPIRED);

	return 0;
}

/* Schedules bfd_expire_thread to run in local_detect_time */
static void
bfd_expire_schedule(bfd_t *bfd)
{
	assert(bfd);
	assert(!bfd->thread_exp);

	bfd->thread_exp =
	    thread_add_timer(master, bfd_expire_thread, bfd,
			     bfd->local_detect_time);
}

/* Cancels bfd_expire_thread run */
static void
bfd_expire_cancel(bfd_t *bfd)
{
	assert(bfd);
	assert(bfd->thread_exp);

	thread_cancel(bfd->thread_exp);
	bfd->thread_exp = NULL;
}

/* Reschedules bfd_expire_thread run (usually after control packet receipt) */
static void
bfd_expire_reschedule(bfd_t *bfd)
{
	assert(bfd);
	assert(bfd->thread_exp);

	timer_thread_update_timeout(bfd->thread_exp, bfd->local_detect_time);
}

/* Returns 1 if bfd_expire_thread is scheduled to run, 0 otherwise */
static int __attribute__ ((pure))
bfd_expire_scheduled(bfd_t *bfd)
{
	assert(bfd);

	return bfd->thread_exp != NULL;
}

/* Suspends expire thread. Needs freshly updated time_now */
static void
bfd_expire_suspend(bfd_t *bfd)
{
	assert(bfd);
	assert(bfd->thread_exp);
	assert(bfd->sands_exp == -1);

	bfd->sands_exp = thread_time_to_wakeup(bfd->thread_exp);
	bfd_expire_cancel(bfd);
}

/* Resumes expire thread */
static void
bfd_expire_resume(bfd_t *bfd)
{
	assert(bfd);
	assert(!bfd->thread_exp);
	assert(bfd->sands_exp != -1);

	bfd->thread_exp =
	    thread_add_timer(master, bfd_expire_thread, bfd, bfd->sands_exp);
	bfd->sands_exp = -1;
}

/* Returns 1 if bfd_expire_thread is suspended, 0 otherwise */
static int __attribute__ ((pure))
bfd_expire_suspended(bfd_t *bfd)
{
	assert(bfd);

	return bfd->sands_exp != -1;
}

static void
bfd_expire_discard(bfd_t *bfd)
{
	assert(bfd);
	assert(bfd->sands_exp != -1);

	bfd->sands_exp = -1;
}

/*
 * Session reset thread
 *
 * Runs after local_detect_time has passed after BFD session
 * gone to Down state.
 */

/* Resets BFD session to initial state */
static int
bfd_reset_thread(thread_ref_t thread)
{
	bfd_t *bfd;

	assert(thread);

	bfd = THREAD_ARG(thread);
	assert(bfd);
	assert(bfd->thread_rst);

	bfd->thread_rst = NULL;

	bfd_reset_state(bfd);

	return 0;
}

/* Schedules bfd_reset_thread to run in local_detect_time */
static void
bfd_reset_schedule(bfd_t * bfd)
{
	assert(bfd);
	assert(!bfd->thread_rst);

	bfd->thread_rst =
	    thread_add_timer(master, bfd_reset_thread, bfd,
			     bfd->local_detect_time);
}

/* Cancels bfd_reset_thread run */
static void
bfd_reset_cancel(bfd_t *bfd)
{
	assert(bfd);
	assert(bfd->thread_rst);

	thread_cancel(bfd->thread_rst);
	bfd->thread_rst = NULL;
}

/* Returns 1 if bfd_reset_thread is scheduled to run, 0 otherwise */
static int __attribute__ ((pure))
bfd_reset_scheduled(bfd_t *bfd)
{
	assert(bfd);

	return bfd->thread_rst != NULL;
}

/* Suspends reset thread. Needs freshly updated time_now */
static void
bfd_reset_suspend(bfd_t *bfd)
{
	assert(bfd);
	assert(bfd->thread_rst);
	assert(bfd->sands_rst == -1);

	bfd->sands_rst = thread_time_to_wakeup(bfd->thread_rst);
	bfd_reset_cancel(bfd);
}

/* Resumes reset thread */
static void
bfd_reset_resume(bfd_t *bfd)
{
	assert(bfd);
	assert(!bfd->thread_rst);
	assert(bfd->sands_rst != -1);

	bfd->thread_rst =
	    thread_add_timer(master, bfd_reset_thread, bfd, bfd->sands_rst);
	bfd->sands_rst = -1;
}

/* Returns 1 if bfd_reset_thread is suspended, 0 otherwise */
static int __attribute__ ((pure))
bfd_reset_suspended(bfd_t *bfd)
{
	assert(bfd);

	return bfd->sands_rst != -1;
}

static void
bfd_reset_discard(bfd_t *bfd)
{
	assert(bfd);
	assert(bfd->sands_rst != -1);

	bfd->sands_rst = -1;
}

/*
 * State change handlers
 */
/* Common actions for Down and AdminDown states */
static void
bfd_state_fall(bfd_t *bfd, bool send_event)
{
	assert(bfd);

	/*
	 * RFC5880:
	 * When bfd.SessionState is not Up, the system MUST set
	 * bfd.DesiredMinTxInterval to a value of not less than
	 * one second (1,000,000 microseconds)
	 */
	bfd_idle_local_tx_intv(bfd);

	if (bfd_expire_scheduled(bfd))
		bfd_expire_cancel(bfd);

	if (send_event &&
	    bfd->remote_state != BFD_STATE_ADMINDOWN)
		bfd_event_send(bfd);
}

/* Runs when BFD session state goes Down */
static void
bfd_state_down(bfd_t *bfd, u_char diag)
{
	assert(bfd);
	assert(BFD_VALID_DIAG(diag));
	int old_state = bfd->local_state;

	if (bfd->local_state == BFD_STATE_UP)
		bfd->local_discr = bfd_get_random_discr(bfd_data);

	if (bfd->local_state == BFD_STATE_UP ||
	    __test_bit(LOG_EXTRA_DETAIL_BIT, &debug))
		log_message(LOG_WARNING, "BFD_Instance(%s) Entering %s state"
			    " (Local diagnostic - %s, Remote diagnostic - %s)",
			    bfd->iname, BFD_STATE_STR(BFD_STATE_DOWN),
			    BFD_DIAG_STR(diag),
			    BFD_DIAG_STR(bfd->remote_diag));

	bfd->local_state = BFD_STATE_DOWN;
	bfd->local_diag = diag;

	bfd_reset_schedule(bfd);

	if (bfd->passive && bfd_sender_scheduled(bfd))
		bfd_sender_cancel(bfd);

	bfd_state_fall(bfd, old_state == BFD_STATE_UP);
}

/* Runs when BFD session state goes AdminDown */
static void
bfd_state_admindown(bfd_t *bfd)
{
	assert(bfd);

	bfd->local_state = BFD_STATE_ADMINDOWN;
	bfd->local_diag = BFD_DIAG_ADMIN_DOWN;

	if (bfd_sender_scheduled(bfd))
		bfd_sender_cancel(bfd);

	log_message(LOG_WARNING, "BFD_Instance(%s) Entering %s state",
		    bfd->iname, BFD_STATE_STR(bfd->local_state));

	bfd_state_fall(bfd, false);
}

/* Common actions for Init and Up states */
static void
bfd_state_rise(bfd_t *bfd)
{
	/* RFC5880 doesn't state if this must be done or not */
	bfd->local_diag = BFD_DIAG_NO_DIAG;

	if (bfd->local_state == BFD_STATE_UP ||
	    __test_bit(LOG_EXTRA_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "BFD_Instance(%s) Entering %s state",
			    bfd->iname, BFD_STATE_STR(bfd->local_state));

	if (bfd_reset_scheduled(bfd))
		bfd_reset_cancel(bfd);

	if (!bfd_expire_scheduled(bfd))
		bfd_expire_schedule(bfd);
}

/* Runs when BFD session state goes Up */
static void
bfd_state_up(bfd_t *bfd)
{
	assert(bfd);

	bfd->local_state = BFD_STATE_UP;
	bfd_state_rise(bfd);

	if (bfd->local_idle_tx_intv != bfd->local_min_tx_intv)
		bfd_set_poll(bfd);

	bfd_event_send(bfd);
}

/* Runs when BFD session state goes Init */
static void
bfd_state_init(bfd_t *bfd)
{
	assert(bfd);

	/* According to RFC5880 session cannot directly
	   transition from Init to Up state */
	assert(!BFD_ISUP(bfd));

	bfd->local_state = BFD_STATE_INIT;
	bfd_state_rise(bfd);

	if (bfd->passive && !bfd_sender_scheduled(bfd))
		bfd_sender_schedule(bfd);
}

/* Dumps current timers values */
static void
bfd_dump_timers(FILE *fp, bfd_t *bfd)
{
	assert(bfd);

	conf_write(fp, "BFD_Instance(%s)"
		    " --------------< Session parameters >-------------",
		    bfd->iname);
	conf_write(fp, "BFD_Instance(%s)"
		    "        min_tx  min_rx  tx_intv  mult  detect_time",
		    bfd->iname);
	conf_write(fp, "BFD_Instance(%s)"
		    " local %7u %7u %8u %5u %12" PRIu64,
		    bfd->iname, (bfd->local_state == BFD_STATE_UP ? bfd->local_min_tx_intv : bfd->local_idle_tx_intv) / 1000,
		    bfd->local_min_rx_intv / 1000,
		    bfd->local_tx_intv / 1000, bfd->local_detect_mult,
		    bfd->local_detect_time / 1000);
	conf_write(fp, "BFD_Instance(%s)" " remote %6u %7u %8u %5u %12" PRIu64,
		    bfd->iname, bfd->remote_min_tx_intv / 1000,
		    bfd->remote_min_rx_intv / 1000,
		    bfd->remote_tx_intv / 1000, bfd->remote_detect_mult,
		    bfd->remote_detect_time / 1000);
}

/*
 * Packet handling functions
 */

/* Sends a control packet to the neighbor (called from bfd_sender_thread)
   returns -1 on error */
static int
bfd_send_packet(int fd, bfdpkt_t *pkt, bool log_error)
{
	int ret;
	socklen_t dstlen;

	assert(fd >= 0);
	assert(pkt);

	if (pkt->dst_addr.ss_family == AF_INET)
		dstlen = sizeof (struct sockaddr_in);
	else
		dstlen = sizeof (struct sockaddr_in6);

	ret =
	    sendto(fd, pkt->buf, pkt->len, 0,
		   (struct sockaddr *) &pkt->dst_addr, dstlen);
	if (ret == -1 && log_error)
		log_message(LOG_ERR, "sendto() error (%m)");

	return ret;
}

/* Handles incoming control packet (called from bfd_receiver_thread) and
   processes it through a BFD state machine. */
static void
bfd_handle_packet(bfdpkt_t *pkt)
{
	uint32_t old_local_tx_intv;
	uint32_t old_remote_rx_intv;
	uint32_t old_remote_tx_intv;
	uint8_t old_remote_detect_mult;
	uint64_t old_local_detect_time;
	bfd_t *bfd;

	assert(pkt);
	assert(pkt->hdr);

	/* Perform sanity checks on a packet */
	if (bfd_check_packet(pkt)) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_ERR,
				    "Discarding bogus packet from %s",
				    inet_sockaddrtopair(&pkt->src_addr));

		return;
	}

	/* Lookup session */
	if (!pkt->hdr->remote_discr)
		bfd = find_bfd_by_addr(&pkt->src_addr, &pkt->dst_addr);
	else
		bfd = find_bfd_by_discr(ntohl(pkt->hdr->remote_discr));

	if (!bfd) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_ERR, "Discarding packet from %s"
				    " (session is not found - your"
				    " discriminator field is %u)",
				    inet_sockaddrtopair(&pkt->src_addr),
				    pkt->hdr->remote_discr);

		return;
	}

	/* We can't check the TTL any earlier, since we need to know what
	 * is configured for this particular instance */
	if (bfd->max_hops != UCHAR_MAX && bfd_check_packet_ttl(pkt, bfd))
		return;

	/* Authentication is not supported for now */
	if (pkt->hdr->auth != 0) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_ERR, "Discarding packet from %s"
				    " (auth bit is set, but no authentication"
				    "  is in use)",
				    inet_sockaddrtopair(&pkt->src_addr));

		return;
	}

	/* Discard all packets while in AdminDown state */
	if (bfd->local_state == BFD_STATE_ADMINDOWN) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "Discarding packet from %s"
				    " (session is in AdminDown state)",
				    inet_sockaddrtopair(&pkt->src_addr));

		return;
	}

	/* Save old timers */
	old_remote_rx_intv = bfd->remote_min_rx_intv;
	old_remote_tx_intv = bfd->remote_min_tx_intv;
	old_remote_detect_mult = bfd->remote_detect_mult;
	old_local_detect_time = bfd->local_detect_time ;
	old_local_tx_intv = bfd->local_tx_intv ;

	/* Update state variables */
	bfd->remote_discr = ntohl(pkt->hdr->local_discr);
	bfd->remote_state = pkt->hdr->state;
	bfd->remote_diag = pkt->hdr->diag;
	bfd->remote_min_rx_intv = ntohl(pkt->hdr->min_rx_intv);
	bfd->remote_min_tx_intv = ntohl(pkt->hdr->min_tx_intv);
	bfd->remote_demand = pkt->hdr->demand;
	bfd->remote_detect_mult = pkt->hdr->detect_mult;

	/* Terminate poll sequence */
	if (pkt->hdr->final)
		bfd->poll = 0;

	/*
	 * Recalculate local and remote TX intervals if:
	 *  Control packet with 'Final' bit is received OR
	 *  Control packet with 'Poll' bit is received OR
	 *  Session is not UP
	 */
	if ((bfd->local_state == BFD_STATE_UP &&
	     (pkt->hdr->poll || pkt->hdr->final)) ||
	    bfd->local_state != BFD_STATE_UP) {
		if (bfd->remote_state == BFD_STATE_UP &&
		    (bfd->local_state == BFD_STATE_INIT || bfd->local_state == BFD_STATE_UP))
			bfd_update_local_tx_intv(bfd);
		else
			bfd_idle_local_tx_intv(bfd);
		bfd_update_remote_tx_intv(bfd);
	}

	/* Update the Detection Time */
	bfd->local_detect_time = bfd->remote_detect_mult * bfd->remote_tx_intv;
	bfd->remote_detect_time = bfd->local_detect_mult * bfd->local_tx_intv;

	/* Check if timers are changed */
	if (__test_bit(LOG_EXTRA_DETAIL_BIT, &debug) ||
	    (__test_bit(LOG_DETAIL_BIT, &debug) &&
	     (bfd->remote_min_rx_intv != old_remote_rx_intv ||
	      bfd->remote_min_tx_intv != old_remote_tx_intv ||
	      bfd->remote_detect_mult != old_remote_detect_mult ||
	      bfd->local_tx_intv != old_local_tx_intv)))
		bfd_dump_timers(NULL, bfd);

	/* Reschedule sender if local_tx_intv is being reduced */
	if (bfd->local_tx_intv < old_local_tx_intv &&
	    bfd_sender_scheduled(bfd))
		bfd_sender_reschedule(bfd);

	/* Report detection time changes */
	if (bfd->local_detect_time != old_local_detect_time)
		log_message(LOG_INFO, "BFD_Instance(%s) Detection time"
			    " is %" PRIu64 " ms (was %" PRIu64 " ms)", bfd->iname,
			    bfd->local_detect_time / 1000,
			    old_local_detect_time / 1000);

	/* BFD state machine */
	if (bfd->remote_state == BFD_STATE_ADMINDOWN &&
	    bfd->local_state != BFD_STATE_DOWN)
		bfd_state_down(bfd, BFD_DIAG_NBR_SIGNALLED_DOWN);
	else {
		if (bfd->local_state == BFD_STATE_DOWN) {
			if (bfd->remote_state == BFD_STATE_DOWN)
				bfd_state_init(bfd);
			else if (bfd->remote_state == BFD_STATE_INIT)
				bfd_state_up(bfd);
		} else if (bfd->local_state == BFD_STATE_INIT) {
			if (bfd->remote_state == BFD_STATE_INIT ||
			    bfd->remote_state == BFD_STATE_UP)
				bfd_state_up(bfd);
		} else if (bfd->local_state == BFD_STATE_UP)
			if (bfd->remote_state == BFD_STATE_DOWN)
				bfd_state_down(bfd, BFD_DIAG_NBR_SIGNALLED_DOWN);
	}

	if (bfd->remote_demand &&
	    bfd->local_state == BFD_STATE_UP &&
	    bfd->remote_state == BFD_STATE_UP)
		if (bfd_sender_scheduled(bfd))
			bfd_sender_cancel(bfd);

	if (!bfd->remote_demand ||
	    bfd->local_state != BFD_STATE_UP ||
	    bfd->remote_state != BFD_STATE_UP)
		if (!bfd_sender_scheduled(bfd))
			bfd_sender_schedule(bfd);

	if (pkt->hdr->poll) {
		bfd->final = 1;
		thread_add_event(master, bfd_sender_thread, bfd, 0);
	}

	/* Update last seen timer */
	bfd->last_seen = timer_now();

	/* Delay expiration if scheduled */
	if (bfd->local_state == BFD_STATE_UP &&
	    bfd_expire_scheduled(bfd))
		bfd_expire_reschedule(bfd);
}

/* Reads one packet from input socket */
static int
bfd_receive_packet(bfdpkt_t *pkt, int fd, char *buf, ssize_t bufsz)
{
	ssize_t len;
	unsigned int ttl = 0;
	struct msghdr msg;
	struct cmsghdr *cmsg = NULL;
	char cbuf[CMSG_SPACE(sizeof (struct in6_pktinfo)) + CMSG_SPACE(sizeof(ttl))];
	struct iovec iov[1];
	struct in6_pktinfo *pktinfo;

	assert(pkt);
	assert(fd >= 0);
	assert(buf);
	assert(bufsz);

	iov[0].iov_base = buf;
	iov[0].iov_len = bufsz;

	msg.msg_name = &pkt->src_addr;
	msg.msg_namelen = sizeof (pkt->src_addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof (cbuf);
	msg.msg_flags = 0;	/* Unnecessary, but keep coverity happy */

	len = recvmsg(fd, &msg, MSG_DONTWAIT);
	if (len == -1) {
		log_message(LOG_ERR, "recvmsg() error (%m)");
		return 1;
	}

	if (msg.msg_flags & MSG_TRUNC) {
		log_message(LOG_WARNING, "recvmsg() message truncated");
		return 1;
	}

	if (msg.msg_flags & MSG_CTRUNC)
		log_message(LOG_WARNING, "recvmsg() control message truncated");

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if ((cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL) ||
		    (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT))
			ttl = *CMSG_DATA(cmsg);
		else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
			pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			if (IN6_IS_ADDR_V4MAPPED(&pktinfo->ipi6_addr)) {
				((struct sockaddr_in *)&pkt->dst_addr)->sin_addr.s_addr = pktinfo->ipi6_addr.s6_addr32[3];
				pkt->dst_addr.ss_family = AF_INET;
			} else {
				memcpy(&((struct sockaddr_in6 *)&pkt->dst_addr)->sin6_addr, &pktinfo->ipi6_addr, sizeof(pktinfo->ipi6_addr));
				pkt->dst_addr.ss_family = AF_INET6;
			}
		}
		else
			log_message(LOG_WARNING, "recvmsg() received"
				    " unexpected control message (level %d type %d)",
				    cmsg->cmsg_level, cmsg->cmsg_type);
	}

	if (!ttl)
		log_message(LOG_WARNING, "recvmsg() returned no TTL control message");

	pkt->hdr = (bfdhdr_t *) buf;
	pkt->len = len;
	pkt->ttl = ttl;

	/* Convert an IPv4-mapped IPv6 address to a real IPv4 address */
	if (IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)&pkt->src_addr)->sin6_addr)) {
		((struct sockaddr_in *)&pkt->src_addr)->sin_addr.s_addr = ((struct sockaddr_in6 *)&pkt->src_addr)->sin6_addr.s6_addr32[3];
		pkt->src_addr.ss_family = AF_INET;
	}

	return 0;
}

/*
 * Reciever thread
 */

/* Runs when data is available in listening socket */
static int
bfd_receiver_thread(thread_ref_t thread)
{
	bfd_data_t *data;
	bfdpkt_t pkt;
	int fd;

	assert(thread);

	data = THREAD_ARG(thread);
	assert(data);

	fd = thread->u.f.fd;
	assert(fd >= 0);

	data->thread_in = NULL;

	/* Ignore THREAD_READ_TIMEOUT */
	if (thread->type == THREAD_READY_READ_FD) {
		if (!bfd_receive_packet(&pkt, fd, bfd_buffer, BFD_BUFFER_SIZE))
			bfd_handle_packet(&pkt);
	}

	data->thread_in =
	    thread_add_read(thread->master, bfd_receiver_thread, data,
			    fd, TIMER_NEVER, false);

	return 0;
}

/*
 * Initialization functions
 */

/* Prepares UDP socket for listening on *:3784 (both IPv4 and IPv6) */
static int
bfd_open_fd_in(bfd_data_t *data)
{
	struct addrinfo hints;
	struct addrinfo *ai_in;
	int ret;
	int yes = 1;

	assert(data);
	assert(data->fd_in == -1);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET6;
	hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_socktype = SOCK_DGRAM;

	if ((ret = getaddrinfo(NULL, BFD_CONTROL_PORT, &hints, &ai_in)))
		log_message(LOG_ERR, "getaddrinfo() error %d (%s)", ret, gai_strerror(ret));
	else if ((data->fd_in = socket(AF_INET6, ai_in->ai_socktype, ai_in->ai_protocol)) == -1)
		log_message(LOG_ERR, "socket() error %d (%m)", errno);
	else if ((ret = setsockopt(data->fd_in, IPPROTO_IP, IP_RECVTTL, &yes, sizeof (yes))) == -1)
		log_message(LOG_ERR, "setsockopt(IP_RECVTTL) error %d (%m)", errno);
	else if ((ret = setsockopt(data->fd_in, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &yes, sizeof (yes))) == -1)
		log_message(LOG_ERR, "setsockopt(IPV6_RECVHOPLIMIT) error %d (%m)", errno);
	else if ((ret = setsockopt(data->fd_in, IPPROTO_IPV6, IPV6_RECVPKTINFO, &yes, sizeof (yes))) == -1)
		log_message(LOG_ERR, "setsockopt(IPV6_RECVPKTINFO) error %d (%m)", errno);
	else if ((ret = bind(data->fd_in, ai_in->ai_addr, ai_in->ai_addrlen)) == -1)
		log_message(LOG_ERR, "bind() error %d (%m)", errno);

	if (ret)
		ret = 1;

	freeaddrinfo(ai_in);
	return ret;
}

static bool
read_local_port_range(uint32_t port_limits[2])
{
	char buf[5 + 1 + 5 + 1 + 1];	/* 32768<TAB>60999<NL> */
	int fd;
	ssize_t len;
	long val[2];
	char *endptr;

	/* Default to sensible values */
	port_limits[0] = 49152;
	port_limits[1] = 60999;

	fd = open("/proc/sys/net/ipv4/ip_local_port_range", O_RDONLY);
	if (fd == -1)
		return false;
	len = read(fd, buf, sizeof(buf));
	close(fd);

	if (len == -1 || len == sizeof(buf))
		return false;

	buf[len] = '\0';

	val[0] = strtol(buf, &endptr, 10);
	if (val[0] <= 0 || val[0] == LONG_MAX || (*endptr != '\t' && *endptr != ' '))
		return false;
	val[1] = strtol(buf, &endptr, 10);
	if (val[1] <= 0 || val[0] == LONG_MAX || *endptr != '\n')
		return false;

	port_limits[0] = val[0];
	port_limits[1] = val[1];

	return true;
}

/* Prepares UDP socket for sending data to neighbor */
static int
bfd_open_fd_out(bfd_t *bfd)
{
	int ttl;
	int ret;
	uint32_t port_limits[2];
	uint16_t orig_port, port;

	assert(bfd);
	assert(bfd->fd_out == -1);

	bfd->fd_out = socket(bfd->nbr_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if (bfd->fd_out == -1) {
		log_message(LOG_ERR, "BFD_Instance(%s) socket() error (%m)",
			    bfd->iname);
		return 1;
	}

	if (bfd->src_addr.ss_family) {
		/* Generate a random port number within the valid range */
		read_local_port_range(port_limits);
		if (port_limits[0] < BFD_MIN_PORT)
			port_limits[0] = BFD_MIN_PORT;
		if (port_limits[1] > BFD_MAX_PORT)
			port_limits[1] = BFD_MAX_PORT;

		/* Ensure we have a range of at least 1024 ports (an arbitrary number)
		 * to try. */
		if (port_limits[0] + 1023 > port_limits[1]) {
			/* Just use the BFD defaults */
			port_limits[0] = BFD_MIN_PORT;
			port_limits[1] = BFD_MAX_PORT;
		}

		orig_port = port = rand_intv(port_limits[0], port_limits[1]);
		do {
			/* Try binding socket to the address until we find one available */
			if (bfd->src_addr.ss_family == AF_INET)
				((struct sockaddr_in *)&bfd->src_addr)->sin_port = htons(port);
			else
				((struct sockaddr_in6 *)&bfd->src_addr)->sin6_port = htons(port);

			ret = bind(bfd->fd_out, (struct sockaddr *) &bfd->src_addr,
				   sizeof (struct sockaddr));

			if (ret == -1 && errno == EADDRINUSE) {
				/* Port already in use, try next */
				if (++port > port_limits[1])
					port = port_limits[0];
				if (port == orig_port)
					break;
				continue;
			}

			break;
		} while (true);

		if (ret == -1) {
			log_message(LOG_ERR,
				    "BFD_Instance(%s) bind() error (%m)",
				    bfd->iname);
			return 1;
		}
	} else {
		/* We have a problem here - we do not have a source address, and so
		 * cannot bind the socket. That means that we will get a system allocated
		 * port, which may be outside the range [49152, 65535], as specified in
		 * RFC5881. */
	}

	ttl = bfd->ttl;
	if (bfd->nbr_addr.ss_family == AF_INET)
		ret = setsockopt(bfd->fd_out, IPPROTO_IP, IP_TTL, &ttl, sizeof (ttl));
	else
		ret = setsockopt(bfd->fd_out, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof (ttl));

	if (ret == -1) {
		log_message(LOG_ERR, "BFD_Instance(%s) setsockopt() "
			    " error (%m)", bfd->iname);
		return 1;
	}

	return 0;
}

/* Opens all needed sockets */
static int
bfd_open_fds(bfd_data_t *data)
{
	bfd_t *bfd;
	element e;

	assert(data);
	assert(data->bfd);

	/* Do not reopen input socket on reload */
	if (bfd_data->fd_in == -1) {
		if (bfd_open_fd_in(data)) {
			log_message(LOG_ERR, "Unable to open listening socket");

			/* There is no point to stay alive w/o listening socket */
			return 1;
		}
	}

	for (e = LIST_HEAD(data->bfd); e; ELEMENT_NEXT(e)) {
		bfd = ELEMENT_DATA(e);
		assert(bfd);

		if (bfd_open_fd_out(bfd)) {
			log_message(LOG_ERR, "BFD_Instance(%s) Unable to"
				    " open output socket, disabling instance",
				    bfd->iname);
			bfd_state_admindown(bfd);
		}
	}

	return 0;
}

/* Registers sender and receiver threads */
static void
bfd_register_workers(bfd_data_t *data)
{
	bfd_t *bfd;
	element e;

	assert(data);
	assert(!data->thread_in);

	/* Set timeout to not expire */
	data->thread_in = thread_add_read(master, bfd_receiver_thread,
					  data, data->fd_in, TIMER_NEVER, false);

	/* Resume or schedule threads */
	for (e = LIST_HEAD(data->bfd); e; ELEMENT_NEXT(e)) {
		bfd = ELEMENT_DATA(e);

		/* Do not start anything if instance is in AdminDown state.
		   Discard saved state if any */
		if (bfd_sender_suspended(bfd)) {
			if (BFD_ISADMINDOWN(bfd))
				bfd_sender_discard(bfd);
			else
				bfd_sender_resume(bfd);
		} else if (!BFD_ISADMINDOWN(bfd) && !bfd->passive)
			bfd_sender_schedule(bfd);

		if (bfd_expire_suspended(bfd)) {
			if (BFD_ISADMINDOWN(bfd))
				bfd_expire_discard(bfd);
			else
				bfd_expire_resume(bfd);
		}

		if (bfd_reset_suspended(bfd)) {
			if (BFD_ISADMINDOWN(bfd))
				bfd_reset_discard(bfd);
			else
				bfd_reset_resume(bfd);
		}

		/* Send our status to VRRP process */
		bfd_event_send(bfd);

		/* If we are starting up, send a packet */
		if (!reload && !bfd->passive)
			thread_add_event(master, bfd_sender_thread, bfd, 0);
	}
}

/* Suspends threads, closes sockets */
void
bfd_dispatcher_release(bfd_data_t *data)
{
	bfd_t *bfd;
	element e;

	assert(data);

	/* Looks like dispatcher wasn't initialized yet
	   This can happen is case of a configuration error */
	if (!data->thread_in)
		return;

	assert(data->fd_in != -1);

	thread_cancel(data->thread_in);
	data->thread_in = NULL;

	/* Do not close fd_in on reload */
	if (!reload) {
		close(data->fd_in);
		data->fd_in = -1;
	}

	/* Suspend threads for possible resuming after reconfiguration */
	set_time_now();
	for (e = LIST_HEAD(data->bfd); e; ELEMENT_NEXT(e)) {
		bfd = ELEMENT_DATA(e);

		if (bfd_sender_scheduled(bfd))
			bfd_sender_suspend(bfd);

		if (bfd_expire_scheduled(bfd))
			bfd_expire_suspend(bfd);

		if (bfd_reset_scheduled(bfd))
			bfd_reset_suspend(bfd);

		assert(bfd->fd_out != -1);

		close(bfd->fd_out);
		bfd->fd_out = -1;
	}

	cancel_signal_read_thread();
}

/* Starts BFD dispatcher */
int
bfd_dispatcher_init(thread_ref_t thread)
{
	bfd_data_t *data;

	assert(thread);

	data = THREAD_ARG(thread);
	if (bfd_open_fds(data))
		exit(EXIT_FAILURE);

	bfd_register_workers(data);

	return 0;
}


#ifdef THREAD_DUMP
void
register_bfd_scheduler_addresses(void)
{
	register_thread_address("bfd_sender_thread", bfd_sender_thread);
	register_thread_address("bfd_expire_thread", bfd_expire_thread);
	register_thread_address("bfd_reset_thread", bfd_reset_thread);
	register_thread_address("bfd_receiver_thread", bfd_receiver_thread);
}
#endif
