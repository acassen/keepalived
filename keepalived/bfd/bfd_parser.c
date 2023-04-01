/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Configuration file parser/reader.
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

#include "bfd.h"
#include "bfd_data.h"
#include "bfd_parser.h"
#include "logger.h"
#include "parser.h"
#include "global_parser.h"
#include "utils.h"
#include "global_data.h"

#include "bitops.h"
#ifdef _WITH_LVS_
#include "check_parser.h"
#include "check_bfd.h"
#endif
#ifdef _WITH_VRRP_
#include "vrrp_parser.h"
#include "vrrp_track.h"
#include "vrrp_data.h"
#endif
#if defined _WITH_VRRP_ || defined _WITH_LVS_
#include "track_file.h"
#endif
#include "main.h"
#include "assert_debug.h"


static unsigned long specified_event_processes;

/* Allow for English spelling */
static const char * neighbor_str = "neighbor";

static void *current_bfd;


static void
bfd_handler(const vector_t *strvec)
{
	global_data->have_bfd_config = true;

	/* If we are not the bfd process, we don't need any more information */
	if (!strvec)
		return;

	if (!(current_bfd = alloc_bfd(vector_slot(strvec, 1)))) {
		skip_block(true);
		return;
	}

	specified_event_processes = 0;
}

static void
bfd_nbrip_handler(const vector_t *strvec)
{
	bfd_t *bfd = current_bfd;
	sockaddr_t nbr_addr;

	assert(strvec);
	assert(bfd_data);

	if (!strcmp(vector_slot(strvec, 1), "neighbour_ip"))
		neighbor_str = "neighbour";

	/* multihop may have already been specified */
	if (inet_stosockaddr(strvec_slot(strvec, 1), bfd->multihop ? BFD_MULTIHOP_CONTROL_PORT : BFD_CONTROL_PORT, &nbr_addr)) {
		report_config_error(CONFIG_GENERAL_ERROR,
			    "Configuration error: BFD instance %s has"
			    " malformed %s address %s, ignoring instance",
			    bfd->iname, neighbor_str, strvec_slot(strvec, 1));
		free_bfd(bfd);
		current_bfd = NULL;
		skip_block(false);
		return;
	}

	/* coverity[uninit_use] */
	bfd->nbr_addr = nbr_addr;
}

static void
bfd_srcip_handler(const vector_t *strvec)
{
	bfd_t *bfd = current_bfd;
	sockaddr_t src_addr;

	assert(strvec);
	assert(bfd_data);

	if (inet_stosockaddr(strvec_slot(strvec, 1), NULL, &src_addr)) {
		report_config_error(CONFIG_GENERAL_ERROR,
			    "Configuration error: BFD instance %s has"
			    " malformed source address %s, ignoring",
			    bfd->iname, strvec_slot(strvec, 1));
	} else {
		/* coverity[uninit_use] */
		bfd->src_addr = src_addr;
	}
}

static void
bfd_minrx_handler(const vector_t *strvec)
{
	bfd_t *bfd = current_bfd;
	unsigned value;

	assert(strvec);
	assert(bfd_data);

	if (!read_decimal_unsigned_strvec(strvec, 1, &value, BFD_MINRX_MIN * 1000, BFD_MINRX_MAX * 1000, 3, false)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: BFD instance %s"
			    " min_rx value %s is not valid (must be in range"
			    " [%u-%u]), ignoring", bfd->iname, strvec_slot(strvec, 1),
			    BFD_MINRX_MIN, BFD_MINRX_MAX);
		return;
	}

	bfd->local_min_rx_intv = value;

	if (value > BFD_MINRX_MAX_SENSIBLE * 1000)
		log_message(LOG_INFO, "Configuration warning: BFD instance %s"
			    " min_rx value %s is larger than max sensible (%u)",
			    bfd->iname, strvec_slot(strvec, 1), BFD_MINRX_MAX_SENSIBLE);
}

static void
bfd_mintx_handler(const vector_t *strvec)
{
	bfd_t *bfd = current_bfd;
	unsigned value;

	assert(strvec);
	assert(bfd_data);

	if (!read_decimal_unsigned_strvec(strvec, 1, &value, BFD_MINTX_MIN * 1000, BFD_MINTX_MAX * 1000, 3, false)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: BFD instance %s"
			    " min_tx value %s is not valid (must be in range"
			    " [%u-%u]), ignoring", bfd->iname, strvec_slot(strvec, 1),
			    BFD_MINTX_MIN, BFD_MINTX_MAX);
		return;
	}

	bfd->local_min_tx_intv = value;

	if (value > BFD_MINTX_MAX_SENSIBLE * 1000)
		log_message(LOG_INFO, "Configuration warning: BFD instance %s"
			    " min_tx value %s is larger than max sensible (%u)",
			    bfd->iname, strvec_slot(strvec, 1), BFD_MINTX_MAX_SENSIBLE);
}

static void
bfd_idletx_handler(const vector_t *strvec)
{
	bfd_t *bfd = current_bfd;
	unsigned value;

	assert(strvec);
	assert(bfd_data);

	if (!read_decimal_unsigned_strvec(strvec, 1, &value, BFD_IDLETX_MIN * 1000, BFD_IDLETX_MAX * 1000, 3, false)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: BFD instance %s"
			    " idle_tx value %s is not valid (must be in range"
			    " [%u-%u]), ignoring", bfd->iname, strvec_slot(strvec, 1),
			    BFD_IDLETX_MIN, BFD_IDLETX_MAX);
		return;
	}

	bfd->local_idle_tx_intv = value;

	if (value > BFD_IDLETX_MAX_SENSIBLE * 1000)
		log_message(LOG_INFO, "Configuration warning: BFD instance %s"
			    " idle_tx value %s is larger than max sensible (%u)",
			    bfd->iname, strvec_slot(strvec, 1), BFD_IDLETX_MAX_SENSIBLE);
}

static void
bfd_multiplier_handler(const vector_t *strvec)
{
	bfd_t *bfd = current_bfd;
	unsigned value;

	assert(strvec);
	assert(bfd_data);

	if (!read_unsigned_strvec(strvec, 1, &value, BFD_MULTIPLIER_MIN, BFD_MULTIPLIER_MAX, false))
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: BFD instance %s"
			    " multiplier value %s not valid (must be in range"
			    " [%u-%u]), ignoring", bfd->iname, strvec_slot(strvec, 1),
			    BFD_MULTIPLIER_MIN, BFD_MULTIPLIER_MAX);
	else
		bfd->local_detect_mult = value;
}

static void
bfd_passive_handler(__attribute__((unused)) const vector_t *strvec)
{
	bfd_t *bfd = current_bfd;

	assert(bfd_data);

	bfd->passive = true;
}

static void
bfd_ttl_handler(const vector_t *strvec)
{
	bfd_t *bfd = current_bfd;
	unsigned value;

	assert(strvec);
	assert(bfd_data);

	if (!read_unsigned_strvec(strvec, 1, &value, 1, BFD_TTL_MAX, false))
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: BFD instance %s"
			    " ttl/hoplimit value %s not valid (must be in range"
			    " [1-%d]), ignoring", bfd->iname,
			    strvec_slot(strvec, 1), BFD_TTL_MAX);
	else
		bfd->ttl = value;
}

static void
bfd_maxhops_handler(const vector_t *strvec)
{
	bfd_t *bfd = current_bfd;
	int value;

	assert(strvec);
	assert(bfd_data);

	if (!read_int_strvec(strvec, 1, &value, -1, BFD_TTL_MAX, false))
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: BFD instance %s"
			    " max_hops value %s not valid (must be in range"
			    " [-1-%d]), ignoring", bfd->iname,
			    strvec_slot(strvec, 1), BFD_TTL_MAX);
	else
		bfd->max_hops = value;
}

static void
bfd_multihop_handler(const vector_t *strvec)
{
	bfd_t *bfd = current_bfd;
	int value;

	assert(strvec);
	assert(bfd_data);

	if (vector_size(strvec) == 1)
		value = 1;
	else {
		value = check_true_false(vector_slot(strvec, 1));
		if (value == -1) {
			report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: BFD instance %s"
				    " multihop setting not valid - %s", bfd->iname, strvec_slot(strvec, 1));
			return;
		}
	}

	bfd->multihop = value;

	/* Neighbour IP may have already been specified */
#ifndef USE_SOCKADDR_STORAGE
	if (bfd->nbr_addr.ss_family == AF_INET)
		bfd->nbr_addr.in.sin_port = htons(atoi(bfd->multihop ? BFD_MULTIHOP_CONTROL_PORT : BFD_CONTROL_PORT));
	else if (bfd->nbr_addr.ss_family == AF_INET6)
		bfd->nbr_addr.in6.sin6_port = htons(atoi(bfd->multihop ? BFD_MULTIHOP_CONTROL_PORT : BFD_CONTROL_PORT));
#else
	if (bfd->nbr_addr.ss_family == AF_INET)
		PTR_CAST(struct sockaddr_in, &bfd->nbr_addr)->sin_port = htons(atoi(bfd->multihop ? BFD_MULTIHOP_CONTROL_PORT : BFD_CONTROL_PORT));
	else if (bfd->nbr_addr.ss_family == AF_INET6)
		PTR_CAST(struct sockaddr_in6, &bfd->nbr_addr)->sin6_port = htons(atoi(bfd->multihop ? BFD_MULTIHOP_CONTROL_PORT : BFD_CONTROL_PORT));
#endif
}

/* Checks for minimum configuration requirements */
#ifdef _WITH_VRRP_
static void
bfd_vrrp_end_handler(void)
{
	vrrp_tracked_bfd_t *tbfd = current_bfd;

	if (specified_event_processes && !__test_bit(DAEMON_VRRP, &specified_event_processes)) {
		free_vrrp_tracked_bfd(tbfd);
		return;
	}

	list_add_tail(&tbfd->e_list, &vrrp_data->vrrp_track_bfds);
}
#endif

#ifdef _WITH_LVS_
static void
bfd_checker_end_handler(void)
{
	checker_tracked_bfd_t *cbfd = current_bfd;

	if (specified_event_processes && !__test_bit(DAEMON_CHECKERS, &specified_event_processes)) {
		free_checker_bfd(cbfd);
		return;
	}

	list_add_tail(&cbfd->e_list, &check_data->track_bfds);
}
#endif

static void
bfd_end_handler(void)
{
	bfd_t *bfd = current_bfd;

	if (!bfd->nbr_addr.ss_family) {
		report_config_error(CONFIG_GENERAL_ERROR,
			    "Configuration error: BFD instance %s has"
			    " no %s address set, disabling instance",
			    bfd->iname, neighbor_str);
		free_bfd(bfd);
		return;
	}

	if (bfd->src_addr.ss_family
	    && bfd->nbr_addr.ss_family != bfd->src_addr.ss_family) {
		report_config_error(CONFIG_GENERAL_ERROR,
			    "Configuration error: BFD instance %s source"
			    " address %s and %s address %s"
			    " are not of the same family, disabling instance",
			    bfd->iname, inet_sockaddrtos(&bfd->src_addr),
			    neighbor_str, inet_sockaddrtos(&bfd->nbr_addr));
		free_bfd(bfd);
		return;
	}

	if (find_bfd_by_addr(&bfd->nbr_addr, &bfd->src_addr, bfd->multihop)) {
		if (bfd->src_addr.ss_family) {
			char src_addr[INET6_ADDRSTRLEN];
			strcpy(src_addr, inet_sockaddrtos(&bfd->src_addr));
			report_config_error(CONFIG_GENERAL_ERROR,
				    "Configuration error: BFD instance %s has"
				    " duplicate source/%s address %s/%s, ignoring instance",
				    bfd->iname, neighbor_str, src_addr, inet_sockaddrtos(&bfd->nbr_addr));
		} else
			report_config_error(CONFIG_GENERAL_ERROR,
				    "Configuration error: BFD instance %s has"
				    " duplicate %s address %s, ignoring instance",
				    bfd->iname, neighbor_str, inet_sockaddrtos(&bfd->nbr_addr));
		free_bfd(bfd);
		return;
	}

	if (!bfd->ttl)
		bfd->ttl = bfd->nbr_addr.ss_family == AF_INET ? BFD_CONTROL_TTL : BFD_CONTROL_HOPLIMIT;
	if (bfd->max_hops > bfd->ttl) {
		report_config_error(CONFIG_GENERAL_ERROR, "BFD instance %s: max_hops exceeds ttl/hoplimit - setting to ttl/hoplimit", bfd->iname);
		bfd->max_hops = bfd->ttl;
	}

#ifdef _WITH_VRRP_
	if (!specified_event_processes || __test_bit(DAEMON_VRRP, &specified_event_processes))
		bfd->vrrp = true;

#ifdef _ONE_PROCESS_DEBUG_
	bfd_vrrp_end_handler();
#endif
#endif
#ifdef _WITH_LVS_
	if (!specified_event_processes || __test_bit(DAEMON_CHECKERS, &specified_event_processes))
		bfd->checker = true;

#ifdef _ONE_PROCESS_DEBUG_
	bfd_checker_end_handler();
#endif
#endif

	list_add_tail(&bfd->e_list, &bfd_data->bfd);
}

#ifdef _WITH_VRRP_
#ifndef _ONE_PROCESS_DEBUG_
static void
bfd_vrrp_handler(const vector_t *strvec)
{
	if (!strvec)
		return;

	current_bfd = alloc_vrrp_tracked_bfd(strvec_slot(strvec, 1), &vrrp_data->vrrp_track_bfds);

	specified_event_processes = 0;
}
#endif

static void
bfd_vrrp_weight_handler(const vector_t *strvec)
{
	vrrp_tracked_bfd_t *tbfd = current_bfd;
	int value;

	assert(strvec);
	assert(vrrp_data);

	if (!read_int_strvec(strvec, 1, &value, -253, 253, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: BFD instance %s"
			    " weight value %s not valid (must be in range"
			    " [%d-%d]), ignoring", tbfd->bname, strvec_slot(strvec, 1),
			    -253, 253);
	} else
		tbfd->weight = value;

	if (vector_size(strvec) >= 3) {
		if (strcmp(strvec_slot(strvec, 2), "reverse"))
			report_config_error(CONFIG_GENERAL_ERROR, "Configuration error: BFD instance %s"
				    " unknown weight option %s", tbfd->bname, strvec_slot(strvec, 2));
		else
			tbfd->weight_reverse = true;
	}
}

static void
bfd_event_vrrp_handler(__attribute__((unused)) const vector_t *strvec)
{
	__set_bit(DAEMON_VRRP, &specified_event_processes);
}
#endif

#ifdef _WITH_LVS_
#ifndef _ONE_PROCESS_DEBUG_
static void
bfd_checker_handler(const vector_t *strvec)
{
	checker_tracked_bfd_t *cbfd;
	char *name;

	if (!strvec)
		return;

	name = vector_slot(strvec, 1);

	list_for_each_entry(cbfd, &check_data->track_bfds, e_list) {
		if (!strcmp(name, cbfd->bname)) {
			report_config_error(CONFIG_GENERAL_ERROR, "BFD %s already specified", name);
			skip_block(true);
			return;
		}
	}

	PMALLOC(cbfd);
	INIT_LIST_HEAD(&cbfd->e_list);
	INIT_LIST_HEAD(&cbfd->tracking_rs);
	cbfd->bname = STRDUP(name);

	current_bfd = cbfd;

	specified_event_processes = 0;
}
#endif

static void
bfd_event_checker_handler(__attribute__((unused)) const vector_t *strvec)
{
	__set_bit(DAEMON_CHECKERS, &specified_event_processes);
}
#endif

static void
ignore_handler(__attribute__((unused)) const vector_t *strvec)
{
	return;
}

static void
install_keyword_conditional(const char *string, void (*handler) (const vector_t *), bool want_handler)
{
	install_keyword(string, want_handler ? handler : ignore_handler);
}

void
init_bfd_keywords(bool active)
{
	bool bfd_handlers = false;

	/* This will be called with active == false for parent process,
	 * for bfd, checker and vrrp process active will be true, but they are interested
	 * in different keywords. */
#ifndef _ONE_PROCESS_DEBUG_
	if (prog_type == PROG_TYPE_BFD || !active)
#endif
	{
		install_keyword_root("bfd_instance", &bfd_handler, active, VPP &current_bfd);
		install_level_end_handler(bfd_end_handler);
		bfd_handlers = true;
	}
#ifndef _ONE_PROCESS_DEBUG_
#ifdef _WITH_VRRP_
	else if (prog_type == PROG_TYPE_VRRP) {
		install_keyword_root("bfd_instance", &bfd_vrrp_handler, active, VPP &current_bfd);
		install_level_end_handler(bfd_vrrp_end_handler);
	}
#endif
#ifdef _WITH_LVS_
	else if (prog_type == PROG_TYPE_CHECKER) {
		install_keyword_root("bfd_instance", &bfd_checker_handler, active, VPP &current_bfd);
		install_level_end_handler(bfd_checker_end_handler);
	}
#endif
#endif

	install_keyword_conditional("source_ip", &bfd_srcip_handler, bfd_handlers);
	install_keyword_conditional("neighbor_ip", &bfd_nbrip_handler, bfd_handlers);
	install_keyword_conditional("neighbour_ip", &bfd_nbrip_handler, bfd_handlers);
	install_keyword_conditional("min_rx", &bfd_minrx_handler, bfd_handlers);
	install_keyword_conditional("min_tx", &bfd_mintx_handler, bfd_handlers);
	install_keyword_conditional("idle_tx", &bfd_idletx_handler, bfd_handlers);
	install_keyword_conditional("multiplier", &bfd_multiplier_handler, bfd_handlers);
	install_keyword_conditional("passive", &bfd_passive_handler, bfd_handlers);
	install_keyword_conditional("ttl", &bfd_ttl_handler, bfd_handlers);
	install_keyword_conditional("hoplimit", &bfd_ttl_handler, bfd_handlers);
	install_keyword_conditional("max_hops", &bfd_maxhops_handler, bfd_handlers);
	install_keyword_conditional("multihop", &bfd_multihop_handler, bfd_handlers);
#ifdef _WITH_VRRP_
	install_keyword_conditional("weight", &bfd_vrrp_weight_handler,
#ifdef _ONE_PROCESS_DEBUG_
									true
#else
									prog_type == PROG_TYPE_VRRP
#endif
												   );
	install_keyword("vrrp", &bfd_event_vrrp_handler);
#endif
#ifdef _WITH_LVS_
	install_keyword("checker", &bfd_event_checker_handler);
#endif
}

const vector_t *
bfd_init_keywords(void)
{
	/* global definitions mapping */
	init_global_keywords(reload);

	init_bfd_keywords(true);
#ifdef _WITH_LVS_
	init_check_keywords(false);
#endif
#ifdef _WITH_VRRP_
	init_vrrp_keywords(false);
#endif
#if defined _WITH_VRRP_ || defined _WITH_LVS_
	add_track_file_keywords(false);
#endif

	return keywords;
}
