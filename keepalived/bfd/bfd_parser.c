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

#include <assert.h>

#include "bfd.h"
#include "bfd_data.h"
#include "bfd_parser.h"
#include "logger.h"
#include "parser.h"
#include "global_parser.h"
#include "utils.h"
#include "global_data.h"

#ifdef _WITH_LVS_
#include "check_parser.h"
#endif
#ifdef _WITH_VRRP_
#include "vrrp_parser.h"
#include "vrrp_track.h"
#include "vrrp_data.h"
#endif
#include "main.h"

static void
bfd_handler(vector_t *strvec)
{
	char *name;

	if (!strvec) {
		have_bfd_instances = true;
		return;
	}

	name = vector_slot(strvec, 1);

	if (strlen(name) >= BFD_INAME_MAX) {
		log_message(LOG_ERR, "Configuration error: BFD instance %s"
			    " name too long (maximum length is %i"
			    " characters) - ignoring", name,
			    BFD_INAME_MAX - 1);
		skip_block();
		return;
	}

	if (find_bfd_by_name(name)) {
		log_message(LOG_ERR,
			    "Configuration error: BFD instance %s"
			    " already configured - ignoring", name);
		skip_block();
		return;
	}

	alloc_bfd(name);
}

static void
bfd_nbrip_handler(vector_t *strvec)
{
	bfd_t *bfd;
	int ret;
	struct sockaddr_storage nbr_addr;

	assert(strvec);
	assert(bfd_data);

	bfd = LIST_TAIL_DATA(bfd_data->bfd);
	assert(bfd);

	ret = inet_stosockaddr(vector_slot(strvec, 1), BFD_CONTROL_PORT, &nbr_addr);
	if (ret < 0) {
		log_message(LOG_ERR,
			    "Configuration error: BFD instance %s has"
			    " malformed neighbor address %s, ignoring instance",
			    bfd->iname, FMT_STR_VSLOT(strvec, 1));
		list_del(bfd_data->bfd, bfd);
		skip_block();
		return;
	} else if (find_bfd_by_addr(&nbr_addr)) {
		log_message(LOG_ERR,
			    "Configuration error: BFD instance %s has"
			    " duplicate neighbor address %s, ignoring instance",
			    bfd->iname, FMT_STR_VSLOT(strvec, 1));
		list_del(bfd_data->bfd, bfd);
		skip_block();
		return;
	} else
		bfd->nbr_addr = nbr_addr;
}

static void
bfd_srcip_handler(vector_t *strvec)
{
	bfd_t *bfd;
	int ret;
	struct sockaddr_storage src_addr;

	assert(strvec);
	assert(bfd_data);

	bfd = LIST_TAIL_DATA(bfd_data->bfd);
	assert(bfd);

	ret = inet_stosockaddr(vector_slot(strvec, 1), 0, &src_addr);
	if (ret < 0) {
		log_message(LOG_ERR,
			    "Configuration error: BFD instance %s has"
			    " malformed source address %s, ignoring",
			    bfd->iname, FMT_STR_VSLOT(strvec, 1));
	} else
		bfd->src_addr = src_addr;
}

static void
bfd_minrx_handler(vector_t *strvec)
{
	bfd_t *bfd;
	char *endptr;
	unsigned long value;

	assert(strvec);
	assert(bfd_data);

	bfd = LIST_TAIL_DATA(bfd_data->bfd);
	assert(bfd);

	value = strtoul(vector_slot(strvec, 1), &endptr, 10);

	if (*endptr || value < BFD_MINRX_MIN || value > BFD_MINRX_MAX)
		log_message(LOG_ERR, "Configuration error: BFD instance %s"
			    " min_rx value %s is not valid (must be in range"
			    " [%u-%u]), ignoring", bfd->iname, FMT_STR_VSLOT(strvec, 1),
			    BFD_MINRX_MIN, BFD_MINRX_MAX);
	else
		bfd->local_min_rx_intv = value * 1000U;

	if (value > BFD_MINRX_MAX_SENSIBLE)
		log_message(LOG_INFO, "Configuration warning: BFD instance %s"
			    " min_rx value %lu is larger than max sensible (%u)",
			    bfd->iname, value, BFD_MINRX_MAX_SENSIBLE);
}

static void
bfd_mintx_handler(vector_t *strvec)
{
	bfd_t *bfd;
	char *endptr;
	unsigned long value;

	assert(strvec);
	assert(bfd_data);

	bfd = LIST_TAIL_DATA(bfd_data->bfd);
	assert(bfd);

	value = strtoul(vector_slot(strvec, 1), &endptr, 10);

	if (*endptr || value < BFD_MINTX_MIN || value > BFD_MINTX_MAX)
		log_message(LOG_ERR, "Configuration error: BFD instance %s"
			    " min_tx value %s is not valid (must be in range"
			    " [%u-%u]), ignoring", bfd->iname, FMT_STR_VSLOT(strvec, 1),
			    BFD_MINTX_MIN, BFD_MINTX_MAX);
	else
		bfd->local_min_tx_intv = value * 1000U;

	if (value > BFD_MINTX_MAX_SENSIBLE)
		log_message(LOG_INFO, "Configuration warning: BFD instance %s"
			    " min_tx value %lu is larger than max sensible (%u)",
			    bfd->iname, value, BFD_MINTX_MAX_SENSIBLE);
}

static void
bfd_idletx_handler(vector_t *strvec)
{
	bfd_t *bfd;
	char *endptr;
	unsigned long value;

	assert(strvec);
	assert(bfd_data);

	bfd = LIST_TAIL_DATA(bfd_data->bfd);
	assert(bfd);

	value = strtoul(vector_slot(strvec, 1), &endptr, 10);

	if (*endptr || value < BFD_IDLETX_MIN || value > BFD_IDLETX_MAX)
		log_message(LOG_ERR, "Configuration error: BFD instance %s"
			    " idle_tx value %s is not valid (must be in range"
			    " [%u-%u]), ignoring", bfd->iname, FMT_STR_VSLOT(strvec, 1),
			    BFD_IDLETX_MIN, BFD_IDLETX_MAX);
	else
		bfd->local_idle_tx_intv = value * 1000U;

	if (value > BFD_IDLETX_MAX_SENSIBLE)
		log_message(LOG_INFO, "Configuration warning: BFD instance %s"
			    " idle_tx value %lu is larger than max sensible (%u)",
			    bfd->iname, value, BFD_IDLETX_MAX_SENSIBLE);
}

static void
bfd_multiplier_handler(vector_t *strvec)
{
	bfd_t *bfd;
	char *endptr;
	unsigned long value;

	assert(strvec);
	assert(bfd_data);

	bfd = LIST_TAIL_DATA(bfd_data->bfd);
	assert(bfd);

	value = strtoul(vector_slot(strvec, 1), &endptr, 10);

	if (*endptr || value < BFD_MULTIPLIER_MIN || value > BFD_MULTIPLIER_MAX)
		log_message(LOG_ERR, "Configuration error: BFD instance %s"
			    " multiplier value %s not valid (must be in range"
			    " [%u-%u]), ignoring", bfd->iname, FMT_STR_VSLOT(strvec, 1),
			    BFD_MULTIPLIER_MIN, BFD_MULTIPLIER_MAX);
	else
		bfd->local_detect_mult = value;
}

static void
bfd_passive_handler(__attribute__((unused)) vector_t *strvec)
{
	bfd_t *bfd;

	assert(bfd_data);

	bfd = LIST_TAIL_DATA(bfd_data->bfd);
	assert(bfd);

	bfd->passive = true;
}

static void
bfd_ttl_handler(vector_t *strvec)
{
	bfd_t *bfd;
	char *endptr;
	unsigned long value;

	assert(strvec);
	assert(bfd_data);

	bfd = LIST_TAIL_DATA(bfd_data->bfd);
	assert(bfd);

	value = strtoul(vector_slot(strvec, 1), &endptr, 10);

	if (*endptr || value == 0 || value > BFD_TTL_MAX) {
		log_message(LOG_ERR, "Configuration error: BFD instance %s"
			    " ttl/hoplimit value %s not valid (must be in range"
			    " [1-%u]), ignoring", bfd->iname,
			    FMT_STR_VSLOT(strvec, 1), BFD_TTL_MAX);
	} else
		bfd->ttl = value;
}

static void
bfd_maxhops_handler(vector_t *strvec)
{
	bfd_t *bfd;
	char *endptr;
	long value;

	assert(strvec);
	assert(bfd_data);

	bfd = LIST_TAIL_DATA(bfd_data->bfd);
	assert(bfd);

	value = strtol(vector_slot(strvec, 1), &endptr, 10);

	if (*endptr || value < -1 || value > BFD_TTL_MAX) {
		log_message(LOG_ERR, "Configuration error: BFD instance %s"
			    " max_hops value %s not valid (must be in range"
			    " [-1-%u]), ignoring", bfd->iname,
			    FMT_STR_VSLOT(strvec, 1), BFD_TTL_MAX);
	} else
		bfd->max_hops = value;
}

/* Checks for minimum configuration requirements */
static void
bfd_config_check_handler(void)
{
	bfd_t *bfd = LIST_TAIL_DATA(bfd_data->bfd);

	assert(bfd);

	if (!bfd->nbr_addr.ss_family) {
		log_message(LOG_ERR,
			    "Configuration error: BFD instance %s has"
			    " no neighbor address set, disabling instance",
			    bfd->iname);
		list_del(bfd_data->bfd, bfd);
		return;
	}

	if (bfd->src_addr.ss_family
	    && bfd->nbr_addr.ss_family != bfd->src_addr.ss_family) {
		log_message(LOG_ERR,
			    "Configuration error: BFD instance %s source"
			    " address %s and neighbor address %s"
			    " are not of the same family, disabling instance",
			    bfd->iname, inet_sockaddrtos(&bfd->src_addr)
			    , inet_sockaddrtos(&bfd->nbr_addr));
		list_del(bfd_data->bfd, bfd);
		return;
	}

	if (!bfd->ttl)
		bfd->ttl = bfd->nbr_addr.ss_family == AF_INET ? BFD_CONTROL_TTL : BFD_CONTROL_HOPLIMIT;
	if (bfd->max_hops > bfd->ttl) {
		log_message(LOG_INFO, "BFD instance %s: max_hops exceeds ttl/hoplimit - setting to ttl/hoplimit", bfd->iname);
		bfd->max_hops = bfd->ttl;
	}
}

#ifdef _WITH_VRRP_
static void
bfd_vrrp_handler(vector_t *strvec)
{
	vrrp_tracked_bfd_t *tbfd;
	element e;
	char *name;

	if (!strvec)
		return;

	name = vector_slot(strvec, 1);

	if (strlen(name) >= BFD_INAME_MAX) {
		log_message(LOG_ERR, "Configuration error: BFD instance %s"
			    " name too long (maximum length is %i"
			    " characters), ignoring instance", name,
			    BFD_INAME_MAX - 1);
		skip_block();
		return;
	}

	LIST_FOREACH(vrrp_data->vrrp_track_bfds, tbfd, e) {
		if (!strcmp(tbfd->bname, name)) {
			log_message(LOG_ERR,
				    "Configuration error: BFD instance %s"
				    " already configured,"
				    " ignoring instance", name);
			skip_block();
			return;
		}
	}

	PMALLOC(tbfd);
	strcpy(tbfd->bname, name);
	tbfd->weight = 0;
	tbfd->bfd_up = false;
	list_add(vrrp_data->vrrp_track_bfds, tbfd);
}

static void
bfd_vrrp_weight_handler(vector_t *strvec)
{
	vrrp_tracked_bfd_t *tbfd;
	char *endptr;
	long value;

	assert(strvec);
	assert(vrrp_data);

	tbfd = LIST_TAIL_DATA(vrrp_data->vrrp_track_bfds);
	assert(tbfd);

	value = strtol(vector_slot(strvec, 1), &endptr, 10);

	if (*endptr || value < -253 || value > 253) {
		log_message(LOG_ERR, "Configuration error: BFD instance %s"
			    " weight value %s not valid (must be in range"
			    " [%u-%u]), ignoring", tbfd->bname, FMT_STR_VSLOT(strvec, 1),
			    -253, 253);
	} else
		tbfd->weight = value;
}

static void
ignore_handler(__attribute__((unused)) vector_t *strvec)
{
	return;
}
#endif

void
init_bfd_keywords(bool active)
{
#ifdef _WITH_VRRP_
	if (prog_type != PROG_TYPE_VRRP)
#endif
	{
		install_keyword_root("bfd_instance", &bfd_handler, active);
		install_sublevel_end_handler(bfd_config_check_handler);
		install_keyword("source_ip", &bfd_srcip_handler);
		install_keyword("neighbor_ip", &bfd_nbrip_handler);
		install_keyword("min_rx", &bfd_minrx_handler);
		install_keyword("min_tx", &bfd_mintx_handler);
		install_keyword("idle_tx", &bfd_idletx_handler);
		install_keyword("multiplier", &bfd_multiplier_handler);
		install_keyword("passive", &bfd_passive_handler);
		install_keyword("ttl", &bfd_ttl_handler);
		install_keyword("hoplimit", &bfd_ttl_handler);
		install_keyword("max_hops", &bfd_maxhops_handler);

#ifdef _WITH_VRRP_
		install_keyword("weight", &ignore_handler);
#endif
	}
#ifdef _WITH_VRRP_
	else {
		install_keyword_root("bfd_instance", &bfd_vrrp_handler, active);
		install_keyword("source_ip", &ignore_handler);
		install_keyword("neighbor_ip", &ignore_handler);
		install_keyword("min_rx", &ignore_handler);
		install_keyword("min_tx", &ignore_handler);
		install_keyword("idle_tx", &ignore_handler);
		install_keyword("multiplier", &ignore_handler);
		install_keyword("passive", &ignore_handler);
		install_keyword("ttl", &ignore_handler);
		install_keyword("hoplimit", &ignore_handler);
		install_keyword("max_hops", &ignore_handler);

		install_keyword("weight", &bfd_vrrp_weight_handler);
	}
#endif
}

vector_t *
bfd_init_keywords(void)
{
        /* global definitions mapping */
        init_global_keywords(true);

        init_bfd_keywords(true);
#ifdef _WITH_LVS_
        init_check_keywords(false);
#endif
#ifdef _WITH_VRRP_
        init_vrrp_keywords(false);
#endif

        return keywords;
}
