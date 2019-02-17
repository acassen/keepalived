/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        bitops.h include file.
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

#ifndef _BITOPS_H
#define _BITOPS_H

#include "config.h"

#include <limits.h>
#include <stdbool.h>

/* Defines */
#define BIT_PER_LONG	(CHAR_BIT * sizeof(unsigned long))
#define BIT_MASK(idx)	(1UL << ((idx) % BIT_PER_LONG))
#define BIT_WORD(idx)	((idx) / BIT_PER_LONG)

/* Helpers */
static inline void __set_bit(unsigned idx, unsigned long *bmap)
{
	bmap[BIT_WORD(idx)] |= BIT_MASK(idx);
}

static inline void __clear_bit(unsigned idx, unsigned long *bmap)
{
	bmap[BIT_WORD(idx)] &= ~BIT_MASK(idx);
}

static inline bool __test_bit(unsigned idx, const unsigned long *bmap)
{
	return !!(bmap[BIT_WORD(idx)] & BIT_MASK(idx));
}

static inline bool __test_and_set_bit(unsigned idx, unsigned long *bmap)
{
	if (__test_bit(idx, bmap))
		return true;

	__set_bit(idx, bmap);

	return false;
}

/* Bits */
enum global_bits {
	LOG_CONSOLE_BIT,
	NO_SYSLOG_BIT,
	DONT_FORK_BIT,
	DUMP_CONF_BIT,
#ifdef _WITH_VRRP_
	DONT_RELEASE_VRRP_BIT,
	RELEASE_VIPS_BIT,
#endif
#ifdef _WITH_LVS_
	DONT_RELEASE_IPVS_BIT,
#endif
	LOG_DETAIL_BIT,
	LOG_EXTRA_DETAIL_BIT,
	DONT_RESPAWN_BIT,
#ifdef _MEM_CHECK_
	MEM_ERR_DETECT_BIT,
#ifdef _MEM_CHECK_LOG_
	MEM_CHECK_LOG_BIT,
#endif
#endif
#ifdef _WITH_LVS_
	LOG_ADDRESS_CHANGES,
#endif
	CONFIG_TEST_BIT,
};

#endif
