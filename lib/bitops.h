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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@linux-vs.org>
 */

#ifndef _BITOPS_H
#define _BITOPS_H

#include <limits.h>

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

static inline bool __test_bit(unsigned idx, unsigned long *bmap)
{
	return !!(bmap[BIT_WORD(idx)] & BIT_MASK(idx));
}

/* Bits */
enum global_bits {
	LOG_CONSOLE_BIT,
	DONT_FORK_BIT,
	DUMP_CONF_BIT,
	DONT_RELEASE_VRRP_BIT,
	DONT_RELEASE_IPVS_BIT,
	LOG_DETAIL_BIT,
	DONT_RESPAWN_BIT,
	RELEASE_VIPS_BIT,
	MEM_ERR_DETECT_BIT,
#ifdef _MEM_CHECK_LOG_
	MEM_CHECK_LOG_BIT,
#endif
};

#endif
