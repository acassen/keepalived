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

/* Defines */
#define BIT_PER_LONG	32
#define BIT_MASK(idx)	(1UL << ((idx) % BIT_PER_LONG))
#define BIT_WORD(idx)	((idx) / BIT_PER_LONG)

/* Helpers */
static inline void __set_bit(int idx, unsigned long *bmap)
{
	unsigned long mask = BIT_MASK(idx);
	unsigned long *p = ((unsigned long *)bmap) + BIT_WORD(idx);

	*p |= mask;
}

static inline void __clear_bit(int idx, unsigned long *bmap)
{
	unsigned long mask = BIT_MASK(idx);
	unsigned long *p = ((unsigned long *)bmap) + BIT_WORD(idx);

	*p &= ~mask;
}

static inline int __test_bit(int idx, unsigned long *bmap)
{
	unsigned long mask = BIT_MASK(idx);
	unsigned long *p = ((unsigned long *)bmap) + BIT_WORD(idx);

	return *p & mask;
}

/* Bits */
enum global_bits {
	LOG_CONSOLE_BIT = 0,
	DONT_FORK_BIT = 1,
	DUMP_CONF_BIT = 2,
	DONT_RELEASE_VRRP_BIT = 3,
	DONT_RELEASE_IPVS_BIT = 4,
	LOG_DETAIL_BIT = 5,
	DONT_RESPAWN_BIT = 6,
	RELEASE_VIPS_BIT = 7,
	MEM_ERR_DETECT_BIT = 8,
};

#endif
