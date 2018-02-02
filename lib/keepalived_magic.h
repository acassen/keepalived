/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        keepalived_magic.c include file.
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
 * Copyright (C) 2017-2017 Alexandre Cassen, <acassen@linux-vs.org>
 */

#ifndef _KEEPALIVED_MAGIC_H
#define _KEEPALIVED_MAGIC_H

#ifdef _HAVE_LIBMAGIC_
#include <magic.h>

#include "logger.h"

static inline magic_t
ka_magic_open(void)
{
	magic_t magic = magic_open(MAGIC_PRESERVE_ATIME | MAGIC_ERROR | MAGIC_NO_CHECK_CDF | MAGIC_NO_CHECK_COMPRESS);
	if (!magic)
		log_message(LOG_INFO, "Unable to open magic");
	else if (magic_load(magic, NULL)) {
		log_message(LOG_INFO, "Unable to load magic database");
		magic_close(magic);
		magic = NULL;
	}

	return magic;
}

static inline void
ka_magic_close(magic_t magic)
{
	magic_close(magic);
}

#else

/* This simplifies code when we don't have libmagic */
typedef void* magic_t;

static inline magic_t
ka_magic_open(void)
{
	return NULL;
}

static inline void
ka_magic_close(__attribute__((unused)) magic_t magic)
{
}

#endif

#endif
