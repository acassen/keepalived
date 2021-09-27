/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        fuse_interface.h include file
 *
 * Author:      Quentin Armitage, <quentin@armitage.org.uk>
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
 * Copyright (C) 2021-2021 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _KEEPALIVED_FUSE_H
#define _KEEPALIVED_FUSE_H

#include "config.h"

#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>
#include <stdbool.h>


extern const char *tbd_str;

struct ent {
	const char *fname;
	struct ent* entries;
	void (*populate)(void *, fuse_fill_dir_t);
	bool (*set)(const char *, size_t len);
};


extern void *start_fuse(const char *, struct ent *, bool);
extern void stop_fuse(void *, const char *);

#ifdef THREAD_DUMP
extern void register_fuse_thread_addresses(void);
#endif

#endif
