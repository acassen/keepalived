/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Routing table names parser/reader. Place into the dynamic
 *              data structure representation the table names and ids.
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

#ifndef _READ_RTTABLES_H
#define _READ_RTTABLES_H

#include <stdbool.h>
#include <stdint.h>

extern void clear_rt_names(void);
#ifdef _HAVE_FIB_ROUTING_
extern bool find_rttables_table(const char *, uint32_t *);
extern bool find_rttables_dsfield(const char *, uint8_t *);
extern bool find_rttables_realms(const char *, uint32_t *);
#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
extern bool find_rttables_group(const char *, uint32_t *);
#endif
extern bool find_rttables_proto(const char *, uint8_t *);
extern bool find_rttables_rtntype(const char *, uint8_t *);
#endif
extern bool find_rttables_scope(const char *, uint8_t *);

extern const char *get_rttables_scope(uint32_t);
#ifdef _HAVE_FIB_ROUTING_
#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
extern const char *get_rttables_group(uint32_t);
#endif
extern const char *get_rttables_rtntype(uint8_t);
#endif

#endif
