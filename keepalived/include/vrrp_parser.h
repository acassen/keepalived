/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vrrp_parser.c include file.
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
 * Copyright (C) 2001-2016 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_PARSER_H
#define _VRRP_PARSER_H

/* Global include */
#include <stdbool.h>

/* local include */
#include "vector.h"
#include "vrrp.h"


extern vrrp_t *current_vrrp;
extern vrrp_sgroup_t *current_vsyncg;

/* Prototypes */
extern const vector_t *vrrp_init_keywords(void);
extern void init_vrrp_keywords(bool);

#endif
