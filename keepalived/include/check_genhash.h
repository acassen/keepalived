/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_genhash.c include file.
 *
 * Authors:     Alexandre Cassen, <acassen@linux-vs.org>
 *              Jan Holmberg, <jan@artech.net>
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

#ifndef _CHECK_GENHASH_H
#define _CHECK_GENHASH_H

#include <stdbool.h>

/* options bits */
enum genhash_option_bits {
        GENHASH_SERVER_BIT,
        GENHASH_PORT_BIT,
        GENHASH_URL_BIT,
        GENHASH_SSL_BIT,
        GENHASH_SNI_BIT,
        GENHASH_HASH_METHOD_BIT,
        GENHASH_VHOST_BIT,
        GENHASH_FWMARK_BIT,
        GENHASH_PROTO_BIT,
        GENHASH_TIMEOUT_BIT,
};

/* Define prototypes */
extern void check_genhash(bool, int, char **);

#endif
