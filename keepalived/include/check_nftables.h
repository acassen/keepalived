/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        check_nftables.c include file.
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
 * Copyright (C) 2020-2020 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _CHECK_NFTABLES_H
#define _CHECK_NFTABLES_H

#include "config.h"

#include "nftables.h"
#include "check_data.h"

#define	DEFAULT_NFTABLES_IPVS_TABLE	"keepalived_ipvs"
#define DEFAULT_IPVS_NF_START_FWMARK    1000

#ifdef _INCLUDE_UNUSED_CODE_
extern void nft_add_ipvs_entry(const struct sockaddr_storage *, uint16_t, uint32_t);
extern void nft_remove_ipvs_entry(const struct sockaddr_storage *, uint16_t, uint32_t);
#endif
extern void nft_ipvs_end(void);
extern unsigned set_vs_fwmark(virtual_server_t *);
extern void clear_vs_fwmark(virtual_server_t *);
extern void remove_vs_fwmark_entry(virtual_server_t *, virtual_server_group_entry_t *);

#endif
