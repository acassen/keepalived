/*
 * Soft:        Vrrpd is an implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Part:        vrrp_print.c program include file.
 *
 * Author:      John Southworth, <john.southworth@vyatta.com>
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
 * Copyright (C) 2012 John Southworth, <john.southworth@vyatta.com>
 */

#include <stdio.h>
#include "vrrp.h"

extern void vrrp_print_list (FILE *f, list l, void (*fptr)(FILE*, void*));
extern void vrrp_print_data(void);
extern void vrrp_print_stats(void);
extern void vrrp_print(FILE *file, void *d);
extern void vgroup_print(FILE *file, void *d);
extern void vscript_print(FILE *file, void *d);
extern void address_print(FILE *file, void *d);
extern void route_print(FILE *file, void *d);
extern void if_print(FILE *file, void *d);
