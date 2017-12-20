/*
 * Soft:        Vrrpd is an implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Part:        Output running VRRP state information in JSON format
 *
 * Author:      Damien Clabaut, <Damien.Clabaut@corp.ovh.com>
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
 * Copyright (C) 2017 Damien Clabaut, <Damien.Clabaut@corp.ovh.com>
 * Copyright (C) 2017-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_JSON_H
#define _VRRP_JSON_H

/* Static definitions */
#define SIGJSON (SIGRTMIN + 2)

/* Prototypes */
extern void vrrp_print_json(void);

#endif
