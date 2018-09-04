/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        bfd_daemon.c include file.
 *
 * Author:      Ilya Voronin, <ivoronin@gmail.com>
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
 * Copyright (C) 2015-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _BFD_DAEMON_H_
#define _BFD_DAEMON_H_

#define PROG_BFD "Keepalived_bfd"

#ifdef _WITH_VRRP_
extern int bfd_vrrp_event_pipe[2];
#endif
#ifdef _WITH_LVS_
extern int bfd_checker_event_pipe[2];
#endif

extern void open_bfd_pipes(void);
extern int start_bfd_child(void);
extern void bfd_validate_config(void);
#ifdef THREAD_DUMP
extern void register_bfd_parent_addresses(void);
#endif

#endif				/* _BFD_DAEMON_H_ */
