/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Checkers arguments structures definitions.
 *
 * Version:     $Id: check.h,v 0.3.8 2001/11/04 21:41:32 acassen Exp $
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
 */

#ifndef _CHECK_H
#define _CHECK_H

/* http specific thread arguments defs */
struct http_thread_arg {
  int retry_it;                /* current number of get retry */
  int url_it;                  /* current url checked index */
};

/* global thread arguments defs */
struct thread_arg {
  configuration_data *root;    /* pointer to the configuration root data */
  virtualserver *vs;           /* pointer to the checker thread virtualserver */
  realserver *svr;             /* pointer to the checker thread realserver */
  void *checker_arg;           /* pointer to the specific checker arg */
};

#endif
