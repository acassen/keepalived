/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Main program include file.
 *
 * Version:     $Id: main.h,v 0.4.9 2001/12/10 10:52:33 acassen Exp $
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

#ifndef _MAIN_H
#define _MAIN_H

/* global includes */
#include <sys/stat.h>
#include <sys/wait.h>
#include <popt.h>

/* local includes */
#include "utils.h"
#include "pidfile.h"
#include "cfreader.h"
#include "scheduler.h"
#include "ipwrapper.h"
#include "smtp.h"
#include "vrrp.h"
#include "check_ssl.h"

/* global var */
thread_master *master;
unsigned int debug;

/* SSL support */
extern void clear_ssl(SSL_DATA *ssl);
extern SSL_DATA *init_ssl_ctx(SSL_DATA *ssl);

/* Build version */
#define PROG    "keepalived"
#define VERSION "0.4.9 (10/12, 2001)"

#endif
