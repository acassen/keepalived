/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        utils.c include file.
 *
 * Version:     $Id: utils.h,v 0.2.1 2000/12/09 $
 *
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *
 * Changes:
 *              Alexandre Cassen      :       Initial release
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#ifndef UTILS_H
#define UTILS_H

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <termios.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netdb.h>
#include <string.h>

#define LOGFILE       "log/keepalived.log"

/* Globals defs */
int daemonpid;

#endif
