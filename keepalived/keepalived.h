/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        keepalived.c include file.
 *  
 * Version:     $Id: keepalived.c,v 0.2.1 2000/12/09 $
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

#ifndef KEEPALIVED_H
#define KEEPALIVED_H

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>

#include "cfreader.h"
#include "icmpcheck.h"
#include "tcpcheck.h"
#include "httpget.h"
#include "utils.h"
#include "ipvswrapper.h"

#define LOGBUFFER_LENGTH 100

/* Configuration file home directory */
#define CONF_HOME_DIR "/etc/keepalived/"

/* Sockets connection errors codes */
#define ERROR_SOCKET        0

/* Global variables */
volatile sig_atomic_t keep_going = 1;
virtualserver *lstVS;
int delay_loop = 5;

/* Build version */
#define PROG    "keepalived"
#define VERSION "0.2.1 (12/23, 2000), Alexandre Cassen"

/* prototypes */
void sig_handler(int signum);
void perform_checks(virtualserver * lstptr);
int init_services(virtualserver *lstptr);

#endif
