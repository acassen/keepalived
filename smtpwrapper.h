/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        smtpwrapper.c include file.
 *
 * Version:     $Id: smtpwrapper.h,v 0.2.6 2001/03/01 $
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

#ifndef SMTPWRAPPER_H
#define SMTPWRAPPER_H

#include <signal.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include "cfreader.h"

#define SOCKET_ERROR   0
#define SOCKET_SUCCESS 1
#define SOCKET_TIMEOUT 3

#define SMTP_PORT      "25"

#define SMTP_CONNECT   "220"
#define SMTP_EHLO      "250"
#define SMTP_MAIL_FROM "250"
#define SMTP_RCPT_TO   "250"
#define SMTP_DATA      "354"
#define SMTP_DOT       "250"


#define LOGBUFFER_LENGTH 100
#define BUFFER_LENGTH 1024
#define SMTP_ERROR_CODE_LENGTH 4
#define SMTP_CMD_LENGTH  500

#endif
