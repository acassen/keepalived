/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        pidfile utility.
 *
 * Version:     $Id: pidfile.c,v 0.5.3 2002/02/24 23:50:11 acassen Exp $
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

#include "pidfile.h"

/* Create the runnnig daemon pidfile */
int pidfile_write(int pid)
{
  FILE *pidfile = fopen(PIDFILENAME,"w");

  if(!pidfile) {
    syslog(LOG_INFO,"pidfile_write : Can not open pidfile");
    return 0;
  }
  fprintf(pidfile,"%d\n",pid);
  fclose(pidfile);
  return 1;
}

/* Remove the running daemon pidfile */
void pidfile_rm(void)
{
  unlink(PIDFILENAME);
}

/* return the daemon running state */
int keepalived_running(void)
{
  FILE *pidfile = fopen(PIDFILENAME,"r");
  pid_t pid;

  /* No pidfile */
  if (!pidfile) return 0;

  fscanf(pidfile,"%d",&pid);
  fclose(pidfile);

  /* If no process is attached to pidfile, remove it */
  if (kill(pid,0)) {
    syslog(LOG_INFO,"Remove a zomby pid file %s.",PIDFILENAME);
    pidfile_rm();
    return 0;
  }

  syslog(LOG_INFO,"daemon is already running");
  return 1;
}
