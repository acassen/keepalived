/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Pid file lock utils.
 *
 * Version:     $Id: pidfile.c,v 0.2.6 2001/03/05 $
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

#include "pidfile.h"

int pidfile_write(int pid)
{
  FILE *pidfile = fopen(PIDFILENAME,"w");

  if(!pidfile) {
    logmessage("pidfile_write : Can not open pidfile\n");
    return(0);
  }
  fprintf(pidfile,"%d\n",pid);
  fclose(pidfile);
  return(1);
}

void pidfile_rm()
{
  unlink(PIDFILENAME);
}

int keepalived_running()
{
  FILE *pidfile;

  if ((pidfile=fopen(PIDFILENAME,"r")) == NULL)
    return 0;

  fclose(pidfile);
  return 1;
}
