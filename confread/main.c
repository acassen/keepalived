/* 
 * Soft:        Keepalived is a failover program for the LVS project 
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Main program structure.
 *  
 * Version:     $Id: keepalived.c,v 0.2.3 2001/01/01 $
 * 
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *              
 * Changes:       
 *         Alexandre Cassen : 2001/01/01 :
 *          <+> Change the signalhandling.
 *
 *          Alexandre Cassen : 2000/12/09 : Initial release
 *              
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */             

#include "main.h"

int main(int argc, char **argv)
{
  int delay_loop=60;
  printf(PROG" v"VERSION"\n");

  if (chdir(CONF_HOME_DIR)) {
    fprintf(stderr,"%s: ",CONF_HOME_DIR);
    perror(NULL);
    exit(1);
  }

  if ((confDATA=(configuration_data *)ConfReader(confDATA)) == NULL) {
    exit(0);
  }

  PrintConf(confDATA);
  ClearConf(confDATA);

  return 0;
}
