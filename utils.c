/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        General program utils.
 *
 * Version:     $Id: utils.c,v 0.2.6 2001/03/01 $
 *
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *
 * Changes:
 *              Alexandre Cassen : 2001/03/01 :
 *               <+> Adding daemonpid var to stock running keepalived daemon pid.
 *
 *              Alexandre Cassen : 2000/12/09 : Initial release
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#include "utils.h"

void print_buffer(int count, char *buff)
{
  int i,j,c;
  int printnext=1;

  if(count) {
    if(count%16)
      c=count+(16-count%16);
    else c=count;
  } else
    c=count;

  for(i=0;i<c;i++) {
    if(printnext) {
      printnext--;
      printf("%.4x ",i&0xffff);
    }
    if(i<count)
      printf("%3.2x",buff[i]&0xff);
    else
      printf("   ");
    if(!((i+1)%8)) {
      if((i+1)%16)
        printf(" -");
      else {
        printf("   ");
        for(j=i-15;j<=i;j++)
          if(j<count) {
            if( (buff[j]&0xff) >= 0x20 && (buff[j]&0xff)<=0x7e)
              printf("%c",buff[j]&0xff);
            else printf(".");
          } else printf(" ");
        printf("\n"); printnext=1;
      }
    }
  }
}

void initdaemonpid(int pid)
{
  daemonpid=pid;
}

void logmessage(char *msg)
{
  FILE *logfile;
  time_t hint;
  struct tm *date;

  hint = time((long*)0);
  date = localtime(&hint);

  logfile=fopen(LOGFILE,"ab");
  fprintf(logfile,"[%.2d/%.2d/%.2d - %.2d:%.2d:%.2d] keepalived[%d]: %s",
                  date->tm_mday,
                  date->tm_mon+1,
                  date->tm_year-100,
                  date->tm_hour,
                  date->tm_min,
                  date->tm_sec,
                  daemonpid,msg);
  fclose(logfile);
}
