/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        General program utils.
 *
 * Version:     $Id: utils.c,v 0.5.9 2002/05/30 16:05:31 acassen Exp $
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

char *ip_ntoa(uint32_t ip)
{
  static char buf[20];
  unsigned char *bytep;

  bytep = (unsigned char *) &(ip);
  sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
  return buf;
}
