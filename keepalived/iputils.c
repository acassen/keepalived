/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        IP packets Utilities.
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

#include "iputils.h"

int in_cksum(register unsigned short *ptr , int nbytes)
{
  register long sum;
  u_short oddbyte;
  register u_short answer;

  sum = 0;
  while (nbytes > 1)  {
    sum += *ptr++;
    nbytes -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nbytes == 1) {
    oddbyte = 0;                                /* make sure top half is zero */
    *((u_char *) &oddbyte) = *(u_char *)ptr;    /* one byte only */
    sum += oddbyte;
  }

  /* Add back carry outs from top 16 bits to low 16 bits. */
  sum  = (sum >> 16) + (sum & 0xffff);  /* add high-16 to low-16 */
  sum += (sum >> 16);                   /* add carry */
  answer = ~sum;                        /* ones-complement, then truncate to 16 bits */
  return(answer);
}

int hostToaddr(char *host, u_long *val)
{
  long in_addr ;
  struct hostent *hp;

  if( (in_addr = inet_addr(host)) != -1 ) {
    *val = in_addr;
    return 0;
  } else {
    while( (hp=gethostbyname(host)) == (struct hostent *)0 ) {
      if( h_errno == HOST_NOT_FOUND ) {
        return -1;
      }
      if( h_errno == TRY_AGAIN ) {
        continue;
      }
      if( h_errno == NO_ADDRESS ) {
        return -1;
      }
    }
    bcopy( (const void *)hp->h_addr , (void *)val , hp->h_length );
    return 0;
  }
}
