/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        ipfwwrapper.c include file.
 *  
 * Version:     $Id: ipfwwrappercmd.h,v 0.2.7 2001/03/30 $
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

#ifndef IPFWWRAPPERCMD_H
#define IPFWWRAPPERCMD_H

/* Cmd codes */
#define IP_FW_CMD_ADD 0x0001
#define IP_FW_CMD_DEL 0x0002

/* Return codes */
#define IPFWNOTDEFINED 0x0003
#define IPFWSVREXIST   0x0004
#define IPFWNODEST     0x0005

#endif
