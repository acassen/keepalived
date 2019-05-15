/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        container.h include file.
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
 *
 * Copyright (C) 2019-2019 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _CONTAINER_H
#define _CONTAINER_H

/* Copy from linux kernel 2.6 source (kernel.h, stddef.h) */

#ifndef offsetof
# define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

/*
 * container_of - cast a member of a structure out to the containing structure
 *
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#ifndef container_of
# define container_of(ptr, type, member) ({	\
	 typeof( ((type *)0)->member ) *__mptr = (ptr);  \
	 (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#ifndef container_of_const
# define container_of_const(ptr, type, member) ({	\
	 const typeof( ((type *)0)->member ) *__mptr = (ptr);  \
	 (type *)( (const char *)__mptr - offsetof(type,member) );})
#endif

#endif
