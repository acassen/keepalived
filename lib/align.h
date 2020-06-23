/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        align.h include file.
 *
 * Author:      Quentin Armitage <quentin@armitage.org.uk>
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
 * Copyright (C) 2020-2020 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _ALIGN_H
#define _ALIGN_H

#include "config.h"

#ifdef CHECK_CAST_ALIGN
#include "logger.h"
#endif

#ifdef CAST_VIA_VOID
#define __CAST_PTR(__const) (__const void *)
#define PTR_CAST_ASSIGN			(void *)
#define PTR_CAST_ASSIGN_CONST		(const void *)
#else
#define __CAST_PTR(__const)
#define PTR_CAST_ASSIGN
#define PTR_CAST_ASSIGN_CONST
#endif

#ifdef CHECK_CAST_ALIGN
#define PTR_CAST_ALL(__type, __ptr, __const) ({		\
		__const void *sav_ptr = __ptr;			\
		if ((long)sav_ptr % __alignof__(__type))	\
			log_message(LOG_INFO, "Alignment error - (" #__type " *)(" #__ptr ") - alignment %zu, address %p", __alignof(__type), sav_ptr); \
		(__const __type *) __CAST_PTR(__const) (sav_ptr);})
#else
#define PTR_CAST_ALL(__type, __ptr, __const) \
		({ (__const __type *) __CAST_PTR(__const) (__ptr); })
#endif

#define PTR_CAST(__type, __ptr)		PTR_CAST_ALL(__type, __ptr,)
#define PTR_CAST_CONST(__type, __ptr)	PTR_CAST_ALL(__type, __ptr, const)

#endif
