/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        warnings.h include file.
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
 * Copyright (C) 2019-2019 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _WARNINGS_H
#define _WARNINGS_H

#ifdef __GNUC__
#include <features.h>
#endif

#include "config.h"


/* musl does not define __GNUC_PREREQ, so create a dummy definition */
#ifndef __GNUC_PREREQ
#define __GNUC_PREREQ(maj, min) 0
#endif

/* GCC allows pragmas in functions, and diagnostic push/pop from version 4.6.0 */

/* See https://clang.llvm.org/docs/DiagnosticsReference.html for clang diagnostics
 * See https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html for GCC warnings
*/

#ifdef _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_
#define RELAX_STACK_PROTECTOR_START \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic ignored \"-Wstack-protector\"")
#else
#define RELAX_STACK_PROTECTOR_START
#endif

#ifdef _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_
#define RELAX_STACK_PROTECTOR_END \
_Pragma("GCC diagnostic pop")
#else
#define RELAX_STACK_PROTECTOR_END
#endif

#if __GNUC__ && !__GNUC_PREREQ(8,0) && defined _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_
#ifdef _HAVE_PRAGMA_WARN_STRICT_OVERFLOW_1_
#define RELAX_STRICT_OVERFLOW_START \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic warning \"-Wstrict-overflow=1\"")
#else
#define RELAX_STRICT_OVERFLOW_START \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic warning \"-Wstrict-overflow\"")
#endif
#else
#define RELAX_STRICT_OVERFLOW_START
#endif

#if __GNUC__ && !__GNUC_PREREQ(8,0) && defined _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_
#define RELAX_STRICT_OVERFLOW_END \
_Pragma("GCC diagnostic pop")
#else
#define RELAX_STRICT_OVERFLOW_END
#endif

#ifdef _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_
#define RELAX_CAST_QUAL_START \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic ignored \"-Wcast-qual\"")
#else
#define RELAX_CAST_QUAL_START
#endif

#ifdef _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_
#define RELAX_CAST_QUAL_END \
_Pragma("GCC diagnostic pop")
#else
#define RELAX_CAST_QUAL_END
#endif

#ifdef _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_
#define RELAX_SUGGEST_ATTRIBUTE_CONST_START \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic ignored \"-Wsuggest-attribute=const\"")
#else
#define RELAX_SUGGEST_ATTRIBUTE_CONST_START
#endif

#ifdef _HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_
#define RELAX_SUGGEST_ATTRIBUTE_CONST_END \
_Pragma("GCC diagnostic pop")
#else
#define RELAX_SUGGEST_ATTRIBUTE_CONST_END
#endif

#endif
