/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        assert facility.
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
 * Copyright (C) 2018-2018 Alexandre Cassen, <acassen@gmail.com>
 */
#include "config.h"

#ifndef  NDEBUG

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "logger.h"

/* This prints an "Assertion failed" message and aborts.  */
void __assert_fail (const char *__assertion, const char *__file,
			   LINE_type __line, const char *__function)
{
	log_message(LOG_ERR, "assert: %s:%u: %s: Assertion: `%s' failed.", __file, __line, __function, __assertion);
	abort();
}

#ifdef __USE_GNU
/* Likewise, but prints the error text for ERRNUM.  */
void __assert_perror_fail (int __errnum, const char *__file,
				  unsigned int __line, const char *__function)
{
	log_message(LOG_ERR, "assert: %s:%u: %s: Unexpected error: %s.", __file, __line, __function, strerror(__errnum));
	abort();
}
#endif
#endif
