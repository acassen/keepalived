/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        decimal_chars.h include file.
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
 * Copyright (C) 2026-2026 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _DECIMAL_CHARS_H
#define _DECIMAL_CHARS_H

// See https://stackoverflow.com/questions/10536207/ansi-c-maximum-number-of-characters-printing-a-decimal-int

/* Appropriate values of LOG2_SHIFT and LOG2_MULT, as used below,
 * can be calculated using the following code.
 *
 * It is worth considering what precision is really needed for
 * the approximation of log10(2) which can be used at compile time,
 * which is what the LOG2_SHIFT and LOG2_MULT values are used for.

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

int main(int argc, char **argv)
{
	long double minf=0.5;
	int i;
	long double a;
	unsigned long long n;
	long double f;
	unsigned long long minn;
	int bits;
	bool upper = false;
	bool is_upper;
	int max_iter = 58;

	if (argc >= 2)
		max_iter = atoi(argv[1]);

	a = log10l(2);
	for (i = 1; i <= max_iter; i++) {
		a *= 2;
		n = a;
		f = a - n;
		if (is_upper = !(f < 0.5L)) {
			f = 1.0 - f;
			n++;
		}
		if (f < minf * (1ULL << (i - bits))) {
			printf("New approx %llu bits %d error %Le -> %Le\n", n, i, minf / (1ULL << bits), f / (1ULL << i));
			minf = f;
			minn = n;
			bits = i;
			upper = is_upper;
		}
	}
	printf("\n(%llu %c %Lf) / 2^%d = %.20Le\n", minn, upper ? '-' : '+', minf, bits, (long double)minn / (1ULL << bits));
	printf("log10(2) = %.20Le, this approximation %.20Le error %.20Le (saved %.20Le)\n", log10l(2), (long double)minn / (1ULL << bits), log10l(2) - (long double)minn / (1ULL << bits), minf / (1ULL << bits));
}

*/

#include "config.h"

#if 1
#define LOG2_MULT	19728
#define LOG2_SHIFT	16
#else
#define LOG2_MULT	646456993
#define LOG2_SHIFT	31
#endif

#define __MAX_B10STRLEN_FOR_UNSIGNED_TYPE(t) \
    (((((sizeof(t) * CHAR_BIT)) * LOG2_MULT) >> LOG2_SHIFT) + 1)

#define __MAX_B10STRLEN_FOR_SIGNED_TYPE(t) \
    (((((sizeof(t) * CHAR_BIT) - 1) * LOG2_MULT) >> LOG2_SHIFT) + 2)

#define __MAX_B10STRLEN_FOR_INT_TYPE(t)                     \
    (((t) (1ULL << (sizeof(t) * CHAR_BIT - 1)) > 0)	    \
		  ? __MAX_B10STRLEN_FOR_UNSIGNED_TYPE(t)    \
                  : __MAX_B10STRLEN_FOR_SIGNED_TYPE(t))


#define	CHAR_MAX_CHRS	__MAX_B10STRLEN_FOR_INT_TYPE(char)
#define	UCHAR_MAX_CHRS	__MAX_B10STRLEN_FOR_INT_TYPE(unsigned char)
#define	SCHAR_MAX_CHRS	__MAX_B10STRLEN_FOR_INT_TYPE(signed char)
#define	SHRT_MAX_CHRS	__MAX_B10STRLEN_FOR_INT_TYPE(short)
#define	USHRT_MAX_CHRS	__MAX_B10STRLEN_FOR_INT_TYPE(unsigned short)
#define	INT_MAX_CHRS	__MAX_B10STRLEN_FOR_INT_TYPE(int)
#define	UINT_MAX_CHRS	__MAX_B10STRLEN_FOR_INT_TYPE(unsigned int)
#define	LONG_MAX_CHRS	__MAX_B10STRLEN_FOR_INT_TYPE(long)
#define	ULONG_MAX_CHRS	__MAX_B10STRLEN_FOR_INT_TYPE(unsigned long)
#define	LLONG_MAX_CHRS	__MAX_B10STRLEN_FOR_INT_TYPE(long long)
#define	ULLONG_MAX_CHRS	__MAX_B10STRLEN_FOR_INT_TYPE(unsigned long long)

/* The maximum pid is 2^22 - see definition of PID_MAX_LIMIT in kernel source include/linux/threads.h,
 * but this is safe if it increases in the future. */
#define PID_MAX_CHRS	__MAX_B10STRLEN_FOR_INT_TYPE(pid_t)

#define TYPE_MAX_CHRS(xxx)	__MAX_B10STRLEN_FOR_INT_TYPE(typeof(xxx))

#endif
