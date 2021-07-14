/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        utils.h include file.
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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _UTILS_H
#define _UTILS_H

#include "config.h"

/* system includes */
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "vector.h"
#include "warnings.h"

#define STR(x)  #x

#define	VERSION_STRING		PACKAGE_NAME " v" PACKAGE_VERSION " (" GIT_DATE ")"
#define COPYRIGHT_STRING	"Copyright(C) 2001-" GIT_YEAR " Alexandre Cassen, <acassen@gmail.com>"

#define max(a,b) ((a) >= (b) ? (a) : (b))

/* Evaluates to -1, 0 or 1 as appropriate.
 * Avoids a - b <= 0 producing "warning: assuming signed overflow does not occur when simplifying ‘X - Y <= 0’ to ‘X <= Y’ [-Wstrict-overflow]" */
#define less_equal_greater_than(a,b)	({ typeof(a) _a = (a); typeof(b) _b = (b); (_a) < (_b) ? -1 : (_a) == (_b) ? 0 : 1; })

#if defined RUN_DIR_ROOT
#define RUN_DIR			RUN_DIR_ROOT "/run/"
#elif defined GNU_STD_PATHS
#define RUN_DIR			LOCAL_STATE_DIR "/run/"
#else
#define RUN_DIR			_PATH_VARRUN
#endif

#ifdef _WITH_PERF_
typedef enum {
	PERF_NONE,
	PERF_RUN,
	PERF_ALL,
	PERF_END,
} perf_t;
#endif

#ifdef _EINTR_DEBUG_
extern bool do_eintr_debug;
#endif

/* Some library functions that take pointer parameters should have them
 * specified as const pointers, but don't. We need to cast away the constness,
 * but also want to avoid compiler warnings for doing so. The following "trick"
 * achieves that. */
#define no_const(type, var_cp) \
({ union { type *p; const type *cp; } ps = { .cp = var_cp }; \
 ps.p;})

#define no_const_char_p(var_cp)	no_const(char, var_cp)

/* If signalfd() is used, we will have no signal handlers, and
 * so we cannot get EINTR. If we cannot get EINTR, there is no
 * point checking for it.
 * If check_EINTR is defined as false, gcc will optimise out the
 * test, and remove any surrounding while loop such as:
 * while (recvmsg(...) == -1 && check_EINTR(errno)); */
#if defined DEBUG_EINTR
static inline bool
check_EINTR(int xx)
{
	if (!do_eintr_debug)
		return (xx == EINTR);

	if (xx == EINTR) {
		log_message(LOG_INFO, "%s:%s(%d) - EINTR returned", (__FILE__), (__func__), (__LINE__));
		return true;
	}

	return false;
}
#elif defined CHECK_EINTR
#define check_EINTR(xx)	((xx) == EINTR)
#else
#define check_EINTR(xx)	(false)
#endif

/* Functions that can return EAGAIN also document that they can return
 * EWOULDBLOCK, and that both should be checked. If they are the same
 * value, that is unnecessary. */
#if EAGAIN == EWOULDBLOCK
#define check_EAGAIN(xx)	((xx) == EAGAIN)
#else
#define check_EAGAIN(xx)	((xx) == EAGAIN || (xx) == EWOULDBLOCK)
#endif

/* Used in functions returning a string matching a defined value */
#define switch_define_str(x) case x: return #x

/* Buffer length needed for inet_sockaddrtotrio() - '[' + INET6_ADDRSTRLEN + ']' + ':' + 'sctp' + ':' + 'nnnnn' */
#define SOCKADDRTRIO_STR_LEN	(INET6_ADDRSTRLEN + 13)

/* The argv parameter to execve etc is declared as char *const [], whereas
 * it should be char const *const [], so we use the following union to cast
 * away the const that we have, but execve etc doesn't. */
union non_const_args {
	const char *const *args;
	char *const *execve_args;
};

/* inline stuff */
static inline int __ip6_addr_equal(const struct in6_addr *a1,
				   const struct in6_addr *a2)
{
	return (((a1->s6_addr32[0] ^ a2->s6_addr32[0]) |
		 (a1->s6_addr32[1] ^ a2->s6_addr32[1]) |
		 (a1->s6_addr32[2] ^ a2->s6_addr32[2]) |
		 (a1->s6_addr32[3] ^ a2->s6_addr32[3])) == 0);
}

static inline bool sockstorage_equal(const struct sockaddr_storage *s1,
				    const struct sockaddr_storage *s2)
{
	if (s1->ss_family != s2->ss_family)
		return false;

	if (s1->ss_family == AF_INET6) {
		const struct sockaddr_in6 *a1 = (const struct sockaddr_in6 *) s1;
		const struct sockaddr_in6 *a2 = (const struct sockaddr_in6 *) s2;

//		if (IN6_ARE_ADDR_EQUAL(a1, a2) && (a1->sin6_port == a2->sin6_port))
		if (__ip6_addr_equal(&a1->sin6_addr, &a2->sin6_addr) &&
		    (a1->sin6_port == a2->sin6_port))
			return true;
	} else if (s1->ss_family == AF_INET) {
		const struct sockaddr_in *a1 = (const struct sockaddr_in *) s1;
		const struct sockaddr_in *a2 = (const struct sockaddr_in *) s2;

		if ((a1->sin_addr.s_addr == a2->sin_addr.s_addr) &&
		    (a1->sin_port == a2->sin_port))
			return true;
	} else if (s1->ss_family == AF_UNSPEC)
		return true;

	return false;
}

static inline bool inaddr_equal(sa_family_t family, const void *addr1, const void *addr2)
{
	if (family == AF_INET6) {
		const struct in6_addr *a1 = (const struct in6_addr *) addr1;
		const struct in6_addr *a2 = (const struct in6_addr *) addr2;

		return __ip6_addr_equal(a1, a2);
	}

	if (family == AF_INET) {
		const struct in_addr *a1 = (const struct in_addr *) addr1;
		const struct in_addr *a2 = (const struct in_addr *) addr2;

		return (a1->s_addr == a2->s_addr);
	}

	return false;
}

static inline uint16_t csum_incremental_update32(const uint16_t old_csum, const uint32_t old_val, const uint32_t new_val)
{
	/* This technique for incremental IP checksum update is described in RFC1624,
	 * along with accompanying errata */

	if (old_val == new_val)
		return old_csum;

	uint32_t acc = (~old_csum & 0xffff) + (~(old_val >> 16 ) & 0xffff) + (~old_val & 0xffff);

	acc += (new_val >> 16) + (new_val & 0xffff);

	/* finally compute vrrp checksum */
	acc = (acc & 0xffff) + (acc >> 16);
	acc += acc >> 16;

	return ~acc & 0xffff;
}

static inline uint16_t csum_incremental_update16(const uint16_t old_csum, const uint16_t old_val, const uint16_t new_val)
{
	/* This technique for incremental IP checksum update is described in RFC1624,
	 * along with accompanying errata */

	if (old_val == new_val)
		return old_csum;

	uint32_t acc = (~old_csum & 0xffff) + (~old_val & 0xffff);

	acc += new_val;

	/* finally compute vrrp checksum */
	acc = (acc & 0xffff) + (acc >> 16);
	acc += acc >> 16;

	return ~acc & 0xffff;
}

/* The following produce -Wstringop-truncation warnings (not produced without the loop):
 * 	do { strncpy(dst, src, sizeof(dst) - 1); dst[sizeof(dst) - 1] = '\0'; } while (0)
	do { dst[0] = '\0'; strncat(dst, src, sizeof(dst) - 1); } while (0)
   even if surrounded by RELAX_STRINGOP_TRUNCATION/RELAX_END
   See GCC BZ#101451
 */
#define strcpy_safe(dst, src)	strcpy_safe_impl(dst, src, sizeof(dst))

static inline char *
strcpy_safe_impl(char *dst, const char *src, size_t len)
{
	dst[0] = '\0';
RELAX_STRINGOP_TRUNCATION
	return strncat(dst, src, len - 1);
RELAX_END
}

/* global vars exported */
extern unsigned long debug;
extern mode_t umask_val;
#ifdef _WITH_PERF_
extern perf_t perf_run;
#endif

/* Prototypes defs */
extern void dump_buffer(const char *, size_t, FILE *, int);
#if defined _CHECKSUM_DEBUG_ || defined _RECVMSG_DEBUG_
extern void log_buffer(const char *, const void *, size_t);
#endif
#ifdef _WITH_STACKTRACE_
extern void write_stacktrace(const char *, const char *);
#endif
extern const char *make_file_name(const char *, const char *, const char *, const char *);
extern void set_process_name(const char *);
#ifdef _WITH_PERF_
extern void run_perf(const char *, const char *, const char *);
#endif
extern uint16_t in_csum(const uint16_t *, size_t, uint32_t, uint32_t *);
extern const char *inet_ntop2(uint32_t);
extern bool inet_stor(const char *, uint32_t *);
extern int domain_stosockaddr(const char *, const char *, struct sockaddr_storage *);
extern bool inet_stosockaddr(const char *, const char *, struct sockaddr_storage *);
extern void inet_ip4tosockaddr(const struct in_addr *, struct sockaddr_storage *);
extern void inet_ip6tosockaddr(const struct in6_addr *, struct sockaddr_storage *);
extern bool check_valid_ipaddress(const char *, bool);
extern const char *inet_sockaddrtos(const struct sockaddr_storage *);
extern const char *inet_sockaddrtopair(const struct sockaddr_storage *);
extern const char *inet_sockaddrtotrio(const struct sockaddr_storage *, uint16_t);
extern char *inet_sockaddrtotrio_r(const struct sockaddr_storage *, uint16_t, char *);
extern uint16_t inet_sockaddrport(const struct sockaddr_storage *) __attribute__ ((pure));
extern void inet_set_sockaddrport(struct sockaddr_storage *, uint16_t);
extern uint32_t inet_sockaddrip4(const struct sockaddr_storage *) __attribute__ ((pure));
extern int inet_sockaddrip6(const struct sockaddr_storage *, struct in6_addr *);
extern int inet_inaddrcmp(int, const void *, const void *); __attribute__ ((pure))
extern int inet_sockaddrcmp(const struct sockaddr_storage *, const struct sockaddr_storage *) __attribute__ ((pure));
extern void format_mac_buf(char *, size_t, const unsigned char *, size_t);
extern const char *get_local_name(void) __attribute__((malloc));
extern bool string_equal(const char *, const char *) __attribute__ ((pure));
extern int integer_to_string(const int, char *, size_t);
extern FILE *fopen_safe(const char *, const char *) __attribute__((malloc));
extern void set_std_fd(bool);
extern void close_std_fd(void);
#if defined _WITH_VRRP_ || defined _WITH_BFD_
extern int open_pipe(int [2]);
#endif
extern int memcmp_constant_time(const void *, const void *, size_t);

#if defined _WITH_LVS_ || defined _HAVE_LIBIPSET_
extern bool keepalived_modprobe(const char *);
#endif

#endif
