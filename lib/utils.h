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

#include "vector.h"
#ifdef _DEBUG_
#include "logger.h"
#endif

/* Global debugging logging facilities */
#ifdef _DEBUG_
#define DBG(fmt, msg...) log_message(LOG_DEBUG, fmt, ## msg)
#else
#define DBG(fmt, msg...)
#endif

#define STR(x)  #x

#ifdef _WITH_PERF_
typedef enum {
	PERF_NONE,
	PERF_RUN,
	PERF_ALL,
	PERF_END,
} perf_t;
#endif

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
		struct sockaddr_in6 *a1 = (struct sockaddr_in6 *) s1;
		struct sockaddr_in6 *a2 = (struct sockaddr_in6 *) s2;

//		if (IN6_ARE_ADDR_EQUAL(a1, a2) && (a1->sin6_port == a2->sin6_port))
		if (__ip6_addr_equal(&a1->sin6_addr, &a2->sin6_addr) &&
		    (a1->sin6_port == a2->sin6_port))
			return true;
	} else if (s1->ss_family == AF_INET) {
		struct sockaddr_in *a1 = (struct sockaddr_in *) s1;
		struct sockaddr_in *a2 = (struct sockaddr_in *) s2;

		if ((a1->sin_addr.s_addr == a2->sin_addr.s_addr) &&
		    (a1->sin_port == a2->sin_port))
			return true;
	} else if (s1->ss_family == AF_UNSPEC)
		return true;

	return false;
}

static inline bool inaddr_equal(sa_family_t family, void *addr1, void *addr2)
{
	if (family == AF_INET6) {
		struct in6_addr *a1 = (struct in6_addr *) addr1;
		struct in6_addr *a2 = (struct in6_addr *) addr2;

		if (__ip6_addr_equal(a1, a2))
			return true;
	} else if (family == AF_INET) {
		struct in_addr *a1 = (struct in_addr *) addr1;
		struct in_addr *a2 = (struct in_addr *) addr2;

		if (a1->s_addr == a2->s_addr)
			return true;
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

/* global vars exported */
extern unsigned long debug;
#ifdef _WITH_PERF_
extern perf_t perf_run;
#endif

/* Prototypes defs */
extern void dump_buffer(char *, size_t, FILE *, int);
#ifdef _WITH_STACKTRACE_
extern void write_stacktrace(const char *, const char *);
#endif
extern char *make_file_name(const char *, const char *, const char *, const char *);
#ifdef _WITH_PERF_
extern void run_perf(const char *, const char *, const char *);
#endif
extern uint16_t in_csum(const uint16_t *, size_t, uint32_t, uint32_t *);
extern char *inet_ntop2(uint32_t);
extern bool inet_stor(const char *, uint32_t *);
extern int domain_stosockaddr(const char *, const char *, struct sockaddr_storage *);
extern int inet_stosockaddr(char *, const char *, struct sockaddr_storage *);
extern void inet_ip4tosockaddr(struct in_addr *, struct sockaddr_storage *);
extern void inet_ip6tosockaddr(struct in6_addr *, struct sockaddr_storage *);
extern char *inet_sockaddrtos(struct sockaddr_storage *);
extern char *inet_sockaddrtopair(struct sockaddr_storage *);
extern char *inet_sockaddrtotrio(struct sockaddr_storage *, uint16_t);
extern uint16_t inet_sockaddrport(struct sockaddr_storage *);
extern uint32_t inet_sockaddrip4(struct sockaddr_storage *);
extern int inet_sockaddrip6(struct sockaddr_storage *, struct in6_addr *);
extern int inet_inaddrcmp(int, const void *, const void *);
extern int inet_sockaddrcmp(const struct sockaddr_storage *, const struct sockaddr_storage *);
extern char *get_local_name(void);
extern bool string_equal(const char *, const char *);
extern void set_std_fd(bool);
extern void close_std_fd(void);
#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
extern int fork_exec(char **argv);
#endif
#if defined _WITH_VRRP_ || defined _WITH_BFD_
extern int open_pipe(int [2]);
#endif

#endif
