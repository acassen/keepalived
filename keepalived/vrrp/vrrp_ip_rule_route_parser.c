/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        iprule and iproute parser
 *
 * Author:      Chris Riley, <kernelchris@gmail.com>
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
 * Copyright (C) 2015 Chris Riley, <kernelchris@gmail.com>
 */

#include "config.h"

#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <math.h>
#include <arpa/inet.h>
#include <stdint.h>

#include "logger.h"
#include "vrrp_ip_rule_route_parser.h"
#include "rttables.h"
#if HAVE_DECL_RTA_ENCAP
#include "vrrp_iproute.h"
#endif

bool
get_realms(uint32_t *realms, char *str)
{
	uint32_t val, val1;
	char *end;

	if ((end = strchr(str,'/')))
		*end = '\0';

	if (!find_rttables_realms(str, &val))
		goto err;

	if (end) {
		if (!find_rttables_realms(end + 1, &val1))
			goto err;

		val <<= 16;
		val |= val1;

		*end = '/';
	}

	*realms = val;

	return false;

err:
	if (end)
		*end = '/';
	return true;
}


bool
get_u8(uint8_t *val, const char *str, uint8_t max, const char* errmsg)
{
	char *end;
	unsigned long t_val;

	t_val = strtoul(str, &end, 0);
	if (*end == '\0' && t_val <= max) {
		*val = (uint8_t)t_val;
		return false;
	}

	log_message(LOG_INFO, errmsg, str);
	return true;
}

bool
get_u16(uint16_t *val, const char *str, uint16_t max, const char* errmsg)
{
	char *end;
	unsigned long t_val;

	/* strtoul can do "nasty" things with -ve unsigneds */
	if (str[0] == '-')
		return true;

	t_val = strtoul(str, &end, 0);
	if (*end == '\0' && t_val <= max) {
		*val = (uint16_t)t_val;
		return false;
	}

	log_message(LOG_INFO, errmsg, str);
	return true;
}

bool
get_u32(uint32_t *val, const char *str, uint32_t max, const char* errmsg)
{
	char *end;
	unsigned long t_val;

	/* strtoul can do "nasty" things with -ve unsigneds */
	if (str[0] == '-')
		return true;

	t_val = strtoul(str, &end, 0);
	if (*end == '\0' && t_val <= max) {
		*val = (uint32_t)t_val;
		return false;
	}

	log_message(LOG_INFO, errmsg, str);
	return true;
}

bool
get_u64(uint64_t *val, const char *str, uint64_t max, const char* errmsg)
{
	char *end;
	unsigned long long t_val;

	/* strtoull can do "nasty" things with -ve unsigneds */
	if (str[0] == '-')
		return true;

	t_val = strtoull(str, &end, 0);
	if (*end == '\0' && t_val <= max) {
		*val = t_val;
		return false;
	}

	log_message(LOG_INFO, errmsg, str);
	return true;
}

bool
get_time_rtt(uint32_t *val, const char *str, bool *raw)
{
	double t;
	unsigned long res;
	char *end;

	errno = 0;
	if (strchr(str, '.') ||
	    (strpbrk(str,"Ee" ) && !strpbrk(str, "xX"))) {
		t = strtod(str, &end);
		if (t <= 0.0)
			return true;

		/* no digits? */
		if (end == str)
			return true;

		/* overflow */
		if (t == HUGE_VAL && errno == ERANGE)
			return true;

		if (t >=UINT32_MAX)
			return true;
	} else {
		/* strtoul does "nasty" things with negative numbers */
		if (str[0] == '-')
			return true;

		res = strtoul(str, &end, 0);

		/* no digits? */
		if (end == str)
			return true;

		/* overflow */
		if (res == ULONG_MAX && errno == ERANGE)
			return true;

		if (res >= UINT32_MAX)
			return true;

		t = (double)res;
	}

	if (*end) {
		*raw = false;
		if (!strcasecmp(end, "s") ||
		    !strcasecmp(end, "sec") ||
		    !strcasecmp(end, "secs")) {
			if (t >= UINT32_MAX / 1000)
				return -1;
			t *= 1000;
		}
		else if (strcasecmp(end, "ms") &&
			 strcasecmp(end, "msec") &&
			 strcasecmp(end, "msecs"))
			return true;
	}
	else
		*raw = true;

	*val = (uint32_t)t;
	if (*val < t)
		(*val)++;
	
	return false;
}

bool
get_addr64(uint64_t *ap, const char *cp)
{
	int i;

	union {
		uint16_t v16[4];
		uint64_t v64;
	} val;

	val.v64 = 0;
	for (i = 0; i < 4; i++) {
		unsigned long n;
		char *endp;

		n = strtoul(cp, &endp, 16);
		if (n > 0xffff)
			return true;	/* bogus network value */

		if (endp == cp) /* no digits */
			return true;

		val.v16[i] = htons(n);

		if (*endp == '\0') {
			if (i != 3)	/* address too short */
				return true;
			break;
		}

		if (i == 3 || *endp != ':')
			return true;	/* extra characters */
		cp = endp + 1;
	}

	*ap = val.v64;

	return false;
}

#if HAVE_DECL_LWTUNNEL_ENCAP_MPLS
bool
parse_mpls_address(const char *str, encap_mpls_t *mpls)
{
	char *endp;
	unsigned count;
	unsigned long label;

	mpls->num_labels = 0;

	for (count = 0; count < MAX_MPLS_LABELS; count++) {
		if (str[0] == '-')
			return true;

		label = strtoul(str, &endp, 0);

		if (endp == str) /* no digits */
			return true;

		/* Fail when the label value is out of range */
		if (label > UINT32_MAX)
			return true;
		if (label & ~(MPLS_LS_LABEL_MASK >> MPLS_LS_LABEL_SHIFT))
			return true;

		mpls->addr[count].entry = htonl((uint32_t)label << MPLS_LS_LABEL_SHIFT);
		if (*endp == '\0') {
			mpls->addr[count].entry |= htonl(1 << MPLS_LS_S_SHIFT);
			mpls->num_labels = count + 1;
			return false;
		}

		/* Bad character in the address */
		if (*endp != '/')
			return true;

		str = endp + 1;
	}
	/* The address was too long */
	return true;
}
#endif
