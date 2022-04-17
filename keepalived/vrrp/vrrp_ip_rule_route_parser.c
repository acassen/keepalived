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
 * Copyright (C) 2016-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <math.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <ctype.h>

#include "logger.h"
#include "vrrp_ip_rule_route_parser.h"
#include "rttables.h"
#if HAVE_DECL_RTA_ENCAP
#include "vrrp_iproute.h"
#endif
#include "parser.h"
#include "memory.h"

bool
get_realms(uint32_t *realms, const char *str)
{
	uint32_t val, val1;
	char *end;

	if ((end = strchr(str,'/')))
		str = STRNDUP(str,  end - str);

	if (!find_rttables_realms(str, &val))
		goto err;

	if (end) {
		if (!find_rttables_realms(end + 1, &val1))
			goto err;

		val <<= 16;
		val |= val1;

		FREE_CONST(str);
	}

	*realms = val;

	return false;

err:
	if (end)
		FREE_CONST(str);
	return true;
}


bool
get_u8(uint8_t *val, const char *str, uint8_t max, const char* errmsg)
{
	unsigned t_val;

	if (read_unsigned(str, &t_val, 0, max, false)) {
		*val = (uint8_t)t_val;
		return false;
	}

	report_config_error(CONFIG_GENERAL_ERROR, errmsg, str);
	return true;
}

bool
get_u16(uint16_t *val, const char *str, uint16_t max, const char* errmsg)
{
	unsigned t_val;

	if (read_unsigned(str, &t_val, 0, max, false)) {
		*val = (uint16_t)t_val;
		return false;
	}

	report_config_error(CONFIG_GENERAL_ERROR, errmsg, str);
	return true;
}

bool
get_u32(uint32_t *val, const char *str, uint32_t max, const char* errmsg)
{
	unsigned t_val;

	if (read_unsigned(str, &t_val, 0, max, false)) {
		*val = (uint32_t)t_val;
		return false;
	}

	report_config_error(CONFIG_GENERAL_ERROR, errmsg, str);
	return true;
}

bool
get_u64(uint64_t *val, const char *str, uint64_t max, const char* errmsg)
{
	uint64_t t_val;

	if (read_unsigned64(str, &t_val, 0, max, false)) {
		*val = (uint64_t)t_val;
		return false;
	}

	report_config_error(CONFIG_GENERAL_ERROR, errmsg, str);
	return true;
}

/* The kernel has the following definitions in include/net/tcp.h:
 *   #define TCP_RTO_MAX     ((unsigned)(120*HZ))
 *   #define TCP_RTO_MIN     ((unsigned)(HZ/5))
 * so rtt values must be between 0.2 and 120 seconds.
 */
#define RTT_MIN_MS	   200U
#define RTT_MAX_MS	120000U

bool
get_time_rtt(uint32_t *val, const char *str, unsigned unit_mult, const char *type)
{
	unsigned res;
	unsigned shift;
	char *p;
	char *str_cpy;
	const char *str1;
	bool ret;
	bool raw;


	/* Skip leading whitespace */
	str += strspn(str, WHITE_SPACE);

	/* Have units been specified? */
	raw = true;
	if ((p = strpbrk(str, "sS"))) {
		if (strcasecmp(p, "s") &&
		    strcasecmp(p, "sec") &&
		    strcasecmp(p, "secs"))
			return true;

		raw = false;
		if (p > str && tolower(p[-1]) == 'm') {
			shift = 0;
			p--;
		} else
			shift = 3;

		if (p == str)
			return true;

		str_cpy = MALLOC(p - str + 1);
		memcpy(str_cpy, str, p - str);
		str_cpy[p - str] = '\0';
		str1 = str_cpy;
	} else {
		str_cpy = NULL;
		str1 = str;
		shift = 0;
	}

	/* We used to support exponential form to match ip route command, but that support was
	 * accidental (e.g. "rtt 1e3" did not work, but "rtt 1.e3" did - exponential form in ip
	 * command is only supported if a decimal point is specified).
	 */
	if (strpbrk(str1, "eE")) {
		report_config_error(CONFIG_GENERAL_ERROR, "%s value exponential form %s no longer supported", type, str);
		if (str_cpy)
			FREE(str_cpy);
		return true;
	}

	ret = read_decimal_unsigned(str1, &res, 0, RTT_MAX_MS * unit_mult, shift, false);

	if (str_cpy)
		FREE(str_cpy);

	if (!ret)
		return true;

	if (!raw)
		res *= unit_mult;

	if (res > RTT_MAX_MS * unit_mult) {
		report_config_error(CONFIG_GENERAL_ERROR, "%s value %s exceeds maximum %us, resetting", type, str, RTT_MAX_MS / 1000U);
		res = RTT_MAX_MS * unit_mult;
	} else if (res < RTT_MIN_MS * unit_mult) {
		report_config_error(CONFIG_GENERAL_ERROR, "%s value %s below minimum %ums, resetting", type, str, RTT_MIN_MS);
		res = RTT_MIN_MS * unit_mult;
	}

	*val = res;

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

	/* Skip leading whitespace */
	cp += strspn(cp, WHITE_SPACE);

	val.v64 = 0;
	for (i = 0; i < 4; i++) {
		unsigned long n;
		char *endp;

		if (!isxdigit(*cp))
			return true;	/* Not a hex digit */

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

#if HAVE_DECL_RTA_ENCAP && HAVE_DECL_LWTUNNEL_ENCAP_MPLS
bool
parse_mpls_address(const char *str, encap_mpls_t *mpls)
{
	char *endp;
	unsigned count;
	unsigned long label;

	mpls->num_labels = 0;

	/* Skip leading whitespace */
	str += strspn(str, WHITE_SPACE);

	for (count = 0; count < MAX_MPLS_LABELS; count++) {
		if (str[0] == '-')
			return true;

		if (strspn(str, WHITE_SPACE))	/* No embedded whitespace */
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
