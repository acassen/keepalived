/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        General program utils.
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
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include "utils.h"

/* global vars */
int debug = 0;

/* Display a buffer into a HEXA formated output */
void
dump_buffer(char *buff, int count)
{
	int i, j, c;
	int printnext = 1;

	if (count % 16)
		c = count + (16 - count % 16);
	else
		c = count;

	for (i = 0; i < c; i++) {
		if (printnext) {
			printnext--;
			printf("%.4x ", i & 0xffff);
		}
		if (i < count)
			printf("%3.2x", buff[i] & 0xff);
		else
			printf("   ");
		if (!((i + 1) % 8)) {
			if ((i + 1) % 16)
				printf(" -");
			else {
				printf("   ");
				for (j = i - 15; j <= i; j++)
					if (j < count) {
						if ((buff[j] & 0xff) >= 0x20
						    && (buff[j] & 0xff) <= 0x7e)
							printf("%c",
							       buff[j] & 0xff);
						else
							printf(".");
					} else
						printf(" ");
				printf("\n");
				printnext = 1;
			}
		}
	}
}

/* Compute a checksum */
u_short
in_csum(u_short * addr, int len, u_short csum)
{
	register int nleft = len;
	const u_short *w = addr;
	register u_short answer;
	register int sum = csum;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += htons(*(u_char *) w << 8);

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

/* IP network to ascii representation */
char *
inet_ntop2(uint32_t ip)
{
	static char buf[16];
	unsigned char *bytep;

	bytep = (unsigned char *) &(ip);
	sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
	return buf;
}

/*
 * IP network to ascii representation. To use
 * for multiple IP address convertion into the same call.
 */
char *
inet_ntoa2(uint32_t ip, char *buf)
{
	unsigned char *bytep;

	bytep = (unsigned char *) &(ip);
	sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
	return buf;
}

/* IP string to network mask representation. CIDR notation. */
uint8_t
inet_stom(char *addr)
{
	uint8_t mask = 32;
	char *cp = addr;

	if (!strstr(addr, "/"))
		return mask;
	while (*cp != '/' && *cp != '\0')
		cp++;
	if (*cp == '/')
		return atoi(++cp);
	return mask;
}

/* IP string to network range representation. */
uint8_t
inet_stor(char *addr)
{
	uint8_t range = 0;
	char *cp = addr;

	if (!strstr(addr, "-"))
		return range;
	while (*cp != '-' && *cp != '\0')
		cp++;
	if (*cp == '-')
		return atoi(++cp);
	return range;
}

/* IP string to sockaddr_storage */
int
inet_stosockaddr(char *ip, char *port, struct sockaddr_storage *addr)
{
	void *addr_ip;
	char *cp = ip;

	addr->ss_family = (strchr(ip, ':')) ? AF_INET6 : AF_INET;

	/* remove range and mask stuff */
	if (strstr(ip, "-")) {
		while (*cp != '-' && *cp != '\0')
			cp++;
		if (*cp == '-')
			*cp = 0;
	} else if (strstr(ip, "/")) {
		while (*cp != '/' && *cp != '\0')
			cp++;
		if (*cp == '/')
			*cp = 0;
	}

	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
		if (port)
			addr6->sin6_port = htons(atoi(port));
		addr_ip = &addr6->sin6_addr;
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		if (port)
			addr4->sin_port = htons(atoi(port));
		addr_ip = &addr4->sin_addr;
	}

	if (!inet_pton(addr->ss_family, ip, addr_ip))
		return -1;

	return 0;
}

/* IP network to string representation */
char *
inet_sockaddrtos2(struct sockaddr_storage *addr, char *addr_str)
{
	void *addr_ip;

	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
		addr_ip = &addr6->sin6_addr;
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		addr_ip = &addr4->sin_addr;
	}

	if (!inet_ntop(addr->ss_family, addr_ip, addr_str, INET6_ADDRSTRLEN))
		return NULL;

	return addr_str;
}

char *
inet_sockaddrtos(struct sockaddr_storage *addr)
{
	static char addr_str[INET6_ADDRSTRLEN];
	inet_sockaddrtos2(addr, addr_str);
	return addr_str;
}

uint16_t
inet_sockaddrport(struct sockaddr_storage *addr)
{
	uint16_t port;

	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
		port = addr6->sin6_port;
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		port = addr4->sin_port;
	}
	
	return port;
}

uint32_t
inet_sockaddrip4(struct sockaddr_storage *addr)
{
	if (addr->ss_family != AF_INET)
		return -1;
	
	return ((struct sockaddr_in *) addr)->sin_addr.s_addr;
}

int
inet_sockaddrip6(struct sockaddr_storage *addr, struct in6_addr *ip6)
{
	if (addr->ss_family != AF_INET6)
		return -1;
	
	*ip6 = ((struct sockaddr_in6 *) addr)->sin6_addr;
	return 0;
}


/*
 * IP string to network representation
 * Highly inspired from Paul Vixie code.
 */
int
inet_ston(const char *addr, uint32_t * dst)
{
	static char digits[] = "0123456789";
	int saw_digit, octets, ch;
	u_char tmp[INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;

	while ((ch = *addr++) != '\0' && ch != '/' && ch != '-') {
		const char *pch;
		if ((pch = strchr(digits, ch)) != NULL) {
			u_int new = *tp * 10 + (pch - digits);
			if (new > 255)
				return 0;
			*tp = new;
			if (!saw_digit) {
				if (++octets > 4)
					return 0;
				saw_digit = 1;
			}
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return 0;
			*++tp = 0;
			saw_digit = 0;
		} else
			return 0;
	}

	if (octets < 4)
		return 0;

	memcpy(dst, tmp, INADDRSZ);
	return 1;
}

/*
 * Return broadcast address from network and netmask.
 */
uint32_t
inet_broadcast(uint32_t network, uint32_t netmask)
{
	return 0xffffffff - netmask + network;
}

/*
 * Convert CIDR netmask notation to long notation.
 */
uint32_t
inet_cidrtomask(uint8_t cidr)
{
	uint32_t mask = 0;
	int b;

	for (b = 0; b < cidr; b++)
		mask |= (1 << (31 - b));
	return ntohl(mask);
}

/* Getting localhost official canonical name */
char *
get_local_name(void)
{
	struct hostent *host;
	struct utsname name;

	if (uname(&name) < 0)
		return NULL;

	if (!(host = gethostbyname(name.nodename)))
		return NULL;

	return host->h_name;
}
