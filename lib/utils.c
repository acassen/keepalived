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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include "config.h"

#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

#ifdef _WITH_STACKTRACE_
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <execinfo.h>
#endif

#include "memory.h"
#include "utils.h"
#include "signals.h"
#include "bitops.h"

/* global vars */
unsigned long debug = 0;

/* Display a buffer into a HEXA formated output */
void
dump_buffer(char *buff, size_t count, FILE* fp)
{
	size_t i, j, c;
	bool printnext = true;

	if (count % 16)
		c = count + (16 - count % 16);
	else
		c = count;

	for (i = 0; i < c; i++) {
		if (printnext) {
			printnext = false;
			fprintf(fp, "%.4zu ", i & 0xffff);
		}
		if (i < count)
			fprintf(fp, "%3.2x", buff[i] & 0xff);
		else
			fprintf(fp, "   ");
		if (!((i + 1) % 8)) {
			if ((i + 1) % 16)
				fprintf(fp, " -");
			else {
				fprintf(fp, "   ");
				for (j = i - 15; j <= i; j++)
					if (j < count) {
						if ((buff[j] & 0xff) >= 0x20
						    && (buff[j] & 0xff) <= 0x7e)
							fprintf(fp, "%c",
							       buff[j] & 0xff);
						else
							fprintf(fp, ".");
					} else
						fprintf(fp, " ");
				fprintf(fp, "\n");
				printnext = true;
			}
		}
	}
}

#ifdef _WITH_STACKTRACE_
void
write_stacktrace(const char *file_name)
{
	int fd = open(file_name, O_WRONLY | O_APPEND | O_CREAT, 0644);
	void *buffer[100];
	int nptrs;

	nptrs = backtrace(buffer, 100);
	backtrace_symbols_fd(buffer, nptrs, fd);
	if (write(fd, "\n", 1) != 1) {
		/* We don't care, but this stops a warning on Ubuntu */
	}
	close(fd);
}
#endif

/* Compute a checksum */
uint16_t
in_csum(const uint16_t *addr, size_t len, uint32_t csum, uint32_t *acc)
{
	register size_t nleft = len;
	const uint16_t *w = addr;
	register uint16_t answer;
	register uint32_t sum = csum;

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

	if (acc)
		*acc = sum;

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = (~sum & 0xffff);		/* truncate to 16 bits */
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

#ifdef _INCLUDE_UNUSED_CODE_
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
inet_stom(const char *addr)
{
	uint8_t mask = 32;
	const char *cp = addr;

	if (!(cp = strchr(addr, '/')))
		return mask;
	return atoi(cp+1);
}
#endif

/* IP string to network range representation. */
uint32_t
inet_stor(const char *addr)
{
	const char *cp = addr;

	if (!(cp = strchr(addr, '-')))
		return 0;

	return (uint32_t)strtoul(cp + 1, NULL, (strchr(addr, ':')) ? 16 : 10);
}

/* Domain to sockaddr_storage */
int
domain_stosockaddr(const char *domain, const char *port, struct sockaddr_storage *addr)
{
	struct addrinfo *res = NULL;

	if (getaddrinfo(domain, NULL, NULL, &res) != 0 || !res)
		return -1;

	addr->ss_family = (sa_family_t)res->ai_family;

	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
		*addr6 = *(struct sockaddr_in6 *) res->ai_addr;
		if (port)
			addr6->sin6_port = htons(atoi(port));
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		*addr4 = *(struct sockaddr_in *) res->ai_addr;
		if (port)
			addr4->sin_port = htons(atoi(port));
	}

	freeaddrinfo(res);

	return 0;
}

/* IP string to sockaddr_storage */
int
inet_stosockaddr(char *ip, const char *port, struct sockaddr_storage *addr)
{
	void *addr_ip;
	char *cp = ip;

	addr->ss_family = (strchr(ip, ':')) ? AF_INET6 : AF_INET;

	/* remove range and mask stuff */
	if ((cp = strchr(ip, '-')))
		*cp = 0;
	else if ((cp = strchr(ip, '/')))
		*cp = 0;

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

	if (!inet_pton(addr->ss_family, ip, addr_ip)) {
		addr->ss_family = AF_UNSPEC;
		return -1;
	}

	return 0;
}

/* IPv4 to sockaddr_storage */
void
inet_ip4tosockaddr(struct in_addr *sin_addr, struct sockaddr_storage *addr)
{
	struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
	addr4->sin_family = AF_INET;
	addr4->sin_addr = *sin_addr;
}

/* IPv6 to sockaddr_storage */
void
inet_ip6tosockaddr(struct in6_addr *sin_addr, struct sockaddr_storage *addr)
{
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
	addr6->sin6_family = AF_INET6;
	addr6->sin6_addr = *sin_addr;
}

void
inet_ip6scopeid(uint32_t ifindex, struct sockaddr_storage *addr)
{
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
	addr6->sin6_scope_id = ifindex;
}

/* IP network to string representation */
static char *
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

char *
inet_sockaddrtopair(struct sockaddr_storage *addr)
{
	static char addr_str[INET6_ADDRSTRLEN + 1];
	static char ret[sizeof(addr_str) + 16];

	inet_sockaddrtos2(addr, addr_str);
	snprintf(ret, sizeof(ret) - 1, "[%s]:%d"
		, addr_str
		, ntohs(inet_sockaddrport(addr)));
	return ret;
}

uint32_t
inet_sockaddrip4(struct sockaddr_storage *addr)
{
	if (addr->ss_family != AF_INET)
		return 0xffffffff;

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

/* IPv6 address compare */
int
inet_inaddrcmp(int family, void *a, void *b)
{
	int64_t addr_diff;

	if (family == AF_INET) {
		addr_diff = (int64_t)ntohl(*((const uint32_t *) a)) - (int64_t)ntohl(*((const uint32_t *) b));
		if (addr_diff > 0)
			return 1;
		if (addr_diff < 0)
			return -1;
		return 0;
	}

	if (family == AF_INET6) {
		int i;

		for (i = 0; i < 4; i++ ) {
			addr_diff = (int64_t)ntohl(((const uint32_t *) (a))[i]) - (int64_t)ntohl(((const uint32_t *) (b))[i]);
			if (addr_diff > 0)
				return 1;
			if (addr_diff < 0)
				return -1;
		}
		return 0;
	}

	return -2;
}

int
inet_sockaddrcmp(struct sockaddr_storage *a, struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family)
		return -2;

	if (a->ss_family == AF_INET)
		return inet_inaddrcmp(a->ss_family,
				      &((struct sockaddr_in *) a)->sin_addr,
				      &((struct sockaddr_in *) b)->sin_addr);
	if (a->ss_family == AF_INET6)
		return inet_inaddrcmp(a->ss_family,
				      &((struct sockaddr_in6 *) a)->sin6_addr,
				      &((struct sockaddr_in6 *) b)->sin6_addr);
	return 0;
}


#ifdef _INCLUDE_UNUSED_CODE_
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
#endif

/* Getting localhost official canonical name */
char *
get_local_name(void)
{
	struct utsname name;
	struct addrinfo hints, *res = NULL;
	char *canonname = NULL;
	size_t len = 0;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;

	if (uname(&name) < 0)
		return NULL;

	if (getaddrinfo(name.nodename, NULL, &hints, &res) != 0)
		return NULL;

	if (res && res->ai_canonname) {
		len = strlen(res->ai_canonname);
		canonname = MALLOC(len + 1);
		if (canonname) {
			memcpy(canonname, res->ai_canonname, len);
		}
	}

	freeaddrinfo(res);

	return canonname;
}

/* String compare with NULL string handling */
int
string_equal(const char *str1, const char *str2)
{
	if (!str1 && !str2)
		return 1;
	if ((!str1 && str2) || (str1 && !str2))
		return 0;
	for (; *str1 == *str2; str1++, str2++) {
		if (*str1 == 0 || *str2 == 0)
			break;
	}

	return (*str1 == 0 && *str2 == 0);
}

void
set_std_fd(int force)
{
	int fd;

	if (force || __test_bit(DONT_FORK_BIT, &debug)) {
		fd = open("/dev/null", O_RDWR);
		if (fd != -1) {
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			if (fd > STDERR_FILENO)
				close(fd);
		}
	}

	signal_pipe_close(STDERR_FILENO+1);
}

#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
int
fork_exec(char **argv)
{
	pid_t pid;
	int status;
	struct sigaction act, old_act;
	int res = 0;

	act.sa_handler = SIG_DFL;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	sigaction(SIGCHLD, &act, &old_act);

	pid = fork();
	if (pid < 0)
		res = -1;
	else if (pid == 0) {
		/* Child */
		set_std_fd(false);

		signal_handler_script();

		execvp(*argv, argv);
		exit(EXIT_FAILURE);
	} else {
		/* Parent */
		while (waitpid(pid, &status, 0) != pid);

		if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS)
			res = -1;
	}

	sigaction(SIGCHLD, &old_act, NULL);

	return res;
}
#endif
