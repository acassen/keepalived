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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

/* System includes */
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>
#include <sys/prctl.h>
#if defined _WITH_LVS_ || defined _HAVE_LIBIPSET_
#include <sys/wait.h>
#endif
#ifdef _WITH_PERF_
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#endif

#ifdef _WITH_STACKTRACE_
#include <sys/stat.h>
#include <execinfo.h>
#include <memory.h>
#endif

/* Local includes */
#include "utils.h"
#include "memory.h"
#include "utils.h"
#include "signals.h"
#include "bitops.h"
#include "parser.h"
#include "logger.h"
#include "process.h"

/* global vars */
unsigned long debug = 0;
mode_t umask_val = S_IXUSR | S_IRWXG | S_IRWXO;

#ifdef _EINTR_DEBUG_
bool do_eintr_debug;
#endif

/* Display a buffer into a HEXA formated output */
void
dump_buffer(const char *buff, size_t count, FILE* fp, int indent)
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
			fprintf(fp, "%*s%.4zu ", indent, "", i & 0xffff);
		}
		if (i < count)
			fprintf(fp, "%3.2x", (unsigned char)buff[i] & 0xff);
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

#if defined _CHECKSUM_DEBUG_ || defined _RECVMSG_DEBUG_
void
log_buffer(const char *msg, const void *buff, size_t count)
{
	char op_buf[60];	// Probably 56 really
	const unsigned char *bufp = buff;
	char *ptr;
	size_t offs = 0;
	unsigned i;

	log_message(LOG_INFO, "%s - len %zu", msg, count);

	while (offs < count) {
		ptr = op_buf;
		ptr += snprintf(ptr, op_buf + sizeof(op_buf) - ptr, "%4.4zx ", offs);

		for (i = 0; i < 16 && offs < count; i++) {
			if (i == 8)
				*ptr++ = ' ';
			ptr += snprintf(ptr, op_buf + sizeof(op_buf) - ptr, " %2.2x", bufp[offs++]);
		}

		log_message(LOG_INFO, "%s", op_buf);
	}
}
#endif

#ifdef _WITH_STACKTRACE_
void
write_stacktrace(const char *file_name, const char *str)
{
	int fd;
	void *buffer[100];
	unsigned int nptrs;
	unsigned int i;
	char **strs;
	char cmd[40];

	nptrs = backtrace(buffer, 100);
	if (file_name) {
		fd = open(file_name, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		if (str)
			dprintf(fd, "%s\n", str);
		backtrace_symbols_fd(buffer, nptrs, fd);
		if (write(fd, "\n", 1) != 1) {
			/* We don't care, but this stops a warning on Ubuntu */
		}
		close(fd);
	} else {
		if (str)
			log_message(LOG_INFO, "%s", str);
		strs = backtrace_symbols(buffer, nptrs);
		if (strs == NULL) {
			log_message(LOG_INFO, "Unable to get stack backtrace");
			return;
		}

		/* We don't need the call to this function, or the first two entries on the stack */
		nptrs -= 2;
		for (i = 1; i < nptrs; i++)
			log_message(LOG_INFO, "  %s", strs[i]);
		free(strs);	/* malloc'd by backtrace_symbols */
	}

	/* gstack() gives a more detailed stacktrace, using gdb and the bt command */
	sprintf(cmd, "gstack %d >>%s", getpid(), file_name ? file_name : KA_TMP_DIR "/keepalived.stack");
	system(cmd);
}
#endif

const char *
make_file_name(const char *name, const char *prog, const char *namespace, const char *instance)
{
	const char *extn_start;
	const char *dir_end;
	size_t len;
	char *file_name;

	if (!name)
		return NULL;

	len = strlen(name);
	if (prog)
		len += strlen(prog) + 1;
	if (namespace)
		len += strlen(namespace) + 1;
	if (instance)
		len += strlen(instance) + 1;

	file_name = MALLOC(len + 1);
	dir_end = strrchr(name, '/');
	extn_start = strrchr(dir_end ? dir_end : name, '.');
	strncpy(file_name, name, extn_start ? (size_t)(extn_start - name) : len);

	if (prog) {
		strcat(file_name, "_");
		strcat(file_name, prog);
	}
	if (namespace) {
		strcat(file_name, "_");
		strcat(file_name, namespace);
	}
	if (instance) {
		strcat(file_name, "_");
		strcat(file_name, instance);
	}
	if (extn_start)
		strcat(file_name, extn_start);

	return file_name;
}

void
set_process_name(const char *name)
{
	if (!name)
		name = "keepalived";

	if (prctl(PR_SET_NAME, name))
		log_message(LOG_INFO, "Failed to set process name '%s'", name);
}

#ifdef _WITH_PERF_
void
run_perf(const char *process, const char *network_namespace, const char *instance_name)
{
	int ret;
	pid_t pid;
	char *orig_name = NULL;
	const char *new_name;
	const char *perf_name = "perf.data";
	int in = -1;
	int ep = -1;

	do {
		orig_name = MALLOC(PATH_MAX);
		if (!getcwd(orig_name, PATH_MAX)) {
			log_message(LOG_INFO, "Unable to get cwd");
			break;
		}

		in = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
		if (in == -1) {
			log_message(LOG_INFO, "inotify_init failed %d - %m", errno);
			break;
		}

		if (inotify_add_watch(in, orig_name, IN_CREATE) == -1) {
			log_message(LOG_INFO, "inotify_add_watch of %s failed %d - %m", orig_name, errno);
			break;
		}

		pid = fork();

		if (pid == -1) {
			log_message(LOG_INFO, "fork() for perf failed");
			break;
		}

		/* Child */
		if (!pid) {
			char buf[PID_MAX_DIGITS + 1];

			snprintf(buf, sizeof buf, "%d", getppid());
			execlp("perf", "perf", "record", "-p", buf, "-q", "-g", "--call-graph", "fp", NULL);
			exit(0);
		}

		/* Parent */
		char buf[sizeof(struct inotify_event) + NAME_MAX + 1] __attribute__((aligned(__alignof__(struct inotify_event))));
		struct inotify_event *ie = PTR_CAST(struct inotify_event, buf);
		struct epoll_event ee = { .events = EPOLLIN, .data.fd = in };

		if ((ep = epoll_create(1)) == -1) {
			log_message(LOG_INFO, "perf epoll_create failed errno %d - %m", errno);
			break;
		}

		if (epoll_ctl(ep, EPOLL_CTL_ADD, in, &ee) == -1) {
			log_message(LOG_INFO, "perf epoll_ctl failed errno %d - %m", errno);
			break;
		}

		do {
			ret = epoll_wait(ep, &ee, 1, 1000);
			if (ret == 0) {
				log_message(LOG_INFO, "Timed out waiting for creation of %s", perf_name);
				break;
			}
			else if (ret == -1) {
				if (check_EINTR(errno))
					continue;

				log_message(LOG_INFO, "perf epoll returned errno %d - %m", errno);
				break;
			}

			ret = read(in, buf, sizeof(buf));
			if (ret == -1) {
				if (check_EINTR(errno))
					continue;

				log_message(LOG_INFO, "perf inotify read returned errno %d %m", errno);
				break;
			}
			if (ret < (int)sizeof(*ie)) {
				log_message(LOG_INFO, "read returned %d", ret);
				break;
			}
			if (!(ie->mask & IN_CREATE)) {
				log_message(LOG_INFO, "mask is 0x%x", ie->mask);
				continue;
			}
			if (!ie->len) {
				log_message(LOG_INFO, "perf inotify read returned no len");
				continue;
			}

			if (strcmp(ie->name, perf_name))
				continue;

			/* Rename the /perf.data file */
			strcat(orig_name, perf_name);
			new_name = make_file_name(orig_name, process,
							network_namespace,
							instance_name);

			if (rename(orig_name, new_name))
				log_message(LOG_INFO, "Rename %s to %s failed - %m (%d)", orig_name, new_name, errno);

			FREE_CONST(new_name);
		} while (false);
	} while (false);

	if (ep != -1)
		close(ep);
	if (in != -1)
		close(in);
	if (orig_name)
		FREE(orig_name);
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
		sum += htons(*PTR_CAST_CONST(u_char, w) << 8);

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

/* IP network to ascii representation - address is in network byte order */
const char *
inet_ntop2(uint32_t ip)
{
	static char buf[16];
	const unsigned char (*bytep)[4] = (unsigned char (*)[4])&ip;

	sprintf(buf, "%d.%d.%d.%d", (*bytep)[0], (*bytep)[1], (*bytep)[2], (*bytep)[3]);
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
	const unsigned char *bytep;

	bytep = PTR_CAST_CONST(unsigned char, &ip);
	sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
	return buf;
}
#endif

/* IP string to network range representation. */
bool
inet_stor(const char *addr, uint32_t *range_end)
{
	const char *cp;
	char *endptr;
	unsigned long range;
	int family = strchr(addr, ':') ? AF_INET6 : AF_INET;
	const char *warn = "";

#ifndef _STRICT_CONFIG_
	if (!__test_bit(CONFIG_TEST_BIT, &debug))
		warn = "WARNING - ";
#endif

	/* Return UINT32_MAX to indicate no range */
	if (!(cp = strchr(addr, '-'))) {
		*range_end = UINT32_MAX;
		return true;
	}

	errno = 0;
	range = strtoul(cp + 1, &endptr, family == AF_INET6 ? 16 : 10);
	*range_end = range;

	if (*endptr)
		report_config_error(CONFIG_INVALID_NUMBER, "%sVirtual server group range '%s' has extra characters at end '%s'", warn, addr, endptr);
	else if (errno == ERANGE ||
		 (family == AF_INET6 && range > 0xffff) ||
		 (family == AF_INET && range > 255)) {
		report_config_error(CONFIG_INVALID_NUMBER, "Virtual server group range '%s' end '%s' too large", addr, cp + 1);

		/* Indicate error */
		return false;
	}
	else
		return true;

#ifdef _STRICT_CONFIG_
	return false;
#else
	return !__test_bit(CONFIG_TEST_BIT, &debug);
#endif
}

/* Domain to sockaddr_storage */
int
domain_stosockaddr(const char *domain, const char *port, struct sockaddr_storage *addr)
{
	struct addrinfo *res = NULL;
	unsigned port_num;

	if (port) {
		if (!read_unsigned(port, &port_num, 1, 65535, true)) {
			addr->ss_family = AF_UNSPEC;
			return -1;
		}
	}

	if (getaddrinfo(domain, NULL, NULL, &res) != 0 || !res) {
		addr->ss_family = AF_UNSPEC;
		return -1;
	}

	addr->ss_family = (sa_family_t)res->ai_family;

	/* Tempting as it is to do something like:
	 *	*(struct sockaddr_in6 *)addr = *(struct sockaddr_in6 *)res->ai_addr;
	 *  the alignment of struct sockaddr (short int) is less than the alignment of
	 *  struct sockaddr_storage (long).
	 */
	memcpy(addr, res->ai_addr, res->ai_addrlen);

	if (port) {
		if (addr->ss_family == AF_INET6)
			PTR_CAST(struct sockaddr_in6, addr)->sin6_port = htons(port_num);
		else
			PTR_CAST(struct sockaddr_in, addr)->sin_port = htons(port_num);
	}

	freeaddrinfo(res);

	return 0;
}

/* IP string to sockaddr_storage
 *   return value is "error". */
bool
inet_stosockaddr(const char *ip, const char *port, struct sockaddr_storage *addr)
{
	void *addr_ip;
	const char *cp;
	char *ip_str = NULL;
	unsigned port_num;
	int res;

	addr->ss_family = (strchr(ip, ':')) ? AF_INET6 : AF_INET;

	if (port) {
		if (!read_unsigned(port, &port_num, 1, 65535, true)) {
			addr->ss_family = AF_UNSPEC;
			return true;
		}
	}

	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = PTR_CAST(struct sockaddr_in6, addr);
		if (port)
			addr6->sin6_port = htons(port_num);
		addr_ip = &addr6->sin6_addr;
	} else {
		struct sockaddr_in *addr4 = PTR_CAST(struct sockaddr_in, addr);
		if (port)
			addr4->sin_port = htons(port_num);
		addr_ip = &addr4->sin_addr;
	}

	/* remove range and mask stuff */
	if ((cp = strchr(ip, '-')) ||
	    (cp = strchr(ip, '/')))
		ip_str = STRNDUP(ip, cp - ip);

	res = inet_pton(addr->ss_family, ip_str ? ip_str : ip, addr_ip);

	if (ip_str)
		FREE(ip_str);

	if (!res) {
		addr->ss_family = AF_UNSPEC;
		return true;
	}

	return false;
}

/* IPv4 to sockaddr_storage */
void
inet_ip4tosockaddr(const struct in_addr *sin_addr, struct sockaddr_storage *addr)
{
	struct sockaddr_in *addr4 = PTR_CAST(struct sockaddr_in, addr);
	addr4->sin_family = AF_INET;
	addr4->sin_addr = *sin_addr;
}

/* IPv6 to sockaddr_storage */
void
inet_ip6tosockaddr(const struct in6_addr *sin_addr, struct sockaddr_storage *addr)
{
	struct sockaddr_in6 *addr6 = PTR_CAST(struct sockaddr_in6, addr);
	addr6->sin6_family = AF_INET6;
	addr6->sin6_addr = *sin_addr;
}

/* Check address, possibly with mask, is valid */
bool
check_valid_ipaddress(const char *str, bool allow_subnet_mask)
{
	int family;
	unsigned long prefixlen;
	const char *p;
	char *endptr;
	union {
		struct in_addr in;
		struct in6_addr in6;
	} addr;
	int res;
	const char *str_dup = NULL;

	if (!strchr(str, ':') && !strchr(str, '.'))
		return false;

	family = (strchr(str, ':')) ? AF_INET6 : AF_INET;

	if (allow_subnet_mask)
		p = strchr(str, '/');
	else
		p = NULL;

	if (p) {
		if (!p[1])
			return false;
		prefixlen = strtoul(p + 1, &endptr, 10);
		if (*endptr || prefixlen > (family == AF_INET6 ? 128 : 32))
			return false;
		str_dup = STRNDUP(str, p - str);
	}

	res = inet_pton(family, str_dup ? str_dup : str, &addr);

	if (str_dup)
		FREE_CONST(str_dup);

	return res;
}

/* IP network to string representation */
static char *
inet_sockaddrtos2(const struct sockaddr_storage *addr, char *addr_str)
{
	const void *addr_ip;

	if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *addr6 = PTR_CAST_CONST(struct sockaddr_in6, addr);
		addr_ip = &addr6->sin6_addr;
	} else {
		const struct sockaddr_in *addr4 = PTR_CAST_CONST(struct sockaddr_in, addr);
		addr_ip = &addr4->sin_addr;
	}

	if (!inet_ntop(addr->ss_family, addr_ip, addr_str, INET6_ADDRSTRLEN))
		return NULL;

	return addr_str;
}

const char *
inet_sockaddrtos(const struct sockaddr_storage *addr)
{
	static char addr_str[INET6_ADDRSTRLEN];
	inet_sockaddrtos2(addr, addr_str);
	return addr_str;
}

uint16_t __attribute__ ((pure))
inet_sockaddrport(const struct sockaddr_storage *addr)
{
	if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *addr6 = PTR_CAST_CONST(struct sockaddr_in6, addr);
		return addr6->sin6_port;
	}

	/* Note: this might be AF_UNSPEC if it is the sequence number of
	 * a virtual server in a virtual server group */
	const struct sockaddr_in *addr4 = PTR_CAST_CONST(struct sockaddr_in, addr);
	return addr4->sin_port;
}

void
inet_set_sockaddrport(struct sockaddr_storage *addr, uint16_t port)
{
	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = PTR_CAST(struct sockaddr_in6, addr);
		addr6->sin6_port = port;
	} else {
		struct sockaddr_in *addr4 = PTR_CAST(struct sockaddr_in, addr);
		addr4->sin_port = port;
	}
}

const char *
inet_sockaddrtopair(const struct sockaddr_storage *addr)
{
	char addr_str[INET6_ADDRSTRLEN];
	static char ret[sizeof(addr_str) + 8];	/* '[' + addr_str + ']' + ':' + 'nnnnn' */

	inet_sockaddrtos2(addr, addr_str);
	snprintf(ret, sizeof(ret), "[%s]:%d"
		, addr_str
		, ntohs(inet_sockaddrport(addr)));
	return ret;
}

char *
inet_sockaddrtotrio_r(const struct sockaddr_storage *addr, uint16_t proto, char *buf)
{
	char addr_str[INET6_ADDRSTRLEN];
	const char *proto_str =
			proto == IPPROTO_TCP ? "tcp" :
			proto == IPPROTO_UDP ? "udp" :
			proto == IPPROTO_SCTP ? "sctp" :
			proto == 0 ? "none" : "?";

	inet_sockaddrtos2(addr, addr_str);
	snprintf(buf, SOCKADDRTRIO_STR_LEN, "[%s]:%s:%d", addr_str, proto_str,
		 ntohs(inet_sockaddrport(addr)));
	return buf;
}

const char *
inet_sockaddrtotrio(const struct sockaddr_storage *addr, uint16_t proto)
{
	static char ret[SOCKADDRTRIO_STR_LEN];

	inet_sockaddrtotrio_r(addr, proto, ret);

	return ret;
}

uint32_t __attribute__ ((pure))
inet_sockaddrip4(const struct sockaddr_storage *addr)
{
	if (addr->ss_family != AF_INET)
		return 0xffffffff;

	return PTR_CAST_CONST(struct sockaddr_in, addr)->sin_addr.s_addr;
}

int
inet_sockaddrip6(const struct sockaddr_storage *addr, struct in6_addr *ip6)
{
	if (addr->ss_family != AF_INET6)
		return -1;

	*ip6 = PTR_CAST_CONST(struct sockaddr_in6, addr)->sin6_addr;
	return 0;
}

/* IPv6 address compare */
int __attribute__ ((pure))
inet_inaddrcmp(const int family, const void *a, const void *b)
{
	int64_t addr_diff;

	if (family == AF_INET) {
		addr_diff = (int64_t)ntohl(*PTR_CAST_CONST(uint32_t, a)) - (int64_t)ntohl(*PTR_CAST_CONST(uint32_t, b));
		if (addr_diff > 0)
			return 1;
		if (addr_diff < 0)
			return -1;
		return 0;
	}

	if (family == AF_INET6) {
		int i;

		for (i = 0; i < 4; i++ ) {
			addr_diff = (int64_t)ntohl(PTR_CAST_CONST(uint32_t, (a))[i]) - (int64_t)ntohl(PTR_CAST_CONST(uint32_t, (b))[i]);
			if (addr_diff > 0)
				return 1;
			if (addr_diff < 0)
				return -1;
		}
		return 0;
	}

	return -2;
}

int  __attribute__ ((pure))
inet_sockaddrcmp(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family)
		return -2;

	if (a->ss_family == AF_INET)
		return inet_inaddrcmp(a->ss_family,
				      &PTR_CAST_CONST(struct sockaddr_in, a)->sin_addr,
				      &PTR_CAST_CONST(struct sockaddr_in, b)->sin_addr);
	if (a->ss_family == AF_INET6)
		return inet_inaddrcmp(a->ss_family,
				      &PTR_CAST_CONST(const struct sockaddr_in6, a)->sin6_addr,
				      &PTR_CAST_CONST(const struct sockaddr_in6, b)->sin6_addr);
	return 0;
}


#ifdef _INCLUDE_UNUSED_CODE_
/*
 * IP string to network representation
 * Highly inspired from Paul Vixie code.
 */
int
inet_ston(const char *addr, uint32_t *dst)
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

void
format_mac_buf(char *op, size_t op_len, const unsigned char *addr, size_t addr_len)
{
	size_t i;
	char *buf_end = op + op_len;

	/* If there is no address, clear the op buffer */
	if (!addr_len && op_len) {
		op[0] = '\0';
		return;
	}

	for (i = 0; i < addr_len; i++) {
		op += snprintf(op, buf_end - op, "%.2x%s",
		      addr[i], i < addr_len -1 ? ":" : "");
		if (op >= buf_end - 1)
			break;
	}
}

/* Getting localhost official canonical name */
const char * __attribute__((malloc))
get_local_name(void)
{
	struct utsname name;
	struct addrinfo hints, *res = NULL;
	char *canonname = NULL;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;

	if (uname(&name) < 0)
		return NULL;

	if (getaddrinfo(name.nodename, NULL, &hints, &res) != 0)
		return NULL;

	if (res && res->ai_canonname)
		canonname = STRDUP(res->ai_canonname);

	freeaddrinfo(res);

	return canonname;
}

/* String compare with NULL string handling */
bool __attribute__ ((pure))
string_equal(const char *str1, const char *str2)
{
	if (!str1 && !str2)
		return true;
	if (!str1 != !str2)
		return false;

	return !strcmp(str1, str2);
}

/* Convert an integer into a string */
int
integer_to_string(const int value, char *str, size_t size)
{
	int i, len = 0, t = value, s = size;

	for (i = value; i; i/=10) {
		if (++len > s)
			return -1;
	}

	for (i = 0; i < len; i++,t/=10)
		str[len - (i + 1)] = t % 10 + '0';

	return len;
}

/* We need to use O_NOFOLLOW if opening a file for write, so that a non privileged user can't
 * create a symbolic link from the path to a system file and cause a system file to be overwritten. */
FILE * __attribute__((malloc))
fopen_safe(const char *path, const char *mode)
{
	int fd;
	FILE *file;
#ifdef ENABLE_LOG_FILE_APPEND
	int flags = O_NOFOLLOW | O_CREAT | O_CLOEXEC;
#endif
	int sav_errno;
	char file_tmp_name[PATH_MAX];

	if (mode[0] == 'r')
		return fopen(path, mode);

	if ((mode[0] != 'a' && mode[0] != 'w') ||
	    (mode[1] &&
	     (mode[1] != '+' || mode[2]))) {
		errno = EINVAL;
		return NULL;
	}

	if (mode[0] == 'w') {
		/* If we truncate an existing file, any non-privileged user who already has the file
		 * open would be able to read what we write, even though the file access mode is changed.
		 *
		 * If we unlink an existing file and the desired file is subsequently created via open,
		 * it leaves a window for someone else to create the same file between the unlink and the open.
		 *
		 * The solution is to create a temporary file that we will rename to the desired file name.
		 * Since the temporary file is created owned by root with the only file access permissions being
		 * owner read and write, no non root user will have access to the file. Further, the rename to
		 * the requested filename is atomic, and so there is no window when someone else could create
		 * another file of the same name.
		 */
		strcpy_safe(file_tmp_name, path);
		if (strlen(path) + 6 < sizeof(file_tmp_name))
			strcat(file_tmp_name, "XXXXXX");
		else
			strcpy(file_tmp_name + sizeof(file_tmp_name) - 6 - 1, "XXXXXX");
		fd = mkostemp(file_tmp_name, O_CLOEXEC);
	} else {
		/* Only allow append mode if debugging features requiring append are enabled. Since we
		 * can't unlink the file, there may be a non privileged user who already has the file open
		 * for read (e.g. tail -f). If these debug option aren't enabled, there is no potential
		 * security risk in that respect. */
#ifndef ENABLE_LOG_FILE_APPEND
		log_message(LOG_INFO, "BUG - shouldn't be opening file for append with current build options");
		errno = EINVAL;
		return NULL;
#else
		flags = O_NOFOLLOW | O_CREAT | O_CLOEXEC | O_APPEND;

		if (mode[1])
			flags |= O_RDWR;
		else
			flags |= O_WRONLY;

		fd = open(path, flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
#endif
	}

	if (fd == -1) {
		sav_errno = errno;
		log_message(LOG_INFO, "Unable to open '%s' - errno %d (%m)", path, errno);
		errno = sav_errno;
		return NULL;
	}

#ifndef ENABLE_LOG_FILE_APPEND
	/* Change file ownership to root */
	if (mode[0] == 'a' && fchown(fd, 0, 0)) {
		sav_errno = errno;
		log_message(LOG_INFO, "Unable to change file ownership of %s- errno %d (%m)", path, errno);
		close(fd);
		errno = sav_errno;
		return NULL;
	}
#endif

	/* Set file mode, default rw------- */
	if (fchmod(fd, (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) & ~umask_val)) {
		sav_errno = errno;
		log_message(LOG_INFO, "Unable to change file permission of %s - errno %d (%m)", path, errno);
		close(fd);
		errno = sav_errno;
		return NULL;
	}

	if (mode[0] == 'w') {
		/* Rename the temporary file to the one we want */
		if (rename(file_tmp_name, path)) {
			sav_errno = errno;
			log_message(LOG_INFO, "Failed to rename %s to %s - errno %d (%m)", file_tmp_name, path, errno);
			close(fd);
			errno = sav_errno;
			return NULL;
		}
	}

	file = fdopen (fd, "w");
	if (!file) {
		sav_errno = errno;
		log_message(LOG_INFO, "fdopen(\"%s\") failed - errno %d (%m)", path, errno);
		close(fd);
		errno = sav_errno;
		return NULL;
	}

	return file;
}

void
set_std_fd(bool force)
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

	/* coverity[leaked_handle] */
}

void
close_std_fd(void)
{
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
}

#if defined _WITH_VRRP_ || defined _WITH_BFD_
int
open_pipe(int pipe_arr[2])
{
	/* Open pipe */
	if (pipe2(pipe_arr, O_CLOEXEC | O_NONBLOCK) == -1)
		return -1;

	return 0;
}
#endif

/*
 * memcmp time constant variant.
 * Need to ensure compiler doesnt get too smart by optimizing generated asm code.
 */
__attribute__((optimize("O0"))) int
memcmp_constant_time(const void *s1, const void *s2, size_t n)
{
	const unsigned char *a, *b;
	unsigned char ret = 0;
	size_t i;

	for (i = 0, a = s1, b = s2; i < n; i++)
		ret |= (*a++ ^ *b++);

	return ret;
}

/*
 * Utility functions coming from Wensong code
 */

#if defined _WITH_LVS_ || defined _HAVE_LIBIPSET_
static char*
get_modprobe(void)
{
	int procfile;
	char *ret;
	ssize_t count;
	struct stat buf;

	ret = MALLOC(PATH_MAX);
	if (!ret)
		return NULL;

	procfile = open("/proc/sys/kernel/modprobe", O_RDONLY | O_CLOEXEC);
	if (procfile < 0) {
		FREE(ret);
		return NULL;
	}

	count = read(procfile, ret, PATH_MAX - 1);
	ret[PATH_MAX - 1] = '\0';
	close(procfile);

	if (count > 0 && count < PATH_MAX - 1)
	{
		if (ret[count - 1] == '\n')
			ret[count - 1] = '\0';
		else
			ret[count] = '\0';

		/* Check it is a regular file, with a execute bit set */
		if (!stat(ret, &buf) &&
		    S_ISREG(buf.st_mode) &&
		    (buf.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)))
			return ret;
	}

	FREE(ret);

	return NULL;
}

bool
keepalived_modprobe(const char *mod_name)
{
	const char *argv[] = { "/sbin/modprobe", "-s", "--", mod_name, NULL };
	int child;
	int status;
	int rc;
	char *modprobe = get_modprobe();
	struct sigaction act, old_act;
	union non_const_args args;

	if (modprobe)
		argv[0] = modprobe;

	act.sa_handler = SIG_DFL;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	sigaction ( SIGCHLD, &act, &old_act);

#ifdef ENABLE_LOG_TO_FILE
	if (log_file_name)
		flush_log_file();
#endif

	if (!(child = fork())) {
		args.args = argv;
		/* coverity[tainted_string] */
		execv(argv[0], args.execve_args);
		exit(1);
	}

	rc = waitpid(child, &status, 0);

	sigaction ( SIGCHLD, &old_act, NULL);

	if (rc < 0) {
		log_message(LOG_INFO, "IPVS: waitpid error (%s)"
				    , strerror(errno));
	}

	if (modprobe)
		FREE(modprobe);

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		return true;
	}

	return false;
}
#endif
