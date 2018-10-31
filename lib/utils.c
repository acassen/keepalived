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
#include <stdint.h>
#include <errno.h>
#ifdef _WITH_PERF_
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#endif

#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
#include <signal.h>
#include <sys/wait.h>
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
#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_ || defined _WITH_STACKTRACE_ || defined _WITH_PERF_
#include "logger.h"
#endif
#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
#include "process.h"
#endif

/* global vars */
unsigned long debug = 0;

/* Display a buffer into a HEXA formated output */
void
dump_buffer(char *buff, size_t count, FILE* fp, int indent)
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
write_stacktrace(const char *file_name, const char *str)
{
	int fd;
	void *buffer[100];
	int nptrs;
	int i;
	char **strs;

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
		for (i = 1; i < nptrs - 2; i++)
			log_message(LOG_INFO, "  %s", strs[i]);
		free(strs);
	}
}
#endif

char *
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

#ifdef _WITH_PERF_
void
run_perf(const char *process, const char *network_namespace, const char *instance_name)
{
	int ret;
	pid_t pid;
	char *orig_name = NULL;
	char *new_name;
	const char *perf_name = "perf.data";
	int in = -1;
	int ep = -1;

	do {
		orig_name = MALLOC(PATH_MAX);
		if (!getcwd(orig_name, PATH_MAX)) {
			log_message(LOG_INFO, "Unable to get cwd");
			break;
		}

#ifdef IN_CLOEXEC
		in = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
#else
		if ((in = inotify_init()) != -1) {
			fcntl(in, F_SETFD, FD_CLOEXEC | fcntl(n, F_GETFD));
			fcntl(in, F_SETFL, O_NONBLOCK | fcntl(n, F_GETFL));
		}
#endif
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
			char buf[9];

			snprintf(buf, sizeof buf, "%d", getppid());
			execlp("perf", "perf", "record", "-p", buf, "-q", "-g", "--call-graph", "fp", NULL);
			exit(0);
		}

		/* Parent */
		char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
		struct inotify_event *ie = (struct inotify_event*)buf;
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
				if (errno == EINTR)
					continue;
				log_message(LOG_INFO, "perf epoll returned errno %d - %m", errno);
				break;
			}

			ret = read(in, buf, sizeof(buf));
			if (ret == -1) {
				if (errno == EINTR)
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
#if HAVE_DECL_CLONE_NEWNET
							network_namespace,
#else
							NULL,
#endif
							instance_name);

			if (rename(orig_name, new_name))
				log_message(LOG_INFO, "Rename %s to %s failed - %m (%d)", orig_name, new_name, errno);

			FREE(new_name);
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
#endif

/* IP string to network range representation. */
bool
inet_stor(const char *addr, uint32_t *range_end)
{
	const char *cp;
	char *endptr;
	unsigned long range;
	int family = strchr(addr, ':') ? AF_INET6 : AF_INET;
	char *warn = "";

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

	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
		*addr6 = *(struct sockaddr_in6 *)res->ai_addr;
		if (port)
			addr6->sin6_port = htons(port_num);
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
		*addr4 = *(struct sockaddr_in *)res->ai_addr;
		if (port)
			addr4->sin_port = htons(port_num);
	}

	freeaddrinfo(res);

	return 0;
}

/* IP string to sockaddr_storage */
int
inet_stosockaddr(char *ip, const char *port, struct sockaddr_storage *addr)
{
	void *addr_ip;
	char *cp;
	char sav_cp;
	unsigned port_num;
	int res;

	addr->ss_family = (strchr(ip, ':')) ? AF_INET6 : AF_INET;

	if (port) {
		if (!read_unsigned(port, &port_num, 1, 65535, true)) {
			addr->ss_family = AF_UNSPEC;
			return -1;
		}
	}

	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
		if (port)
			addr6->sin6_port = htons(port_num);
		addr_ip = &addr6->sin6_addr;
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		if (port)
			addr4->sin_port = htons(port_num);
		addr_ip = &addr4->sin_addr;
	}

	/* remove range and mask stuff */
	if ((cp = strchr(ip, '-')) ||
	    (cp = strchr(ip, '/'))) {
		sav_cp = *cp;
		*cp = 0;
	}

	res = inet_pton(addr->ss_family, ip, addr_ip);

	/* restore range and mask stuff */
	if (cp)
		*cp = sav_cp;

	if (!res) {
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
		/* Note: this might be AF_UNSPEC if it is the sequence number of
		 * a virtual server in a virtual server group */
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		port = addr4->sin_port;
	}

	return port;
}

char *
inet_sockaddrtopair(struct sockaddr_storage *addr)
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
inet_sockaddrtotrio(struct sockaddr_storage *addr, uint16_t proto)
{
	char addr_str[INET6_ADDRSTRLEN];
	static char ret[sizeof(addr_str) + 13];	/* '[' + addr_str + ']' + ':' + 'sctp' + ':' + 'nnnnn' */
	char *proto_str = proto == IPPROTO_TCP ? "tcp" : proto == IPPROTO_UDP ? "udp" : proto == IPPROTO_SCTP ? "sctp" : proto == 0 ? "none" : "?";

	inet_sockaddrtos2(addr, addr_str);
	snprintf(ret, sizeof(ret), "[%s]:%s:%d" ,addr_str, proto_str,
		 ntohs(inet_sockaddrport(addr)));
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
inet_inaddrcmp(const int family, const void *a, const void *b)
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
inet_sockaddrcmp(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
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
bool
string_equal(const char *str1, const char *str2)
{
	if (!str1 && !str2)
		return true;
	if (!str1 != !str2)
		return false;

	return !strcmp(str1, str2);
}

/* We need to use O_NOFOLLOW if opening a file for write, so that a non privileged user can't
 * create a symbolic link from the path to a system file and cause a system file to be overwritten. */
FILE *fopen_safe(const char *path, const char *mode)
{
	int fd;
	FILE *file;
	int flags = O_NOFOLLOW | O_CREAT;

	if (mode[0] == 'r')
		return fopen(path, mode);

	if (mode[0] != 'a' && mode[0] != 'w')
		return NULL;

	if (mode[1] &&
	    (mode[1] != '+' || mode[2]))
		return NULL;

	if (mode[0] == 'w')
		flags |= O_TRUNC;
	else
		flags |= O_APPEND;

	if (mode[1])
		flags |= O_RDWR;
	else
		flags |= O_WRONLY;

	fd = open(path, flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (fd == -1)
		return NULL;

	file = fdopen (fd, "w");
	if (!file) {
		close(fd);
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

	signal_fd_close(STDERR_FILENO+1);
}

void
close_std_fd(void)
{
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
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

	if (log_file_name)
		flush_log_file();

	pid = local_fork();
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

#if defined _WITH_VRRP_ || defined _WITH_BFD_
int
open_pipe(int pipe_arr[2])
{
	/* Open pipe */
#ifdef HAVE_PIPE2
	if (pipe2(pipe_arr, O_CLOEXEC | O_NONBLOCK) == -1)
#else
	if (pipe(pipe_arr) == -1)
#endif
		return -1;

#ifndef HAVE_PIPE2
	fcntl(pipe_arr[0], F_SETFL, O_NONBLOCK | fcntl(pipe_arr[0], F_GETFL));
	fcntl(pipe_arr[1], F_SETFL, O_NONBLOCK | fcntl(pipe_arr[1], F_GETFL));

	fcntl(pipe_arr[0], F_SETFD, FD_CLOEXEC | fcntl(pipe_arr[0], F_GETFD));
	fcntl(pipe_arr[1], F_SETFD, FD_CLOEXEC | fcntl(pipe_arr[1], F_GETFD));
#endif

	return 0;
}
#endif
