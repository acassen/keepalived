#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>

struct cmd_resp {
	struct cmd_resp *next;
	char *cmd;
	char *resp;
};

static struct cmd_resp *cmd_resp_list;
static char EOL = '\r';
static struct timespec rep_delay;
static bool random_delay;
static int random_seed = 0;

static void find_resp(int fd, const char *cmd)
{
	struct cmd_resp *p;
	const char *s, *e;
	size_t len;
	const char *resp;
	struct timespec delay;

//printf("Processing: '%s', end = %d\n", cmd, cmd[strlen(cmd)-1]);
	s = cmd;
	for (s = cmd; *s; s = *e ? e + 1 : e) {
		e = strchr(s, EOL);
		if (!e)
			e = s + strlen(s);
		len = e - s;
//printf("Looking for '%.*s'\n", len, s);

		resp = s;
		for (p = cmd_resp_list; p; p = p->next) {
			if (len == strlen(p->cmd) &&
			    !strncmp(p->cmd, s, len)) {
//printf("Found %s -> %s\n", p->cmd, p->resp);
				resp = p->resp;
				len = strlen(resp);
				if (!len)
					exit(0);
				break;
			}
		}
		if (rep_delay.tv_nsec || rep_delay.tv_sec) {
			if (random_delay) {
				delay.tv_nsec = (rep_delay.tv_sec * 1000000000 + rep_delay.tv_nsec) * random();
				delay.tv_sec = delay.tv_nsec / 1000000000;
				delay.tv_nsec %= 1000000000;
			} else
				delay = rep_delay;
			nanosleep(&delay, NULL);
		}

printf("Replying '%.*s'\n", len, resp);
		write(fd, resp, len);
	}
}

static void
process_data(int fd)
{
	char buf[129];
	int len;

	while ((len = read(fd, buf, sizeof(buf) - 1)) > 0) {
		/* Exit if receive ^D */
		if (len == 1 && buf[0] == 4)
			return;
		if (cmd_resp_list) {
			buf[len] = '\0';
			find_resp(fd, buf);
		} else
			write(fd, buf, len);
	}
}

int main(int argc, char **argv)
{
	int family = AF_UNSPEC;
	int port = 30080;
	int listenfd, connfd;
	pid_t childpid;
	socklen_t clilen;
	struct sockaddr_in cliaddr, servaddr;
	struct sockaddr_in6 cliaddr6, servaddr6;
	int opt;
	int sock_type = SOCK_STREAM;
	int n;
	char buf[128];
	struct sigaction sa;
	bool silent = false;
	char *addr_str = NULL;
	char addr_buf[sizeof (struct in6_addr)];
	bool echo_data = false;
	char *endptr;
	long port_num;
	unsigned backlog = 4;
	struct cmd_resp *cr;

	while ((opt = getopt(argc, argv, ":46a:p:sueb:c:l:d:r")) != -1) {
		switch (opt) {
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		case 'a':
			addr_str = optarg;
			break;
		case 'p':
			port_num = strtol(optarg, &endptr, 10);
			if (*endptr || port_num <= 0 || port_num > 65535) {
				fprintf(stderr, "Port number '%s' invalid\n", optarg);
				exit(EXIT_FAILURE);
			}
			port = port_num;
			break;
		case 's':
			silent = true;
			break;
		case 'u':
			sock_type = SOCK_DGRAM;
			break;
		case 'e':
			echo_data = true;
			break;
		case 'b':
			backlog = strtoul(optarg, &endptr, 10);
			if (*endptr || backlog > 65535) {
				fprintf(stderr, "Backlog '%s' invalid\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'c':
			if (optind >= argc) {
				fprintf(stderr, "-c '%s' missing response\n", optarg);
				exit(EXIT_FAILURE);
			}

			cr = malloc(sizeof(struct cmd_resp));
			cr->next = cmd_resp_list;
			cmd_resp_list = cr;
			cr->cmd = malloc(strlen(optarg)+1);
			cr->resp = malloc(strlen(argv[optind]) + 1);
			strcpy(cr->cmd, optarg);
			strcpy(cr->resp, argv[optind++]);
			break;
		case 'l':
			EOL = strtoul(optarg, &endptr, 10);
			break;
		case 'd':
			rep_delay.tv_nsec = strtoul(optarg, &endptr, 10);
			rep_delay.tv_sec = rep_delay.tv_nsec / 1000;
			rep_delay.tv_nsec %= 1000;
			rep_delay.tv_nsec *= 1000000;
			break;
		case 'r':
			random_delay = true;
			if (optind < argc && argv[optind][0] != '-')
				random_seed = strtoul(argv[optind++], &endptr, 10);
			break;
		case ':':
			fprintf(stderr, "Option '%c' is missing an argument\n", optopt);
			break;
		default: /* '?' */
			fprintf(stderr, "Usage: %s [-a bind address] [-p port] [-4] [-6] [-s(ilent)] [-u(dp)] [-e(cho)] [-b(acklog) n][-c cmd resp] [-l EOL char value] [-d reply-delay [-r]]\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (random_delay) {
		if (!random_seed)
			random_seed = time(NULL);
		srandom(random_seed);
	}

	if (addr_str) {
		if (family == AF_UNSPEC) {
			if (strchr(addr_str, ':'))
				family = AF_INET6;
			else
				family = AF_INET;
		}
			
		if (inet_pton(family, addr_str, addr_buf) != 1) {
			printf("Invalid IPv%d address - %s\n", family == AF_INET ? 4 : 6, addr_str);
			exit (1);
		}
	}
	else if (family == AF_UNSPEC)
		family = AF_INET6;
 
	if ((listenfd = socket(family, sock_type, 0)) == -1) {
		printf ("Unable to create socket, errno %d (%m)\n", errno);
		exit(1);
	}

	if (family == AF_INET) {
		bzero(&servaddr, sizeof(servaddr));
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = addr_str ? *(uint32_t*)addr_buf : htonl(INADDR_ANY);
		servaddr.sin_port = htons(port);

		if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
			printf ("bind returned %d (%m)\n", errno);
			exit(1);
		}
	} else {
		bzero(&servaddr6, sizeof(servaddr6));
		servaddr6.sin6_family = AF_INET6;
		servaddr6.sin6_addr = addr_str ? *(struct in6_addr *)addr_buf : in6addr_any;
		servaddr6.sin6_port = htons(port);

		if (bind(listenfd, (struct sockaddr *)&servaddr6, sizeof(servaddr6))) {
			printf ("bind returned %d (%m)\n", errno);
			exit(1);
		}
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	sa.sa_flags = SA_NOCLDWAIT;
	sigaction(SIGCHLD, &sa, NULL);

	if (sock_type == SOCK_STREAM) {
		listen(listenfd, backlog);

		for (;;) {
			if (family == AF_INET) {
				clilen = sizeof (cliaddr);
				connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);
			}
			else {
				clilen = sizeof (cliaddr6);
				connfd = accept(listenfd, (struct sockaddr *)&cliaddr6, &clilen);
			}

			if (!silent)
				printf("Received connection\n");
			if ((childpid = fork()) == 0) {
				close(listenfd);
				if (echo_data || cmd_resp_list)
					process_data(connfd);
				else
					sleep (1);
				exit(0);
			}

			close(connfd);
		}
	}
	else
	{
		for (;;) {
			if (family == AF_INET) {
				clilen = sizeof (cliaddr);
				n = recvfrom(listenfd, buf, sizeof(buf), 0, (struct sockaddr *)&cliaddr, &clilen);
				sendto(listenfd, buf, n, 0, (struct sockaddr *)&cliaddr, clilen);
			}
			else {
				clilen = sizeof (cliaddr6);
				n = recvfrom(listenfd, buf, sizeof(buf), 0, (struct sockaddr *)&cliaddr6, &clilen);
				sendto(listenfd, buf, n, 0, (struct sockaddr *)&cliaddr6, clilen);
			}
			if (!silent)
				printf("Received %d bytes\n", n);
		}
	}
}
