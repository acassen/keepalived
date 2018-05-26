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

static void
process_data(int fd)
{
	char buf[128];
	int len;

	while ((len = read(fd, buf, sizeof(buf))) > 0) {
		/* Exit if receive ^D */
		if (len == 1 && buf[0] == 4)
			return;
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
	char opt;
	int sock_type = SOCK_STREAM;
	int n;
	char buf[128];
	struct sigaction sa;
	bool silent = false;
	char *addr_str = NULL;
	char addr_buf[sizeof (struct in6_addr)];
	bool echo_data = false;

	while ((opt = getopt(argc, argv, "46a:p:sue")) != -1) {
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
			port = atoi(optarg);
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
		default: /* '?' */
			fprintf(stderr, "Usage: %s [-a bind address] [-p port] [-4] [-6] [-s(ilent)] [-u(dp)] [-e(cho)]\n", argv[0]);
			exit(EXIT_FAILURE);
		}
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
		listen(listenfd, 4);

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
				if (echo_data)
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
			clilen = sizeof(cliaddr);
			if (family == AF_INET) {
				clilen = sizeof (cliaddr);
				n = recvfrom(listenfd, buf, sizeof(buf), 0, (struct sockaddr *)&cliaddr, &clilen);
				sendto(listenfd, buf, n, 0, (struct sockaddr *)&cliaddr, clilen);
			}
			else {
				clilen = sizeof (cliaddr6);
				sendto(listenfd, buf, n, 0, (struct sockaddr *)&cliaddr6, clilen);
			}
			if (!silent)
				printf("Received %d bytes\n", n);
		}
	}
}
