#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int family = AF_INET6;
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

	while ((opt = getopt(argc, argv, "46p:u")) != -1) {
		switch (opt) {
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'u':
			sock_type = SOCK_DGRAM;
			break;
		default: /* '?' */
			fprintf(stderr, "Usage: %s [-p port] [-4] [-6]\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	listenfd = socket(family, sock_type, 0);

	if (family == AF_INET) {
		bzero(&servaddr, sizeof(servaddr));
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
		servaddr.sin_port = htons(port);

		bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
	}
	else {
		bzero(&servaddr6, sizeof(servaddr6));
		servaddr6.sin6_family = AF_INET6;
		servaddr6.sin6_addr = in6addr_any;
		servaddr6.sin6_port = htons(port);

		bind(listenfd, (struct sockaddr *)&servaddr6, sizeof(servaddr6));
	}

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

			printf("Received connection\n");
			if ((childpid = fork()) == 0) {
				close(listenfd);
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
			printf("Received %d bytes\n", n);
		}
	}
}
