#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <string.h>

static void
print_usage(FILE *fp, const char *name)
{
	fprintf(fp, "Usage: %s [options]\n", name);
	fprintf(fp, "\t-a addr\t\tconnect to addr\n");
	fprintf(fp, "\t-p port\t\tconnect to port\n");
	fprintf(fp, "\t-s\t\tsilent\n");
	fprintf(fp, "\t-u\t\tuse UDP\n");
	fprintf(fp, "\t-d dly\t\tdelay dly seconds after connect\n");
	fprintf(fp, "\t-e\t\tsend stdin\n");
	fprintf(fp, "\t-f\t\tenable tcp_fastopen\n");
	fprintf(fp, "\t-h\t\tprint this\n");
}

static void
send_stdin(int sock)
{
	char *line;
	size_t len;

	while ((line = readline("Send> "))) {
		len = strlen(line);
		line[len] = '\n';	// No longer NULL terminated
		write(sock, line, len + 1);
		free(line);
	}
}

int main(int argc, char **argv)
{
	struct addrinfo hint = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
	struct addrinfo *res;
	int ret;
	int sock;
	char *addr_str;
	char *port_str;
	bool silent = false;
	bool use_stdin = false;
	int sock_type = SOCK_STREAM;
	bool tcp_fastopen = false;
	ssize_t r;
	ssize_t len;
	int opt;
	char *endptr;
	int msglen = 4000;
	char *msg = malloc(msglen);
	uint8_t *buf = malloc(msglen);
	unsigned delay_after_connect = 0;


	while ((opt = getopt(argc, argv, ":ha:p:sud:ef")) != -1) {
		switch (opt) {
		case 'a':
			addr_str = optarg;
			break;
		case 'p':
#if 0
			port_num = strtol(optarg, &endptr, 10);
			if (*endptr || port_num <= 0 || port_num > 65535) {
				fprintf(stderr, "Port number '%s' invalid\n", optarg);
				exit(EXIT_FAILURE);
			}
			port = port_num;
#endif
			port_str = optarg;
			break;
		case 's':
			silent = true;
			break;
		case 'u':
			sock_type = SOCK_DGRAM;
			break;
		case 'd':
			delay_after_connect = strtol(optarg, &endptr, 10);
			break;
		case 'e':
			use_stdin = true;
			break;
		case 'h':
			print_usage(stdout, argv[0]);
			exit(0);
		case 'f':
			tcp_fastopen = true;
			break;
		case ':':
			fprintf(stderr, "Option '%c' is missing an argument\n", optopt);
			break;
		default: /* '?' */
			print_usage(stderr, argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	ret = getaddrinfo(addr_str, port_str, &hint, &res);
	if (ret == -1) {
		printf("getaddrinfo failed %d (%s)\n", ret, gai_strerror(ret));
		exit(1);
	}

	sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock == -1) {
		printf("socket failed %d (%m)\n", errno);
		exit(1);
	}

	if (tcp_fastopen) {
		r = sendto(sock, &msg, msglen, MSG_FASTOPEN, res->ai_addr, res->ai_addrlen);
		if (r != msglen)
			printf("fastopen sendto returned %d (errno %d)\n", r, errno);
	} else {
		r = connect(sock, res->ai_addr, res->ai_addrlen);
		if (r)
			printf("connect returned %d (errno %d)\n", r, errno);
	}

	if (delay_after_connect) {
		sleep(delay_after_connect);
		printf("Woken up\n");
	}

	if (use_stdin) {
		send_stdin(sock);
	} else {
		int i = 0;
		while (i++ < 5) {
			uint16_t *p = (uint16_t *)msg;
			for (int h = 0; h < msglen / sizeof(*p); h++)
				*p++ = h + i;
			write(sock, msg, msglen / 2);
			if ((len = read(sock, buf, msglen - 1)) <= 0) {
				printf("read returned %d (%m)\n", errno);
				exit(1);
			} else
				printf("read read %zd bytes %u %u %u %u\n", len, buf[0], buf[1], buf[2], buf[3]);

			sleep(1);
		}
	}

	shutdown(sock, SHUT_WR);
	len = read(sock, buf, msglen - 1);
	printf("Final read returned %d\n", len);
	shutdown(sock, SHUT_RD);
	close(sock);
	sleep(1);

	freeaddrinfo(res);
}
